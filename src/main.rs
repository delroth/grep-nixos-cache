use anyhow::{bail, Context, Result};
use aws_config::imds::region::ImdsRegionProvider;
use bytes::buf::Buf;
use clap::Parser;
use futures::prelude::*;
use memmem::Searcher;
use std::{
    fs,
    io::{self, Read},
    process,
    sync::Arc,
};

const PATHS_COUNT_AWS_THRESHOLD: usize = 50;
const NIX_CACHE_S3_BUCKET: &str = "nix-cache";
const NIX_CACHE_CDN_URL: &str = "https://cache.nixos.org";
const NIX_CACHE_REGION: &str = "us-east-1";
const USER_AGENT: &str = "grep-nixos-cache 1.0 (https://github.com/delroth/grep-nixos-cache)";
const YARA_TIMEOUT_SECS: i32 = 30;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Flags {
    /// String to look for in the target Nix store paths.
    #[arg(long, conflicts_with_all = ["yara_ruleset"])]
    needle: Option<String>,

    // Yara rules file to match against Nix store paths.
    #[arg(long, conflicts_with_all = ["needle"])]
    yara_ruleset: Option<String>,

    /// Single Nix store path that need to be checked (mostly for testing purposes).
    #[arg(long, conflicts_with_all = ["paths", "hydra_eval_url"])]
    path: Option<String>,

    /// Filename containing a newline-separated list of Nix store paths that need to be checked.
    #[arg(long, conflicts_with_all = ["path", "hydra_eval_url"])]
    paths: Option<String>,

    /// Hydra eval URL to get all output Nix store paths from.
    #[arg(long, conflicts_with_all = ["path", "paths"])]
    hydra_eval_url: Option<String>,

    /// Number of simultaneous store paths to process in flight.
    #[arg(long, default_value_t = 15)]
    parallelism: usize,

    /// Allow possibly expensive runs fetching from S3 with requester-pays.
    #[arg(long, default_value_t = false)]
    allow_possibly_expensive_run: bool,
}

async fn get_aws_region() -> Option<String> {
    ImdsRegionProvider::builder()
        .build()
        .region()
        .await
        .map(|x| x.to_string())
}

fn collect_output_paths(flags: &Flags) -> Vec<String> {
    if flags.path.is_some() {
        vec![flags.path.clone().unwrap()]
    } else if flags.paths.is_some() {
        fs::read_to_string(flags.paths.as_ref().unwrap())
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    } else if flags.hydra_eval_url.is_some() {
        println!(
            "Reading output paths from Hydra eval URLs is currently unsupported (fix Hydra plz)."
        );
        vec![]
    } else {
        vec![]
    }
}

#[derive(Clone)]
enum Matcher<'a> {
    String(StringMatcher<'a>),
    Yara(YaraMatcher),
}

#[derive(Clone)]
struct StringMatcher<'a> {
    searcher: memmem::TwoWaySearcher<'a>,
}

impl StringMatcher<'_> {
    fn new<'a>(needle: &'static String) -> StringMatcher<'a> {
        StringMatcher {
            searcher: memmem::TwoWaySearcher::new(needle.as_bytes()),
        }
    }
}

#[derive(Clone)]
struct YaraMatcher {
    rules: Arc<yara::Rules>,
}

impl YaraMatcher {
    fn new(rules_file: &String) -> Result<YaraMatcher> {
        let compiler = yara::Compiler::new()?.add_rules_file(rules_file)?;
        let rules = compiler.compile_rules()?;

        Ok(YaraMatcher {
            rules: Arc::new(rules),
        })
    }
}

impl Matcher<'_> {
    fn matches(&self, haystack: &[u8]) -> Result<Vec<String>> {
        match self {
            Matcher::String(sm) => {
                if sm.searcher.search_in(haystack).is_some() {
                    Ok(vec!["needle".to_string()])
                } else {
                    Ok(vec![])
                }
            }
            Matcher::Yara(ym) => {
                let matches = ym.rules.scan_mem(haystack, YARA_TIMEOUT_SECS)?;
                Ok(matches.iter().map(|r| r.identifier.to_string()).collect())
            }
        }
    }
}

#[derive(Clone)]
enum Fetcher {
    Cdn(CdnFetcher),
    S3(S3Fetcher),
}

#[derive(Clone)]
struct CdnFetcher {
    client: reqwest::Client,
    url_base: String,
}

#[derive(Clone)]
struct S3Fetcher {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl CdnFetcher {
    fn new(url_base: &str) -> CdnFetcher {
        CdnFetcher {
            client: reqwest::Client::builder()
                .user_agent(USER_AGENT)
                .build()
                .unwrap(),
            url_base: url_base.to_string(),
        }
    }
}

impl S3Fetcher {
    fn new(config: &aws_config::SdkConfig, bucket: &str) -> S3Fetcher {
        S3Fetcher {
            client: aws_sdk_s3::Client::new(config),
            bucket: bucket.to_string(),
        }
    }
}

impl Fetcher {
    async fn download(&self, path: &str) -> Result<(u16, bytes::Bytes)> {
        match self {
            Fetcher::Cdn(cf) => {
                let url = format!("{}/{}", cf.url_base, path);
                let resp = cf.client.get(url).send().await?;
                Ok((resp.status().as_u16(), resp.bytes().await?))
            }
            Fetcher::S3(sf) => {
                let resp = sf
                    .client
                    .get_object()
                    .bucket(&sf.bucket)
                    .request_payer(aws_sdk_s3::types::RequestPayer::Requester)
                    .key(path)
                    .send()
                    .await?;
                Ok((200, resp.body.collect().await?.into_bytes()))
            }
        }
    }
}

struct SearchOutcome {
    path: String,
    files_matched: multimap::MultiMap<String, String>,
}

struct NarInfo {
    nar_url: String,
    compression: String,
    nar_size: usize,
}

fn hash_from_path(path: &String) -> Result<String> {
    let basename = path
        .strip_prefix("/nix/store/")
        .context("Path does not start with /nix/store/")?;
    Ok(basename
        .split_once('-')
        .context("No - in path basename")?
        .0
        .to_string())
}

fn parse_narinfo(text: String) -> Result<NarInfo> {
    let mut nar_url: Option<String> = None;
    let mut compression: Option<String> = None;
    let mut nar_size: Option<usize> = None;

    for l in text.lines() {
        if let Some(val) = l.strip_prefix("URL: ") {
            nar_url = Some(val.to_string());
        } else if let Some(val) = l.strip_prefix("Compression: ") {
            compression = Some(val.to_string());
        } else if let Some(val) = l.strip_prefix("NarSize: ") {
            nar_size = Some(val.parse::<usize>().context("Invalid NarSize")?);
        }
    }

    Ok(NarInfo {
        nar_url: nar_url.context("Did not find a NAR URL key")?,
        compression: compression.context("Did not a NAR Compression key")?,
        nar_size: nar_size.context("Did not find a NAR NarSize key")?,
    })
}

async fn fetch_narinfo(fetcher: &Fetcher, hash: &String) -> Result<Option<NarInfo>> {
    let path = format!("{}.narinfo", hash);
    let (code, body) = fetcher.download(&path).await?;

    if code == 403 {
        return Ok(None);
    }

    let data = std::str::from_utf8(&body)?.to_string();
    Ok(Some(
        parse_narinfo(data).context("Could not parse narinfo file")?,
    ))
}

async fn fetch_nar(fetcher: &Fetcher, narinfo: NarInfo) -> Result<nix_nar::Decoder<impl io::Read>> {
    // TODO: This buffers everything into memory. Unfortunately there's no NAR parser right now
    // which can deal with async decoding...

    let (_, compressed) = fetcher.download(&narinfo.nar_url).await?;

    let mut contents = Vec::with_capacity(narinfo.nar_size);
    match narinfo.compression.as_str() {
        "xz" => xz2::bufread::XzDecoder::new(compressed.reader()).read_to_end(&mut contents)?,
        _ => bail!("Unknown compression method: {}", narinfo.compression),
    };

    Ok(nix_nar::Decoder::new(io::Cursor::new(contents)).context("Not a valid NAR file")?)
}

async fn find_matches_in_path(
    matcher: &Matcher<'_>,
    fetcher: &Fetcher,
    path: &String,
) -> Result<SearchOutcome> {
    let hash = hash_from_path(path).with_context(|| format!("Failed to parse path: {}", path))?;
    let narinfo = fetch_narinfo(fetcher, &hash)
        .await
        .context("Failed to fetch narinfo")?;

    let mut files_matched = multimap::MultiMap::<String, String>::new();

    if let Some(narinfo) = narinfo {
        let nar = fetch_nar(fetcher, narinfo)
            .await
            .context("Failed to fetch nar")?;

        for entry in nar.entries()? {
            let entry = entry.context("Failed to parse NAR entry")?;
            if let nix_nar::Content::File { mut data, size, .. } = entry.content {
                let mut bytes = Vec::with_capacity(size.try_into().unwrap());
                data.read_to_end(&mut bytes)?;
                for tag in matcher.matches(bytes.as_slice())?.iter() {
                    files_matched.insert(entry.path.clone().unwrap().into_string(), tag.clone());
                }
            }
        }
    }

    Ok(SearchOutcome {
        path: path.clone(),
        files_matched,
    })
}

#[tokio::main]
async fn main() {
    let flags = Flags::parse();

    let paths = collect_output_paths(&flags);

    let fetcher = if paths.is_empty() {
        println!("No paths to check, exiting");
        process::exit(1);
    } else if paths.len() >= PATHS_COUNT_AWS_THRESHOLD {
        if !flags.allow_possibly_expensive_run
            && get_aws_region().await.unwrap_or("not-aws".to_string()) != NIX_CACHE_REGION
        {
            println!("To avoid unnecessary costs, please run this program in the AWS {} region. Exiting.", NIX_CACHE_REGION);
            println!("This behavior can be overridden with --allow-possibly-expensive-run.");
            process::exit(1);
        } else {
            let aws_config = aws_config::load_from_env().await;
            Fetcher::S3(S3Fetcher::new(&aws_config, NIX_CACHE_S3_BUCKET))
        }
    } else {
        Fetcher::Cdn(CdnFetcher::new(NIX_CACHE_CDN_URL))
    };

    let matcher = if let Some(needle) = flags.needle {
        let needle = Box::leak(Box::new(needle));
        Matcher::String(StringMatcher::new(needle))
    } else if let Some(ruleset) = flags.yara_ruleset {
        Matcher::Yara(YaraMatcher::new(&ruleset).expect("Failed to parse Yara ruleset"))
    } else {
        println!("No matcher provided, please use either --needle or --yara_ruleset");
        process::exit(1);
    };

    let futures = paths.iter().map(|p| {
        let matcher = matcher.clone();
        let fetcher = fetcher.clone();
        let p = p.clone();
        async move {
            tokio::spawn(async move {
                find_matches_in_path(&matcher, &fetcher, &p)
                    .await
                    .with_context(|| format!("Error while analyzing path {:?}", p))
            })
            .await?
        }
    });

    let mut processed: u32 = 0;
    let mut stream = futures::stream::iter(futures).buffer_unordered(flags.parallelism);
    while let Some(result) = stream.next().await {
        match result {
            Ok(result) => {
                if !result.files_matched.is_empty() {
                    println!("Found in {}: {:?}", result.path, result.files_matched);
                }
            }
            Err(err) => {
                println!("Error: {:?}", err);
            }
        }

        processed += 1;
        if processed % 1000 == 0 {
            let pct = 100.0 * (processed as f32) / (paths.len() as f32);
            println!(
                "Processed {} out of {} ({}%)",
                processed,
                paths.len(),
                pct as u32
            );
        }
    }
}
