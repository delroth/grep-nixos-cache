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
};

const PATHS_COUNT_AWS_THRESHOLD: usize = 50;
const NIX_CACHE_S3_BASE: &str = "https://nix-cache.s3.amazonaws.com";
const NIX_CACHE_CDN_BASE: &str = "https://cache.nixos.org";
const NIX_CACHE_REGION: &str = "us-east-1";
const USER_AGENT: &str = "grep-nixos-cache 1.0 (https://github.com/delroth/grep-nixos-cache)";

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Flags {
    /// String to look for in the target Nix store paths.
    #[arg(long)]
    needle: String,

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

struct SearchOutcome {
    path: String,
    files_matched: Vec<String>,
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

async fn fetch_narinfo(
    http: &reqwest::Client,
    url_base: &str,
    hash: &String,
) -> Result<Option<NarInfo>> {
    let url = format!("{}/{}.narinfo", url_base, hash);
    let resp = http.get(url).send().await?;

    if resp.status().as_u16() == 403 {
        return Ok(None);
    }

    let data = resp.text().await?;
    Ok(Some(
        parse_narinfo(data).context("Could not parse narinfo file")?,
    ))
}

async fn fetch_nar(
    http: &reqwest::Client,
    url_base: &str,
    narinfo: NarInfo,
) -> Result<nix_nar::Decoder<impl io::Read>> {
    // TODO: This buffers everything into memory. Unfortunately there's no NAR parser right now
    // which can deal with async decoding...

    let url = format!("{}/{}", url_base, narinfo.nar_url);
    let compressed = http
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let mut contents = Vec::with_capacity(narinfo.nar_size);
    match narinfo.compression.as_str() {
        "xz" => xz2::bufread::XzDecoder::new(compressed.reader()).read_to_end(&mut contents)?,
        _ => bail!("Unknown compression method: {}", narinfo.compression),
    };

    Ok(nix_nar::Decoder::new(io::Cursor::new(contents)).context("Not a valid NAR file")?)
}

async fn find_needle_in_path(
    needle: &String,
    path: &String,
    http: &reqwest::Client,
    url_base: &str,
) -> Result<SearchOutcome> {
    let hash = hash_from_path(path).with_context(|| format!("Failed to parse path: {}", path))?;
    let narinfo = fetch_narinfo(http, url_base, &hash)
        .await
        .context("Failed to fetch narinfo")?;

    let mut files_matched = Vec::new();

    if let Some(narinfo) = narinfo {
        let nar = fetch_nar(http, url_base, narinfo)
            .await
            .context("Failed to fetch nar")?;

        let searcher = memmem::TwoWaySearcher::new(needle.as_bytes());

        for entry in nar.entries()? {
            let entry = entry.context("Failed to parse NAR entry")?;
            if let nix_nar::Content::File { mut data, size, .. } = entry.content {
                let mut bytes = Vec::with_capacity(size.try_into().unwrap());
                data.read_to_end(&mut bytes)?;
                if searcher.search_in(bytes.as_slice()).is_some() {
                    files_matched.push(entry.path.unwrap().into_string());
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

    let mut url_base = NIX_CACHE_CDN_BASE;
    let paths = collect_output_paths(&flags);

    if paths.is_empty() {
        println!("No paths to check, exiting");
        process::exit(1);
    } else if paths.len() >= PATHS_COUNT_AWS_THRESHOLD {
        println!(
            "More than {} paths to check, ensuring that we run co-located with the Nix cache...",
            PATHS_COUNT_AWS_THRESHOLD
        );
        if get_aws_region().await.unwrap_or("not-aws".to_string()) != NIX_CACHE_REGION {
            println!("To avoid unnecessary costs to the NixOS project, please run this program in the AWS {} region. Exiting.", NIX_CACHE_REGION);
            process::exit(1);
        } else {
            url_base = NIX_CACHE_S3_BASE;
        }
    }

    let http = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .build()
        .unwrap();

    let futures = paths.iter().map(|p| {
        let p = p.clone();
        let http = http.clone();
        let needle = flags.needle.clone();
        async move {
            tokio::spawn(async move {
                find_needle_in_path(&needle, &p, &http, &url_base)
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
