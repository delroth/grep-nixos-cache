# grep-nixos-cache

A tool to efficiently grep the contents of many NixOS store paths for a given
string to find. The main use case is looking for vendored libraries through the
entirety of a Hydra evaluation.

## How to use

```
$ grep-nixos-cache --needle what-to-search --path /nix/store/...
```

```
$ grep-nixos-cache --needle what-to-search --paths /path/to/store-paths.txt
```
