# ipsw iOS/macOS Firmware Triage

{{#include ../../banners/hacktricks-training.md}}

## Overview

[`ipsw`](https://github.com/blacktop/ipsw) is a Go-based CLI/daemon that automates the end-to-end workflow of grabbing Apple firmware images, carving their DMGs, and reverse engineering Mach-O binaries, kernelcaches, dyld shared caches, and code-signing metadata. Each command in `cmd/` reuses packages in `pkg/dmg`, `pkg/macho`, `pkg/dyld`, `pkg/ota`, and others, so you can either rely on a single Swiss-army CLI or import the packages into custom tooling. Typical flows are:

1. Acquire the IPSW/OTA (from Apple CDN, AppleDB, RSS feeds, App Store Connect, etc.).
2. Extract disk images, kernelcache slices, dyld caches, SEP/iBoot payloads, and trust caches.
3. Parse Mach-O headers, load commands, ObjC/Swift metadata, entitlements, and strings to map privileged attack surface.
4. Diff firmware builds to identify newly exposed daemons, sandbox profiles, or syscall handlers.
5. Optionally interrogate a tethered device over USBMUX/lockdown/AFC to compare the live state with the static firmware artifacts.

Because the binaries ship for macOS, Linux, and Windows (scoop bucket) and the repo also ships Dockerfiles, you can drop it into CI, fuzzing farms, or fleet-wide triage pipelines to keep up with every new Apple release.

## Installation & Workspace Bootstrap

```bash
# macOS (formula ships all subcommands)
brew install ipsw

# Linux snap
sudo snap install ipsw

# Windows via Scoop
scoop bucket add blacktop https://github.com/blacktop/scoop-bucket.git
scoop install blacktop/ipsw
```

When you first run the tool, copy the example configuration so you can pin cache paths, proxies, and daemon settings:

```bash
mkdir -p ~/.config/ipsw
cp config.example.yml ~/.config/ipsw/config.yaml
```

Common knobs in that YAML:

- `daemon.host/port/socket`: where `ipswd` listens when exposing the REST API.
- Firmware cache roots for IPSW/OTA/KDK downloads (keeps deltas local for quick diffs).
- Default `device` / `version` selectors so you can omit them from commands.
- HTTP proxy settings plus paths to external helpers (e.g., custom dmg/IMG4 decryptors).
- Database driver (`sqlite` by default, `postgres` when serving many analysts via `ipswd`).

## Firmware Acquisition & Disk Extraction

`ipsw download` knows how to resolve Apple firmware metadata via AppleDB, developer feeds, or direct CDN URLs, so you only need a board ID or marketing name:

```bash
# Pull the latest signed firmware for iPhone16,1 and keep it cached
ipsw download ipsw --device iPhone16,1 --latest --output ~/firmware-cache

# Compare two builds to quickly diff kernel/iBoot payloads
ipsw diff iPhone16,1_18.1_22B83_Restore.ipsw iPhone16,1_18.2_22C150_Restore.ipsw
```

After the archive is cached, use `ipsw extract` to target specific artifacts without inflating the entire bundle:

```bash
# Recover the kernelcache from the restore image and decompress it
ipsw extract --kernel ~/firmware-cache/iPhone16,1_18.2_22C150_Restore.ipsw --out kernelcache.decompressed

# Enumerate and pull DMGs for filesystem inspection
ipsw extract --dmg System ~/firmware-cache/iPhone16,1_18.2_22C150_Restore.ipsw --out ./system.dmg
```

The extracted DMGs can then be mounted, loop-backed, or converted so you can crawl `/System/Library/LaunchDaemons`, `trustcache/`, `usr/libexec`, and other privileged locations without dealing with Apple’s proprietary compression yourself.

## Kernelcache, Mach-O, and dyld Shared Cache Analysis

Every binary inside the IPSW/OTA can be parsed with `ipsw macho` to understand load commands, symbols, Objective-C metadata, entitlements, and strings:

```bash
# Quick header/segment dump
ipsw macho info kernelcache.decompressed

# Symbol-aware disassembly of specific routines
ipsw macho disass /System/Library/PrivateFrameworks/ApplePushService.framework/apsd --symbol _main

# Search for suspicious strings or selectors
ipsw macho search /System/Library/CoreServices/SpringBoard.app/SpringBoard --string "com.apple.private.tcc"
```

The dyld shared cache extractor lets you carve out frameworks or inspect ObjC/Swift classes without manually reconstructing the cache:

```bash
# Dump cache metadata (UUIDs, mappings, slide info)
ipsw dyld info /Volumes/System/System/Library/dyld/dyld_shared_cache_arm64e

# Rebuild a single dylib for IDA/Ghidra work
ipsw dyld extract /path/to/dyld_shared_cache_arm64e --dylib CoreTelephony.framework/CoreTelephony

# Enumerate Objective-C classes/methods to locate new IPC surfaces
ipsw dyld objc class /path/to/dyld_shared_cache_arm64e --class CXCallDirectoryExtensionHostContext
```

Use these outputs to track syscall handlers, MIG endpoints, sandbox profiles, entitlement-gated services, or IOKit user clients every time Apple revs the firmware.

## Metadata and Trust Surface Enumeration

Because `ipsw` understands IMG4, iBoot, SEP, trust caches, and Info.plists, you can quickly dump the configuration layers that guard privileged code:

- Parse Info.plist and entitlement plists with `ipsw macho info ...` to see which daemons hold `com.apple.private.*` capabilities.
- Enumerate trust caches and KCID manifests to check if a binary remains trusted after your modifications.
- Inspect SEP/iBoot payloads (`ipsw fw sep`, `ipsw fw iboot`) to diff mailbox handlers, allowed services, or boot arguments.
- Feed the data to downstream tooling (MobSF, IDA loaders, emulator harnesses) without writing bespoke extractors for each release.

## Device-side Reconnaissance via `idev`

`ipsw idev` wraps USBMUX, lockdown, and AFC so that the same workstation used for firmware diffing can interrogate a tethered device:

```bash
# Enumerate attached devices and their product types
ipsw idev list

# Browse the filesystem over AFC to validate on-disk changes
ipsw idev afc ls /System/Library/LaunchDaemons
ipsw idev afc pull /private/var/mobile/Library/Logs/CrashReporter/DiagnosticLogs ./crashlogs

# Enumerate installed apps or take a full backup prior to fuzzing
ipsw idev apps ls
ipsw idev backup create --output ~/ios-backups/device_20250101

# Stream syslog/crashlog output while triggering exploits
ipsw idev syslog
```

This abstraction saves you from coding directly against lockdownd, AFC, or House Arrest every time you need logs after a crash, proof of persistence, or a copy of modified configuration files.

## Automation, Daemon Mode, and Docker

Running `ipswd` turns the toolkit into an HTTP API so you can trigger firmware downloads, dyld carving, or device data collection from CI, remote analysts, or fuzzing clusters:

```bash
# Start the daemon with explicit listen address and database settings
ipswd --config ~/.config/ipsw/config.yaml --host 0.0.0.0 --port 3993
```

The daemon exposes the same handlers as the CLI through JSON/HTTP (see the generated docs served by `ipswd`), so you can enqueue firmware downloads, request dyld extraction jobs, or pull device inventories without granting shell access to the host running the caches.

Two container recipes exist:

- `Dockerfile` – ships the CLI plus dependencies so analysts can run heavy extraction/diff workloads without polluting their host.
- `Dockerfile.daemon` – builds the API service for deployment behind an ingress or inside a lab subnet, enabling shared firmware caches and remote tasking.

The `hack/` directory holds practical scripts (firmware diffing, DSC carving helpers, conversion utilities) that consume the Go packages directly—use them as templates for bespoke research pipelines.

## References

- [ipsw – iOS/macOS Research Swiss Army Knife](https://github.com/blacktop/ipsw)
- [ipsw documentation](https://blacktop.github.io/ipsw)

{{#include ../../banners/hacktricks-training.md}}
