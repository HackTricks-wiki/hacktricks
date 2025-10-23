# MSI Installer CustomAction Analysis

{{#include ../../../banners/hacktricks-training.md}}

Windows Installer packages (MSI) are relational databases of tables that drive install logic. Malicious actors abuse MSI CustomActions to execute staged droppers/loaders during installation while keeping static detections low. This page shows how to quickly triage MSIs and reconstruct execution chains using lessmsi.

## Quick background
- Tables of interest:
  - CustomAction: defines actions (DLL/EXE/script) and their command lines (Target) and sources.
  - InstallExecuteSequence: specifies the execution order for actions.
  - File/Component/Feature: map logical keys to on-disk filenames and install locations.
  - Binary: embedded streams referenced by CustomActions (e.g., DLLs/EXEs run from memory or temp).

## Tooling: lessmsi CLI
Install via Chocolatey or download a release. Core commands:

```powershell
# Extract files (trailing backslash required for output dir)
lessmsi x .\sample.msi .\out\

# List any MSI table as CSV to stdout
lessmsi l -t CustomAction .\sample.msi
lessmsi l -t InstallExecuteSequence .\sample.msi
lessmsi l -t File .\sample.msi
lessmsi l -t Component .\sample.msi
lessmsi l -t Binary .\sample.msi
```

## Triage workflow
1) Enumerate CustomActions

```powershell
lessmsi l -t CustomAction .\sample.msi
```

- Focus on actions whose `Type` implies launching EXE/script or loading a DLL.
- Inspect the `Target` for command lines that drop/launch staged payloads.

2) Map files referenced by actions

```powershell
# Find referenced filenames and their logical keys
lessmsi l -t File .\sample.msi | findstr /i "\.exe\|\.bat\|\.vbs"
lessmsi l -t Component .\sample.msi > components.csv
```

- Use the `File`/`Component` mapping to locate dropped executables in the extracted `out/` tree.

3) Understand execution timing

```powershell
lessmsi l -t InstallExecuteSequence .\sample.msi | sort
```

- Identify where the suspicious CustomAction runs (e.g., between `InstallInitialize` and `InstallFinalize`).
- Look for immediate actions that execute before files are committed.

4) Check embedded streams

```powershell
lessmsi l -t Binary .\sample.msi
```

- If a CustomAction `Source` points to the `Binary` table, extract the stream (via GUI or a generic MSI stream dumper) and analyze it.

5) Reconstruct the loader chain
- Many stealer campaigns use: `MSI (CustomAction) → stage-1 EXE (loader, e.g., HijackLoader) → final stealer (e.g., Rhadamanthys)`.
- Confirm by statically inspecting the stage-1 EXE and observing network beacons after detonation.

## Execution tracing tip (runtime)
Enable verbose installation logs to observe the CustomAction being invoked:

```powershell
msiexec /i .\sample.msi /l*v install.log
```

Search for the CustomAction name in `install.log` to confirm invocation order and parameters.

## Heuristics that often indicate a malicious MSI
- Low VT score but non-trivial `CustomAction` launching an EXE from `%TEMP%`, `%APPDATA%`, or a random subfolder.
- `Binary`-backed actions executing opaque payloads without installing legitimate products.
- Archives ship a plausible cracked installer alongside the MSI to maintain legitimacy.

See also platform-abuse delivery via YouTube and end-to-end chain examples:
- [YouTube Platform Abuse for Malware Distribution](../../phishing-methodology/youtube-platform-abuse-malware-distribution.md)

## References

- [lessmsi – MSI extractor and table viewer](https://github.com/activescott/lessmsi)
- [Dissecting YouTube’s Malware Distribution Network (Check Point Research)](https://research.checkpoint.com/2025/youtube-ghost-network/)

{{#include ../../../banners/hacktricks-training.md}}