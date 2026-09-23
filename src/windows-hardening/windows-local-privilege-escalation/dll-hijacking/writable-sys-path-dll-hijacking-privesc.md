# Writable System PATH + DLL Hijacking Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione

Se puoi **scrivere in una directory inclusa nel `PATH` a livello di sistema** (non semplicemente nel `PATH` del tuo utente), potresti essere in grado di **eseguire un'escalation dei privilegi** sul sistema.

Questo può essere sfruttato tramite **DLL hijacking** quando un servizio o processo con maggiori privilegi tenta di caricare una DLL che non esiste nelle posizioni di ricerca precedenti e alla fine cerca nella directory `PATH` di sistema scrivibile.

Una voce `PATH` Machine scrivibile è solo una **primitive**, non una prova di esecuzione del codice. Per un'applicazione non pacchettizzata che utilizza l'ordine di ricerca standard, `PATH` viene raggiunto dopo redirection, API sets, SxS, l'elenco dei moduli caricati, KnownDLLs, le directory dell'applicazione e di Windows e la directory corrente. Un percorso completo o una policy `LOAD_LIBRARY_SEARCH_*` / `SetDefaultDllDirectories` può escludere completamente `PATH`.<sup>[[4]](#references)</sup>

Per ulteriori informazioni sul **DLL hijacking**, consulta:

{{#ref}}
./
{{#endref}}

## Privesc con DLL Hijacking

### Individuazione di una DLL mancante

Per prima cosa, **identifica un processo** in esecuzione con **maggiori privilegi** che tenti di **caricare una DLL da una directory `PATH` di sistema scrivibile**.

Ricorda che questa tecnica dipende da una voce `PATH` Machine/System, non solo dal tuo `PATH` User. Pertanto, prima di dedicare tempo a Procmon, vale la pena enumerare le voci del `PATH` Machine e verificare quali siano scrivibili:<sup>[[1]](#references)</sup>
```powershell
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';' | Where-Object { $_ }
$machinePath | ForEach-Object {
$path = $_.Trim()
if ($path) {
Write-Host "`n[*] $path"
icacls $path 2>$null
}
}
```
Il testo delle ACL può essere fuorviante perché l'appartenenza ai gruppi, le ACE di negazione e le autorizzazioni ereditate influenzano il risultato. In un test autorizzato, una probe di creazione/eliminazione verifica l'**accesso effettivo del token corrente** (è invasiva e può generare alert):<sup>[[1]](#references)</sup>
```powershell
$dirs = [Environment]::GetEnvironmentVariable('Path','Machine') -split ';' |
ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } |
Where-Object { $_ } | Sort-Object -Unique
foreach ($dir in $dirs) {
if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
$probe = Join-Path $dir ('.ht-write-' + [guid]::NewGuid().ToString('N') + '.tmp')
try { [IO.File]::WriteAllBytes($probe, [byte[]]@()); Remove-Item -LiteralPath $probe -Force; "[WRITABLE] $dir" }
catch { }
}
```
### Conferma il `PATH` effettivo del target

Il `PATH` Machine letto dal registro è un dato di configurazione; il loader usa il blocco dell'ambiente del **processo target**. Ogni processo possiede un blocco dell'ambiente e un processo figlio normalmente eredita una copia dell'ambiente del processo padre. Di conseguenza, un servizio in esecuzione da molto tempo può conservare un valore precedente e un servizio avviato con un ambiente personalizzato può differire dal valore visualizzato nella tua shell. Considera come ground truth una probe di Procmon della directory esatta effettuata dal PID target; dopo aver modificato il `PATH` in una lab, riavvia l'albero dei processi interessato oppure esegui un reboot prima di concludere che il lookup non avvenga.<sup>[[5]](#references)</sup>

Il problema in questi casi è che tali processi sono probabilmente già in esecuzione. Per identificare le DLL che i servizi tentano di caricare senza riuscirci, avvia Procmon il prima possibile (prima dell'avvio dei processi), quindi:

> [!WARNING]
> L'aggiunta di una directory scrivibile dall'utente al `PATH` Machine **crea la condizione di vulnerabilità**. Esegui questa operazione solo in una research VM isolata per rivelare quali processi privilegiati raggiungono il `PATH`; su un host sottoposto ad assessment, monitora la voce scrivibile già esistente senza modificare la configurazione di sistema.<sup>[[1]](#references)</sup>

- **Crea** la cartella `C:\privesc_hijacking` e aggiungi il path `C:\privesc_hijacking` alla **variabile d'ambiente System Path**. Puoi farlo **manualmente** oppure con **PS**:
```bash
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- Avvia **`procmon`** e vai su **`Options`** --> **`Enable boot logging`**, quindi premi **`OK`** nella richiesta.
- Quindi, **riavvia** il computer. Quando il computer viene riavviato, **`procmon`** inizierà a **registrare** gli eventi il prima possibile.
- Una volta **avviato Windows**, esegui nuovamente **`procmon`**: ti dirà che è stato in esecuzione e ti **chiederà se vuoi salvare** gli eventi in un file. Rispondi **sì** e **salva gli eventi in un file**.
- **Dopo** che il **file** è stato **generato**, **chiudi** la finestra di **`procmon`** aperta e **apri il file degli eventi**.
- Aggiungi questi **filtri** per trovare tutte le DLL che un **processo ha tentato di caricare** dalla cartella writable System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Il **boot logging** è richiesto solo per i servizi che si avviano **troppo presto** per poterli osservare altrimenti. Se puoi **attivare il servizio/programma target su richiesta** (ad esempio interagendo con la sua interfaccia COM, riavviando il servizio o rilanciando un'attività pianificata), di solito è più veloce mantenere una cattura normale di Procmon con filtri come **`Path contains .dll`**, **`Result is NAME NOT FOUND`** e **`Path begins with <writable_machine_path>`**.

### DLL perse

Eseguendo questa procedura in una **macchina virtuale (vmware) Windows 11** gratuita ho ottenuto questi risultati:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

In questo caso, ignora i risultati `.exe`. Le ricerche delle DLL mancanti provenivano da:

| Servizio                         | Dll                | Riga CMD                                                           |
| ------------------------------- | ------------------ | ------------------------------------------------------------------ |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

L'esempio seguente utilizza la tecnica descritta in questo articolo sull'[**abuso di `WptsExtensions.dll` per la privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Altri candidati che vale la pena sottoporre a triage

`WptsExtensions.dll` è un buon esempio, ma non è l'unica **phantom DLL** ricorrente che compare nei servizi privilegiati. Le regole moderne di hunting e i cataloghi pubblici di hijack continuano a tenere traccia di nomi come:<sup>[[2]](#references)</sup>

| Servizio / Scenario | DLL mancante | Note |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Candidato classico **SYSTEM** sui sistemi client. Utile quando la directory writable si trova nel **Machine PATH** e il servizio cerca la DLL durante l'avvio. |
| NetMan su Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interessante nelle **server editions** perché il servizio viene eseguito come **SYSTEM** e in alcune build può essere **attivato su richiesta da un utente normale**, rendendolo migliore dei casi che richiedono solo un riavvio. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Di solito restituisce prima **`NT AUTHORITY\LOCAL SERVICE`**. Spesso è comunque sufficiente perché il token dispone di **`SeImpersonatePrivilege`**, quindi puoi concatenarlo con [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Considera questi nomi come **suggerimenti per il triage**, non come risultati garantiti: dipendono dalla **SKU/build** e Microsoft potrebbe modificare il comportamento tra le diverse release. L'elemento importante è cercare **DLL mancanti nei servizi privilegiati che attraversano il Machine PATH**, soprattutto se il servizio può essere **riattivato senza riavviare il sistema**.

### Convalidare un candidato prima di armarlo

Un evento `NAME NOT FOUND` da solo non è sufficiente. Prima di posizionare un payload, verifica la catena completa:<sup>[[1]](#references)[[4]](#references)</sup>

1. L'evento appartiene al **PID, alla riga di comando, all'account del servizio e al livello di integrità** previsti, e il percorso mancante è esattamente la directory writable del Machine `PATH`.
2. Per lo stesso basename della DLL, nessuna directory precedente restituisce `SUCCESS`, e il modulo non è soddisfatto dall'elenco dei moduli caricati, da KnownDLLs, dal redirection o da un manifest SxS.
3. La ricerca viene ripetuta quando un utente con pochi privilegi invoca il trigger previsto. Una ricerca eseguita solo all'avvio è utilizzabile, ma operativamente molto peggiore di una eseguita su richiesta.
4. L'architettura del payload corrisponde a quella del processo. Se l'applicazione in seguito risolve le esportazioni, fai da proxy alla DLL legittima o esporta i simboli previsti; consulta [Creating and compiling DLLs](README.md#creating-and-compiling-dlls).
5. Inizia utilizzando una DLL canary innocua che registri il PID, l'identità e il timestamp. In Procmon, richiedi un **`Load Image`** riuscito dal percorso in cui è stata inserita la DLL, invece di presumere che una precedente ricerca del file abbia causato l'esecuzione.

### Exploitation

Per **escalare i privilegi**, esegui l'hijack di **`WptsExtensions.dll`**. Una volta noti il **percorso** e il **nome**, genera la DLL dannosa.

Puoi [**provare a utilizzare uno di questi esempi**](README.md#creating-and-compiling-dlls). Potresti eseguire payload come: ottenere una reverse shell, aggiungere un utente, eseguire un beacon...

> [!WARNING]
> Nota che **non tutti i servizi vengono eseguiti** come **`NT AUTHORITY\SYSTEM`**. Alcuni vengono eseguiti come **`NT AUTHORITY\LOCAL SERVICE`**, che dispone di **meno privilegi**, quindi l'abuso di uno di questi servizi potrebbe non consentirti di creare un nuovo utente.\
> Tuttavia, tale account dispone del diritto utente **`SeImpersonatePrivilege`**, quindi puoi utilizzare la [**suite Potato per escalare i privilegi**](../roguepotato-and-printspoofer.md). In questo caso, una reverse shell è un'opzione migliore rispetto al tentativo di creare un utente.

Il servizio **Task Scheduler** viene normalmente eseguito come **`NT AUTHORITY\SYSTEM`**, ma verifica la distribuzione effettiva e non dedurre l'identità di esecuzione solo dal nome del servizio:<sup>[[3]](#references)</sup>
```powershell
Get-CimInstance Win32_Service -Filter "Name='Schedule'" | Select-Object Name, StartName, State, PathName
```
Dopo aver **generato la DLL malevola** (_nel mio caso ho usato una x64 rev shell e ho ottenuto una shell, ma Defender l'ha terminata perché proveniva da msfvenom_), salvala nel System Path scrivibile con il nome **WptsExtensions.dll** e **riavvia** il computer (oppure riavvia il servizio o fai tutto ciò che è necessario per eseguire nuovamente il servizio/programma interessato).

Quando il servizio viene riavviato, la **DLL dovrebbe essere caricata ed eseguita** (puoi **riutilizzare** il trucco di **Procmon** per verificare se la **libreria è stata caricata come previsto**).

> [!NOTE]
> Pianifica la pulizia prima dell'esecuzione. Un servizio potrebbe mantenere la DLL mappata e bloccare il file finché non viene arrestato; per `WptsExtensions.dll`, arrestare Task Scheduler richiede diritti elevati. Dopo aver ottenuto il contesto desiderato, arresta il target in modo sicuro, rimuovi il payload e ripristina qualsiasi modifica al `PATH` effettuata solo nel laboratorio.<sup>[[1]](#references)</sup>

### Bonifica / rilevamento

Rimuovi i permessi di scrittura deboli da ogni directory del `PATH` della macchina e rimuovi le voci obsolete. Gli sviluppatori dovrebbero caricare le librerie attendibili tramite il percorso completo oppure limitare la risoluzione usando `SetDefaultDllDirectories` / i flag di ricerca di `LoadLibraryEx`. I difensori possono correlare le modifiche al `PATH` della macchina con processi privilegiati che caricano DLL da directory non di sistema scrivibili dagli utenti.<sup>[[2]](#references)[[4]](#references)</sup>



## References

- [1] [DLL Hijacking di Windows (si spera) chiarito](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [DLL sospetta caricata per persistenza o escalation dei privilegi](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Escalation dei privilegi in Windows](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
- [4] [Ordine di ricerca delle dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [5] [Variabili d'ambiente](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
{{#include ../../../banners/hacktricks-training.md}}
