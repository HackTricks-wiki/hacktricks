# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione

Se puoi **scrivere in una directory del `PATH` a livello di sistema** (non semplicemente nel `PATH` del tuo utente), potresti essere in grado di **eseguire una privilege escalation** sul sistema.

Questo può essere sfruttato tramite **DLL hijacking** quando un servizio o processo con privilegi maggiori tenta di caricare una DLL che non esiste nelle posizioni di ricerca precedenti e alla fine cerca nella directory del `PATH` di sistema con permessi di scrittura.

Per ulteriori informazioni sul **DLL hijacking**, consulta:


{{#ref}}
./
{{#endref}}

## Privesc con Dll Hijacking

### Individuazione di una DLL mancante

Per prima cosa, **identifica un processo** in esecuzione con **privilegi maggiori** che tenta di **caricare una DLL da una directory del `PATH` di sistema con permessi di scrittura**.

Ricorda che questa tecnica dipende da una voce del **Machine/System PATH**, non solo dal tuo **User PATH**. Pertanto, prima di dedicare tempo a Procmon, vale la pena enumerare le voci del **Machine PATH** e verificare quali siano scrivibili:<sup>[[1]](#references)</sup>
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
Il problema in questi casi è che quei processi sono probabilmente già in esecuzione. Per identificare le DLL che i servizi tentano di caricare senza riuscirci, avvia Procmon il prima possibile (prima dell’avvio dei processi), quindi:

- **Crea** la cartella `C:\privesc_hijacking` e aggiungi il percorso `C:\privesc_hijacking` alla **variabile d’ambiente System Path**. Puoi farlo **manualmente** oppure con **PS**:
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
- Quindi **riavvia** il computer. Quando il computer viene riavviato, **`procmon`** inizierà a **registrare** gli eventi il prima possibile.
- Una volta **avviato Windows, esegui nuovamente `procmon`**. Ti informerà che era in esecuzione e ti **chiederà se vuoi salvare** gli eventi in un file. Rispondi **sì** e **salva gli eventi in un file**.
- **Dopo** che il **file** è stato **generato**, **chiudi** la finestra di **`procmon`** aperta e **apri il file degli eventi**.
- Aggiungi questi **filtri** per trovare tutte le DLL che un **processo ha tentato di caricare** dalla cartella writable System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging è richiesto solo per i servizi che si avviano troppo presto** per poterli osservare in altro modo. Se puoi **attivare il servizio/programma target on demand** (ad esempio interagendo con la sua interfaccia COM, riavviando il servizio o rilanciando un'attività pianificata), di solito è più rapido mantenere una normale cattura di Procmon con filtri come **`Path contains .dll`**, **`Result is NAME NOT FOUND`** e **`Path begins with <writable_machine_path>`**.

### DLL non rilevate

Eseguendo questa operazione su una **macchina Windows 11 virtuale (vmware) gratuita** ho ottenuto questi risultati:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

In questo caso, ignora i risultati relativi ai file `.exe`. Le richieste delle DLL mancanti provenivano da:

| Servizio                              | DLL                | Riga CMD                                                            |
| ------------------------------------- | ------------------ | ------------------------------------------------------------------- |
| Task Scheduler (Schedule)             | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`         |
| Diagnostic Policy Service (DPS)       | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                                   | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`               |

L'esempio seguente utilizza la tecnica descritta in questo articolo sull'[**abuso di `WptsExtensions.dll` per la privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Altri candidati che vale la pena analizzare

`WptsExtensions.dll` è un buon esempio, ma non è l'unica **phantom DLL** ricorrente che compare nei servizi privilegiati. Le regole moderne di hunting e i cataloghi pubblici di hijack continuano a monitorare nomi come:<sup>[[2]](#references)</sup>

| Servizio / Scenario | DLL mancante | Note |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Candidato classico **SYSTEM** sui sistemi client. Utile quando la directory writable si trova nel **Machine PATH** e il servizio cerca la DLL durante l'avvio. |
| NetMan su Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interessante nelle **edizioni server** perché il servizio viene eseguito come **SYSTEM** e in alcune build può essere **attivato on demand da un utente normale**, rendendolo migliore dei casi che richiedono solo un riavvio. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Di solito restituisce prima **`NT AUTHORITY\LOCAL SERVICE`**. Spesso è comunque sufficiente perché il token dispone di **`SeImpersonatePrivilege`**, consentendo di concatenarlo con [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Considera questi nomi come **indicazioni per il triage**, non come risultati garantiti: dipendono dalla **SKU/build** e Microsoft potrebbe modificare il comportamento tra una release e l'altra. Il punto importante è cercare **DLL mancanti nei servizi privilegiati che attraversano il Machine PATH**, soprattutto se il servizio può essere **riattivato senza riavviare il computer**.

### Exploitation

Per **eseguire la privilege escalation**, effettua l'hijack di **`WptsExtensions.dll`**. Una volta noti il **percorso** e il **nome**, genera la DLL malevola.

Puoi [**provare a usare uno qualsiasi di questi esempi**](#creating-and-compiling-dlls). Potresti eseguire payload come: ottenere una rev shell, aggiungere un utente, eseguire un beacon...

> [!WARNING]
> Nota che **non tutti i servizi vengono eseguiti** come **`NT AUTHORITY\SYSTEM`**. Alcuni vengono eseguiti come **`NT AUTHORITY\LOCAL SERVICE`**, che dispone di **meno privilegi**, quindi l'abuso di uno di questi servizi potrebbe non consentirti di creare un nuovo utente.\
> Tuttavia, quell'account dispone del diritto utente **`SeImpersonatePrivilege`**, quindi puoi usare la [**Potato suite per eseguire la privilege escalation**](../roguepotato-and-printspoofer.md). In questo caso, una reverse shell è un'opzione migliore rispetto al tentativo di creare un utente.

Al momento della stesura, il servizio **Task Scheduler** viene eseguito con **Nt AUTHORITY\SYSTEM**.

Dopo aver **generato la DLL malevola** (_nel mio caso ho usato una x64 rev shell e ho ottenuto una shell, ma Defender l'ha terminata perché proveniva da msfvenom_), salvala nel System Path writable con il nome **WptsExtensions.dll** e **riavvia** il computer (oppure riavvia il servizio o fai tutto ciò che è necessario per eseguire nuovamente il servizio/programma interessato).

Quando il servizio viene riavviato, la **DLL dovrebbe essere caricata ed eseguita** (puoi **riutilizzare** il trucco di **procmon** per verificare se la **libreria è stata caricata come previsto**).

## References

- [1] [Windows DLL Hijacking (si spera) chiarito](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [DLL sospetta caricata per la persistenza o la privilege escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
