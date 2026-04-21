# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione

Se hai scoperto di poter **scrivere in una cartella del System Path** (nota che questo non funzionerà se puoi scrivere in una cartella del User Path), è possibile che tu possa **escalare i privilegi** nel sistema.

Per farlo puoi abusare di un **Dll Hijacking**, in cui andrai a **hijackare una library in fase di caricamento** da parte di un service o process con **più privilegi** dei tuoi, e poiché quel service sta caricando una Dll che probabilmente non esiste nemmeno nell'intero sistema, proverà a caricarla dal System Path in cui puoi scrivere.

Per maggiori info su **cos'è il Dll Hijackig** controlla:


{{#ref}}
./
{{#endref}}

## Privesc con Dll Hijacking

### Trovare una Dll mancante

La prima cosa di cui hai bisogno è **identificare un process** in esecuzione con **più privilegi** dei tuoi che sta cercando di **caricare una Dll dal System Path** in cui puoi scrivere.

Ricorda che questa tecnica dipende da una voce **Machine/System PATH**, non solo dal tuo **User PATH**. Quindi, prima di perdere tempo con Procmon, conviene enumerare le voci del **Machine PATH** e verificare quali sono scrivibili:
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
Il problema in questi casi è che probabilmente quei processi sono già in esecuzione. Per trovare quali Dll mancano ai servizi, devi avviare procmon il prima possibile (prima che i processi vengano caricati). Quindi, per trovare le .dll mancanti fai così:

- **Crea** la cartella `C:\privesc_hijacking` e aggiungi il path `C:\privesc_hijacking` alla **variabile di ambiente System Path**. Puoi farlo **manualmente** oppure con **PS**:
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
- Avvia **`procmon`** e vai su **`Options`** --> **`Enable boot logging`** e premi **`OK`** nel prompt.
- Poi, **riavvia**. Quando il computer viene riavviato **`procmon`** inizierà a **registrare** gli eventi il prima possibile.
- Una volta che **Windows** è **avviato esegui `procmon`** di nuovo, ti dirà che è stato in esecuzione e ti **chiederà se vuoi salvare** gli eventi in un file. Rispondi **yes** e **salva gli eventi in un file**.
- **Dopo** che il **file** è stato **generato**, **chiudi** la finestra aperta di **`procmon`** e **apri il file degli eventi**.
- Aggiungi questi **filtri** e troverai tutte le Dll che qualche **processo ha cercato di caricare** dalla cartella writable System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Il boot logging è necessario solo per i servizi che si avviano troppo presto** per poterli osservare altrimenti. Se puoi **attivare il servizio/program target on demand** (per esempio, interagendo con la sua interfaccia COM, riavviando il servizio o rilanciando un task pianificato), di solito è più veloce mantenere una normale cattura di Procmon con filtri come **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, e **`Path begins with <writable_machine_path>`**.

### Missed Dlls

Eseguendo questo in una free **virtual (vmware) Windows 11 machine** ho ottenuto questi risultati:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

In questo caso gli .exe sono inutili quindi ignorali, le DLL mancanti erano:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Dopo aver trovato questo, ho trovato questo interessante post sul blog che spiega anche come [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Ed è quello che **faremo ora**.

### Other candidates worth triaging

`WptsExtensions.dll` è un buon esempio, ma non è l’unico **phantom DLL** ricorrente che compare nei servizi privilegiati. Le regole moderne di hunting e i cataloghi pubblici di hijack tracciano ancora nomi come:

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Classico candidato **SYSTEM** sui sistemi client. Utile quando la directory writable si trova nel **Machine PATH** e il servizio verifica la DLL durante l’avvio. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interessante sulle **server editions** perché il servizio gira come **SYSTEM** e può essere **attivato on demand da un utente normale** in alcune build, rendendolo migliore dei casi che richiedono solo il riavvio. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Di solito produce prima **`NT AUTHORITY\LOCAL SERVICE`**. Spesso è ancora sufficiente perché il token ha **`SeImpersonatePrivilege`**, quindi puoi concatenarlo con [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Considera questi nomi come **indizi di triage**, non come vittorie garantite: dipendono da **SKU/build**, e Microsoft può cambiare il comportamento tra una release e l’altra. Il punto importante è cercare **DLL mancanti in servizi privilegiati che attraversano il Machine PATH**, soprattutto se il servizio può essere **riattivato senza riavviare**.

### Exploitation

Quindi, per **escalate privileges** andremo a hijackare la libreria **WptsExtensions.dll**. Avendo il **path** e il **nome** ci basta **generare la dll malevola**.

Puoi [**provare a usare uno qualsiasi di questi esempi**](#creating-and-compiling-dlls). Potresti eseguire payload come: ottenere una rev shell, aggiungere un utente, eseguire un beacon...

> [!WARNING]
> Nota che **non tutti i service vengono eseguiti** con **`NT AUTHORITY\SYSTEM`** alcuni vengono eseguiti anche con **`NT AUTHORITY\LOCAL SERVICE`** che ha **meno privilegi** e non potrai creare un nuovo utente abusando dei suoi permessi.\
> Tuttavia, quell’utente ha il privilegio **`seImpersonate`**, quindi puoi usare la [**potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). Quindi, in questo caso una rev shell è un’opzione migliore che provare a creare un utente.

Al momento della stesura, il servizio **Task Scheduler** viene eseguito con **Nt AUTHORITY\SYSTEM**.

Dopo aver **generato la Dll malevola** (_nel mio caso ho usato una x64 rev shell e ho ottenuto una shell, ma defender l’ha uccisa perché proveniva da msfvenom_), salvala nel writable System Path con il nome **WptsExtensions.dll** e **riavvia** il computer (o riavvia il servizio o fai tutto ciò che serve per rieseguire il servizio/programma interessato).

Quando il servizio viene riavviato, la **dll dovrebbe essere caricata ed eseguita** (puoi **riutilizzare** il trucco di **procmon** per verificare se la **libreria è stata caricata come previsto**).

## References

- [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)

{{#include ../../../banners/hacktricks-training.md}}
