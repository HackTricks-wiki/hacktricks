# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione

Se hai scoperto di poter **scrivere in una cartella del System Path** (nota che questo non funzionerà se puoi scrivere in una cartella del User Path), è possibile che tu possa **escalare i privilegi** nel sistema.

Per farlo, puoi sfruttare un **Dll Hijacking** con cui andrai a **dirottare una libreria in fase di caricamento** da parte di un service o process con **più privilegi** dei tuoi; inoltre, poiché quel service sta caricando una Dll che probabilmente non esiste nemmeno nell'intero sistema, tenterà di caricarla dal System Path, dove puoi scrivere.

Per maggiori informazioni su **cos'è il Dll Hijackig**, consulta:


{{#ref}}
./
{{#endref}}

## Privesc con Dll Hijacking

### Individuazione di una Dll mancante

La prima cosa di cui hai bisogno è **identificare un process** in esecuzione con **più privilegi** dei tuoi, che stia tentando di **caricare una Dll dal System Path** in cui puoi scrivere.

Ricorda che questa tecnica dipende da una voce del **Machine/System PATH**, non soltanto dal tuo **User PATH**. Pertanto, prima di dedicare tempo a Procmon, vale la pena enumerare le voci del **Machine PATH** e verificare quali siano scrivibili:<sup>[[1]](#references)</sup>
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
Il problema in questi casi è che probabilmente quei processi sono già in esecuzione. Per trovare quali DLL mancano ai servizi, devi avviare procmon il prima possibile (prima che i processi vengano caricati). Quindi, per trovare i .dll mancanti:

- **Crea** la cartella `C:\privesc_hijacking` e aggiungi il percorso `C:\privesc_hijacking` alla **variabile d'ambiente System Path**. Puoi farlo **manualmente** o con **PS**:
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
- Avvia **`procmon`** e vai su **`Options`** --> **`Enable boot logging`**, quindi premi **`OK`** nel prompt.
- Poi, **riavvia**. Quando il computer viene riavviato, **`procmon`** inizierà a **registrare** gli eventi il prima possibile.
- Una volta avviato **Windows**, esegui nuovamente **`procmon`**: ti dirà che è stato in esecuzione e ti **chiederà se vuoi salvare** gli eventi in un file. Rispondi **sì** e **salva gli eventi in un file**.
- **Dopo** che il **file** è stato **generato**, chiudi la finestra **`procmon`** aperta e **apri il file degli eventi**.
- Aggiungi questi **filtri** e troverai tutte le DLL che un **processo ha provato a caricare** dalla cartella System Path scrivibile:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** è necessario solo per i servizi che si avviano troppo presto per poterli osservare in altro modo. Se puoi **attivare il servizio/programma target on demand** (ad esempio interagendo con la sua interfaccia COM, riavviando il servizio o rilanciando un task pianificato), di solito è più veloce mantenere una normale acquisizione di Procmon con filtri come **`Path contains .dll`**, **`Result is NAME NOT FOUND`** e **`Path begins with <writable_machine_path>`**.

### DLL non rilevate

Eseguendo questa procedura su una **macchina Windows 11 virtuale (VMware) gratuita**, ho ottenuto questi risultati:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

In questo caso i file .exe sono inutili, quindi ignorali; le DLL non rilevate provenivano da:

| Servizio                       | DLL                | Riga CMD                                                            |
| ----------------------------- | ------------------ | ------------------------------------------------------------------- |
| Task Scheduler (Schedule)     | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`         |
| Diagnostic Policy Service (DPS) | Unknown.DLL      | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                           | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`               |

Dopo averlo scoperto, ho trovato questo interessante post sul blog che spiega anche come [**abusare di WptsExtensions.dll per fare privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Ed è proprio ciò che **faremo ora**.<sup>[[3]](#references)</sup>

### Altri candidati che vale la pena analizzare

`WptsExtensions.dll` è un buon esempio, ma non è l'unica **phantom DLL** ricorrente che compare nei servizi privilegiati. Le regole moderne di hunting e i cataloghi pubblici di hijacking continuano a monitorare nomi come:<sup>[[2]](#references)</sup>

| Servizio / Scenario | DLL mancante | Note |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Candidato classico con privilegi **SYSTEM** sui sistemi client. Utile quando la directory scrivibile si trova nel **Machine PATH** e il servizio cerca la DLL durante l'avvio. |
| NetMan su Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interessante nelle **edizioni server** perché il servizio viene eseguito come **SYSTEM** e, in alcune build, può essere **attivato on demand da un utente normale**, rendendolo migliore dei casi che richiedono solo un riavvio. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Di solito restituisce inizialmente **`NT AUTHORITY\LOCAL SERVICE`**. Spesso è comunque sufficiente perché il token dispone di **`SeImpersonatePrivilege`**, quindi puoi concatenarlo con [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Considera questi nomi come **indicazioni per il triage**, non come risultati garantiti: dipendono dalla **SKU/build** e Microsoft potrebbe modificarne il comportamento tra una release e l'altra. L'aspetto importante è cercare **DLL mancanti nei servizi privilegiati che attraversano il Machine PATH**, soprattutto se il servizio può essere **riattivato senza riavviare il computer**.

### Exploitation

Quindi, per **escalare i privilegi**, faremo hijacking della libreria **WptsExtensions.dll**. Avendo il **percorso** e il **nome**, dobbiamo solo **generare la DLL malevola**.

Puoi [**provare a usare uno qualsiasi di questi esempi**](#creating-and-compiling-dlls). Potresti eseguire payload come: ottenere una rev shell, aggiungere un utente, eseguire un beacon...

> [!WARNING]
> Nota che **non tutti i servizi vengono eseguiti** con **`NT AUTHORITY\SYSTEM`**; alcuni vengono eseguiti anche con **`NT AUTHORITY\LOCAL SERVICE`**, che ha **meno privilegi**, e **non potrai creare un nuovo utente** abusando dei suoi permessi.\
> Tuttavia, questo utente dispone del privilegio **`seImpersonate`**, quindi puoi usare la[ **potato suite per escalare i privilegi**](../roguepotato-and-printspoofer.md). In questo caso, quindi, una rev shell è un'opzione migliore rispetto al tentativo di creare un utente.

Al momento della stesura, il servizio **Task Scheduler** viene eseguito con **Nt AUTHORITY\SYSTEM**.

Dopo aver **generato la DLL malevola** (_nel mio caso ho usato una rev shell x64 e ho ottenuto una shell, ma Defender l'ha terminata perché proveniva da msfvenom_), salvala nel System Path scrivibile con il nome **WptsExtensions.dll** e **riavvia** il computer (oppure riavvia il servizio o fai tutto il necessario per eseguire nuovamente il servizio/programma interessato).

Quando il servizio viene riavviato, la **DLL dovrebbe essere caricata ed eseguita** (puoi **riutilizzare** il trucco di **procmon** per verificare che la **libreria sia stata caricata come previsto**).

## Riferimenti

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)

{{#include ../../../banners/hacktricks-training.md}}
