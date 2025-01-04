# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione

Se hai scoperto che puoi **scrivere in una cartella di System Path** (nota che questo non funzionerà se puoi scrivere in una cartella di User Path) è possibile che tu possa **escalare i privilegi** nel sistema.

Per fare ciò puoi abusare di un **Dll Hijacking** dove andrai a **hijackare una libreria che viene caricata** da un servizio o processo con **più privilegi** dei tuoi, e poiché quel servizio sta caricando una Dll che probabilmente non esiste nemmeno nell'intero sistema, cercherà di caricarla dal System Path dove puoi scrivere.

Per ulteriori informazioni su **cosa è Dll Hijacking** controlla:

{{#ref}}
./
{{#endref}}

## Privesc con Dll Hijacking

### Trovare una Dll mancante

La prima cosa di cui hai bisogno è **identificare un processo** in esecuzione con **più privilegi** di te che sta cercando di **caricare una Dll dal System Path** in cui puoi scrivere.

Il problema in questi casi è che probabilmente quei processi sono già in esecuzione. Per trovare quali Dll mancano ai servizi devi avviare procmon il prima possibile (prima che i processi vengano caricati). Quindi, per trovare le .dll mancanti fai:

- **Crea** la cartella `C:\privesc_hijacking` e aggiungi il percorso `C:\privesc_hijacking` alla **variabile d'ambiente System Path**. Puoi farlo **manualmente** o con **PS**:
```powershell
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
- Poi, **riavvia**. Quando il computer si riavvia, **`procmon`** inizierà a **registrare** eventi il prima possibile.
- Una volta che **Windows** è **avviato, esegui di nuovo `procmon`**, ti dirà che è stato in esecuzione e ti **chiederà se vuoi memorizzare** gli eventi in un file. Rispondi **sì** e **memorizza gli eventi in un file**.
- **Dopo** che il **file** è stato **generato**, **chiudi** la finestra **`procmon`** aperta e **apri il file degli eventi**.
- Aggiungi questi **filtri** e troverai tutti i Dll che alcuni **processi hanno cercato di caricare** dalla cartella del System Path scrivibile:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Dll mancanti

Eseguendo questo su una **macchina virtuale (vmware) Windows 11** gratuita ho ottenuto questi risultati:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

In questo caso gli .exe sono inutili, quindi ignorali, le DLL mancanti erano da:

| Servizio                         | Dll                | Riga CMD                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Dopo aver trovato questo, ho trovato questo interessante post sul blog che spiega anche come [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Che è ciò che **faremo ora**.

### Sfruttamento

Quindi, per **escalare i privilegi** stiamo per hijackare la libreria **WptsExtensions.dll**. Avendo il **percorso** e il **nome** dobbiamo solo **generare la dll malevola**.

Puoi [**provare a usare uno di questi esempi**](#creating-and-compiling-dlls). Potresti eseguire payload come: ottenere una rev shell, aggiungere un utente, eseguire un beacon...

> [!WARNING]
> Nota che **non tutti i servizi vengono eseguiti** con **`NT AUTHORITY\SYSTEM`**, alcuni vengono eseguiti anche con **`NT AUTHORITY\LOCAL SERVICE`** che ha **meno privilegi** e **non sarai in grado di creare un nuovo utente** abusando delle sue autorizzazioni.\
> Tuttavia, quell'utente ha il privilegio **`seImpersonate`**, quindi puoi usare il [**potato suite per escalare i privilegi**](../roguepotato-and-printspoofer.md). Quindi, in questo caso una rev shell è una migliore opzione rispetto a cercare di creare un utente.

Al momento della scrittura, il servizio **Task Scheduler** è eseguito con **Nt AUTHORITY\SYSTEM**.

Avendo **generato la Dll malevola** (_nel mio caso ho usato una rev shell x64 e ho ottenuto una shell di ritorno ma Defender l'ha uccisa perché proveniva da msfvenom_), salvala nel System Path scrivibile con il nome **WptsExtensions.dll** e **riavvia** il computer (o riavvia il servizio o fai tutto il necessario per rieseguire il servizio/programma interessato).

Quando il servizio viene riavviato, la **dll dovrebbe essere caricata ed eseguita** (puoi **riutilizzare** il trucco **procmon** per controllare se la **libreria è stata caricata come previsto**).

{{#include ../../../banners/hacktricks-training.md}}
