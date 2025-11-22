# Sys Path scrivibile +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione

Se scopri di poter **scrivere in una cartella del System Path** (nota che questo non funzionerà se puoi scrivere in una cartella del User Path) è possibile che tu possa **ottenere privilegi più elevati** nel sistema.

Per farlo puoi abusare di una **Dll Hijacking** in cui andrai a **dirottare una libreria caricata** da un servizio o processo con **privilegi maggiori** dei tuoi, e dato che quel servizio sta caricando una Dll che probabilmente non esiste nemmeno nell'intero sistema, cercherà di caricarla dal System Path dove puoi scrivere.

Per maggiori informazioni su **che cos'è Dll Hijackig** consulta:


{{#ref}}
./
{{#endref}}

## Privesc con Dll Hijacking

### Trovare una Dll mancante

La prima cosa da fare è **identificare un processo** in esecuzione con **privilegi maggiori** dei tuoi che sta cercando di **caricare una Dll dal System Path** in cui puoi scrivere.

Il problema in questi casi è che probabilmente quei processi sono già in esecuzione. Per trovare quali Dll mancano nei servizi devi avviare procmon il prima possibile (prima che i processi vengano caricati). Quindi, per trovare le .dll mancanti fai:

- **Crea** la cartella `C:\privesc_hijacking` e aggiungi il percorso `C:\privesc_hijacking` alla **System Path env variable**. Puoi farlo **manualmente** o con **PS**:
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
- Poi, **riavvia**. Quando il computer si riavvia **`procmon`** inizierà a **registrare** gli eventi il prima possibile.
- Una volta che **Windows** è avviato, esegui di nuovo **`procmon`**; ti dirà che è in esecuzione e ti **chiederà se vuoi salvare** gli eventi in un file. Rispondi **yes** e **salva gli eventi in un file**.
- **After** il **file** è **generated**, **close** la finestra aperta di **`procmon`** e **open the events file**.
- Aggiungi questi **filters** e troverai tutte le Dll che qualche **proccess tried to load** dalla cartella del writable System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Dll mancanti

Eseguendo questo in una macchina virtuale (vmware) Windows 11 gratuita ho ottenuto questi risultati:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

In questo caso i .exe sono inutili quindi ignorali, le DLL mancanti provenivano da:

| Servizio                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

After finding this, I found this interesting blog post that also explains how to [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Which is what we **are going to do now**.

### Sfruttamento

Quindi, per **escalate privileges** andremo a hijackare la libreria **WptsExtensions.dll**. Avendo il **path** e il **nome** dobbiamo solo **generate the malicious dll**.

You can [**try to use any of these examples**](#creating-and-compiling-dlls). You could run payloads such as: get a rev shell, add a user, execute a beacon...

> [!WARNING]
> Nota che **non tutti i servizi vengono eseguiti** con **`NT AUTHORITY\SYSTEM`**; alcuni vengono eseguiti con **`NT AUTHORITY\LOCAL SERVICE`** che ha **meno privilegi** e **non potrai creare un nuovo utente** abusando di quei permessi.\
> Tuttavia, quell'utente ha il privilegio **`seImpersonate`**, quindi puoi usare la [ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). Quindi, in questo caso, un rev shell è una opzione migliore rispetto a provare a creare un utente.

Al momento della stesura il servizio **Task Scheduler** è eseguito con **Nt AUTHORITY\SYSTEM**.

Dopo aver **generated the malicious Dll** (_nel mio caso ho usato x64 rev shell e ho ottenuto una shell ma defender l'ha uccisa perché era generata con msfvenom_), salvala nel writable System Path con il nome **WptsExtensions.dll** e **restart** il computer (o riavvia il servizio o fai quello che serve per rieseguire il servizio/programa interessato).

Quando il servizio viene riavviato, la **dll dovrebbe essere caricata ed eseguita** (puoi **reuse** il trucco di **procmon** per verificare se la **library was loaded as expected**).

{{#include ../../../banners/hacktricks-training.md}}
