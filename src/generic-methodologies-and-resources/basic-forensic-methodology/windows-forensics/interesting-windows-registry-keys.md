# Chiavi di Registro di Windows Interessanti

### Chiavi di Registro di Windows Interessanti

{{#include ../../../banners/hacktricks-training.md}}

### **Informazioni sulla Versione di Windows e Proprietario**

- Situato in **`Software\Microsoft\Windows NT\CurrentVersion`**, troverai la versione di Windows, il Service Pack, l'orario di installazione e il nome del proprietario registrato in modo chiaro.

### **Nome del Computer**

- Il nome host si trova sotto **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Impostazione del Fuso Orario**

- Il fuso orario del sistema è memorizzato in **`System\ControlSet001\Control\TimeZoneInformation`**.

### **Tracciamento del Tempo di Accesso**

- Per impostazione predefinita, il tracciamento dell'ultimo tempo di accesso è disattivato (**`NtfsDisableLastAccessUpdate=1`**). Per abilitarlo, usa:
`fsutil behavior set disablelastaccess 0`

### Versioni di Windows e Service Pack

- La **versione di Windows** indica l'edizione (ad es., Home, Pro) e la sua release (ad es., Windows 10, Windows 11), mentre i **Service Pack** sono aggiornamenti che includono correzioni e, a volte, nuove funzionalità.

### Abilitazione del Tempo di Accesso

- Abilitare il tracciamento dell'ultimo tempo di accesso consente di vedere quando i file sono stati aperti per l'ultima volta, il che può essere fondamentale per l'analisi forense o il monitoraggio del sistema.

### Dettagli sulle Informazioni di Rete

- Il registro contiene dati estesi sulle configurazioni di rete, inclusi **tipi di reti (wireless, cavo, 3G)** e **categorie di rete (Pubblica, Privata/Casa, Dominio/Lavoro)**, che sono vitali per comprendere le impostazioni di sicurezza della rete e i permessi.

### Caching Lato Client (CSC)

- **CSC** migliora l'accesso ai file offline memorizzando copie di file condivisi. Diverse impostazioni di **CSCFlags** controllano come e quali file vengono memorizzati nella cache, influenzando le prestazioni e l'esperienza dell'utente, specialmente in ambienti con connettività intermittente.

### Programmi di Avvio Automatico

- I programmi elencati in varie chiavi di registro `Run` e `RunOnce` vengono avviati automaticamente all'avvio, influenzando il tempo di avvio del sistema e potenzialmente essendo punti di interesse per identificare malware o software indesiderato.

### Shellbags

- **Shellbags** non solo memorizzano le preferenze per le visualizzazioni delle cartelle, ma forniscono anche prove forensi di accesso alle cartelle anche se la cartella non esiste più. Sono inestimabili per le indagini, rivelando l'attività dell'utente che non è ovvia attraverso altri mezzi.

### Informazioni e Forense USB

- I dettagli memorizzati nel registro sui dispositivi USB possono aiutare a tracciare quali dispositivi sono stati collegati a un computer, potenzialmente collegando un dispositivo a trasferimenti di file sensibili o incidenti di accesso non autorizzato.

### Numero di Serie del Volume

- Il **Numero di Serie del Volume** può essere cruciale per tracciare l'istanza specifica di un file system, utile in scenari forensi in cui è necessario stabilire l'origine del file su diversi dispositivi.

### **Dettagli di Spegnimento**

- L'orario di spegnimento e il conteggio (quest'ultimo solo per XP) sono conservati in **`System\ControlSet001\Control\Windows`** e **`System\ControlSet001\Control\Watchdog\Display`**.

### **Configurazione di Rete**

- Per informazioni dettagliate sull'interfaccia di rete, fare riferimento a **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**.
- I tempi di connessione di rete, inclusi i collegamenti VPN, sono registrati sotto vari percorsi in **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**.

### **Cartelle Condivise**

- Le cartelle condivise e le impostazioni si trovano in **`System\ControlSet001\Services\lanmanserver\Shares`**. Le impostazioni di Caching Lato Client (CSC) determinano la disponibilità dei file offline.

### **Programmi che Si Avviano Automaticamente**

- Percorsi come **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** e voci simili sotto `Software\Microsoft\Windows\CurrentVersion` dettagliano i programmi impostati per avviarsi all'avvio.

### **Ricerche e Percorsi Digitati**

- Le ricerche di Explorer e i percorsi digitati sono tracciati nel registro sotto **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** per WordwheelQuery e TypedPaths, rispettivamente.

### **Documenti Recenti e File di Office**

- I documenti recenti e i file di Office accessibili sono annotati in `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` e percorsi specifici della versione di Office.

### **Elementi Utilizzati di Recente (MRU)**

- Le liste MRU, che indicano i percorsi e i comandi dei file recenti, sono memorizzate in varie sottochiavi `ComDlg32` e `Explorer` sotto `NTUSER.DAT`.

### **Tracciamento dell'Attività Utente**

- La funzione User Assist registra statistiche dettagliate sull'uso delle applicazioni, inclusi il conteggio delle esecuzioni e l'ora dell'ultima esecuzione, in **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**.

### **Analisi delle Shellbags**

- Le shellbags, che rivelano dettagli sull'accesso alle cartelle, sono memorizzate in `USRCLASS.DAT` e `NTUSER.DAT` sotto `Software\Microsoft\Windows\Shell`. Usa **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** per l'analisi.

### **Storia dei Dispositivi USB**

- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** e **`HKLM\SYSTEM\ControlSet001\Enum\USB`** contengono dettagli ricchi sui dispositivi USB collegati, inclusi produttore, nome del prodotto e timestamp di connessione.
- L'utente associato a un dispositivo USB specifico può essere individuato cercando nei registri `NTUSER.DAT` per il **{GUID}** del dispositivo.
- L'ultimo dispositivo montato e il suo numero di serie del volume possono essere tracciati attraverso `System\MountedDevices` e `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`, rispettivamente.

Questa guida riassume i percorsi e i metodi cruciali per accedere a informazioni dettagliate su sistema, rete e attività utente sui sistemi Windows, puntando alla chiarezza e all'usabilità.

{{#include ../../../banners/hacktricks-training.md}}
