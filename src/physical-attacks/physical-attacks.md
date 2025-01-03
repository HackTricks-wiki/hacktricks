# Attacchi Fisici

{{#include ../banners/hacktricks-training.md}}

## Recupero della Password del BIOS e Sicurezza del Sistema

**Ripristinare il BIOS** può essere realizzato in diversi modi. La maggior parte delle schede madri include una **batteria** che, se rimossa per circa **30 minuti**, ripristinerà le impostazioni del BIOS, inclusa la password. In alternativa, un **jumper sulla scheda madre** può essere regolato per ripristinare queste impostazioni collegando pin specifici.

Per situazioni in cui le regolazioni hardware non sono possibili o pratiche, gli **strumenti software** offrono una soluzione. Eseguire un sistema da un **Live CD/USB** con distribuzioni come **Kali Linux** fornisce accesso a strumenti come **_killCmos_** e **_CmosPWD_**, che possono assistere nel recupero della password del BIOS.

Nei casi in cui la password del BIOS è sconosciuta, inserirla in modo errato **tre volte** di solito comporta un codice di errore. Questo codice può essere utilizzato su siti web come [https://bios-pw.org](https://bios-pw.org) per potenzialmente recuperare una password utilizzabile.

### Sicurezza UEFI

Per i sistemi moderni che utilizzano **UEFI** invece del tradizionale BIOS, lo strumento **chipsec** può essere utilizzato per analizzare e modificare le impostazioni UEFI, inclusa la disabilitazione del **Secure Boot**. Questo può essere realizzato con il seguente comando:

`python chipsec_main.py -module exploits.secure.boot.pk`

### Analisi della RAM e Attacchi Cold Boot

La RAM conserva i dati brevemente dopo che l'alimentazione è stata interrotta, di solito per **1-2 minuti**. Questa persistenza può essere estesa a **10 minuti** applicando sostanze fredde, come l'azoto liquido. Durante questo periodo prolungato, è possibile creare un **memory dump** utilizzando strumenti come **dd.exe** e **volatility** per l'analisi.

### Attacchi Direct Memory Access (DMA)

**INCEPTION** è uno strumento progettato per la **manipolazione della memoria fisica** tramite DMA, compatibile con interfacce come **FireWire** e **Thunderbolt**. Consente di bypassare le procedure di accesso patchando la memoria per accettare qualsiasi password. Tuttavia, è inefficace contro i sistemi **Windows 10**.

### Live CD/USB per Accesso al Sistema

Modificare i binari di sistema come **_sethc.exe_** o **_Utilman.exe_** con una copia di **_cmd.exe_** può fornire un prompt dei comandi con privilegi di sistema. Strumenti come **chntpw** possono essere utilizzati per modificare il file **SAM** di un'installazione di Windows, consentendo cambiamenti di password.

**Kon-Boot** è uno strumento che facilita l'accesso ai sistemi Windows senza conoscere la password, modificando temporaneamente il kernel di Windows o UEFI. Maggiori informazioni possono essere trovate su [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Gestione delle Funzionalità di Sicurezza di Windows

#### Scorciatoie per Avvio e Ripristino

- **Supr**: Accedi alle impostazioni del BIOS.
- **F8**: Entra in modalità di ripristino.
- Premere **Shift** dopo il banner di Windows può bypassare l'autologon.

#### Dispositivi BAD USB

Dispositivi come **Rubber Ducky** e **Teensyduino** fungono da piattaforme per creare dispositivi **bad USB**, capaci di eseguire payload predefiniti quando collegati a un computer target.

#### Volume Shadow Copy

I privilegi di amministratore consentono la creazione di copie di file sensibili, incluso il file **SAM**, tramite PowerShell.

### Bypassare la Crittografia BitLocker

La crittografia BitLocker può potenzialmente essere bypassata se la **password di recupero** viene trovata all'interno di un file di memory dump (**MEMORY.DMP**). Strumenti come **Elcomsoft Forensic Disk Decryptor** o **Passware Kit Forensic** possono essere utilizzati a questo scopo.

### Ingegneria Sociale per Aggiunta della Chiave di Recupero

Una nuova chiave di recupero BitLocker può essere aggiunta attraverso tattiche di ingegneria sociale, convincendo un utente a eseguire un comando che aggiunge una nuova chiave di recupero composta da zeri, semplificando così il processo di decrittazione.

{{#include ../banners/hacktricks-training.md}}
