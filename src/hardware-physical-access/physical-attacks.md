# Attacchi Fisici

{{#include ../banners/hacktricks-training.md}}

## Recupero della Password del BIOS e Sicurezza del Sistema

**Ripristinare il BIOS** può essere realizzato in diversi modi. La maggior parte delle schede madri include una **batteria** che, se rimossa per circa **30 minuti**, ripristinerà le impostazioni del BIOS, inclusa la password. In alternativa, un **jumper sulla scheda madre** può essere regolato per ripristinare queste impostazioni collegando pin specifici.

Per situazioni in cui le regolazioni hardware non sono possibili o pratiche, **strumenti software** offrono una soluzione. Eseguire un sistema da un **Live CD/USB** con distribuzioni come **Kali Linux** fornisce accesso a strumenti come **_killCmos_** e **_CmosPWD_**, che possono assistere nel recupero della password del BIOS.

Nei casi in cui la password del BIOS è sconosciuta, inserirla in modo errato **tre volte** di solito comporta un codice di errore. Questo codice può essere utilizzato su siti web come [https://bios-pw.org](https://bios-pw.org) per potenzialmente recuperare una password utilizzabile.

### Sicurezza UEFI

Per i sistemi moderni che utilizzano **UEFI** invece del tradizionale BIOS, lo strumento **chipsec** può essere utilizzato per analizzare e modificare le impostazioni UEFI, inclusa la disabilitazione del **Secure Boot**. Questo può essere realizzato con il seguente comando:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Analisi della RAM e Attacchi Cold Boot

La RAM conserva i dati brevemente dopo che l'alimentazione è stata interrotta, di solito per **1-2 minuti**. Questa persistenza può essere estesa a **10 minuti** applicando sostanze fredde, come l'azoto liquido. Durante questo periodo prolungato, è possibile creare un **memory dump** utilizzando strumenti come **dd.exe** e **volatility** per l'analisi.

---

## Attacchi Direct Memory Access (DMA)

**INCEPTION** è uno strumento progettato per la **manipolazione della memoria fisica** tramite DMA, compatibile con interfacce come **FireWire** e **Thunderbolt**. Consente di bypassare le procedure di accesso patchando la memoria per accettare qualsiasi password. Tuttavia, è inefficace contro i sistemi **Windows 10**.

---

## Live CD/USB per Accesso al Sistema

Cambiare i file binari di sistema come **_sethc.exe_** o **_Utilman.exe_** con una copia di **_cmd.exe_** può fornire un prompt dei comandi con privilegi di sistema. Strumenti come **chntpw** possono essere utilizzati per modificare il file **SAM** di un'installazione di Windows, consentendo cambi di password.

**Kon-Boot** è uno strumento che facilita l'accesso ai sistemi Windows senza conoscere la password, modificando temporaneamente il kernel di Windows o UEFI. Maggiori informazioni possono essere trovate su [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Gestione delle Funzionalità di Sicurezza di Windows

### Scorciatoie di Avvio e Ripristino

- **Supr**: Accedi alle impostazioni del BIOS.
- **F8**: Entra in modalità di ripristino.
- Premere **Shift** dopo il banner di Windows può bypassare l'autologon.

### Dispositivi BAD USB

Dispositivi come **Rubber Ducky** e **Teensyduino** fungono da piattaforme per creare dispositivi **bad USB**, capaci di eseguire payload predefiniti quando collegati a un computer target.

### Volume Shadow Copy

I privilegi di amministratore consentono la creazione di copie di file sensibili, incluso il file **SAM**, tramite PowerShell.

---

## Bypassare la Crittografia BitLocker

La crittografia BitLocker può potenzialmente essere bypassata se la **password di recupero** viene trovata all'interno di un file di memory dump (**MEMORY.DMP**). Strumenti come **Elcomsoft Forensic Disk Decryptor** o **Passware Kit Forensic** possono essere utilizzati a questo scopo.

---

## Ingegneria Sociale per Aggiungere una Chiave di Recupero

Una nuova chiave di recupero BitLocker può essere aggiunta attraverso tattiche di ingegneria sociale, convincendo un utente a eseguire un comando che aggiunge una nuova chiave di recupero composta da zeri, semplificando così il processo di decrittazione.

---

## Sfruttare gli Interruttori di Intrusione del Chassis / Manutenzione per Ripristinare il BIOS alle Impostazioni di Fabbrica

Molti laptop moderni e desktop di piccole dimensioni includono un **interruttore di intrusione del chassis** che è monitorato dal Controller Integrato (EC) e dal firmware BIOS/UEFI. Sebbene lo scopo principale dell'interruttore sia quello di sollevare un allerta quando un dispositivo viene aperto, i fornitori a volte implementano una **scorciatoia di recupero non documentata** che viene attivata quando l'interruttore viene attivato in un determinato schema.

### Come Funziona l'Attacco

1. L'interruttore è collegato a un **interruzione GPIO** sull'EC.
2. Il firmware in esecuzione sull'EC tiene traccia del **tempo e del numero di pressioni**.
3. Quando viene riconosciuto uno schema hard-coded, l'EC invoca una routine di *reset della scheda madre* che **cancella il contenuto della NVRAM/CMOS di sistema**.
4. Al successivo avvio, il BIOS carica i valori predefiniti – **la password di supervisore, le chiavi di Secure Boot e tutte le configurazioni personalizzate vengono cancellate**.

> Una volta disabilitato Secure Boot e rimossa la password del firmware, l'attaccante può semplicemente avviare qualsiasi immagine di OS esterna e ottenere accesso illimitato ai dischi interni.

### Esempio Reale – Laptop Framework 13

La scorciatoia di recupero per il Framework 13 (11a/12a/13a generazione) è:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Dopo il decimo ciclo, l'EC imposta un flag che istruisce il BIOS a cancellare l'NVRAM al prossimo riavvio. L'intera procedura richiede ~40 s e richiede **nient'altro che un cacciavite**.

### Procedura di Sfruttamento Generica

1. Accendere o sospendere-ripristinare il target in modo che l'EC sia in esecuzione.
2. Rimuovere il coperchio inferiore per esporre l'interruttore di intrusione/manutenzione.
3. Riprodurre il pattern di attivazione specifico del fornitore (consultare la documentazione, i forum o fare reverse-engineering del firmware dell'EC).
4. Rimontare e riavviare – le protezioni del firmware dovrebbero essere disabilitate.
5. Avviare una USB live (ad es. Kali Linux) e eseguire le consuete operazioni post-sfruttamento (dumping delle credenziali, esfiltrazione dei dati, impianto di binari EFI malevoli, ecc.).

### Rilevamento e Mitigazione

* Registrare gli eventi di intrusione del telaio nella console di gestione del sistema operativo e correlare con i riavvii imprevisti del BIOS.
* Utilizzare **sigilli a prova di manomissione** su viti/coperchi per rilevare l'apertura.
* Tenere i dispositivi in **aree fisicamente controllate**; assumere che l'accesso fisico equivalga a una compromissione totale.
* Dove disponibile, disabilitare la funzione di "reset dell'interruttore di manutenzione" del fornitore o richiedere un'ulteriore autorizzazione crittografica per i reset dell'NVRAM.

---

## Riferimenti

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Guida al Reset della Scheda Madre](https://framewiki.net/guides/mainboard-reset)

{{#include ../banners/hacktricks-training.md}}
