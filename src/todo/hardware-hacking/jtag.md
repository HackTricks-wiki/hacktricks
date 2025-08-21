# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) è uno strumento che puoi caricare su un MCU compatibile con Arduino o (in via sperimentale) su un Raspberry Pi per forzare le pinout JTAG sconosciute e persino enumerare i registri delle istruzioni.

- Arduino: collega i pin digitali D2–D11 a un massimo di 10 pad/testpoint JTAG sospetti, e GND di Arduino a GND di destinazione. Alimenta il target separatamente a meno che tu non sappia che il rail è sicuro. Preferisci la logica a 3.3 V (ad es., Arduino Due) o utilizza un level shifter/resistori in serie quando sondi target a 1.8–3.3 V.
- Raspberry Pi: la build del Pi espone meno GPIO utilizzabili (quindi le scansioni sono più lente); controlla il repo per la mappa dei pin attuale e le limitazioni.

Una volta flashato, apri il monitor seriale a 115200 baud e invia `h` per aiuto. Flusso tipico:

- `l` trova loopback per evitare falsi positivi
- `r` attiva/disattiva pull-up interni se necessario
- `s` scansiona per TCK/TMS/TDI/TDO (e talvolta TRST/SRST)
- `y` forzatura IR per scoprire opcode non documentati
- `x` snapshot di boundary-scan degli stati dei pin

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

![](<../../images/image (774).png>)



Se viene trovato un TAP valido vedrai righe che iniziano con `FOUND!` indicando i pin scoperti.

Suggerimenti
- Condividi sempre il ground e non alimentare mai pin sconosciuti sopra il Vtref del target. In caso di dubbio, aggiungi resistori in serie da 100–470 Ω sui pin candidati.
- Se il dispositivo utilizza SWD/SWJ invece di JTAG a 4 fili, JTAGenum potrebbe non rilevarlo; prova strumenti SWD o un adattatore che supporta SWJ‑DP.

## Caccia ai pin più sicura e configurazione hardware

- Identifica prima Vtref e GND con un multimetro. Molti adattatori necessitano di Vtref per impostare la tensione I/O.
- Livellamento: preferisci level shifter bidirezionali progettati per segnali push‑pull (le linee JTAG non sono open‑drain). Evita level shifter I2C a direzione automatica per JTAG.
- Adattatori utili: schede FT2232H/FT232H (ad es., Tigard), CMSIS‑DAP, J‑Link, ST‑LINK (specifici del fornitore), ESP‑USB‑JTAG (su ESP32‑Sx). Collega almeno TCK, TMS, TDI, TDO, GND e Vtref; opzionalmente TRST e SRST.

## Primo contatto con OpenOCD (scansione e IDCODE)

OpenOCD è l'OSS de facto per JTAG/SWD. Con un adattatore supportato puoi scansionare la catena e leggere gli IDCODE:

- Esempio generico con un J‑Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 USB‑JTAG integrato (nessuna sonda esterna richiesta):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Note
- Se ottieni un IDCODE "tutti uno/zero", controlla il cablaggio, l'alimentazione, Vtref e che la porta non sia bloccata da fusibili/opzioni.
- Vedi OpenOCD low‑level `irscan`/`drscan` per interazione manuale TAP quando si attivano catene sconosciute.

## Fermare la CPU e scaricare la memoria/flash

Una volta che il TAP è riconosciuto e uno script di destinazione è scelto, puoi fermare il core e scaricare le regioni di memoria o la flash interna. Esempi (regola destinazione, indirizzi base e dimensioni):

- Destinazione generica dopo l'inizializzazione:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (preferire SBA quando disponibile):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programma o leggi tramite l'aiuto di OpenOCD:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Tips
- Usa `mdw/mdh/mdb` per controllare la memoria prima di dump lunghi.
- Per catene multi-dispositivo, imposta BYPASS su non-target o usa un file di scheda che definisce tutti i TAP.

## Trucchi di boundary-scan (EXTEST/SAMPLE)

Anche quando l'accesso al debug della CPU è bloccato, il boundary-scan potrebbe essere ancora esposto. Con UrJTAG/OpenOCD puoi:
- SAMPLE per acquisire gli stati dei pin mentre il sistema è in esecuzione (trovare attività del bus, confermare il mapping dei pin).
- EXTEST per pilotare i pin (ad esempio, bit-bangare le linee SPI flash esterne tramite l'MCU per leggerle offline se il cablaggio della scheda lo consente).

Flusso minimo di UrJTAG con un adattatore FT2232x:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Hai bisogno del BSDL del dispositivo per conoscere l'ordinamento dei bit del registro di confine. Fai attenzione che alcuni fornitori bloccano le celle di scansione del confine in produzione.

## Obiettivi moderni e note

- ESP32‑S3/C3 include un ponte USB‑JTAG nativo; OpenOCD può comunicare direttamente tramite USB senza una sonda esterna. Molto comodo per la triage e i dump.
- Il debug RISC‑V (v0.13+) è ampiamente supportato da OpenOCD; preferisci SBA per l'accesso alla memoria quando il core non può essere arrestato in modo sicuro.
- Molti MCU implementano l'autenticazione del debug e stati del ciclo di vita. Se JTAG sembra morto ma l'alimentazione è corretta, il dispositivo potrebbe essere fuso in uno stato chiuso o richiedere una sonda autenticata.

## Difese e indurimento (cosa aspettarsi su dispositivi reali)

- Disabilita o blocca permanentemente JTAG/SWD in produzione (ad es., STM32 RDP livello 2, ESP eFuses che disabilitano PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Richiedi debug autenticato (ARMv8.2‑A ADIv6 Debug Authentication, sfida-risposta gestita da OEM) mantenendo l'accesso alla produzione.
- Non instradare pad di test facili; seppellire via di test, rimuovere/popolare resistori per isolare TAP, utilizzare connettori con chiavi o fixture a pogo-pin.
- Blocco del debug all'accensione: controlla il TAP dietro il ROM iniziale che impone l'avvio sicuro.

## Riferimenti

- OpenOCD User’s Guide – JTAG Commands and configuration. https://openocd.org/doc-release/html/JTAG-Commands.html
- Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage). https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/

{{#include ../../banners/hacktricks-training.md}}
