# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) è uno strumento che puoi caricare su un MCU compatibile con Arduino o, in via sperimentale, su un Raspberry Pi per eseguire il brute-force di pinout JTAG sconosciuti e persino enumerare i registri delle istruzioni.

- Arduino: collega i pin digitali D2–D11 a un massimo di 10 pad/testpoint JTAG sospetti e il pin GND di Arduino al GND del target. Alimenta il target separatamente, a meno che tu non sappia che la rail sia sicura. Preferisci una logica a 3,3 V (ad esempio Arduino Due) oppure usa un level shifter/resistenze in serie quando esegui il probing di target a 1,8–3,3 V.
- Raspberry Pi: la build per Pi espone meno GPIO utilizzabili (quindi le scansioni sono più lente); controlla il repository per la mappatura dei pin e i vincoli attuali.

Dopo il flashing, apri il monitor seriale a 115200 baud e invia `h` per visualizzare l'help. Flusso tipico:

- `l` trova i loopback per evitare falsi positivi
- `r` commuta le resistenze di pull-up interne, se necessario
- `s` esegue la scansione per TCK/TMS/TDI/TDO (e talvolta TRST/SRST)
- `y` esegue il brute-force dell'IR per scoprire opcode non documentati
- `x` acquisisce uno snapshot boundary-scan degli stati dei pin

![JTAG - JTAGenum: x snapshot boundary-scan degli stati dei pin](<../../images/image (939).png>)

![JTAG - JTAGenum: x snapshot boundary-scan degli stati dei pin](<../../images/image (578).png>)

![JTAG - JTAGenum: x snapshot boundary-scan degli stati dei pin](<../../images/image (774).png>)



Se viene trovato un TAP valido, vedrai righe che iniziano con `FOUND!` e indicano i pin scoperti.

Suggerimenti
- Condividi sempre la massa e non pilotare mai pin sconosciuti al di sopra del Vtref del target. In caso di dubbio, aggiungi resistenze da 100–470 Ω in serie sui pin candidati.
- Se il dispositivo usa SWD/SWJ invece del JTAG a 4 fili, JTAGenum potrebbe non rilevarlo; prova gli strumenti SWD o un adapter che supporti SWJ-DP.

## Ricerca più sicura dei pin e configurazione hardware

- Identifica prima Vtref e GND con un multimetro. Molti adapter richiedono Vtref per impostare la tensione I/O.
- Level shifting: preferisci level shifter bidirezionali progettati per segnali push-pull (le linee JTAG non sono open-drain). Evita gli shifter I2C con autodirezione per JTAG.
- Adapter utili: schede FT2232H/FT232H (ad esempio Tigard), CMSIS-DAP, J-Link, ST-LINK (specifico del vendor), ESP-USB-JTAG (su ESP32-Sx). Collega almeno TCK, TMS, TDI, TDO, GND e Vtref; opzionalmente TRST e SRST.

## Primo contatto con OpenOCD (scansione e IDCODE)

OpenOCD è il software OSS de facto per JTAG/SWD. Con un adapter supportato puoi eseguire la scansione della chain e leggere gli IDCODE:

- Esempio generico con un J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- USB-JTAG integrato nell'ESP32-S3 (non è necessaria alcuna probe esterna):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Note
- Se ottieni un IDCODE composto da "all ones/zeros", controlla il wiring, l'alimentazione, Vtref e che la porta non sia bloccata da fuse/option bytes.
- Consulta `irscan`/`drscan` di basso livello di OpenOCD per l'interazione manuale con il TAP durante l'inizializzazione di chain sconosciute.<sup>[[1]](#references)</sup>

## Arrestare la CPU ed eseguire il dump della memoria/flash

Una volta riconosciuto il TAP e scelto uno script per il target, puoi arrestare il core ed eseguire il dump delle aree di memoria o della flash interna. Esempi (modifica target, indirizzi di base e dimensioni secondo necessità):

- Target generico dopo l'inizializzazione:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- SoC RISC‑V (preferire SBA quando disponibile):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32-S3, programmare o leggere tramite l'helper di OpenOCD:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Consigli
- Usa `mdw/mdh/mdb` per verificare lo stato della memoria prima di eseguire dump lunghi.
- Per le chain multi-device, imposta BYPASS sui non-target oppure usa un board file che definisca tutti i TAP.

## Trucchi di boundary-scan (EXTEST/SAMPLE)

Anche quando l'accesso al debug della CPU è bloccato, il boundary-scan potrebbe essere ancora esposto. Con UrJTAG/OpenOCD puoi:
- Usare SAMPLE per acquisire lo stato dei pin mentre il sistema è in esecuzione (individuare l'attività del bus, confermare il mapping dei pin).
- Usare EXTEST per pilotare i pin (ad esempio, eseguire il bit-bang delle linee SPI flash esterne tramite l'MCU per leggerle offline, se il wiring della board lo consente).

Flusso UrJTAG minimale con un adapter FT2232x:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
È necessario il BSDL del dispositivo per conoscere l'ordinamento dei bit del boundary register. Attenzione: alcuni vendor bloccano le boundary-scan cells in produzione.

## Target moderni e note

- ESP32‑S3/C3 includono un bridge USB‑JTAG nativo; OpenOCD può comunicare direttamente via USB senza un probe esterno. Molto pratico per il triage e i dump.<sup>[[2]](#references)</sup>
- Il debug RISC‑V (v0.13+) è ampiamente supportato da OpenOCD; preferire SBA per l'accesso alla memoria quando il core non può essere arrestato in sicurezza.
- Molti MCU implementano l'autenticazione del debug e stati del lifecycle. Se JTAG sembra inattivo ma l'alimentazione è corretta, il dispositivo potrebbe essere configurato in uno stato chiuso tramite fuse o richiedere un probe autenticato.

## Difese e hardening (cosa aspettarsi sui dispositivi reali)

- Disabilitare o bloccare permanentemente JTAG/SWD in produzione (ad esempio, STM32 RDP level 2, eFuse ESP che disabilitano PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Richiedere un debug autenticato (ARMv8.2‑A ADIv6 Debug Authentication, challenge-response gestito dall'OEM) mantenendo al contempo l'accesso per la produzione.
- Non instradare test pad facilmente accessibili; interrare le test via, rimuovere/popolarе resistori per isolare il TAP, usare connettori con codifica o fixture a pogo-pin.
- Blocco del debug all'accensione: mettere il TAP dietro una ROM iniziale che imponga il secure boot.

## Riferimenti

- [1] [OpenOCD User’s Guide – JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
