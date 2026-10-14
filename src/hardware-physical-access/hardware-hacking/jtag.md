# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** è uno strumento che puoi caricare su un MCU compatibile con Arduino o, in via sperimentale, su un Raspberry Pi per forzare le combinazioni dei pinout JTAG sconosciuti ed enumerare i registri di istruzione.<sup>[[3]](#references)</sup>

- Arduino: collega i pin digitali D2–D11 a un massimo di 10 pad/testpoint JTAG sospetti e il GND di Arduino al GND del dispositivo target. Alimenta il target separatamente, a meno che tu non sappia che la linea di alimentazione è sicura. Preferisci la logica a 3,3 V (ad es., Arduino Due) oppure usa un level shifter/resistenze in serie quando analizzi target da 1,8–3,3 V.
- Raspberry Pi: la versione per Pi espone meno GPIO utilizzabili (quindi le scansioni sono più lente); consulta il repo per la mappatura dei pin e i vincoli attuali.

Dopo aver caricato il firmware, apri il monitor seriale a 115200 baud e invia `h` per visualizzare la guida. Flusso tipico:

- `l` trova i loopback per evitare falsi positivi
- `r` attiva/disattiva le resistenze di pull-up interne, se necessario
- `s` cerca TCK/TMS/TDI/TDO (e talvolta TRST/SRST)
- `y` forza le combinazioni IR per scoprire opcode non documentati
- `x` acquisisce uno snapshot boundary-scan degli stati dei pin

![JTAG - JTAGenum: x snapshot boundary-scan degli stati dei pin](<../../images/image (939).png>)

![JTAG - JTAGenum: x snapshot boundary-scan degli stati dei pin](<../../images/image (578).png>)

![JTAG - JTAGenum: x snapshot boundary-scan degli stati dei pin](<../../images/image (774).png>)



Se viene trovato un TAP valido, vedrai righe che iniziano con `FOUND!` e indicano i pin individuati.

### Suggerimenti di sicurezza per JTAGenum

- Collega sempre le masse e non pilotare mai pin sconosciuti con una tensione superiore a Vtref del target. In caso di dubbio, aggiungi resistenze da 100–470 Ω in serie ai pin candidati.
- Se il dispositivo usa SWD/SWJ anziché JTAG a 4 fili, JTAGenum potrebbe non rilevarlo; prova strumenti SWD o un adattatore che supporti SWJ‑DP.

## Ricerca più sicura dei pin e configurazione hardware

- Individua prima Vtref e GND con un multimetro. Molti adattatori richiedono Vtref per impostare la tensione I/O.
- Level shifting: preferisci level shifter bidirezionali progettati per segnali push-pull (le linee JTAG non sono open-drain). Evita i level shifter I2C con direzione automatica per JTAG.
- Adattatori utili: schede FT2232H/FT232H (ad es., Tigard), CMSIS-DAP, J-Link, ST-LINK (specifico del produttore), ESP-USB-JTAG (su ESP32-Sx). Collega almeno TCK, TMS, TDI, TDO, GND e Vtref; facoltativamente TRST e SRST.

## Primo approccio a OpenOCD (scansione e IDCODE)

OpenOCD è il software OSS de facto per JTAG/SWD. Con un adattatore supportato puoi scansionare la catena e leggere gli IDCODE:<sup>[[1]](#references)</sup>

- Esempio generico con un J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- USB-JTAG integrato nell’ESP32-S3 (non è necessaria una sonda esterna):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Note

- Se ottieni un IDCODE composto da tutti 1/0, controlla il cablaggio, l’alimentazione, Vtref e che la porta non sia bloccata da fuse/option bytes.
- Consulta `irscan`/`drscan` di basso livello di OpenOCD per interagire manualmente con il TAP durante l’inizializzazione di chain sconosciute.<sup>[[1]](#references)</sup>

## Arrestare la CPU e scaricare la memoria/flash

Una volta riconosciuto il TAP e scelto uno script target, puoi arrestare il core e scaricare le regioni di memoria o la flash interna. Esempi (modifica target, indirizzi di base e dimensioni):<sup>[[1]](#references)</sup>

- Target generico dopo l’inizializzazione:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- SoC RISC-V (preferire SBA quando disponibile):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programmare o leggere tramite l’helper OpenOCD:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Suggerimenti per il dump della memoria

- Usa `mdw/mdh/mdb` per verificare rapidamente la memoria prima dei dump lunghi.
- Per le catene multi-dispositivo, imposta BYPASS sui dispositivi non target oppure usa un board file che definisca tutti i TAP.

## Trucchi boundary-scan (EXTEST/SAMPLE)

Anche quando l’accesso al debug della CPU è bloccato, il boundary-scan potrebbe essere comunque esposto. Con UrJTAG/OpenOCD puoi:<sup>[[1]](#references)</sup>
- Usare SAMPLE per acquisire uno snapshot degli stati dei pin mentre il sistema è in esecuzione (individuare l’attività del bus, confermare la mappatura dei pin).
- Usare EXTEST per pilotare i pin (ad es. eseguire bit-banging sulle linee della flash SPI esterna tramite l’MCU per leggerla offline, se il cablaggio della scheda lo consente).

Flusso UrJTAG minimo con un adattatore FT2232x:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
È necessario disporre del BSDL del dispositivo per conoscere l’ordinamento dei bit del registro boundary-scan. Attenzione: alcuni vendor bloccano le celle boundary-scan in produzione.

## Target moderni e note

- ESP32‑S3/C3 includono un bridge USB‑JTAG nativo; OpenOCD può comunicare direttamente via USB senza una probe esterna. Molto comodo per il triage e i dump.<sup>[[2]](#references)</sup>
- Il debug RISC‑V (v0.13+) è ampiamente supportato da OpenOCD; preferisci SBA per l’accesso alla memoria quando non è possibile arrestare il core in sicurezza.
- Molti MCU implementano l’autenticazione del debug e stati del ciclo di vita. Se JTAG sembra inattivo ma l’alimentazione è corretta, il dispositivo potrebbe essere stato impostato tramite fuse su uno stato chiuso o richiedere una probe autenticata.

## Difese e hardening (cosa aspettarsi dai dispositivi reali)

- Disabilitare o bloccare permanentemente JTAG/SWD in produzione (ad es., STM32 RDP livello 2, eFuse ESP che disabilitano PAD JTAG, APPROTECT/DPAP di NXP/Nordic).
- Richiedere l’autenticazione del debug (ARMv8.2‑A ADIv6 Debug Authentication, challenge-response gestito dall’OEM), mantenendo l’accesso per la produzione.
- Evitare di instradare test pad facilmente accessibili; nascondere le vie di test, rimuovere o installare resistori per isolare il TAP, usare connettori con chiave o fixture con pogo pin.
- Blocco del debug all’accensione: proteggere il TAP tramite la ROM iniziale che applica il secure boot.

## References

- [1] [Guida utente di OpenOCD – Comandi e configurazione JTAG](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Debug JTAG di Espressif ESP32‑S3 (USB‑JTAG, uso di OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Scanner del pinout JTAG basato su Arduino](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
