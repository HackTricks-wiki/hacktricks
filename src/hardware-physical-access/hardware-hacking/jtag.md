# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## Individuazione sicura dei pin e configurazione hardware

- Identifica prima Vtref e GND con un multimetro. Molti adattatori richiedono Vtref per impostare la tensione I/O.
- Level shifting: preferisci level shifter bidirezionali progettati per segnali push-pull (le linee JTAG non sono open-drain). Evita gli shifter I2C con direzione automatica per JTAG.
- Adattatori utili: schede FT2232H/FT232H (ad es. Tigard), CMSIS-DAP, J-Link, ST-LINK (specifico del produttore), ESP-USB-JTAG (su ESP32-Sx). Collega almeno TCK, TMS, TDI, TDO, GND e Vtref; TRST e SRST sono opzionali.

Per un header non documentato, identifica GND verificando la continuità con un piano di massa noto **mentre il target è spento**. Dopo aver selezionato la modalità tensione e averlo alimentato, non classificare ogni pin con tensione alta come Vtref: gli ingressi digitali alti possono apparire simili su un multimetro. Segui le piste delle alimentazioni candidate fino ai condensatori di disaccoppiamento vicini e confrontane le forme d’onda all’accensione e allo spegnimento con un oscilloscopio. Una salita o discesa più lenta, con andamento simile a quella di un condensatore, è un indizio che si tratti di una rete di alimentazione/riferimento; verifica comunque la tensione e il cablaggio prima di collegare una sonda con level shifter. Su PiFex, è possibile selezionare un riferimento esterno a tensione inferiore per il target tramite `VCCA_IN`, invece dell’impostazione predefinita di 3.3 V.<sup>[[4]](#references)</sup>

## JTAGenum

**JTAGenum** è uno strumento che puoi caricare su un MCU compatibile con Arduino o, in via sperimentale, su un Raspberry Pi per provare con la forza bruta pinout JTAG sconosciuti ed enumerare i registri di istruzioni.<sup>[[3]](#references)</sup>

- Arduino: collega i pin digitali D2–D11 a un massimo di 10 pad/testpoint JTAG sospetti e Arduino GND a GND del target. Alimenta il target separatamente, a meno che tu non sappia che la linea di alimentazione è sicura. Preferisci la logica a 3.3 V (ad es. Arduino Due) oppure usa un level shifter/resistenze in serie quando esegui il probing di target a 1.8–3.3 V.
- Raspberry Pi: la versione per Pi espone meno GPIO utilizzabili (quindi le scansioni sono più lente); consulta il repository per la mappatura dei pin e i vincoli aggiornati.

Dopo aver eseguito il flashing, apri il monitor seriale a 115200 baud e invia `h` per visualizzare la guida. Flusso tipico:

- `l` trova i loopback per evitare falsi positivi
- `r` commuta i pull-up interni, se necessario
- `s` esegue la scansione di TCK/TMS/TDI/TDO (e talvolta TRST/SRST)
- `y` prova con la forza bruta l’IR per individuare opcode non documentati
- `x` acquisisce un’istantanea boundary-scan degli stati dei pin

![JTAG - JTAGenum: x istantanea boundary-scan degli stati dei pin](<../../images/image (939).png>)

![JTAG - JTAGenum: x istantanea boundary-scan degli stati dei pin](<../../images/image (578).png>)

![JTAG - JTAGenum: x istantanea boundary-scan degli stati dei pin](<../../images/image (774).png>)



Se viene rilevato un TAP valido, vedrai righe che iniziano con `FOUND!` e indicano i pin individuati.

### Suggerimenti di sicurezza per JTAGenum

- Collega sempre le masse e non pilotare mai pin sconosciuti con una tensione superiore a Vtref del target. In caso di dubbio, aggiungi resistenze da 100–470 Ω in serie ai pin candidati.
- Se il dispositivo usa SWD/SWJ invece di JTAG a 4 fili, JTAGenum potrebbe non rilevarlo; prova strumenti SWD o un adattatore che supporti SWJ-DP.

## Individuazione dei pin GPIO con go-jtagenum

Su un target alimentato, con massa comune verificata e tensione I/O compatibile, `go-jtagenum` può enumerare i segnali JTAG candidati dai GPIO del Raspberry Pi. Il JSON `-pins` associa le etichette ai **numeri GPIO**, non alle posizioni fisiche dell’header.<sup>[[5]](#references)</sup> Nell’esempio dell’SSD, la prima scansione IDCODE ha riportato anche una catena implausibilmente lunga di valori variabili: una linea TDO candidata che cambia da sola non dimostra la presenza di un TAP valido. Verifica nuovamente un risultato plausibile con una scansione BYPASS, che sposta un pattern di bit noto da TDI attraverso il registro bypass a un bit fino a TDO.<sup>[[4]](#references)</sup>

```bash
PINS='{ "pin2": 2, "pin3": 3, "pin9": 9, "pin10": 10, "pin14": 14, "pin15": 15 }'
go-jtagenum -pins "$PINS" -command scan_idcode -delay-tck 50
go-jtagenum -pins "$PINS" -command scan_bypass -delay-tck 50
```

Per quella scheda, BYPASS ha confermato `TCK=10`, `TMS=14`, `TDI=9` e `TDO=15`; i pin aggiuntivi erano solo possibili candidati nTRST. Se un candidato restituisce solo zeri o un pattern incoerente, verifica il contatto, l'alimentazione del target, i pull-up e i ritardi di clock/reset prima di assegnargli un segnale.<sup>[[4]](#references)[[5]](#references)</sup> Lo strumento accetta anche `-known-pins` con `test_bypass` per ripetere il test su una mappatura recuperata.<sup>[[5]](#references)</sup>

## Caratterizzare un TAP non documentato con UrJTAG

Un pinout individuato non permette di identificare gli opcode del registro istruzioni (IR) o le larghezze del registro dati (DR) necessarie per il debug. Con una build di UrJTAG che supporta il cavo GPIO Raspberry Pi, imposta la mappatura recuperata ed esegui `idcode`, poi `detect` e infine `discover`. L'esempio SSD ha rilevato un TAP, un IR a quattro bit e larghezze DR diverse per valori IR diversi. Una lunghezza DR pari a `-1` o il messaggio «TDO stuck at 0» non definiscono un registro utilizzabile; controlla temporizzazione, cablaggio e istruzione selezionata invece di assegnargli una larghezza.<sup>[[4]](#references)</sup>

```text
jtag> cable gpio tck=10 tdi=9 tms=14 tdo=15
jtag> idcode
jtag> detect
jtag> discover
```

Questa è una ricognizione TAP, non un'identificazione automatica della CPU: confronta l'IDCODE risultante con la documentazione del dispositivo e i target supportati da OpenOCD. Il database locale dei produttori di UrJTAG potrebbe indicare come sconosciuto un ID altrimenti valido.<sup>[[4]](#references)</sup>

## Primo contatto con OpenOCD (scansione e IDCODE)

OpenOCD è l'OSS de facto per JTAG/SWD. Con un adapter supportato puoi scansionare la catena e leggere gli IDCODE:<sup>[[1]](#references)</sup>

- Esempio generico con un J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- USB-JTAG integrato nell’ESP32‑S3 (non è necessaria una sonda esterna):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Note

- Se si ottiene un IDCODE composto solo da uno/zero, controllare il cablaggio, l’alimentazione, Vtref e verificare che la porta non sia bloccata da fuse/option bytes.
- Per l’interazione manuale con il TAP durante l’inizializzazione di catene sconosciute, vedere i comandi low-level `irscan`/`drscan` di OpenOCD.<sup>[[1]](#references)</sup>

## Aggiungere a OpenOCD un target non documentato

Una volta noti l’ID del TAP e la lunghezza dell’IR, esaminare gli script `cpu/`, `target/` e `board/` di OpenOCD per trovare un’**architettura CPU corrispondente**, quindi creare configurazioni separate per adapter e target.<sup>[[4]](#references)[[6]](#references)</sup> La mappatura GPIO del Pi e il target ARCv2 riportati di seguito sono l’esempio SSD testato, non una configurazione JTAG universale. La scelta del target ARC e le impostazioni di debug erano ipotesi che hanno funzionato con questo dispositivo; su un’altra scheda, usare l’ID, la lunghezza dell’IR, l’architettura e i numeri GPIO misurati per quel target.<sup>[[4]](#references)</sup>

```tcl
# raspberrypi-io.cfg
source [find interface/raspberrypi-native.cfg]
transport select jtag
adapter gpio tck -chip 0 10
adapter gpio tms -chip 0 14
adapter gpio tdi -chip 0 9
adapter gpio tdo -chip 0 15
adapter speed 100
```

```tcl
# target.cfg: ARCv2 example only
source [find cpu/arc/hs.tcl]
set _CHIPNAME arc-em
set _TARGETNAME $_CHIPNAME.cpu
jtag newtap $_CHIPNAME cpu -irlen 4 -ircapture 0x1 -expected-id 0x100434b1
target create $_TARGETNAME arcv2 -chain-position $_TARGETNAME
$_TARGETNAME configure -coreid 0
$_TARGETNAME configure -dbgbase 0
$_TARGETNAME configure -event reset-assert "arc_hs_reset $_TARGETNAME"
arc_hs_init_regs
$_TARGETNAME arc cache l2 auto 1
```

Esegui `openocd -f raspberrypi-io.cfg -f target.cfg` e verifica che l’esame del TAP abbia esito positivo prima di leggere la memoria. L’esempio apre Telnet sulla porta `4444` e un server GDB sulla porta `3333`; il solo fatto che venga riconosciuto un IDCODE non dimostra che il target CPU selezionato possa essere esaminato o sottoposto a debug.<sup>[[4]](#references)</sup> I GPIO del Raspberry Pi non devono necessariamente essere i pin etichettati JTAG su una breakout board, se l’adattatore consente il remapping con `adapter gpio`.<sup>[[4]](#references)[[6]](#references)</sup>

## Arrestare la CPU e scaricare la memoria/flash

Una volta riconosciuto il TAP e scelto uno script per il target, puoi arrestare il core e scaricare regioni di memoria o la flash interna. Esempi (adatta target, indirizzi di base e dimensioni):<sup>[[1]](#references)</sup>

- Target generico dopo l’inizializzazione:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- SoC RISC-V (preferisci SBA quando disponibile):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programmare o leggere tramite l'helper di OpenOCD:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Suggerimenti per il dumping della memoria

- Usa `mdw/mdh/mdb` per verificare rapidamente la memoria prima di eseguire dump di grandi dimensioni.
- Per catene multi-dispositivo, imposta BYPASS sui dispositivi che non sono target oppure usa un file board che definisca tutti i TAP.

Per una mappa di memoria non documentata, la ricerca sull’SSD ha esaminato un dump da 1 MiB alla ricerca di stringhe riconoscibili del controller, quindi ha usato GDB compatibile con l’architettura tramite OpenOCD per ispezionare `$pc`, il disassembly e i registri. Questi indirizzi live hanno guidato un secondo dump di una regione, poi confrontato con istruzioni corrispondenti in una build di Ghidra compatibile con ARC. Le sole stringhe sono un semplice controllo di plausibilità, non la prova che l’immagine sia completa o mappata correttamente.<sup>[[4]](#references)</sup> Consulta [l’analisi del firmware](../firmware-analysis/) per ulteriori passaggi di analisi statica.

## Tecniche di boundary-scan (EXTEST/SAMPLE)

Anche quando l’accesso al debug della CPU è bloccato, il boundary-scan potrebbe essere comunque esposto. Con UrJTAG/OpenOCD puoi:<sup>[[1]](#references)</sup>
- Usare SAMPLE per acquisire uno snapshot degli stati dei pin mentre il sistema è in esecuzione (individuare l’attività del bus, confermare la mappatura dei pin).
- Usare EXTEST per pilotare i pin (ad esempio, usare il bit-banging sulle linee della flash SPI esterna tramite l’MCU per leggerla offline, se il cablaggio della scheda lo consente).

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
È necessario disporre del BSDL del dispositivo per conoscere l’ordine dei bit del boundary register. Attenzione: alcuni vendor bloccano le celle boundary-scan in produzione.

## Target moderni e note

- ESP32‑S3/C3 includono un bridge USB‑JTAG nativo; OpenOCD può comunicare direttamente via USB senza una probe esterna. Molto comodo per il triage e i dump.<sup>[[2]](#references)</sup>
- Il debug RISC‑V (v0.13+) è ampiamente supportato da OpenOCD; preferire SBA per l’accesso alla memoria quando non è possibile arrestare il core in sicurezza.
- Molti MCU implementano l’autenticazione del debug e stati del ciclo di vita. Se JTAG sembra non funzionare ma l’alimentazione è corretta, il dispositivo potrebbe essere stato fuso in uno stato chiuso o richiedere una probe autenticata.

## Difese e hardening (cosa aspettarsi sui dispositivi reali)

- Disabilitare o bloccare permanentemente JTAG/SWD in produzione (ad es. STM32 RDP livello 2, eFuse ESP che disabilitano PAD JTAG, APPROTECT/DPAP di NXP/Nordic).
- Richiedere l’autenticazione del debug (ARMv8.2‑A ADIv6 Debug Authentication, challenge-response gestita dall’OEM), mantenendo al contempo l’accesso in fase di produzione.
- Evitare di esporre facilmente i test pad; nascondere le vie di test, rimuovere/inserire resistori per isolare TAP e usare connettori con chiave o fixture con pogo pin.
- Blocco del debug all’accensione: subordinare l’accesso al TAP alla ROM iniziale che impone il secure boot.

## References

- [1] [Guida utente di OpenOCD – Comandi JTAG e configurazione](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Debug JTAG su Espressif ESP32‑S3 (USB‑JTAG, utilizzo di OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Scanner dei pinout JTAG basato su Arduino](https://github.com/cyphunk/JTAGenum)
- [4] [VoidStar Security — Hacking JTAG con un Raspberry Pi](https://voidstarsec.com/blog/jtag-pifex)
- [5] [gremwell/go-jtagenum — Enumerazione JTAG tramite GPIO](https://github.com/gremwell/go-jtagenum)
- [6] [Guida utente di OpenOCD — Configurazione dell’adattatore di debug](https://openocd.org/doc-release/html/Debug-Adapter-Configuration.html)
{{#include ../../banners/hacktricks-training.md}}
