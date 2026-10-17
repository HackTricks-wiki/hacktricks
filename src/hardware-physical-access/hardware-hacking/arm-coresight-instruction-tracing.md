# ARM CoreSight Instruction Tracing über SWO

{{#include ../../banners/hacktricks-training.md}}

Ein zugänglicher [SWD/JTAG-Debug-Port](jtag.md) kann verwendet werden, um ohne Firmware-Instrumentierung einen laufenden Cortex-M-Execution-Trace zu aktivieren. Dafür benötigt man einen MCU mit ETM und TPIU, eine herausgeführte SWO-Leitung, eine Kopie der exakten Firmware zum Dekodieren und einen Logikanalysator, der für die gewählte SWO-Bitrate schnell genug ist. Anders als bei [Power- oder EM-Side-Channel-Messungen](side_channel_analysis.md) handelt es sich bei ETM um einen Debug-Trace; wenn beides aufgezeichnet wird, lassen sich beobachtete Leaks mit ausgeführtem Code abgleichen. Derselbe Abgleich kann dabei helfen, [fault injection](fault_injection_attacks.md) zeitlich abzustimmen.<sup>[[1]](#references)</sup>

ETM gibt komprimierte Kontrollflussereignisse statt Instruktionsbytes aus. Ein Decoder rekonstruiert die Ausführung anhand des passenden Firmware-Images. ITM transportiert Software-Instrumentierung, während TPIU Trace-Quellen zusammenfasst und die Serial-Wire-Ausgabe ansteuert. Prüfe die CoreSight-Komponenten und die Pin-Multiplexierung des Targets im Referenzhandbuch, bevor du Registerwerte verwendest: Das folgende Beispiel gilt für einen STM32F401 und ist keine universelle Cortex-M-Konfiguration.<sup>[[1]](#references)</sup>

## Trace-Ausgang finden

Beim STM32F401 verwendet asynchrones SWO PB3. Beim untersuchten Controller war PB3 mit dem Widerstand R15 verbunden, der einen zugänglichen Messpunkt bot. Wenn das Gehäuse oder der Netzknoten nicht zugänglich ist, konfiguriere den möglichen SWO-fähigen Pin vorübergehend als GPIO und schalte ihn über SWD-Speicherschreibvorgänge um. Prüfe die Messpunkte auf der Platine auf die passende Wellenform und stelle anschließend die Trace-Pin-Konfiguration wieder her. Verbinde den Analysator mit gemeinsamer Masse und kompatibler Logikspannung.<sup>[[1]](#references)</sup>

## TPIU und ETM mit OpenOCD aktivieren

Die folgenden Befehle gehören in eine OpenOCD-Konfiguration, nachdem der passende Adapter und `target/stm32f4x.cfg` ausgewählt wurden. `setbits` lässt nicht betroffene Bits in Steuerregistern unverändert, während `mww` das gesamte Wort überschreibt. Zuerst leitet TPIU den asynchronen Trace weiter; anschließend wird ETM entsperrt, im Programmiermodus konfiguriert, die Trace-Quellen-ID `1` zugewiesen und der Trace gestartet. Diese Werte entsprechen der funktionierenden STM32F401-Konfiguration des Autors. Passe sie daher an das Register-Map und den Clock Tree des Targets an.<sup>[[1]](#references)[[2]](#references)</sup>

<details>
<summary>STM32F401-OpenOCD-Konfiguration der Trace-Register</summary>

```tcl
proc setbits {addr mask} {
    mem2array value 32 $addr 1
    set value(0) [expr {$value(0) | $mask}]
    array2mem value 32 $addr 1
}
init
reset halt
setbits 0xe0042004 0x20       ;# DBGMCU_CR: trace I/O, async SWO
setbits 0xe000edfc 0x1000000  ;# DEMCR: TRCENA
mww 0xe0040004 1              ;# TPIU_CPSR: port size
mww 0xe0040010 3              ;# TPIU_ACPR: 16 MHz / (3 + 1) = 4 Mbaud
mww 0xe00400f0 2              ;# TPIU_SPPR: async UART framing
mww 0xe0040304 0x102          ;# TPIU_FFCR: formatter
mww 0xe0041fb0 0xC5ACCE55     ;# ETM_LAR: unlock
mww 0xe0041000 0x00201d0e     ;# ETM_CR: programming mode
mww 0xe0041200 1              ;# ETM_TRACEIDR: source ID 1
mww 0xe0041008 0x0000406F     ;# ETM_TER: trigger event
mww 0xe0041020 0x0000006F     ;# ETM_TEE: trace-enable event
mww 0xe0041024 0x00000001     ;# ETM_TSSR: start trace
mww 0xe0041000 0x0000191E     ;# ETM_CR: leave programming mode
```

</details>

Die SWO-Rate beträgt `HCLK / (TPIU_ACPR + 1)`. Bei einem HCLK von 16 MHz und `ACPR=3` erfolgt die Aufzeichnung mit 4 Mbaud. Platziere in PulseView den ETM-Decoder über einem UART-Decoder auf dem SWO-Analyzer-Kanal, stelle den UART auf die tatsächliche Baudrate der Leitung ein und verwende die oben konfigurierte ETM-Source-ID. Im Beispiel wurden eine Abtastrate von 24 MHz (sechs Samples pro Bit), eine Triggerung auf die fallende Flanke und eine Pre-Trigger-Aufzeichnung von 25 % verwendet. Halte/setze nach der Konfiguration das Target zurück, aktiviere die Aufzeichnung und führe dann `resume` aus. Überprüfe die ETM-Synchronisierung und einen plausiblen PC-Pfad anhand der Firmware, statt dich allein auf eine decodiert wirkende Ausgabe zu verlassen.<sup>[[1]](#references)</sup>

## Wiederherstellung nach Änderungen an Takt und Pin-Mux

Zwei voneinander unabhängige Firmware-Aktionen können eine gültige Trace-Aufzeichnung unterbrechen. Eine PLL-Änderung erhöht HCLK und damit die SWO-Baudrate, während `ACPR` unverändert bleibt. Die UART-Schicht decodiert dann falsche Bytes und die ETM-Wiedergabe wird unbrauchbar. Untersuche die RCC-/PLL-Konfiguration in der [Firmware-Analyse](../firmware-analysis/) und lade im STM32F401-Beispiel das Cortex-M-Image unter `0x08000000`; importiere außerdem dessen SVD in Ghidra, damit Taktregister-Schreibzugriffe mit Namen versehen werden. Setze einen Hardware-Breakpoint auf eine zwei Byte lange Thumb-Instruktion *nach* der Taktinitialisierung. Im Beispiel hält `bp 0x080001fa 2 hw` gefolgt von `resume` nach der PLL-Konfiguration an; im angehaltenen Zustand setzt `mww 0xe0040010 31` den neuen Teiler. Berechne und stelle die neue UART-Rate ein, aktiviere die Aufzeichnung und führe dann erneut `resume` aus. So wird der Ausführungspfad nach dem Taktwechsel aufgezeichnet; der verpasste Übergang wird dadurch nicht wiederhergestellt.<sup>[[1]](#references)</sup>

Unabhängig davon kann die Firmware den SWO-Pad einem anderen Peripheriegerät zuweisen. Im Beispiel änderte die GPIO-Alternate-Function-Konfiguration PB3 zu I2C2 SDA, sodass sich die Trace-Ausgabe auf dieser Leitung durch keine Decodereinstellung wiederherstellen ließ. Suche die entsprechende GPIO-Initialisierung in der Firmware und ersetze dann entweder ihre Aufrufstellen durch größenangepasste Thumb-NOPs (`0xBF00` pro Halfword), oder halte den Core an und stelle über SWD die Trace-kompatible Pin-Konfiguration wieder her. Beide Methoden können das verdrängte Peripheriegerät deaktivieren; außerdem kann die Firmware eine zur Laufzeit vorgenommene Wiederherstellung erneut überschreiben. Stelle beim Wiederherstellen des Pins zur Laufzeit den SWO-Teiler passend zum aktuellen HCLK ein.<sup>[[1]](#references)</sup>

## References

- [1] [Den Instruktionen folgen: Live-ARM-Tracing mit ETM, ITM und TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
- [2] [wrongbaud/etm-examples: STM32F4-OpenOCD-Konfiguration für ETM/TPIU](https://github.com/wrongbaud/etm-examples/blob/main/openocd-configs/prescaler.cfg)
{{#include ../../banners/hacktricks-training.md}}
