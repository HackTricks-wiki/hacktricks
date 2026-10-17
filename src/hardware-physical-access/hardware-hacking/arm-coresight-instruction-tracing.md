# Tracciamento delle istruzioni ARM CoreSight tramite SWO

{{#include ../../banners/hacktricks-training.md}}

Una [porta di debug SWD/JTAG](jtag.md) accessibile può essere usata per abilitare una traccia in tempo reale dell'esecuzione Cortex-M senza strumentazione del firmware. Ciò richiede un MCU con ETM e TPIU, una linea SWO esposta, una copia esatta del firmware per la decodifica e un logic analyzer sufficientemente veloce per il bit rate SWO selezionato. A differenza delle [misurazioni side-channel di potenza o EM](side_channel_analysis.md), ETM è una traccia di debug; registrarle entrambe consente di allineare le leakage osservate al codice eseguito. Lo stesso allineamento può aiutare a temporizzare la [fault injection](fault_injection_attacks.md).<sup>[[1]](#references)</sup>

ETM emette eventi di control flow compressi anziché byte di istruzioni. Un decoder ricostruisce l'esecuzione usando l'immagine firmware corrispondente. ITM trasporta la strumentazione software, mentre TPIU inquadra le sorgenti di trace e gestisce l'uscita serial-wire. Prima di applicare valori ai registri, verifica i componenti CoreSight e il pin multiplexing del target nel relativo manuale: l'esempio qui sotto è per uno STM32F401, non è una configurazione Cortex-M universale.<sup>[[1]](#references)</sup>

## Individuare l'uscita di trace

Sullo STM32F401, SWO asincrono usa PB3. Sul controller esaminato, PB3 era collegato alla resistenza R15, che forniva un punto di probe accessibile. Se il package o la net non sono visibili, configura temporaneamente il pin candidato compatibile con SWO come GPIO e commutalo tramite scritture in memoria SWD. Usa il probe sui punti della scheda per individuare la forma d'onda corrispondente, quindi ripristina la configurazione del pin di trace. Collega l'analizzatore con una massa comune e una tensione logica compatibile.<sup>[[1]](#references)</sup>

## Abilitare TPIU ed ETM con OpenOCD

I seguenti comandi vanno inseriti in una configurazione OpenOCD dopo aver selezionato l'adattatore appropriato e `target/stm32f4x.cfg`. `setbits` preserva i bit non correlati nei registri di controllo, mentre `mww` sovrascrive l'intera word. Prima viene instradato il trace asincrono tramite TPIU; poi ETM viene sbloccato, configurato in modalità di programmazione, assegnato all'ID sorgente di trace `1` e avviato. Questi valori corrispondono alla configurazione STM32F401 funzionante dell'autore, quindi adattali alla mappa dei registri e al clock tree del target.<sup>[[1]](#references)[[2]](#references)</sup>

<details>
<summary>Configurazione dei registri di trace STM32F401 in OpenOCD</summary>

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

La velocità SWO è `HCLK / (TPIU_ACPR + 1)`. Con un HCLK di 16 MHz e `ACPR=3`, acquisisci a 4 Mbaud. In PulseView, posiziona il decoder ETM sopra un decoder UART sul canale SWO dell’analizzatore, imposta la UART alla velocità effettiva sulla linea e usa l’ID sorgente ETM configurato sopra. L’esempio ha usato un campionamento a 24 MHz (sei campioni per bit), un trigger sul fronte di discesa e un’acquisizione pre-trigger del 25%. Dopo la configurazione, arresta/reimposta il target, avvia l’acquisizione e poi esegui `resume`; verifica la sincronizzazione ETM e un percorso PC plausibile rispetto al firmware, invece di fidarti solo di un output che sembra decodificato.<sup>[[1]](#references)</sup>

## Ripristinare il funzionamento dopo le modifiche a clock e pin-mux

Due azioni indipendenti del firmware possono interrompere una traccia valida. Una modifica del PLL aumenta HCLK e quindi la velocità baud SWO, mentre `ACPR` rimane invariato; il livello UART recupera quindi byte errati e la riproduzione ETM diventa priva di senso. Esamina la configurazione RCC/PLL in [analisi del firmware](../firmware-analysis/) e, nell’esempio STM32F401, carica l’immagine Cortex-M all’indirizzo `0x08000000` e importa il relativo SVD in Ghidra, così da visualizzare i nomi dei registri di clock. Imposta un breakpoint hardware su un’istruzione Thumb di due byte *dopo* l’inizializzazione del clock. Nell’esempio, `bp 0x080001fa 2 hw` seguito da `resume` si arresta dopo la configurazione del PLL; durante l’arresto, `mww 0xe0040010 31` imposta il nuovo divisore. Calcola e imposta la nuova velocità UART, avvia l’acquisizione e poi esegui di nuovo `resume`. In questo modo acquisisci il percorso successivo alla transizione, ma non recuperi la transizione persa.<sup>[[1]](#references)</sup>

Separatamente, il firmware potrebbe rimappare il pad SWO su un’altra periferica. Nell’esempio, la configurazione della funzione alternativa GPIO ha impostato PB3 come SDA di I2C2, quindi nessuna impostazione del decoder poteva ripristinare la traccia su quel filo. Individua nel firmware l’inizializzazione GPIO pertinente, quindi sostituisci i relativi punti di chiamata con NOP Thumb della stessa dimensione (`0xBF00` per halfword) oppure arresta il core e ripristina tramite SWD una configurazione dei pin compatibile con la traccia. Entrambi gli approcci possono disabilitare la periferica rimossa; inoltre, il firmware potrebbe sovrascrivere di nuovo un ripristino effettuato in fase di esecuzione. Quando ripristini il pin in fase di esecuzione, imposta il divisore SWO in base all’HCLK corrente.<sup>[[1]](#references)</sup>

## References

- [1] [Seguire le istruzioni: tracing ARM live con ETM, ITM e TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
- [2] [wrongbaud/etm-examples: configurazione ETM/TPIU di STM32F4 OpenOCD](https://github.com/wrongbaud/etm-examples/blob/main/openocd-configs/prescaler.cfg)
{{#include ../../banners/hacktricks-training.md}}
