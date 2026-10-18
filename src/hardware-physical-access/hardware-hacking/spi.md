# SPI

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

SPI (Serial Peripheral Interface) è un bus seriale sincrono comunemente usato per le comunicazioni a breve distanza tra circuiti integrati. Un controller fornisce il clock e seleziona una periferica, come una EEPROM, un sensore o un dispositivo di controllo, usando un segnale di chip-select.<sup>[[1]](#references)</sup>

Più periferiche possono condividere le linee del clock e dei dati, normalmente con un chip-select separato per ogni periferica. Il controller coordina i trasferimenti; normalmente le periferiche non comunicano direttamente tra loro tramite il bus SPI. La polarità e la temporizzazione del chip-select dipendono dal dispositivo; la selezione attiva bassa è comune, ma non universale. SPI non definisce il rilevamento delle periferiche, l’indirizzamento, i comandi né una lunghezza massima unica per i trasferimenti, quindi consulta sempre il datasheet del dispositivo target.<sup>[[1]](#references)</sup>

MOSI/COPI trasporta i dati dal controller alla periferica, mentre MISO/CIPO trasporta i dati dalla periferica al controller. Entrambe le direzioni possono trasmettere simultaneamente. La relazione tra un comando, un indirizzo, i cicli dummy e i dati restituiti è definita dalla periferica, non da SPI, e dipende dalla polarità e dalla fase del clock (modalità 0–3). Non dare per scontato che l’output inizi esattamente un ciclo di clock dopo la fine dell’input.<sup>[[1]](#references)</sup>

## Estrazione del firmware dalle EEPROM

L’estrazione del firmware può essere utile per analizzarlo e individuare vulnerabilità. L’immagine corretta potrebbe non essere disponibile online o potrebbe differire in base al modello, alla revisione hardware o alla versione; estrarla direttamente dal dispositivo fisico fornisce quindi un target di analisi esatto.

Una console seriale può essere utile, ma il suo filesystem potrebbe essere in sola lettura e il target potrebbe non disporre di strumenti di analisi, incluse le utility necessarie per inviare/ricevere traffico di test o estrarre comodamente i binari. Un’immagine offline conserva l’intero layout della flash e consente di estrarre il filesystem e svolgere reverse engineering senza modificare il target in esecuzione.

Durante una valutazione fisica autorizzata, un dump verificato può anche supportare test controllati di modifica e riflashing. Ciò include la modifica di file o l’iniezione di un payload/backdoor di test per dimostrare la persistenza a livello firmware. Conserva più letture corrispondenti e l’immagine originale prima di qualsiasi scrittura: una tensione, selezione del chip, layout o immagine errati possono rendere il dispositivo inutilizzabile.

### Programmatore e lettore EEPROM CH341A

Questo economico strumento USB può eseguire il dump e il reflash di dispositivi EEPROM seriali e flash SPI compatibili. È comunemente usato con i chip flash SPI NOR che contengono il firmware BIOS/UEFI dei PC ed è pratico durante un accesso fisico limitato nel tempo.

![drawing](../../images/board_image_ch341a.jpg)

Collega la memoria flash al CH341A, quindi collega il programmatore al computer. Se il programmatore non viene rilevato, controlla il cavo USB, i permessi del sistema operativo e il driver CH341A appropriato prima di eseguire la diagnosi del chip target. Verifica la tensione del chip, il pin 1, il cablaggio dell’adattatore e l’output del programmatore consultando i datasheet o usando un multimetro: **non** affidarti a una regola come posizionare VCC sul lato opposto al connettore USB. Un orientamento errato o l’applicazione di 5 V a un componente da 3,3/1,8 V possono distruggerlo. Le letture in-circuit possono anche fallire perché il resto della scheda carica il bus o lo alimenta.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Usa software come `flashrom` o G-Flash per leggere il chip. G-Flash è un’interfaccia grafica minimale e può rilevare automaticamente i dispositivi compatibili, il che può essere pratico durante un’acquisizione rapida; verifica comunque il modello rilevato e la tensione. Specifica il programmatore esatto e, quando necessario, il modello esatto del chip; esegui almeno due letture e confrontane gli hash prima di considerare affidabile un dump.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Dopo aver estratto il firmware, l’analisi può essere svolta sui file binari. È possibile usare strumenti come strings, hexdump, xxd, binwalk ecc. per estrarre molte informazioni sul firmware e sull’intero filesystem.

Per un triage iniziale, Binwalk può cercare firme note ed estrarre i contenuti incorporati supportati:

```
binwalk -e <filename>
```

Il file di output può avere estensione `.bin`, `.rom` o un'altra; l'estensione non determina il formato.

> [!CAUTION]
> Tieni presente che l'estrazione del firmware è un processo delicato e richiede molta pazienza. Qualsiasi manipolazione errata può potenzialmente corrompere il firmware o persino cancellarlo completamente, rendendo inutilizzabile il dispositivo. Si consiglia di studiare il dispositivo specifico prima di tentare di estrarre il firmware.

### Bus Pirate + flashrom

![Programmatore e lettore EEPROM CH341A - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Alcune schede tecniche indicano i pin target come `DI` e `DO`: per un collegamento flash convenzionale con una sola linea dati, il pin **MOSI/COPI** del controller si collega a DI e il pin **MISO/CIPO** del controller si collega a DO. Verifica la scheda tecnica del target, perché i componenti con I/O dual/quad riutilizzano i pin in altre modalità.

![Programmatore e lettore EEPROM CH341A - Bus Pirate + flashrom: Tieni presente che, anche se il PINOUT del Bus Pirate indica i pin MOSI e MISO da collegare a SPI, alcuni SPI potrebbero...](<../../images/image (360).png>)

Su Windows o Linux puoi usare il programma [**`flashrom`**](https://www.flashrom.org/Flashrom) per eseguire il dump del contenuto della memoria flash con un comando simile a questo:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

La documentazione recente di Bus Pirate mostra anche i parametri facoltativi `serialspeed` e `spispeed`. Iniziate con valori conservativi se i cavi lunghi o il carico in-circuit rendono instabili le letture.<sup>[[3]](#references)</sup>

### Letture in-circuit quando il controller condivide il bus flash

Una clip SOIC può alimentare il resto del PCB tramite l’alimentazione della flash. Se l’MCU è quindi alimentato e accede allo stesso chip, i suoi trasferimenti SPI possono entrare in conflitto con quelli del programmatore esterno. Un risultato `No EEPROM/flash device found` non prova quindi che la flash sia assente o non supportata. Verificate prima il pinout, la tensione e il contatto, poi stabilite se anche il controller sulla scheda è attivo.<sup>[[4]](#references)</sup>

Se è disponibile un test pad di reset, verificatene la polarità e la tensione con un multimetro prima di attivarlo. Tenere l’MCU in reset può lasciare la flash accessibile e fermare al contempo l’host SPI concorrente. In alternativa, si può dissaldare il chip o registrare passivamente le letture dell’MCU; quest’ultimo metodo non consente di accedere alle aree non lette né di scrivere sul chip, e il cablaggio aggiuntivo delle sonde può disturbare un bus veloce. Intervenire sull’oscillatore o sulla modalità di avvio dipende dal target e non sostituisce la verifica dello schema e dei segnali.<sup>[[4]](#references)</sup>

Con l’MCU mantenuto inattivo, un Raspberry Pi con interfaccia `spidev` abilitata può leggere usando il programmer `linux_spi` di flashrom. Modificate `-p` per usare un adattatore diverso. Ripetete la lettura e confrontate gli hash prima di fidarvene; l’autodetect SFDP e una lettura riuscita **non** dimostrano che le operazioni di cancellazione, scrittura o protezione dalla scrittura funzionino su un componente altrimenti non supportato.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Ricostruire le letture della flash SPI con un logic analyzer

Quando non è possibile eseguire una lettura attiva, acquisisci chip select, clock, dati dal controller alla flash e dati dalla flash al controller durante l'avvio o un'azione UI scelta. In PulseView, individua prima l'intervallo di chip-select attivo e il clock, quindi configura i canali dati del decoder SPI in base al pinout della flash e verifica che sia presente un comando/indirizzo plausibile seguito dai byte restituiti. Esporta i byte **MISO/output della flash** con Binary Decoder Output View e conserva gli indirizzi di lettura decodificati, così da poter collocare ogni risposta all'offset corrispondente nella flash. Acquisire solo le letture richieste dai menu fornisce solo le regioni richieste, non un'immagine completa della flash; non concatenare le risposte come se fossero contigue senza verificarne gli indirizzi.<sup>[[4]](#references)</sup>

Se un dump sembra contenere grafica anziché codice eseguibile, prosegui con il [triage degli asset di visualizzazione raw](../firmware-analysis/#raw-display-assets-in-external-flash).<sup>[[4]](#references)</sup>

#### Scapy e acquisizioni SPI/QSPI miste

Con sonde senza etichette, distingui MOSI da MISO identificando la linea che trasporta l'opcode prima dei dati di risposta, quindi verifica il comando consultando il datasheet della flash. Gli impulsi più brevi di un ciclo di clock possono essere rumore della sonda anziché bit campionati, e i cavi aggiuntivi delle clip possono rendere inaffidabili le acquisizioni ad alta velocità.<sup>[[5]](#references)</sup>

L'esportazione CSV SPI di Saleae usa `enable` e `disable` per delimitare un intervallo di chip-select, con i byte MOSI/MISO nelle righe `result`. Raggruppa i byte per intervallo prima della decodifica; concatenare tutti i dati MISO fa perdere gli indirizzi delle transazioni.<sup>[[5]](#references)</sup> Un `Packet` di Scapy può modellare l'header MOSI con un opcode `ByteEnumField` e campi condizionali per indirizzo e dummy. Nelle letture NOR a 24 bit, `0x03` comprende un opcode e tre byte di indirizzo, mentre `0x0B` aggiunge un byte dummy. `len(req.self_build())` restituisce la lunghezza dell'header modellato: in una lettura single-lane, `miso[header_length:]` contiene la risposta della flash, mentre i dati MOSI successivi all'header sono dati don't-care dal lato controller.<sup>[[5]](#references)</sup> Inserisci le risposte agli indirizzi decodificati in un'immagine riempita con `0xFF` e tieni traccia separatamente degli offset coperti. Un byte non osservato non dimostra che la flash contenesse `0xFF` in quella posizione.<sup>[[5]](#references)[[6]](#references)</sup>

Una lettura `0x6B` (1-1-4) di tipo W25Q usa una lane per l'opcode e l'indirizzo, ma IO0–IO3 per i dati di risposta. L'attività sui pin precedentemente `/WP` e `/HOLD` è un indizio più forte di un passaggio alla modalità quad rispetto al solo aumento della velocità del clock; un analyzer single-lane può decodificare in modo errato la risposta quad.<sup>[[5]](#references)</sup> Esporta quella fase con un analyzer QSPI configurato per le larghezze delle lane e i cicli dummy del comando, quindi unisci le letture single-lane e quad-lane in base all'indirizzo della flash.<sup>[[5]](#references)[[7]](#references)</sup> `spidump` rileva automaticamente entrambi i formati di esportazione, scarta le letture decodificate con una larghezza di lane errata e riporta la copertura delle letture.<sup>[[6]](#references)</sup> Dal suo repository, dopo aver installato le dipendenze, unisci le acquisizioni con:<sup>[[6]](#references)</sup>

```bash
python main.py single_lane_boot.csv --merge quad_boot.txt -o recovered_flash.bin -v
```

Il risultato rimane un’osservazione parziale, non un dump completo del chip.<sup>[[5]](#references)[[6]](#references)</sup> Per esaminare separatamente le operazioni di scrittura, correla l’abilitazione alla scrittura `0x06`, i controlli dello stato `0x05`, gli opcode di cancellazione e i comandi di programmazione delle pagine `0x02`. I dati di programmazione delle pagine seguono l’indirizzo su MOSI e non sono inclusi nella ricostruzione in sola lettura.<sup>[[5]](#references)</sup> Analizza l’immagine risultante con [analisi del firmware](../firmware-analysis/), conservando le informazioni sulla copertura della lettura.

## References

- [1] [Analog Devices — Introduzione all’interfaccia SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Manuale di flashrom — programmatore SPI CH341A e opzioni di lettura/scrittura](https://flashrom.org/classic_cli_manpage.html)
- [3] [Documentazione di Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Ripasso dell’hardware hacking, parte 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [5] [VoidStar Security — Estensione di Scapy per il reverse engineering hardware](https://voidstarsec.com/blog/scapy-spi-reconstruction)
- [6] [spidump — acquisizione e ricostruzione di tracce SPI/QSPI](https://github.com/wrongbaud/spidump)
- [7] [Analizzatore QSPI per Saleae Logic/KingstVIS](https://github.com/AddioElectronics/QSPI-Analyzer)
{{#include ../../banners/hacktricks-training.md}}
