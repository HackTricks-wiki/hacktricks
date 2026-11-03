# Tasti USB

{{#include ../../../banners/hacktricks-training.md}}

Se hai un pcap contenente la comunicazione USB di una tastiera, come quello seguente:

![Tasti USB: se hai un pcap contenente la comunicazione USB di una tastiera, come quello seguente](<../../../images/image (962).png>)

Per una tastiera che usa il protocollo boot HID, ogni report Interrupt IN ha un layout fisso di 8 byte: un byte per i modificatori, un byte riservato e sei byte per i keycode. L'host confronta i report successivi e associa i keycode agli usage HID per ricostruire gli eventi dei tasti.<sup>[[8]](#references)</sup>

Per un'analisi preliminare generale delle acquisizioni, consulta [Ispezione dei pcap](./).

## Nozioni di base sui report USB HID

Il report di input standard per una tastiera in modalità boot ha la seguente struttura.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Significato |
| --- | --- |
| 0 | Bitmap dei modificatori (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt, ecc.). È possibile impostare più bit contemporaneamente. |
| 1 | Byte riservato; normalmente dovrebbe essere impostato a zero nei report che non lo usano. Gli usi specifici di OEM o sistema non sono portabili. |
| 2-7 | Fino a sei keycode simultanei nel formato USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` significa "nessun tasto". | 

Nel layout boot, l'usage ID `0x01` (`Keyboard ErrorRollOver`) viene riportato in tutti gli slot dei tasti quando vengono premuti più di sei tasti non modificatori; può anche segnalare una combinazione non riconoscibile.<sup>[[8]](#references)[[9]](#references)</sup> Comprendere questo layout è utile quando si dispone solo dei byte `usb.capdata` grezzi.

## Estrazione dei dati HID da un PCAP

### Identifica prima l'interfaccia della tastiera

Nelle acquisizioni più affollate, identifica la tastiera HID prima di estrarre i report. Un punto di partenza affidabile è la risposta al descrittore dell'interfaccia:<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

La classe HID definisce questi valori dell'interfaccia:<sup>[[8]](#references)</sup>

- `subclass == 1` è la Boot Interface Subclass; con `protocol == 1` identifica una tastiera boot
- `protocol == 2` identifica un mouse boot
- `protocol == 0` indica l'assenza del boot protocol; esamina invece il descrittore HID report anziché presumere un layout di 8 byte

Un'interfaccia compatibile con il boot **non prova che il boot protocol sia attivo**. I dispositivi HID si inizializzano in report protocol. L'host seleziona la modalità boot con `SET_PROTOCOL` (`bRequest = 0x0b`, `wValue = 0`); `wValue = 1` seleziona il report protocol. Se la capture include l'enumerazione, controlla la richiesta per l'interfaccia della tastiera (`wIndex`) prima di usare un decoder boot a otto byte. Se è assente, verifica il layout dei report osservato anziché dedurre la modalità dal descrittore dell'interfaccia.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usb.setup.bRequest == 0x0b' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address \
  -e usb.setup.wIndex -e usb.setup.wValue
```

Una volta identificata l’interfaccia, imposta i filtri su `usb.bus_id`, `usb.device_address` e, se possibile, `usb.bInterfaceNumber` prima di esportare qualsiasi dato.

### Flusso di lavoro in Wireshark

1. **Isola il dispositivo**: filtra il traffico interrupt IN proveniente dalla tastiera, ad es. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Aggiungi colonne utili**: fai clic con il tasto destro sul campo `Leftover Capture Data` (`usb.capdata`) e sui campi `usbhid.*` che preferisci (ad es. `usbhid.boot_report.keyboard.keycode_1`) per seguire i tasti premuti senza aprire ogni frame.<sup>[[11]](#references)</sup>
3. **Nascondi i report vuoti**: applica `!(usb.capdata == 00:00:00:00:00:00:00:00)` per escludere i frame inattivi.
4. **Esporta per la post-elaborazione**: `File -> Export Packet Dissections -> As CSV`, includi `frame.number`, `usb.src`, `usb.capdata` e i campi dei modificatori decodificati, come `usbhid.boot_report.keyboard.modifier.left_shift` e `usbhid.boot_report.keyboard.modifier.right_alt`, per ricostruire i dati in seguito tramite script.<sup>[[10]](#references)[[11]](#references)</sup>

### Flusso di lavoro da riga di comando

Il classico schema di estrazione—scaricare `usb.capdata`, escludere i report inattivi e mappare gli ID di utilizzo—compare nell’analisi originale del 2017 e nella relativa guida.<sup>[[1]](#references)[[2]](#references)</sup>

Il repository `ctf-usb-keyboard-parser` automatizza la classica pipeline tshark + sed:<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

Nelle acquisizioni più recenti, preferisci il campo decodificato `usbhid.data` di Wireshark e, in alternativa, usa `usb.capdata`; scrivi un payload per report in un file per dispositivo:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

Questi file per dispositivo possono essere passati a un decoder dopo aver normalizzato il formato esadecimale richiesto. Se la cattura proviene da tastiere BLE instradate tramite GATT, filtra con `btatt.value && frame.len == 20` ed esporta i payload esadecimali prima della decodifica.<sup>[[7]](#references)</sup>

### Quando il report non è il classico report di boot da 8 byte

Un'interfaccia non di boot o un ID report possono modificare il layout del payload, quindi non dare per scontato che ogni report della tastiera corrisponda a `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Preferisci `usbhid.data` a `usb.capdata` quando Wireshark ha già analizzato il livello HID.
- Se ogni riga inizia con un prefisso costante o un ID report, rimuovilo con un decoder che tenga conto dell'offset, invece di presumere che il byte 0 sia sempre il modificatore.<sup>[[7]](#references)</sup>
- Alcune esportazioni USBPcap omettono il byte riservato, quindi i decoder che supportano `--no-reserved` o un offset personalizzato fanno risparmiare tempo.<sup>[[7]](#references)</sup>
- Se nella cattura è presente il descrittore HID o la mappa dei report BLE HOGP, usalo per ricostruire il layout effettivo dei campi prima di scrivere un parser.

### Decodificare una bitmap di tasti del protocollo report

Per una tastiera il cui report di input è una bitmap anziché sei slot di tasti di boot, individua il suo **descrittore HID** nel traffico di enumerazione. Questo filtro trova i frame in cui Wireshark ha decodificato un elemento Report Size; aprine uno e ispeziona il descrittore completo. Avvia una nuova cattura prima di collegare la tastiera se il descrittore non è presente.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usbhid.item.global.report_size' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address
```

Per ogni report Input della tastiera, annota il relativo `Report ID` (se presente), `Usage Page` (`0x07` per i tasti della tastiera), `Usage Minimum/Maximum`, `Report Size`, `Report Count` e se ogni elemento `Input` è **Variable** o **Array**. Conta tutti i campi Input precedenti e il padding costante per trovare l'offset in bit del campo dei tasti; i campi dei report non devono necessariamente essere allineati ai byte. Un campo Variable di un bit con usage consecutivi della tastiera è una bitmap dello stato dei tasti: il bit 0 di quel campo corrisponde al primo usage dichiarato, il bit 1 al successivo e così via. Un Array contiene invece valori determinati dall'intervallo di usage del descriptor, non un tasto premuto per ogni bit. Se è dichiarato un Report ID, seleziona prima i report con quel prefisso e salta il relativo byte nel calcolo degli offset dei campi. Confronta gli insiemi di usage mantenuti premuti tra report consecutivi della **stessa interfaccia e dello stesso Report ID** per emettere solo le nuove pressioni.<sup>[[8]](#references)[[12]](#references)[[13]](#references)</sup>

## Automazione della decodifica

- **ctf-usb-keyboard-parser** è ancora utile per le sfide CTF rapide ed è già incluso nel repository.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) analizza nativamente file `pcap` e `pcapng`, riconosce `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` e non richiede tshark né altre dipendenze esterne, quindi è adatto a sandbox isolate.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** aggiunge visualizzatori per tastiera, mouse e tablet. Puoi eseguire l'helper `extract_hid_data.sh` (backend tshark) oppure `extract_hid_data.py` (backend scapy), quindi fornire il file di testo risultante al decoder o ai moduli di replay per osservare la comparsa dei tasti premuti.<sup>[[7]](#references)</sup>

### È importante una decodifica con stato

Le tastiere USB boot inviano report alla frequenza di idle anche quando non si verifica un nuovo evento di tasto, quindi le catture possono contenere report ripetuti prima dell'evento di rilascio. Un decoder pratico dovrebbe:<sup>[[3]](#references)[[8]](#references)</sup>

- emettere solo i keycode appena premuti rispetto al report precedente
- mantenere lo stato dei modificatori (`Shift`, `Ctrl`, `AltGr`) dal byte 0 o da campi analizzati come `usbhid.boot_report.keyboard.modifier.left_shift` e `usbhid.boot_report.keyboard.modifier.right_alt`
- tenere traccia dei tasti di commutazione come `Caps Lock`, perché le maiuscole non dipendono solo da Shift
- ricordare che gli ID di usage HID non dipendono dal layout: `0x1d` corrisponde alla posizione fisica del tasto `z`/`y` a seconda del layout della tastiera host.<sup>[[9]](#references)</sup>

## Decoder Python rapido

```python
#!/usr/bin/env python3
import sys
NORMAL = {0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x1c:'y',0x1d:'z',0x28:'\n',0x2d:'-',0x2e:'=',0x2f:'[',0x30:']',0x33:';',0x34:"'",0x36:',',0x37:'.'}
SHIFTED = {0x2d:'_',0x2e:'+',0x2f:'{',0x30:'}',0x33:':',0x34:'"',0x36:'<',0x37:'>'}
prev = set()
caps = False
for raw in sys.stdin:
    raw = raw.strip().replace(':', '')
    if len(raw) != 16:
        continue
    modifier = int(raw[0:2], 16)
    keycodes = [int(raw[i:i+2], 16) for i in range(4, 16, 2)]
    current = {k for k in keycodes if k}
    newly_pressed = [k for k in keycodes if k and k not in prev]
    shift = bool(modifier & 0x22)
    for keycode in newly_pressed:
        if keycode == 0x39:
            caps = not caps
            continue
        char = SHIFTED.get(keycode) if shift else None
        if char is None:
            char = NORMAL.get(keycode, '?')
            if char.isalpha() and (shift ^ caps):
                char = char.upper()
        sys.stdout.write(char)
    prev = current
```

Forniscigli le righe esadecimali semplici estratte in precedenza per ottenere una ricostruzione approssimativa immediata, senza dover caricare un parser completo nell’ambiente. Per i layout non statunitensi, ricostruisce comunque la posizione fisica del tasto, ma non necessariamente il carattere finale visualizzato sul sistema della vittima.

## Suggerimenti per la risoluzione dei problemi

- Se Wireshark non popola i campi `usbhid.*`, probabilmente il descrittore del report HID non è stato acquisito. Scollega e ricollega la tastiera durante l’acquisizione oppure ripiega sui dati grezzi `usb.capdata`.
- Nelle acquisizioni software su Linux, `usbmon` è la sorgente abituale; su Windows, Wireshark dipende dall’extcap **USBPcap** per visualizzare i raw USB URB.<sup>[[4]](#references)</sup>
- Se la tastiera era collegata tramite un hub o una docking station, verifica prima il descrittore dell’interfaccia e poi decodifica solo la coppia dispositivo/interfaccia corrispondente. Le acquisizioni HID composite spesso mescolano i report di tastiera e mouse.
- Le acquisizioni su Windows richiedono l’interfaccia extcap **USBPcap**; assicurati che sia ancora presente dopo gli aggiornamenti di Wireshark, perché se mancano gli extcap l’elenco dei dispositivi risulta vuoto.<sup>[[4]](#references)</sup>
- Prima di decodificare qualsiasi dato, verifica sempre la tupla bus, dispositivo e interfaccia (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; ad es. `1.9.1`): confondere più tastiere o dispositivi di archiviazione produce sequenze di tasti senza senso.<sup>[[10]](#references)</sup>



## References

- [1] [Resoconto di HackIT CTF 2017: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Analisi dell’acquisizione dei pacchetti della tastiera USB](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [Qualificazioni ACSC 2023 - write-up di pcap 1 e 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Configurazione dell’acquisizione USB con Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [Decodificatori USB-HID](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Definizione della classe di dispositivo per i dispositivi di interfaccia umana (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Tabelle degli utilizzi HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Riferimento dei filtri di visualizzazione di Wireshark: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Riferimento dei filtri di visualizzazione di Wireshark: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
- [12] [Kernel Linux: introduzione ai descrittori dei report HID](https://docs.kernel.org/hid/hidintro.html)
- [13] [snakeCTF 2024: write-up di ordinary-keyboard](https://snakectf.org/writeups/2024-quals/misc/ordinary-keyboard)
{{#include ../../../banners/hacktricks-training.md}}
