# Teclas USB

{{#include ../../../banners/hacktricks-training.md}}

Se você tem um pcap contendo a comunicação via USB de um teclado como o seguinte:

![](<../../../images/image (962).png>)

Teclados USB normalmente usam o HID **boot protocol**, então cada transferência de interrupt para o host tem apenas 8 bytes: um byte de bits modificadores (Ctrl/Shift/Alt/Super), um byte reservado, e até seis keycodes por relatório. Decodificar esses bytes é suficiente para reconstruir tudo que foi digitado.

## Noções básicas do relatório HID USB

O típico relatório IN se parece com:

| Byte | Significado |
| --- | --- |
| 0 | Bitmap de modificadores (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Vários bits podem estar setados simultaneamente. |
| 1 | Reservado/padding, mas frequentemente reutilizado por teclados gamers para dados do fabricante. |
| 2-7 | Até seis códigos de tecla simultâneos no formato USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` significa "nenhuma tecla". |

Teclados sem NKRO geralmente enviam `0x01` no byte 2 quando mais de seis teclas são pressionadas para sinalizar "rollover". Entender esse layout ajuda quando você só tem os bytes brutos de `usb.capdata`.

## Extraindo dados HID de um PCAP

### Fluxo de trabalho no Wireshark

1. **Isolar o dispositivo**: filtrar o tráfego interrupt IN do teclado, por exemplo `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Adicionar colunas úteis**: clique com o botão direito no campo `Leftover Capture Data` (`usb.capdata`) e nos seus campos `usbhid.*` preferidos (ex.: `usbhid.boot_report.keyboard.keycode_1`) para acompanhar as teclas digitadas sem abrir cada frame.
3. **Ocultar relatórios vazios**: aplique `!(usb.capdata == 00:00:00:00:00:00:00:00)` para descartar frames inativos.
4. **Exportar para pós-processamento**: `File -> Export Packet Dissections -> As CSV`, inclua `frame.number`, `usb.src`, `usb.capdata` e `usbhid.modifiers` para scriptar a reconstrução depois.

### Fluxo de trabalho via linha de comando

`ctf-usb-keyboard-parser` already automates the classic tshark + sed pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Em capturas mais recentes, você pode manter tanto `usb.capdata` quanto o campo mais rico `usbhid.data` agrupando por dispositivo:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Esses arquivos individuais por dispositivo podem ser inseridos diretamente em qualquer decoder. Se a captura veio de teclados BLE tunelados sobre GATT, filtre por `btatt.value && frame.len == 20` e extraia os payloads hexadecimais antes de decodificar.

## Automatizando a decodificação

- **ctf-usb-keyboard-parser** continua útil para desafios rápidos de CTF e já vem incluído no repositório.
- **CTF-Usb_Keyboard_Parser** (`main.py`) analisa nativamente arquivos `pcap` e `pcapng`, entende `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` e não requer tshark, portanto funciona bem dentro de sandboxes isoladas.
- **USB-HID-decoders** adiciona visualizadores de teclado, mouse e tablet. Você pode executar o helper `extract_hid_data.sh` (backend tshark) ou `extract_hid_data.py` (backend scapy) e então alimentar o arquivo de texto resultante nos módulos de decoder ou replay para ver as teclas sendo reproduzidas.

## Decodificador Python rápido
```python
#!/usr/bin/env python3
import sys
HID = {0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x1c:'y',0x1d:'z',0x28:'\n'}
for raw in sys.stdin:
raw = raw.strip().replace(':', '')
if len(raw) != 16:
continue
keycode = int(raw[4:6], 16)
modifier = int(raw[0:2], 16)
if keycode:
char = HID.get(keycode, '?')
if modifier & 0x02:
char = char.upper()
sys.stdout.write(char)
```
Alimente-o com as linhas hex simples despejadas anteriormente para obter uma reconstrução aproximada instantânea sem precisar carregar um parser completo no ambiente.

## Dicas de solução de problemas

- Se o Wireshark não preencher os campos `usbhid.*`, o HID report descriptor provavelmente não foi capturado. Reconecte o teclado enquanto captura ou recorra ao `usb.capdata` bruto.
- Capturas no Windows exigem a interface extcap **USBPcap**; verifique se ela sobreviveu às atualizações do Wireshark, pois extcaps ausentes deixam você com listas de dispositivos vazias.
- Sempre correlacione `usb.bus_id:device:interface` (e.g. `1.9.1`) antes de decodificar qualquer coisa — misturar múltiplos teclados ou dispositivos de armazenamento gera pressionamentos de tecla sem sentido.

## Referências

- [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [HackTheBox Deadly Arthropod write-up](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)
- [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
