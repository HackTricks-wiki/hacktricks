# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Se você tiver um pcap contendo a comunicação via USB de um teclado como o seguinte:

![](<../../../images/image (962).png>)

Teclados USB normalmente usam o protocolo HID **boot protocol**, então cada transferência de interrupção para o host tem apenas 8 bytes: um byte de bits modificadores (Ctrl/Shift/Alt/Super), um byte reservado, e até seis keycodes por report. Decodificar esses bytes é suficiente para reconstruir tudo o que foi digitado.

## USB HID report basics

O report IN típico se parece com:

| Byte | Meaning |
| --- | --- |
| 0 | Bitmask de modificadores (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Vários bits podem ser definidos simultaneamente. |
| 1 | Reservado/padding, mas muitas vezes reutilizado por teclados gaming para dados do vendor. |
| 2-7 | Até seis keycodes simultâneos no formato USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` significa "no key". |

Teclados sem NKRO normalmente enviam `0x01` no byte 2 quando mais de seis teclas são pressionadas para sinalizar "rollover". Entender esse layout ajuda quando você só tem os bytes brutos `usb.capdata`.

## Extracting HID data from a PCAP

### Identify the keyboard interface first

Em capturas movimentadas, identifique o teclado HID antes de despejar qualquer report. Um ponto de partida confiável é a resposta do descritor da interface:
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Olhe para `usb.bInterfaceSubClass` e `usb.bInterfaceProtocol`:

- `subclass == 1` e `protocol == 1` normalmente significam um boot keyboard
- `protocol == 2` é tipicamente um mouse
- `protocol == 0` muitas vezes significa uma interface HID definida pelo vendor ou estilo NKRO que ainda carrega dados de keyboard, mas não no layout simples de 8 bytes do boot

Uma vez que a interface seja conhecida, fixe seus filtros em `usb.bus_id`, `usb.device_address` e, se possível, `usb.interface_number` antes de exportar qualquer coisa.

### Fluxo de trabalho no Wireshark

1. **Isole o dispositivo**: filtre o tráfego interrupt IN do keyboard, por exemplo `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Adicione colunas úteis**: clique com o botão direito no campo `Leftover Capture Data` (`usb.capdata`) e nos campos `usbhid.*` de sua preferência (por exemplo, `usbhid.boot_report.keyboard.keycode_1`) para acompanhar as keystrokes sem abrir cada frame.
3. **Oculte reports vazios**: aplique `!(usb.capdata == 00:00:00:00:00:00:00:00)` para remover frames ociosos.
4. **Exporte para pós-processamento**: `File -> Export Packet Dissections -> As CSV`, inclua `frame.number`, `usb.src`, `usb.capdata` e `usbhid.modifiers` para automatizar a reconstrução depois.

### Fluxo de trabalho na linha de comando

`ctf-usb-keyboard-parser` já automatiza o pipeline clássico `tshark + sed`:
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
Esses arquivos por dispositivo vão direto para qualquer decoder. Se a captura veio de teclados BLE encapsulados sobre GATT, filtre em `btatt.value && frame.len == 20` e faça dump dos payloads hex antes de decodificar.

### Quando o relatório não é o clássico relatório boot de 8 bytes

Teclados gamer recentes, teclados split e dispositivos HID compostos muitas vezes expõem uma interface de teclado non-boot onde o payload já não corresponde a `modifier,reserved,key1..key6`.

- Prefira `usbhid.data` em vez de `usb.capdata` quando o Wireshark já tiver analisado a camada HID.
- Se cada linha começa com um prefixo constante ou report ID, remova-o com um decoder que considere offset em vez de assumir que o byte 0 é sempre o modifier.
- Algumas exportações do USBPcap omitem o byte reserved, então decoders que suportam `--no-reserved` ou um offset customizado economizam tempo.
- Se o descriptor do HID report ou o BLE HOGP report map estiver presente na captura, use-o para recuperar o layout real dos campos antes de escrever um parser.

## Automatizando a decodificação

- **ctf-usb-keyboard-parser** continua útil para desafios CTF rápidos e já vem no repositório.
- **CTF-Usb_Keyboard_Parser** (`main.py`) analisa nativamente arquivos `pcap` e `pcapng`, entende `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` e não requer tshark, então funciona bem dentro de sandboxes isoladas.
- **USB-HID-decoders** adiciona visualizadores de teclado, mouse e tablet. Você pode executar o helper `extract_hid_data.sh` (backend tshark) ou `extract_hid_data.py` (backend scapy) e então alimentar o arquivo de texto resultante no decoder ou nos módulos de replay para ver as teclas sendo digitadas.

### A decodificação com estado importa

Capturas USB interrupt geralmente contêm tanto a tecla pressionada quanto uma ou mais cópias repetidas do mesmo report antes que o evento de release chegue. Um decoder prático deve:

- emitir apenas os keycodes recém-pressionados em comparação com o report anterior
- manter o estado dos modifiers (`Shift`, `Ctrl`, `AltGr`) a partir do byte 0 ou do campo `usbhid.boot_report.keyboard.modifier` já parseado
- acompanhar teclas de alternância como `Caps Lock`, porque a saída em maiúsculas não é controlada só por Shift
- lembrar que os usage IDs do HID são agnósticos ao layout: `0x1d` é a posição física da tecla `z`/`y` dependendo do layout de teclado do host

## Quick Python decoder
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
Alimente-o com as linhas hex brutas despejadas anteriormente para obter uma reconstrução aproximada instantânea sem trazer um parser completo para o ambiente. Para layouts não-US, isso ainda reconstrói a posição física da tecla, não necessariamente o glyph final mostrado no host da vítima.

## Troubleshooting tips

- Se o Wireshark não preencher os campos `usbhid.*`, o HID report descriptor provavelmente não foi capturado. Reconecte o teclado enquanto captura ou use `usb.capdata` bruto como fallback.
- Em capturas de software no Linux, `usbmon` é a fonte normal; no Windows, o Wireshark depende do **USBPcap** extcap para ver URBs USB brutas.
- Se o teclado estava conectado por um hub ou dock, confirme primeiro o interface descriptor e então decodifique apenas esse par device/interface. Capturas HID compostas frequentemente misturam reports de teclado e mouse.
- Capturas no Windows exigem a interface extcap do **USBPcap**; verifique se ela sobreviveu às atualizações do Wireshark, pois extcaps ausentes deixam você com listas vazias de dispositivos.
- Sempre correlacione `usb.bus_id:device:interface` (por exemplo, `1.9.1`) antes de decodificar qualquer coisa — misturar vários teclados ou dispositivos de armazenamento leva a keystrokes sem sentido.

## References

- [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)

{{#include ../../../banners/hacktricks-training.md}}
