# Teclas USB

{{#include ../../../banners/hacktricks-training.md}}

Se você tiver um pcap contendo a comunicação via USB de um teclado como o seguinte:

![Teclas USB: Se você tiver um pcap contendo a comunicação via USB de um teclado como o seguinte](<../../../images/image (962).png>)

Teclados USB geralmente usam o **boot protocol** do HID, portanto cada transferência de interrupção em direção ao host tem apenas 8 bytes: um byte de bits de modificadores (Ctrl/Shift/Alt/Super), um byte reservado e até seis keycodes por report. Decodificar esses bytes é suficiente para reconstruir tudo o que foi digitado.

## Noções básicas dos reports USB HID

O report IN típico é:

| Byte | Significado |
| --- | --- |
| 0 | Bitmap de modificadores (`0x02` = Left Shift, `0x20` = Right Alt etc.). Vários bits podem estar definidos simultaneamente. |
| 1 | Reservado/padding, mas frequentemente reutilizado por teclados gaming para dados do fornecedor. |
| 2-7 | Até seis keycodes simultâneos no formato USB usage ID (`0x04` = a, `0x1E` = 1). `0x00` significa "nenhuma tecla". |

Teclados sem NKRO geralmente enviam `0x01` no byte 2 quando mais de seis teclas são pressionadas, para sinalizar "rollover". Entender esse layout ajuda quando você tem apenas os bytes `usb.capdata` brutos.

## Extraindo dados HID de um PCAP

### Identifique primeiro a interface do teclado

Em captures movimentadas, identifique o teclado HID antes de fazer dump dos reports. Um ponto de partida confiável é a resposta do descritor da interface:<sup>[[2]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Observe `usb.bInterfaceSubClass` e `usb.bInterfaceProtocol`:

- `subclass == 1` e `protocol == 1` geralmente indicam um boot keyboard
- `protocol == 2` normalmente indica um mouse
- `protocol == 0` frequentemente indica uma interface HID definida pelo fornecedor ou no estilo NKRO que ainda transporta dados do teclado, mas não no layout boot simples de 8 bytes

Depois de identificar a interface, restrinja seus filtros a `usb.bus_id`, `usb.device_address` e, se possível, `usb.interface_number` antes de exportar qualquer coisa.

### Fluxo de trabalho no Wireshark

1. **Isole o dispositivo**: filtre o tráfego interrupt IN do teclado, por exemplo, `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Adicione colunas úteis**: clique com o botão direito no campo `Leftover Capture Data` (`usb.capdata`) e nos campos `usbhid.*` de sua preferência (por exemplo, `usbhid.boot_report.keyboard.keycode_1`) para acompanhar as teclas sem abrir cada frame.
3. **Oculte reports vazios**: aplique `!(usb.capdata == 00:00:00:00:00:00:00:00)` para remover os frames ociosos.
4. **Exporte para pós-processamento**: `File -> Export Packet Dissections -> As CSV`, incluindo `frame.number`, `usb.src`, `usb.capdata` e `usbhid.modifiers` para realizar a reconstrução posteriormente via script.

### Fluxo de trabalho na linha de comando

`ctf-usb-keyboard-parser` já automatiza o pipeline clássico de tshark + sed:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Em capturas mais recentes, você pode manter os campos `usb.capdata` e `usbhid.data`, mais completos, agrupando por dispositivo:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Esses arquivos por dispositivo podem ser inseridos diretamente em qualquer decoder. Se a captura veio de teclados BLE encapsulados sobre GATT, filtre por `btatt.value && frame.len == 20` e extraia os payloads hexadecimais antes da decodificação.

### Quando o report não é o clássico report boot de 8 bytes

Teclados gaming recentes, teclados split e dispositivos HID compostos frequentemente expõem uma interface de teclado não boot, na qual o payload não corresponde mais a `modifier,reserved,key1..key6`.

- Prefira `usbhid.data` a `usb.capdata` quando o Wireshark já tiver analisado a camada HID.
- Se toda linha começar com um prefixo constante ou report ID, remova-o com um decoder que considere o offset, em vez de presumir que o byte 0 é sempre o modifier.
- Algumas exportações do USBPcap omitem o byte reservado, portanto decoders compatíveis com `--no-reserved` ou um offset personalizado economizam tempo.
- Se o descritor HID ou o report map BLE HOGP estiver presente na captura, use-o para recuperar o layout real dos campos antes de escrever um parser.

## Automatizando a decodificação

- **ctf-usb-keyboard-parser** continua sendo útil para desafios CTF rápidos e já vem incluído no repositório.<sup>[[3]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) analisa arquivos `pcap` e `pcapng` nativamente, entende `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` e não requer tshark, funcionando bem em sandboxes isolados.<sup>[[4]](#references)</sup>
- **USB-HID-decoders** adiciona visualizadores de teclado, mouse e tablet. Você pode executar o helper `extract_hid_data.sh` (backend tshark) ou `extract_hid_data.py` (backend scapy) e depois fornecer o arquivo de texto resultante ao decoder ou aos módulos de replay para observar as teclas sendo decodificadas.<sup>[[5]](#references)</sup>

### A decodificação com estado é importante

Capturas de interrupções USB geralmente contêm tanto o pressionamento da tecla quanto uma ou mais cópias repetidas do mesmo report antes da chegada do evento de liberação. Um decoder prático deve:<sup>[[2]](#references)</sup>

- emitir apenas os keycodes pressionados recentemente em comparação com o report anterior
- manter o estado dos modifiers (`Shift`, `Ctrl`, `AltGr`) a partir do byte 0 ou do campo analisado `usbhid.boot_report.keyboard.modifier`
- rastrear teclas de alternância como `Caps Lock`, pois a saída em maiúsculas não é controlada apenas por Shift
- lembrar que os IDs de uso HID não dependem do layout: `0x1d` é a posição física da tecla `z`/`y`, dependendo do layout do teclado do host

## Decoder Python rápido
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
Alimente-o com as linhas hexadecimais simples extraídas anteriormente para obter uma reconstrução aproximada instantânea, sem carregar um parser completo no ambiente. Para layouts não americanos, isso ainda reconstrói a posição física da tecla, mas não necessariamente o caractere final exibido no host da vítima.

## Dicas para solução de problemas

- Se o Wireshark não preencher os campos `usbhid.*`, provavelmente o descritor de relatório HID não foi capturado. Reconecte o teclado durante a captura ou use `usb.capdata` bruto como alternativa.
- Em capturas de software no Linux, `usbmon` é a fonte normal; no Windows, o Wireshark depende do extcap **USBPcap** para visualizar URBs USB brutos.<sup>[[1]](#references)</sup>
- Se o teclado estiver conectado por meio de um hub ou dock, confirme primeiro o descritor da interface e, em seguida, decodifique apenas o par dispositivo/interface correspondente. Capturas HID compostas frequentemente misturam relatórios de teclado e mouse.
- As capturas do Windows exigem a interface extcap **USBPcap**; certifique-se de que ela permaneceu disponível após as atualizações do Wireshark, pois extcaps ausentes deixam as listas de dispositivos vazias.<sup>[[1]](#references)</sup>
- Sempre correlacione `usb.bus_id:device:interface` (por exemplo, `1.9.1`) antes de decodificar qualquer coisa — misturar vários teclados ou dispositivos de armazenamento resulta em teclas sem sentido.

## Referências

- [1] [Configuração da captura USB no Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [2] [ACSC Quals 2023 - pcap 1, 2 - write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [3] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [4] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [5] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
