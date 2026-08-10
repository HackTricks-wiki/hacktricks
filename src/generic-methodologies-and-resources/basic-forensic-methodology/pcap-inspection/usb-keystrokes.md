# USB Keystrokes

Se você tiver um pcap contendo a comunicação via USB de um teclado como o seguinte:

![USB Keystrokes: Se você tiver um pcap contendo a comunicação via USB de um teclado como o seguinte](<../../../images/image (962).png>)

Para um teclado que usa o **boot protocol** HID, cada relatório Interrupt IN tem um layout fixo de 8 bytes: um byte de modificador, um byte reservado e seis bytes de keycode. O host compara relatórios sucessivos e mapeia os keycodes para HID usages, reconstruindo os eventos de teclas.<sup>[[8]](#references)</sup>

## Noções básicas dos relatórios USB HID

O relatório de entrada padrão de um teclado boot é estruturado da seguinte forma.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Significado |
| --- | --- |
| 0 | Bitmap de modificadores (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt etc.). Vários bits podem ser definidos simultaneamente. |
| 1 | Byte reservado; os relatórios não utilizados normalmente devem defini-lo como zero. O uso específico de OEM ou do sistema não é portátil. |
| 2-7 | Até seis keycodes simultâneos no formato USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` significa "nenhuma tecla". |

No layout boot, o usage ID `0x01` (`Keyboard ErrorRollOver`) é reportado em todos os slots de teclas quando mais de seis teclas que não são modificadores são pressionadas; ele também pode indicar uma combinação não reconhecível.<sup>[[8]](#references)[[9]](#references)</sup> Entender esse layout ajuda quando você tem apenas os bytes `usb.capdata` brutos.

## Extraindo dados HID de um PCAP

### Identifique primeiro a interface do teclado

Em captures movimentados, identifique o teclado HID antes de extrair os relatórios. Um ponto de partida confiável é a resposta do descritor de interface:<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
A classe HID define estes valores de interface:<sup>[[8]](#references)</sup>

- `subclass == 1` é a Boot Interface Subclass; com `protocol == 1`, identifica um teclado de boot
- `protocol == 2` identifica um mouse de boot
- `protocol == 0` significa que não há boot protocol; inspecione o HID report descriptor em vez de presumir um layout de 8 bytes

Depois que a interface for identificada, fixe seus filtros em `usb.bus_id`, `usb.device_address` e, se possível, `usb.bInterfaceNumber` antes de exportar qualquer coisa.

### Fluxo de trabalho no Wireshark

1. **Isole o dispositivo**: filtre o tráfego interrupt IN do teclado, por exemplo, `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Adicione colunas úteis**: clique com o botão direito no campo `Leftover Capture Data` (`usb.capdata`) e nos campos `usbhid.*` de sua preferência (por exemplo, `usbhid.boot_report.keyboard.keycode_1`) para acompanhar as teclas pressionadas sem abrir cada frame.<sup>[[11]](#references)</sup>
3. **Oculte reports vazios**: aplique `!(usb.capdata == 00:00:00:00:00:00:00:00)` para remover os frames ociosos.
4. **Exporte para pós-processamento**: `File -> Export Packet Dissections -> As CSV`, incluindo `frame.number`, `usb.src`, `usb.capdata` e campos de modificadores decodificados, como `usbhid.boot_report.keyboard.modifier.left_shift` e `usbhid.boot_report.keyboard.modifier.right_alt`, para executar a reconstrução posteriormente usando um script.<sup>[[10]](#references)[[11]](#references)</sup>

### Fluxo de trabalho pela linha de comando

O padrão clássico de extração — descarregar `usb.capdata`, remover os reports ociosos e mapear os usage IDs — aparece na análise original de 2017 e em seu walkthrough.<sup>[[1]](#references)[[2]](#references)</sup>

O repositório `ctf-usb-keyboard-parser` automatiza o pipeline clássico de tshark + sed:<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Em capturas mais recentes, prefira o campo decodificado `usbhid.data` do Wireshark e use `usb.capdata` como alternativa; escreva um payload por relatório em um arquivo por dispositivo:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
Esses arquivos por dispositivo podem ser enviados a um decoder após normalizar o formato hexadecimal esperado por ele. Se a captura veio de teclados BLE encapsulados sobre GATT, filtre por `btatt.value && frame.len == 20` e extraia os payloads hexadecimais antes de decodificá-los.<sup>[[7]](#references)</sup>

### Quando o report não é o clássico boot report de 8 bytes

Uma interface non-boot ou um report ID pode alterar o layout do payload; portanto, não presuma que todo keyboard report corresponda a `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Prefira `usbhid.data` a `usb.capdata` quando o Wireshark já tiver analisado a camada HID.
- Se toda linha começar com um prefixo constante ou report ID, remova-o com um decoder ciente do offset, em vez de presumir que o byte 0 seja sempre o modifier.<sup>[[7]](#references)</sup>
- Algumas exportações do USBPcap omitem o reserved byte, portanto decoders compatíveis com `--no-reserved` ou com um offset personalizado economizam tempo.<sup>[[7]](#references)</sup>
- Se o HID report descriptor ou o BLE HOGP report map estiver presente na captura, use-o para recuperar o layout real dos campos antes de escrever um parser.

## Automatizando a decodificação

- **ctf-usb-keyboard-parser** continua sendo útil para CTF challenges rápidos e já vem incluído no repository.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) analisa arquivos `pcap` e `pcapng` nativamente, entende `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` e não requer tshark nem outra dependência externa, sendo adequado para sandboxes isolados.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** adiciona visualizadores de keyboard, mouse e tablet. Você pode executar o helper `extract_hid_data.sh` (backend tshark) ou `extract_hid_data.py` (backend scapy) e, em seguida, enviar o arquivo de texto resultante ao decoder ou aos módulos de replay para observar as teclas sendo reproduzidas.<sup>[[7]](#references)</sup>

### A decodificação stateful é importante

Teclados USB boot enviam reports na idle rate mesmo quando não há um novo key event; portanto, as capturas podem conter reports repetidos antes do evento de release. Um decoder prático deve:<sup>[[3]](#references)[[8]](#references)</sup>

- emitir apenas os keycodes pressionados recentemente em comparação com o report anterior
- manter o estado dos modifiers (`Shift`, `Ctrl`, `AltGr`) a partir do byte 0 ou de campos analisados, como `usbhid.boot_report.keyboard.modifier.left_shift` e `usbhid.boot_report.keyboard.modifier.right_alt`
- rastrear toggle keys como `Caps Lock`, pois a saída em maiúsculas não é controlada apenas por Shift
- lembrar que os HID usage IDs são independentes do layout: `0x1d` corresponde à posição física da tecla `z`/`y`, dependendo do layout do keyboard host.<sup>[[9]](#references)</sup>

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
Alimente-o com as linhas hexadecimais simples despejadas anteriormente para obter uma reconstrução aproximada instantânea sem carregar um parser completo no ambiente. Para layouts não americanos, isso ainda reconstrói a posição física da tecla, não necessariamente o caractere final exibido no host da vítima.

## Dicas para solução de problemas

- Se o Wireshark não preencher os campos `usbhid.*`, provavelmente o descritor de relatório HID não foi capturado. Reconecte o teclado durante a captura ou use `usb.capdata` bruto como alternativa.
- Em capturas de software no Linux, `usbmon` é a fonte normal; no Windows, o Wireshark depende do extcap **USBPcap** para visualizar URBs USB brutos.<sup>[[4]](#references)</sup>
- Se o teclado estiver conectado por meio de um hub ou dock, confirme primeiro o descritor da interface e depois decodifique apenas esse par de dispositivo/interface. Capturas HID compostas frequentemente misturam relatórios de teclado e mouse.
- As capturas do Windows exigem a interface extcap **USBPcap**; certifique-se de que ela tenha sobrevivido às atualizações do Wireshark, pois extcaps ausentes deixam as listas de dispositivos vazias.<sup>[[4]](#references)</sup>
- Sempre correlacione a tupla de barramento, dispositivo e interface (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; por exemplo, `1.9.1`) antes de decodificar qualquer coisa — misturar vários teclados ou dispositivos de armazenamento gera pressionamentos de teclas sem sentido.<sup>[[10]](#references)</sup>

## References

- [1] [Relatório do HackIT CTF 2017: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Análise da captura de pacotes de teclado USB](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - análise dos pcaps 1 e 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Configuração de captura USB do Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [Decodificadores USB-HID](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Definição da classe de dispositivos para dispositivos de interface humana (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Tabelas de uso HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Referência de filtros de exibição do Wireshark: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Referência de filtros de exibição do Wireshark: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
