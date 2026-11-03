# Teclas USB

{{#include ../../../banners/hacktricks-training.md}}

Se você tiver um pcap contendo a comunicação via USB de um teclado como o seguinte:

![Teclas USB: se você tiver um pcap contendo a comunicação via USB de um teclado como o seguinte](<../../../images/image (962).png>)

Para um teclado que usa o **boot protocol** HID, cada relatório Interrupt IN tem um layout fixo de 8 bytes: um byte de modificadores, um byte reservado e seis bytes de códigos de tecla. O host compara relatórios sucessivos e mapeia os códigos de tecla para usos HID a fim de reconstruir eventos de tecla.<sup>[[8]](#references)</sup>

Para uma triagem geral de capturas, consulte [Inspeção de PCAP](./).

## Noções básicas sobre relatórios USB HID

O relatório padrão de entrada de teclado em boot protocol tem a seguinte estrutura.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Significado |
| --- | --- |
| 0 | Bitmap de modificadores (`0x02` = Shift esquerdo, `0x20` = Shift direito, `0x40` = Alt direito, etc.). Vários bits podem estar definidos simultaneamente. |
| 1 | Byte reservado; relatórios sem uso normalmente devem defini-lo como zero. O uso específico de OEM ou do sistema não é portável. |
| 2-7 | Até seis códigos de tecla simultâneos no formato USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` significa "nenhuma tecla". | 

No layout boot, o usage ID `0x01` (`Keyboard ErrorRollOver`) é reportado em todos os slots de tecla quando mais de seis teclas não modificadoras são pressionadas; também pode indicar uma combinação não reconhecida.<sup>[[8]](#references)[[9]](#references)</sup> Entender esse layout ajuda quando você tem apenas os bytes brutos de `usb.capdata`.

## Extraindo dados HID de um PCAP

### Identifique primeiro a interface do teclado

Em capturas movimentadas, identifique o teclado HID antes de despejar os relatórios. Um ponto de partida confiável é a resposta do descritor da interface:<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

A classe HID define estes valores de interface:<sup>[[8]](#references)</sup>

- `subclass == 1` é a subclasse da interface de inicialização; com `protocol == 1`, identifica um teclado de inicialização
- `protocol == 2` identifica um mouse de inicialização
- `protocol == 0` significa que não há protocolo de inicialização; inspecione o descritor de relatório HID em vez de presumir um layout de 8 bytes

Uma interface compatível com inicialização **não é prova de que o protocolo de inicialização está ativo**. Os dispositivos HID são inicializados no protocolo de relatório. O host seleciona o modo de inicialização com `SET_PROTOCOL` (`bRequest = 0x0b`, `wValue = 0`); `wValue = 1` seleciona o protocolo de relatório. Se a enumeração estiver na captura, verifique a solicitação da interface do teclado (`wIndex`) antes de usar um decodificador de inicialização de oito bytes. Se estiver ausente, verifique o layout de relatório observado em vez de inferir o modo a partir do descritor da interface.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usb.setup.bRequest == 0x0b' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address \
  -e usb.setup.wIndex -e usb.setup.wValue
```

Assim que a interface for conhecida, fixe seus filtros em `usb.bus_id`, `usb.device_address` e, se possível, `usb.bInterfaceNumber` antes de exportar qualquer coisa.

### Fluxo de trabalho no Wireshark

1. **Isole o dispositivo**: filtre o tráfego interrupt IN do teclado, por exemplo, `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Adicione colunas úteis**: clique com o botão direito no campo `Leftover Capture Data` (`usb.capdata`) e nos campos `usbhid.*` de sua preferência (por exemplo, `usbhid.boot_report.keyboard.keycode_1`) para acompanhar as teclas pressionadas sem abrir cada quadro.<sup>[[11]](#references)</sup>
3. **Oculte relatórios vazios**: aplique `!(usb.capdata == 00:00:00:00:00:00:00:00)` para descartar quadros ociosos.
4. **Exporte para pós-processamento**: `File -> Export Packet Dissections -> As CSV`; inclua `frame.number`, `usb.src`, `usb.capdata` e campos de modificadores decodificados, como `usbhid.boot_report.keyboard.modifier.left_shift` e `usbhid.boot_report.keyboard.modifier.right_alt`, para fazer a reconstrução com um script mais tarde.<sup>[[10]](#references)[[11]](#references)</sup>

### Fluxo de trabalho na linha de comando

O padrão clássico de extração — despejar `usb.capdata`, descartar relatórios ociosos e mapear IDs de uso — aparece na análise original de 2017 e em seu passo a passo.<sup>[[1]](#references)[[2]](#references)</sup>

O repositório `ctf-usb-keyboard-parser` automatiza o pipeline clássico de tshark + sed:<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

Em capturas mais recentes, prefira o campo decodificado `usbhid.data` do Wireshark e use `usb.capdata` como alternativa; grave um payload por relatório em um arquivo por dispositivo:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

Esses arquivos por dispositivo podem ser enviados a um decoder após normalizar o formato hexadecimal que ele espera. Se a captura veio de teclados BLE encapsulados em GATT, filtre com `btatt.value && frame.len == 20` e extraia os payloads hexadecimais antes de decodificar.<sup>[[7]](#references)</sup>

### Quando o relatório não é o relatório clássico de inicialização de 8 bytes

Uma interface que não seja de inicialização ou um ID de relatório pode alterar o layout do payload; portanto, não presuma que todo relatório de teclado corresponda a `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Prefira `usbhid.data` a `usb.capdata` quando o Wireshark já tiver analisado a camada HID.
- Se todas as linhas começarem com um prefixo constante ou ID de relatório, remova-o com um decoder que leve o offset em conta, em vez de presumir que o byte 0 é sempre o modificador.<sup>[[7]](#references)</sup>
- Algumas exportações do USBPcap omitem o byte reservado; por isso, decoders com suporte a `--no-reserved` ou um offset personalizado economizam tempo.<sup>[[7]](#references)</sup>
- Se o descritor de relatório HID ou o mapa de relatórios BLE HOGP estiver presente na captura, use-o para recuperar o layout real dos campos antes de escrever um parser.

### Decodificar um bitmap de teclas do protocolo de relatórios

Para um teclado cujo relatório de entrada seja um bitmap, em vez de seis slots de teclas de inicialização, localize o **descritor de relatório HID** no tráfego de enumeração. Este filtro encontra quadros nos quais o Wireshark decodificou um item Report Size; abra um deles e inspecione o descritor completo. Inicie uma nova captura antes de conectar o teclado se o descritor estiver ausente.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usbhid.item.global.report_size' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address
```

Para cada relatório de entrada do teclado, anote seu `Report ID` (se houver), `Usage Page` (`0x07` para teclas do teclado), `Usage Minimum/Maximum`, `Report Size`, `Report Count` e se cada item `Input` é **Variable** ou **Array**. Conte todos os campos `Input` anteriores e o preenchimento constante para encontrar o deslocamento em bits do campo de teclas; os campos do relatório não precisam estar alinhados a bytes. Um campo `Variable` de um bit com usos consecutivos do teclado é um bitmap de estado das teclas: o bit 0 desse campo corresponde ao primeiro uso declarado, o bit 1 ao seguinte, e assim por diante. Já um `Array` contém valores resolvidos usando o intervalo de usos do descritor, e não um valor por bit para cada tecla pressionada. Se houver um `Report ID` declarado, primeiro selecione os relatórios com esse prefixo e ignore seu byte ao calcular os deslocamentos dos campos. Compare os conjuntos de usos ativos entre relatórios consecutivos da **mesma interface e do mesmo Report ID** para emitir apenas novas pressões.<sup>[[8]](#references)[[12]](#references)[[13]](#references)</sup>

## Automatizando a decodificação

- **ctf-usb-keyboard-parser** continua sendo útil para desafios rápidos de CTF e já vem incluído no repositório.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) analisa arquivos `pcap` e `pcapng` nativamente, entende `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` e não requer tshark nem outra dependência externa, sendo adequado para sandboxes isolados.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** adiciona visualizadores de teclado, mouse e tablet. Você pode executar o auxiliar `extract_hid_data.sh` (backend tshark) ou `extract_hid_data.py` (backend scapy) e, em seguida, fornecer o arquivo de texto resultante ao decodificador ou aos módulos de reprodução para acompanhar as teclas digitadas.<sup>[[7]](#references)</sup>

### A decodificação com estado é importante

Teclados USB boot enviam relatórios na taxa de inatividade mesmo quando não há novos eventos de tecla, então as capturas podem conter relatórios repetidos antes do evento de soltura. Um decodificador prático deve:<sup>[[3]](#references)[[8]](#references)</sup>

- emitir apenas os códigos de tecla pressionados recentemente em comparação com o relatório anterior
- manter o estado dos modificadores (`Shift`, `Ctrl`, `AltGr`) a partir do byte 0 ou de campos analisados, como `usbhid.boot_report.keyboard.modifier.left_shift` e `usbhid.boot_report.keyboard.modifier.right_alt`
- rastrear teclas de alternância, como `Caps Lock`, pois a saída em maiúsculas não é controlada apenas por Shift
- lembrar que os IDs de uso HID não dependem do layout: `0x1d` corresponde à posição física da tecla `z`/`y`, dependendo do layout do teclado do host.<sup>[[9]](#references)</sup>

## Decodificador rápido em Python

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

Alimente-o com as linhas hexadecimais simples despejadas anteriormente para obter uma reconstrução aproximada instantânea, sem carregar um parser completo no ambiente. Em layouts que não sejam dos EUA, isso ainda reconstrói a posição física da tecla, não necessariamente o caractere final exibido no host da vítima.

## Dicas para solução de problemas

- Se o Wireshark não preencher os campos `usbhid.*`, provavelmente o descritor de relatório HID não foi capturado. Reconecte o teclado durante a captura ou use `usb.capdata` bruto como alternativa.
- Em capturas de software no Linux, `usbmon` é a fonte padrão; no Windows, o Wireshark depende do extcap **USBPcap** para sequer visualizar URBs USB brutos.<sup>[[4]](#references)</sup>
- Se o teclado estava conectado por meio de um hub ou dock, primeiro confirme o descritor da interface e depois decodifique apenas esse par de dispositivo/interface. Capturas HID compostas frequentemente misturam relatórios de teclado e mouse.
- Capturas no Windows exigem a interface extcap **USBPcap**; verifique se ela continuou disponível após as atualizações do Wireshark, pois extcaps ausentes deixam as listas de dispositivos vazias.<sup>[[4]](#references)</sup>
- Sempre correlacione a tupla de barramento, dispositivo e interface (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; por exemplo, `1.9.1`) antes de decodificar qualquer coisa — misturar vários teclados ou dispositivos de armazenamento resulta em teclas sem sentido.<sup>[[10]](#references)</sup>



## References

- [1] [HackIT CTF 2017 Writeup: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Análise de captura de pacotes de teclado USB](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Configuração de captura USB do Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Definição da classe de dispositivo para dispositivos de interface humana (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Tabelas de uso HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Referência de filtros de exibição do Wireshark: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Referência de filtros de exibição do Wireshark: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
- [12] [Kernel do Linux: Introdução aos descritores de relatório HID](https://docs.kernel.org/hid/hidintro.html)
- [13] [snakeCTF 2024: writeup de ordinary-keyboard](https://snakectf.org/writeups/2024-quals/misc/ordinary-keyboard)
{{#include ../../../banners/hacktricks-training.md}}
