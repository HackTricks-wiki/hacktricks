# Teclas USB

{{#include ../../../banners/hacktricks-training.md}}

Si tienes un pcap que contiene la comunicación vía USB de un teclado como el siguiente:

![Teclas USB: Si tienes un pcap que contiene la comunicación vía USB de un teclado como el siguiente](<../../../images/image (962).png>)

Los teclados USB suelen utilizar el **boot protocol** de HID, por lo que cada transferencia de interrupción hacia el host tiene solo 8 bytes: un byte de bits modificadores (Ctrl/Shift/Alt/Super), un byte reservado y hasta seis keycodes por reporte. Decodificar esos bytes es suficiente para reconstruir todo lo que se escribió.

## Conceptos básicos de los reportes USB HID

El reporte IN típico tiene el siguiente formato:

| Byte | Significado |
| --- | --- |
| 0 | Bitmap de modificadores (`0x02` = Shift izquierdo, `0x20` = Alt derecho, etc.). Se pueden establecer varios bits simultáneamente. |
| 1 | Reservado/relleno, pero los teclados gaming suelen reutilizarlo para datos del fabricante. |
| 2-7 | Hasta seis keycodes en formato USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` significa "ninguna tecla". |

Los teclados sin NKRO suelen enviar `0x01` en el byte 2 cuando se presionan más de seis teclas, para indicar "rollover". Comprender este formato resulta útil cuando solo tienes los bytes `usb.capdata` sin procesar.

## Extracción de datos HID desde un PCAP

### Identifica primero la interfaz del teclado

En capturas con mucho tráfico, identifica el teclado HID antes de volcar los reportes. Un punto de partida fiable es la respuesta del descriptor de interfaz:<sup>[[2]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Observa `usb.bInterfaceSubClass` y `usb.bInterfaceProtocol`:

- `subclass == 1` y `protocol == 1` normalmente indican un teclado boot
- `protocol == 2` normalmente corresponde a un mouse
- `protocol == 0` a menudo indica una interfaz HID definida por el vendor o de estilo NKRO que todavía transporta datos del teclado, pero no en el layout boot simple de 8 bytes

Una vez identificada la interfaz, fija tus filtros en `usb.bus_id`, `usb.device_address` y, si es posible, `usb.interface_number` antes de exportar cualquier dato.

### Flujo de trabajo con Wireshark

1. **Aísla el dispositivo**: filtra el tráfico interrupt IN del teclado, por ejemplo, `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Añade columnas útiles**: haz clic derecho en el campo `Leftover Capture Data` (`usb.capdata`) y en los campos `usbhid.*` que prefieras (por ejemplo, `usbhid.boot_report.keyboard.keycode_1`) para seguir las pulsaciones sin abrir cada frame.
3. **Oculta los reports vacíos**: aplica `!(usb.capdata == 00:00:00:00:00:00:00:00)` para descartar los frames inactivos.
4. **Exporta para el post-processing**: `File -> Export Packet Dissections -> As CSV`, e incluye `frame.number`, `usb.src`, `usb.capdata` y `usbhid.modifiers` para programar posteriormente la reconstrucción.

### Flujo de trabajo en línea de comandos

`ctf-usb-keyboard-parser` ya automatiza el pipeline clásico de tshark + sed:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
En capturas más recientes, puedes conservar los campos `usb.capdata` y `usbhid.data`, que contiene más información, agrupándolos por dispositivo:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Esos archivos por dispositivo se introducen directamente en cualquier decoder. Si la captura procede de teclados BLE tunelizados mediante GATT, filtra con `btatt.value && frame.len == 20` y extrae los payloads hexadecimales antes de decodificarlos.

### Cuando el report no es el boot report clásico de 8 bytes

Los teclados gaming recientes, los teclados divididos y los dispositivos HID compuestos suelen exponer una interfaz de teclado no boot en la que el payload ya no coincide con `modifier,reserved,key1..key6`.

- Da preferencia a `usbhid.data` sobre `usb.capdata` cuando Wireshark ya haya parseado la capa HID.
- Si todas las líneas empiezan con un prefijo constante o un report ID, elimínalo con un decoder compatible con offsets en lugar de asumir que el byte 0 siempre es el modifier.
- Algunas exportaciones de USBPcap omiten el byte reserved, por lo que los decoders compatibles con `--no-reserved` o con un offset personalizado ahorran tiempo.
- Si el descriptor HID o el report map de BLE HOGP están presentes en la captura, úsalos para recuperar la disposición real de los campos antes de escribir un parser.

## Automatización del decoding

- **ctf-usb-keyboard-parser** sigue siendo útil para desafíos CTF rápidos y ya viene incluido en el repositorio.<sup>[[3]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) parsea archivos `pcap` y `pcapng` de forma nativa, entiende `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` y no requiere tshark, por lo que funciona muy bien dentro de sandboxes aislados.<sup>[[4]](#references)</sup>
- **USB-HID-decoders** añade visualizadores para teclado, ratón y tablet. Puedes ejecutar el helper `extract_hid_data.sh` (backend de tshark) o `extract_hid_data.py` (backend de scapy) y después pasar el archivo de texto resultante al decoder o a los módulos de replay para observar cómo se reproducen las pulsaciones de teclas.<sup>[[5]](#references)</sup>

### El decoding con estado es importante

Las capturas de interrupciones USB suelen contener tanto la pulsación de la tecla como una o más copias repetidas del mismo report antes de que llegue el evento de liberación. Un decoder práctico debería:<sup>[[2]](#references)</sup>

- emitir únicamente los keycodes nuevos comparados con el report anterior
- mantener el estado de los modifiers (`Shift`, `Ctrl`, `AltGr`) desde el byte 0 o desde el campo parseado `usbhid.boot_report.keyboard.modifier`
- realizar un seguimiento de las teclas de alternancia, como `Caps Lock`, porque la salida en mayúsculas no depende únicamente de `Shift`
- recordar que los usage IDs de HID son independientes de la distribución: `0x1d` corresponde a la posición física de la tecla `z`/`y`, según la distribución del teclado del host

## Decoder de Python rápido
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
Aliméntalo con las líneas hexadecimales simples volcadas anteriormente para obtener una reconstrucción aproximada instantánea sin incorporar un parser completo al entorno. Para layouts no estadounidenses, esto aún reconstruye la posición física de la tecla, no necesariamente el glyph final mostrado en el host de la víctima.

## Consejos para solucionar problemas

- Si Wireshark no completa los campos `usbhid.*`, probablemente no se capturó el descriptor de informe HID. Vuelve a conectar el teclado mientras capturas o recurre a `usb.capdata` sin procesar.
- En las capturas de software de Linux, `usbmon` es la fuente habitual; en Windows, Wireshark depende del extcap **USBPcap** para poder ver URBs USB sin procesar.<sup>[[1]](#references)</sup>
- Si el teclado estaba conectado mediante un hub o dock, confirma primero el descriptor de interfaz y decodifica únicamente ese par de dispositivo/interfaz. Las capturas HID compuestas suelen mezclar informes del teclado y del ratón.
- Las capturas de Windows requieren la interfaz extcap **USBPcap**; asegúrate de que siga disponible después de actualizar Wireshark, ya que la ausencia de extcaps deja las listas de dispositivos vacías.<sup>[[1]](#references)</sup>
- Correlaciona siempre `usb.bus_id:device:interface` (por ejemplo, `1.9.1`) antes de decodificar cualquier cosa; mezclar varios teclados o dispositivos de almacenamiento produce keystrokes sin sentido.

## Referencias

- [1] [Configuración de captura USB en Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [2] [ACSC Quals 2023 - write-up de pcap 1 y 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [3] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [4] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [5] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
