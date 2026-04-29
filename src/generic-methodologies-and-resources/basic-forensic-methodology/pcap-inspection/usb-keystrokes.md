# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Si tienes un pcap que contiene la comunicación vía USB de un teclado como el siguiente:

![](<../../../images/image (962).png>)

Los teclados USB normalmente usan el HID **boot protocol**, así que cada transferencia de interrupción hacia el host solo mide 8 bytes: un byte de bits de modificador (Ctrl/Shift/Alt/Super), un byte reservado y hasta seis keycodes por reporte. Decodificar esos bytes es suficiente para reconstruir todo lo que se escribió.

## Conceptos básicos del reporte USB HID

El reporte IN típico se ve así:

| Byte | Significado |
| --- | --- |
| 0 | Mapa de bits de modificador (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Se pueden establecer varios bits a la vez. |
| 1 | Reservado/relleno, pero a menudo reutilizado por teclados gaming para datos del fabricante. |
| 2-7 | Hasta seis keycodes concurrentes en formato USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` significa "no key". |

Los teclados sin NKRO normalmente envían `0x01` en el byte 2 cuando se pulsan más de seis keys para indicar "rollover". Entender este formato ayuda cuando solo tienes los bytes crudos de `usb.capdata`.

## Extraer datos HID de un PCAP

### Identifica primero la interfaz del teclado

En capturas con mucho tráfico, identifica el teclado HID antes de volcar cualquier reporte. Un punto de partida fiable es la respuesta del descriptor de interfaz:
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Mira `usb.bInterfaceSubClass` y `usb.bInterfaceProtocol`:

- `subclass == 1` y `protocol == 1` normalmente significa un boot keyboard
- `protocol == 2` suele ser un mouse
- `protocol == 0` a menudo significa una interfaz HID definida por el vendor o estilo NKRO que aún lleva datos de teclado, pero no en el simple layout boot de 8 bytes

Una vez conocida la interfaz, fija tus filtros en `usb.bus_id`, `usb.device_address` y, si es posible, `usb.interface_number` antes de exportar nada.

### Wireshark workflow

1. **Aislar el dispositivo**: filtra el tráfico interrupt IN del teclado, por ejemplo `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Añadir columnas útiles**: haz clic derecho en el campo `Leftover Capture Data` (`usb.capdata`) y en tus campos `usbhid.*` preferidos (por ejemplo `usbhid.boot_report.keyboard.keycode_1`) para seguir las pulsaciones sin abrir cada frame.
3. **Ocultar informes vacíos**: aplica `!(usb.capdata == 00:00:00:00:00:00:00:00)` para eliminar frames inactivos.
4. **Exportar para post-processing**: `File -> Export Packet Dissections -> As CSV`, incluye `frame.number`, `usb.src`, `usb.capdata` y `usbhid.modifiers` para automatizar luego la reconstrucción.

### Command-line workflow

`ctf-usb-keyboard-parser` ya automatiza el pipeline clásico de tshark + sed:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
En capturas más recientes puedes conservar tanto `usb.capdata` como el campo más completo `usbhid.data` agrupando por dispositivo:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Esos archivos por dispositivo se pueden usar directamente en cualquier decoder. Si la captura proviene de teclados BLE encapsulados sobre GATT, filtra con `btatt.value && frame.len == 20` y vuelca los payloads hex antes de decodificar.

### Cuando el reporte no es el clásico report de arranque de 8 bytes

Los teclados gaming recientes, los teclados split y los dispositivos HID compuestos suelen exponer una interfaz de teclado no-boot donde el payload ya no coincide con `modifier,reserved,key1..key6`.

- Prefiere `usbhid.data` sobre `usb.capdata` cuando Wireshark ya ha parseado la capa HID.
- Si cada línea empieza con un prefijo constante o un report ID, elimínalo con un decoder consciente del offset en vez de asumir que el byte 0 es siempre el modifier.
- Algunas exports de USBPcap omiten el byte reserved, así que los decoders que soportan `--no-reserved` o un offset personalizado ahorran tiempo.
- Si el HID report descriptor o el BLE HOGP report map están presentes en la captura, úsalos para recuperar el layout real de campos antes de escribir un parser.

## Automatizando la decodificación

- **ctf-usb-keyboard-parser** sigue siendo útil para retos CTF rápidos y ya viene incluido en el repository.
- **CTF-Usb_Keyboard_Parser** (`main.py`) analiza de forma nativa archivos `pcap` y `pcapng`, entiende `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`, y no requiere tshark, así que funciona bien dentro de sandboxes aislados.
- **USB-HID-decoders** añade visualizadores de keyboard, mouse y tablet. Puedes ejecutar el helper `extract_hid_data.sh` (backend tshark) o `extract_hid_data.py` (backend scapy) y luego pasar el archivo de texto resultante al decoder o a los módulos de replay para ver cómo se desarrollan las pulsaciones.

### La decodificación con estado importa

Las capturas USB interrupt suelen contener tanto la pulsación de tecla como una o más copias repetidas del mismo report antes de que llegue el evento de liberación. Un decoder práctico debería:

- emitir solo los keycodes recién pulsados en comparación con el report anterior
- mantener el estado de modifiers (`Shift`, `Ctrl`, `AltGr`) desde el byte 0 o el campo `usbhid.boot_report.keyboard.modifier` parseado
- rastrear teclas de alternancia como `Caps Lock`, porque la salida en mayúsculas no está controlada solo por Shift
- recordar que los HID usage IDs son agnósticos al layout: `0x1d` es la posición física de la tecla `z`/`y` según el layout del teclado del host

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
Aliméntalo con las líneas hex en bruto volcadas antes para obtener una reconstrucción aproximada instantánea sin cargar un parser completo en el entorno. Para distribuciones no-US, esto sigue reconstruyendo la posición física de la tecla, no necesariamente el glyph final mostrado en el host víctima.

## Consejos de troubleshooting

- Si Wireshark no completa los campos `usbhid.*`, probablemente no se capturó el descriptor HID report descriptor. Vuelve a conectar el teclado mientras capturas o usa `usb.capdata` en bruto como fallback.
- En capturas de software en Linux, `usbmon` es la fuente normal; en Windows, Wireshark depende del extcap **USBPcap** para ver URBs USB en bruto en absoluto.
- Si el teclado estaba conectado a través de un hub o dock, confirma primero el interface descriptor y luego decodifica solo ese par device/interface. Las capturas HID compuestas mezclan con frecuencia reports de teclado y ratón.
- Las capturas de Windows requieren la interfaz extcap **USBPcap**; asegúrate de que sobrevivió a las actualizaciones de Wireshark, ya que los extcaps faltantes te dejan con listas de dispositivos vacías.
- Correlaciona siempre `usb.bus_id:device:interface` (por ejemplo `1.9.1`) antes de decodificar nada — mezclar varios teclados o dispositivos de almacenamiento lleva a keystrokes sin sentido.

## References

- [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)

{{#include ../../../banners/hacktricks-training.md}}
