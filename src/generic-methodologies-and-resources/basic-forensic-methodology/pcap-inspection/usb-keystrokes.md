# Pulsaciones de teclas USB

{{#include ../../../banners/hacktricks-training.md}}

Si tienes un pcap que contiene la comunicación USB de un teclado como el siguiente:

![Pulsaciones de teclas USB: si tienes un pcap que contiene la comunicación USB de un teclado como el siguiente](<../../../images/image (962).png>)

Para un teclado que utiliza el **boot protocol** de HID, cada informe Interrupt IN tiene un diseño fijo de 8 bytes: un byte de modificadores, un byte reservado y seis bytes de keycodes. El host compara los informes sucesivos y asigna los keycodes a los HID usages para reconstruir los eventos de teclas.<sup>[[8]](#references)</sup>

## Conceptos básicos de los informes USB HID

El informe de entrada estándar de un teclado en boot protocol está estructurado de la siguiente manera.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Significado |
| --- | --- |
| 0 | Mapa de bits de modificadores (`0x02` = Shift izquierdo, `0x20` = Shift derecho, `0x40` = Alt derecho, etc.). Se pueden establecer varios bits simultáneamente. |
| 1 | Byte reservado; los informes sin utilizar normalmente deberían establecerlo en cero. El uso específico del OEM o del sistema no es portable. |
| 2-7 | Hasta seis keycodes simultáneos en formato de USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` significa "ninguna tecla". |

En el diseño de boot, el usage ID `0x01` (`Keyboard ErrorRollOver`) se informa en todas las ranuras de teclas cuando se presionan más de seis teclas que no son modificadores; también puede indicar una combinación no reconocible.<sup>[[8]](#references)[[9]](#references)</sup> Comprender este diseño resulta útil cuando solo tienes los bytes sin procesar de `usb.capdata`.

## Extracción de datos HID de un PCAP

### Identifica primero la interfaz del teclado

En capturas con mucho tráfico, identifica el teclado HID antes de volcar los informes. Un punto de partida fiable es la respuesta del descriptor de interfaz:<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
La clase HID define estos valores de interfaz:<sup>[[8]](#references)</sup>

- `subclass == 1` es la subclase de interfaz Boot; con `protocol == 1`, identifica un teclado boot
- `protocol == 2` identifica un mouse boot
- `protocol == 0` significa que no se usa el protocolo boot; inspecciona el descriptor de informes HID en lugar de asumir un diseño de 8 bytes

Una vez conocida la interfaz, fija tus filtros en `usb.bus_id`, `usb.device_address` y, si es posible, `usb.bInterfaceNumber` antes de exportar cualquier dato.

### Flujo de trabajo de Wireshark

1. **Aísla el dispositivo**: filtra el tráfico interrupt IN del teclado, por ejemplo, `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Añade columnas útiles**: haz clic derecho en el campo `Leftover Capture Data` (`usb.capdata`) y en los campos `usbhid.*` que prefieras (por ejemplo, `usbhid.boot_report.keyboard.keycode_1`) para seguir las pulsaciones sin abrir cada frame.<sup>[[11]](#references)</sup>
3. **Oculta los informes vacíos**: aplica `!(usb.capdata == 00:00:00:00:00:00:00:00)` para descartar los frames inactivos.
4. **Exporta para el post-processing**: `File -> Export Packet Dissections -> As CSV`, e incluye `frame.number`, `usb.src`, `usb.capdata` y los campos de modificadores decodificados, como `usbhid.boot_report.keyboard.modifier.left_shift` y `usbhid.boot_report.keyboard.modifier.right_alt`, para programar posteriormente la reconstrucción.<sup>[[10]](#references)[[11]](#references)</sup>

### Flujo de trabajo de línea de comandos

El patrón clásico de extracción —volcar `usb.capdata`, descartar los informes inactivos y mapear los IDs de uso— aparece en el análisis original de 2017 y en su walkthrough.<sup>[[1]](#references)[[2]](#references)</sup>

El repositorio `ctf-usb-keyboard-parser` automatiza el pipeline clásico de tshark + sed:<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
En capturas más recientes, prefiere el campo decodificado `usbhid.data` de Wireshark y recurre a `usb.capdata` como alternativa; escribe un payload por informe en un archivo por dispositivo:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
Esos archivos por dispositivo se pueden pasar a un decoder después de normalizar el formato hexadecimal que espera. Si la captura proviene de teclados BLE tunelizados mediante GATT, filtra con `btatt.value && frame.len == 20` y extrae los payloads hexadecimales antes de decodificarlos.<sup>[[7]](#references)</sup>

### Cuando el informe no es el clásico informe boot de 8 bytes

Una interfaz que no sea boot o un ID de informe puede cambiar el diseño del payload, así que no asumas que todos los informes de teclado siguen el formato `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Prefiere `usbhid.data` sobre `usb.capdata` cuando Wireshark ya haya analizado la capa HID.
- Si todas las líneas comienzan con un prefijo constante o un ID de informe, elimínalo con un decoder que tenga en cuenta el offset, en lugar de asumir que el byte 0 siempre es el modifier.<sup>[[7]](#references)</sup>
- Algunas exportaciones de USBPcap omiten el byte reserved, por lo que los decoders compatibles con `--no-reserved` o con un offset personalizado ahorran tiempo.<sup>[[7]](#references)</sup>
- Si el descriptor de informe HID o el mapa de informes BLE HOGP está presente en la captura, úsalo para recuperar el diseño real de los campos antes de escribir un parser.

## Automatizar la decodificación

- **ctf-usb-keyboard-parser** sigue siendo práctico para challenges rápidos de CTF y ya está incluido en el repository.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) analiza archivos `pcap` y `pcapng` de forma nativa, entiende `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` y no requiere tshark ni otra dependencia externa, por lo que es adecuado para sandboxes aislados.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** añade visualizadores para teclado, ratón y tablet. Puedes ejecutar el helper `extract_hid_data.sh` (backend de tshark) o `extract_hid_data.py` (backend de scapy) y después pasar el archivo de texto resultante al decoder o a los módulos de replay para observar cómo se reproducen las pulsaciones.<sup>[[7]](#references)</sup>

### La decodificación con estado es importante

Los teclados USB boot envían informes según la tasa de idle incluso cuando no hay un nuevo evento de tecla, por lo que las capturas pueden contener informes repetidos antes del evento de liberación. Un decoder práctico debería:<sup>[[3]](#references)[[8]](#references)</sup>

- emitir únicamente los keycodes pulsados recientemente en comparación con el informe anterior
- mantener el estado de los modifiers (`Shift`, `Ctrl`, `AltGr`) del byte 0 o de campos analizados como `usbhid.boot_report.keyboard.modifier.left_shift` y `usbhid.boot_report.keyboard.modifier.right_alt`
- realizar un seguimiento de las teclas de alternancia, como `Caps Lock`, porque la salida en mayúsculas no depende únicamente de Shift
- recordar que los IDs de uso HID son independientes del layout: `0x1d` corresponde a la posición física de la tecla `z`/`y`, según el layout del teclado del host.<sup>[[9]](#references)</sup>

## Decoder rápido en Python
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
Aliméntalo con las líneas hexadecimales sin formato volcadas anteriormente para obtener una reconstrucción aproximada instantánea sin incorporar un parser completo al entorno. Para layouts no estadounidenses, esto aún reconstruye la posición física de la tecla, no necesariamente el glifo final mostrado en el host de la víctima.

## Consejos para la resolución de problemas

- Si Wireshark no rellena los campos `usbhid.*`, probablemente no se capturó el descriptor del informe HID. Vuelve a conectar el teclado mientras capturas o usa como alternativa el `usb.capdata` sin procesar.
- En capturas de software de Linux, `usbmon` es la fuente habitual; en Windows, Wireshark depende de la extcap **USBPcap** para poder ver URB USB sin procesar.<sup>[[4]](#references)</sup>
- Si el teclado estaba conectado mediante un hub o dock, confirma primero el descriptor de interfaz y decodifica únicamente ese par de dispositivo/interfaz. Las capturas HID compuestas suelen mezclar informes del teclado y del ratón.
- Las capturas de Windows requieren la interfaz extcap **USBPcap**; asegúrate de que siga disponible después de actualizar Wireshark, ya que la ausencia de extcaps deja las listas de dispositivos vacías.<sup>[[4]](#references)</sup>
- Correlaciona siempre la tupla de bus, dispositivo e interfaz (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; por ejemplo, `1.9.1`) antes de decodificar cualquier cosa; mezclar varios teclados o dispositivos de almacenamiento produce pulsaciones sin sentido.<sup>[[10]](#references)</sup>

## References

- [1] [HackIT CTF 2017 Writeup: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Análisis de captura de paquetes de teclado USB](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - write-up de pcap 1 y 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Configuración de captura USB de Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Definición de clase de dispositivo para dispositivos de interfaz humana (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Tablas de usos HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Referencia de filtros de visualización de Wireshark: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Referencia de filtros de visualización de Wireshark: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
