# Pulsaciones de teclas USB

Si tienes un pcap que contiene la comunicación vía USB de un teclado como el siguiente:

![Pulsaciones de teclas USB: Si tienes un pcap que contiene la comunicación vía USB de un teclado como el siguiente](<../../../images/image (962).png>)

Para un teclado que utiliza el **boot protocol** HID, cada reporte Interrupt IN tiene un diseño fijo de 8 bytes: un byte de modificadores, un byte reservado y seis bytes de keycodes. El host compara los reportes sucesivos y asigna los keycodes a HID usages para reconstruir los eventos de teclado.<sup>[[8]](#references)</sup>

## Conceptos básicos de los reportes USB HID

El reporte de entrada estándar de un teclado boot está estructurado de la siguiente manera.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Significado |
| --- | --- |
| 0 | Bitmap de modificadores (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt, etc.). Se pueden establecer varios bits simultáneamente. |
| 1 | Byte reservado; normalmente, los reportes sin uso deben establecerlo en cero. El uso específico del OEM o del sistema no es portable. |
| 2-7 | Hasta seis keycodes simultáneos en formato USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` significa "ninguna tecla". |

En el diseño boot, el usage ID `0x01` (`Keyboard ErrorRollOver`) se informa en todos los slots de teclas cuando se presionan más de seis teclas que no son modificadores; también puede indicar una combinación no reconocible.<sup>[[8]](#references)[[9]](#references)</sup> Comprender este diseño resulta útil cuando solo tienes los bytes `usb.capdata` sin procesar.

## Extracción de datos HID de un PCAP

### Identifica primero la interfaz del teclado

En capturas con mucho tráfico, identifica el teclado HID antes de volcar los reportes. Un punto de partida fiable es la respuesta del descriptor de interfaz:<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
La clase HID define estos valores de interfaz:<sup>[[8]](#references)</sup>

- `subclass == 1` es el Boot Interface Subclass; con `protocol == 1`, identifica un boot keyboard
- `protocol == 2` identifica un boot mouse
- `protocol == 0` significa que no hay boot protocol; inspecciona el HID report descriptor en lugar de asumir un layout de 8 bytes

Una vez identificada la interfaz, fija tus filtros en `usb.bus_id`, `usb.device_address` y, si es posible, `usb.bInterfaceNumber` antes de exportar cualquier dato.

### Flujo de trabajo con Wireshark

1. **Aísla el dispositivo**: filtra el tráfico interrupt IN del teclado, por ejemplo, `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Añade columnas útiles**: haz clic derecho en el campo `Leftover Capture Data` (`usb.capdata`) y en tus campos `usbhid.*` preferidos (por ejemplo, `usbhid.boot_report.keyboard.keycode_1`) para seguir las pulsaciones sin abrir cada frame.<sup>[[11]](#references)</sup>
3. **Oculta los reports vacíos**: aplica `!(usb.capdata == 00:00:00:00:00:00:00:00)` para descartar los frames inactivos.
4. **Exporta para el post-processing**: `File -> Export Packet Dissections -> As CSV`, incluye `frame.number`, `usb.src`, `usb.capdata` y los campos de modificadores decodificados, como `usbhid.boot_report.keyboard.modifier.left_shift` y `usbhid.boot_report.keyboard.modifier.right_alt`, para programar después la reconstrucción.<sup>[[10]](#references)[[11]](#references)</sup>

### Flujo de trabajo desde la línea de comandos

El patrón clásico de extracción —volcar `usb.capdata`, descartar los reports inactivos y mapear los usage IDs— aparece en el análisis original de 2017 y en su walkthrough.<sup>[[1]](#references)[[2]](#references)</sup>

El repositorio `ctf-usb-keyboard-parser` automatiza el pipeline clásico de tshark + sed:<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
En capturas más recientes, prioriza el campo `usbhid.data` decodificado de Wireshark y, como alternativa, usa `usb.capdata`; escribe un payload por reporte en un archivo por dispositivo:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
Esos archivos por dispositivo se pueden pasar a un decoder después de normalizar el formato hexadecimal que espera. Si la captura procede de teclados BLE encapsulados mediante GATT, filtra con `btatt.value && frame.len == 20` y extrae los payloads hexadecimales antes de decodificarlos.<sup>[[7]](#references)</sup>

### Cuando el informe no es el informe boot clásico de 8 bytes

Una interfaz que no sea boot o un report ID pueden cambiar el diseño del payload, así que no asumas que todos los informes de teclado coinciden con `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Prefiere `usbhid.data` en lugar de `usb.capdata` cuando Wireshark ya haya analizado la capa HID.
- Si todas las líneas comienzan con un prefijo constante o un report ID, elimínalo con un decoder que tenga en cuenta el offset, en lugar de asumir que el byte 0 siempre es el modifier.<sup>[[7]](#references)</sup>
- Algunas exportaciones de USBPcap omiten el byte reservado, por lo que los decoders compatibles con `--no-reserved` o con un offset personalizado ahorran tiempo.<sup>[[7]](#references)</sup>
- Si el descriptor del informe HID o el mapa de informes BLE HOGP están presentes en la captura, úsalos para recuperar el diseño real de los campos antes de escribir un parser.

## Automatizar la decodificación

- **ctf-usb-keyboard-parser** sigue siendo útil para desafíos CTF rápidos y ya viene incluido en el repositorio.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) analiza archivos `pcap` y `pcapng` de forma nativa, entiende `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` y no requiere tshark ni otra dependencia externa, por lo que es adecuado para sandboxes aislados.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** añade visualizadores de teclado, ratón y tablet. Puedes ejecutar el helper `extract_hid_data.sh` (backend tshark) o `extract_hid_data.py` (backend scapy) y después pasar el archivo de texto resultante al decoder o a los módulos de replay para observar cómo se van mostrando las pulsaciones.<sup>[[7]](#references)</sup>

### La decodificación con estado es importante

Los teclados USB boot envían informes a la tasa de inactividad incluso cuando no hay ningún evento de tecla nuevo, por lo que las capturas pueden contener informes repetidos antes del evento de liberación. Un decoder práctico debería:<sup>[[3]](#references)[[8]](#references)</sup>

- emitir únicamente los keycodes pulsados recientemente en comparación con el informe anterior
- mantener el estado de los modifiers (`Shift`, `Ctrl`, `AltGr`) del byte 0 o de campos analizados como `usbhid.boot_report.keyboard.modifier.left_shift` y `usbhid.boot_report.keyboard.modifier.right_alt`
- realizar un seguimiento de las teclas de alternancia como `Caps Lock`, porque la salida en mayúsculas no depende únicamente de Shift
- recordar que los IDs de uso HID son independientes de la distribución: `0x1d` es la posición física de la tecla `z`/`y`, según la distribución del teclado del host.<sup>[[9]](#references)</sup>

## Decodificador rápido en Python
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
Aliméntalo con las líneas hexadecimales sin formato volcadas anteriormente para obtener una reconstrucción aproximada instantánea sin incorporar un parser completo al entorno. Para layouts que no sean de EE. UU., esto aún reconstruye la posición física de la tecla, no necesariamente el glifo final mostrado en el host de la víctima.

## Troubleshooting tips

- Si Wireshark no muestra campos `usbhid.*`, probablemente no se capturó el descriptor del informe HID. Desconecta y vuelve a conectar el teclado durante la captura o usa `usb.capdata` sin procesar como alternativa.
- En las capturas de software de Linux, `usbmon` es la fuente habitual; en Windows, Wireshark depende del extcap **USBPcap** para poder ver los USB URBs sin procesar.<sup>[[4]](#references)</sup>
- Si el teclado estaba conectado mediante un hub o dock, confirma primero el descriptor de la interfaz y luego decodifica únicamente ese par de dispositivo/interfaz. Las capturas HID compuestas suelen mezclar informes del teclado y del ratón.
- Las capturas de Windows requieren la interfaz extcap **USBPcap**; asegúrate de que siga disponible después de las actualizaciones de Wireshark, ya que la ausencia de extcaps deja las listas de dispositivos vacías.<sup>[[4]](#references)</sup>
- Correlaciona siempre la tupla de bus, dispositivo e interfaz (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; por ejemplo, `1.9.1`) antes de decodificar cualquier cosa; mezclar varios teclados o dispositivos de almacenamiento produce pulsaciones sin sentido.<sup>[[10]](#references)</sup>

## References

- [1] [Informe de HackIT CTF 2017: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Análisis de la captura de paquetes de un teclado USB](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - write-up de pcap 1 y 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Configuración de captura USB de Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Definición de clase de dispositivo para dispositivos de interfaz humana (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Tablas de uso HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Referencia de filtros de visualización de Wireshark: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Referencia de filtros de visualización de Wireshark: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
