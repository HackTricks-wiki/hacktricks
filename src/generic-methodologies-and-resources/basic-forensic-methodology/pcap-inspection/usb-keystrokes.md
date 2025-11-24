# Pulsaciones del teclado USB

{{#include ../../../banners/hacktricks-training.md}}

Si tienes un pcap que contiene la comunicación vía USB de un teclado como el siguiente:

![](<../../../images/image (962).png>)

Los teclados USB suelen usar el HID **boot protocol**, por lo que cada transferencia de interrupción hacia el host tiene solo 8 bytes: un byte con bits de modificador (Ctrl/Shift/Alt/Super), un byte reservado y hasta seis keycodes por informe. Decodificar esos bytes es suficiente para reconstruir todo lo que se escribió.

## Conceptos básicos del informe HID USB

El típico reporte IN se ve así:

| Byte | Significado |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Pueden establecerse varios bits simultáneamente. |
| 1 | Reservado/relleno pero a menudo reutilizado por teclados para juegos para datos del proveedor. |
| 2-7 | Hasta seis keycodes concurrentes en formato USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` significa "sin tecla". |

Los teclados sin NKRO suelen enviar `0x01` en el byte 2 cuando se pulsan más de seis teclas para indicar "rollover". Entender esta estructura ayuda cuando solo tienes los bytes crudos de `usb.capdata`.

## Extracción de datos HID de un PCAP

### Flujo de trabajo en Wireshark

1. **Aislar el dispositivo**: filtra el tráfico IN de interrupción desde el teclado, p. ej. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Agregar columnas útiles**: clic derecho en el campo `Leftover Capture Data` (`usb.capdata`) y en tus campos `usbhid.*` preferidos (p. ej. `usbhid.boot_report.keyboard.keycode_1`) para seguir las pulsaciones sin abrir cada frame.
3. **Ocultar informes vacíos**: aplica `!(usb.capdata == 00:00:00:00:00:00:00:00)` para eliminar frames inactivos.
4. **Exportar para post-procesamiento**: `File -> Export Packet Dissections -> As CSV`, incluye `frame.number`, `usb.src`, `usb.capdata`, y `usbhid.modifiers` para scriptar la reconstrucción más tarde.

### Flujo de trabajo por línea de comandos

`ctf-usb-keyboard-parser` ya automatiza la clásica pipeline tshark + sed:
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
Esos archivos por dispositivo se pueden insertar directamente en cualquier decoder. Si la captura proviene de teclados BLE tunelizados sobre GATT, filtra con `btatt.value && frame.len == 20` y vuelca los payloads hex antes de decodificar.

## Automatizando la decodificación

- **ctf-usb-keyboard-parser** sigue siendo útil para desafíos CTF rápidos y ya se incluye en el repositorio.
- **CTF-Usb_Keyboard_Parser** (`main.py`) analiza de forma nativa tanto archivos `pcap` como `pcapng`, entiende `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`, y no requiere tshark, por lo que funciona bien dentro de sandboxes aislados.
- **USB-HID-decoders** añade visualizadores para keyboard, mouse y tablet. Puedes ejecutar el script auxiliar `extract_hid_data.sh` (tshark backend) o `extract_hid_data.py` (scapy backend) y luego pasar el archivo de texto resultante al decoder o a los módulos de replay para ver cómo se reproducen los keystrokes.

## Decodificador rápido en Python
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
Aliméntalo con las líneas hex simples volcadas anteriormente para obtener una reconstrucción aproximada instantánea sin cargar un parser completo en el entorno.

## Consejos para solución de problemas

- Si Wireshark no rellena los campos `usbhid.*`, probablemente no se capturó el descriptor de informe HID. Vuelve a enchufar el teclado mientras capturas o recurre al `usb.capdata` crudo.
- Las capturas en Windows requieren la interfaz extcap **USBPcap**; asegúrate de que sobrevivió a las actualizaciones de Wireshark, ya que la ausencia de extcaps deja las listas de dispositivos vacías.
- Siempre correlaciona `usb.bus_id:device:interface` (p. ej. `1.9.1`) antes de decodificar nada — mezclar múltiples teclados o dispositivos de almacenamiento conduce a pulsaciones sin sentido.

## Referencias

- [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [HackTheBox Deadly Arthropod write-up](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)
- [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
