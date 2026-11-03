# Pulsaciones de teclas USB

{{#include ../../../banners/hacktricks-training.md}}

Si tienes un pcap que contiene la comunicación USB de un teclado como el siguiente:

![Pulsaciones de teclas USB: Si tienes un pcap que contiene la comunicación USB de un teclado como el siguiente](<../../../images/image (962).png>)

Para un teclado que usa el **boot protocol** de HID, cada informe Interrupt IN tiene una estructura fija de 8 bytes: un byte de modificadores, un byte reservado y seis bytes de códigos de tecla. El host compara informes sucesivos y asigna los códigos de tecla a usos HID para reconstruir los eventos de teclado.<sup>[[8]](#references)</sup>

Para el análisis inicial general de capturas, consulta [Inspección de Pcap](./).

## Conceptos básicos de los informes USB HID

El informe de entrada estándar del teclado en el modo boot tiene la siguiente estructura.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Significado |
| --- | --- |
| 0 | Mapa de bits de modificadores (`0x02` = Shift izquierdo, `0x20` = Shift derecho, `0x40` = Alt derecho, etc.). Se pueden activar varios bits simultáneamente. |
| 1 | Byte reservado; normalmente, los informes no utilizados deberían establecerlo en cero. El uso específico de OEM o del sistema no es portable. |
| 2-7 | Hasta seis códigos de tecla simultáneos en formato USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` significa «ninguna tecla». | 

En el formato boot, el usage ID `0x01` (`Keyboard ErrorRollOver`) se informa en todas las posiciones de tecla cuando se presionan más de seis teclas que no son modificadores; también puede indicar una combinación no reconocible.<sup>[[8]](#references)[[9]](#references)</sup> Entender esta estructura ayuda cuando solo tienes los bytes `usb.capdata` sin procesar.

## Extracción de datos HID de un PCAP

### Identifica primero la interfaz del teclado

En capturas con mucho tráfico, identifica el teclado HID antes de volcar los informes. Un buen punto de partida es la respuesta del descriptor de interfaz:<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

La clase HID define estos valores de interfaz:<sup>[[8]](#references)</sup>

- `subclass == 1` es la subclase de interfaz Boot; con `protocol == 1`, identifica un teclado Boot
- `protocol == 2` identifica un mouse Boot
- `protocol == 0` significa que no hay protocolo Boot; inspecciona el descriptor de informe HID en lugar de asumir una disposición de 8 bytes

Una interfaz compatible con Boot **no demuestra que el protocolo Boot esté activo**. Los dispositivos HID se inicializan en modo de protocolo de informe. El host selecciona el modo Boot con `SET_PROTOCOL` (`bRequest = 0x0b`, `wValue = 0`); `wValue = 1` selecciona el protocolo de informe. Si la captura incluye la enumeración, comprueba la solicitud para la interfaz del teclado (`wIndex`) antes de usar un decodificador Boot de ocho bytes. Si no está presente, verifica la disposición del informe observada en lugar de inferir el modo a partir del descriptor de interfaz.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usb.setup.bRequest == 0x0b' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address \
  -e usb.setup.wIndex -e usb.setup.wValue
```

Una vez que conozcas la interfaz, fija los filtros en `usb.bus_id`, `usb.device_address` y, si es posible, `usb.bInterfaceNumber` antes de exportar nada.

### Flujo de trabajo en Wireshark

1. **Aísla el dispositivo**: filtra el tráfico interrupt IN del teclado, por ejemplo, `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Añade columnas útiles**: haz clic con el botón derecho en el campo `Leftover Capture Data` (`usb.capdata`) y en los campos `usbhid.*` que prefieras (por ejemplo, `usbhid.boot_report.keyboard.keycode_1`) para seguir las pulsaciones sin abrir cada trama.<sup>[[11]](#references)</sup>
3. **Oculta los informes vacíos**: aplica `!(usb.capdata == 00:00:00:00:00:00:00:00)` para descartar las tramas inactivas.
4. **Exporta para el posprocesamiento**: `File -> Export Packet Dissections -> As CSV`, e incluye `frame.number`, `usb.src`, `usb.capdata` y los campos de modificadores decodificados, como `usbhid.boot_report.keyboard.modifier.left_shift` y `usbhid.boot_report.keyboard.modifier.right_alt`, para crear un script que reconstruya las pulsaciones más adelante.<sup>[[10]](#references)[[11]](#references)</sup>

### Flujo de trabajo en línea de comandos

El método clásico de extracción —volcar `usb.capdata`, descartar los informes inactivos y asignar los identificadores de uso— aparece en el análisis original de 2017 y en su tutorial.<sup>[[1]](#references)[[2]](#references)</sup>

El repositorio `ctf-usb-keyboard-parser` automatiza el flujo clásico de tshark + sed:<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

En capturas más recientes, prefiere el campo decodificado `usbhid.data` de Wireshark y, si no está disponible, usa `usb.capdata`; escribe un payload por reporte en un archivo por dispositivo:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

Esos archivos por dispositivo se pueden pasar a un decoder después de normalizar el formato hexadecimal que espera. Si la captura proviene de teclados BLE encapsulados en GATT, filtra con `btatt.value && frame.len == 20` y extrae los payloads hexadecimales antes de decodificarlos.<sup>[[7]](#references)</sup>

### Cuando el reporte no es el reporte boot clásico de 8 bytes

Una interfaz que no sea boot o un ID de reporte pueden cambiar la disposición del payload, así que no supongas que todos los reportes de teclado coinciden con `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Prefiere `usbhid.data` en lugar de `usb.capdata` cuando Wireshark ya haya analizado la capa HID.
- Si todas las líneas empiezan con un prefijo constante o un ID de reporte, elimínalo con un decoder que tenga en cuenta el desplazamiento, en vez de suponer que el byte 0 siempre es el modificador.<sup>[[7]](#references)</sup>
- Algunas exportaciones de USBPcap omiten el byte reservado, así que usar decoders compatibles con `--no-reserved` o un desplazamiento personalizado ahorra tiempo.<sup>[[7]](#references)</sup>
- Si el descriptor de reporte HID o el mapa de reportes HOGP de BLE están presentes en la captura, úsalos para recuperar la disposición real de los campos antes de escribir un parser.

### Decodificar un bitmap de teclas del protocolo de reportes

Para un teclado cuyo reporte de entrada es un bitmap en lugar de seis espacios para teclas boot, localiza su **descriptor de reporte HID** en el tráfico de enumeración. Este filtro encuentra tramas en las que Wireshark decodificó un elemento Report Size; abre una y examina el descriptor completo. Inicia una nueva captura antes de conectar el teclado si falta el descriptor.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usbhid.item.global.report_size' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address
```

Para cada informe de entrada del teclado, anota su `Report ID` (si lo hay), `Usage Page` (`0x07` para las teclas del teclado), `Usage Minimum/Maximum`, `Report Size`, `Report Count` y si cada elemento `Input` es **Variable** o **Array**. Cuenta todos los campos `Input` anteriores y el relleno constante para hallar el desplazamiento en bits del campo de teclas; los campos del informe no tienen por qué estar alineados con bytes. Un campo `Variable` de un bit con usos de teclado consecutivos es un mapa de bits del estado de las teclas: el bit 0 de ese campo corresponde al primer uso declarado, el bit 1 al siguiente, y así sucesivamente. En cambio, un `Array` contiene valores que se resuelven mediante el rango de usos del descriptor; no representa una tecla pulsada por bit. Si se declara un `Report ID`, primero selecciona los informes que tengan ese prefijo y omite su byte al calcular los desplazamientos de los campos. Compara los conjuntos de usos activos entre informes consecutivos de la **misma interfaz y el mismo Report ID** para emitir solo las nuevas pulsaciones.<sup>[[8]](#references)[[12]](#references)[[13]](#references)</sup>

## Automatizar la decodificación

- **ctf-usb-keyboard-parser** sigue siendo práctico para resolver rápidamente retos CTF y ya viene incluido en el repositorio.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) analiza archivos `pcap` y `pcapng` de forma nativa, entiende `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` y no requiere tshark ni otras dependencias externas, por lo que resulta adecuado para sandboxes aislados.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** añade visualizadores de teclado, mouse y tablet. Puedes ejecutar el helper `extract_hid_data.sh` (backend de tshark) o `extract_hid_data.py` (backend de scapy) y luego pasar el archivo de texto resultante al decoder o a los módulos de reproducción para ver cómo se van desplegando las pulsaciones.<sup>[[7]](#references)</sup>

### La decodificación con estado es importante

Los teclados USB boot envían informes a la tasa de inactividad incluso cuando no hay ningún evento de tecla nuevo, por lo que las capturas pueden contener informes repetidos antes del evento de liberación. Un decoder práctico debería:<sup>[[3]](#references)[[8]](#references)</sup>

- emitir solo los keycodes recién pulsados respecto del informe anterior
- mantener el estado de los modificadores (`Shift`, `Ctrl`, `AltGr`) a partir del byte 0 o de campos analizados como `usbhid.boot_report.keyboard.modifier.left_shift` y `usbhid.boot_report.keyboard.modifier.right_alt`
- llevar el seguimiento de las teclas de alternancia, como `Caps Lock`, porque la salida en mayúsculas no depende únicamente de Shift
- recordar que los ID de uso HID son independientes de la distribución: `0x1d` corresponde a la posición física de la tecla `z`/`y`, según la distribución del teclado del host.<sup>[[9]](#references)</sup>

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

Aliméntalo con las líneas hexadecimales sin procesar volcadas anteriormente para obtener una reconstrucción aproximada al instante, sin cargar un parser completo en el entorno. En distribuciones de teclado que no sean estadounidenses, esto reconstruye la posición física de la tecla, no necesariamente el carácter final que aparece en el host de la víctima.

## Consejos para solucionar problemas

- Si Wireshark no completa los campos `usbhid.*`, probablemente no se capturó el descriptor de informe HID. Vuelve a conectar el teclado mientras capturas o recurre a `usb.capdata` sin procesar.
- En las capturas de software de Linux, `usbmon` es la fuente habitual; en Windows, Wireshark depende de **USBPcap** extcap para poder ver URB USB sin procesar.<sup>[[4]](#references)</sup>
- Si el teclado estaba conectado a través de un hub o una base, primero confirma el descriptor de interfaz y luego decodifica solo esa pareja de dispositivo/interfaz. Las capturas HID compuestas suelen mezclar informes del teclado y del mouse.
- Las capturas de Windows requieren la interfaz extcap de **USBPcap**; asegúrate de que haya sobrevivido a las actualizaciones de Wireshark, ya que si faltan extcaps, las listas de dispositivos estarán vacías.<sup>[[4]](#references)</sup>
- Correlaciona siempre la tupla de bus, dispositivo e interfaz (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; p. ej., `1.9.1`) antes de decodificar nada: mezclar varios teclados o dispositivos de almacenamiento produce pulsaciones sin sentido.<sup>[[10]](#references)</sup>



## References

- [1] [Resolución de HackIT CTF 2017: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Análisis de captura de paquetes de un teclado USB](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [Clasificatorias ACSC 2023: resolución de pcap 1 y 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Configuración de captura USB en Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [Decodificadores USB-HID](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Definición de clase de dispositivo para dispositivos de interfaz humana (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Tablas de usos HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Referencia de filtros de visualización de Wireshark: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Referencia de filtros de visualización de Wireshark: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
- [12] [Kernel de Linux: introducción a los descriptores de informes HID](https://docs.kernel.org/hid/hidintro.html)
- [13] [snakeCTF 2024: resolución de ordinary-keyboard](https://snakectf.org/writeups/2024-quals/misc/ordinary-keyboard)
{{#include ../../../banners/hacktricks-training.md}}
