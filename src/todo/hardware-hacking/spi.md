# SPI

{{#include ../../banners/hacktricks-training.md}}

## Información básica

SPI (Serial Peripheral Interface) es un bus serie síncrono utilizado habitualmente para la comunicación a corta distancia entre circuitos integrados. Un controlador proporciona el reloj y selecciona un periférico, como una EEPROM, un sensor o un dispositivo de control, mediante una señal de selección de chip.<sup>[[1]](#references)</sup>

Varios periféricos pueden compartir las líneas de reloj y datos, normalmente con una selección de chip independiente para cada periférico. El controlador coordina las transferencias; normalmente, los periféricos no se comunican directamente entre sí a través del bus SPI. La polaridad y la temporización de la selección de chip dependen del dispositivo; la selección activa en nivel bajo es común, pero no universal. SPI no define descubrimiento, direccionamiento, comandos ni una única longitud máxima de transferencia, por lo que siempre se debe consultar la hoja de datos del objetivo.<sup>[[1]](#references)</sup>

MOSI/COPI transporta datos del controlador al periférico, y MISO/CIPO transporta datos del periférico al controlador. Ambas direcciones pueden desplazarse simultáneamente. La relación entre un comando, una dirección, los ciclos dummy y los datos devueltos la define el periférico —no SPI— y depende de la polaridad y la fase del reloj (modos 0–3). No se debe asumir que la salida comienza exactamente un reloj después de que termine la entrada.<sup>[[1]](#references)</sup>

## Extracción de Firmware de EEPROM

Extraer el firmware puede ser útil para analizarlo y encontrar vulnerabilidades. Es posible que la imagen correcta no esté disponible en línea o que difiera según el modelo, la revisión del hardware o la versión, por lo que extraerla directamente del dispositivo físico proporciona un objetivo de evaluación exacto.

Una consola serie puede ser útil, pero su sistema de archivos puede ser de solo lectura y el objetivo puede carecer de herramientas de análisis, incluidas las utilidades necesarias para enviar y recibir tráfico de prueba o extraer binarios cómodamente. Una imagen offline conserva el diseño completo de la flash y permite extraer el sistema de archivos y realizar ingeniería inversa sin modificar el objetivo en ejecución.

Durante una evaluación física autorizada, un volcado verificado también puede servir para realizar modificaciones controladas y pruebas de reflashing. Esto incluye cambiar archivos o inyectar un payload/backdoor de prueba para demostrar persistencia a nivel de firmware. Conserva varias lecturas coincidentes y la imagen original antes de realizar cualquier escritura: un voltaje, una selección de chip, un diseño o una imagen incorrectos pueden dejar el dispositivo inutilizable.

### Programador y lector de EEPROM CH341A

Esta herramienta USB económica puede extraer y reflashear dispositivos EEPROM serie y flash SPI compatibles. Se utiliza habitualmente con chips de flash SPI NOR que almacenan el firmware BIOS/UEFI de los PC y resulta práctica durante accesos físicos de duración limitada.

![dibujo](../../images/board_image_ch341a.jpg)

Conecta la memoria flash al CH341A y, después, conecta el programador al ordenador. Si el programador no se detecta, comprueba el cable USB, los permisos del sistema operativo y el driver adecuado del CH341A antes de solucionar problemas del chip objetivo. Confirma el voltaje del chip, el pin 1, el cableado del adaptador y la salida del programador mediante las hojas de datos o un medidor; **no** te bases en una regla como colocar VCC en el lado opuesto al conector USB. Una orientación incorrecta o aplicar 5 V a un componente de 3,3/1,8 V puede destruirlo. Las lecturas en circuito también pueden fallar porque el resto de la placa carga o alimenta el bus.<sup>[[2]](#references)</sup>

![dibujo](../../images/connect_wires_ch341a.jpg) ![dibujo](../../images/eeprom_plugged_ch341a.jpg)

Utiliza software como `flashrom` o G-Flash para leer el chip. G-Flash es una GUI minimalista y puede detectar automáticamente dispositivos compatibles, lo que resulta práctico durante una adquisición rápida, pero confirma por tu cuenta el modelo y el voltaje detectados. Especifica el programador exacto y, cuando sea necesario, el modelo exacto del chip; realiza al menos dos lecturas y compara sus hashes antes de considerar fiable un volcado.<sup>[[2]](#references)</sup>

![dibujo](../../images/connected_status_ch341a.jpg)

Después de extraer el firmware, el análisis puede realizarse sobre los archivos binarios. Se pueden utilizar herramientas como strings, hexdump, xxd, binwalk, etc. para extraer mucha información sobre el firmware, así como sobre todo el sistema de archivos.

Para el análisis inicial, Binwalk puede buscar firmas conocidas y extraer contenido embebido compatible:
```
binwalk -e <filename>
```
El archivo de salida puede usar `.bin`, `.rom` u otra extensión; la extensión no establece el formato.

> [!CAUTION]
> Ten en cuenta que la extracción del firmware es un proceso delicado y requiere mucha paciencia. Cualquier manipulación incorrecta puede corromper potencialmente el firmware o incluso borrarlo por completo y dejar el dispositivo inutilizable. Se recomienda estudiar el dispositivo específico antes de intentar extraer el firmware.

### Bus Pirate + flashrom

![Programador y lector de EEPROM CH341A - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Algunas hojas de datos etiquetan los pines de destino como `DI` y `DO`: para una conexión flash convencional de una sola línea de datos, el controlador **MOSI/COPI se conecta a DI** y el controlador **MISO/CIPO se conecta a DO**. Verifica la hoja de datos del objetivo, ya que los componentes con E/S dual o cuádruple reutilizan los pines en otros modos.

![Programador y lector de EEPROM CH341A - Bus Pirate + flashrom: Ten en cuenta que, aunque el PINOUT de Pirate Bus indica pines para que MOSI y MISO se conecten a SPI, algunos SPI pueden...](<../../images/image (360).png>)

En Windows o Linux puedes usar el programa [**`flashrom`**](https://www.flashrom.org/Flashrom) para volcar el contenido de la memoria flash ejecutando algo como:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
La documentación reciente de Bus Pirate también muestra los parámetros opcionales `serialspeed` y `spispeed`. Empieza de forma conservadora si los cables largos o la carga del circuito hacen que las lecturas sean inestables.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Introducción a la interfaz SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Manual de flashrom — programador SPI CH341A y opciones de lectura/escritura](https://flashrom.org/classic_cli_manpage.html)
- [3] [Documentación de Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
