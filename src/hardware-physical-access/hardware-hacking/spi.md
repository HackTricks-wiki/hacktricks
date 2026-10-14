# SPI

{{#include ../../banners/hacktricks-training.md}}

## Información básica

SPI (Serial Peripheral Interface) es un bus serial síncrono que se usa comúnmente para la comunicación a corta distancia entre circuitos integrados. Un controlador proporciona la señal de reloj y selecciona un periférico, como una EEPROM, un sensor o un dispositivo de control, mediante una señal de selección del chip.<sup>[[1]](#references)</sup>

Varios periféricos pueden compartir las líneas de reloj y datos, normalmente con una señal de selección del chip independiente para cada periférico. El controlador coordina las transferencias; normalmente, los periféricos no se comunican directamente entre sí a través del bus SPI. La polaridad y la temporización de la señal de selección del chip dependen del dispositivo; la selección activa en nivel bajo es común, pero no universal. SPI no define mecanismos de detección, direccionamiento, comandos ni una longitud máxima única de transferencia, así que consulta siempre la hoja de datos del dispositivo objetivo.<sup>[[1]](#references)</sup>

MOSI/COPI transporta datos del controlador al periférico, y MISO/CIPO transporta datos del periférico al controlador. Los datos pueden desplazarse simultáneamente en ambas direcciones. La relación entre un comando, una dirección, los ciclos dummy y los datos devueltos la define el periférico —no SPI— y depende de la polaridad y la fase del reloj (modos 0–3). No des por sentado que la salida comienza exactamente un ciclo de reloj después de que termina la entrada.<sup>[[1]](#references)</sup>

## Volcado de firmware de EEPROMs

Volcar el firmware puede ser útil para analizarlo y encontrar vulnerabilidades. Es posible que la imagen correcta no esté disponible en línea o que varíe según el modelo, la revisión del hardware o la versión; por ello, extraerla directamente del dispositivo físico proporciona un objetivo de evaluación exacto.

Una consola serial puede ser útil, pero su sistema de archivos podría ser de solo lectura y el objetivo quizá no tenga herramientas de análisis, incluidas utilidades para enviar o recibir tráfico de prueba o extraer binarios fácilmente. Una imagen offline conserva el diseño completo de la flash y permite extraer el sistema de archivos y hacer ingeniería inversa sin modificar el objetivo en ejecución.

Durante una evaluación física autorizada, un volcado verificado también puede servir para realizar pruebas controladas de modificación y reflasheo. Esto incluye cambiar archivos o inyectar un payload de prueba/backdoor para demostrar persistencia a nivel de firmware. Conserva varias lecturas coincidentes y la imagen original antes de escribir nada: un voltaje, una selección de chip, un diseño o una imagen incorrectos pueden dejar el dispositivo inutilizable.

### Programador y lector de EEPROM CH341A

Esta herramienta USB económica puede volcar y reflashear dispositivos compatibles de memoria EEPROM serial y flash SPI. Se usa comúnmente con los chips de flash SPI NOR que almacenan el firmware BIOS/UEFI de PC y es práctica cuando el acceso físico está limitado en el tiempo.

![drawing](../../images/board_image_ch341a.jpg)

Conecta la memoria flash al CH341A y luego conecta el programador al ordenador. Si el programador no se detecta, comprueba el cable USB, los permisos del sistema operativo y el controlador adecuado del CH341A antes de solucionar problemas con el chip objetivo. Confirma el voltaje del chip, el pin 1, el cableado del adaptador y la salida del programador con las hojas de datos o un multímetro; **no** te fíes de reglas como colocar VCC en el lado opuesto al conector USB. Una orientación incorrecta o aplicar 5 V a un componente de 3,3/1,8 V puede destruirlo. Las lecturas en circuito también pueden fallar porque el resto de la placa carga o alimenta el bus.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Usa software como `flashrom` o G-Flash para leer el chip. G-Flash es una interfaz gráfica minimalista que puede detectar automáticamente dispositivos compatibles, lo cual puede resultar práctico durante una adquisición rápida, pero confirma por tu cuenta el modelo detectado y el voltaje. Especifica el programador exacto y, cuando sea necesario, el modelo exacto del chip; realiza al menos dos lecturas y compara sus hashes antes de considerar fiable un volcado.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Después de volcar el firmware, puedes analizar los archivos binarios. Se pueden usar herramientas como strings, hexdump, xxd, binwalk, etc. para extraer mucha información sobre el firmware y también sobre todo el sistema de archivos.

Para el análisis inicial, Binwalk puede buscar firmas conocidas y extraer contenido integrado compatible:

```
binwalk -e <filename>
```

El archivo de salida puede usar la extensión `.bin`, `.rom` u otra; la extensión no determina el formato.

> [!CAUTION]
> Ten en cuenta que extraer firmware es un proceso delicado y requiere mucha paciencia. Cualquier manipulación incorrecta puede corromper el firmware o incluso borrarlo por completo y dejar el dispositivo inutilizable. Se recomienda estudiar el dispositivo específico antes de intentar extraer el firmware.

### Bus Pirate + flashrom

![Programador y lector EEPROM CH341A - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Algunas hojas de datos etiquetan los pines del objetivo como `DI` y `DO`: en una conexión convencional de flash con una sola línea de datos, **MOSI/COPI** del controlador se conecta a **DI**, y **MISO/CIPO** del controlador se conecta a **DO**. Verifica la hoja de datos del objetivo, ya que los componentes con I/O dual/cuádruple reutilizan los pines en otros modos.

![Programador y lector EEPROM CH341A - Bus Pirate + flashrom: Ten en cuenta que, aunque el pinout del Bus Pirate indica pines para conectar MOSI y MISO a SPI, algunos SPI pueden...](<../../images/image (360).png>)

En Windows o Linux puedes usar el programa [**`flashrom`**](https://www.flashrom.org/Flashrom) para volcar el contenido de la memoria flash ejecutando algo como:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

La documentación reciente de Bus Pirate también muestra los parámetros opcionales `serialspeed` y `spispeed`. Empieza con valores conservadores si los cables largos o la carga en el circuito hacen que las lecturas sean inestables.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Introducción a la interfaz SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Manual de flashrom — programador SPI CH341A y opciones de lectura/escritura](https://flashrom.org/classic_cli_manpage.html)
- [3] [Documentación de Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
