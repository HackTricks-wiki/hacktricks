# SPI

{{#include ../../banners/hacktricks-training.md}}

## Información básica

SPI (Serial Peripheral Interface) es un bus serie síncrono que se usa habitualmente para la comunicación de corta distancia entre circuitos integrados. Un controlador proporciona la señal de reloj y selecciona un periférico, como una EEPROM, un sensor o un dispositivo de control, mediante una señal chip-select.<sup>[[1]](#references)</sup>

Varios periféricos pueden compartir las líneas de reloj y datos, normalmente con una línea chip-select independiente para cada periférico. El controlador coordina las transferencias; los periféricos normalmente no se comunican directamente entre sí a través del bus SPI. La polaridad y la temporización de chip-select dependen del dispositivo; la selección activa en bajo es común, pero no universal. SPI no define mecanismos de detección, direccionamiento, comandos ni una longitud máxima única de transferencia, por lo que siempre hay que consultar la hoja de datos del dispositivo objetivo.<sup>[[1]](#references)</sup>

MOSI/COPI transporta datos del controlador al periférico, y MISO/CIPO, del periférico al controlador. Los datos pueden desplazarse simultáneamente en ambas direcciones. La relación entre un comando, una dirección, los ciclos dummy y los datos devueltos la define el periférico —no SPI— y depende de la polaridad y la fase del reloj (modos 0–3). No hay que asumir que la salida comienza exactamente un ciclo de reloj después de que termine la entrada.<sup>[[1]](#references)</sup>

## Volcado de firmware de EEPROM

Volcar el firmware puede ser útil para analizarlo y encontrar vulnerabilidades. Es posible que la imagen correcta no esté disponible en línea o que difiera según el modelo, la revisión del hardware o la versión, por lo que extraerla directamente del dispositivo físico proporciona el objetivo exacto para la evaluación.

Una consola serie puede ser útil, pero su sistema de archivos podría ser de solo lectura y el objetivo podría carecer de herramientas de análisis, incluidas las utilidades necesarias para enviar o recibir tráfico de prueba o extraer binarios de forma práctica. Una imagen sin conexión conserva el diseño completo de la memoria flash y permite extraer el sistema de archivos y hacer ingeniería inversa sin modificar el objetivo en ejecución.

Durante una evaluación física autorizada, un volcado verificado también puede servir para realizar pruebas controladas de modificación y regrabación. Esto incluye cambiar archivos o inyectar un payload de prueba/backdoor para demostrar la persistencia a nivel de firmware. Conserva varias lecturas coincidentes y la imagen original antes de escribir nada: un voltaje, una selección del chip, un diseño o una imagen incorrectos pueden dejar el dispositivo inutilizable.

### Programador y lector de EEPROM CH341A

Esta herramienta USB económica puede volcar y regrabar dispositivos compatibles de EEPROM serie y memoria flash SPI. Se usa habitualmente con chips de memoria flash SPI NOR que almacenan el firmware BIOS/UEFI de los PC, y resulta práctica cuando el acceso físico está limitado en el tiempo.

![drawing](../../images/board_image_ch341a.jpg)

Conecta la memoria flash al CH341A y, después, conecta el programador al ordenador. Si el programador no se detecta, comprueba el cable USB, los permisos del sistema operativo y el controlador CH341A adecuado antes de diagnosticar el chip objetivo. Confirma el voltaje del chip, el pin 1, el cableado del adaptador y la salida del programador consultando las hojas de datos o usando un multímetro: **no** confíes en una regla como colocar VCC en el lado opuesto al conector USB. Una orientación incorrecta o aplicar 5 V a un componente de 3,3/1,8 V puede destruirlo. Las lecturas dentro del circuito también pueden fallar porque el resto de la placa carga o alimenta el bus.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Usa software como `flashrom` o G-Flash para leer el chip. G-Flash es una interfaz gráfica mínima que puede detectar automáticamente dispositivos compatibles, lo que resulta práctico para una adquisición rápida, pero confirma por tu cuenta el modelo detectado y el voltaje. Especifica el programador exacto y, cuando sea necesario, el modelo exacto del chip; realiza al menos dos lecturas y compara sus hashes antes de considerar fiable un volcado.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Después de volcar el firmware, puedes analizar los archivos binarios. Se pueden usar herramientas como strings, hexdump, xxd, binwalk, etc. para extraer mucha información sobre el firmware y también sobre todo el sistema de archivos.

Para el análisis inicial, Binwalk puede buscar firmas conocidas y extraer el contenido integrado compatible:

```
binwalk -e <filename>
```

El archivo de salida puede usar `.bin`, `.rom` u otra extensión; la extensión no determina el formato.

> [!CAUTION]
> Ten en cuenta que extraer firmware es un proceso delicado que requiere mucha paciencia. Cualquier manipulación incorrecta puede corromper el firmware o incluso borrarlo por completo y dejar el dispositivo inutilizable. Se recomienda estudiar el dispositivo específico antes de intentar extraer el firmware.

### Bus Pirate + flashrom

![Programador y lector de EEPROM CH341A - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Algunas hojas de datos etiquetan los pines del dispositivo como `DI` y `DO`: en una conexión flash convencional de una sola línea de datos, el controlador **MOSI/COPI se conecta a DI** y **MISO/CIPO se conecta a DO**. Consulta la hoja de datos del dispositivo, ya que los componentes con entrada/salida dual o cuádruple reutilizan los pines en otros modos.

![Programador y lector de EEPROM CH341A - Bus Pirate + flashrom: Ten en cuenta que, aunque el PINOUT del Bus Pirate indica pines para conectar MOSI y MISO a SPI, algunos SPI pueden...](<../../images/image (360).png>)

En Windows o Linux puedes usar el programa [**`flashrom`**](https://www.flashrom.org/Flashrom) para volcar el contenido de la memoria flash con algo como:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

La documentación reciente de Bus Pirate también muestra los parámetros opcionales `serialspeed` y `spispeed`. Empieza de forma conservadora si los cables largos o la carga en circuito hacen que las lecturas sean inestables.<sup>[[3]](#references)</sup>

### Lecturas en circuito cuando el controlador comparte el bus flash

Un clip SOIC puede suministrar alimentación al flash y al resto de la PCB. Si el MCU recibe alimentación y accede al mismo chip, sus transferencias SPI pueden colisionar con las del programador externo. Por tanto, el resultado `No EEPROM/flash device found` no demuestra que el flash esté ausente o no sea compatible. Comprueba primero el pinout, el voltaje y el contacto; después, determina si el controlador integrado también está activo.<sup>[[4]](#references)</sup>

Si hay un punto de prueba de reset, confirma su polaridad y voltaje con un multímetro antes de activarlo. Mantener el MCU en reset puede dejar el flash accesible y detener al host SPI que está generando interferencias. Otras alternativas son desoldar el chip o registrar pasivamente las lecturas del MCU; esto último no permite acceder a las regiones que no se hayan leído ni escribir en el chip, y el cableado adicional de la sonda puede perturbar un bus rápido. Una intervención en el oscilador o en el modo de arranque depende del dispositivo y no sustituye la comprobación del esquema y las señales.<sup>[[4]](#references)</sup>

Con el MCU desactivado, una Raspberry Pi con la interfaz `spidev` habilitada puede leer mediante el programador `linux_spi` de flashrom. Cambia `-p` si usas otro adaptador. Repite la lectura y compara los hashes antes de confiar en ella; la autodetección mediante SFDP y una lectura correcta **no** demuestran que las operaciones de borrado, escritura o protección contra escritura funcionen en una pieza que, por lo demás, no es compatible.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Reconstruir lecturas de memoria flash SPI con un analizador lógico

Cuando no sea posible realizar una lectura activa, captura chip select, clock, los datos del controlador a la memoria flash y los datos de la memoria flash al controlador durante el boot o una acción elegida en la interfaz. En PulseView, identifica primero el intervalo activo de chip select y el clock; luego configura los canales de datos del decodificador SPI según el pinout de la memoria flash y verifica que aparezca un comando/dirección plausible seguido de bytes devueltos. Exporta los bytes **MISO/salida de la memoria flash** con Binary Decoder Output View y conserva las direcciones de lectura decodificadas para poder ubicar cada respuesta en su offset correspondiente de la memoria flash. Si capturas solo las lecturas solicitadas mediante los menús, obtendrás únicamente las regiones solicitadas, no una imagen completa de la memoria flash; no concatenes las respuestas como si fueran contiguas sin comprobar las direcciones.<sup>[[4]](#references)</sup>

Si un volcado parece contener gráficos en lugar de código ejecutable, continúa con el [triaje de recursos gráficos en bruto](../firmware-analysis/#raw-display-assets-in-external-flash).<sup>[[4]](#references)</sup>

## References

- [1] [Analog Devices — Introducción a la interfaz SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Manual de flashrom — Programador SPI CH341A y opciones de lectura/escritura](https://flashrom.org/classic_cli_manpage.html)
- [3] [Documentación de Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Repaso del hacking de hardware, parte 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
