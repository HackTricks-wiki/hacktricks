# SPI

{{#include ../../banners/hacktricks-training.md}}

## Información básica

SPI (Serial Peripheral Interface) es un bus serie síncrono que se utiliza habitualmente para la comunicación a corta distancia entre circuitos integrados. Un controlador proporciona el reloj y selecciona un periférico, como una EEPROM, un sensor o un dispositivo de control, mediante una señal chip-select.<sup>[[1]](#references)</sup>

Varios periféricos pueden compartir las líneas de reloj y datos, normalmente con un chip-select independiente para cada periférico. El controlador coordina las transferencias; los periféricos normalmente no se comunican directamente entre sí a través del bus SPI. La polaridad y la temporización de chip-select dependen del dispositivo; la selección activa en nivel bajo es común, pero no universal. SPI no define el descubrimiento, el direccionamiento, los comandos ni una longitud máxima única de transferencia, así que consulta siempre la hoja de datos del dispositivo objetivo.<sup>[[1]](#references)</sup>

MOSI/COPI transporta datos del controlador al periférico y MISO/CIPO transporta datos del periférico al controlador. Ambos sentidos pueden desplazarse simultáneamente. La relación entre un comando, una dirección, los ciclos dummy y los datos devueltos la define el periférico —no SPI— y depende de la polaridad y la fase del reloj (modos 0–3). No des por hecho que la salida empieza exactamente un ciclo de reloj después de que termine la entrada.<sup>[[1]](#references)</sup>

## Volcado de firmware de EEPROM

Volcar el firmware puede resultar útil para analizarlo y encontrar vulnerabilidades. Es posible que la imagen correcta no esté disponible en línea o que difiera según el modelo, la revisión del hardware o la versión, así que extraerla directamente del dispositivo físico proporciona un objetivo de evaluación exacto.

Una consola serie puede ser útil, pero su sistema de archivos puede ser de solo lectura y el objetivo puede carecer de herramientas de análisis, incluidas las utilidades necesarias para enviar/recibir tráfico de prueba o extraer binarios cómodamente. Una imagen sin conexión conserva el diseño completo de la memoria flash y permite extraer el sistema de archivos y realizar ingeniería inversa sin modificar el objetivo en ejecución.

Durante una evaluación física autorizada, un volcado verificado también puede servir para realizar pruebas controladas de modificación y reprogramación. Esto incluye cambiar archivos o inyectar un payload/puerta trasera de prueba para demostrar persistencia a nivel de firmware. Conserva varias lecturas coincidentes y la imagen original antes de escribir nada: un voltaje, una selección de chip, una disposición o una imagen incorrectos pueden dejar el dispositivo inutilizable.

### Programador y lector de EEPROM CH341A

Esta herramienta USB económica puede volcar y reprogramar dispositivos compatibles de EEPROM serie y memoria flash SPI. Se utiliza habitualmente con los chips de memoria flash NOR SPI que almacenan el firmware del BIOS/UEFI de PC y resulta práctica cuando se dispone de poco tiempo de acceso físico.

![drawing](../../images/board_image_ch341a.jpg)

Conecta la memoria flash al CH341A y luego conecta el programador al ordenador. Si el programador no se detecta, comprueba el cable USB, los permisos del sistema operativo y el controlador CH341A adecuado antes de solucionar problemas con el chip objetivo. Confirma el voltaje del chip, el pin 1, el cableado del adaptador y la salida del programador consultando las hojas de datos o usando un multímetro; **no** te fíes de una regla como colocar VCC en el lado opuesto al conector USB. Una orientación incorrecta o aplicar 5 V a un componente de 3,3/1,8 V puede destruirlo. Las lecturas en circuito también pueden fallar porque el resto de la placa carga o alimenta el bus.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Usa software como `flashrom` o G-Flash para leer el chip. G-Flash es una interfaz gráfica mínima y puede detectar automáticamente dispositivos compatibles, lo que resulta práctico para una adquisición rápida, pero confirma por tu cuenta el modelo detectado y el voltaje. Especifica el programador exacto y, cuando sea necesario, el modelo exacto del chip; realiza al menos dos lecturas y compara sus hashes antes de considerar fiable un volcado.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Tras volcar el firmware, el análisis puede realizarse sobre los archivos binarios. Se pueden utilizar herramientas como strings, hexdump, xxd, binwalk, etc. para extraer mucha información sobre el firmware y también sobre todo el sistema de archivos.

Para el análisis inicial, Binwalk puede buscar firmas conocidas y extraer contenido integrado compatible:

```
binwalk -e <filename>
```

El archivo de salida puede usar `.bin`, `.rom` u otra extensión; la extensión no determina el formato.

> [!CAUTION]
> Ten en cuenta que extraer firmware es un proceso delicado y requiere mucha paciencia. Cualquier manipulación incorrecta podría dañar el firmware o incluso borrarlo por completo y dejar el dispositivo inutilizable. Se recomienda estudiar el dispositivo específico antes de intentar extraer el firmware.

### Bus Pirate + flashrom

![Programador y lector EEPROM CH341A - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Algunas hojas de datos etiquetan los pines del dispositivo como `DI` y `DO`: en una conexión flash convencional de una sola línea de datos, el pin **MOSI/COPI** del controlador se conecta a DI y el pin **MISO/CIPO** del controlador se conecta a DO. Consulta la hoja de datos del dispositivo, ya que los componentes con E/S duales/cuádruples reutilizan los pines en otros modos.

![Programador y lector EEPROM CH341A - Bus Pirate + flashrom: Ten en cuenta que, aunque el PINOUT del Bus Pirate indica pines para conectar MOSI y MISO a SPI, algunos dispositivos SPI pueden...](<../../images/image (360).png>)

En Windows o Linux puedes usar el programa [**`flashrom`**](https://www.flashrom.org/Flashrom) para volcar el contenido de la memoria flash ejecutando algo como:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

La documentación reciente de Bus Pirate también muestra los parámetros opcionales `serialspeed` y `spispeed`. Empieza con valores conservadores si los cables largos o la carga en circuito hacen que las lecturas sean inestables.<sup>[[3]](#references)</sup>

### Lecturas en circuito cuando el controlador comparte el bus de flash

Un clip SOIC puede suministrar alimentación al flash y al resto de la PCB. Si el MCU recibe alimentación y accede al mismo chip, sus transferencias SPI pueden entrar en conflicto con las del programador externo. Por tanto, el resultado `No EEPROM/flash device found` no demuestra que el flash esté ausente o no sea compatible. Comprueba primero el pinout, el voltaje y el contacto; después, determina si el controlador integrado también está activo.<sup>[[4]](#references)</sup>

Si hay un punto de prueba de reset, confirma su polaridad y voltaje con un multímetro antes de activarlo. Mantener el MCU en reset puede dejar el flash accesible e impedir que el host SPI compita por el bus. Otras opciones son desoldar el chip o registrar pasivamente las lecturas del MCU. Esta última opción no permite acceder a regiones que no se hayan leído ni escribir en el chip, y el cableado adicional de las sondas puede perturbar un bus rápido. Intervenir en el oscilador o en el modo de arranque depende del objetivo; no sustituye la comprobación del esquema y las señales.<sup>[[4]](#references)</sup>

Con el MCU inactivo, una Raspberry Pi con una interfaz `spidev` habilitada puede leer mediante el programador `linux_spi` de flashrom. Cambia `-p` si usas otro adaptador. Repite la lectura y compara los hashes antes de confiar en ella; la autodetección de SFDP y una lectura correcta **no** demuestran que las operaciones de borrado, escritura o protección contra escritura funcionen en una pieza que no sea compatible.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Reconstruir lecturas de SPI flash con un analizador lógico

Cuando no sea posible realizar una lectura activa, captura chip select, clock, los datos del controlador a la flash y los datos de la flash al controlador durante el arranque o una acción de la interfaz elegida. En PulseView, identifica primero el intervalo activo de chip select y el clock; luego configura los canales de datos del decodificador SPI según el pinout de la flash y verifica que haya un comando/dirección plausible seguido de bytes de respuesta. Exporta los bytes **MISO/salida de flash** con Binary Decoder Output View y conserva las direcciones de lectura decodificadas para poder ubicar cada respuesta en su offset correspondiente de la flash. Si solo capturas lecturas solicitadas desde los menús, obtendrás únicamente las regiones solicitadas, no una imagen completa de la flash; no concatenes las respuestas como si fueran contiguas sin comprobar las direcciones.<sup>[[4]](#references)</sup>

Si un dump parece contener gráficos y no código ejecutable, continúa con el [triaje de recursos gráficos sin procesar](../firmware-analysis/#raw-display-assets-in-external-flash).<sup>[[4]](#references)</sup>

#### Scapy y capturas SPI/QSPI mixtas

En sondas sin etiquetas, distingue MOSI de MISO identificando la línea que transporta el opcode antes de los datos de respuesta; luego verifica el comando con la hoja de datos de la flash. Los pulsos de duración inferior a un ciclo de clock pueden ser ruido de la sonda y no bits muestreados, y el cableado adicional de las pinzas puede volver poco fiables las capturas de alta velocidad.<sup>[[5]](#references)</sup>

La exportación CSV de SPI de Saleae utiliza `enable` y `disable` para delimitar un intervalo de chip select, con bytes MOSI/MISO en las filas `result`. Agrupa los bytes por intervalo antes de decodificarlos; concatenar todos los datos MISO hace que se pierdan las direcciones de las transacciones.<sup>[[5]](#references)</sup> Un `Packet` de Scapy puede modelar el encabezado MOSI con un opcode `ByteEnumField` y campos condicionales para la dirección y los ciclos dummy. En lecturas NOR de 24 bits, `0x03` tiene un opcode y tres bytes de dirección, mientras que `0x0B` añade un byte dummy. `len(req.self_build())` proporciona la longitud del encabezado modelado: en una lectura de una sola línea, `miso[header_length:]` es la respuesta de la flash, mientras que los datos MOSI posteriores al encabezado son datos don't-care del lado del controlador.<sup>[[5]](#references)</sup> Ubica las respuestas en sus direcciones decodificadas dentro de una imagen rellenada con `0xFF` y lleva un registro independiente de los offsets cubiertos. Que no se haya observado un byte no demuestra que la flash contuviera `0xFF` en esa posición.<sup>[[5]](#references)[[6]](#references)</sup>

Una lectura `0x6B` (1-1-4) de tipo W25Q usa una línea para el opcode y la dirección, pero IO0–IO3 para los datos de respuesta. La actividad en los antiguos pines `/WP` y `/HOLD` es una prueba más sólida de un cambio a modo quad que un clock más rápido por sí solo; un analizador de una sola línea puede decodificar incorrectamente la respuesta quad.<sup>[[5]](#references)</sup> Exporta esa fase con un analizador QSPI configurado para los anchos de línea y los ciclos dummy del comando, y luego combina las lecturas de una y cuatro líneas por dirección de flash.<sup>[[5]](#references)[[7]](#references)</sup> `spidump` detecta automáticamente ambos formatos de exportación, descarta las lecturas decodificadas con un ancho de línea incorrecto e informa la cobertura de lectura.<sup>[[6]](#references)</sup> Desde su repositorio, después de instalar sus dependencias, combina las capturas con:<sup>[[6]](#references)</sup>

```bash
python main.py single_lane_boot.csv --merge quad_boot.txt -o recovered_flash.bin -v
```

El resultado sigue siendo una observación parcial, no un volcado completo del chip.<sup>[[5]](#references)[[6]](#references)</sup> Para inspeccionar las escrituras por separado, correlaciona la habilitación de escritura `0x06`, las consultas de estado `0x05`, los códigos de borrado y los comandos de programación de página `0x02`. Los datos de programación de página siguen a la dirección en MOSI y no se incluyen en una reconstrucción de solo lectura.<sup>[[5]](#references)</sup> Analiza la imagen resultante con [análisis de firmware](../firmware-analysis/), conservando la información de cobertura de lectura.

## References

- [1] [Analog Devices — Introducción a la interfaz SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Manual de flashrom — Programador SPI CH341A y opciones de lectura/escritura](https://flashrom.org/classic_cli_manpage.html)
- [3] [Documentación de Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Repaso del hardware hacking, parte 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [5] [VoidStar Security — Ampliación de Scapy para la ingeniería inversa de hardware](https://voidstarsec.com/blog/scapy-spi-reconstruction)
- [6] [spidump — Captura y reconstrucción de trazas SPI/QSPI](https://github.com/wrongbaud/spidump)
- [7] [Analizador QSPI para Saleae Logic/KingstVIS](https://github.com/AddioElectronics/QSPI-Analyzer)
{{#include ../../banners/hacktricks-training.md}}
