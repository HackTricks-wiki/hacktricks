# SPI

{{#include ../../banners/hacktricks-training.md}}

## Información básica

SPI (Serial Peripheral Interface) es un protocolo de comunicación serial síncrona utilizado en sistemas embebidos para la comunicación a corta distancia entre ICs (Integrated Circuits). El protocolo de comunicación SPI utiliza una arquitectura master-slave orquestada por las señales de Clock y Chip Select. Una arquitectura master-slave consiste en un master (normalmente un microprocesador) que administra periféricos externos como EEPROMs, sensores, dispositivos de control, etc., que se consideran los slaves.

Se pueden conectar múltiples slaves a un master, pero los slaves no pueden comunicarse entre sí. Los slaves son administrados mediante dos pines: Clock y Chip Select. Como SPI es un protocolo de comunicación síncrona, los pines de entrada y salida siguen las señales de Clock. El Chip Select es utilizado por el master para seleccionar un slave e interactuar con él. Cuando el Chip Select está en estado alto, el dispositivo slave no está seleccionado; cuando está en estado bajo, el chip ha sido seleccionado y el master interactúa con el slave.

MOSI (Master Out, Slave In) y MISO (Master In, Slave Out) son responsables de enviar y recibir datos. Los datos se envían al dispositivo slave a través del pin MOSI mientras el Chip Select se mantiene en estado bajo. Los datos de entrada contienen instrucciones, direcciones de memoria o datos según el datasheet del fabricante del dispositivo slave. Tras una entrada válida, el pin MISO se encarga de transmitir datos al master. Los datos de salida se envían exactamente en el siguiente ciclo de Clock después de que termina la entrada. Los pines MISO transmiten datos hasta que estos se transmiten por completo o hasta que el master establece el pin Chip Select en estado alto (en ese caso, el slave deja de transmitir y el master deja de escuchar después de ese ciclo de Clock).

## Dumping de Firmware desde EEPROMs

El dumping de firmware puede ser útil para analizar el firmware y encontrar vulnerabilidades en él. A menudo, el firmware no está disponible en Internet o es irrelevante debido a variaciones en factores como el número de modelo, la versión, etc. Por ello, extraer el firmware directamente del dispositivo físico puede ayudar a ser más específico al buscar amenazas.

Obtener una Serial Console puede ser útil, pero a menudo ocurre que los archivos son de solo lectura. Esto limita el análisis por diversos motivos. Por ejemplo, las herramientas necesarias para enviar y recibir paquetes no estarían presentes en el firmware. Por tanto, extraer los binarios para hacerles reverse engineering no resulta viable. Por ello, disponer de todo el firmware dumpeado en el sistema y extraer los binarios para analizarlos puede ser muy útil.

Además, durante red teaming y al obtener acceso físico a dispositivos, dumpear el firmware puede ayudar a modificar los archivos o inyectar archivos maliciosos y después reflashearlos en la memoria, lo que podría ser útil para implantar un backdoor en el dispositivo. Por tanto, el firmware dumping permite desbloquear numerosas posibilidades.

### CH341A EEPROM Programmer and Reader

Este dispositivo es una herramienta económica para dumpear firmwares desde EEPROMs y también reflashearlas con archivos de firmware. Ha sido una opción popular para trabajar con chips BIOS de computadoras (que no son más que EEPROMs). Este dispositivo se conecta mediante USB y necesita muy pocas herramientas para comenzar. Además, normalmente realiza la tarea rápidamente, por lo que también puede ser útil durante el acceso físico a dispositivos.

![drawing](../../images/board_image_ch341a.jpg)

Conecta la memoria EEPROM al CH341a Programmer y conecta el dispositivo a la computadora. En caso de que el dispositivo no sea detectado, intenta instalar los drivers en la computadora. Además, asegúrate de que la EEPROM esté conectada en la orientación correcta (normalmente, coloca el pin VCC en orientación inversa respecto al conector USB); de lo contrario, el software no podrá detectar el chip. Consulta el diagrama si es necesario:

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Finalmente, utiliza softwares como flashrom, G-Flash (GUI), etc. para dumpear el firmware. G-Flash es una herramienta GUI minimalista y rápida que detecta automáticamente la EEPROM. Esto puede ser útil cuando el firmware debe extraerse rápidamente, sin tener que revisar demasiado la documentación.

![drawing](../../images/connected_status_ch341a.jpg)

Después de dumpear el firmware, el análisis puede realizarse sobre los archivos binarios. Se pueden utilizar herramientas como strings, hexdump, xxd, binwalk, etc. para extraer mucha información sobre el firmware y también sobre todo el sistema de archivos.

Para extraer el contenido del firmware, se puede utilizar binwalk. Binwalk analiza las firmas hexadecimales, identifica los archivos dentro del archivo binario y es capaz de extraerlos.
```
binwalk -e <filename>
```
Puede ser `.bin` o `.rom`, según las herramientas y configuraciones utilizadas.

> [!CAUTION]
> Ten en cuenta que la extracción del firmware es un proceso delicado y requiere mucha paciencia. Cualquier manipulación incorrecta puede corromper potencialmente el firmware o incluso borrarlo por completo, dejando el dispositivo inutilizable. Se recomienda estudiar el dispositivo específico antes de intentar extraer el firmware.

### Bus Pirate + flashrom

![Programador y lector de EEPROM CH341A - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Ten en cuenta que, aunque el PINOUT del Bus Pirate indique pines **MOSI** y **MISO** para conectarse a SPI, algunos SPIs pueden indicar los pines como DI y DO. **MOSI -> DI, MISO -> DO**

![Programador y lector de EEPROM CH341A - Bus Pirate + flashrom: Ten en cuenta que, aunque el PINOUT del Bus Pirate indique pines MOSI y MISO para conectarse a SPI, algunos SPIs pueden...](<../../images/image (360).png>)

En Windows o Linux puedes utilizar el programa [**`flashrom`**](https://www.flashrom.org/Flashrom) para volcar el contenido de la memoria flash ejecutando algo como:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{{#include ../../banners/hacktricks-training.md}}
