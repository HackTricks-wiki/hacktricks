# SPI

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

SPI (Serial Peripheral Interface) es un Protocolo de Comunicación Serial Síncrono utilizado en sistemas embebidos para la comunicación a corta distancia entre Circuitos Integrados (ICs). El Protocolo de Comunicación SPI hace uso de la arquitectura maestro-esclavo que es orquestada por la Señal de Reloj y Selección de Chip. Una arquitectura maestro-esclavo consta de un maestro (generalmente un microprocesador) que gestiona periféricos externos como EEPROM, sensores, dispositivos de control, etc., que son considerados esclavos.

Se pueden conectar varios esclavos a un maestro, pero los esclavos no pueden comunicarse entre sí. Los esclavos son administrados por dos pines, reloj y selección de chip. Como SPI es un protocolo de comunicación síncrono, los pines de entrada y salida siguen las señales de reloj. La selección de chip es utilizada por el maestro para seleccionar un esclavo e interactuar con él. Cuando la selección de chip está alta, el dispositivo esclavo no está seleccionado, mientras que cuando está baja, el chip ha sido seleccionado y el maestro estaría interactuando con el esclavo.

Los pines MOSI (Master Out, Slave In) y MISO (Master In, Slave Out) son responsables del envío y recepción de datos. Los datos se envían al dispositivo esclavo a través del pin MOSI mientras la selección de chip se mantiene baja. Los datos de entrada contienen instrucciones, direcciones de memoria o datos según la hoja de datos del proveedor del dispositivo esclavo. Tras una entrada válida, el pin MISO es responsable de transmitir datos al maestro. Los datos de salida se envían exactamente en el siguiente ciclo de reloj después de que finaliza la entrada. Los pines MISO transmiten datos hasta que los datos se transmiten por completo o el maestro establece la selección de chip en alto (en ese caso, el esclavo dejaría de transmitir y el maestro no escucharía después de ese ciclo de reloj).

## Extracción de Firmware de EEPROMs

La extracción de firmware puede ser útil para analizar el firmware y encontrar vulnerabilidades en ellos. A menudo, el firmware no está disponible en internet o es irrelevante debido a variaciones de factores como el número de modelo, la versión, etc. Por lo tanto, extraer el firmware directamente del dispositivo físico puede ser útil para ser específico al buscar amenazas.

Obtener una Consola Serial puede ser útil, pero a menudo sucede que los archivos son de solo lectura. Esto limita el análisis debido a varias razones. Por ejemplo, las herramientas que se requieren para enviar y recibir paquetes no estarían presentes en el firmware. Por lo tanto, extraer los binarios para analizarlos inversamente no es factible. Por lo tanto, tener todo el firmware volcado en el sistema y extraer los binarios para su análisis puede ser muy útil.

Además, durante la revisión y el acceso físico a dispositivos, el volcado del firmware puede ayudar a modificar los archivos o inyectar archivos maliciosos y luego regrabarlos en la memoria, lo que podría ser útil para implantar una puerta trasera en el dispositivo. Por lo tanto, hay numerosas posibilidades que se pueden desbloquear con la extracción de firmware.

### Programador y Lector de EEPROM CH341A

Este dispositivo es una herramienta económica para volcar firmwares de EEPROMs y también regrabarlos con archivos de firmware. Esta ha sido una opción popular para trabajar con chips de BIOS de computadora (que son simplemente EEPROMs). Este dispositivo se conecta a través de USB y necesita herramientas mínimas para comenzar. Además, generalmente realiza la tarea rápidamente, por lo que puede ser útil también en el acceso físico al dispositivo.

<img src="../../.gitbook/assets/board_image_ch341a.jpg" alt="drawing" width="400" align="center"/>

Conecta la memoria EEPROM con el Programador CH341a y enchufa el dispositivo en la computadora. En caso de que el dispositivo no sea detectado, intenta instalar los controladores en la computadora. Además, asegúrate de que la EEPROM esté conectada en la orientación correcta (generalmente, coloca el Pin VCC en orientación inversa al conector USB) o de lo contrario, el software no podrá detectar el chip. Consulta el diagrama si es necesario:

<img src="../../.gitbook/assets/connect_wires_ch341a.jpg" alt="drawing" width="350"/>

<img src="../../.gitbook/assets/eeprom_plugged_ch341a.jpg" alt="drawing" width="350"/>

Finalmente, utiliza software como flashrom, G-Flash (GUI), etc. para volcar el firmware. G-Flash es una herramienta GUI mínima que es rápida y detecta automáticamente la EEPROM. Esto puede ser útil si se necesita extraer el firmware rápidamente, sin tener que trastear mucho con la documentación.

<img src="../../.gitbook/assets/connected_status_ch341a.jpg" alt="drawing" width="350"/>

Después de volcar el firmware, el análisis se puede realizar en los archivos binarios. Herramientas como strings, hexdump, xxd, binwalk, etc. se pueden utilizar para extraer mucha información sobre el firmware, así como sobre todo el sistema de archivos también.

Para extraer el contenido del firmware, se puede utilizar binwalk. Binwalk analiza las firmas hexadecimales e identifica los archivos en el archivo binario y es capaz de extraerlos.
```
binwalk -e <filename>
```
El <filename> puede ser .bin o .rom según las herramientas y configuraciones utilizadas.

{% hint style="danger" %} Ten en cuenta que la extracción del firmware es un proceso delicado que requiere mucha paciencia. Cualquier error puede potencialmente corromper el firmware o incluso borrarlo por completo y hacer que el dispositivo sea inutilizable. Se recomienda estudiar el dispositivo específico antes de intentar extraer el firmware. {% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (907).png>)

Ten en cuenta que aunque el PINOUT del Bus Pirate indica pines para **MOSI** y **MISO** para conectarse a SPI, algunos SPI pueden indicar los pines como DI y DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (357).png>)

En Windows o Linux, puedes usar el programa [**`flashrom`**](https://www.flashrom.org/Flashrom) para volcar el contenido de la memoria flash ejecutando algo como:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipo Rojo de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
