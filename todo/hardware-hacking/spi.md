<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


# Información Básica

SPI (Serial Peripheral Interface) es un Protocolo de Comunicación Serial Síncrono utilizado en sistemas embebidos para la comunicación a corta distancia entre Circuitos Integrados (ICs). El Protocolo de Comunicación SPI hace uso de la arquitectura maestro-esclavo que es orquestada por la Señal de Reloj y Selección de Chip. Una arquitectura maestro-esclavo consta de un maestro (generalmente un microprocesador) que gestiona periféricos externos como EEPROM, sensores, dispositivos de control, etc., que son considerados esclavos.

Se pueden conectar varios esclavos a un maestro, pero los esclavos no pueden comunicarse entre sí. Los esclavos son administrados por dos pines, reloj y selección de chip. Como SPI es un protocolo de comunicación síncrono, los pines de entrada y salida siguen las señales de reloj. La selección de chip es utilizada por el maestro para seleccionar un esclavo e interactuar con él. Cuando la selección de chip está alta, el dispositivo esclavo no está seleccionado, mientras que cuando está baja, el chip ha sido seleccionado y el maestro estaría interactuando con el esclavo.

El MOSI (Master Out, Slave In) y MISO (Master In, Slave Out) son responsables del envío y recepción de datos. Los datos se envían al dispositivo esclavo a través del pin MOSI mientras que la selección de chip se mantiene baja. Los datos de entrada contienen instrucciones, direcciones de memoria o datos según la hoja de datos del proveedor del dispositivo esclavo. Tras una entrada válida, el pin MISO es responsable de transmitir datos al maestro. Los datos de salida se envían exactamente en el siguiente ciclo de reloj después de que finaliza la entrada. Los pines MISO transmiten datos hasta que los datos se transmiten por completo o el maestro establece el pin de selección de chip en alto (en ese caso, el esclavo dejaría de transmitir y el maestro no escucharía después de ese ciclo de reloj).

# Volcar Flash

## Bus Pirate + flashrom

![](<../../.gitbook/assets/image (201).png>)

Ten en cuenta que aunque el PINOUT del Bus Pirate indica pines para **MOSI** y **MISO** para conectarse a SPI, algunos SPI pueden indicar pines como DI y DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (648) (1) (1).png>)

En Windows o Linux puedes utilizar el programa [**`flashrom`**](https://www.flashrom.org/Flashrom) para volcar el contenido de la memoria flash ejecutando algo como:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
