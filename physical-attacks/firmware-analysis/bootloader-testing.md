Cuando se modifica el inicio del dispositivo y los cargadores de arranque como U-boot, se deben intentar las siguientes técnicas:

* Intentar acceder a la shell del intérprete de los cargadores de arranque presionando "0", espacio u otros "códigos mágicos" identificados durante el arranque.
* Modificar las configuraciones para ejecutar un comando de shell como agregar '`init=/bin/sh`' al final de los argumentos de arranque
  * `#printenv`
  * `#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh`
  * `#saveenv`
  * `#boot`
* Configurar un servidor tftp para cargar imágenes a través de la red localmente desde su estación de trabajo. Asegúrese de que el dispositivo tenga acceso a la red.
  * `#setenv ipaddr 192.168.2.2 #IP local del dispositivo`
  * `#setenv serverip 192.168.2.1 #IP del servidor tftp`
  * `#saveenv`
  * `#reset`
  * `#ping 192.168.2.1 #verificar si hay acceso a la red`
  * `#tftp ${loadaddr} uImage-3.6.35 #loadaddr toma dos argumentos: la dirección para cargar el archivo y el nombre del archivo de la imagen en el servidor TFTP`
* Usar `ubootwrite.py` para escribir la imagen de uboot y cargar un firmware modificado para obtener acceso root.
* Verificar si hay características de depuración habilitadas, como:
  * registro detallado
  * carga de kernels arbitrarios
  * arranque desde fuentes no confiables
* \*Tener precaución: Conectar un pin a tierra, observar la secuencia de arranque del dispositivo, antes de que el kernel se descomprima, cortocircuitar/conectar el pin a tierra al pin de datos (DO) en un chip flash SPI.
* \*Tener precaución: Conectar un pin a tierra, observar la secuencia de arranque del dispositivo, antes de que el kernel se descomprima, cortocircuitar/conectar el pin a tierra al pin 8 y 9 del chip flash NAND en el momento en que U-boot descomprime la imagen UBI.
  * \*Revisar la hoja de datos del chip flash NAND antes de cortocircuitar los pines.
* Configurar un servidor DHCP falso con parámetros maliciosos como entrada para que el dispositivo los ingiera durante un arranque PXE.
  * Usar el servidor auxiliar DHCP de Metasploit (MSF) y modificar el parámetro '`FILENAME`' con comandos de inyección de comandos como `‘a";/bin/sh;#’` para probar la validación de entrada para los procedimientos de inicio del dispositivo.

\*Pruebas de seguridad de hardware
