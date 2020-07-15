# Basic Forensics \(ESP\)

*  **Collect**
* **Preserve**
* **Analyze**
* **Present**

Cuando hagas reboot a una máquina afectada hay que iniciarla desde nuestro propio USB booteado. Pues usar el SO de la maquina modificara metadata de algunos archivos \(como access time\) y las herramientas de dicha máquina no son confiables.

**Linux/Unix**

En linux cualquier cosa es un archivo. Por ejemplo la RAM es un archivo llamado **/dev/mem**

**lsof** —&gt; Open files belonging to any process  
**lsof -i** 4 —&gt; Todos los archivos relacionados con conexiones IPv4  
**lsof -i 4 -a -p 1234** —&gt; List all open IPV4 network files in use by the preocess 1234  
**lsof /dev/hda3** lista todos los archivos abiertos en /dev/hda3  
**lsof -t /u/ade/foo** encuentra el proceso que tiene /u/abe/foo abierto  
**lsof +D /directory/path** Busca que procesos tienen abiertos dicho directorio y archivos de dicho directorio  
**lsof -i :1-1024** Archivos que usan dichos puertos  
**lsof -i udp** Archivos que usan UDP -uid 0  
**lsof -p 3 - R** Muestra del proceso nº3 también su proceso padre  
**date** —&gt; Hora del ordenador actual  
**uptime** —&gt; Rebooted  
**uname -a** —&gt; System information  
**ifconfig** —&gt; Ver si esta en modo promiscuo  
**ps -eaf** —&gt; Procesos y servicios inusuales  
**netstat -punta**  
**lsof +L1** —&gt; Muestra todos los archivos abiertos con un contador de link menor de 1. Esto es para los procesos que eliminan el archivo del que vienen pero siguen ejecutandose porque ya están en memoria. Es decir lista todos los procesos que tienen su archivo borrado.  
**w who users** —&gt; Info de usuarios  
**find / -uid 0 -perm -4000 2&gt;/dev/null** —&gt; Sirve para encontrar todos los archivos que tienen de permiso la **s**  
**find /directory -type f -mtime -1 -print** —&gt; Encuentra todos los archivos dentro de ese directorio modificados hace menos de 1 día  
**last** —&gt; Último usuario loggeado  
**df** —&gt; Free space  
**free** —&gt; free y used physical y swap memory

Toda la info obtenida de la máquina infectada NO debe ser guardada en la máquina sino enviada a otra con **netcat**

### **MemoryDump**

####  **memdmp**

 **Linux Memory Extractor \(LiME\)** —&gt; Kernel module —&gt; Descargar de git y hacer make —&gt; **insmod ./lime-3.13.0-44-generic.ko "path=/home/sansforensics/Desktop/mem\_dump.bin format=padded"** —&gt; Inserta el modulo en el kernel el cual puede ser visto con **lsmod** —&gt; **rmmod lime** —&gt; Para eliminarlo  
**strings -n 8 mem\_dump.bin** —&gt; Da todas las strings de tamaño igual o superior a 8  
**Fmem** —&gt; Kernel Module  
live response from **E-FENSE** —&gt; Insertar un USB y vas seleccionando los datos que quieres  
**F-Response** —&gt; Remotely

### **Copy Hard Drive**

**DD —&gt;** Coge bloques de memoria, les aplica el cambio que necesita y los coloca en su sitio. Por defecto bloques de 512B

**dd if=INPUT\_FILE of=OUTPUT\_FILE bs=Nk \(N es el numero de Kilobytes\)** —&gt; Un bs mayor de 8KB puede hacer que vaya más lento  
**count=s** —&gt; s es el numero de bloques a copiar  
**skip=n** —&gt; n es el numero de bloques de los que pasar  
**seek=n** —&gt; n es el número de de bloques del outputfile

Un problema con DD es que no da feedback y si encuentra un error se queda parado sin que tu lo sepas \(una seccion no puede leerla y se para\) para eso se puede usar:

**conv=noerror,sync** —&gt; Pasa de los errores y sigue y rellena con 0s lo que no pudo copiar  
**dd if=/dev/zero of=/dev/hdb** —&gt; Lo pone a cero \(3-7 veces para dejarlo limpio\)  
**dd if=/dev/zero of/path/file count=1** —&gt; Si no ponemos un count nunca parará de copiar 0s  
**dd if=/dev/hdb of=/dev/hda** —&gt; Hay que tener cuidado pues lo que sobre del disco serán 0s y esto hará que el hash sea distinto. Hay que averiguar el número de bloques para calcular el hash solo de ese número de bloques  
**dd if=/dev/hda of=/cas1/evidence.dd**  
**ssh** [**pi@10.10.10.48**](mailto:pi@10.10.10.48) **“sudo dcfldd if=/dev/sbd \| gzip -1 -” \| dcfldd of=pi.dd.gz**  
**Forensic listen: nc -l -p 8888 &gt; /dev/hdg**  
**Infected device: dd if/dev/hda \| nc IPADDR 8888 -w 3** —&gt; La opción w le dice que si no se envía nada en 3 segundo, se desconecta  
DD no checkea hashes, hay que hacerlo de forma manual  
**sdd** —&gt; DD para forensia, da más datos y puede ser un poco más rápido

[http://malwarefieldguide.com/LinuxChapter1.html](http://malwarefieldguide.com/LinuxChapter1.html)

### **BOOT LINUX**

La MBR \(master boot record\) está en el sector 0, se crea al particionar el disco y es siempre de 512B. 446B son el boot code, 64B de la tabla de partición y 2B son de la firma \(55AA\).

La firma del offset 01B8 identifica el disco al SO.

La tabla de partición contiene las 4 primeras particiones en 16B cada especificando el inicio y el fin. También indica si la partición es la que hay que bootear y el tamaño.

Cuando identifica la active partition carga un copia del boot sector de la active partition en memoria y pasa el control al código ejecutable.

EFI usa GUID \(globally unique identification\) compuesto por GPT\(puede tener hasta 128 primary partitions\) y jumps.

Linux usa EXT file system \(basado en el de UNIX\) . Un sistema con este particionado tiene un optional boot block y un superblock. El superblock define las estructuras de datos y los limites del sistema de ficheros. Contiene información de:

 Magic number

 Mount count and maximum mount count

 block size \(4096B\) —&gt; Un bloque es la unidad mínima para guardar info

 INODE count y block count![](https://feelsec.info/wp-content/uploads/2019/01/Pasted-Graphic.jpg)

 number of free disk blocks

 number of free INODEs on the system

 first INODE —&gt; INODE number del first INODE en l file system \(en un EXT2,3,4 sería / del directorio\)

Un INODE contiene metadata de un archivo \(uno o varios files tienen por lo menos un INODE\): tipo, dueño, permiso, tiempos \(ultima modif, aceso..\), links al file y data block addresses.

Cómo encuentra /etc/myconfig

Primero va al INODE de / del cual saca la info de que es un directorio y dónde tiene el contenido. El contenido es una lista de archivos y subdirs que están en /. El subdirectorio etc debe de estar en esta lista con su INODE. Por lo tanto se mira su INODE, se averigua que es un directorio y se va donde tenga el contenido. En este contenido se busca myconfig junto con su número de INODE. Del INODE sacamos que myconfig es un archivo y su contenido son los block addresses donde lo guarda.

Pasted Graphic.tiff ¬

Cada archivo tiene su contenido almacenado en bloques, metadata en el INODE y el nombre e INODE number en el directorio dentro del que está. Cada vez que se crea, el numero de INODES decrementa en 1.

Cuando se elimina un archivo y el numero de Link-Count del INODE llega a 0 en EXT2:

 los data blocks del block bitmap son marcados como libres

 el INODE en el INODE bitmap se marca como libre

 el deletion Time se pone en el INODE

 el directory entry se marca como unused

 Las conexiones entre la entrada del directorio, INODE, y los data blocks seguirán ahí hasta que se sobreescriban.

Como la informacion del directory entry aún está disponible, puedes encontrar la relacion entre el file name y su INODE.

Cambios en EXT3 y 4:

 EL file size en el INODE se pone a 0

 Los datos sobre los bloques son limpiados, por lo que no hay LINK entre INODE y los data blocks. Aun así, hay algunas formas de recuperar la info.

Los comandos **SRM** o **shred** borran intencionadamente el contenido.

Un Hard link tendrá el mismo INODE que el orginial por lo tanto comparten metadata y apuntan a los mismos bloques. Es decir un archivo con otro nombre que apunta a lo mismo.

Un Soft link tendrá distinto INODE y solo guardará la información de a qué archivo apunta.

|  **Directory** |  **Content** |
| :--- | :--- |
|  /bin |  Common programs, shared by the system, the system administrator and the users. |
|  /boot |  The startup files and the kernel, vmlinuz. In some recent distributions also grub data. Grub is the GRand Unified Boot loader and is an attempt to get rid of the many different boot-loaders we know today. |
|  /dev |  Contains references to all the CPU peripheral hardware, which are represented as files with special properties. |
|  /etc |  Most important system configuration files are in /etc, this directory contains data similar to those in the Control Panel in Windows |
|  /home |  Home directories of the common users. |
|  /initrd |  \(on some distributions\) Information for booting. Do not remove! |
|  /lib |  Library files, includes files for all kinds of programs needed by the system and the users. |
|  /lost+found |  Every partition has a lost+found in its upper directory. Files that were saved during failures are here. |
|  /misc |  For miscellaneous purposes. |
|  /mnt |  Standard mount point for external file systems, e.g. a CD-ROM or a digital camera. |
|  /net |  Standard mount point for entire remote file systems |
|  /opt |  Typically contains extra and third party software. |
|  /proc |  A virtual file system containing information about system resources. More information about the meaning of the files in proc is obtained by entering the command **man** _**proc**_ in a terminal window. The file proc.txt discusses the virtual file system in detail. |
|  /root |  The administrative user's home directory. Mind the difference between /, the root directory and /root, the home directory of the _root_ user. |
|  /sbin |  Programs for use by the system and the system administrator. |
|  /tmp |  Temporary space for use by the system, cleaned upon reboot, so don't use this for saving any work! |
|  /usr |  Programs, libraries, documentation etc. for all user-related programs. |
|  /var |  Storage for all variable files and temporary files created by users, such as log files, the mail queue, the print spooler area, space for temporary storage of files downloaded from the Internet, or to keep an image of a CD before burning it. |

**Sleuthkit y Autopsy**

Lo primero que tenemos que hacer es encontrar el inicio de la partición. Para eso podemos usar **fdisk** o **mmls**. **mmls PATH\_IMAGEN** \(mmls da la info en base a bloques de 512B y fdisk da la info en base a cilindros, se suele usar mmls porque te interesan los Bytes para sleuthkit\)

De esta forma encontramos el offset en la que comienza el SO. Conociendo en offset con el que empieza podemos empezar a usar Sleuthkit.

Con **fsstat** podemos encontrar el tipo de partición que es. **fsstat -o OFFSET IMAGEN**

**fls -o OFFSET -f FS\_TYPE -m “/“ -r PATH\_IMAGEN &gt; flsBody** —&gt; Da todos los archivos encontrados que aun tienen el nombre puesto desde / en formato MACTIME

**ils -o OFFSET -f FS\_TYPE -m PATH\_IMAGEM &gt; ilsBody** —&gt; Da todos los INODES que encuentra en formato MACTIME

Autopsy es la GUI de Sleuth Kit.

Los SDD complican el rescatar información.

File system layer tools start with **FS**

File name layer tools starts with **F**

Metadata layer tools strat with **I**

Data layer tools start with **BLK**

Todos los comandos necesitan por lo menos el nombre de la imagen:

 **-f &lt;fs\_type&gt;** —&gt; EXT2,3 FAT12,16,32…

 **-o imgoffset** —&gt; Sector offset where the file system starts in the image

 **BLK —&gt;Block**

 **blkstat** —&gt; Muestra información del bloque \(como si está allocated\)

 **blkstat -f ext2 myImage.img 300** —&gt; Muestra info del bloque 300

 **blkls** —&gt; Muestra toda la Unallocated Data \(útil para recuperar info\)

 **-e** —&gt; Lista todos los datos

 **-s** —&gt; liste the slack \(ntfs o fat\)

 **blkcat** —&gt; Muestra el contenido de un bloque

 **-h** -&gt; Para mostrarlo en hexadecimal

 **blkcat -f ext2 myImage.img 200** —&gt; Muestra lo que hay en el bloque 200

 I **—&gt; INODE\(Meta data\)**

 **istat** —&gt; Info de un INODE: INODE number, mac time, permission, file size, allocation status o allocated data blocks number, number of links…

 **istat -f ext2 myImage.img INODENUMBER**

 **ifind** —&gt; De un block number a un INODE number. Si encuentras un bloque interesante así puedes encontrar los demás.

 **ifind -f ext2 -d DATABLOCKNUMBER myImage.img**

 **ils** —&gt; List all inodes and info. Included deleted files and unlinked but opened files

 Por defecto solo muestra los de archivos borrados

 **-e** —&gt; Muestra todos

 **-m** —&gt; crea un archivo para MACTIME —&gt; Organiza el resultado y presenta un timeline de actividades. Pone un 127 al INODE si ela rchivo ha sido borrado.

 **-o** —&gt; Open but no filename

 **-z** —&gt; INODE with zero status time change \(never used\)

 **icat** —&gt; Dada la imagen sospechosa y el INODE, saca el contenido, puede recuperar archivos perdidos. Debemos encontrar el INODE number con ils.

 **icat -f ext2 /image 20**

 **F —&gt; File name**

 **fls** —&gt; Lista los nombres y subdirs de un directorio. Por defecto los del root. Deleted files have a \* before them. Si el nombre fue sobreescrito, no lo encontrará, pero ILS sí.

 **-a** —&gt; Display all

 **-d** —&gt; Deleted only

 **-u** —&gt; undeleted

 **-D** —&gt; Directories

 **-F** —&gt; File entries only

 **-r** —&gt; Recursive on subdirs

 **-p** —&gt; Full path

 **-m output** —&gt; TIMELINE format

 **-l** —&gt; Long version information

 **-s** —&gt; Skew in seconds combined with -l and/or -m

 **fls -r image 12**

 **fls -f ext3 -m “/” -r imaes/root.dd**

 **fls -o 2048 -f ext2 -m "/" -r '/home/sansforensics/Desktop/LinuxFinancialCase.001' &gt; flsBody**

 **ffind** —&gt; Filename de un INODE. Busca por todas partes hasta encontrar a qué filename apunta el INODE

 **-a** —&gt; Coge todos los nombres que apuntan al INODE

 **ffind -f ext2 myImage.img INODENUMBER**

**Mount -o ro,loop /my\_hda1.dd /mnt/hacked** —&gt; Siempre se debe montar con ro \(read only\), loop es por si lo que montas no es un disco sino un archivo \(una imagen por ejemplo\)

**MACTIME:**

 **M** —&gt; Last time files data block changed \(Modification\)

 **A** —&gt; Last time files data block accessed \(Access\)

 **C** —&gt; Last time inodes content changed \(in windows, this is creation time\) \(Change time\)

**mactime -b FLSbodymac -d &gt; MACtimeFLS.csv**

En linux usar **touch** modifica los 2 primeros. En windows hay un programa que modifica los 3 \(todo se modifica muy facilmente\).

**touch -a -d ‘2017-01-03 08:46:23’ FILE** —&gt; Modifica el access según la hora dada

Comando **stat** da los tres valores MAC del archivo.

Conseguir el archivo en formato MACTIME

 **fls -f ext3 -m “/“ -r images/root.dd &gt; data/body**

 **ils -f openbsd -m images/root.dd &gt; data/body**

Binary files modified in 1 day: **find /directory\_path -type f -a=x -mtime -1 -print**

Files created in 1 day: **find /directory\_path -type f -a=x -bmin -24 -print**

Se pueden guardar todo el raw data unallocated de la imagen usando dls myImage &gt; unallocated \(el contenido de estos datos puede ser cualquier cosa: .jpeg, .pdf …\)

Se puede saber qué datos son usando programas de data carving \(se basan en headers, footers para saber que tipo de archivo es, dónde empieza y dónde acaba\).

Data carving tools: **Foremost, Scalpel, Magic Rescue, Photorec, TestDisk, etc**

**Foremost**

Para user Foremost tenemos que ir a su archivo de configuración \(find / -name foremost.comf\) y descomentar las líneas de los tipos de archivo que nos interesen.

**foremost -c fremost.conf -T -i FILE** \(La T es para que vaya asginando nombres unicos\)

**BOOTABLES**

CAINE

HELIXS/HELIX3 PRO

KALI

PENGUIN SLEUTH

F.I.R.E

SNARL

**BUILT-IN FUNCTIONALITIES**

Deleted file recovery

Keyword search

Hash Analysis

Data carving

Graphic view

Email view

**Analysis procedure**

Create a case

Add evidence to a case

Perform throrough analysis

Obtain basic analysis data

Export files

Generate report

**WINDOWS**

**Volatile Information**

System Information

 Processes information

 Network information

 Logged on users

 Clipboard contents

 Command history - doskey/history

 MACTime

Comandos para obtener esta info:

 date /T; time /T

 uptime

 ipconfig

 tasklist /svc

 openfiles

 netstat

**Helix:**

Primer apartado: Info del sistema

 Procesos corriendo

 Segundo apartado: Permite crear copias del disco y memoria, primero usando **dd** \(mejor usar os otros\)

 En la segunda página usando **FTK imager**

 Es la tercera página, RAM usando **Winen** o **MDD**

 Tercer apartado: Incident response

 Cuarto apartado: Navegación por el disco, no usar mucho porque cambian los tiempos de acceso

 Quinto apartado: Saca todas las imagenes

**Volatility:**

 vol.py -f PATH\_IMAGE imageinfo —&gt; Primer plug-in a usar para obtener el so

 vol.py -f PATH\_IMAGE pslist —&gt; Procesos pslist no supera los rootkits pero psscan algunos sí

 vol.py -f PATH\_IMAGE psscan —&gt; Comparar esta salida y la anterior para buscar rootkits

 vol.py -f PATH\_IMAGE connscan —&gt; Conexiones, a partir de windows Vista se usa netscan

 vol.py -f PATH\_IMAGE printkey -K “Microsoft\Windows NT\CurrentVersion\Winlogon” —&gt; procesos que escribieron en dicho registro

**Cold Boot Attack:**

En el caso en el que el sistema esté cifrado y encendido pero no se tenga la contraseña para entrar se realiza este tipo de ataque.

Este ataque se basa en la posibilidad de que el delincuente ya accediese antes al sistema y se desloggeara, de forma que la contraseña del cifrado aún pudiese estar en memoria pero no se puede hacer un dump de la memoria pues no se puede loggear uno como el usuario pues no se tiene la contraseña.

El ataque cold boot consiste en que la memoria RAM no se elimina en cuanto se apaga el ordenador y si se le aplica frío puede durar varios minutos, de esta forma para intentar extraerla:

 1\) Hacer que la BIOS inicie desde usb

 2\) Conectar el USB especial \(scraper.bin\) que hace un copiado de la memoria

 3\) El USB ha copiado la memoria

**High speed forensics imagers**

Logicube’s Forensic Falcon —&gt; 30GB por minuto

Mediaclone’s Superimager —&gt; de 29 a 31 GB por minuto

En Windows un Block es llamado Cluster. En este sistema operativo cuando un cluster no se llena el espacio vacio se queda sin usar, lo cual es util pues puede contener datos eliminados. En linux la parte que no se llena de un block se rellena con ceros.

Windows filesystems: FAT12, FAT16, FAT32, exFAT, NTFS4, NTFS5 y ReFS

Un sistema de ficheros FAT comienza con un BOOT RECORD seguido de una ALLOCATION TABLE, depués el ROOT DIRECTORY y finalmente el DATA AREA, el tamaño de un cluster es de 512B

 BOOT SECTOR:

 Primer setor de FAT12 o FAT16, o 3 primeros sectores de FAT32, define el volumen, el offset de las otras 3 áreas y contiene el boot program si es booteable

 FAT \(File Allocation Table\):

 Es una tabla donde buscar qué cluster va a continuacion. Para localizar un archivo basta con saber la dirección del primer cluster y luego usando la FAT se localiza lo demás. FAT32 usa 32 bits para la dirección del cluster. Una dirección en la tabla guarda la dirección del siguiente cluster. Un cluster es el ultimo estara relleno de unos y si no se usa, de ceros. Un cluster malo tiene hex FFF7.

 WINDOWS ROOT DIRECTORY:

 Un directorio contiene info del nombre y la extension, entry type, la dirección del primer cluster, the lens of the file y data time \(contiene toda esta info en 32bits\)

Cuando se elimina un archivo se cambia el primer byte del nombre por 0xE5 y se desalojan los clusters la ta tabla FAT.

Quick format: Pone a cero las entradas de root directory y file allocation table entries, pero deja los datos sin tocar.

**NTFS**

El tamaño de un cluster es de 64kB, aunque se pueden crear clusters mas pequeños o más grandes. 64bits para la dirección de cada cluster

 BOOT RECORD:

 Puede usar hasta 16 sectores, tiene el cluster size, dirección de MFT\(master file table\), el mirror de MFT\(4 primeras entradas\) y el código si es booteable.

 MASTER FILE TABLE \(se puede ver con EnCase\)

 Su nombre comienza con $ y se crea cuando el NTFS es formateado. Cada archivo usa uno o mas MFT records para guardar info: $file record head\(MFT nº, link count, tipo de archivo, tamaño, etc\), $standard information, $filename, $data y $attribute.

 Si el metadata de un archivo es mayor que un MFT record, se usan mas.

 El primer archivo es $MFT

 $BITMAP guarda el estado de cada cluster, si está usado vale 1, sino vale 0.

Cuando se elimina algo, el pone el cluster a 0 \(unallocated\) la entrada de $index es eliminada el MTF padre, pero no se borran los datos.

**REGSTRO**

 Usuarios y contraseñas, e-mails, sitios de internet

 Historial de navegación

 Internet searches

 Lista de archivos accedidos

 Lista de programas instalados

Windows guarda el registro en archivos binarios llamados hives.

SAM: Información de cuentas y contraseñas asi como el SID de cada. También guarda el tiempo de LOGON

SID: Identifica unequivocamente a usuarios y su grupo para dar derecho o no a archivos

En system se guarda info de los usbs introducidos asi como cuando entraron y cuando se sacaron

El registro se puede ver tanto en máquinas corriendo como en imagenes de memoria. Para verlos se puede usar EnCase, Registry Explore, RegRipper, Registry Recon, Access Data Registry Viewer

Registros: SAM \(para cuentas\), SYSTEM \(para info del sistema\), NTUSER.dat \(cada usuario tiene el suyo que guarda info del usuario\)

**CUSTOM**

Cuando tienes una imagen puedes pasarle binwalk para saber qué esconde la imagen.

Si tienes una copia de la MFT:

 Con volatility puedes reconstruir la MFT e ir mirando todos los archivos que hay y su contenido en hex y ascii \(aunque son muchos pero está bien para buscar archivos extraños\) con: volatility -f mft.dd mftparser -N --output-file=mft.dd.vol.txt --&gt; Te da un archivo con texto cno todos los archivos que existen en dicha imagen

Borrado de datos: [https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

recuperacion de datos: [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

En imagenes:

Strings  
exiftool

