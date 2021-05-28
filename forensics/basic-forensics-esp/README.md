# Basic Forensics \(ESP\)

* 
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

### \*\*\*\*

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

\*\*\*\*

**Cold Boot Attack:**

En el caso en el que el sistema esté cifrado y encendido pero no se tenga la contraseña para entrar se realiza este tipo de ataque.

Este ataque se basa en la posibilidad de que el delincuente ya accediese antes al sistema y se desloggeara, de forma que la contraseña del cifrado aún pudiese estar en memoria pero no se puede hacer un dump de la memoria pues no se puede loggear uno como el usuario pues no se tiene la contraseña.

El ataque cold boot consiste en que la memoria RAM no se elimina en cuanto se apaga el ordenador y si se le aplica frío puede durar varios minutos, de esta forma para intentar extraerla:

 1\) Hacer que la BIOS inicie desde usb

 2\) Conectar el USB especial \(scraper.bin\) que hace un copiado de la memoria

 3\) El USB ha copiado la memoria

\*\*\*\*



\*\*\*\*

Borrado de datos: [https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

recuperacion de datos: [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)







## 

