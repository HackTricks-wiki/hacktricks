# Basic Forensic Methodology

In this section of the book we are going to learn about some **useful forensics tricks**.  
We are going to talk about partitions, file-systems, carving, memory, logs, backups, OSs, and much more.

So if you are doing a professional forensic analysis to some data or just playing a CTF you can find here useful interesting tricks.

## Creating and Mounting an Image

{% page-ref page="image-adquisition-and-mount.md" %}

## Malware Analysis

This **isn't necessary the first step to perform once you have the image**. But you can use this malware analysis techniques independently if you have a file, a file-system image, memory image, pcap... so it's good to **keep these actions in mind**:

{% page-ref page="malware-analysis.md" %}

## Inspecting an Image

if you are given a **forensic image** of a device you can start **analyzing the partitions, file-system** used and **recovering** potentially **interesting files** \(even deleted ones\). Learn how in:

{% page-ref page="partitions-file-systems-carving/" %}

Depending on the used OSs and even platform different interesting artifacts should be searched:

{% page-ref page="windows-forensics/" %}

{% page-ref page="linux-forensics.md" %}

{% page-ref page="docker-forensics.md" %}

## Deep inspection of specific file-types and Software

If you have very **suspicious** **file**, then **depending on the file-type and software** that created it several **tricks** may be useful.  
Read the following page to learn some interesting tricks:

{% page-ref page="specific-software-file-type-tricks/" %}

I want to do a special mention to the page:

{% page-ref page="specific-software-file-type-tricks/browser-artifacts.md" %}

## Memory Dump Inspection

{% page-ref page="memory-dump-analysis/" %}

## Pcap Inspection

When yo







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

## **Anti-Forensic Techniques**

Keep in mind the possible use of anti-forensic techniques:

{% page-ref page="anti-forensic-techniques.md" %}



\*\*\*\*

\*\*\*\*



\*\*\*\*

Borrado de datos: [https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

recuperacion de datos: [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)







## 

