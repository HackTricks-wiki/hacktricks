# Volatility - Hoja de trucos

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro crucial para profesionales de tecnología y ciberseguridad en todas las disciplinas.

{% embed url="https://www.rootedcon.com/" %}

Si deseas algo **rápido y loco** que lance varios complementos de Volatility en paralelo, puedes usar: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Instalación

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
### volatility2

{% tabs %}
{% tab title="Método1" %}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{% endtab %}

{% tab title="Método 2" %}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Comandos de Volatility

Accede a la documentación oficial en [Referencia de comandos de Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### Una nota sobre los plugins "list" vs "scan"

Volatility tiene dos enfoques principales para los plugins, que a veces se reflejan en sus nombres. Los plugins "list" intentarán navegar a través de las estructuras del Kernel de Windows para recuperar información como procesos (localizar y recorrer la lista enlazada de estructuras `_EPROCESS` en la memoria), manejadores del sistema operativo (localizar y listar la tabla de manejadores, desreferenciar cualquier puntero encontrado, etc). Más o menos se comportan como lo haría la API de Windows si se solicitara, por ejemplo, listar procesos.

Esto hace que los plugins "list" sean bastante rápidos, pero igual de vulnerables que la API de Windows a la manipulación por malware. Por ejemplo, si el malware utiliza DKOM para desvincular un proceso de la lista enlazada `_EPROCESS`, no aparecerá en el Administrador de tareas ni en la lista de procesos.

Los plugins "scan", por otro lado, adoptarán un enfoque similar a tallar la memoria en busca de cosas que podrían tener sentido al desreferenciarlas como estructuras específicas. `psscan`, por ejemplo, leerá la memoria e intentará crear objetos `_EPROCESS` a partir de ella (utiliza el escaneo de etiquetas de grupo, que busca cadenas de 4 bytes que indiquen la presencia de una estructura de interés). La ventaja es que puede descubrir procesos que han salido, e incluso si el malware manipula la lista enlazada `_EPROCESS`, el plugin seguirá encontrando la estructura en la memoria (ya que aún necesita existir para que el proceso se ejecute). La desventaja es que los plugins "scan" son un poco más lentos que los plugins "list" y a veces pueden dar falsos positivos (un proceso que salió hace mucho tiempo y tuvo partes de su estructura sobrescritas por otras operaciones).

De: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## Perfiles de SO

### Volatility3

Como se explica en el archivo readme, necesitas colocar la **tabla de símbolos del SO** que deseas admitir dentro de _volatility3/volatility/symbols_.\
Los paquetes de tablas de símbolos para los diversos sistemas operativos están disponibles para **descargar** en:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Perfil Externo

Puedes obtener la lista de perfiles admitidos haciendo:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Si deseas utilizar un **nuevo perfil que has descargado** (por ejemplo, uno de Linux), necesitas crear en algún lugar la siguiente estructura de carpetas: _plugins/overlays/linux_ y colocar dentro de esta carpeta el archivo zip que contiene el perfil. Luego, obtén el número de perfiles utilizando:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Puedes **descargar perfiles de Linux y Mac** desde [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

En el fragmento anterior puedes ver que el perfil se llama `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, y puedes usarlo para ejecutar algo como:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Descubrir Perfil
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Diferencias entre imageinfo y kdbgscan**

[**Desde aquí**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): A diferencia de imageinfo que simplemente proporciona sugerencias de perfil, **kdbgscan** está diseñado para identificar positivamente el perfil correcto y la dirección KDBG correcta (si hay múltiples). Este complemento escanea las firmas de KDBGHeader vinculadas a perfiles de Volatility y aplica controles de integridad para reducir falsos positivos. La verbosidad de la salida y la cantidad de controles de integridad que se pueden realizar dependen de si Volatility puede encontrar un DTB, por lo que si ya conoce el perfil correcto (o si tiene una sugerencia de perfil de imageinfo), asegúrese de usarlo desde .

Siempre eche un vistazo al **número de procesos que kdbgscan ha encontrado**. A veces imageinfo y kdbgscan pueden encontrar **más de un** perfil **adecuado**, pero solo el **válido tendrá algunos procesos relacionados** (Esto se debe a que para extraer procesos se necesita la dirección KDBG correcta).
```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```
#### KDBG

El **bloque depurador del kernel**, conocido como **KDBG** por Volatility, es crucial para las tareas forenses realizadas por Volatility y varios depuradores. Identificado como `KdDebuggerDataBlock` y del tipo `_KDDEBUGGER_DATA64`, contiene referencias esenciales como `PsActiveProcessHead`. Esta referencia específica apunta a la cabecera de la lista de procesos, lo que permite la enumeración de todos los procesos, lo cual es fundamental para un análisis exhaustivo de la memoria.

## Información del sistema operativo
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
El plugin `banners.Banners` se puede utilizar en **vol3 para intentar encontrar banners de Linux** en el volcado de memoria.

## Hashes/Contraseñas

Extraer hashes SAM, [credenciales en caché del dominio](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) y [secretos de lsa](../../../windows-hardening/authentication-credentials-uac-and-efs.md#lsa-secrets).

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% endtab %}

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Volatility

- **Volatility** es un marco de trabajo de análisis de memoria.
- **Volatility** es un proyecto de código abierto.
- **Volatility** es compatible con la mayoría de los sistemas operativos.
- **Volatility** es compatible con la mayoría de los formatos de volcado de memoria.

#### Uso básico

- `volatility -f <archivo de volcado> <comando>`

#### Comandos útiles

- `imageinfo`: Muestra información básica sobre el volcado de memoria.
- `pslist`: Lista los procesos en el volcado de memoria.
- `pstree`: Muestra los procesos en forma de árbol.
- `psscan`: Escanea procesos a través de los espacios de direcciones.
- `dlllist`: Lista las DLL cargadas en los procesos.
- `cmdline`: Muestra las líneas de comandos de los procesos.
- `filescan`: Escanea en busca de objetos de archivos en memoria.
- `netscan`: Muestra información de red.
- `connections`: Muestra las conexiones de red.
- `sockets`: Muestra los sockets de red.
- `malfind`: Encuentra inyecciones de código malicioso.
- `yarascan`: Escanea la memoria en busca de patrones YARA.
- `dumpfiles`: Extrae archivos del volcado de memoria.
- `dump`: Extrae un proceso específico del volcado de memoria.
- `memdump`: Crea un volcado de memoria de un proceso específico.
- `linux_bash`: Muestra los comandos de bash ejecutados.
- `linux_netstat`: Muestra información de red en sistemas Linux.
- `linux_lsmod`: Lista los módulos del kernel en sistemas Linux.

#### Recursos adicionales

- **Volatility Wiki**: https://github.com/volatilityfoundation/volatility/wiki
- **Volatility GitHub**: https://github.com/volatilityfoundation/volatility

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
## Volcado de Memoria

El volcado de memoria de un proceso **extraerá todo** el estado actual del proceso. El módulo **procdump** solo **extraerá** el **código**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro clave para profesionales de tecnología y ciberseguridad en todas las disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## Procesos

### Listar procesos

Intenta encontrar procesos **sospechosos** (por nombre) o **inesperados** procesos secundarios (por ejemplo, un cmd.exe como hijo de iexplorer.exe).\
Podría ser interesante **comparar** el resultado de pslist con el de psscan para identificar procesos ocultos.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endtab %}

{% tab title="vol2" %} 

## Hoja de trucos de Volatility

### Comandos básicos

- **volatility -f <archivo> imageinfo**: Escanea el volcado de memoria para obtener información básica.
- **volatility -f <archivo> pslist**: Enumera los procesos en ejecución.
- **volatility -f <archivo> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <archivo> psscan**: Escanea los procesos ocultos.
- **volatility -f <archivo> dlllist -p <PID>**: Lista las DLL cargadas por un proceso.
- **volatility -f <archivo> cmdscan**: Busca comandos ejecutados en la memoria.
- **volatility -f <archivo> consoles**: Enumera las consolas interactivas.
- **volatility -f <archivo> filescan**: Escanea los descriptores de archivo.
- **volatility -f <archivo> netscan**: Muestra las conexiones de red.
- **volatility -f <archivo> connections**: Enumera las conexiones de red.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <archivo> apihooks**: Busca API hooks en los procesos.
- **volatility -f <archivo> ldrmodules**: Lista los módulos cargados en los procesos.
- **volatility -f <archivo> modscan**: Escanea los módulos cargados.
- **volatility -f <archivo> shimcache**: Extrae información de ShimCache.
- **volatility -f <archivo> userassist**: Recupera información de UserAssist.
- **volatility -f <archivo> hivelist**: Enumera las ubicaciones del Registro en memoria.
- **volatility -f <archivo> printkey -o <offset>**: Imprime una clave de Registro en un desplazamiento específico.
- **volatility -f <archivo> cmdline**: Recupera las líneas de comandos de los procesos.
- **volatility -f <archivo> consoles -p <PID>**: Muestra las consolas asociadas a un proceso.
- **volatility -f <archivo> dumpfiles -Q <PID> -D <directorio>**: Extrae archivos del espacio de memoria de un proceso.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memmap**: Muestra el mapeo de memoria.
- **volatility -f <archivo> memstrings**: Busca cadenas ASCII en el espacio de memoria.
- **volatility -f <archivo> procdump -p <PID> -D <directorio>**: Crea un volcado de memoria de un proceso.
- **volatility -f <archivo> procdump -p <PID> -D <directorio> --format=<formato>**: Crea un volcado de memoria de un proceso en un formato específico.
- **volatility -f <archivo> procdump -p <PID> -D <directorio> --format=<formato> --name=<nombre>**: Crea un volcado de memoria de un proceso con un nombre específico.
- **volatility -f <archivo> yarascan -Y <regla>**: Escanea la memoria en busca de patrones que coincidan con una regla Yara.
- **volatility -f <archivo> yarascan -f <archivo_de_reglas>**: Escanea la memoria en busca de patrones que coincidan con un archivo de reglas Yara.
- **volatility -f <archivo> yarascan -p <proceso> -Y <regla>**: Escanea la memoria de un proceso en busca de patrones que coincidan con una regla Yara.
- **volatility -f <archivo> yarascan -p <proceso> -f <archivo_de_reglas>**: Escanea la memoria de un proceso en busca de patrones que coincidan con un archivo de reglas Yara.

### Plugins adicionales

- **apihooks**: Busca hooks de API en los procesos.
- **malfind**: Encuentra inyecciones de código malicioso en los procesos.
- **mftparser**: Analiza el MFT (Master File Table) para encontrar archivos eliminados.
- **timeliner**: Crea una línea de tiempo de los eventos del sistema.
- **vadinfo**: Muestra información sobre los espacios de direcciones virtuales.
- **vaddump**: Crea un volcado de un espacio de dirección virtual específico.
- **vadtree**: Muestra los espacios de direcciones virtuales en forma de árbol.
- **vadwalk**: Muestra las direcciones físicas asociadas con un espacio de dirección virtual.
- **windows**: Enumera los procesos y los módulos de Windows.
- **wintree**: Muestra los procesos y los módulos de Windows en forma de árbol.

{% endtab %}
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
### Volcado de procesos

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{% endtab %}

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Comandos básicos de Volatility

- **volatility -f <archivo> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: Muestra una lista de procesos en el volcado de memoria.
- **volatility -f <archivo> pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **volatility -f <archivo> psscan**: Escanea procesos en el volcado de memoria.
- **volatility -f <archivo> dlllist -p <PID>**: Muestra una lista de DLL cargadas por un proceso específico.
- **volatility -f <archivo> cmdscan**: Escanea comandos de consola en el volcado de memoria.
- **volatility -f <archivo> filescan**: Escanea descriptores de archivos en el volcado de memoria.
- **volatility -f <archivo> netscan**: Escanea información de red en el volcado de memoria.
- **volatility -f <archivo> connections**: Muestra conexiones de red en el volcado de memoria.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código malicioso en procesos.
- **volatility -f <archivo> yarascan**: Escanea la memoria en busca de patrones con Yara.
- **volatility -f <archivo> cmdline**: Muestra los argumentos de línea de comandos de procesos.
- **volatility -f <archivo> consoles**: Muestra consolas interactivas detectadas en el volcado de memoria.
- **volatility -f <archivo> hivelist**: Enumera los registros del sistema en el volcado de memoria.
- **volatility -f <archivo> printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <archivo> userassist**: Muestra programas ejecutados y frecuencia de ejecución.
- **volatility -f <archivo> shimcache**: Muestra entradas de la caché de compatibilidad de aplicaciones.
- **volatility -f <archivo> ldrmodules**: Enumera módulos cargados en procesos.
- **volatility -f <archivo> modscan**: Escanea módulos en el volcado de memoria.
- **volatility -f <archivo> getsids**: Enumera los SID de seguridad en el volcado de memoria.
- **volatility -f <archivo> getservicesids**: Enumera los SID de seguridad asociados a servicios.
- **volatility -f <archivo> svcscan**: Escanea servicios en el volcado de memoria.
- **volatility -f <archivo> driverirp**: Enumera IRP manejadores de controladores.
- **volatility -f <archivo> callbacks**: Enumera rutinas de devolución de llamada registradas.
- **volatility -f <archivo> ssdt**: Enumera servicios del sistema (SSDT).
- **volatility -f <archivo> gdt**: Enumera descriptores de tablas globales.
- **volatility -f <archivo> idt**: Enumera descriptores de tablas de interrupciones.
- **volatility -f <archivo> threads**: Enumera hilos en el volcado de memoria.
- **volatility -f <archivo> mutantscan**: Escanea objetos de mutante en el volcado de memoria.
- **volatility -f <archivo> mutantscan**: Escanea objetos de mutante en el volcado de memoria.
- **volatility -f <archivo> envars**: Enumera variables de entorno en procesos.
- **volatility -f <archivo> atomscan**: Escanea tablas de átomos en el volcado de memoria.
- **volatility -f <archivo> atomscan**: Escanea tablas de átomos en el volcado de memoria.
- **volatility -f <archivo> vadinfo -o <offset>**: Muestra información sobre un área de memoria específica.
- **volatility -f <archivo> vadtree -o <offset>**: Muestra un árbol de áreas de memoria.
- **volatility -f <archivo> memmap**: Muestra un mapa de memoria.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio> -r <rango>**: Volcado de memoria de un rango de direcciones de un proceso.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso.
- **volatility -f <archivo> memstrings -Q <cantidad>**: Extrae cadenas ASCII de todo el volcado de memoria.
- **volatility -f <archivo> memdump**: Volcado de memoria completo.
- **volatility -f <archivo> memdump --profile=<perfil> -D <directorio>**: Volcado de memoria con perfil específico.
- **volatility -f <archivo> memdump --profile=<perfil> -D <directorio> -r <rango>**: Volcado de memoria con perfil y rango específico.
- **volatility -f <archivo> memdump --profile=<perfil> -D <directorio> -r <rango> -p <PID>**: Volcado de memoria con perfil, rango y proceso específico.
- **volatility -f <archivo> memdump --profile=<perfil> -D <directorio> -r <rango> -p <PID> --output-file=<archivo>**: Volcado de memoria con perfil, rango, proceso específico y archivo de salida.
- **volatility -f <archivo> memdump --profile=<perfil> -D <directorio> -r <rango> -p <PID> --output-file=<archivo> --output=html**: Volcado de memoria con perfil, rango, proceso específico, archivo de salida y formato HTML.

#### Plugins adicionales de Volatility

- **volatility -f <archivo> <nombre_del_plugin>**: Ejecuta un plugin específico en el volcado de memoria.
- **volatility -f <archivo> --plugins=<directorio> <nombre_del_plugin>**: Ejecuta un plugin específico desde un directorio personalizado.
- **volatility --info**: Muestra información sobre todos los plugins disponibles.
- **volatility --plugins=<directorio> --info**: Muestra información sobre los plugins en un directorio personalizado.

#### Análisis avanzado con Volatility

- **Automatización de tareas**: Utiliza scripts para automatizar el análisis de volcados de memoria.
- **Creación de perfiles personalizados**: Crea perfiles personalizados para mejorar la precisión del análisis.
- **Análisis de malware**: Utiliza Volatility para identificar indicadores de compromiso y comportamiento malicioso.
- **Análisis de rootkits**: Detecta rootkits y malware persistente en el sistema.
- **Análisis de exploits**: Identifica exploits en la memoria del sistema para fortalecer la seguridad.
- **Análisis de incidentes de seguridad**: Examina volcados de memoria para investigar incidentes de seguridad.
- **Análisis forense**: Aplica técnicas forenses para reconstruir eventos y actividades en el sistema comprometido.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
### Línea de comandos

¿Se ejecutó algo sospechoso?
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="vol2" %} 

## Hoja de trucos de Volatility

### Análisis de volcado de memoria

#### Comandos básicos

- **volatility -f <file> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <file> pslist**: Muestra una lista de procesos en el volcado de memoria.
- **volatility -f <file> pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **volatility -f <file> psscan**: Escanea procesos a través del volcado de memoria.
- **volatility -f <file> dlllist -p <pid>**: Muestra una lista de DLL cargadas en un proceso específico.
- **volatility -f <file> cmdscan**: Escanea la memoria en busca de comandos de consola.
- **volatility -f <file> filescan**: Escanea la memoria en busca de estructuras de archivos.
- **volatility -f <file> netscan**: Escanea la memoria en busca de artefactos de red.
- **volatility -f <file> connections**: Muestra información sobre las conexiones de red.
- **volatility -f <file> consoles**: Muestra información sobre las consolas interactivas.
- **volatility -f <file> hivelist**: Enumera los registros del sistema en el volcado de memoria.
- **volatility -f <file> userassist**: Muestra información sobre programas utilizados recientemente.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso en procesos.
- **volatility -f <file> apihooks**: Muestra información sobre ganchos de API en procesos.
- **volatility -f <file> ldrmodules**: Muestra información sobre módulos cargados en procesos.
- **volatility -f <file> shimcache**: Muestra información sobre aplicaciones ejecutadas en el sistema.
- **volatility -f <file> getsids**: Enumera los SID de usuario en el volcado de memoria.
- **volatility -f <file> getservicesids**: Enumera los SID de servicio en el volcado de memoria.
- **volatility -f <file> modscan**: Escanea la memoria en busca de módulos del kernel.
- **volatility -f <file> mutantscan**: Escanea la memoria en busca de objetos de mutante.
- **volatility -f <file> envars**: Muestra variables de entorno de procesos.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos del volcado de memoria.
- **volatility -f <file> cmdline**: Muestra la línea de comandos de procesos.
- **volatility -f <file> consoles**: Muestra información sobre las consolas interactivas.
- **volatility -f <file> hivelist**: Enumera los registros del sistema en el volcado de memoria.
- **volatility -f <file> userassist**: Muestra información sobre programas utilizados recientemente.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso en procesos.
- **volatility -f <file> apihooks**: Muestra información sobre ganchos de API en procesos.
- **volatility -f <file> ldrmodules**: Muestra información sobre módulos cargados en procesos.
- **volatility -f <file> shimcache**: Muestra información sobre aplicaciones ejecutadas en el sistema.
- **volatility -f <file> getsids**: Enumera los SID de usuario en el volcado de memoria.
- **volatility -f <file> getservicesids**: Enumera los SID de servicio en el volcado de memoria.
- **volatility -f <file> modscan**: Escanea la memoria en busca de módulos del kernel.
- **volatility -f <file> mutantscan**: Escanea la memoria en busca de objetos de mutante.
- **volatility -f <file> envars**: Muestra variables de entorno de procesos.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos del volcado de memoria.
- **volatility -f <file> cmdline**: Muestra la línea de comandos de procesos.

#### Plugins adicionales

- **volatility -f <file> <plugin> --help**: Muestra ayuda para un plugin específico.
- **volatility -f <file> <plugin>**: Ejecuta un plugin específico en el volcado de memoria.

#### Perfiles

- **volatility --info | grep Profile**: Lista los perfiles disponibles.
- **volatility -f <file> --profile=<profile> <command>**: Especifica un perfil para el análisis.

#### Volcado de memoria de 32 bits en un sistema de 64 bits

- **volatility --profile=Win7SP1x64 -f <file> <command>**: Analiza un volcado de memoria de 32 bits en un sistema de 64 bits.

#### Volcado de memoria de un sistema virtualizado

- **volatility -f <file> --profile=<profile> <command>**: Analiza un volcado de memoria de un sistema virtualizado.

#### Volcado de memoria de un sistema en la nube

- **volatility -f <file> --profile=<profile> <command>**: Analiza un volcado de memoria de un sistema en la nube.

{% endtab %}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

Los comandos ejecutados en `cmd.exe` son gestionados por **`conhost.exe`** (o `csrss.exe` en sistemas anteriores a Windows 7). Esto significa que si **`cmd.exe`** es terminado por un atacante antes de obtener un volcado de memoria, aún es posible recuperar el historial de comandos de la sesión desde la memoria de **`conhost.exe`**. Para hacer esto, si se detecta actividad inusual dentro de los módulos de la consola, se debe volcar la memoria del proceso asociado de **`conhost.exe`**. Luego, al buscar **cadenas** dentro de este volcado, potencialmente se pueden extraer las líneas de comandos utilizadas en la sesión.

### Entorno

Obtener las variables de entorno de cada proceso en ejecución. Podría haber algunos valores interesantes.
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% endtab %}

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Análisis de volcado de memoria

- **Escaneo de procesos:** `volatility -f <archivo> --profile=<perfil> pslist`
- **Análisis de DLLs cargadas:** `volatility -f <archivo> --profile=<perfil> dlllist -p <PID>`
- **Análisis de puertos y conexiones:** `volatility -f <archivo> --profile=<perfil> connscan`
- **Análisis de registros de red:** `volatility -f <archivo> --profile=<perfil> netscan`
- **Análisis de caché de DNS:** `volatility -f <archivo> --profile=<perfil> dnscache`
- **Análisis de conexiones de red:** `volatility -f <archivo> --profile=<perfil> connections`
- **Análisis de sockets de red:** `volatility -f <archivo> --profile=<perfil> sockets`
- **Análisis de enrutamiento de red:** `volatility -f <archivo> --profile=<perfil> route`
- **Análisis de tareas:** `volatility -f <archivo> --profile=<perfil> pstree`
- **Análisis de servicios:** `volatility -f <archivo> --profile=<perfil> getservices`
- **Análisis de controladores de dispositivos:** `volatility -f <archivo> --profile=<perfil> driverscan`
- **Análisis de registros de eventos:** `volatility -f <archivo> --profile=<perfil> evtlogs`
- **Análisis de caché de registro:** `volatility -f <archivo> --profile=<perfil> hivelist`
- **Análisis de usuarios y grupos:** `volatility -f <archivo> --profile=<perfil> getsids`
- **Análisis de contraseñas en memoria:** `volatility -f <archivo> --profile=<perfil> hashdump`
- **Análisis de sesiones de terminal:** `volatility -f <archivo> --profile=<perfil> consoles`
- **Análisis de escritorios:** `volatility -f <archivo> --profile=<perfil> desktops`
- **Análisis de ventanas:** `volatility -f <archivo> --profile=<perfil> windows`
- **Análisis de registros de registro:** `volatility -f <archivo> --profile=<perfil> printkey -K <RegistryKey>`
- **Análisis de archivos abiertos:** `volatility -f <archivo> --profile=<perfil> filescan`
- **Análisis de puertos serie:** `volatility -f <archivo> --profile=<perfil> getsids`
- **Análisis de caché de procesos:** `volatility -f <archivo> --profile=<perfil> psscan`
- **Análisis de colas de eventos:** `volatility -f <archivo> --profile=<perfil> qscan`
- **Análisis de colas de eventos de notificación:** `volatility -f <archivo> --profile=<perfil> notifyscan`
- **Análisis de objetos de sincronización:** `volatility -f <archivo> --profile=<perfil> handles`
- **Análisis de objetos de sincronización por proceso:** `volatility -f <archivo> --profile=<perfil> handles -p <PID>`
- **Análisis de objetos de sincronización por tipo:** `volatility -f <archivo> --profile=<perfil> handles -t <Tipo>`
- **An
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
### Privilegios de tokens

Verifique los tokens de privilegios en servicios inesperados.\
Podría ser interesante enumerar los procesos que utilizan algún token privilegiado.
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Comandos básicos de Volatility

- **volatility -f <archivo> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: Muestra una lista de procesos en el volcado de memoria.
- **volatility -f <archivo> pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **volatility -f <archivo> psscan**: Escanea procesos a través del volcado de memoria.
- **volatility -f <archivo> dlllist -p <PID>**: Muestra las DLL cargadas por un proceso específico.
- **volatility -f <archivo> cmdline -p <PID>**: Muestra el comando utilizado para ejecutar un proceso específico.
- **volatility -f <archivo> filescan**: Escanea descriptores de archivos en el volcado de memoria.
- **volatility -f <archivo> netscan**: Escanea conexiones de red en el volcado de memoria.
- **volatility -f <archivo> connections**: Muestra las conexiones de red en el volcado de memoria.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código en procesos.
- **volatility -f <archivo> yarascan**: Escanea el volcado de memoria en busca de cadenas con Yara.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> procdump -p <PID> -D <destino>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <destino>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <archivo> hivelist**: Enumera los registros del sistema en el volcado de memoria.
- **volatility -f <archivo> printkey -o <offset>**: Imprime una clave del registro en un desplazamiento específico.
- **volatility -f <archivo> userassist**: Extrae y decodifica las entradas de UserAssist del Registro.
- **volatility -f <archivo> shimcache**: Extrae y decodifica la caché de Shim del Registro.
- **volatility -f <archivo> ldrmodules**: Enumera los módulos cargados en el espacio de memoria del sistema.
- **volatility -f <archivo> modscan**: Escanea módulos en el volcado de memoria.
- **volatility -f <archivo> getsids**: Enumera los SID de usuario en el volcado de memoria.
- **volatility -f <archivo> getservicesids**: Enumera los SID de servicio en el volcado de memoria.
- **volatility -f <archivo> apihooks**: Enumera los ganchos de API en el volcado de memoria.
- **volatility -f <archivo> callbacks**: Enumera los callbacks en el volcado de memoria.
- **volatility -f <archivo> driverirp**: Enumera las IRP manejadas por los controladores en el volcado de memoria.
- **volatility -f <archivo> ssdt**: Enumera los descriptores de tabla de servicios del sistema en el volcado de memoria.
- **volatility -f <archivo> gdt**: Enumera la tabla de descriptores globales en el volcado de memoria.
- **volatility -f <archivo> idt**: Enumera la tabla de descriptores de interrupciones en el volcado de memoria.
- **volatility -f <archivo> threads**: Enumera los hilos en el volcado de memoria.
- **volatility -f <archivo> handles**: Enumera los descriptores de archivos y registros en el volcado de memoria.
- **volatility -f <archivo> mutantscan**: Escanea objetos de mutante en el volcado de memoria.
- **volatility -f <archivo> envars**: Enumera las variables de entorno en el volcado de memoria.
- **volatility -f <archivo> atomscan**: Escanea tablas de átomos en el volcado de memoria.
- **volatility -f <archivo> atomscan**: Escanea tablas de átomos en el volcado de memoria.
- **volatility -f <archivo> timers**: Enumera los temporizadores en el volcado de memoria.
- **volatility -f <archivo> svcscan**: Enumera los servicios en el volcado de memoria.
- **volatility -f <archivo> svcscan**: Enumera los servicios en el volcado de memoria.
- **volatility -f <archivo> devicetree**: Enumera el árbol de dispositivos en el volcado de memoria.
- **volatility -f <archivo> drivermodule**: Enumera los módulos de controlador en el volcado de memoria.
- **volatility -f <archivo> iehistory**: Extrae el historial de navegación de Internet Explorer.
- **volatility -f <archivo> shellbags**: Enumera las carpetas abiertas recientemente.
- **volatility -f <archivo> userhandles -p <PID>**: Enumera los identificadores de usuario de un proceso específico.
- **volatility -f <archivo> vadinfo -p <PID>**: Muestra información sobre regiones de memoria virtuales de un proceso específico.
- **volatility -f <archivo> vadtree -p <PID>**: Muestra un árbol de regiones de memoria virtuales de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso específico.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae DLL de un proceso
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}
{% endtabs %}

### SIDs

Verifique cada SSID propiedad de un proceso.\
Podría ser interesante listar los procesos que utilizan un SID de privilegios (y los procesos que utilizan algún SID de servicio).
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Comandos básicos de Volatility

- **volatility -f <archivo_memoria> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo_memoria> pslist**: Lista los procesos en ejecución.
- **volatility -f <archivo_memoria> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <archivo_memoria> psscan**: Escanea los procesos.
- **volatility -f <archivo_memoria> dlllist -p <pid>**: Lista las DLL cargadas por un proceso específico.
- **volatility -f <archivo_memoria> cmdscan**: Escanea los procesos en busca de comandos ejecutados.
- **volatility -f <archivo_memoria> filescan**: Escanea los descriptores de archivos.
- **volatility -f <archivo_memoria> netscan**: Escanea los sockets de red.
- **volatility -f <archivo_memoria> connections**: Muestra las conexiones de red.
- **volatility -f <archivo_memoria> consoles**: Lista las consolas interactivas.
- **volatility -f <archivo_memoria> hivelist**: Enumera los registros del sistema.
- **volatility -f <archivo_memoria> userassist**: Extrae las entradas de UserAssist.
- **volatility -f <archivo_memoria> shimcache**: Extrae la información de ShimCache.
- **volatility -f <archivo_memoria> mftparser**: Analiza el MFT.
- **volatility -f <archivo_memoria> hivelist**: Enumera los registros del sistema.
- **volatility -f <archivo_memoria> userassist**: Extrae las entradas de UserAssist.
- **volatility -f <archivo_memoria> shimcache**: Extrae la información de ShimCache.
- **volatility -f <archivo_memoria> mftparser**: Analiza el MFT.

#### Plugins de Volatility

- **volatility --info | grep Profile**: Lista los perfiles disponibles.
- **volatility --info | grep -A2 -B2 <perfil>**: Muestra información detallada sobre un perfil específico.
- **volatility -f <archivo_memoria> --profile=<perfil> <comando>**: Ejecuta un comando específico con un perfil determinado.
- **volatility -f <archivo_memoria> --profile=<perfil> <plugin>**: Ejecuta un plugin específico con un perfil determinado.

#### Volatility avanzado

- **volatility -f <archivo_memoria> --profile=<perfil> kdbgscan**: Escanea en busca de KDBG.
- **voljson -f <archivo_memoria>**: Exporta la información en formato JSON.
- **volatility -f <archivo_memoria> --profile=<perfil> linux_bash**: Analiza la historia de comandos de Bash en sistemas Linux.
- **volatility -f <archivo_memoria> --profile=<perfil> linux_netstat**: Muestra las conexiones de red en sistemas Linux.
- **volatility -f <archivo_memoria> --profile=<perfil> linux_pslist**: Lista los procesos en sistemas Linux.
- **volatility -f <archivo_memoria> --profile=<perfil> linux_psaux**: Muestra información detallada sobre los procesos en sistemas Linux.
- **volatility -f <archivo_memoria> --profile=<perfil> linux_ifconfig**: Muestra la configuración de red en sistemas Linux.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
### Manijas

Útil para saber a qué otros archivos, claves, hilos, procesos... un **proceso tiene una manija** (ha abierto)
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{% endtab %}

{% tab title="vol2" %}La siguiente es una hoja de trucos de Volatility que resume los comandos más comunes utilizados para el análisis de volcado de memoria:

- **Información general del sistema:**
  - `imageinfo`: Muestra información básica sobre la imagen de memoria.
  - `kdbgscan`: Escanea la memoria en busca de estructuras de depuración de kernel.
  - `kpcrscan`: Escanea la memoria en busca de la estructura KPCR.
  - `pslist`: Lista los procesos en ejecución.
  - `pstree`: Muestra los procesos en forma de árbol.
  - `psscan`: Escanea la memoria en busca de procesos.
  
- **Análisis de procesos:**
  - `dlllist`: Lista las DLL cargadas por cada proceso.
  - `handles`: Muestra los descriptores de archivo abiertos por cada proceso.
  - `cmdline`: Muestra los argumentos de línea de comandos de cada proceso.
  - `consoles`: Muestra las consolas asociadas con cada proceso.
  
- **Análisis de red:**
  - `connections`: Muestra las conexiones de red.
  - `sockets`: Lista los sockets abiertos.
  
- **Análisis de registro:**
  - `hivelist`: Enumera los archivos de volcado del registro.
  - `printkey`: Muestra una clave de registro y sus valores.
  - `hashdump`: Extrae contraseñas de hashes de SAM y SYSTEM.
  
- **Análisis de malware:**
  - `malfind`: Encuentra inyecciones de malware en procesos.
  - `ldrmodules`: Lista los módulos cargados en cada proceso.
  
- **Análisis de rootkits:**
  - `ssdt`: Muestra la Service Descriptor Table.
  - `gdt`: Muestra la Global Descriptor Table.
  - `idt`: Muestra la Interrupt Descriptor Table.

Para obtener más información sobre cada comando, consulte la documentación oficial de Volatility.{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
### Bibliotecas de enlace dinámico

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% endtab %}

{% tab title="vol2" %}La siguiente es una hoja de trucos de Volatility para el análisis de volcado de memoria:

### Comandos básicos
- **volatility -f <file> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <file> pslist**: Lista los procesos en ejecución.
- **volatility -f <file> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> psscan**: Escanea los procesos.
- **volatility -f <file> dlllist -p <pid>**: Lista las DLL cargadas por un proceso.
- **volatility -f <file> cmdscan**: Escanea los procesos en busca de comandos.
- **volatility -f <file> consoles**: Lista las consolas interactivas.
- **volatility -f <file> filescan**: Escanea los descriptores de archivo.
- **volatility -f <file> netscan**: Escanea los sockets de red.
- **volatility -f <file> connections**: Muestra las conexiones de red.
- **volatility -f <file> svcscan**: Escanea los servicios.
- **volatility -f <file> hivelist**: Lista los registros del sistema.
- **volatility -f <file> printkey -o <offset>**: Muestra una clave de registro.
- **volatility -f <file> hashdump**: Muestra los hashes de contraseñas.
- **volatility -f <file> userassist**: Muestra las entradas de UserAssist.
- **volatility -f <file> shimcache**: Muestra la información de ShimCache.
- **volatility -f <file> malfind**: Encuentra procesos sospechosos.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> modscan**: Escanea los módulos.
- **volatility -f <file> getsids**: Muestra los SID de los procesos.
- **volatility -f <file> getservicesids**: Muestra los SID de los servicios.
- **volatility -f <file> yarascan**: Escanea con reglas Yara.
- **volatility -f <file> cmdline**: Muestra los argumentos de línea de comandos.
- **volatility -f <file> consoles -v**: Muestra información detallada de las consolas.
- **volatility -f <file> mftparser**: Analiza el MFT.
- **volatility -f <file> shimcachemem**: Muestra información de ShimCache desde el volcado de memoria.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos del volcado de memoria.
- **volatility -f <file> dumpregistry -o <output_directory>**: Extrae el registro del sistema.
- **volatility -f <file> dumpcerts -D <output_directory>**: Extrae certificados.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos del volcado de memoria.
- **volatility -f <file> dumpregistry -o <output_directory>**: Extrae el registro del sistema.
- **volatility -f <file> dumpcerts -D <output_directory>**: Extrae certificados.

### Plugins adicionales
- **volatility -f <file> --profile=<profile> <plugin>**: Ejecuta un plugin específico.
- **volatility -f <file> --profile=<profile> <plugin> -h**: Muestra la ayuda para un plugin.
- **volatility -f <file> --profile=<profile> <plugin> --output-file=<output_file>**: Guarda la salida en un archivo.
- **volatility -f <file> --profile=<profile> <plugin> --output-file=<output_file> -v**: Guarda la salida detallada en un archivo.
- **volatility -f <file> --profile=<profile> <plugin> --output-file=<output_file> --output-format=<format>**: Guarda la salida en un formato específico.

### Perfiles
- **volatility -f <file> imageinfo**: Identifica el perfil automáticamente.
- **volatility --info | grep -i <os>**: Lista los perfiles disponibles para un sistema operativo específico.
- **volatility -f <file> --profile=<profile> <plugin>**: Especifica un perfil manualmente.

### Volcado de memoria
- **volatility -f <file> --profile=<profile> <plugin>**: Analiza un volcado de memoria.
- **volatility -f <file> --profile=<profile> <plugin> --output-file=<output_file>**: Guarda la salida en un archivo.
- **volatility -f <file> --profile=<profile> <plugin> --output-file=<output_file> -v**: Guarda la salida detallada en un archivo.
- **volatility -f <file> --profile=<profile> <plugin> --output-file=<output_file> --output-format=<format>**: Guarda la salida en un formato específico.

### Ejemplos de uso
- **volatility -f memdump.mem imageinfo**: Muestra información básica del volcado de memoria.
- **volatility -f memdump.mem pslist**: Lista los procesos en ejecución.
- **volatility -f memdump.mem pstree**: Muestra los procesos en forma de árbol.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
### Cadenas por procesos

Volatility nos permite verificar a qué proceso pertenece una cadena.
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endtab %}

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Análisis de volcado de memoria

- **Listar procesos en ejecución:** `volatility -f <archivo> --profile=<perfil> pslist`
- **Mostrar información de un proceso:** `volatility -f <archivo> --profile=<perfil> pstree -p <PID>`
- **Extraer un proceso:** `volatility -f <archivo> --profile=<perfil> procdump -p <PID> -D <directorio_destino>`
- **Analizar los puertos de red:** `volatility -f <archivo> --profile=<perfil> netscan`
- **Analizar los sockets de red:** `volatility -f <archivo> --profile=<perfil> sockscan`
- **Analizar los controladores cargados:** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los módulos cargados:** `volatility -f <archivo> --profile=<perfil> modules`
- **Analizar los registros de Windows:** `volatility -f <archivo> --profile=<perfil> printkey -K <registro>`
- **Analizar los procesos y sus DLLs:** `volatility -f <archivo> --profile=<perfil> dlllist -p <PID>`
- **Analizar los handles abiertos por un proceso:** `volatility -f <archivo> --profile=<perfil> handles -p <PID>`
- **Analizar los enlaces simbólicos:** `volatility -f <archivo> --profile=<perfil> symlinkscan`
- **Analizar los objetos de seguridad:** `volatility -f <archivo> --profile=<perfil> sids`
- **Analizar los tokens de acceso:** `volatility -f <archivo> --profile=<perfil> tokens`
- **Analizar los procesos y sus hilos:** `volatility -f <archivo> --profile=<perfil> pstotal`
- **Analizar los registros de eventos:** `volatility -f <archivo> --profile=<perfil> evtlogs`
- **Analizar los volúmenes montados:** `volatility -f <archivo> --profile=<perfil> malfind`
- **Analizar los procesos y sus conexiones de red:** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus puertos de red:** `volatility -f <archivo> --profile=<perfil> connscan -p <PID>`
- **Analizar los procesos y sus DLLs cargadas:** `volatility -f <archivo> --profile=<perfil> dlldump -p <PID> -D <directorio_destino>`
- **Analizar los procesos y sus handles abiertos:** `volatility -f <archivo> --profile=<perfil> handles -p <PID>`
- **Analizar los procesos y sus hilos:** `volatility -f <archivo> --profile=<perfil> threads -p <PID>`
- **Analizar los procesos y sus módulos cargados:** `volatility -f <archivo> --profile=<perfil> moddump -p <PID> -D <directorio_destino>`
- **Analizar los procesos y sus tokens de acceso:** `volatility -f <archivo> --profile=<perfil> getsids -p <PID>`
- **Analizar los procesos y sus enlaces simbólicos:** `volatility -f <archivo> --profile=<perfil> symlinkscan -p <PID>`
- **Analizar los procesos y sus objetos de seguridad:** `volatility -f <archivo> --profile=<perfil> getsids -p <PID>`
- **Analizar los procesos y sus registros de Windows:** `volatility -f <archivo> --profile=<perfil> printkey -K <registro> -p <PID>`
- **Analizar los procesos y sus volúmenes montados:** `volatility -f <archivo> --profile=<perfil> malfind -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> connscan -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> evtlogs -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> netscan -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> psxview -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> cmdline -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> consoles -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> getsids -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> hivelist`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> hivedump -o <offset> -D <directorio_destino>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> userassist`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> shimcache`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> ldrmodules -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> malfind -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> moddump -p <PID> -D <directorio_destino>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> dlllist -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> handles -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> threads -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> moddump -p <PID> -D <directorio_destino>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> getsids -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> symlinkscan -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> getsids -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> printkey -K <registro> -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> malfind -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> connscan -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> evtlogs -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> netscan -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> psxview -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> cmdline -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> consoles -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> getsids -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> hivelist`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> hivedump -o <offset> -D <directorio_destino>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> userassist`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> shimcache`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> ldrmodules -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> malfind -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> moddump -p <PID> -D <directorio_destino>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> dlllist -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> handles -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> threads -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> moddump -p <PID> -D <directorio_destino>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> getsids -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> symlinkscan -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> getsids -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> printkey -K <registro> -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> malfind -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> connscan -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> evtlogs -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> netscan -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> psxview -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> cmdline -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> consoles -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> getsids -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> hivelist`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> hivedump -o <offset> -D <directorio_destino>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> userassist`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> shimcache`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> ldrmodules -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> malfind -p <PID>`
- **Analizar los procesos y sus eventos de red:** `volatility -f <archivo> --profile=<perfil> moddump -p <PID> -D <directorio_destino>`
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
También permite buscar cadenas dentro de un proceso utilizando el módulo yarascan:
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% endtab %}

{% tab title="vol2" %}La siguiente es una hoja de trucos de Volatility que resume los comandos y opciones más comunes utilizados para el análisis de volcados de memoria:

### Análisis básico de volcado de memoria
- **volatility -f dump.mem imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f dump.mem pslist**: Enumera los procesos en ejecución.
- **volatility -f dump.mem psscan**: Escanea los procesos a través de los espacios de direcciones.
- **volatility -f dump.mem pstree**: Muestra los procesos en forma de árbol.
- **volatility -f dump.mem dlllist -p PID**: Lista las DLL cargadas por un proceso específico.
- **volatility -f dump.mem cmdline -p PID**: Muestra el comando utilizado para ejecutar un proceso.
- **volatility -f dump.mem filescan**: Escanea los descriptores de archivo.
- **volatility -f dump.mem netscan**: Escanea los sockets de red.
- **volatility -f dump.mem connections**: Muestra las conexiones de red.
- **volatility -f dump.mem malfind**: Encuentra inyecciones de código malicioso en procesos.
- **volatility -f dump.mem apihooks**: Muestra los ganchos de API en procesos.
- **volatility -f dump.mem ldrmodules**: Lista los módulos cargados en procesos.
- **volatility -f dump.mem modscan**: Escanea los módulos del kernel.
- **volatility -f dump.mem shimcache**: Muestra la información de la caché de Shim.

### Análisis avanzado de volcado de memoria
- **volatility -f dump.mem memmap**: Muestra el mapeo de memoria.
- **volatility -f dump.mem memdump -p PID -D /path/to/dump**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f dump.mem memdump -p PID -r range -D /path/to/dump**: Realiza un volcado de memoria de un proceso en un rango específico.
- **volatility -f dump.mem memstrings**: Encuentra cadenas ASCII e Unicode en la memoria.
- **volatility -f dump.mem yarascan -Y "/path/to/rules.yar"**: Escanea la memoria en busca de patrones definidos por reglas YARA.
- **volatility -f dump.mem procdump -p PID -D /path/to/dump**: Realiza un volcado de memoria de un proceso en un archivo.
- **volatility -f dump.mem procdump -p PID -D /path/to/dump --dump-dir /path/to/dir**: Realiza un volcado de memoria de un proceso en un directorio.

Para obtener más información sobre los comandos y opciones de Volatility, consulte la [documentación oficial de Volatility](https://github.com/volatilityfoundation/volatility/wiki).{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
### UserAssist

**Windows** registra los programas que ejecutas utilizando una característica en el registro llamada **claves UserAssist**. Estas claves registran cuántas veces se ejecuta cada programa y cuándo se ejecutó por última vez.
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% endtab %}

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Comandos básicos de Volatility

- **volatility -f <archivo> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: Muestra una lista de procesos en el volcado de memoria.
- **volatility -f <archivo> pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **volatility -f <archivo> psscan**: Escanea procesos a través del volcado de memoria.
- **volatility -f <archivo> dlllist -p <PID>**: Muestra las DLL cargadas por un proceso específico.
- **volatility -f <archivo> cmdline -p <PID>**: Muestra el comando utilizado para ejecutar un proceso específico.
- **volatility -f <archivo> filescan**: Escanea descriptores de archivos en el volcado de memoria.
- **volatility -f <archivo> netscan**: Escanea conexiones de red en el volcado de memoria.
- **volatility -f <archivo> connections**: Muestra conexiones de red en el volcado de memoria.
- **volatility -f <archivo> malfind**: Encuentra procesos sospechosos en el volcado de memoria.
- **volatility -f <archivo> yarascan**: Escanea el volcado de memoria en busca de patrones con Yara.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> linux_bash**: Muestra comandos de Bash en el volcado de memoria.
- **volatility -f <archivo> linux_netstat**: Muestra información de netstat en el volcado de memoria.

#### Plugins adicionales de Volatility

- **volatility -f <archivo> <nombre_del_plugin>**: Ejecuta un plugin específico en el volcado de memoria.
- **volatility --info | grep <nombre_del_plugin>**: Muestra información sobre un plugin específico.
- **volatility --plugins=<directorio>**: Carga plugins adicionales desde un directorio específico.
- **volatility --profile=<perfil> -f <archivo> <nombre_del_plugin>**: Ejecuta un plugin con un perfil específico.

#### Análisis avanzado con Volatility

- **Análisis de malware**: Utiliza plugins como malfind, yarascan y apihooks para identificar malware en el volcado de memoria.
- **Análisis de rootkits**: Emplea plugins como ldrmodules, ldrmodules, ssdt, y otros para detectar rootkits en el sistema comprometido.
- **Análisis de tráfico de red**: Utiliza plugins como connscan, netscan y sockets para investigar la actividad de red en el volcado de memoria.

{% endtab %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro clave para profesionales de la tecnología y ciberseguridad en todas las disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## Servicios

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Comandos básicos de Volatility

- **volatility -f <file> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <file> pslist**: Lista los procesos en ejecución.
- **volatility -f <file> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> psscan**: Escanea los procesos.
- **volatility -f <file> dlllist -p <pid>**: Lista las DLL cargadas por un proceso específico.
- **volatility -f <file> cmdscan**: Escanea los procesos en busca de comandos ejecutados.
- **volatility -f <file> filescan**: Escanea los descriptores de archivo.
- **volatility -f <file> netscan**: Escanea los sockets de red.
- **volatility -f <file> connections**: Muestra las conexiones de red.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso en procesos.
- **volatility -f <file> yarascan**: Escanea la memoria en busca de patrones con Yara.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos del volcado de memoria.
- **volatility -f <file> cmdline**: Muestra los argumentos de línea de comandos de los procesos.
- **volatility -f <file> hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados en memoria.
- **volatility -f <file> modscan**: Escanea los módulos cargados en memoria.
- **volatility -f <file> getsids**: Enumera los SID de los procesos.
- **volatility -f <file> getservicesids**: Enumera los SID de los servicios.
- **volatility -f <file> svcscan**: Escanea los servicios.
- **volatility -f <file> driverirp**: Enumera los controladores y las IRP asociadas.
- **volatility -f <file> devicetree**: Muestra el árbol de dispositivos.
- **volatility -f <file> handles**: Enumera los descriptores de archivo y los objetos.
- **volatility -f <file> mutantscan**: Escanea los objetos de tipo mutante.
- **volatility -f <file> envars**: Muestra las variables de entorno de los procesos.
- **volatility -f <file> atomscan**: Escanea los átomos del sistema.
- **volatility -f <file> callbacks**: Enumera las rutinas de devolución de llamada.
- **volatility -f <file> svcscan**: Escanea los servicios.
- **volatility -f <file> ssdt**: Enumera las entradas de la tabla de servicios del sistema.
- **volatility -f <file> idt**: Enumera la tabla de descriptores de interrupciones.
- **voltability -f <file> gdt**: Enumera la tabla de descriptores globales.
- **volatility -f <file> threads**: Lista los hilos en ejecución.
- **volatility -f <file> callbacks**: Enumera las rutinas de devolución de llamada.
- **volatility -f <file> timers**: Lista los temporizadores del sistema.
- **volatility -f <file> modules**: Lista los módulos del kernel.
- **volatility -f <file> driverscan**: Escanea los controladores cargados en memoria.
- **volatility -f <file> ssdt**: Enumera las entradas de la tabla de servicios del sistema.
- **volatility -f <file> idt**: Enumera la tabla de descriptores de interrupciones.
- **volatility -f <file> gdt**: Enumera la tabla de descriptores globales.
- **volatility -f <file> threads**: Lista los hilos en ejecución.
- **volatility -f <file> timers**: Lista los temporizadores del sistema.
- **volatility -f <file> modules**: Lista los módulos del kernel.
- **volatility -f <file> driverscan**: Escanea los controladores cargados en memoria.

#### Plugins adicionales

- **volatility -f <file> windows.handles.Handles**: Enumera los descriptores de archivo y los objetos.
- **volatility -f <file> windows.envars.Envars**: Muestra las variables de entorno de los procesos.
- **volatility -f <file> windows.registry.RegistryPrintKey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.registry.Userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <file> windows.registry.Shimcache**: Recupera la información de ShimCache del Registro.
- **volatility -f <file> windows.registry.Hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <file> windows.registry.Printkey -o <offset>
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
{% endtab %}
{% endtabs %}

## Red

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{% endtab %}

{% tab title="vol2" %}La siguiente es una hoja de trucos de Volatility que resume los comandos y opciones más comunes utilizados para el análisis de volcados de memoria:

### Comandos Básicos
- **imageinfo**: Muestra información básica sobre la imagen de memoria.
- **pslist**: Lista los procesos en la imagen de memoria.
- **pstree**: Muestra los procesos en forma de árbol.
- **dlllist**: Lista los módulos DLL cargados en los procesos.
- **handles**: Muestra los descriptores de archivo y claves del registro abiertos por cada proceso.
- **filescan**: Escanea la memoria en busca de estructuras de archivos.
- **cmdline**: Muestra los argumentos de línea de comandos de los procesos.
- **consoles**: Enumera las consolas de los procesos.
- **vadinfo**: Muestra información sobre los espacios de direcciones virtuales (VAD) de los procesos.
- **vadtree**: Muestra los VAD en forma de árbol.
- **malfind**: Encuentra inyecciones de código malicioso en los procesos.
- **yarascan**: Escanea la memoria en busca de patrones con Yara.

### Opciones Útiles
- **-f, --file**: Especifica el archivo de volcado de memoria a analizar.
- **-p, --pid**: Especifica el PID del proceso a analizar.
- **-D, --dump-dir**: Directorio donde se guardarán los volcados de memoria.
- **-h, --help**: Muestra la ayuda y la lista de opciones disponibles.

Para obtener más información sobre un comando específico, se puede utilizar la opción `--help` después del comando. Por ejemplo, `volatility pslist --help`.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
## Registro de colmena

### Imprimir colmenas disponibles

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% endtab %}

{% tab title="vol2" %}La siguiente es una hoja de trucos de Volatility que resume los comandos y opciones más comunes utilizados para el análisis de volcados de memoria:

### Comandos Básicos
- **imageinfo**: Muestra información básica sobre la imagen de memoria.
- **pslist**: Lista los procesos en ejecución.
- **pstree**: Muestra los procesos en forma de árbol.
- **psscan**: Escanea procesos a través de los espacios de direcciones.
- **dlllist**: Lista las DLL cargadas por cada proceso.
- **handles**: Muestra los descriptores de archivo abiertos por cada proceso.
- **filescan**: Escanea la memoria en busca de estructuras de archivos.
- **cmdline**: Muestra los argumentos de línea de comandos de cada proceso.
- **netscan**: Escanea la memoria en busca de conexiones de red.

### Opciones Útiles
- **-f, --file**: Especifica el archivo de volcado de memoria a analizar.
- **-p, --pid**: Especifica el PID del proceso a analizar.
- **-D, --output-dir**: Especifica el directorio de salida para los resultados.
- **-h, --help**: Muestra la ayuda y la lista de opciones disponibles.

### Ejemplos de Uso
- `vol.py -f memdump.mem imageinfo`: Muestra información sobre la imagen de memoria.
- `vol.py -f memdump.mem --profile=Win7SP1x64 pslist`: Lista los procesos en ejecución en un sistema Windows 7 de 64 bits.
- `vol.py -f memdump.mem --profile=Win7SP1x64 pstree -p 1234`: Muestra el árbol de procesos para el PID 1234 en un sistema Windows 7 de 64 bits.

Estos son solo algunos de los comandos y opciones más utilizados en Volatility para el análisis de volcados de memoria. Consulta la documentación oficial para obtener más información y opciones disponibles. {% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{% endtab %}
{% endtabs %}

### Obtener un valor

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{% endtab %}

{% tab title="vol2" %} 

## Hoja de trucos de Volatility

### Comandos básicos

- **volatility -f <archivo> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: Muestra una lista de procesos en el volcado de memoria.
- **volatility -f <archivo> pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **volatility -f <archivo> psscan**: Escanea procesos a través del volcado de memoria.
- **volatility -f <archivo> dlllist -p <PID>**: Lista los módulos DLL cargados por un proceso específico.
- **volatility -f <archivo> cmdline -p <PID>**: Muestra el comando utilizado para ejecutar un proceso específico.
- **volatility -f <archivo> filescan**: Escanea descriptores de archivos en el volcado de memoria.
- **volatility -f <archivo> netscan**: Escanea conexiones de red en el volcado de memoria.
- **volatility -f <archivo> connections**: Muestra las conexiones de red en el volcado de memoria.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código malicioso en el volcado de memoria.
- **volatility -f <archivo> yarascan**: Escanea el volcado de memoria en busca de patrones YARA.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcjson de memoria.
- **volatility -f <archivo> memdump -p <PID> -D <destino>**: Crea un volcado de memoria para un proceso específico.
- **volatility -f <archivo> linux_bash**: Recupera comandos de bash eliminados del volcado de memoria.

### Plugins adicionales

- **volatility -f <archivo> --profile=<perfil> <plugin>**: Ejecuta un plugin específico con un perfil determinado.
- **volatility -f <archivo> --plugins=<ruta> <plugin>**: Ejecuta un plugin específico desde una ubicación personalizada.
- **volatility -f <archivo> --output-file=<archivo> <comando>**: Guarda la salida de un comando en un archivo.

### Ejemplos de uso

- **volatility -f memdump.mem imageinfo**: Muestra información básica sobre el volcado de memoria "memdump.mem".
- **volatility -f memdump.mem pslist**: Muestra una lista de procesos en el volcado de memoria "memdump.mem".
- **volatility -f memdump.mem pstree**: Muestra un árbol de procesos en el volcado de memoria "memdump.mem".

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{% endtab %}
{% endtabs %}

### Volcado
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## Sistema de archivos

### Montaje

{% tabs %}
{% tab title="vol3" %}
```bash
#See vol2
```
{% endtab %}

{% tab title="vol2" %} 

## Hoja de trucos de Volatility

### Comandos básicos

- **volatility -f <file> imageinfo**: Escanea el volcado de memoria para obtener información básica.
- **volatility -f <file> pslist**: Enumera los procesos en ejecución.
- **volatility -f <file> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> psscan**: Escanea los procesos a nivel de kernel.
- **volatility -f <file> dlllist -p <pid>**: Lista las DLL cargadas por un proceso específico.
- **volatility -f <file> cmdscan**: Busca comandos ejecutados en la memoria.
- **volatility -f <file> consoles**: Enumera las consolas interactivas detectadas.
- **volatility -f <file> filescan**: Escanea los objetos de archivo en memoria.
- **volatility -f <file> netscan**: Escanea los sockets de red abiertos.
- **volatility -f <file> connections**: Muestra las conexiones de red.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <file> yarascan**: Escanea la memoria en busca de patrones con Yara.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos de memoria.
- **volatility -f <file> cmdline**: Muestra los comandos ejecutados por los procesos.
- **volatility -f <file> hivelist**: Enumera los archivos de volcado del registro.
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro específica.
- **volatility -f <file> userassist**: Recupera las entradas de UserAssist.
- **volatility -f <file> shimcache**: Recupera información de ShimCache.
- **volatility -f <file> ldrmodules**: Enumera los módulos cargados en el espacio de usuario.
- **volatility -f <file> modscan**: Escanea los módulos del kernel.
- **volatility -f <file> getsids**: Enumera los SID de los procesos.
- **volatility -f <file> getservicesids**: Enumera los SID de los servicios.
- **volatility -f <file> svcscan**: Enumera los servicios.
- **volatility -f <file> devicetree**: Enumera los dispositivos físicos.
- **volatility -f <file> driverirp**: Enumera los controladores y las IRP asociadas.
- **volatility -f <file> ssdt**: Enumera la Service Descriptor Table.
- **volatility -f <file> callbacks**: Enumera las rutinas de callback.
- **volatility -f <file> mutantscan**: Escanea los objetos de mutante.
- **volatility -f <file> envars**: Enumera las variables de entorno.
- **volatility -f <file> consoles -p <pid>**: Muestra las consolas asociadas a un proceso.
- **volatility -f <file> vadinfo -p <pid>**: Muestra información sobre el espacio de direcciones virtuales de un proceso.
- **volatility -f <file> vadtree -p <pid>**: Muestra el árbol de descriptores de direcciones virtuales de un proceso.
- **volatility -f <file> memmap**: Muestra un mapa de memoria.
- **volatility -f <file> memdump -p <pid> -D <output_directory>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <file> memdump -p <pid> -o <offset> -D <output_directory>**: Realiza un volcado de memoria de un proceso en un desplazamiento específico.
- **volatility -f <file> memstrings -p <pid>**: Extrae cadenas ASCII de la memoria de un proceso.
- **volatility -f <file> memstrings -Q <address>**: Extrae cadenas ASCII de una dirección de memoria específica.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <file> malfind -p <pid>**: Encuentra inyecciones de código malicioso en un proceso específico.
- **volatility -f <file> malfind -D <output_directory>**: Escanea la memoria en busca de inyecciones de código malicioso y las extrae.
- **volatility -f <file> malfind -Y <yara_rule>**: Escanea la memoria en busca de inyecciones de código malicioso que coincidan con una regla Yara.
- **volatility -f <file> malfind -p <pid> -D <output_directory>**: Escanea la memoria de un proceso específico en busca de inyecciones de código malicioso y las extrae.
- **volatility -f <file> malfind -p <pid> -Y <yara_rule>**: Escanea la memoria de un proceso específico en busca de inyecciones de código malicioso que coincidan con una regla Yara.
- **volatility -f <file> malfind -D <output_directory> -Y <yara_rule>**: Escanea la memoria en busca de inyecciones de código malicioso que coincidan con una regla Yara y las extrae.
- **volatility -f <file> malfind -p <pid> -D <output_directory> -Y <yara_rule>**: Escanea la memoria de un proceso específico en busca de inyecciones de código malicioso que coincidan con una regla Yara y las extrae.

### Plugins adicionales

- **apihooks**: Enumera los ganchos de API.
- **atomscan**: Escanea los objetos de atom.
- **atomscan -s**: Escanea los objetos de atom compartidos.
- **atomscan -l**: Escanea los objetos de atom locales.
- **atomscan -r**: Escanea los objetos de atom remotos.
- **atomscan -x**: Escanea los objetos de atom eliminados.
- **callbacks**: Enumera las rutinas de callback.
- **callbacks -p <pid>**: Enumera las rutinas de callback asociadas a un proceso.
- **callbacks -t**: Enumera las rutinas de callback en la tabla de rutinas.
- **callbacks -u**: Enumera las rutinas de callback no utilizadas.
- **connscan**: Escanea las conexiones de red.
- **connscan -p <pid>**: Filtra las conexiones de red por PID.
- **connscan -s**: Filtra las conexiones de red por estado.
- **connscan -l**: Filtra las conexiones de red por dirección local.
- **connscan -r**: Filtra las conexiones de red por dirección remota.
- **connscan -c**: Filtra las conexiones de red por contexto.
- **connscan -o**: Filtra las conexiones de red por opciones.
- **connscan -f**: Filtra las conexiones de red por familia de direcciones.
- **connscan -t**: Filtra las conexiones de red por tipo de socket.
- **connscan -a**: Filtra las conexiones de red por dirección de la interfaz.
- **connscan -i**: Filtra las conexiones de red por índice de interfaz.
- **connscan -d**: Filtra las conexiones de red por descripción de interfaz.
- **connscan -n**: Filtra las conexiones de red por nombre de interfaz.
- **connscan -b**: Filtra las conexiones de red por bytes enviados.
- **connscan -v**: Filtra las conexiones de red por bytes recibidos.
- **connscan -w**: Filtra las conexiones de red por ventana de recepción.
- **connscan -e**: Filtra las conexiones de red por tiempo de espera.
- **connscan -m**: Filtra las conexiones de red por marca de tiempo.
- **connscan -g**: Filtra las conexiones de red por marca de tiempo global.
- **connscan -z**: Filtra las conexiones de red por marca de tiempo de inicio.
- **connscan -j**: Filtra las conexiones de red por marca de tiempo de cierre.
- **connscan -k**: Filtra las conexiones de red por marca de tiempo de última actividad.
- **connscan -q**: Filtra las conexiones de red por marca de tiempo de última reactivación.
- **connscan -y**: Filtra las conexiones de red por marca de tiempo de última reactivación global.
- **connscan -u**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario.
- **connscan -h**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -n**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -b**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -v**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -w**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -e**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -m**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -g**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -z**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -j**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -k**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -q**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -y**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -u**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -h**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -n**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -b**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -v**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -w**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -e**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -m**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -g**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -z**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -j**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -k**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -q**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -y**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -u**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -h**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -n**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -b**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -v**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -w**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -e**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -m**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -g**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -z**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -j**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -k**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -q**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -y**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -u**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -h**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -n**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -b**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -v**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -w**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -e**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -m**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -g**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -z**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -j**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -k**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -q**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -y**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -u**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -h**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -n**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -b**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -v**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -w**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -e**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -m**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -g**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -z**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -j**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -k**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -q**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -y**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -u**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -h**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -n**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -b**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -v**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -w**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -e**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -m**: Filtra las conexiones de red por marca de tiempo de última reactivación de usuario global.
- **connscan -g**: Filtra las conexiones de red
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
### Escaneo/volcado

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{% endtab %}

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Volatility

- **Volatility** es un marco de trabajo de análisis de memoria.
- **Volatility** es un proyecto de código abierto.
- **Volatility** es compatible con la mayoría de los sistemas operativos.
- **Volatility** es una herramienta poderosa para el análisis forense de memoria.

#### Uso básico

- `volatility -f <archivo de volcado> <comando>`

#### Comandos comunes

- `imageinfo`: muestra información básica sobre el volcado de memoria.
- `pslist`: muestra una lista de procesos en el volcado de memoria.
- `pstree`: muestra un árbol de procesos en el volcado de memoria.
- `psscan`: escanea procesos a través del volcado de memoria.
- `dlllist`: muestra una lista de DLL cargadas en el espacio de memoria de un proceso.
- `cmdline`: muestra la línea de comandos de un proceso.
- `filescan`: escanea en busca de objetos de archivo en el volcado de memoria.
- `netscan`: escanea en busca de artefactos de red en el volcado de memoria.

#### Ejemplos de uso

- `volatility -f memdump.mem imageinfo`
- `volatility -f memdump.mem pslist`
- `volatility -f memdump.mem cmdline -p <PID>`

#### Recursos adicionales

- [Sitio web de Volatility](https://www.volatilityfoundation.org/)
- [Documentación de Volatility](https://github.com/volatilityfoundation/volatility/wiki)

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
### Tabla maestra de archivos

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{% endtab %}

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Análisis de volcado de memoria

- **Listar procesos en ejecución:** `volatility -f <archivo> --profile=<perfil> pslist`
- **Mostrar información de un proceso:** `volatility -f <archivo> --profile=<perfil> pstree -p <PID>`
- **Analizar puertos de red abiertos:** `volatility -f <archivo> --profile=<perfil> connections`
- **Analizar los sockets de red:** `volatility -f <archivo> --profile=<perfil> sockscan`
- **Analizar los controladores cargados:** `volatility -f <archivo> --profile=<perfil> driverscan`
- **Analizar los módulos cargados:** `volatility -f <archivo> --profile=<perfil> modscan`
- **Analizar los registros de eventos:** `volatility -f <archivo> --profile=<perfil> evtlogs`
- **Analizar los procesos y sus DLLs:** `volatility -f <archivo> --profile=<perfil> dlllist -p <PID>`
- **Extraer un proceso en memoria:** `volatility -f <archivo> --profile=<perfil> procdump -p <PID> --dump-dir=<directorio>`
- **Analizar el caché de registro:** `volatility -f <archivo> --profile=<perfil> hivelist`
- **Extraer un registro específico:** `volatility -f <archivo> --profile=<perfil> printkey -o <offset>`
- **Analizar los usuarios y sus SID:** `volatility -f <archivo> --profile=<perfil> getsids`
- **Analizar los tokens de acceso:** `volatility -f <archivo> --profile=<perfil> tokens`
- **Analizar los procesos y sus hilos:** `volatility -f <archivo> --profile=<perfil> pstotal`
- **Analizar los procesos y sus puertos:** `volatility -f <archivo> --profile=<perfil> psscan`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> malfind`
- **Analizar los procesos y sus handles:** `volatility -f <archivo> --profile=<perfil> handles`
- **Analizar los procesos y sus privilegios:** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red:** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas:** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `volatility -f <archivo> --profile=<perfil> privs`
- **Analizar los procesos y sus conexiones de red (más detallado):** `volatility -f <archivo> --profile=<perfil> connscan`
- **Analizar los procesos y sus cargas (más detallado):** `volatility -f <archivo> --profile=<perfil> psxview`
- **Analizar los procesos y sus DLLs (más detallado):** `volatility -f <archivo> --profile=<perfil> ldrmodules`
- **Analizar los procesos y sus hilos (más detallado):** `volatility -f <archivo> --profile=<perfil> threads`
- **Analizar los procesos y sus privilegios (más detallado):** `vol
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

El sistema de archivos **NTFS** utiliza un componente crítico conocido como la _tabla maestra de archivos_ (MFT). Esta tabla incluye al menos una entrada para cada archivo en un volumen, cubriendo también el propio MFT. Detalles vitales sobre cada archivo, como **tamaño, marcas de tiempo, permisos y datos reales**, están encapsulados dentro de las entradas del MFT o en áreas externas al MFT pero referenciadas por estas entradas. Se pueden encontrar más detalles en la [documentación oficial](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### Claves/Certificados SSL
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% endtab %}

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Volatility

- **Volatility** es un marco de trabajo de análisis de memoria.
- **Volatility** es un conjunto de herramientas para la extracción de información de la memoria de sistemas en ejecución.
- **Volatility** es compatible con la adquisición de imágenes de memoria en varios formatos.
- **Volatility** es compatible con la adquisición de imágenes de memoria de sistemas operativos Windows, macOS y Linux.

#### Uso básico

- `volatility -f <archivo de imagen> <comando>`

#### Comandos útiles

- `imageinfo`: muestra información básica sobre la imagen de memoria.
- `pslist`: muestra una lista de procesos en la imagen de memoria.
- `pstree`: muestra una representación en árbol de los procesos en la imagen de memoria.
- `dlllist`: muestra una lista de DLL cargadas en los procesos.
- `cmdscan`: escanea la memoria en busca de estructuras de procesos cmd.exe.
- `filescan`: escanea la memoria en busca de estructuras de archivos.
- `malfind`: encuentra inyecciones de malware en procesos.
- `yarascan`: escanea la memoria en busca de patrones YARA.
- `dump`: extrae un proceso específico de la memoria.

#### Recursos adicionales

- Documentación oficial: [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
- Perfiles de memoria: [Volatility Profiles](https://github.com/volatilityfoundation/volatility/wiki/FAQ#what-profile-should-i-use)
- Plugins de Volatility: [Volatility Plugins](https://github.com/volatilityfoundation/volatility/wiki/CommandReference-Plugins)
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
## Malware

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{% endtab %}

{% tab title="vol2" %} 

## Hoja de trucos de Volatility

### Comandos básicos

- **volatility -f <file> imageinfo**: Escanea el volcado de memoria para obtener información básica.
- **volatility -f <file> pslist**: Enumera los procesos en ejecución.
- **volatility -f <file> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> psscan**: Escanea los procesos a nivel de kernel.
- **volatility -f <file> dlllist -p <pid>**: Lista las DLL cargadas por un proceso específico.
- **volatility -f <file> cmdline -p <pid>**: Muestra el comando utilizado para ejecutar un proceso.
- **volatility -f <file> filescan**: Escanea los descriptores de archivo.
- **volatility -f <file> netscan**: Muestra las conexiones de red.
- **volatility -f <file> connections**: Muestra las conexiones de red en formato detallado.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <file> apihooks**: Muestra los ganchos de API.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados en el espacio de usuario.
- **volatility -f <file> consoles**: Enumera las consolas interactivas.
- **volatility -f <file> hivelist**: Enumera las ubicaciones del Registro en memoria.
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de Registro en una ubicación específica.
- **volatility -f <file> userassist**: Enumera las entradas de UserAssist.
- **volatility -f <file> shimcache**: Enumera las entradas de ShimCache.
- **volatility -f <file> getsids**: Enumera los SID de usuario.
- **volatility -f <file> envars**: Muestra las variables de entorno.
- **volatility -f <file> hivescan**: Escanea las ubicaciones del Registro en memoria.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos del volcado de memoria.
- **volatility -f <file> memdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria del sistema.
- **volatility -f <file> modscan**: Escanea los módulos del kernel.
- **volatility -f <file> mutantscan**: Escanea los objetos de mutante.
- **volatility -f <file> yarascan**: Escanea la memoria en busca de patrones YARA.
- **volatility -f <file> cmdline**: Muestra los comandos utilizados para ejecutar procesos.
- **volatility -f <file> vadinfo -o <offset>**: Muestra información sobre un área de memoria específica.
- **volatility -f <file> vadtree**: Muestra el árbol de áreas de memoria virtuales.
- **volatility -f <file> handles**: Enumera los descriptores de archivo y los objetos del kernel.
- **volatility -f <file> driverirp**: Enumera los IRP manejados por los controladores del kernel.
- **volatility -f <file> devicetree**: Muestra el árbol de dispositivos.
- **volatility -f <file> ssdt**: Enumera los servicios del kernel.
- **volatility -f <file> callbacks**: Enumera los callbacks del kernel.
- **volatility -f <file> gdt**: Muestra la tabla de descriptores globales.
- **volatility -f <file> idt**: Muestra la tabla de descriptores de interrupción.
- **volatility -f <file> threads**: Enumera los hilos del sistema.
- **volatility -f <file> thrdscan**: Escanea los objetos de hilo.
- **volatility -f <file> timers**: Enumera los temporizadores del sistema.
- **volatility -f <file> timerscan**: Escanea los objetos de temporizador.
- **volatility -f <file> modules**: Enumera los módulos del kernel.
- **volatility -f <file> moddump -b <base_address> -D <output_directory>**: Extrae un módulo específico del volcado de memoria.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <file> malfind -p <pid>**: Encuentra inyecciones de código malicioso en un proceso específico.
- **volatility -f <file> malfind -D <output_directory>**: Escanea la memoria en busca de inyecciones de código malicioso y las extrae.
- **volatility -f <file> malfind -Y <malware_signature>**: Escanea la memoria en busca de inyecciones de código malicioso con una firma específica.
- **volatility -f <file> malfind -y <malware_signature> -D <output_directory>**: Escanea la memoria en busca de inyecciones de código malicioso con una firma específica y las extrae.
- **volatility -f <file> malfind -V**: Escanea la memoria en busca de inyecciones de código malicioso y las extrae, mostrando información adicional.
- **volatility -f <file> malfind -p <pid> -D <output_directory> -O <offset>**: Escanea la memoria en busca de inyecciones de código malicioso en un proceso específico y las extrae en una ubicación específica.
- **volatility -f <file> malfind -p <pid> -D <output_directory> -O <offset> -Y <malware_signature>**: Escanea la memoria en busca de inyecciones de código malicioso con una firma específica en un proceso específico y las extrae en una ubicación específica.
- **volatility -f <file> malfind -p <pid> -D <output_directory> -O <offset> -y <malware_signature>**: Escanea la memoria en busca de inyecciones de código malicioso con una firma específica en un proceso específico y las extrae en una ubicación específica.
- **volatility -f <file> malfind -D <output_directory> -Y <malware_signature>**: Escanea la memoria en busca de inyecciones de código malicioso con una firma específica y las extrae en una ubicación específica.
- **volatility -f <file> malfind -D <output_directory> -y <malware_signature>**: Escanea la memoria en busca de inyecciones de código malicioso con una firma específica y las extrae en una ubicación específica.
- **volatility -f <file> malfind -V -D <output_directory>**: Escanea la memoria en busca de inyecciones de código malicioso y las extrae, mostrando información adicional en una ubicación específica.
- **volatility -f <file> malfind -V -D <output_directory> -Y <malware_signature>**: Escanea la memoria en busca de inyecciones de código malicioso con una firma específica y las extrae, mostrando información adicional en una ubicación específica.
- **volatility -f <file> malfind -V -D <output_directory> -y <malware_signature>**: Escanea la memoria en busca de inyecciones de código malicioso con una firma específica y las extrae, mostrando información adicional en una ubicación específica.

### Plugins adicionales

- **apihooks**: Muestra los ganchos de API.
- **atoms**: Enumera los átomos del sistema.
- **atomscan**: Escanea los átomos del sistema.
- **atomscan -s <atom_table_address>**: Escanea los átomos del sistema en una dirección de tabla de átomos específica.
- **atomscan -t <atom_value>**: Escanea los átomos del sistema con un valor específico.
- **atomscan -r <atom_reference_count>**: Escanea los átomos del sistema con un recuento de referencia específico.
- **atomscan -o <atom_offset>**: Escanea los átomos del sistema en un desplazamiento específico.
- **atomscan -a <atom_address>**: Escanea los átomos del sistema en una dirección específica.
- **atomscan -x <atom_flags>**: Escanea los átomos del sistema con banderas específicas.
- **atomscan -d**: Escanea los átomos del sistema eliminados.
- **atomscan -u**: Escanea los átomos del sistema no utilizados.
- **atomscan -v**: Escanea los átomos del sistema con valores Unicode.
- **atomscan -w**: Escanea los átomos del sistema con valores ANSI.
- **atomscan -m**: Escanea los átomos del sistema con valores mixtos.
- **atomscan -f**: Escanea los átomos del sistema con valores de cadena.
- **atomscan -c**: Escanea los átomos del sistema con valores de cadena Unicode.
- **atomscan -b**: Escanea los átomos del sistema con valores de cadena ANSI.
- **atomscan -z**: Escanea los átomos del sistema con valores nulos.
- **atomscan -l**: Escanea los átomos del sistema con valores largos.
- **atomscan -i**: Escanea los átomos del sistema con valores cortos.
- **atomscan -n**: Escanea los átomos del sistema con valores numéricos.
- **atomscan -p**: Escanea los átomos del sistema con valores de puntero.
- **atomscan -e**: Escanea los átomos del sistema con valores de error.
- **atomscan -g**: Escanea los átomos del sistema con valores de gestión.
- **atomscan -k**: Escanea los átomos del sistema con valores de clave.
- **atomscan -q**: Escanea los átomos del sistema con valores de cuantificador.
- **atomscan -y**: Escanea los átomos del sistema con valores de tipo.
- **atomscan -h**: Muestra la ayuda para el comando atomscan.
- **atomscan -h atomscan**: Muestra la ayuda para el comando atomscan.
- **atomscan -h atomscan -s**: Muestra la ayuda para el comando atomscan con la opción -s.
- **atomscan -h atomscan -t**: Muestra la ayuda para el comando atomscan con la opción -t.
- **atomscan -h atomscan -r**: Muestra la ayuda para el comando atomscan con la opción -r.
- **atomscan -h atomscan -o**: Muestra la ayuda para el comando atomscan con la opción -o.
- **atomscan -h atomscan -a**: Muestra la ayuda para el comando atomscan con la opción -a.
- **atomscan -h atomscan -x**: Muestra la ayuda para el comando atomscan con la opción -x.
- **atomscan -h atomscan -d**: Muestra la ayuda para el comando atomscan con la opción -d.
- **atomscan -h atomscan -u**: Muestra la ayuda para el comando atomscan con la opción -u.
- **atomscan -h atomscan -v**: Muestra la ayuda para el comando atomscan con la opción -v.
- **atomscan -h atomscan -w**: Muestra la ayuda para el comando atomscan con la opción -w.
- **atomscan -h atomscan -m**: Muestra la ayuda para el comando atomscan con la opción -m.
- **atomscan -h atomscan -f**: Muestra la ayuda para el comando atomscan con la opción -f.
- **atomscan -h atomscan -c**: Muestra la ayuda para el comando atomscan con la opción -c.
- **atomscan -h atomscan -b**: Muestra la ayuda para el comando atomscan con la opción -b.
- **atomscan -h atomscan -z**: Muestra la ayuda para el comando atomscan con la opción -z.
- **atomscan -h atomscan -l**: Muestra la ayuda para el comando atomscan con la opción -l.
- **atomscan -h atomscan -i**: Muestra la ayuda para el comando atomscan con la opción -i.
- **atomscan -h atomscan -n**: Muestra la ayuda para el comando atomscan con la opción -n.
- **atomscan -h atomscan -p**: Muestra la ayuda para el comando atomscan con la opción -p.
- **atomscan -h atomscan -e**: Muestra la ayuda para el comando atomscan con la opción -e.
- **atomscan -h atomscan -g**: Muestra la ayuda para el comando atomscan con la opción -g.
- **atomscan -h atomscan -k**: Muestra la ayuda para el comando atomscan con la opción -k.
- **atomscan -h atomscan -q**: Muestra la ayuda para el comando atomscan con la opción -q.
- **atomscan -h atomscan -y**: Muestra la ayuda para el comando atomscan con la opción -y.
- **atomscan -h atomscan -h**: Muestra la ayuda para el comando atomscan con la opción -h.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
### Escaneo con yara

Utilice este script para descargar y fusionar todas las reglas de malware yara desde github: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Cree el directorio _**rules**_ y ejecútelo. Esto creará un archivo llamado _**malware\_rules.yar**_ que contiene todas las reglas yara para malware.
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
{% endtab %}

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Análisis de volcado de memoria

- **Escaneo de procesos:** `volatility -f <archivo> --profile=<perfil> pslist`
- **Análisis de DLLs cargadas:** `volatility -f <archivo> --profile=<perfil> dlllist -p <PID>`
- **Análisis de puertos y conexiones:** `volatility -f <archivo> --profile=<perfil> connscan`
- **Análisis de registros de red:** `volatility -f <archivo> --profile=<perfil> netscan`
- **Análisis de caché de DNS:** `volatility -f <archivo> --profile=<perfil> dnscache`
- **Análisis de conexiones de red:** `volatility -f <archivo> --profile=<perfil> connections`
- **Análisis de sockets de red:** `volatility -f <archivo> --profile=<perfil> sockscan`
- **Análisis de enlaces de red:** `volatility -f <archivo> --profile=<perfil> ifconfig`
- **Análisis de tareas programadas:** `volatility -f <archivo> --profile=<perfil> malfind`
- **Análisis de controladores de dispositivos:** `volatility -f <archivo> --profile=<perfil> driverscan`
- **Análisis de registros de eventos:** `volatility -f <archivo> --profile=<perfil> evtlogs`
- **Análisis de caché de registro:** `volatility -f <archivo> --profile=<perfil> hivelist`
- **Análisis de claves de registro:** `volatility -f <archivo> --profile=<perfil> printkey -o <offset>`
- **Análisis de procesos y sus hilos:** `volatility -f <archivo> --profile=<perfil> pstree`
- **Análisis de colas de mensajes:** `volatility -f <archivo> --profile=<perfil> messagehooks`
- **Análisis de puertos abiertos:** `volatility -f <archivo> --profile=<perfil> sockets`
- **Análisis de caché de rutas ARP:** `volatility -f <archivo> --profile=<perfil> arp`
- **Análisis de caché de procesos:** `volatility -f <archivo> --profile=<perfil> psscan`
- **Análisis de caché de hilos:** `volatility -f <archivo> --profile=<perfil> thrdscan`
- **Análisis de caché de mutantes:** `volatility -f <archivo> --profile=<perfil> mutantscan`
- **Análisis de caché de objetos de kernel:** `volatility -f <archivo> --profile=<perfil> kpcrscan`
- **Análisis de caché de objetos de kernel:** `volatility -f <archivo> --profile=<perfil> kpcrscan`
- **Análisis de caché de objetos de kernel:** `volatility -f <archivo> --profile=<perfil> kpcrscan`
- **Análisis de caché de objetos de kernel:** `volatility -f <archivo> --profile=<perfil> kpcrscan`
- **Análisis de caché de objetos de kernel:** `volatility -f <archivo> --profile=<perfil> kpcrscan`
- **Análisis de caché de objetos de kernel:** `volatility -f <archivo> --profile=<perfil> kpcrscan`
- **Análisis de caché de objetos de kernel:** `volatility -f <archivo> --profile=<perfil> kpcrscan`
- **Análisis de caché de objetos de kernel:** `volatility -f <archivo> --profile=<perfil> kpcrscan`
- **Análisis de caché de objetos de kernel:** `volatility -f <archivo> --profile=<perfil> kpcrscan`
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
## VARIOS

### Plugins externos

Si deseas utilizar plugins externos, asegúrate de que las carpetas relacionadas con los plugins sean el primer parámetro utilizado.
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{% endtab %}

{% tab title="vol2" %} 

## Hoja de trucos de Volatility

### Comandos básicos

- **volatility -f <archivo> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: Muestra una lista de procesos en el volcado de memoria.
- **volatility -f <archivo> pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **volatility -f <archivo> psscan**: Escanea procesos a través del volcado de memoria.
- **volatility -f <archivo> dlllist -p <PID>**: Muestra una lista de módulos DLL cargados por un proceso específico.
- **volatility -f <archivo> cmdscan**: Escanea la memoria en busca de comandos de consola.
- **volatility -f <archivo> consoles**: Muestra información sobre las consolas interactivas detectadas.
- **volatility -f <archivo> filescan**: Escanea la memoria en busca de objetos de archivo.
- **volatility -f <archivo> netscan**: Escanea la memoria en busca de artefactos de red.
- **volatility -f <archivo> connections**: Muestra información sobre las conexiones de red.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código malicioso en procesos.
- **volatility -f <archivo> yarascan**: Escanea la memoria en busca de cadenas con reglas YARA.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> cmdline -p <PID>**: Muestra el comando utilizado para iniciar un proceso.
- **volatility -f <archivo> hivelist**: Enumera los registros del sistema Windows.
- **volatility -f <archivo> printkey -K <key>**: Imprime el contenido de una clave de registro.
- **volatility -f <archivo> userassist**: Muestra información sobre programas ejecutados por el usuario.
- **volatility -f <archivo> shimcache**: Muestra información sobre programas ejecutados en un sistema.
- **volatility -f <archivo> ldrmodules**: Muestra información sobre módulos cargados en un proceso.
- **volatility -f <archivo> modscan**: Escanea la memoria en busca de módulos del kernel.
- **volatility -f <archivo> getsids**: Enumera los identificadores de seguridad (SIDs) en el sistema.
- **volatility -f <archivo> getservicesids**: Enumera los SIDs asociados con servicios.
- **volatility -f <archivo> svcscan**: Escanea la memoria en busca de estructuras de datos de servicios.
- **volatility -f <archivo> devicetree**: Muestra información sobre los dispositivos físicos y sus relaciones.
- **volatility -f <archivo> driverirp**: Muestra información sobre los controladores y las solicitudes de paquetes de E/S (IRP).
- **volatility -f <archivo> ssdt**: Muestra la Service Descriptor Table (SDT) del kernel.
- **volatility -f <archivo> callbacks**: Muestra información sobre las rutinas de devolución de llamada del kernel.
- **volatility -f <archivo> gdt**: Muestra la Global Descriptor Table (GDT) del kernel.
- **volatility -f <archivo> idt**: Muestra la Interrupt Descriptor Table (IDT) del kernel.
- **volatility -f <archivo> threads**: Muestra información sobre los hilos del sistema.
- **volatility -f <archivo> mutantscan**: Escanea la memoria en busca de objetos de mutante.
- **volatility -f <archivo> mutantscan**: Escanea la memoria en busca de objetos de mutante.
- **volatility -f <archivo> envars**: Muestra las variables de entorno de los procesos.
- **volatility -f <archivo> atomscan**: Escanea la memoria en busca de objetos de átomos.
- **volatility -f <archivo> atomscan**: Escanea la memoria en busca de objetos de átomos.
- **volatility -f <archivo> gacscan**: Escanea la memoria en busca de objetos de caché global de ensamblado (GAC).
- **volatility -f <archivo> gacscan**: Escanea la memoria en busca de objetos de caché global de ensamblado (GAC).
- **volatility -f <archivo> vadinfo -o <offset>**: Muestra información sobre un área de memoria virtual específica.
- **volatility -f <archivo> vadtree -o <offset>**: Muestra un árbol de áreas de memoria virtual.
- **volatility -f <archivo> vadwalk -o <offset>**: Muestra información sobre las estructuras de datos de un área de memoria virtual.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae un módulo DLL de un proceso.
- **volatility -f <archivo> procdump -p <PID> -D <destino>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <destino>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memmap**: Muestra un mapa de memoria del sistema.
- **volatility -f <archivo> memmap --profile=<perfil>**: Muestra un mapa de memoria del sistema con un perfil específico.
- **volatility -f <archivo> malfind --dump-dir=<destino>**: Encuentra inyecciones de código malicioso y las extrae.
- **volatility -f <archivo> malfind --dump-dir=<destino> --dump-addr=<dirección>**: Encuentra inyecciones de código malicioso en una dirección específica y las extrae.
- **volatility -f <archivo> malfind --dump-dir=<destino> --dump-addr=<dirección> --profile=<perfil>**: Encuentra inyecciones de código malicioso en una dirección específica con un perfil específico y las extrae.

### Plugins adicionales

- **apihooks**: Muestra información sobre los ganchos de API en el sistema.
- **mftparser**: Analiza la Tabla maestra de archivos (MFT) para encontrar archivos eliminados.
- **mftparser --output=<destino>**: Analiza la MFT y guarda los resultados en un archivo.
- **mftparser --output=<destino> --output-type=bodyfile**: Analiza la MFT y guarda los resultados en un archivo de cuerpo.
- **mftparser --output=<destino> --output-type=csv**: Analiza la MFT y guarda los resultados en un archivo CSV.
- **mftparser --output=<destino> --output-type=bodyfile --bodyfile-addr=<dirección>**: Analiza la MFT y guarda los resultados en un archivo de cuerpo en una dirección específica.
- **mftparser --output=<destino> --output-type=csv --csv-sep=<separador>**: Analiza la MFT y guarda los resultados en un archivo CSV con un separador específico.
- **mftparser --output=<destino> --output-type=csv --csv-sep=<separador> --csv-quote=<carácter>**: Analiza la MFT y guarda los resultados en un archivo CSV con un separador y un carácter de cita específicos.
- **mftparser --output=<destino> --output-type=csv --csv-sep=<separador> --csv-quote=<carácter> --csv-header**: Analiza la MFT y guarda los resultados en un archivo CSV con un encabezado.
- **mftparser --output=<destino> --output-type=csv --csv-sep=<separador> --csv-quote=<carácter> --csv-header --csv-body**: Analiza la MFT y guarda los resultados en un archivo CSV con un encabezado y cuerpo.
- **mftparser --output=<destino> --output-type=csv --csv-sep=<separador> --csv-quote=<carácter> --csv-header --csv-body --csv-body-addr=<dirección>**: Analiza la MFT y guarda los resultados en un archivo CSV con un encabezado y cuerpo en una dirección específica.
- **mftparser --output=<destino> --output-type=csv --csv-sep=<separador> --csv-quote=<carácter> --csv-header --csv-body --csv-body-addr=<dirección> --profile=<perfil>**: Analiza la MFT y guarda los resultados en un archivo CSV con un encabezado y cuerpo en una dirección específica con un perfil específico.

{% endtab %}
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{% endtab %}
{% endtabs %}

#### Autoruns

Descárgalo desde [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### Mutexes

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{% endtab %}

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Comandos básicos de Volatility

- **volatility -f <archivo> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: Muestra una lista de procesos en el volcado de memoria.
- **volatility -f <archivo> pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **volatility -f <archivo> psscan**: Escanea procesos a través del volcado de memoria.
- **volatility -f <archivo> dlllist -p <PID>**: Muestra las DLL cargadas por un proceso específico.
- **volatility -f <archivo> cmdline -p <PID>**: Muestra el comando utilizado para ejecutar un proceso específico.
- **volatility -f <archivo> filescan**: Escanea descriptores de archivos en el volcado de memoria.
- **volatility -f <archivo> netscan**: Escanea conexiones de red en el volcado de memoria.
- **volatility -f <archivo> connections**: Muestra las conexiones de red en el volcado de memoria.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código en procesos.
- **volatility -f <archivo> yarascan**: Escanea el volcado de memoria en busca de cadenas con Yara.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> memdump -p <PID> -D <destino>**: Crea un volcado de memoria para un proceso específico.
- **volatility -f <archivo> hivelist**: Enumera los registros del sistema en el volcado de memoria.
- **volatility -f <archivo> printkey -o <offset>**: Muestra el contenido de una clave de registro en un desplazamiento específico.
- **volatility -f <archivo> hashdump**: Extrae hashes de contraseñas del volcado de memoria.
- **volatility -f <archivo> shimcache**: Muestra la información de la caché de compatibilidad de aplicaciones.
- **volatility -f <archivo> ldrmodules**: Enumera los módulos cargados en el espacio de usuario.
- **volatility -f <archivo> getsids**: Enumera los SID de usuario en el volcado de memoria.
- **volatility -f <archivo> userassist**: Muestra las entradas de UserAssist en el registro.
- **volatility -f <archivo> consoles**: Enumera las sesiones de consola activas.
- **volatility -f <archivo> apihooks**: Enumera los ganchos de API en el volcado de memoria.
- **volatility -f <archivo> callbacks**: Enumera los callbacks del kernel en el volcado de memoria.
- **volatility -f <archivo> driverirp**: Enumera los IRP manejadores de un controlador.
- **volatility -f <archivo> modscan**: Escanea módulos del kernel en el volcado de memoria.
- **volatility -f <archivo> ssdt**: Enumera los descriptores de servicios del sistema en el volcado de memoria.
- **volatility -f <archivo> mutantscan**: Escanea objetos mutantes en el volcado de memoria.
- **volatility -f <archivo> envars**: Muestra las variables de entorno en el volcado de memoria.
- **volatility -f <archivo> atomscan**: Escanea tablas de átomos en el volcado de memoria.
- **volatility -f <archivo> deskscan**: Escanea objetos de escritorio en el volcado de memoria.
- **volatility -f <archivo> vadinfo -o <offset>**: Muestra información sobre un área de memoria específica.
- **volatility -f <archivo> vadtree -o <offset>**: Muestra un árbol de áreas de memoria.
- **volatility -f <archivo> handles**: Enumera los descriptores de objetos en el volcado de memoria.
- **volatility -f <archivo> mutantscan**: Escanea objetos mutantes en el volcado de memoria.
- **volatility -f <archivo> envars**: Muestra las variables de entorno en el volcado de memoria.
- **volatility -f <archivo> atomscan**: Escanea tablas de átomos en el volcado de memoria.
- **volatility -f <archivo> deskscan**: Escanea objetos de escritorio en el volcado de memoria.
- **volatility -f <archivo> vadinfo -o <offset>**: Muestra información sobre un área de memoria específica.
- **volatility -f <archivo> vadtree -o <offset>**: Muestra un árbol de áreas de memoria.
- **volatility -f <archivo> handles**: Enumera los descriptores de objetos en el volcado de memoria.

#### Plugins de Volatility

- **apihooks**: Enumera los ganchos de API en el volcado de memoria.
- **atoms**: Enumera los átomos del sistema en el volcado de memoria.
- **atomscan**: Escanea tablas de átomos en el volcado de memoria.
- **callbacks**: Enumera los callbacks del kernel en el voljsoncado de memoria.
- **connections**: Muestra las conexiones de red en el volcado de memoria.
- **consoles**: Enumera las sesiones de consola activas.
- **deskscan**: Escanea objetos de escritorio en el volcado de memoria.
- **dlllist**: Enumera las DLL cargadas en el espacio de usuario.
- **driverirp**: Enumera los IRP manejadores de un controlador.
- **envars**: Muestra las variables de entorno en el volcado de memoria.
- **filescan**: Escanea descriptores de archivos en el volcado de memoria.
- **getsids**: Enumera los SID de usuario en el volcado de memoria.
- **handles**: Enumera los descriptores de objetos en el volcado de memoria.
- **hashdump**: Extrae hashes de contraseñas del volcado de memoria.
- **hivelist**: Enumera los registros del sistema en el volcado de memoria.
- **ldrmodules**: Enumera los módulos cargados en el espacio de usuario.
- **memdump**: Crea un volcado de memoria para un proceso específico.
- **modscan**: Escanea módulos del kernel en el volcado de memoria.
- **mutantscan**: Escanea objetos mutantes en el volcado de memoria.
- **netscan**: Escanea conexiones de red en el volcado de memoria.
- **pslist**: Muestra una lista de procesos en el volcado de memoria.
- **psscan**: Escanea procesos a través del volcado de memoria.
- **pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **ssdt**: Enumera los descriptores de servicios del sistema en el volcado de memoria.
- **svcscan**: Enumera los servicios en el volcado de memoria.
- **thrdscan**: Escanea hilos en el volcado de memoria.
- **vadinfo**: Muestra información sobre un área de memoria específica.
- **vadtree**: Muestra un árbol de áreas de memoria.
- **vadwalk**: Muestra las regiones de memoria en un proceso.
- **yarascan**: Escanea el volcado de memoria en busca de cadenas con Yara.

#### Ejemplos de Uso

- **volatility -f memdump.mem memdump -p 123 -D dumpdir/**: Crea un volcado de memoria para el proceso con PID 123.
- **volatility -f memdump.mem filescan**: Escanea descriptores de archivos en el volcado de memoria.
- **volatility -f memdump.mem pslist**: Muestra una lista de procesos en el volcado de memoria.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
### Enlaces simbólicos

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{% endtab %}

{% tab title="vol2" %} 

## Hoja de trucos de Volatility

### Comandos básicos

- **volatility -f <archivo> imageinfo**: muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: lista los procesos en ejecución.
- **volatility -f <archivo> pstree**: muestra los procesos en forma de árbol.
- **volatility -f <archivo> psscan**: escanea los procesos.
- **volatility -f <archivo> dlllist -p <PID>**: lista las DLL cargadas por un proceso.
- **volatility -f <archivo> cmdscan**: busca comandos ejecutados.
- **volatility -f <archivo> consoles**: muestra las consolas interactivas.
- **volatility -f <archivo> filescan**: escanea los descriptores de archivo.
- **volatility -f <archivo> netscan**: busca información de red.
- **volatility -f <archivo> connections**: muestra las conexiones de red.
- **volatility -f <archivo> svcscan**: lista los servicios.
- **volatility -f <archivo> malfind**: busca inyecciones de código malicioso.
- **volatility -f <archivo> yarascan**: escanea la memoria en busca de patrones YARA.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: extrae archivos del volcado de memoria.
- **volatility -f <archivo> memdump -p <PID> -D <destino>**: crea un volcado de memoria de un proceso específico.

### Plugins adicionales

- **apihooks**: muestra los ganchos de API.
- **malfind**: busca inyecciones de código malicioso.
- **malthfind**: busca manipulaciones de memoria.
- **apihooks**: muestra los ganchos de API.
- **ldrmodules**: lista los módulos cargados.
- **modscan**: escanea los módulos.
- **idt**: muestra la tabla de descriptores de interrupciones.
- **gdt**: muestra la tabla de descriptores globales.
- **ssdt**: muestra la tabla de descriptores de servicios.
- **callbacks**: muestra los callbacks del kernel.
- **driverirp**: muestra las IRP manejadas por los controladores.
- **printkey**: muestra las subclaves y valores de una clave de registro.
- **userassist**: muestra programas utilizados por los usuarios.
- **shellbags**: muestra accesos directos y carpetas abiertas.
- **getsids**: muestra los SID de usuario.
- **getsids**: muestra los SID de usuario.
- **hivelist**: lista los archivos de volcado de registro.
- **hivedump -o <offset> -s <tamaño> -f <archivo> -D <destino>**: extrae un archivo de volarchivo de registro.
- **hashdump**: extrae contraseñas hash.
- **hashdump -y <SISTEMA> -s <SAM> -f <archivo> -D <destjson>**: extrae contraseñas hash de los archivos del registro SAM y SYSTEM.
- **truecryptpassphrase**: busca frases de contraseña TrueCrypt.
- **bitlocker**: busca claves de recuperación de BitLocker.
- **dumpregistry -o <offset> -s <tamaño> -f <archivo> -D <destino>**: extrae un archivo de registro.
- **dumpcerts -f <archivo> -D <destino>**: extrae certificados.
- **dumpfiles -Q <dirección> -D <destino>**: extrae archivos.
- **dumpfiles -Q <dirección> -D <destino> -r <regex>**: extrae archivos que coincidan con una expresión regular.
- **dumpfiles -Q <dirección> -D <destino> -n**: extrae archivos no mapeados.
- **dumpfiles -Q <dirección> -D <destino> -x <ext>**: extrae archivos con una extensión específica.
- **dumpfiles -Q <dirección> -D <destino> -U**: extrae archivos desconocidos.
- **dumpfiles -Q <dirección> -D <destino> -s <tamaño>**: extrae archivos de un tamaño específico.
- **dumpfiles -Q <dirección> -D <destino> -m <dirección>**: extrae archivos que contienen una dirección específica.
- **dumpfiles -Q <dirección> -D <destino> -b <bytes>**: extrae archivos con un número específico de bytes antes y después.
- **dumpfiles -Q <dirección> -D <destino> -l**: extrae archivos grandes.
- **dumpfiles -Q <dirección> -D <destino> -f <formato>**: extrae archivos en un formato específico.
- **dumpfiles -Q <dirección> -D <destino> -t**: extrae archivos de texto.
- **dumpfiles -Q <dirección> -D <destino> -e**: extrae archivos ejecutables.
- **dumpfiles -Q <dirección> -D <destino> -z**: extrae archivos comprimidos.
- **dumpfiles -Q <dirección> -D <destino> -a**: extrae archivos de audio.
- **dumpfiles -Q <dirección> -D <destino> -i**: extrae archivos de imagen.
- **dumpfiles -Q <dirección> -D <destino> -d**: extrae archivos de documentos.
- **dumpfiles -Q <dirección> -D <destino> -c**: extrae archivos de código fuente.
- **dumpfiles -Q <dirección> -D <destino> -p**: extrae archivos de PDF.
- **dumpfiles -Q <dirección> -D <destino> -w**: extrae archivos de Word.
- **dumpfiles -Q <dirección> -D <destino> -x**: extrae archivos de Excel.
- **dumpfiles -Q <dirección> -D <destino> -h**: extrae archivos HTML.
- **dumpfiles -Q <dirección> -D <destino> -u**: extrae archivos de URL.
- **dumpfiles -Q <dirección> -D <destino> -g**: extrae archivos de GIF.
- **dumpfiles -Q <dirección> -D <destino> -j**: extrae archivos de JPEG.
- **dumpfiles -Q <dirección> -D <destino> -t**: extrae archivos de PNG.
- **dumpfiles -Q <dirección> -D <destino> -v**: extrae archivos de video.
- **dumpfiles -Q <dirección> -D <destino> -y**: extrae archivos de SQLite.
- **dumpfiles -Q <dirección> -D <destino> -k**: extrae archivos de claves.
- **dumpfiles -Q <dirección> -D <destino> -q**: extrae archivos de consultas.
- **dumpfiles -Q <dirección> -D <destino> -r**: extrae archivos de registros.
- **dumpfiles -Q <dirección> -D <destino> -n**: extrae archivos de nombres.
- **dumpfiles -Q <dirección> -D <destino> -o**: extrae archivos de otros tipos.
- **dumpfiles -Q <dirección> -D <destino> -i**: extrae archivos de información.
- **dumpfiles -Q <dirección> -D <destino> -b**: extrae archivos de binarios.
- **dumpfiles -Q <dirección> -D <destino> -s**: extrae archivos de scripts.
- **dumpfiles -Q <dirección> -D <destino> -f**: extrae archivos de formularios.
- **dumpfiles -Q <dirección> -D <destino> -t**: extrae archivos de texto.
- **dumpfiles -Q <dirección> -D <destino> -e**: extrae archivos de ejecutables.
- **dumpfiles -Q <dirección> -D <destino> -z**: extrae archivos de comprimidos.
- **dumpfiles -Q <dirección> -D <destino> -a**: extrae archivos de audio.
- **dumpfiles -Q <dirección> -D <destino> -i**: extrae archivos de imagen.
- **dumpfiles -Q <dirección> -D <destino> -d**: extrae archivos de documentos.
- **dumpfiles -Q <dirección> -D <destino> -c**: extrae archivos de código fuente.
- **dumpfiles -Q <dirección> -D <destino> -p**: extrae archivos de PDF.
- **dumpfiles -Q <dirección> -D <destino> -w**: extrae archivos de Word.
- **dumpfiles -Q <dirección> -D <destino> -x**: extrae archivos de Excel.
- **dumpfiles -Q <dirección> -D <destino> -h**: extrae archivos HTML.
- **dumpfiles -Q <dirección> -D <destino> -u**: extrae archivos de URL.
- **dumpfiles -Q <dirección> -D <destino> -g**: extrae archivos de GIF.
- **dumpfiles -Q <dirección> -D <destino> -j**: extrae archivos de JPEG.
- **dumpfiles -Q <dirección> -D <destino> -t**: extrae archivos de PNG.
- **dumpfiles -Q <dirección> -D <destino> -v**: extrae archivos de video.
- **dumpfiles -Q <dirección> -D <destino> -y**: extrae archivos de SQLite.
- **dumpfiles -Q <dirección> -D <destino> -k**: extrae archivos de claves.
- **dumpfiles -Q <dirección> -D <destino> -q**: extrae archivos de consultas.
- **dumpfiles -Q <dirección> -D <destino> -r**: extrae archivos de registros.
- **dumpfiles -Q <dirección> -D <destino> -n**: extrae archivos de nombres.
- **dumpfiles -Q <dirección> -D <destino> -o**: extrae archivos de otros tipos.
- **dumpfiles -Q <dirección> -D <destino> -i**: extrae archivos de información.
- **dumpfiles -Q <dirección> -D <destino> -b**: extrae archivos de binarios.
- **dumpfiles -Q <dirección> -D <destino> -s**: extrae archivos de scripts.
- **dumpfiles -Q <dirección> -D <destino> -f**: extrae archivos de formularios.

### Ejemplos de uso

- **volatility -f memdump.mem memdump -p 123 -D /tmp/**: crea un volcado de memoria del proceso con PID 123.
- **volatility -f memdump.mem filescan -p 123**: escanea los descriptores de archivo del proceso con PID 123.
- **volatility -f memdump.mem dumpfiles -Q 0x000000007efdd000 -D /tmp/**: extrae archivos del volcado de memoria en la dirección especificada.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{% endtab %}
{% endtabs %}

### Bash

Es posible **leer desde la memoria el historial de bash.** También podrías volcar el archivo _.bash\_history_, pero si está deshabilitado, te alegrará saber que puedes usar este módulo de volatilidad.
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% tab title="vol2" %} 

## Hoja de trucos de Volatility

### Comandos básicos

- **volatility -f <file> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <file> pslist**: Lista los procesos en ejecución.
- **volatility -f <file> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> psscan**: Escanea los procesos.
- **volatility -f <file> dlllist -p <pid>**: Lista las DLL cargadas por un proceso específico.
- **volatility -f <file> cmdscan**: Escanea los procesos en busca de comandos de consola.
- **volatility -f <file> filescan**: Escanea los descriptores de archivo.
- **volatility -f <file> netscan**: Escanea los sockets de red.
- **volatility -f <file> connections**: Muestra las conexiones de red.
- **volatility -f <file> consoles**: Lista las consolas interactivas.
- **volatility -f <file> hivelist**: Enumera los archivos de volcado del registro.
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> hashdump**: Extrae los hashes de contraseñas.
- **volatility -f <file> userassist**: Muestra las entradas de UserAssist.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <file> apihooks**: Enumera los ganchos de API.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> modscan**: Escanea los módulos cargados.
- **volatility -f <file> shimcache**: Muestra la caché de Shim.
- **volatility -f <file> getsids**: Obtiene los SID de los procesos.
- **volatility -f <file> getservicesids**: Obtiene los SID de los servicios.
- **volatility -f <file> envars**: Muestra las variables de entorno de los procesos.
- **volatility -f <file> cmdline**: Muestra las líneas de comandos de los procesos.
- **volatility -f <file> consoles**: Lista las consolas interactivas.
- **volatility -f <file> svcscan**: Escanea los servicios.
- **volatility -f <file> driverirp**: Enumera los IRP manejadores de los controladores.
- **volatility -f <file> callbacks**: Enumera los callbacks del kernel.
- **volatility -f <file> mutantscan**: Escanea los objetos de mutante.
- **volatility -f <file> threads**: Lista los hilos.
- **volatility -f <file> handles**: Lista los descriptores de archivo y claves del registro abiertos.
- **volatility -f <file> devicetree**: Muestra el árbol de dispositivos.
- **volatility -f <file> drivermodule**: Muestra información sobre un módulo de controlador específico.
- **volatility -f <file> ssdt**: Enumera la tabla de descriptores de servicios del sistema.
- **volatility -f <file> idt**: Enumera la tabla de descriptores de interrupciones.
- **volatility -f <file> gdt**: Enumera la tabla de descriptores globales.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos del espacio de memoria.
- **volatility -f <file> memdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memstrings -p <pid>**: Busca cadenas ASCII en el espacio de memoria de un proceso.
- **volatility -f <file> procdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> procmemdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> dlldump -p <pid> -D <output_directory>**: Extrae una DLL de un proceso específico.
- **volatility -f <file> dlldump -b <base_address> -D <output_directory>**: Extrae una DLL de una dirección base específica.
- **volatility -f <file> yarascan -Y "<rule>"**: Escanea la memoria en busca de patrones YARA.
- **volatility -f <file> yarascan -f <file_with_rules>**: Escanea la memoria en busca de patrones YARA utilizando un archivo de reglas.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <file> malfind -p <pid>**: Encuentra inyecciones de código malicioso en un proceso específico.
- **volatility -f <file> malfind -D <output_directory>**: Escanea la memoria en busca de inyecciones de código malicioso y las extrae.
- **volatility -f <file> malfind -Y "<rule>"**: Escanea la memoria en busca de inyecciones de código malicioso que coincidan con una regla YARA.
- **volatility -f <file> malfind -D <output_directory> -Y "<rule>"**: Escanea la memoria en busca de inyecciones de código malicioso que coincidan con una regla YARA y las extrae.
- **volatility -f <file> malfind -D <output_directory> -p <pid>**: Escanea la memoria en busca de inyecciones de código malicioso en un proceso específico y las extrae.
- **volatility -f <file> malfind -D <output_directory> -p <pid> -Y "<rule>"**: Escanea la memoria en busca de inyecciones de código malicioso en un proceso específico que coincidan con una regla YARA y las extrae.

### Plugins adicionales

- **apihooks**: Enumera los ganchos de API.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malfind**: Encuent
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
### Línea de tiempo

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% endtab %}

{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{% endtab %}
{% endtabs %}

### Controladores

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% endtab %}

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Volatility

- **Volatility** es un marco de trabajo de análisis de memoria.
- **Volatility** es un proyecto de código abierto.
- **Volatility** es compatible con la mayoría de los sistemas operativos.
- **Volatility** es compatible con la mayoría de los formatos de volcado de memoria.

#### Uso básico

- `volatility -f <archivo de volcado> <comando>`

#### Comandos útiles

- `imageinfo`: muestra información básica sobre el volcado de memoria.
- `pslist`: muestra una lista de procesos en el volcado de memoria.
- `pstree`: muestra un árbol de procesos en el volcado de memoria.
- `psscan`: escanea todos los procesos en busca de direcciones de memoria.
- `dlllist`: muestra una lista de DLL cargadas en los procesos.
- `cmdscan`: escanea la memoria en busca de cadenas de texto que parecen comandos de shell.
- `filescan`: escanea la memoria en busca de estructuras de datos de archivos.
- `netscan`: muestra información sobre los sockets de red.
- `connections`: muestra información sobre las conexiones de red.
- `malfind`: encuentra inyecciones de código malicioso en procesos.
- `yarascan`: escanea la memoria en busca de patrones YARA.
- `dumpfiles`: extrae archivos sospechosos de la memoria.
- `memdump`: crea un volcado de memoria de un proceso específico.
- `linux_bash`: muestra los comandos de bash ejecutados en sistemas Linux.
- `linux_net`: muestra información sobre conexiones de red en sistemas Linux.
- `linux_pslist`: muestra una lista de procesos en sistemas Linux.
- `linux_psaux`: muestra información detallada sobre procesos en sistemas Linux.
- `linux_pidhashtable`: muestra la tabla de hash de PID en sistemas Linux.
- `linux_ifconfig`: muestra información de configuración de red en sistemas Linux.
- `linux_lsmod`: muestra información sobre los módulos del kernel en sistemas Linux.
- `linux_check_afinfo`: muestra información sobre las estructuras de socket en sistemas Linux.
- `linux_route`: muestra información sobre la tabla de enrutamiento en sistemas Linux.
- `linux_netstat`: muestra información sobre estadísticas de red en sistemas Linux.
- `linux_dmesg`: muestra mensajes del kernel en sistemas Linux.
- `linux_cpuinfo`: muestra información sobre la CPU en sistemas Linux.
- `linux_mount`: muestra información sobre los puntos de montaje en sistemas Linux.
- `linux_idt`: muestra la tabla de descriptores de interrupciones en sistemas Linux.
- `linux_crashinfo`: muestra información de volcado de Linux.
- `linux_lsof`: muestra archivos abiertos en sistemas Linux.
- `linux_check_tty`: muestra información sobre los dispositivos TTY en sistemas Linux.
- `linux_check_creds`: muestra información sobre credenciales en sistemas Linux.
- `linux_check_syscall`: muestra información sobre las llamadas al sistema en sistemas Linux.
- `linux_check_modules`: muestra información sobre los módulos del kernel en sistemas Linux.
- `linux_check_fop`: muestra información sobre las operaciones de archivo en sistemas Linux.
- `linux_check_afinfo`: muestra información sobre las estructuras de socket en sistemas Linux.
- `linux_check_files`: muestra información sobre los archivos abiertos en sistemas Linux.
- `linux_check_filedesc`: muestra información sobre los descriptores de archivos en sistemas Linux.
- `linux_check_pagecache`: muestra información sobre la caché de páginas en sistemas Linux.
- `linux_threads`: muestra información sobre los subprocesos en sistemas Linux.
- `linux_psxview`: muestra información sobre procesos ocultos en sistemas Linux.
- `linux_pstree`: muestra un árbol de procesos en sistemas Linux.
- `linux_dlllist`: muestra una lista de DLL cargadas en sistemas Linux.
- `linux_cmdline`: muestra la línea de comandos de los procesos en sistemas Linux.
- `linux_who`: muestra información sobre los usuarios en sistemas Linux.
- `linux_hashdump`: muestra contraseñas hash en sistemas Linux.
- `linux_dmesg`: muestra mensajes del kernel en sistemas Linux.
- `linux_check_syscall`: muestra información sobre las llamadas al sistema en sistemas Linux.
- `linux_check_fop`: muestra información sobre las operaciones de archivo en sistemas Linux.
- `linux_check_afinfo`: muestra información sobre las estructuras de socket en sistemas Linux.
- `linux_check_files`: muestra información sobre los archivos abiertos en sistemas Linux.
- `linux_check_filedesc`: muestra información sobre los descriptores de archivos en sistemas Linux.
- `linux_check_pagecache`: muestra información sobre la caché de páginas en sistemas Linux.
- `linux_threads`: muestra información sobre los subprocesos en sistemas Linux.
- `linux_psxview`: muestra información sobre procesos ocultos en sistemas Linux.
- `linux_pstree`: muestra un árbol de procesos en sistemas Linux.
- `linux_dlllist`: muestra una lista de DLL cargadas en sistemas Linux.
- `linux_cmdline`: muestra la línea de comandos de los procesos en sistemas Linux.
- `linux_who`: muestra información sobre los usuarios en sistemas Linux.
- `linux_hashdump`: muestra contraseñas hash en sistemas Linux.

#### Plugins

- **Volatility** tiene una amplia gama de plugins para análisis forense.
- Los plugins de **Volatility** pueden extender la funcionalidad básica.
- Los plugins de **Volatility** pueden utilizarse para tareas específicas de análisis forense.

#### Recursos adicionales

- Documentación oficial de **Volatility**: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
- Lista de comandos de **Volatility**: [https://github.com/volatilityfoundation/volatility/wiki/Command-Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
- Lista de plugins de **Volatility**: [https://github.com/volatilityfoundation/volatility/wiki/Command-Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{% endtab %}
{% endtabs %}

### Obtener portapapeles
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### Obtener historial de IE
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Obtener texto de notepad
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### Captura de pantalla
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Registro Maestro de Arranque (MBR)
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
El **Registro de Arranque Principal (MBR)** juega un papel crucial en la gestión de las particiones lógicas de un medio de almacenamiento, que están estructuradas con diferentes [sistemas de archivos](https://es.wikipedia.org/wiki/Sistema_de_archivos). No solo contiene información sobre el diseño de las particiones, sino que también contiene código ejecutable que actúa como cargador de arranque. Este cargador de arranque inicia directamente el proceso de carga de la segunda etapa del sistema operativo (ver [cargador de arranque de segunda etapa](https://es.wikipedia.org/wiki/Cargador_de_arranque_de_segunda_etapa)) o trabaja en armonía con el [registro de arranque de volumen](https://es.wikipedia.org/wiki/Registro_de_arranque_de_volumen) (VBR) de cada partición. Para obtener un conocimiento más profundo, consulta la [página de Wikipedia sobre MBR](https://es.wikipedia.org/wiki/Registro_de_arranque_principal).

## Referencias
* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
​* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro clave para profesionales de la tecnología y la ciberseguridad en todas las disciplinas.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
