# Volatility - Hoja de trucos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro hirviente para los profesionales de la tecnología y la ciberseguridad en todas las disciplinas.

{% embed url="https://www.rootedcon.com/" %}

Si quieres algo **rápido y loco** que lance varios plugins de Volatility en paralelo, puedes usar: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
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

#### Comandos básicos

- `volatility2 -f <archivo_memoria> imageinfo`: muestra información sobre la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> <comando>`: ejecuta un comando en la imagen de memoria con el perfil especificado.
- `volatility2 -f <archivo_memoria> --profile=<perfil> pslist`: muestra una lista de procesos en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> pstree`: muestra un árbol de procesos en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> psscan`: muestra una lista de procesos en la imagen de memoria, incluyendo procesos ocultos.
- `volatility2 -f <archivo_memoria> --profile=<perfil> netscan`: muestra una lista de conexiones de red en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> connscan`: muestra una lista de conexiones de red en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> filescan`: muestra una lista de archivos abiertos en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> dlllist`: muestra una lista de DLL cargadas en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> handles`: muestra una lista de handles abiertos en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> getsids`: muestra una lista de SIDs en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> hivelist`: muestra una lista de archivos de registro en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> printkey`: muestra el contenido de una clave de registro en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> dumpregistry`: extrae un archivo de registro de la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> malfind`: busca malware en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> apihooks`: muestra una lista de ganchos de API en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> idt`: muestra la tabla de descriptores de interrupción en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> gdt`: muestra la tabla de descriptores globales en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> ldrmodules`: muestra una lista de módulos cargados en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> modscan`: muestra una lista de módulos cargados en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> svcscan`: muestra una lista de servicios en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> printkey`: muestra el contenido de una clave de registro en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> dumpregistry`: extrae un archivo de registro de la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> malfind`: busca malware en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> apihooks`: muestra una lista de ganchos de API en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> idt`: muestra la tabla de descriptores de interrupción en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> gdt`: muestra la tabla de descriptores globales en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> ldrmodules`: muestra una lista de módulos cargados en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> modscan`: muestra una lista de módulos cargados en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> svcscan`: muestra una lista de servicios en la imagen de memoria.

#### Análisis de procesos

- `volatility2 -f <archivo_memoria> --profile=<perfil> pslist`: muestra una lista de procesos en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> pstree`: muestra un árbol de procesos en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> psscan`: muestra una lista de procesos en la imagen de memoria, incluyendo procesos ocultos.
- `volatility2 -f <archivo_memoria> --profile=<perfil> cmdline`: muestra el comando utilizado para ejecutar un proceso en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> consoles`: muestra una lista de consolas asociadas a procesos en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> dlllist`: muestra una lista de DLL cargadas en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> handles`: muestra una lista de handles abiertos en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> memdump`: extrae el espacio de memoria de un proceso en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> memmap`: muestra un mapa de memoria de un proceso en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> vadinfo`: muestra información sobre los VADs (áreas de asignación de memoria) de un proceso en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> vadtree`: muestra un árbol de los VADs de un proceso en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> vadwalk`: muestra una lista de los VADs de un proceso en la imagen de memoria.

#### Análisis de red

- `volatility2 -f <archivo_memoria> --profile=<perfil> netscan`: muestra una lista de conexiones de red en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> connscan`: muestra una lista de conexiones de red en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> sockets`: muestra una lista de sockets en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> sockscan`: muestra una lista de sockets en la imagen de memoria.

#### Análisis de archivos

- `volatility2 -f <archivo_memoria> --profile=<perfil> filescan`: muestra una lista de archivos abiertos en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> dumpfiles`: extrae un archivo de la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> handles`: muestra una lista de handles abiertos en la imagen de memoria.

#### Análisis de registro

- `volatility2 -f <archivo_memoria> --profile=<perfil> hivelist`: muestra una lista de archivos de registro en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> printkey`: muestra el contenido de una clave de registro en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> dumpregistry`: extrae un archivo de registro de la imagen de memoria.

#### Análisis de malware

- `volatility2 -f <archivo_memoria> --profile=<perfil> malfind`: busca malware en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> apihooks`: muestra una lista de ganchos de API en la imagen de memoria.

#### Análisis de kernel

- `volatility2 -f <archivo_memoria> --profile=<perfil> idt`: muestra la tabla de descriptores de interrupción en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> gdt`: muestra la tabla de descriptores globales en la imagen de memoria.

#### Análisis de módulos

- `volatility2 -f <archivo_memoria> --profile=<perfil> ldrmodules`: muestra una lista de módulos cargados en la imagen de memoria.
- `volatility2 -f <archivo_memoria> --profile=<perfil> modscan`: muestra una lista de módulos cargados en la imagen de memoria.

#### Análisis de servicios

- `volatility2 -f <archivo_memoria> --profile=<perfil> svcscan`: muestra una lista de servicios en la imagen de memoria.

{% endtab %}
{% endtabs %}
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

Acceda a la documentación oficial en [Referencia de comandos de Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### Una nota sobre los plugins "list" vs "scan"

Volatility tiene dos enfoques principales para los plugins, que a veces se reflejan en sus nombres. Los plugins "list" intentarán navegar a través de las estructuras del kernel de Windows para recuperar información como procesos (ubicar y recorrer la lista vinculada de estructuras `_EPROCESS` en la memoria), manejadores del sistema operativo (ubicar y listar la tabla de manejadores, desreferenciando cualquier puntero encontrado, etc.). Se comportan más o menos como lo haría la API de Windows si se solicita, por ejemplo, listar procesos.

Eso hace que los plugins "list" sean bastante rápidos, pero igual de vulnerables que la API de Windows a la manipulación por parte de malware. Por ejemplo, si el malware utiliza DKOM para desvincular un proceso de la lista vinculada `_EPROCESS`, no aparecerá en el Administrador de tareas ni en la lista de procesos.

Los plugins "scan", por otro lado, tomarán un enfoque similar al tallado de la memoria para cosas que podrían tener sentido cuando se desreferencian como estructuras específicas. `psscan`, por ejemplo, leerá la memoria e intentará hacer objetos `_EPROCESS` de ella (utiliza el escaneo de etiquetas de grupo, que busca cadenas de 4 bytes que indiquen la presencia de una estructura de interés). La ventaja es que puede desenterrar procesos que han salido, e incluso si el malware manipula la lista vinculada `_EPROCESS`, el plugin seguirá encontrando la estructura en la memoria (ya que aún necesita existir para que el proceso se ejecute). La desventaja es que los plugins "scan" son un poco más lentos que los plugins "list" y a veces pueden dar falsos positivos (un proceso que salió hace demasiado tiempo y tuvo partes de su estructura sobrescritas por otras operaciones).

De: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## Perfiles de SO

### Volatility3

Como se explica en el archivo readme, debe colocar la **tabla de símbolos del SO** que desea admitir dentro de _volatility3/volatility/symbols_.\
Los paquetes de tabla de símbolos para los diversos sistemas operativos están disponibles para **descarga** en:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Perfil externo

Puede obtener la lista de perfiles admitidos haciendo:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Si deseas utilizar un **nuevo perfil que has descargado** (por ejemplo, uno de Linux), debes crear en algún lugar la siguiente estructura de carpetas: _plugins/overlays/linux_ y colocar dentro de esta carpeta el archivo zip que contiene el perfil. Luego, obtén el número de perfiles usando:
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

A diferencia de imageinfo, que simplemente proporciona sugerencias de perfil, **kdbgscan** está diseñado para identificar positivamente el perfil correcto y la dirección KDBG correcta (si hay varias). Este complemento escanea las firmas de KDBGHeader vinculadas a los perfiles de Volatility y aplica comprobaciones de integridad para reducir los falsos positivos. La verbosidad de la salida y el número de comprobaciones de integridad que se pueden realizar dependen de si Volatility puede encontrar un DTB, por lo que si ya conoce el perfil correcto (o si tiene una sugerencia de perfil de imageinfo), asegúrese de usarlo (de [aquí](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)).

Siempre eche un vistazo al **número de procesos que kdbgscan ha encontrado**. A veces, imageinfo y kdbgscan pueden encontrar **más de un perfil adecuado**, pero solo el **válido tendrá algo relacionado con procesos** (esto se debe a que se necesita la dirección KDBG correcta para extraer procesos).
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

El **bloque del depurador del kernel** (llamado KdDebuggerDataBlock del tipo \_KDDEBUGGER\_DATA64, o **KDBG** por Volatility) es importante para muchas cosas que Volatility y los depuradores hacen. Por ejemplo, tiene una referencia a PsActiveProcessHead que es la cabeza de lista de todos los procesos necesarios para la lista de procesos.

## Información del sistema operativo
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
El plugin `banners.Banners` puede ser utilizado en **vol3 para intentar encontrar banners de linux** en el volcado.

## Hashes/Contraseñas

Extraer hashes SAM, credenciales en caché del dominio y secretos de LSA.
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
volatility -f <memory_dump> filescan
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
volatility -f <memory_dump> malfind
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> ldrmodules
volatility -f <memory_dump> modscan
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> handles
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> ssdt
volatility -f <memory_dump> driverscan
volatility -f <memory_dump> fileinfo -F <file_path>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
volatility -f <memory_dump> memdump -b <start_address> -e <end_address> -D <output_directory>
volatility -f <memory_dump> memdump -o <offset> -s <size> -D <output_directory>
```

### Advanced Commands

```bash
volatility -f <memory_dump> --profile=<profile> <plugin> <plugin_options>
```

### Plugins

#### Malware Analysis

```bash
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malfind -Y <malware_directory>
volatility -f <memory_dump> malfind -D <output_directory>
volatility -f <memory_dump> malfind -p <pid>
volatility -f <memory_dump> malfind -u
volatility -f <memory_dump> malfind -U
volatility -f <memory_dump> malfind -Y <malware_directory> -D <output_directory>
volatility -f <memory_dump> malfind -Y <malware_directory> -p <pid>
volatility -f <memory_dump> malfind -Y <malware_directory> -u
volatility -f <memory_dump> malfind -Y <malware_directory> -U
volatility -f <memory_dump> malfind -D <output_directory> -p <pid>
volatility -f <memory_dump> malfind -D <output_directory> -u
volatility -f <memory_dump> malfind -D <output_directory> -U
volatility -f <memory_dump> malfind -p <pid> -u
volatility -f <memory_dump> malfind -p <pid> -U
volatility -f <memory_dump> malfind -u -U
volatility -f <memory_dump> malfind -Y <malware_directory> -D <output_directory> -p <pid>
volatility -f <memory_dump> malfind -Y <malware_directory> -D <output_directory> -u
volatility -f <memory_dump> malfind -Y <malware_directory> -D <output_directory> -U
volatility -f <memory_dump> malfind -Y <malware_directory> -p <pid> -u
volatility -f <memory_dump> malfind -Y <malware_directory> -p <pid> -U
volatility -f <memory_dump> malfind -Y <malware_directory> -u -U
```

#### Registry Analysis

```bash
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
```

#### File Analysis

```bash
volatility -f <memory_dump> filescan
volatility -f <memory_dump> filescan -S <string>
volatility -f <memory_dump> filescan -F <file_path>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> -n
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> -u
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> -U
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> -n -u
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> -n -U
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> -u -U
```

#### Process Analysis

```bash
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> handles
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
volatility -f <memory_dump> modscan
volatility -f <memory_dump> ldrmodules
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
```

#### Memory Analysis

```bash
volatility -f <memory_dump> memdump -b <start_address> -e <end_address> -D <output_directory>
volatility -f <memory_dump> memdump -o <offset> -s <size> -D <output_directory>
```

#### Kernel Analysis

```bash
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> ssdt
volatility -f <memory_dump> driverscan
```

## Volatility Profiles

### Linux

```bash
volatility --info | grep Linux
```

### Windows

```bash
volatility --info | grep Win
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
{% endtab %}
{% endtabs %}

## Volcado de memoria

El volcado de memoria de un proceso **extraerá todo** el estado actual del proceso. El módulo **procdump** solo **extraerá** el **código**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro para profesionales de la tecnología y la ciberseguridad en todas las disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## Procesos

### Listar procesos

Trate de encontrar procesos **sospechosos** (por nombre) o **inesperados** procesos secundarios (por ejemplo, un cmd.exe como proceso secundario de iexplorer.exe).\
Podría ser interesante **comparar** el resultado de pslist con el de psscan para identificar procesos ocultos.
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endtab %}

{% tab title="volatility-cheatsheet" %}
# Volatility Cheatsheet

## Basic Commands

### Image Identification

```bash
volatility -f <image> imageinfo
```

### Profile Identification

```bash
volatility -f <image> imageinfo | grep Profile
```

### Process List

```bash
volatility -f <image> --profile=<profile> pslist
```

### Process Tree

```bash
volatility -f <image> --profile=<profile> pstree
```

### DLL List

```bash
volatility -f <image> --profile=<profile> dlllist
```

### Handles

```bash
volatility -f <image> --profile=<profile> handles
```

### Network Connections

```bash
volatility -f <image> --profile=<profile> netscan
```

### Open Files

```bash
volatility -f <image> --profile=<profile> filescan
```

### Registry Analysis

```bash
volatility -f <image> --profile=<profile> hivelist
volatility -f <image> --profile=<profile> printkey -K <offset>
volatility -f <image> --profile=<profile> printkey -o <offset>
volatility -f <image> --profile=<profile> printval -K <offset>
volatility -f <image> --profile=<profile> printval -o <offset>
```

### Dumping Processes

```bash
volatility -f <image> --profile=<profile> procdump -p <pid> -D <output_directory>
```

### Dumping Files

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <string> -D <output_directory>
```

### Strings

```bash
volatility -f <image> --profile=<profile> strings -s <address> -e <address>
```

### Malware Analysis

```bash
volatility -f <image> --profile=<profile> malfind
volatility -f <image> --profile=<profile> malfind -Y <output_directory>
volatility -f <image> --profile=<profile> malfind -D <output_directory>
volatility -f <image> --profile=<profile> malfind -p <pid> -D <output_directory>
```

## Advanced Commands

### Finding Hidden Processes

```bash
volatility -f <image> --profile=<profile> psxview
```

### Finding Hidden DLLs

```bash
volatility -f <image> --profile=<profile> ldrmodules
```

### Finding Hidden Sockets

```bash
volatility -f <image> --profile=<profile> sockets
```

### Finding Hidden Registry Keys

```bash
volatility -f <image> --profile=<profile> hivescan
```

### Finding Hidden Files

```bash
volatility -f <image> --profile=<profile> filescan -S -D <output_directory>
```

### Finding Hidden Processes and DLLs

```bash
volatility -f <image> --profile=<profile> mutantscan
```

### Finding Hidden Code Injection

```bash
volatility -f <image> --profile=<profile> malfind -Y <output_directory>
volatility -f <image> --profile=<profile> malfind -D <output_directory>
volatility -f <image> --profile=<profile> malfind -p <pid> -D <output_directory>
```

### Finding Hidden Rootkits

```bash
volatility -f <image> --profile=<profile> linux_check_afinfo
volatility -f <image> --profile=<profile> linux_check_creds
volatility -f <image> --profile=<profile> linux_check_fop
volatility -f <image> --profile=<profile> linux_check_idt
volatility -f <image> --profile=<profile> linux_check_modules
volatility -f <image> --profile=<profile> linux_check_syscall
volatility -f <image> --profile=<profile> linux_check_syscalltbl
volatility -f <image> --profile=<profile> linux_check_tty
volatility -f <image> --profile=<profile> linux_check_uname
volatility -f <image> --profile=<profile> linux_check_syscall_generic
volatility -f <image> --profile=<profile> linux_hidden_modules
volatility -f <image> --profile=<profile> linux_hidden_procs
volatility -f <image> --profile=<profile> linux_hidden_files
volatility -f <image> --profile=<profile> linux_hidden_ports
volatility -f <image> --profile=<profile> linux_hidden_registries
volatility -f <image> --profile=<profile> linux_hidden_sockets
volatility -f <image> --profile=<profile> linux_hidden_syscall
volatility -f <image> --profile=<profile> linux_hidden_tty
volatility -f <image> --profile=<profile> linux_hidden_modules
volatility -f <image> --profile=<profile> linux_hidden_syscalltbl
volatility -f <image> --profile=<profile> linux_hidden_uname
```

### Finding Hidden Processes and DLLs (Windows 10)

```bash
volatility -f <image> --profile=<profile> pslist --apply-rules
volatility -f <image> --profile=<profile> dlllist --apply-rules
```

### Finding Hidden Code Injection (Windows 10)

```bash
volatility -f <image> --profile=<profile> malfind --apply-rules
```

### Finding Hidden Rootkits (Windows 10)

```bash
volatility -f <image> --profile=<profile> autoruns --apply-rules
volatility -f <image> --profile=<profile> driverirp --apply-rules
volatility -f <image> --profile=<profile> drivermodule --apply-rules
volatility -f <image> --profile=<profile> driverobject --apply-rules
volatility -f <image> --profile=<profile> driverscan --apply-rules
volatility -f <image> --profile=<profile> filescan --apply-rules
volatility -f <image> --profile=<profile> getsids --apply-rules
volatility -f <image> --profile=<profile> hivelist --apply-rules
volatility -f <image> --profile=<profile> hivescan --apply-rules
volatility -f <image> --profile=<profile> idt --apply-rules
volatility -f <image> --profile=<profile> imagecopy --apply-rules
volatility -f <image> --profile=<profile> imageinfo --apply-rules
volatility -f <image> --profile=<profile> ldrmodules --apply-rules
volatility -f <image> --profile=<profile> malfind --apply-rules
volatility -f <image> --profile=<profile> mutantscan --apply-rules
volatility -f <image> --profile=<profile> netscan --apply-rules
volatility -f <image> --profile=<profile> privs --apply-rules
volatility -f <image> --profile=<profile> pslist --apply-rules
volatility -f <image> --profile=<profile> psscan --apply-rules
volatility -f <image> --profile=<profile> pstree --apply-rules
volatility -f <image> --profile=<profile> regdiff --apply-rules
volatility -f <image> --profile=<profile> shimcache --apply-rules
volatility -f <image> --profile=<profile> sockets --apply-rules
volatility -f <image> --profile=<profile> ssdt --apply-rules
volatility -f <image> --profile=<profile> svcscan --apply-rules
volatility -f <image> --profile=<profile> thrdscan --apply-rules
volatility -f <image> --profile=<profile> userassist --apply-rules
volatility -f <image> --profile=<profile> vadinfo --apply-rules
volatility -f <image> --profile=<profile> vadtree --apply-rules
volatility -f <image> --profile=<profile> windows --apply-rules
volatility -f <image> --profile=<profile> wintree --apply-rules
```

## References

- [Volatility Cheat Sheet](https://github.com/sans-dfir/sift/blob/master/Cheat%20Sheets/Volatility%20Cheat%20Sheet.pdf)
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
### Volcado de procesos

{% tabs %}
{% tab title="vol3" %}

El volcado de procesos es una técnica que consiste en extraer la memoria de un proceso específico y analizarla para obtener información valiosa. Para realizar un volcado de procesos con Volatility, se puede utilizar el comando `procdump` seguido del PID del proceso que se desea volcar:

```bash
volatility -f <archivo_memoria> procdump -p <PID>
```

Una vez que se ha realizado el volcado, se puede analizar la memoria del proceso utilizando los plugins de Volatility correspondientes. Por ejemplo, para analizar la memoria de un proceso en busca de conexiones de red, se puede utilizar el plugin `netscan`:

```bash
volatility -f <archivo_memoria> --profile=<perfil> netscan -p <PID>
```

También es posible analizar la memoria del proceso en busca de cadenas de texto utilizando el plugin `strings`:

```bash
volatility -f <archivo_memoria> --profile=<perfil> strings -p <PID>
```

Otra técnica útil es la de buscar handles abiertos por el proceso utilizando el plugin `handles`:

```bash
volatility -f <archivo_memoria> --profile=<perfil> handles -p <PID>
```

Estas son solo algunas de las técnicas que se pueden utilizar para analizar la memoria de un proceso volcado. Es importante tener en cuenta que el volcado de procesos puede ser una técnica invasiva y que puede afectar el funcionamiento del sistema en el que se está trabajando. Por lo tanto, es recomendable utilizar esta técnica con precaución y solo en sistemas que no estén en producción.
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> handles
volatility -f <memory_dump> filescan
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> privs
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> userassist
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> malfind
volatility -f <memory_dump> mftparser
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> printkey
volatility -f <memory_dump> hashdump
volatility -f <memory_dump> envars
volatility -f <memory_dump> dumpregistry
volatility -f <memory_dump> dumpfiles
volatility -f <memory_dump> memdump
```

### Advanced Commands

```bash
volatility -f <memory_dump> --profile=<profile> <plugin> <options>
```

### Plugins

#### Malware Analysis

```bash
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malfind -Y <path_to_yara_rules>
volatility -f <memory_dump> malfind -D <path_to_dump_directory>
volatility -f <memory_dump> malfind -p <pid>
volatility -f <memory_dump> malfind -u <user>
volatility -f <memory_dump> malfind -P <process_name>
volatility -f <memory_dump> malfind -Y <path_to_yara_rules> -D <path_to_dump_directory> -p <pid> -u <user> -P <process_name>
```

```bash
volatility -f <memory_dump> mftparser
volatility -f <memory_dump> mftparser -o <output_directory>
volatility -f <memory_dump> mftparser -f <filename>
volatility -f <memory_dump> mftparser -o <output_directory> -f <filename>
```

#### Registry Analysis

```bash
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivelist -o <output_directory>
volatility -f <memory_dump> hivelist -o <output_directory> -p <pid>
volatility -f <memory_dump> hivelist -o <output_directory> -p <pid> -u <user>
```

```bash
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> printkey -K <key> -o <output_directory>
volatility -f <memory_dump> printkey -K <key> -o <output_directory> -p <pid>
volatility -f <memory_dump> printkey -K <key> -o <output_directory> -p <pid> -u <user>
```

```bash
volatility -f <memory_dump> hashdump -s <system_hive> -s <software_hive>
volatility -f <memory_dump> hashdump -s <system_hive> -s <software_hive> -o <output_directory>
volatility -f <memory_dump> hashdump -s <system_hive> -s <software_hive> -o <output_directory> -p <pid>
volatility -f <memory_dump> hashdump -s <system_hive> -s <software_hive> -o <output_directory> -p <pid> -u <user>
```

#### Network Analysis

```bash
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
```

#### Process Analysis

```bash
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> handles
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> privs
volatility -f <memory_dump> apihooks
```

#### File Analysis

```bash
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> filescan
volatility -f <memory_dump> dumpfiles -Q <file_path>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> -p <pid>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> -p <pid> -u <user>
```

#### Memory Analysis

```bash
volatility -f <memory_dump> memdump -p <pid>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir=<dump_directory>
```

#### Other

```bash
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> userassist
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> envars
```

## Volatility Profiles

### Linux

```bash
volatility --info | grep Linux
```

### Windows

```bash
volatility --info | grep Win
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
### Línea de comandos

¿Se ejecutó algo sospechoso? 

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> handles
volatility -f <memory_dump> filescan
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> privs
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> userassist
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> malfind
volatility -f <memory_dump> mftparser
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> printkey
volatility -f <memory_dump> hashdump
volatility -f <memory_dump> envars
volatility -f <memory_dump> dumpregistry
volatility -f <memory_dump> dumpfiles
volatility -f <memory_dump> memdump
```

### Advanced Commands

```bash
volatility -f <memory_dump> --profile=<profile> <plugin> <options>
```

### Plugins

#### Malware Analysis

```bash
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malfind -Y <malware_directory>
volatility -f <memory_dump> malfind -D <output_directory>
volatility -f <memory_dump> malfind -p <pid>
volatility -f <memory_dump> malfind -u <user>
volatility -f <memory_dump> malfind -P <process_name>
volatility -f <memory_dump> malfind -Y <malware_directory> -D <output_directory> -p <pid> -u <user> -P <process_name>
```

#### Registry Analysis

```bash
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> printkey -K <registry_key>
volatility -f <memory_dump> hashdump -y <hive_offset> -s <system_offset> -s <software_offset>
volatility -f <memory_dump> dumpregistry -y <hive_offset> -s <system_offset> -s <software_offset> -D <output_directory>
```

#### File Analysis

```bash
volatility -f <memory_dump> filescan
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir=<dump_directory>
```

#### Network Analysis

```bash
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
```

#### Process Analysis

```bash
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> handles
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> privs
volatility -f <memory_dump> apihooks
```

#### Memory Analysis

```bash
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
volatility -f <memory_dump> memdump --dump-dir=<dump_directory> -p <pid> -D <output_directory>
```

#### Other

```bash
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> userassist
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> envars
```

## Volatility Profiles

### Linux

```bash
volatility --info | grep Linux
```

### Windows

```bash
volatility --info | grep Win
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
Los comandos ingresados en cmd.exe son procesados por conhost.exe (csrss.exe antes de Windows 7). Por lo tanto, incluso si un atacante logró matar cmd.exe antes de que obtuviéramos un volcado de memoria, todavía hay una buena posibilidad de recuperar el historial de la sesión de línea de comandos de la memoria de conhost.exe. Si encuentra algo extraño (usando los módulos de la consola), intente hacer un volcado de memoria del proceso asociado con conhost.exe y busque cadenas dentro de él para extraer las líneas de comando.

### Entorno

Obtenga las variables de entorno de cada proceso en ejecución. Puede haber algunos valores interesantes.
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> handles
volatility -f <memory_dump> filescan
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> privs
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> userassist
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> malfind
volatility -f <memory_dump> mftparser
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> printkey
volatility -f <memory_dump> hashdump
volatility -f <memory_dump> envars
volatility -f <memory_dump> dumpregistry
volatility -f <memory_dump> dumpfiles
volatility -f <memory_dump> memdump
```

### Advanced Commands

```bash
volatility -f <memory_dump> --profile=<profile> <plugin> <options>
```

### Plugins

#### Malware Analysis

```bash
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malfind -Y <path_to_yara_rules>
volatility -f <memory_dump> malfind -D <path_to_dump_directory>
volatility -f <memory_dump> malfind -p <pid>
volatility -f <memory_dump> malfind -u <user>
volatility -f <memory_dump> malfind -P <process_name>
volatility -f <memory_dump> malfind -Y <path_to_yara_rules> -D <path_to_dump_directory> -p <pid> -u <user> -P <process_name>
```

```bash
volatility -f <memory_dump> mftparser
volatility -f <memory_dump> mftparser -o <output_directory>
volatility -f <memory_dump> mftparser -f <filename>
volatility -f <memory_dump> mftparser -o <output_directory> -f <filename>
```

#### Registry Analysis

```bash
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivelist -o <output_directory>
volatility -f <memory_dump> hivelist -o <output_directory> -p <pid>
volatility -f <memory_dump> hivelist -o <output_directory> -p <pid> -u <user>
```

```bash
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> printkey -K <key> -o <output_directory>
volatility -f <memory_dump> printkey -K <key> -o <output_directory> -p <pid>
volatility -f <memory_dump> printkey -K <key> -o <output_directory> -p <pid> -u <user>
```

```bash
volatility -f <memory_dump> hashdump -s <system_hive> -s <software_hive>
volatility -f <memory_dump> hashdump -s <system_hive> -s <software_hive> -o <output_directory>
volatility -f <memory_dump> hashdump -s <system_hive> -s <software_hive> -o <output_directory> -p <pid>
volatility -f <memory_dump> hashdump -s <system_hive> -s <software_hive> -o <output_directory> -p <pid> -u <user>
```

#### Network Analysis

```bash
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
```

#### Process Analysis

```bash
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> handles
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> privs
volatility -f <memory_dump> apihooks
```

#### File Analysis

```bash
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> filescan
volatility -f <memory_dump> dumpfiles -Q <file_path>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> -p <pid>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> -p <pid> -u <user>
```

#### Memory Analysis

```bash
volatility -f <memory_dump> memdump -p <pid>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir=<dump_directory>
```

#### Other

```bash
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> userassist
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> envars
```

## Volatility Profiles

### Linux

```bash
volatility --info | grep Linux
```

### Windows

```bash
volatility --info | grep Win
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated 
```
### Privilegios de token

Comprueba si hay tokens de privilegios en servicios inesperados.\
Podría ser interesante listar los procesos que utilizan algún token privilegiado.
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}

{% tab title="volatility-cheatsheet" %}
# Volatility Cheatsheet

## Basic Commands

### Image Identification

```bash
volatility -f <image> imageinfo
```

### Profile Identification

```bash
volatility -f <image> imageinfo | grep Profile
```

### Process List

```bash
volatility -f <image> --profile=<profile> pslist
```

### Process Tree

```bash
volatility -f <image> --profile=<profile> pstree
```

### DLL List

```bash
volatility -f <image> --profile=<profile> dlllist
```

### Handles

```bash
volatility -f <image> --profile=<profile> handles
```

### Network Connections

```bash
volatility -f <image> --profile=<profile> netscan
```

### Open Files

```bash
volatility -f <image> --profile=<profile> filescan
```

### Registry Analysis

```bash
volatility -f <image> --profile=<profile> hivelist
volatility -f <image> --profile=<profile> printkey -K <key>
volatility -f <image> --profile=<profile> printval -K <key> -V <value>
```

### Dumping Processes

```bash
volatility -f <image> --profile=<profile> procdump -p <pid> -D <output_directory>
```

### Dumping Files

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <address_space> -D <output_directory>
```

### Strings

```bash
volatility -f <image> --profile=<profile> strings -s <address_space> -o <offset>
```

### Malware Analysis

```bash
volatility -f <image> --profile=<profile> malfind
volatility -f <image> --profile=<profile> malsysproc
volatility -f <image> --profile=<profile> malprocfind
```

## Advanced Commands

### Finding Hidden Processes

```bash
volatility -f <image> --profile=<profile> psxview
```

### Finding Hidden DLLs

```bash
volatility -f <image> --profile=<profile> ldrmodules
```

### Finding Hidden Sockets

```bash
volatility -f <image> --profile=<profile> sockets
```

### Finding Hidden Registry Keys

```bash
volatility -f <image> --profile=<profile> hivescan
```

### Finding Hidden Files

```bash
volatility -f <image> --profile=<profile> filescan -S -u
```

### Finding Hidden Processes and DLLs

```bash
volatility -f <image> --profile=<profile> mutantscan
```

### Finding Hidden Code Injection

```bash
volatility -f <image> --profile=<profile> malfind -Y <dll_name>
```

### Finding Hidden Rootkits

```bash
volatility -f <image> --profile=<profile> linux_check_afinfo
volatility -f <image> --profile=<profile> linux_check_creds
volatility -f <image> --profile=<profile> linux_check_fop
volatility -f <image> --profile=<profile> linux_check_idt
volatility -f <image> --profile=<profile> linux_check_modules
volatility -f <image> --profile=<profile> linux_check_syscall
volatility -f <image> --profile=<profile> linux_check_syscalltbl
volatility -f <image> --profile=<profile> linux_check_tty
volatility -f <image> --profile=<profile> linux_check_vdso
volatility -f <image> --profile=<profile> linux_hidden_modules
volatility -f <image> --profile=<profile> linux_hidden_procs
volatility -f <image> --profile=<profile> linux_hidden_syscall
volatility -f <image> --profile=<profile> linux_hidden_syscalltbl
volatility -f <image> --profile=<profile> linux_hidden_tty
volatility -f <image> --profile=<profile> linux_hidden_vdso
```
{% endtab %}
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
### SIDs

Verifique cada SSID propiedad de un proceso.\
Podría ser interesante listar los procesos que utilizan un SID de privilegios (y los procesos que utilizan algún SID de servicio).
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> handles
volatility -f <memory_dump> filescan
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> privs
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> userassist
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> malfind
volatility -f <memory_dump> mftparser
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> printkey
volatility -f <memory_dump> hashdump
volatility -f <memory_dump> envars
volatility -f <memory_dump> dumpregistry
volatility -f <memory_dump> dumpfiles
volatility -f <memory_dump> memdump
```

### Advanced Commands

```bash
volatility -f <memory_dump> --profile=<profile> <plugin> <options>
```

### Plugins

#### Malware Analysis

```bash
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malfind -Y <path_to_yara_rules>
volatility -f <memory_dump> malfind -D <path_to_dump_directory>
volatility -f <memory_dump> malfind -p <pid>
volatility -f <memory_dump> malfind -u <user>
volatility -f <memory_dump> malfind -P <process_name>
volatility -f <memory_dump> malfind -Y <path_to_yara_rules> -D <path_to_dump_directory> -p <pid> -u <user> -P <process_name>
```

```bash
volatility -f <memory_dump> malsysproc
volatility -f <memory_dump> malsysproc -p <pid>
volatility -f <memory_dump> malsysproc -u <user>
volatility -f <memory_dump> malsysproc -P <process_name>
volatility -f <memory_dump> malsysproc -p <pid> -u <user> -P <process_name>
```

```bash
volatility -f <memory_dump> malfindsock
volatility -f <memory_dump> malfindsock -p <pid>
volatility -f <memory_dump> malfindsock -u <user>
volatility -f <memory_dump> malfindsock -P <process_name>
volatility -f <memory_dump> malfindsock -p <pid> -u <user> -P <process_name>
```

#### Network Analysis

```bash
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
volatility -f <memory_dump> sockscan
volatility -f <memory_dump> sockstat
volatility -f <memory_dump> connscan -p <pid>
volatility -f <memory_dump> connscan -u <user>
volatility -f <memory_dump> connscan -P <process_name>
volatility -f <memory_dump> connscan -p <pid> -u <user> -P <process_name>
```

#### Memory Analysis

```bash
volatility -f <memory_dump> memdump
volatility -f <memory_dump> memdump -p <pid>
volatility -f <memory_dump> memdump -u <user>
volatility -f <memory_dump> memdump -P <process_name>
volatility -f <memory_dump> memdump -p <pid> -u <user> -P <process_name>
```

```bash
volatility -f <memory_dump> memmap
volatility -f <memory_dump> memmap -p <pid>
volatility -f <memory_dump> memmap -u <user>
volatility -f <memory_dump> memmap -P <process_name>
volatility -f <memory_dump> memmap -p <pid> -u <user> -P <process_name>
```

#### Registry Analysis

```bash
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> printkey -K <registry_key>
volatility -f <memory_dump> dumpregistry -K <registry_key> -D <path_to_dump_directory>
```

#### Process Analysis

```bash
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> psxview
volatility -f <memory_dump> pslist -p <pid>
volatility -f <memory_dump> pslist -u <user>
volatility -f <memory_dump> pslist -P <process_name>
volatility -f <memory_dump> pslist -p <pid> -u <user> -P <process_name>
```

```bash
volatility -f <memory_dump> handles
volatility -f <memory_dump> handles -p <pid>
volatility -f <memory_dump> handles -u <user>
volatility -f <memory_dump> handles -P <process_name>
volatility -f <memory_dump> handles -p <pid> -u <user> -P <process_name>
```

```bash
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> cmdline -p <pid>
volatility -f <memory_dump> cmdline -u <user>
volatility -f <memory_dump> cmdline -P <process_name>
volatility -f <memory_dump> cmdline -p <pid> -u <user> -P <process_name>
```

```bash
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> dlllist -p <pid>
volatility -f <memory_dump> dlllist -u <user>
volatility -f <memory_dump> dlllist -P <process_name>
volatility -f <memory_dump> dlllist -p <pid> -u <user> -P <process_name>
```

#### System Analysis

```bash
volatility -f <memory_dump> filescan
volatility -f <memory_dump> filescan -p <pid>
volatility -f <memory_dump> filescan -u <user>
volatility -f <memory_dump> filescan -P <process_name>
volatility -f <memory_dump> filescan -p <pid> -u <user> -P <process_name>
```

```bash
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> shimcache -p <pid>
volatility -f <memory_dump> shimcache -u <user>
volatility -f <memory_dump> shimcache -P <process_name>
volatility -f <memory_dump> shimcache -p <pid> -u <user> -P <process_name>
```

```bash
volatility -f <memory_dump> userassist
volatility -f <memory_dump> userassist -p <pid>
volatility -f <memory_dump> userassist -u <user>
volatility -f <memory_dump> userassist -P <process_name>
volatility -f <memory_dump> userassist -p <pid> -u <user> -P <process_name>
```

#### Other Plugins

```bash
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> privs
volatility -f <memory_dump> printkey
volatility -f <memory_dump> hashdump
volatility -f <memory_dump> envars
volatility -f <memory_dump> dumpfiles
```

## Volatility Profiles

### Linux

```bash
volatility --info | grep Linux
```

### Windows

```bash
volatility --info | grep Win
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
### Handles

Es útil saber a qué otros archivos, claves, hilos, procesos... un **proceso tiene un handle** (ha abierto).
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{% endtab %}
{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from [Volatility Releases](https://github.com/volatilityfoundation/volatility/releases).

## Volatility Usage

### Basic Usage

```bash
volatility -f <memory_dump> <plugin> [options]
```

### List Available Plugins

```bash
volatility --info | less
```

### List Processes

```bash
volatility -f <memory_dump> pslist
```

### Dump Process Memory

```bash
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
```

### Analyze Network Connections

```bash
volatility -f <memory_dump> netscan
```

### Analyze Open Files

```bash
volatility -f <memory_dump> filescan
```

### Analyze Registry

```bash
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> printkey -K <registry_key>
volatility -f <memory_dump> printval -K <registry_key> -V <registry_value>
```

### Analyze Malware

```bash
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malprocfind
```

### Analyze Drivers

```bash
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> driverscan
```

### Analyze Services

```bash
volatility -f <memory_dump> svcscan
volatility -f <memory_dump> servicehooks
```

### Analyze DLLs

```bash
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> dlldump -D <output_directory> -b <base_address>
```

### Analyze Processes

```bash
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> psxview
```

### Analyze Handles

```bash
volatility -f <memory_dump> handles
volatility -f <memory_dump> handles -p <pid>
```

### Analyze Timelining

```bash
volatility -f <memory_dump> timeliner
```

### Analyze User Accounts

```bash
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getsid -u <username>
volatility -f <memory_dump> hashdump
```

### Analyze Memory

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> kdbgscan
volatility -f <memory_dump> memmap
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
volatility -f <memory_dump> memdump -b <address> -e <address> -D <output_directory>
volatility -f <memory_dump> strings -s <address> -e <address>
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vaddump -D <output_directory> -b <base_address> -e <end_address>
```

### Analyze Virtual File System

```bash
volatility -f <memory_dump> vfiles
volatility -f <memory_dump> vinfo
volatility -f <memory_dump> vshot
```

### Analyze Windows

```bash
volatility -f <memory_dump> envars
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> hibinfo
volatility -f <memory_dump> hiblist
volatility -f <memory_dump> hibdump -o <offset> -D <output_directory>
volatility -f <memory_dump> printkey -K <registry_key>
volatility -f <memory_dump> printkey -K <registry_key> -o <offset>
volatility -f <memory_dump> printval -K <registry_key> -V <registry_value>
volatility -f <memory_dump> printval -K <registry_key> -V <registry_value> -o <offset>
volatility -f <memory_dump> userassist
volatility -f <memory_dump> userhandles
volatility -f <memory_dump> userhandles -p <pid>
volatility -f <memory_dump> userhives
volatility -f <memory_dump> userhives -u <username>
volatility -f <memory_dump> windows
```

### Analyze Linux

```bash
volatility -f <memory_dump> linux_banner
volatility -f <memory_dump> linux_bash
volatility -f <memory_dump> linux_check_afinfo
volatility -f <memory_dump> linux_check_creds
volatility -f <memory_dump> linux_check_idt
volatility -f <memory_dump> linux_check_syscall
volatility -f <memory_dump> linux_cpuinfo
volatility -f <memory_dump> linux_dentry_cache
volatility -f <memory_dump> linux_dmesg
volatility -f <memory_dump> linux_file_cache
volatility -f <memory_dump> linux_hidden_modules
volatility -f <memory_dump> linux_hidden_procs
volatility -f <memory_dump> linux_hidden_shm
volatility -f <memory_dump> linux_hidden_sockets
volatility -f <memory_dump> linux_hidden_syscalls
volatility -f <memory_dump> linux_hidden_tcp
volatility -f <memory_dump> linux_hidden_timerfd
volatility -f <memory_dump> linux_hidden_vmas
volatility -f <memory_dump> linux_ifconfig
volatility -f <memory_dump> linux_lsmod
volatility -f <memory_dump> linux_lsof
volatility -f <memory_dump> linux_meminfo
volatility -f <memory_dump> linux_mount
volatility -f <memory_dump> linux_netstat
volatility -f <memory_dump> linux_pidhashtable
volatility -f <memory_dump> linux_pslist
volatility -f <memory_dump> linux_pstree
volatility -f <memory_dump> linux_route_cache
volatility -f <memory_dump> linux_sockets
volatility -f <memory_dump> linux_taskstats
volatility -f <memory_dump> linux_version
volatility -f <memory_dump> linux_vm_map
volatility -f <memory_dump> linux_yarascan
```

### Analyze Mac

```bash
volatility -f <memory_dump> mac_check_syscall
volatility -f <memory_dump> mac_file_cache
volatility -f <memory_dump> mac_ifconfig
volatility -f <memory_dump> mac_kextstat
volatility -f <memory_dump> mac_lsof
volatility -f <memory_dump> mac_mount
volatility -f <memory_dump> mac_netstat
volatility -f <memory_dump> mac_pslist
volatility -f <memory_dump> mac_pstree
volatility -f <memory_dump> mac_taskstats
volatility -f <memory_dump> mac_version
volatility -f <memory_dump> mac_yarascan
```

## Volatility Plugins

### Process

```bash
volatility -f <memory_dump> psscan
volatility -f <memory_dump> pstree
volatility -f <memory_dump> pslist
volatility -f <memory_dump> psxview
volatility -f <memory_dump> pcmdump
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> dlldump
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malprocfind
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> thrdscan
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vaddump
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadwalk
volatility -f <memory_dump> vadtree
vol
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
{% endtab %}
{% tab title="esp3" %}
### DLLs

Las bibliotecas de enlace dinámico (DLLs) son archivos que contienen código y datos que pueden ser utilizados por más de un programa al mismo tiempo. En la memoria, las DLLs se cargan en el espacio de direcciones de un proceso y se pueden analizar para buscar pistas sobre la actividad del proceso. Volatility proporciona varias opciones para analizar las DLLs cargadas en la memoria.

#### dlllist

El comando `dlllist` muestra una lista de todas las DLLs cargadas en la memoria de un proceso. También muestra la dirección base de la DLL, el tamaño, la ruta del archivo y la hora de carga.

```
volatility -f memory_dump.mem --profile=PROFILE dlllist -p PID
```

#### dlldump

El comando `dlldump` permite extraer una DLL de la memoria y guardarla en un archivo. Esto puede ser útil para analizar la DLL en una herramienta de análisis estática.

```
volatility -f memory_dump.mem --profile=PROFILE dlldump -p PID -b ADDRESS -D OUTPUT_DIR
```

Donde `ADDRESS` es la dirección base de la DLL y `OUTPUT_DIR` es el directorio donde se guardará el archivo de la DLL.

#### dllscan

El comando `dllscan` busca todas las DLLs cargadas en la memoria y las compara con una lista de DLLs conocidas. Esto puede ser útil para identificar DLLs maliciosas que se han cargado en la memoria.

```
volatility -f memory_dump.mem --profile=PROFILE dllscan
```

#### dllsummary

El comando `dllsummary` muestra un resumen de todas las DLLs cargadas en la memoria, incluyendo la cantidad de procesos que han cargado cada DLL.

```
volatility -f memory_dump.mem --profile=PROFILE dllsummary
```

#### dllhash

El comando `dllhash` calcula el hash MD5 de una DLL cargada en la memoria. Esto puede ser útil para identificar DLLs maliciosas que tienen un hash diferente al de la DLL legítima.

```
volatility -f memory_dump.mem --profile=PROFILE dllhash -p PID -b ADDRESS
```

Donde `ADDRESS` es la dirección base de la DLL.
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% endtab %}

{% tab title="volatility-cheatsheet" %}
# Volatility Cheatsheet

## Basic Commands

### Image Identification

```bash
volatility -f <image> imageinfo
```

### Profile Identification

```bash
volatility -f <image> imageinfo | grep Profile
```

### Process List

```bash
volatility -f <image> --profile=<profile> pslist
```

### Process Tree

```bash
volatility -f <image> --profile=<profile> pstree
```

### DLL List

```bash
volatility -f <image> --profile=<profile> dlllist
```

### Handles

```bash
volatility -f <image> --profile=<profile> handles
```

### Network Connections

```bash
volatility -f <image> --profile=<profile> netscan
```

### Open Files

```bash
volatility -f <image> --profile=<profile> filescan
```

### Registry Keys

```bash
volatility -f <image> --profile=<profile> printkey -K <key>
```

### Registry Values

```bash
volatility -f <image> --profile=<profile> printkey -K <key> -V
```

### Dump Process

```bash
volatility -f <image> --profile=<profile> memdump -p <pid> -D <output_directory>
```

### Dump Module

```bash
volatility -f <image> --profile=<profile> moddump -p <pid> -D <output_directory>
```

### Dump Registry Key

```bash
volatility -f <image> --profile=<profile> dumpregistry -K <key> -D <output_directory>
```

### Dump File

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <path> -D <output_directory>
```

### Strings

```bash
volatility -f <image> --profile=<profile> strings -s <address> -e <address>
```

### Search

```bash
volatility -f <image> --profile=<profile> search -s <string>
```

### Yara

```bash
volatility -f <image> --profile=<profile> yarascan -Y <yara_rule>
```

## Advanced Commands

### Malware Analysis

```bash
volatility -f <image> --profile=<profile> malfind
```

### Rootkit Analysis

```bash
volatility -f <image> --profile=<profile> ldrmodules
```

### Kernel Drivers

```bash
volatility -f <image> --profile=<profile> driverscan
```

### SSDT

```bash
volatility -f <image> --profile=<profile> ssdt
```

### IDT

```bash
volatility -f <image> --profile=<profile> idt
```

### GDT

```bash
volatility -f <image> --profile=<profile> gdt
```

### Interrupt Descriptor Table

```bash
volatility -f <image> --profile=<profile> interrupts
```

### Process Environment Block

```bash
volatility -f <image> --profile=<profile> psscan
```

### Kernel Objects

```bash
volatility -f <image> --profile=<profile> kdbgscan
```

### Kernel Object Types

```bash
volatility -f <image> --profile=<profile> kpcrscan
```

### Kernel Object Handles

```bash
volatility -f <image> --profile=<profile> objecthandles
```

### Pool Tags

```bash
volatility -f <image> --profile=<profile> pooltag
```

### Pool Allocations

```bash
volatility -f <image> --profile=<profile> poolfind
```

### Virtual Address Descriptors

```bash
volatility -f <image> --profile=<profile> vadinfo
```

### Virtual Address Descriptors Tree

```bash
volatility -f <image> --profile=<profile> vadtree
```

### Virtual Address Descriptors Walk

```bash
volatility -f <image> --profile=<profile> vadwalk
```

### Physical Memory

```bash
volatility -f <image> --profile=<profile> hivedump -o <offset> -s <size> -D <output_directory>
```

### Dump Registry Hive

```bash
volatility -f <image> --profile=<profile> hivelist
volatility -f <image> --profile=<profile> hivedump -o <offset> -D <output_directory>
```

### Dump SAM

```bash
volatility -f <image> --profile=<profile> samdump -o <offset> -D <output_directory>
```

### Dump Security

```bash
volatility -f <image> --profile=<profile> cachedump -o <offset> -D <output_directory>
```

### Dump LSA Secrets

```bash
volatility -f <image> --profile=<profile> lsadump -o <offset> -D <output_directory>
```

### Dump LSA Cache

```bash
volatility -f <image> --profile=<profile> lscache
```

### Dump LSA Secrets and Cache

```bash
volatility -f <image> --profile=<profile> lsadump -o <offset> -D <output_directory> --system <system_hive> --security <security_hive> --sam <sam_hive>
```

### Dump Password Hashes

```bash
volatility -f <image> --profile=<profile> hashdump -o <offset> -D <output_directory>
```

### Dump Cached Password Hashes

```bash
volatility -f <image> --profile=<profile> cachedump -o <offset> -D <output_directory> --system <system_hive> --security <security_hive> --sam <sam_hive>
```

### Dump Bitlocker Keys

```bash
volatility -f <image> --profile=<profile> bitlocker
```

### Dump Truecrypt Keys

```bash
volatility -f <image> --profile=<profile> truecryptmaster
```

### Dump KeePass Passwords

```bash
volatility -f <image> --profile=<profile> keepass
```

### Dump Putty Passwords

```bash
volatility -f <image> --profile=<profile> putty
```

### Dump WinSCP Passwords

```bash
volatility -f <image> --profile=<profile> winscp
```

### Dump Filezilla Passwords

```bash
volatility -f <image> --profile=<profile> filezilla
```

### Dump Chrome Passwords

```bash
volatility -f <image> --profile=<profile> chromepasswords
```

### Dump Firefox Passwords

```bash
volatility -f <image> --profile=<profile> firepwd
```

### Dump Thunderbird Passwords

```bash
volatility -f <image> --profile=<profile> thunderbird
```

### Dump Skype Conversations

```bash
volatility -f <image> --profile=<profile> skype
```

### Dump Slack Conversations

```bash
volatility -f <image> --profile=<profile> slack
```

### Dump Discord Conversations

```bash
volatility -f <image> --profile=<profile> discord
```

### Dump Telegram Conversations

```bash
volatility -f <image> --profile=<profile> telegram
```

### Dump Signal Conversations

```bash
volatility -f <image> --profile=<profile> signal
```

### Dump WhatsApp Conversations

```bash
volatility -f <image> --profile=<profile> whatsapp
```

### Dump Skype Contacts

```bash
volatility -f <image> --profile=<profile> skypecontacts
```

### Dump Slack Contacts

```bash
volatility -f <image> --profile=<profile> slackcontacts
```

### Dump Discord Contacts

```bash
volatility -f <image> --profile=<profile> discordcontacts
```

### Dump Telegram Contacts

```bash
volatility -f <image> --profile=<profile> telegramcontacts
```

### Dump Signal Contacts

```bash
volatility -f <image> --profile=<profile> signalcontacts
```

### Dump WhatsApp Contacts

```bash
volatility -f <image> --profile=<profile> whatsappcontacts
```

### Dump Chrome History

```bash
volatility -f <image> --profile=<profile> chromehistory
```

### Dump Firefox History

```bash
volatility -f <image> --profile=<profile> firefoxhistory
```

### Dump Thunderbird Emails

```bash
volatility -f <image> --profile=<profile> thunderbirdemails
```

### Dump Outlook Emails

```bash
volatility -f <image> --profile=<profile> outlookemails
```

### Dump Outlook Contacts

```bash
volatility -f <image> --profile=<profile> outlookcontacts
```

### Dump Outlook Calendar

```bash
volatility -f <image> --profile=<profile> outlookcalendar
```

### Dump Outlook Tasks

```bash
volatility -f <image> --profile=<profile> outlooktasks
```

### Dump Outlook Notes

```bash
volatility -f <image> --profile=<profile> outlooknotes
```

### Dump Outlook Journals

```bash
volatility -f <image> --profile=<profile> outlookjournals
```

### Dump Windows Vault

```bash
volatility -f <image> --profile=<profile> vault
```

### Dump Windows Credentials

```bash
volatility -f <image> --profile=<profile> wincred
```

### Dump Windows Logon Passwords

```bash
volatility -f <image> --profile=<profile> mimikatz
```

### Dump Windows Logon Passwords (LSASS Method)

```bash
volatility -f <image> --profile=<profile> lsadump2
```

### Dump Windows Logon Passwords (System Method)

```bash
volatility -f <image> --profile=<profile> lsadump
```

### Dump Windows Logon Passwords (Cached Method)

```bash
volatility -f <image> --profile=<profile> cachedump
```

### Dump Windows Logon Passwords (Registry Method)

```bash
volatility -f <image> --profile=<profile> hashdump
```

### Dump Windows Logon Passwords (SAM Method)

```bash
volatility -f <image> --profile=<profile> samdump2
```

### Dump Windows Logon Passwords (DPAPI Method)

```bash
volatility -f <image> --profile=<profile> dpapi
```

### Dump Windows Logon Passwords (Vault Method)

```bash
volatility -f <image> --profile=<profile> vault
```

### Dump Windows Logon Passwords (LSA Method)

```bash
volatility -f <image> --profile=<profile> lsadump
```

### Dump Windows Logon Passwords (LSASS Method)

```bash
volatility -f <image> --profile=<profile> lsadump2
```

### Dump Windows Logon Passwords (Cached Method)

```bash
volatility -f <image> --profile=<profile> cachedump
```

### Dump Windows Logon Passwords (Registry Method)

```bash
volatility -f <image> --profile=<profile> hashdump
```

### Dump Windows Logon Passwords (SAM Method)

```bash
volatility -f <image> --profile=<profile> samdump2
```

### Dump Windows Logon Passwords (DPAPI Method)

```bash
volatility -f <image> --profile=<profile> dpapi
```

### Dump Windows Logon Passwords (Vault Method)

```bash
volatility -f <image> --profile=<profile> vault
```

### Dump Windows Logon Passwords (LSA Method)

```bash
volatility -f <image> --profile=<profile> lsadump
```

### Dump Windows Logon Passwords (LSASS Method)

```bash
volatility -f <image> --profile=<profile> lsadump2
```

### Dump Windows Logon Passwords (Cached Method)

```bash
volatility -f <image> --profile=<profile> cachedump
```

### Dump Windows Logon Passwords (Registry Method)

```bash
volatility -f <image> --profile=<profile> hashdump
```

### Dump Windows Logon Passwords (SAM Method)

```bash
volatility -f <image> --profile=<profile> samdump2
```

### Dump Windows Logon Passwords (DPAPI Method)

```bash
volatility -f <image> --profile=<profile> dpapi
```

### Dump Windows Logon Passwords (Vault Method)

```bash
volatility -f <image> --profile=<profile> vault
```

### Dump Windows Logon Passwords (LSA Method)

```bash
volatility -f <image> --profile=<profile> lsadump
```

### Dump Windows Logon Passwords (LSASS Method)

```bash
volatility -f <image> --profile=<profile> lsadump2
```

### Dump Windows Logon Passwords (Cached Method)

```bash
volatility -f <image> --profile=<profile> cachedump
```

### Dump Windows Logon Passwords (Registry Method)

```bash
volatility -f <image> --profile=<profile> hashdump
```

### Dump Windows Logon Passwords (SAM Method)

```bash
volatility -f <image> --profile=<profile> samdump2
```

### Dump Windows Logon Passwords (DPAPI Method)

```bash
volatility -f <image> --profile=<profile> dpapi
```

### Dump Windows Logon Passwords (Vault Method)

```bash
volatility -f <image> --profile=<profile> vault
```

### Dump Windows Logon Passwords (LSA Method)

```bash
volatility -f <image> --profile=<profile> lsadump
```

### Dump Windows Logon Passwords (LSASS Method)

```bash
volatility -f <image> --profile=<profile> lsadump2
```

### Dump Windows Logon Passwords (Cached Method)

```bash
volatility -f <image> --profile=<profile> cachedump
```

### Dump Windows Logon Passwords (Registry Method)

```bash
volatility -f <image> --profile=<profile> hashdump
```

### Dump Windows Logon Passwords (SAM Method)

```bash
volatility -f <image> --profile=<profile> samdump2
```

### Dump Windows Logon Passwords (DPAPI Method)

```bash
volatility -f <image> --profile=<profile> dpapi
```

### Dump Windows Logon Passwords (Vault Method)

```bash
volatility -f <image> --profile=<profile> vault
```

### Dump Windows Logon Passwords (LSA Method)

```bash
volatility -f <image> --profile=<profile> lsadump
```

### Dump Windows Logon Passwords (LSASS Method)

```bash
volatility -f <image> --profile=<profile> lsadump2
```

### Dump Windows Logon Passwords (Cached Method)

```bash
volatility -f <image> --profile=<profile> cachedump
```

### Dump Windows Logon Passwords (Registry Method)

```bash
volatility -f <image> --profile=<profile> hashdump
```

### Dump Windows Logon Passwords (SAM Method)

```bash
volatility -f <image> --profile=<profile> samdump2
```

### Dump Windows Logon Passwords (DPAPI Method)

```bash
volatility -f <image> --profile=<profile> dpapi
```

### Dump Windows Logon Passwords (Vault Method)

```bash
volatility -f <image> --profile=<profile> vault
```

### Dump Windows Logon Passwords (LSA Method)

```bash
volatility -f <image> --profile=<profile> lsadump
```

### Dump Windows Logon Passwords (LSASS Method)

```bash
volatility -f <image> --profile=<profile> lsadump2
```

### Dump Windows Logon Passwords (Cached Method)

```bash
volatility -f <image> --profile=<profile> cachedump
```

### Dump Windows Logon Passwords (Registry Method)

```bash
volatility -f <image> --profile=<profile> hashdump
```

### Dump Windows Logon Passwords (SAM Method)

```bash
volatility -f <image> --profile=<profile> samdump2
```

### Dump Windows Logon Passwords (DPAPI Method)

```bash
volatility -f <image> --profile=<profile> dpapi
```

### Dump Windows Logon Passwords (Vault Method)

```bash
volatility -f <image> --profile=<profile> vault
```

### Dump Windows Logon Passwords (LSA Method)

```bash
volatility -f <image> --profile=<profile> lsadump
```

### Dump Windows Logon Passwords (LSASS Method)

```bash
volatility -f <image> --profile=<profile> lsadump2
```

### Dump Windows Logon Passwords (Cached Method)

```bash
volatility -f <image> --profile=<profile> cachedump
```

### Dump Windows Logon Passwords (Registry Method)

```bash
volatility -f <image> --profile=<profile> hashdump
```

### Dump Windows Logon Passwords (SAM Method)

```bash
volatility -f <image> --profile=<profile> samdump2
```

### Dump Windows Logon Passwords (DPAPI Method)

```bash
volatility -f <image> --profile=<profile> dpapi
```

### Dump Windows Logon Passwords (Vault Method)

```bash
volatility -f <image> --profile=<profile> vault
```
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
{% endtab %}
{% tab title="vol3" %}

### Cadenas por procesos

Volatility nos permite verificar a qué proceso pertenece una cadena.

{% tabs %}
{% tab title="vol3" %}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> handles
volatility -f <memory_dump> filescan
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> privs
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> userassist
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> malfind
volatility -f <memory_dump> mftparser
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> printkey
volatility -f <memory_dump> hashdump
volatility -f <memory_dump> envars
volatility -f <memory_dump> dumpregistry
volatility -f <memory_dump> dumpfiles
volatility -f <memory_dump> memdump
```

### Advanced Commands

```bash
volatility -f <memory_dump> --profile=<profile> <plugin> <options>
```

### Plugins

#### Malware Analysis

```bash
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malfind -Y <malware_directory>
volatility -f <memory_dump> malfind -D <output_directory>
volatility -f <memory_dump> malfind -p <pid>
volatility -f <memory_dump> malfind -u <user>
volatility -f <memory_dump> malfind -P <process_name>
volatility -f <memory_dump> malfind -Y <malware_directory> -D <output_directory> -p <pid> -u <user> -P <process_name>
```

#### Registry Analysis

```bash
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> printkey -K <registry_key>
volatility -f <memory_dump> hashdump -y <hive_offset> -s <system_offset> -a <sam_offset>
volatility -f <memory_dump> dumpregistry -K <registry_key> -D <output_directory>
```

#### File Analysis

```bash
volatility -f <memory_dump> filescan
volatility -f <memory_dump> dumpfiles -D <output_directory> --name <file_name>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
```

#### Network Analysis

```bash
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
```

#### Process Analysis

```bash
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> handles
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> privs
volatility -f <memory_dump> apihooks
```

#### System Analysis

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> userassist
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> envars
```

### Memory Dump Acquisition

#### Linux

```bash
sudo apt-get install hibernation-ramcapture
sudo hibagent -r <output_file>
```

#### Windows

```bash
winpmem -o <output_file>
```

### Memory Dump Analysis

#### Basic Forensic Methodology

1. Identify the operating system and its version.
2. Identify the profile to use with Volatility.
3. Identify the process(es) of interest.
4. Identify the network connections.
5. Identify the open files.
6. Identify the loaded modules.
7. Identify the registry keys.
8. Identify the malware.
9. Identify the user activity.

#### Malware Analysis

1. Identify the malware.
2. Identify the malware's behavior.
3. Identify the malware's persistence mechanism.
4. Identify the malware's network activity.
5. Identify the malware's communication protocol.
6. Identify the malware's command and control server.
7. Identify the malware's payload.

#### Network Analysis

1. Identify the network connections.
2. Identify the open ports.
3. Identify the network traffic.
4. Identify the network protocols.
5. Identify the network services.
6. Identify the network devices.
7. Identify the network topology.

#### Process Analysis

1. Identify the process(es) of interest.
2. Identify the process's command line arguments.
3. Identify the process's environment variables.
4. Identify the process's loaded modules.
5. Identify the process's network connections.
6. Identify the process's open files.
7. Identify the process's memory usage.

#### System Analysis

1. Identify the operating system and its version.
2. Identify the system's hardware configuration.
3. Identify the system's software configuration.
4. Identify the system's network configuration.
5. Identify the system's security configuration.
6. Identify the system's user accounts.
7. Identify the system's logs.

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% tab title="vol3" %}

También permite buscar cadenas de texto dentro de un proceso utilizando el módulo yarascan:

{% endtab %}
{% endtabs %}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
volatility -f <memory_dump> filescan
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
volatility -f <memory_dump> malfind
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> ldrmodules
volatility -f <memory_dump> modscan
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> handles
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> ssdt
volatility -f <memory_dump> driverscan
volatility -f <memory_dump> fileinfo -F <file_path>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
volatility -f <memory_dump> memdump -b <start_address> -e <end_address> -D <output_directory>
volatility -f <memory_dump> memdump -o <offset> -s <size> -D <output_directory>
```

### Advanced Commands

```bash
volatility -f <memory_dump> --profile=<profile> <plugin> <plugin_options>
```

### Plugins

#### Malware Analysis

```bash
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malsysproc
volatility -f <memory_dump> malprocfind
volatility -f <memory_dump> maldriverscan
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malheap
volatility -f <memory_dump> malpscan
volatility -f <memory_dump> malstack
volatility -f <memory_dump> malstrings
volatility -f <memory_dump> malwaredetect
```

#### Network Analysis

```bash
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockscan
volatility -f <memory_dump> sockstat
volatility -f <memory_dump> sockeye
volatility -f <memory_dump> sockdump
volatility -f <memory_dump> connscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> connscan
```

#### Process Analysis

```bash
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> psxview
volatility -f <memory_dump> psinfo
volatility -f <memory_dump> psselect
volatility -f <memory_dump> psscan
volatility -f <memory_dump> psscan
volatility -f <memory_dump> psscan
```

#### Registry Analysis

```bash
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
```

#### File Analysis

```bash
volatility -f <memory_dump> filescan
volatility -f <memory_dump> fileinfo -F <file_path>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory>
```

#### Memory Analysis

```bash
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
volatility -f <memory_dump> memdump -b <start_address> -e <end_address> -D <output_directory>
volatility -f <memory_dump> memdump -o <offset> -s <size> -D <output_directory>
```

#### Driver Analysis

```bash
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
volatility -f <memory_dump> driverscan
```

#### Other Analysis

```bash
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> ldrmodules
volatility -f <memory_dump> modscan
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> ssdt
```

## Volatility Profiles

### Linux

```bash
volatility --info | grep Linux
```

### Windows

```bash
volatility --info | grep Win
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
### UserAssist

Los sistemas **Windows** mantienen un conjunto de **claves** en la base de datos del registro (**claves UserAssist**) para realizar un seguimiento de los programas que se ejecutan. El número de ejecuciones y la fecha y hora de la última ejecución están disponibles en estas **claves**.
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
volatility -f <memory_dump> filescan
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
volatility -f <memory_dump> malfind
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> ldrmodules
volatility -f <memory_dump> modscan
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> handles
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> ssdt
volatility -f <memory_dump> driverscan
volatility -f <memory_dump> fileinfo -D <directory> -S <suffix>
volatility -f <memory_dump> dumpfiles -Q <file_offset> -u <file_size> -n <file_name> -f <output_directory>
volatility -f <memory_dump> memdump -p <pid> -D <directory> -u <user_space_address> -s <user_space_size>
```

### Advanced Commands

```bash
volatility -f <memory_dump> --profile=<profile> <plugin> <plugin_options>
```

### Plugins

#### Malware Analysis

```bash
volatility -f <memory_dump> malfind
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> ldrmodules
volatility -f <memory_dump> modscan
```

#### Process Analysis

```bash
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
```

#### Network Analysis

```bash
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
```

#### Registry Analysis

```bash
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
```

#### File Analysis

```bash
volatility -f <memory_dump> filescan
volatility -f <memory_dump> fileinfo -D <directory> -S <suffix>
volatility -f <memory_dump> dumpfiles -Q <file_offset> -u <file_size> -n <file_name> -f <output_directory>
```

#### Memory Analysis

```bash
volatility -f <memory_dump> memdump -p <pid> -D <directory> -u <user_space_address> -s <user_space_size>
```

#### Other Analysis

```bash
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> handles
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> ssdt
volatility -f <memory_dump> driverscan
```

## Volatility Profiles

### Linux

```bash
volatility --info | grep Linux
```

### Windows

```bash
volatility --info | grep Win
```

## Volatility Plugins

### Malware Analysis

#### malfind

```bash
volatility -f <memory_dump> malfind
```

#### apihooks

```bash
volatility -f <memory_dump> apihooks
```

#### ldrmodules

```bash
volatility -f <memory_dump> ldrmodules
```

#### modscan

```bash
volatility -f <memory_dump> modscan
```

### Process Analysis

#### pslist

```bash
volatility -f <memory_dump> pslist
```

#### pstree

```bash
volatility -f <memory_dump> pstree
```

#### psscan

```bash
volatility -f <memory_dump> psscan
```

### Network Analysis

#### netscan

```bash
volatility -f <memory_dump> netscan
```

#### connscan

```bash
volatility -f <memory_dump> connscan
```

#### sockets

```bash
volatility -f <memory_dump> sockets
```

### Registry Analysis

#### hivelist

```bash
volatility -f <memory_dump> hivelist
```

#### hivedump

```bash
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
```

#### printkey

```bash
volatility -f <memory_dump> printkey -K <key>
```

#### dumpregistry

```bash
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
```

### File Analysis

#### filescan

```bash
volatility -f <memory_dump> filescan
```

#### fileinfo

```bash
volatility -f <memory_dump> fileinfo -D <directory> -S <suffix>
```

#### dumpfiles

```bash
volatility -f <memory_dump> dumpfiles -Q <file_offset> -u <file_size> -n <file_name> -f <output_directory>
```

### Memory Analysis

#### memdump

```bash
volatility -f <memory_dump> memdump -p <pid> -D <directory> -u <user_space_address> -s <user_space_size>
```

### Other Analysis

#### getsids

```bash
volatility -f <memory_dump> getsids
```

#### getservicesids

```bash
volatility -f <memory_dump> getservicesids
```

#### handles

```bash
volatility -f <memory_dump> handles
```

#### mutantscan

```bash
volatility -f <memory_dump> mutantscan
```

#### driverirp

```bash
volatility -f <memory_dump> driverirp
```

#### devicetree

```bash
volatility -f <memory_dump> devicetree
```

#### callbacks

```bash
volatility -f <memory_dump> callbacks
```

#### idt

```bash
volatility -f <memory_dump> idt
```

#### gdt

```bash
volatility -f <memory_dump> gdt
```

#### ssdt

```bash
volatility -f <memory_dump> ssdt
```

#### driverscan

```bash
volatility -f <memory_dump> driverscan
```
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con la misión de promover el conocimiento técnico, este congreso es un punto de encuentro para profesionales de la tecnología y la ciberseguridad en todas las disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## Servicios
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> handles
volatility -f <memory_dump> filescan
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> privs
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> userassist
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> malfind
volatility -f <memory_dump> mftparser
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> printkey
volatility -f <memory_dump> hashdump
volatility -f <memory_dump> envars
volatility -f <memory_dump> dumpregistry
volatility -f <memory_dump> dumpfiles
volatility -f <memory_dump> memdump
```

### Advanced Commands

```bash
volatility -f <memory_dump> --profile=<profile> <plugin> <options>
```

### Plugins

#### Malware Analysis

```bash
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malfind -Y <path_to_yara_rules>
volatility -f <memory_dump> malfind -D <path_to_dump_directory>
volatility -f <memory_dump> malfind -p <pid>
volatility -f <memory_dump> malfind -u <user>
volatility -f <memory_dump> malfind -P <process_name>
volatility -f <memory_dump> malfind -Y <path_to_yara_rules> -D <path_to_dump_directory> -p <pid> -u <user> -P <process_name>
```

```bash
volatility -f <memory_dump> mftparser
volatility -f <memory_dump> mftparser -o <output_directory>
volatility -f <memory_dump> mftparser -f <filename>
volatility -f <memory_dump> mftparser -o <output_directory> -f <filename>
```

#### Registry Analysis

```bash
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivelist -o <output_directory>
volatility -f <memory_dump> hivelist -o <output_directory> -p <pid>
```

```bash
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> printkey -K <key> -o <output_directory>
volatility -f <memory_dump> printkey -K <key> -o <output_directory> -p <pid>
```

```bash
volatility -f <memory_dump> hashdump -s <system_hive> -s <software_hive>
volatility -f <memory_dump> hashdump -s <system_hive> -s <software_hive> -o <output_directory>
volatility -f <memory_dump> hashdump -s <system_hive> -s <software_hive> -o <output_directory> -p <pid>
```

#### Network Analysis

```bash
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
```

#### Process Analysis

```bash
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> handles
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> privs
volatility -f <memory_dump> apihooks
```

#### File Analysis

```bash
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> filescan
volatility -f <memory_dump> dumpfiles -Q <file_path>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> -p <pid>
```

#### Memory Analysis

```bash
volatility -f <memory_dump> memdump -p <pid>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir=<dump_directory>
```

#### Other

```bash
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> userassist
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> envars
volatility -f <memory_dump> dumpregistry
```

## Volatility Profiles

### Linux

```bash
volatility --info | grep Linux
```

### Windows

```bash
volatility --info | grep Win
```

## Volatility Plugins

### Malware Analysis

#### malfind

Finds hidden and injected code in memory.

```bash
volatility -f <memory_dump> malfind
```

#### mftparser

Parses the Master File Table (MFT) and outputs information about files and directories.

```bash
volatility -f <memory_dump> mftparser
```

### Registry Analysis

#### hivelist

Lists the registry hives in memory.

```bash
volatility -f <memory_dump> hivelist
```

#### printkey

Prints the values of a registry key.

```bash
volatility -f <memory_dump> printkey -K <key>
```

#### hashdump

Dumps the password hashes from the SAM and SYSTEM registry hives.

```bash
volatility -f <memory_dump> hashdump -s <system_hive> -s <software_hive>
```

### Network Analysis

#### netscan

Lists the open network connections.

```bash
volatility -f <memory_dump> netscan
```

#### connscan

Lists the network connections.

```bash
volatility -f <memory_dump> connscan
```

### Process Analysis

#### pslist

Lists the running processes.

```bash
volatility -f <memory_dump> pslist
```

#### pstree

Lists the running processes in a tree format.

```bash
volatility -f <memory_dump> pstree
```

#### psscan

Scans for hidden and terminated processes.

```bash
volatility -f <memory_dump> psscan
```

#### handles

Lists the open handles for each process.

```bash
volatility -f <memory_dump> handles
```

#### cmdline

Lists the command line arguments for each process.

```bash
volatility -f <memory_dump> cmdline
```

#### consoles

Lists the open consoles for each process.

```bash
volatility -f <memory_dump> consoles
```

#### getsids

Lists the security identifiers (SIDs) for each process.

```bash
volatility -f <memory_dump> getsids
```

#### getservicesids

Lists the SIDs for each service.

```bash
volatility -f <memory_dump> getservicesids
```

#### privs

Lists the privileges for each process.

```bash
volatility -f <memory_dump> privs
```

#### apihooks

Lists the API hooks for each process.

```bash
volatility -f <memory_dump> apihooks
```

### File Analysis

#### dlllist

Lists the loaded DLLs for each process.

```bash
volatility -f <memory_dump> dlllist
```

#### filescan

Scans for open files.

```bash
volatility -f <memory_dump> filescan
```

#### dumpfiles

Dumps a file from memory.

```bash
volatility -f <memory_dump> dumpfiles -Q <file_path>
```

### Memory Analysis

#### memdump

Dumps the memory of a process.

```bash
volatility -f <memory_dump> memdump -p <pid>
```

### Other

#### shimcache

Lists the entries in the Application Compatibility Shim Cache.

```bash
volatility -f <memory_dump> shimcache
```

#### userassist

Lists the UserAssist entries.

```bash
volatility -f <memory_dump> userassist
```

#### idt

Lists the Interrupt Descriptor Table (IDT) entries.

```bash
volatility -f <memory_dump> idt
```

#### gdt

Lists the Global Descriptor Table (GDT) entries.

```bash
volatility -f <memory_dump> gdt
```

#### envars

Lists the environment variables.

```bash
volatility -f <memory_dump> envars
```

#### dumpregistry

Dumps the registry hives.

```bash
volatility -f <memory_dump> dumpregistry
```
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
{% endtab %}
{% tab title="volatility" %}
# Volatility Cheatsheet

## Volatility Basics

### Image Identification

- `imageinfo`: Identify information about the memory image, such as the operating system version, service pack, and profile.

### Process and DLL Enumeration

- `pslist`: List all running processes.
- `psscan`: Scan for processes in the memory image.
- `pstree`: Display the process list as a tree.
- `dlllist`: List all loaded DLLs for each process.
- `ldrmodules`: List all loaded modules (including DLLs) for each process.

### Process Memory Analysis

- `memdump`: Dump the memory of a process to a file.
- `memmap`: Display the memory map for a process.
- `memstrings`: Extract printable and non-printable strings from process memory.

### Malware Analysis

- `malfind`: Find hidden and injected code in process memory.
- `apihooks`: Detect API hooks in process memory.
- `svcscan`: List all Windows services and their corresponding processes.
- `svcscan -t`: List all Windows services and their corresponding processes, including terminated processes.

### Network Analysis

- `connscan`: List all open network connections.
- `sockets`: List all open sockets.
- `sockscan`: Scan for open sockets in the memory image.

### Registry Analysis

- `printkey`: Print the values of a registry key.
- `hivelist`: List the registry hives in the memory image.
- `hivedump`: Dump a registry hive to a file.

### Filesystem Analysis

- `filescan`: Scan for file objects in the memory image.
- `filescan -f filename`: Search for a specific file in the memory image.
- `dumpfiles`: Extract files from the memory image.

## Volatility Plugins

### Malware Analysis

- `malfind`: Find hidden and injected code in process memory.
- `apihooks`: Detect API hooks in process memory.
- `svcscan`: List all Windows services and their corresponding processes.
- `svcscan -t`: List all Windows services and their corresponding processes, including terminated processes.
- `ldrmodules`: List all loaded modules (including DLLs) for each process.
- `modscan`: Scan for loaded kernel modules.
- `moddump`: Dump a loaded kernel module to a file.
- `driverirp`: List all IRP handlers for loaded kernel drivers.
- `ssdt`: List the System Service Descriptor Table (SSDT) entries.
- `idt`: List the Interrupt Descriptor Table (IDT) entries.
- `gdt`: List the Global Descriptor Table (GDT) entries.
- `callbacks`: List the registered kernel callbacks.
- `timers`: List the kernel timers.
- `atomscan`: List the global and session atom tables.
- `atomscan -s`: List the global and session atom tables, including deleted atoms.
- `deskscan`: List the desktops and their corresponding windows.
- `wndscan`: List the windows and their corresponding processes.
- `thrdscan`: List the threads and their corresponding processes.
- `handles`: List the open handles for each process.
- `getsids`: List the Security Identifiers (SIDs) for each process.
- `privs`: List the privileges for each process.
- `psxview`: Detect process hiding techniques.
- `cmdline`: List the command line arguments for each process.
- `consoles`: List the open console handles for each process.
- `shimcache`: List the entries in the Application Compatibility Cache.
- `shimcache -s`: List the entries in the Application Compatibility Cache, including deleted entries.
- `mftparser`: Parse the Master File Table (MFT) entries.
- `usnjrnl`: Parse the Update Sequence Number Journal (USN Journal) entries.
- `printkey`: Print the values of a registry key.
- `hivelist`: List the registry hives in the memory image.
- `hivedump`: Dump a registry hive to a file.
- `dumpregistry`: Dump the entire registry to a file.
- `dumpregistry -H hive`: Dump a specific registry hive to a file.
- `dumpregistry -K key`: Dump a specific registry key to a file.
- `dumpregistry -o offset`: Dump a specific registry key at a specific offset to a file.
- `filescan`: Scan for file objects in the memory image.
- `filescan -f filename`: Search for a specific file in the memory image.
- `dumpfiles`: Extract files from the memory image.
- `dumpfiles -Q offset,size`: Extract a file at a specific offset and size from the memory image.
- `dumpfiles -D directory`: Extract all files from the memory image to a directory.
- `dumpfiles -r directory`: Recursively extract all files from the memory image to a directory.
- `dumpfiles -U`: Uniquely name extracted files.
- `dumpfiles -u`: Uniquely name extracted files and include the original path.

### Network Analysis

- `connscan`: List all open network connections.
- `sockets`: List all open sockets.
- `sockscan`: Scan for open sockets in the memory image.
- `netscan`: List all network connections and their corresponding processes.
- `connscan -p pid`: List all network connections for a specific process.
- `connscan -P protocol`: List all network connections for a specific protocol.
- `connscan -s state`: List all network connections in a specific state.
- `connscan -S srcip`: List all network connections with a specific source IP address.
- `connscan -S srcip:srcport`: List all network connections with a specific source IP address and port.
- `connscan -S srcip/24`: List all network connections with a specific source IP address range.
- `connscan -D dstip`: List all network connections with a specific destination IP address.
- `connscan -D dstip:dstport`: List all network connections with a specific destination IP address and port.
- `connscan -D dstip/24`: List all network connections with a specific destination IP address range.
- `connscan -r`: Resolve IP addresses to hostnames.
- `connscan -v`: Verbose output.
- `pcap`: Generate a PCAP file of network traffic.
- `pcap -p pid`: Generate a PCAP file of network traffic for a specific process.
- `pcap -f "filter"`: Generate a PCAP file of network traffic using a specific BPF filter.

### Memory Analysis

- `memdump`: Dump the memory of a process to a file.
- `memmap`: Display the memory map for a process.
- `memstrings`: Extract printable and non-printable strings from process memory.
- `memdump -p pid`: Dump the memory of a specific process to a file.
- `memdump -D directory`: Dump the memory of all processes to a directory.
- `memdump -r directory`: Recursively dump the memory of all processes to a directory.
- `memdump -u`: Uniquely name dumped memory files.
- `memdump -U`: Uniquely name dumped memory files and include the process name.
- `memdump -s startaddr:endaddr`: Dump a specific memory range to a file.
- `memdump -R regex`: Dump the memory of processes whose name matches a regular expression to a file.
- `memdump -i imagebase`: Dump the memory of processes whose image base matches a value to a file.
- `memdump -c`: Compress dumped memory files.
- `memdump -C`: Compress dumped memory files and delete the original files.
- `vaddump`: Dump the virtual address space of a process to a file.
- `vadinfo`: Display information about the Virtual Address Descriptor (VAD) tree for a process.
- `vadtree`: Display the Virtual Address Descriptor (VAD) tree for a process.
- `vadwalk`: Walk the Virtual Address Descriptor (VAD) tree for a process.
- `vadwalk -p pid`: Walk the Virtual Address Descriptor (VAD) tree for a specific process.
- `vadwalk -s startaddr:endaddr`: Walk the Virtual Address Descriptor (VAD) tree for a specific memory range.
- `vadtree -s startaddr:endaddr`: Display the Virtual Address Descriptor (VAD) tree for a specific memory range.
- `vadtree -v`: Verbose output.
- `vadtree -u`: Display only unique VAD nodes.
- `vadtree -U`: Display only unique VAD nodes and include the process name.
- `vadtree -r`: Resolve file names for VAD nodes.
- `vadtree -R`: Resolve file names for VAD nodes and include the process name.
- `vadtree -f`: Display only VAD nodes with file objects.
- `vadtree -F`: Display only VAD nodes with file objects and include the process name.
- `vadtree -m`: Display only VAD nodes with mapped sections.
- `vadtree -M`: Display only VAD nodes with mapped sections and include the process name.
- `vadtree -n`: Display only VAD nodes with no mapped sections.
- `vadtree -N`: Display only VAD nodes with no mapped sections and include the process name.
- `vadtree -p`: Display only VAD nodes with private memory.
- `vadtree -P`: Display only VAD nodes with private memory and include the process name.
- `vadtree -s`: Display only VAD nodes with shared memory.
- `vadtree -S`: Display only VAD nodes with shared memory and include the process name.
- `vadtree -x`: Display only VAD nodes with executable memory.
- `vadtree -X`: Display only VAD nodes with executable memory and include the process name.
- `vadtree -w`: Display only VAD nodes with writeable memory.
- `vadtree -W`: Display only VAD nodes with writeable memory and include the process name.
- `vadtree -r`: Resolve file names for VAD nodes.
- `vadtree -R`: Resolve file names for VAD nodes and include the process name.
- `vadtree -v`: Verbose output.
- `vadtree -u`: Display only unique VAD nodes.
- `vadtree -U`: Display only unique VAD nodes and include the process name.
- `vadtree -h`: Display help.

### Windows Registry Analysis

- `printkey`: Print the values of a registry key.
- `hivelist`: List the registry hives in the memory image.
- `hivedump`: Dump a registry hive to a file.
- `dumpregistry`: Dump the entire registry to a file.
- `dumpregistry -H hive`: Dump a specific registry hive to a file.
- `dumpregistry -K key`: Dump a specific registry key to a file.
- `dumpregistry -o offset`: Dump a specific registry key at a specific offset to a file.
- `userassist`: List the UserAssist keys and their corresponding programs.
- `userassist -p`: List the UserAssist keys and their corresponding programs, including deleted keys.
- `userassist -U`: Decode the ROT13-encoded UserAssist keys.
- `userassist -c`: Count the number of times each program was executed.
- `userassist -v`: Verbose output.
- `shellbags`: List the ShellBags keys and their corresponding folders.
- `shellbags -p`: List the ShellBags keys and their corresponding folders, including deleted keys.
- `shellbags -v`: Verbose output.
- `shimcache`: List the entries in the Application Compatibility Cache.
- `shimcache -s`: List the entries in the Application Compatibility Cache, including deleted entries.
- `shimcache -v`: Verbose output.
- `prefetch`: List the entries in the Prefetch folder.
- `prefetch -p`: List the entries in the Prefetch folder, including deleted entries.
- `prefetch -v`: Verbose output.
- `mftparser`: Parse the Master File Table (MFT) entries.
- `usnjrnl`: Parse the Update Sequence Number Journal (USN Journal) entries.
- `iehistory`: List the Internet Explorer browsing history.
- `iehistory -p`: List the Internet Explorer browsing history, including deleted entries.
- `iehistory -v`: Verbose output.
- `cmdscan`: List the commands executed on the command line.
- `cmdscan -p`: List the commands executed on the command line, including deleted entries.
- `cmdscan -v`: Verbose output.
- `consoles`: List the open console handles for each process.
- `consoles -p pid`: List the open console handles for a specific process.
- `consoles -v`: Verbose output.
- `mbrparser`: Parse the Master Boot Record (MBR).
- `partitions`: List the partition table entries.
- `partitions -v`: Verbose output.
- `yarascan`: Scan for a YARA rule in the memory image.
- `yarascan -r rulefile`: Scan for a YARA rule in the memory image using a rule file.
- `yarascan -s`: Scan for a YARA rule in the memory image using the default YARA rules.
- `yarascan -v`: Verbose output.

### Linux Analysis

- `linux_pslist`: List all running processes.
- `linux_pstree`: Display the process list as a tree.
- `linux_proc_maps`: Display the memory map for a process.
- `linux_proc_maps -p pid`: Display the memory map for a specific process.
- `linux_proc_maps -D directory`: Display the memory map for all processes to a directory.
- `linux_proc_maps -r directory`: Recursively display the memory map for all processes to a directory.
- `linux_proc_maps -s startaddr:endaddr`: Display the memory map for a specific memory range.
- `linux_proc_maps -R regex`: Display the memory map for processes whose name matches a regular expression.
- `linux_proc_maps -i imagebase`: Display the memory map for processes whose image base matches a value.
- `linux_proc_maps -v`: Verbose output.
- `linux_psaux`: List all running processes with additional information.
- `linux_pstree`: Display the process list as a tree.
- `linux_lsof`: List all open files for each process.
- `linux_netstat`: List all open network connections.
- `linux_ifconfig`: List all network interfaces and their corresponding IP addresses.
- `linux_route`: List the routing table.
- `linux_mount`: List the mounted filesystems.
- `linux_lsmod`: List the loaded kernel modules.
- `linux_dmesg`: Display the kernel ring buffer.
- `linux_last`: List the last logged in users.
- `linux_w`: List the currently logged in users.
- `linux_who`: List the currently logged in users.
- `linux_psxview`: Detect process hiding techniques.
- `linux_check_afinfo`: Check for vulnerabilities in the Address Family Information (AFINFO) cache.
- `linux_check_creds`: Check for vulnerabilities in the kernel credentials.
- `linux_check_syslog`: Check for vulnerabilities in the syslog buffer.
- `linux_check_tty`: Check for vulnerabilities in the TTY layer.
- `linux_check_wtmp`: Check for vulnerabilities in the wtmp file.
- `linux_check_cgroups`: Check for vulnerabilities in the Control Groups (cgroups) filesystem.
- `linux_check_fop`: Check for vulnerabilities in the File Operations (f_op) structure.
- `linux_check_idt`: Check for vulnerabilities in the Interrupt Descriptor Table (IDT).
- `linux_check_slab`: Check for vulnerabilities in the slab allocator.
- `linux_check_tcache`: Check for vulnerabilities in the Thread-Cache (tcache) allocator.
- `linux_check_vdso`: Check for vulnerabilities in the Virtual Dynamic Shared Object (vDSO).
- `linux_check_vsyscall`: Check for vulnerabilities in the Virtual System Call (vsyscall) page.
- `linux_check_syscall`: Check for vulnerabilities in the syscall table.
- `linux_check_kptr_restrict`: Check if the kernel pointer hiding feature is enabled.
- `linux_check_selinux`: Check if SELinux is enabled.
- `linux_check_apparmor`: Check if AppArmor is enabled.
- `linux_check_grsec`: Check if Grsecurity is enabled.
- `linux_check_pax`: Check if PaX is enabled.
- `linux_check_yama`: Check if Yama is enabled.
- `linux_check_auditd`: Check if the audit daemon is running.
- `linux_check_sysctl`: Check for insecure sysctl settings.
- `linux_check_kernel_config`: Check for insecure kernel configuration settings.
- `linux_check_kernel`: Check for known kernel vulnerabilities.
- `linux_check_all`: Check for all known Linux vulnerabilities.
- `linux_yarascan`: Scan for a YARA rule in the memory image.
- `linux_yarascan -r rulefile`: Scan for a YARA rule in the memory image using a rule file.
- `linux_yarascan -s`: Scan for a YARA rule in the memory image using the default YARA rules.
- `linux_yarascan -v`: Verbose output.

### Mac OS X Analysis

- `mac_pslist`: List all running processes.
- `mac_pstree`: Display the process list as a tree.
- `mac_proc_maps`: Display the memory map for a process.
- `mac_proc_maps -p pid`: Display the memory map for a specific process.
- `mac_proc_maps -D directory`: Display the memory map for all processes to a directory.
- `mac_proc_maps -r directory`: Recursively display the memory map for all processes to a directory.
- `mac_proc_maps -s startaddr:endaddr`: Display the memory map for a specific memory range.
- `mac_proc_maps -R regex`: Display the memory map for processes whose name matches a regular expression.
- `mac_proc_maps -i imagebase`: Display the memory map for processes whose image base matches a value.
- `mac_proc_maps -v`: Verbose output.
- `mac_psaux`: List all running processes with additional information.
- `mac_pstree`: Display the process list as a tree.
- `mac_lsof`:
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> handles
volatility -f <memory_dump> filescan
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> privs
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> userassist
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> malfind
volatility -f <memory_dump> mftparser
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> printkey
volatility -f <memory_dump> hashdump
volatility -f <memory_dump> envars
volatility -f <memory_dump> dumpregistry
volatility -f <memory_dump> dumpfiles
volatility -f <memory_dump> memdump
```

### Advanced Commands

```bash
volatility -f <memory_dump> --profile=<profile> <plugin> <options>
```

### Plugins

#### Process Related

```bash
pslist
pstree
psscan
```

#### Network Related

```bash
netscan
connscan
```

#### DLL Related

```bash
dlllist
handles
```

#### File Related

```bash
filescan
```

#### Memory Related

```bash
memdump
```

#### Registry Related

```bash
hivelist
printkey
hashdump
envars
dumpregistry
```

#### Malware Related

```bash
malfind
mftparser
```

#### Other

```bash
cmdline
consoles
getsids
getservicesids
privs
apihooks
idt
gdt
userassist
shimcache
dumpfiles
```

### Memory Dump Acquisition

#### Linux

```bash
sudo cat /proc/kcore > /path/to/memory_dump
```

#### Windows

Use [Mimikatz](https://github.com/gentilkiwi/mimikatz) or [DumpIt](https://github.com/jschicht/DumpIt) to acquire the memory dump.

### Memory Dump Analysis

#### Profile Selection

```bash
volatility -f <memory_dump> imageinfo
```

#### Process Analysis

```bash
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
```

#### Network Analysis

```bash
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
```

#### DLL Analysis

```bash
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> handles
```

#### File Analysis

```bash
volatility -f <memory_dump> filescan
```

#### Memory Analysis

```bash
volatility -f <memory_dump> memdump
```

#### Registry Analysis

```bash
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> printkey
volatility -f <memory_dump> hashdump
volatility -f <memory_dump> envars
volatility -f <memory_dump> dumpregistry
```

#### Malware Analysis

```bash
volatility -f <memory_dump> malfind
volatility -f <memory_dump> mftparser
```

#### Other Analysis

```bash
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> privs
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> userassist
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> dumpfiles
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
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
{% endtab %}
{% endtabs %}

## Registro del sistema

### Imprimir los registros disponibles

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% endtab %}
{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> handles
volatility -f <memory_dump> filescan
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> getsids
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> printkey
volatility -f <memory_dump> dumpregistry -D <output_directory> -K <registry_key>
volatility -f <memory_dump> malfind
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> ldrmodules
volatility -f <memory_dump> modscan
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> svcscan
volatility -f <memory_dump> thrdscan
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> userassist
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> prefetchparser
volatility -f <memory_dump> hibinfo
volatility -f <memory_dump> hiblist
volatility -f <memory_dump> hibdump -o <offset> -L <length> -D <output_directory>
```

### Advanced Commands

```bash
volatility -f <memory_dump> --profile=<profile> <plugin> <plugin_options>
```

### Plugins

#### Malware Analysis

```bash
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malfind -Y <malware_directory>
volatility -f <memory_dump> malfind -D <output_directory>
volatility -f <memory_dump> malfind -p <pid>
volatility -f <memory_dump> malfind -u
volatility -f <memory_dump> malfind -U
volatility -f <memory_dump> malfind -Y <malware_directory> -p <pid>
volatility -f <memory_dump> malfind -Y <malware_directory> -u
volatility -f <memory_dump> malfind -Y <malware_directory> -U
volatility -f <memory_dump> malfind -D <output_directory> -p <pid>
volatility -f <memory_dump> malfind -D <output_directory> -u
volatility -f <memory_dump> malfind -D <output_directory> -U
volatility -f <memory_dump> malfind -D <output_directory> -Y <malware_directory>
volatility -f <memory_dump> malfind -D <output_directory> -Y <malware_directory> -p <pid>
volatility -f <memory_dump> malfind -D <output_directory> -Y <malware_directory> -u
volatility -f <memory_dump> malfind -D <output_directory> -Y <malware_directory> -U
```

#### Registry Analysis

```bash
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> printkey -K <registry_key>
volatility -f <memory_dump> dumpregistry -D <output_directory> -K <registry_key>
```

#### Network Analysis

```bash
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
```

#### Process Analysis

```bash
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> handles
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> getsids
```

#### File Analysis

```bash
volatility -f <memory_dump> filescan
volatility -f <memory_dump> dlllist
```

#### Memory Analysis

```bash
volatility -f <memory_dump> vadinfo
volatility -f <memory_dump> vadtree
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
volatility -f <memory_dump> memdump -p <pid> -o <offset> -L <length> -D <output_directory>
```

#### Service Analysis

```bash
volatility -f <memory_dump> svcscan
```

#### Driver Analysis

```bash
volatility -f <memory_dump> modscan
```

#### User Analysis

```bash
volatility -f <memory_dump> userassist
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> prefetchparser
```

#### Other Analysis

```bash
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> thrdscan
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> ldrmodules
volatility -f <memory_dump> hibinfo
volatility -f <memory_dump> hiblist
volatility -f <memory_dump> hibdump -o <offset> -L <length> -D <output_directory>
```

## Volatility Profiles

### Linux

```bash
volatility --info | grep Linux
```

### Windows

```bash
volatility --info | grep Win
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
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

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
volatility -f <memory_dump> filescan
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
volatility -f <memory_dump> malfind
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> ldrmodules
volatility -f <memory_dump> modscan
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> handles
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> ssdt
volatility -f <memory_dump> driverscan
volatility -f <memory_dump> fileinfo -D <directory> -S <suffix>
volatility -f <memory_dump> dumpfiles -Q <file_offset> -u <file_size> -n <file_name> -f <output_directory>
volatility -f <memory_dump> memdump -p <pid> -D <directory> -u <user_space_address> -s <user_space_size>
```

### Advanced Commands

```bash
volatility -f <memory_dump> --profile=<profile> <plugin> <plugin_options>
```

### Plugins

#### Malware Analysis

```bash
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malsysproc
volatility -f <memory_dump> malprocfind
volatility -f <memory_dump> maldrivers
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malheap
volatility -f <memory_dump> malpscan
volatility -f <memory_dump> malwaredetect
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> ldrmodules
volatility -f <memory_dump> modscan
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> callbacks
```

#### Memory Analysis

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
volatility -f <memory_dump> filescan
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> ssdt
volatility -f <memory_dump> driverscan
volatility -f <memory_dump> fileinfo -D <directory> -S <suffix>
volatility -f <memory_dump> dumpfiles -Q <file_offset> -u <file_size> -n <file_name> -f <output_directory>
volatility -f <memory_dump> memdump -p <pid> -D <directory> -u <user_space_address> -s <user_space_size>
```

#### Network Analysis

```bash
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
```

#### Process Analysis

```bash
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> psxview
volatility -f <memory_dump> cmdscan
volatility -f <memory_dump> consoles
volatility -f <memory_dump> consoles -p <pid>
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> handles
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
```

#### Registry Analysis

```bash
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
```

#### System Information

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> kdbgscan
volatility -f <memory_dump> kpcrscan
volatility -f <memory_dump> kpcrspace
volatility -f <memory_dump> kdtree
volatility -f <memory_dump> kpcr
volatility -f <memory_dump> kpcr -p <pid>
volatility -f <memory_dump> kpcr -t <thread>
volatility -f <memory_dump> kpcr -c <cpu>
volatility -f <memory_dump> kpcr -a <address>
volatility -f <memory_dump> kpcr -s <symbol>
volatility -f <memory_dump> kpcr -l <level>
volatility -f <memory_dump> kpcr -d <debugger>
volatility -f <memory_dump> kpcr -o <output>
volatility -f <memory_dump> kpcr -v
volatility -f <memory_dump> kpcr -h
volatility -f <memory_dump> kpcr -V
volatility -f <memory_dump> kpcr -H
volatility -f <memory_dump> kpcr -D
volatility -f <memory_dump> kpcr -O
volatility -f <memory_dump> kpcr -S
volatility -f <memory_dump> kpcr -L
volatility -f <memory_dump> kpcr -C
volatility -f <memory_dump> kpcr -A
volatility -f <memory_dump> kpcr -T
volatility -f <memory_dump> kpcr -P
volatility -f <memory_dump> kpcr -K
volatility -f <memory_dump> kpcr -U
volatility -f <memory_dump> kpcr -I
volatility -f <memory_dump> kpcr -E
volatility -f <memory_dump> kpcr -F
volatility -f <memory_dump> kpcr -G
volatility -f <memory_dump> kpcr -B
volatility -f <memory_dump> kpcr -R
volatility -f <memory_dump> kpcr -N
volatility -f <memory_dump> kpcr -M
volatility -f <memory_dump> kpcr -Q
volatility -f <memory_dump> kpcr -W
volatility -f <memory_dump> kpcr -X
volatility -f <memory_dump> kpcr -Y
volatility -f <memory_dump> kpcr -Z
volatility -f <memory_dump> kpcr -j
volatility -f <memory_dump> kpcr -i
volatility -f <memory_dump> kpcr -e
volatility -f <memory_dump> kpcr -f
volatility -f <memory_dump> kpcr -g
volatility -f <memory_dump> kpcr -w
volatility -f <memory_dump> kpcr -x
volatility -f <memory_dump> kpcr -y
volatility -f <memory_dump> kpcr -z
volatility -f <memory_dump> kpcr -q
volatility -f <memory_dump> kpcr -r
volatility -f <memory_dump> kpcr -n
volatility -f <memory_dump> kpcr -m
volatility -f <memory_dump> kpcr -u
volatility -f <memory_dump> kpcr -b
volatility -f <memory_dump> kpcr -s
volatility -f <memory_dump> kpcr -d
volatility -f <memory_dump> kpcr -o
volatility -f <memory_dump> kpcr -v
volatility -f <memory_dump> kpcr -h
volatility -f <memory_dump> kpcr -V
volatility -f <memory_dump> kpcr -H
volatility -f <memory_dump> kpcr -D
volatility -f <memory_dump> kpcr -O
volatility -f <memory_dump> kpcr -S
volatility -f <memory_dump> kpcr -L
volatility -f <memory_dump> kpcr -C
volatility -f <memory_dump> kpcr -A
volatility -f <memory_dump> kpcr -T
volatility -f <memory_dump> kpcr -P
volatility -f <memory_dump> kpcr -K
volatility -f <memory_dump> kpcr -U
volatility -f <memory_dump> kpcr -I
volatility -f <memory_dump> kpcr -E
volatility -f <memory_dump> kpcr -F
volatility -f <memory_dump> kpcr -G
volatility -f <memory_dump> kpcr -B
volatility -f <memory_dump> kpcr -R
volatility -f <memory_dump> kpcr -N
volatility -f <memory_dump> kpcr -M
volatility -f <memory_dump> kpcr -Q
volatility -f <memory_dump> kpcr -W
volatility -f <memory_dump> kpcr -X
volatility -f <memory_dump> kpcr -Y
volatility -f <memory_dump> kpcr -Z
volatility -f <memory_dump> kpcr -j
volatility -f <memory_dump> kpcr -i
volatility -f <memory_dump> kpcr -e
volatility -f <memory_dump> kpcr -f
volatility -f <memory_dump> kpcr -g
volatility -f <memory_dump> kpcr -w
volatility -f <memory_dump> kpcr -x
volatility -f <memory_dump> kpcr -y
volatility -f <memory_dump> kpcr -z
volatility -f <memory_dump> kpcr -q
volatility -f <memory_dump> kpcr -r
volatility -f <memory_dump> kpcr -n
volatility -f <memory_dump> kpcr -m
volatility -f <memory_dump> kpcr -u
volatility -f <memory_dump> kpcr -b
volatility -f <memory_dump> kpcr -s
volatility -f <memory_dump> kpcr -d
volatility -f <memory_dump> kpcr -o
volatility -f <memory_dump> kpcr -v
volatility -f <memory_dump> kpcr -h
volatility -f <memory_dump> kpcr -V
volatility -f <memory_dump> kpcr -H
volatility -f <memory_dump> kpcr -D
volatility -f <memory_dump> kpcr -O
volatility -f <memory_dump> kpcr -S
volatility -f <memory_dump> kpcr -L
volatility -f <memory_dump> kpcr -C
volatility -f <memory_dump> kpcr -A
volatility -f <memory_dump> kpcr -T
volatility -f <memory_dump> kpcr -P
volatility -f <memory_dump> kpcr -K
volatility -f <memory_dump> kpcr -U
volatility -f <memory_dump> kpcr -I
volatility -f <memory_dump> kpcr -E
volatility -f <memory_dump> kpcr -F
volatility -f <memory_dump> kpcr -G
volatility -f <memory_dump> kpcr -B
volatility -f <memory_dump> kpcr -R
volatility -f <memory_dump> kpcr -N
volatility -f <memory_dump> kpcr -M
volatility -f <memory_dump> kpcr -Q
volatility -f <memory_dump> kpcr -W
volatility -f <memory_dump> kpcr -X
volatility -f <memory_dump> kpcr -Y
volatility -f <memory_dump> kpcr -Z
volatility -f <memory_dump> kpcr -j
volatility -f <memory_dump> kpcr -i
volatility -f <memory_dump> kpcr -e
volatility -f <memory_dump> kpcr -f
volatility -f <memory_dump> kpcr -g
volatility -f <memory_dump> kpcr -w
volatility -f <memory_dump> kpcr -x
volatility -f <memory_dump> kpcr -y
volatility -f <memory_dump> kpcr -z
volatility -f <memory_dump> kpcr -q
volatility -f <memory_dump> kpcr -r
volatility -f <memory_dump> kpcr -n
volatility -f <memory_dump> kpcr -m
volatility -f <memory_dump> kpcr -u
volatility -f <memory_dump> kpcr -b
volatility -f <memory_dump> kpcr -s
volatility -f <memory_dump> kpcr -d
volatility -f <memory_dump> kpcr -o
volatility -f <memory_dump> kpcr -v
volatility -f <memory_dump> kpcr -h
volatility -f <memory_dump> kpcr -V
volatility -f <memory_dump> kpcr -H
volatility -f <memory_dump> kpcr -D
volatility -f <memory_dump> kpcr -O
volatility -f <memory_dump> kpcr -S
volatility -f <memory_dump> kpcr -L
volatility -f <memory_dump> kpcr -C
volatility -f <memory_dump> kpcr -A
volatility -f <memory_dump> kpcr -T
volatility -f <memory_dump> kpcr -P
volatility -f <memory_dump> kpcr -K
volatility -f <memory_dump> kpcr -U
volatility -f <memory_dump> kpcr -I
volatility -f <memory_dump> kpcr -E
volatility -f <memory_dump> kpcr -F
volatility -f <memory_dump> kpcr -G
volatility -f <memory_dump> kpcr -B
volatility -f <memory_dump> kpcr -R
volatility -f <memory_dump> kpcr -N
volatility -f <memory_dump> kpcr -M
volatility -f <memory_dump> kpcr -Q
volatility -f <memory_dump> kpcr -W
volatility -f <memory_dump> kpcr -X
volatility -f <memory_dump> kpcr -Y
volatility -f <memory_dump> kpcr -Z
volatility -f <memory_dump> kpcr -j
volatility -f <memory_dump> kpcr -i
volatility -f <memory_dump> kpcr -e
volatility -f <memory_dump> kpcr -f
volatility -f <memory_dump> kpcr -g
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

{% tab title="volatility-cheatsheet" %}
# Volatility Cheatsheet

## Basic Commands

### Image Identification

```bash
volatility -f <image> imageinfo
```

### Profile Identification

```bash
volatility -f <image> imageinfo | grep Profile
```

### Process List

```bash
volatility -f <image> --profile=<profile> pslist
```

### Process Tree

```bash
volatility -f <image> --profile=<profile> pstree
```

### DLL List

```bash
volatility -f <image> --profile=<profile> dlllist
```

### Handles

```bash
volatility -f <image> --profile=<profile> handles
```

### Network Connections

```bash
volatility -f <image> --profile=<profile> netscan
```

### Open Files

```bash
volatility -f <image> --profile=<profile> filescan
```

### Registry Analysis

```bash
volatility -f <image> --profile=<profile> hivelist
volatility -f <image> --profile=<profile> printkey -K <offset>
volatility -f <image> --profile=<profile> printkey -o <offset>
volatility -f <image> --profile=<profile> printval -K <offset>
volatility -f <image> --profile=<profile> printval -o <offset>
```

### Dumping Processes

```bash
volatility -f <image> --profile=<profile> procdump -p <pid> -D <output_directory>
```

### Dumping Files

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <string> -D <output_directory>
```

### Strings

```bash
volatility -f <image> --profile=<profile> strings -s <address> -e <address>
```

### Malware Analysis

```bash
volatility -f <image> --profile=<profile> malfind
volatility -f <image> --profile=<profile> malfind -Y <output_directory>
volatility -f <image> --profile=<profile> malfind -D <output_directory>
volatility -f <image> --profile=<profile> malfind -p <pid> -D <output_directory>
```

## Advanced Commands

### Finding Hidden Processes

```bash
volatility -f <image> --profile=<profile> psxview
```

### Finding Hidden DLLs

```bash
volatility -f <image> --profile=<profile> ldrmodules
```

### Finding Hidden Sockets

```bash
volatility -f <image> --profile=<profile> sockets
```

### Finding Hidden Registry Keys

```bash
volatility -f <image> --profile=<profile> hivescan
```

### Finding Hidden Files

```bash
volatility -f <image> --profile=<profile> filescan -S -D <output_directory>
```

### Finding Hidden Processes and DLLs

```bash
volatility -f <image> --profile=<profile> mutantscan
```

### Finding Hidden Code Injection

```bash
volatility -f <image> --profile=<profile> malfind -Y <output_directory>
volatility -f <image> --profile=<profile> malfind -D <output_directory>
volatility -f <image> --profile=<profile> malfind -p <pid> -D <output_directory>
```

### Finding Hidden Rootkits

```bash
volatility -f <image> --profile=<profile> linux_check_afinfo
volatility -f <image> --profile=<profile> linux_check_creds
volatility -f <image> --profile=<profile> linux_check_fop
volatility -f <image> --profile=<profile> linux_check_idt
volatility -f <image> --profile=<profile> linux_check_modules
volatility -f <image> --profile=<profile> linux_check_syscall
volatility -f <image> --profile=<profile> linux_check_syscalltbl
volatility -f <image> --profile=<profile> linux_check_tty
volatility -f <image> --profile=<profile> linux_check_uname
volatility -f <image> --profile=<profile> linux_check_syscall_generic
volatility -f <image> --profile=<profile> linux_hidden_modules
volatility -f <image> --profile=<profile> linux_hidden_procs
volatility -f <image> --profile=<profile> linux_hidden_files
volatility -f <image> --profile=<profile> linux_hidden_ports
volatility -f <image> --profile=<profile> linux_hidden_registries
volatility -f <image> --profile=<profile> linux_hidden_sockets
volatility -f <image> --profile=<profile> linux_hidden_syscall
volatility -f <image> --profile=<profile> linux_hidden_tty
volatility -f <image> --profile=<profile> linux_hidden_modules
volatility -f <image> --profile=<profile> linux_hidden_syscalltbl
volatility -f <image> --profile=<profile> linux_hidden_uname
```

### Finding Hidden Processes and DLLs (Windows 10)

```bash
volatility -f <image> --profile=<profile> pslist --apply-rules
volatility -f <image> --profile=<profile> dlllist --apply-rules
```

### Finding Hidden Code Injection (Windows 10)

```bash
volatility -f <image> --profile=<profile> malfind --apply-rules
```

### Finding Hidden Rootkits (Windows 10)

```bash
volatility -f <image> --profile=<profile> autoruns --apply-rules
volatility -f <image> --profile=<profile> driverirp --apply-rules
volatility -f <image> --profile=<profile> drivermodule --apply-rules
volatility -f <image> --profile=<profile> driverobject --apply-rules
volatility -f <image> --profile=<profile> driverscan --apply-rules
volatility -f <image> --profile=<profile> filescan --apply-rules
volatility -f <image> --profile=<profile> getsids --apply-rules
volatility -f <image> --profile=<profile> hivelist --apply-rules
volatility -f <image> --profile=<profile> hivescan --apply-rules
volatility -f <image> --profile=<profile> idt --apply-rules
volatility -f <image> --profile=<profile> imagecopy --apply-rules
volatility -f <image> --profile=<profile> imageinfo --apply-rules
volatility -f <image> --profile=<profile> ldrmodules --apply-rules
volatility -f <image> --profile=<profile> lsadump --apply-rules
volatility -f <image> --profile=<profile> malfind --apply-rules
volatility -f <image> --profile=<profile> mutantscan --apply-rules
volatility -f <image> --profile=<profile> netscan --apply-rules
volatility -f <image> --profile=<profile> printkey --apply-rules
volatility -f <image> --profile=<profile> privs --apply-rules
volatility -f <image> --profile=<profile> pslist --apply-rules
volatility -f <image> --profile=<profile> psscan --apply-rules
volatility -f <image> --profile=<profile> pstree --apply-rules
volatility -f <image> --profile=<profile> regdiff --apply-rules
volatility -f <image> --profile=<profile> registry --apply-rules
volatility -f <image> --profile=<profile> sockets --apply-rules
volatility -f <image> --profile=<profile> ssdt --apply-rules
volatility -f <image> --profile=<profile> symlinkscan --apply-rules
volatility -f <image> --profile=<profile> thrdscan --apply-rules
volatility -f <image> --profile=<profile> userassist --apply-rules
volatility -f <image> --profile=<profile> vadinfo --apply-rules
volatility -f <image> --profile=<profile> vadtree --apply-rules
volatility -f <image> --profile=<profile> windows --apply-rules
volatility -f <image> --profile=<profile> wintree --apply-rules
```

## References

- [Volatility Cheat Sheet](https://github.com/sans-dfir/sift/blob/master/Cheat%20Sheets/Volatility%20Cheat%20Sheet.pdf)
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
### Escaneo/volcado

{% tabs %}
{% tab title="vol3" %}
#### Escaneo de procesos

- `vol3 pslist -p <pid>`: muestra información detallada sobre un proceso específico.
- `vol3 psscan`: muestra información sobre todos los procesos en la memoria.
- `vol3 pstree`: muestra la jerarquía de procesos en la memoria.
- `vol3 psxview`: muestra información detallada sobre los procesos ocultos.

#### Escaneo de conexiones de red

- `vol3 connscan`: muestra información sobre todas las conexiones de red en la memoria.
- `vol3 sockets`: muestra información detallada sobre los sockets en la memoria.

#### Escaneo de archivos

- `vol3 filescan`: muestra información sobre todos los archivos abiertos en la memoria.
- `vol3 filescan -S <address>`: muestra información sobre el archivo que contiene la dirección especificada.
- `vol3 handles`: muestra información detallada sobre los descriptores de archivo en la memoria.

#### Escaneo de DLL

- `vol3 dlllist`: muestra información sobre todas las DLL cargadas en la memoria.
- `vol3 dlldump -D <dll_name>`: muestra el contenido de la DLL especificada.

#### Escaneo de registro

- `vol3 printkey`: muestra el contenido de una clave de registro específica.
- `vol3 hivelist`: muestra información sobre los archivos de registro en la memoria.
- `vol3 hivedump -o <offset> -f <filename>`: vuelca el archivo de registro en la dirección especificada a un archivo.

#### Escaneo de servicios

- `vol3 servicelist`: muestra información sobre todos los servicios en la memoria.
- `vol3 svcscan`: muestra información detallada sobre los servicios en la memoria.

#### Escaneo de tareas programadas

- `vol3 schedtasks`: muestra información sobre todas las tareas programadas en la memoria.

#### Escaneo de controladores

- `vol3 driverirp`: muestra información sobre todos los controladores en la memoria.
- `vol3 driverscan`: muestra información detallada sobre los controladores en la memoria.

#### Escaneo de usuarios

- `vol3 getsids`: muestra información sobre todos los SID en la memoria.
- `vol3 getsidbysubject`: muestra información sobre el SID asociado con un usuario específico.
- `vol3 getsidbyusername`: muestra información sobre el SID asociado con un nombre de usuario específico.
- `vol3 getsidbygroup`: muestra información sobre el SID asociado con un grupo específico.
- `vol3 getsidbyprocess`: muestra información sobre el SID asociado con un proceso específico.

#### Escaneo de caché

- `vol3 cachedump`: muestra información sobre los objetos en la caché de Windows.
- `vol3 cachedump -c <cache_type>`: muestra información sobre los objetos en el tipo de caché especificado.

#### Escaneo de memoria

- `vol3 memdump -p <pid> -D <dump_directory>`: vuelca la memoria del proceso especificado a un archivo.
- `vol3 memdump -b <address> -e <address> -D <dump_directory>`: vuelca la memoria en el rango de direcciones especificado a un archivo.
- `vol3 memdump -r <range> -D <dump_directory>`: vuelca la memoria en el rango de direcciones especificado a un archivo.
- `vol3 memmap`: muestra información sobre los rangos de memoria en la memoria.
- `vol3 vadinfo -p <pid>`: muestra información detallada sobre el espacio de direcciones virtuales de un proceso específico.
- `vol3 vadtree -p <pid>`: muestra la jerarquía de los espacios de direcciones virtuales de un proceso específico.
- `vol3 vadwalk -p <pid> -V <address>`: muestra información detallada sobre un espacio de direcciones virtuales específico.
- `vol3 vaddump -p <pid> -b <address> -e <address> -D <dump_directory>`: vuelca el espacio de direcciones virtuales en el rango de direcciones especificado a un archivo.
- `vol3 vaddump -p <pid> -V <address> -D <dump_directory>`: vuelca el espacio de direcciones virtuales especificado a un archivo.
{% endtab %}
{% endtabs %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
volatility -f <memory_dump> filescan
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
volatility -f <memory_dump> malfind
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> ldrmodules
volatility -f <memory_dump> modscan
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> handles
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> ssdt
volatility -f <memory_dump> driverscan
volatility -f <memory_dump> fileinfo -D <directory> -S <suffix>
volatility -f <memory_dump> dumpfiles -Q <file_offset> -u <file_size> -n <file_name> -f <output_directory>
volatility -f <memory_dump> memdump -p <pid> -D <directory> -u <user_space_address> -s <user_space_size>
```

### Advanced Commands

```bash
volatility -f <memory_dump> --profile=<profile> <plugin> <plugin_options>
```

### Plugins

#### Malware Analysis

```bash
volatility -f <memory_dump> malfind
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> ldrmodules
```

#### Process Analysis

```bash
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
```

#### Network Analysis

```bash
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
```

#### Registry Analysis

```bash
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
```

#### File Analysis

```bash
volatility -f <memory_dump> filescan
volatility -f <memory_dump> fileinfo -D <directory> -S <suffix>
volatility -f <memory_dump> dumpfiles -Q <file_offset> -u <file_size> -n <file_name> -f <output_directory>
```

#### Memory Analysis

```bash
volatility -f <memory_dump> memdump -p <pid> -D <directory> -u <user_space_address> -s <user_space_size>
```

#### Other Analysis

```bash
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> handles
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> ssdt
volatility -f <memory_dump> driverscan
```

## Volatility Profiles

### Linux

```bash
volatility --info | grep Linux
```

### Windows

```bash
volatility --info | grep Win
```

## Volatility Plugins

### Malware Analysis

#### malfind

```bash
volatility -f <memory_dump> malfind
```

#### apihooks

```bash
volatility -f <memory_dump> apihooks
```

#### ldrmodules

```bash
volatility -f <memory_dump> ldrmodules
```

### Process Analysis

#### pslist

```bash
volatility -f <memory_dump> pslist
```

#### pstree

```bash
volatility -f <memory_dump> pstree
```

#### psscan

```bash
volatility -f <memory_dump> psscan
```

### Network Analysis

#### netscan

```bash
volatility -f <memory_dump> netscan
```

#### connscan

```bash
volatility -f <memory_dump> connscan
```

#### sockets

```bash
volatility -f <memory_dump> sockets
```

### Registry Analysis

#### hivelist

```bash
volatility -f <memory_dump> hivelist
```

#### hivedump

```bash
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
```

#### printkey

```bash
volatility -f <memory_dump> printkey -K <key>
```

#### dumpregistry

```bash
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
```

### File Analysis

#### filescan

```bash
volatility -f <memory_dump> filescan
```

#### fileinfo

```bash
volatility -f <memory_dump> fileinfo -D <directory> -S <suffix>
```

#### dumpfiles

```bash
volatility -f <memory_dump> dumpfiles -Q <file_offset> -u <file_size> -n <file_name> -f <output_directory>
```

### Memory Analysis

#### memdump

```bash
volatility -f <memory_dump> memdump -p <pid> -D <directory> -u <user_space_address> -s <user_space_size>
```

### Other Analysis

#### getsids

```bash
volatility -f <memory_dump> getsids
```

#### getservicesids

```bash
volatility -f <memory_dump> getservicesids
```

#### handles

```bash
volatility -f <memory_dump> handles
```

#### mutantscan

```bash
volatility -f <memory_dump> mutantscan
```

#### driverirp

```bash
volatility -f <memory_dump> driverirp
```

#### devicetree

```bash
volatility -f <memory_dump> devicetree
```

#### callbacks

```bash
volatility -f <memory_dump> callbacks
```

#### idt

```bash
volatility -f <memory_dump> idt
```

#### gdt

```bash
volatility -f <memory_dump> gdt
```

#### ssdt

```bash
volatility -f <memory_dump> ssdt
```

#### driverscan

```bash
volatility -f <memory_dump> driverscan
```
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
{% endtab %}
{% tab title="Español" %}
### Tabla maestra de archivos

La tabla maestra de archivos (MFT) es una estructura de datos en sistemas de archivos NTFS que contiene información sobre todos los archivos y directorios en una partición. La MFT se almacena en una ubicación fija en el disco y se divide en entradas de archivo individuales. Cada entrada de archivo contiene información sobre un archivo o directorio específico, como su nombre, tamaño, fecha de creación y ubicación en el disco.

La MFT es una herramienta útil para la recuperación de datos y la investigación forense, ya que puede proporcionar información detallada sobre los archivos y directorios en una partición. Volatility tiene varios plugins que pueden analizar la MFT, incluyendo `mftparser`, `mftparser2` y `mftparser3`. Estos plugins pueden mostrar información sobre los archivos y directorios en la MFT, así como información sobre los atributos de archivo, como los tiempos de creación, modificación y acceso.
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{% endtab %}

{% tab title="volatility-cheatsheet" %}
# Volatility Cheatsheet

## Basic Commands

### Image Identification

```bash
volatility -f <image> imageinfo
```

### Profile Identification

```bash
volatility -f <image> imageinfo | grep Profile
```

### Process List

```bash
volatility -f <image> --profile=<profile> pslist
```

### Process Tree

```bash
volatility -f <image> --profile=<profile> pstree
```

### DLL List

```bash
volatility -f <image> --profile=<profile> dlllist
```

### Handles

```bash
volatility -f <image> --profile=<profile> handles
```

### Network Connections

```bash
volatility -f <image> --profile=<profile> netscan
```

### Open Files

```bash
volatility -f <image> --profile=<profile> filescan
```

### Registry Analysis

```bash
volatility -f <image> --profile=<profile> hivelist
volatility -f <image> --profile=<profile> printkey -K <key>
volatility -f <image> --profile=<profile> printval -K <key> -V <value>
```

### Dumping Processes

```bash
volatility -f <image> --profile=<profile> procdump -p <pid> -D <output_directory>
```

### Dumping Files

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <address_space> -D <output_directory>
```

### Strings

```bash
volatility -f <image> --profile=<profile> strings -s <address_space> -o <offset>
```

### Malware Analysis

```bash
volatility -f <image> --profile=<profile> malfind
volatility -f <image> --profile=<profile> malsysproc
volatility -f <image> --profile=<profile> malprocfind
```

## Advanced Commands

### Finding Hidden Processes

```bash
volatility -f <image> --profile=<profile> psxview
```

### Finding Hidden DLLs

```bash
volatility -f <image> --profile=<profile> ldrmodules
```

### Finding Hidden Sockets

```bash
volatility -f <image> --profile=<profile> sockets
```

### Finding Hidden Registry Keys

```bash
volatility -f <image> --profile=<profile> hivescan
```

### Finding Hidden Files

```bash
volatility -f <image> --profile=<profile> filescan -S -u
```

### Finding Hidden Processes and DLLs

```bash
volatility -f <image> --profile=<profile> mutantscan
```

### Finding Hidden Code Injection

```bash
volatility -f <image> --profile=<profile> malfind -Y <dll_name>
```

### Finding Hidden Rootkits

```bash
volatility -f <image> --profile=<profile> linux_check_afinfo
volatility -f <image> --profile=<profile> linux_check_creds
volatility -f <image> --profile=<profile> linux_check_fop
volatility -f <image> --profile=<profile> linux_check_idt
volatility -f <image> --profile=<profile> linux_check_modules
volatility -f <image> --profile=<profile> linux_check_syscall
volatility -f <image> --profile=<profile> linux_check_syscalltbl
volatility -f <image> --profile=<profile> linux_check_tty
volatility -f <image> --profile=<profile> linux_check_vdso
volatility -f <image> --profile=<profile> linux_hidden_modules
volatility -f <image> --profile=<profile> linux_hidden_procs
volatility -f <image> --profile=<profile> linux_hidden_syscall
volatility -f <image> --profile=<profile> linux_hidden_syscalltbl
volatility -f <image> --profile=<profile> linux_hidden_tty
volatility -f <image> --profile=<profile> linux_hidden_vdso
```
{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% tab title="volatility" %}
El sistema de archivos NTFS contiene un archivo llamado _tabla maestra de archivos_, o MFT. Hay al menos una entrada en el MFT para cada archivo en un volumen del sistema de archivos NTFS, incluido el propio MFT. **Toda la información sobre un archivo, incluido su tamaño, sellos de tiempo y fecha, permisos y contenido de datos**, se almacena en entradas MFT o en espacio fuera del MFT que es descrito por entradas MFT. Desde [aquí](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### Claves/Certificados SSL
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
volatility -f <memory_dump> filescan
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
volatility -f <memory_dump> malfind
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> ldrmodules
volatility -f <memory_dump> modscan
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> handles
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> ssdt
volatility -f <memory_dump> driverscan
volatility -f <memory_dump> fileinfo -F <file_path>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yara
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yara --yara-rules <yara_rules>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yara --yara-rules <yara_rules> --yara-strings
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yara --yara-rules <yara_rules> --yara-strings --yara-scan <yara_scan>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yara --yara-rules <yara_rules> --yara-strings --yara-scan <yara_scan> --yara-scan-args <yara_scan_args>
```

### Advanced Commands

```bash
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yara
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yara --yara-rules <yara_rules>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yara --yara-rules <yara_rules> --yara-strings
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yara --yara-rules <yara_rules> --yara-strings --yara-scan <yara_scan>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yara --yara-rules <yara_rules> --yara-strings --yara-scan <yara_scan> --yara-scan-args <yara_scan_args>
```

### Plugins

```bash
volatility --plugins=<path_to_plugins_directory> -f <memory_dump> <plugin_name> [options]
```

### Volshell

```bash
volatility -f <memory_dump> volshell
```

### Volatility Profile

```bash
volatility -f <memory_dump> --profile=<profile_name> <command>
```

### Volatility API

```python
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands

registry.PluginImporter()
config = conf.ConfObject()

config.parse_options()
config.PROFILE = "<profile_name>"
config.LOCATION = "file://<memory_dump>"

registry.register_global_options(config, commands.Command)
registry.register_global_options(config, commands.FileCarvingOptions)

plugin = commands.Command
plugin.config = config

p = plugin()

p.calculate()
p.render_text()
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
{% endtab %}
{% tab title="volatility-cheatsheet" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

1. Download the latest version of Volatility from https://github.com/volatilityfoundation/volatility/releases
2. Extract the contents of the zip file to a directory of your choice
3. Add the directory to your system's PATH environment variable

## Volatility Usage

### Basic Usage

```bash
volatility -f <memory_dump> <plugin> [options]
```

### Examples

```bash
# List all available plugins
volatility --info

# Analyze a memory dump using the pslist plugin
volatility -f memdump.mem pslist

# Analyze a memory dump using multiple plugins
volatility -f memdump.mem pslist psscan netscan

# Analyze a memory dump using a specific profile
volatility -f memdump.mem --profile=Win7SP1x64 pslist

# Analyze a memory dump using a specific plugin option
volatility -f memdump.mem malfind -D /tmp/output/
```

### Memory Dump Acquisition

#### Linux

```bash
sudo dd if=/dev/mem of=memdump.mem bs=1M
```

#### Windows

1. Download and install [DumpIt](https://github.com/jschicht/DumpIt/releases)
2. Run DumpIt as an administrator
3. Choose a location to save the memory dump file

### Memory Analysis

#### Profile Detection

```bash
volatility -f memdump.mem imageinfo
```

#### Process List

```bash
volatility -f memdump.mem pslist
```

#### Process Tree

```bash
volatility -f memdump.mem pstree
```

#### Process Memory Map

```bash
volatility -f memdump.mem pmap --pid=<pid>
```

#### DLL List

```bash
volatility -f memdump.mem dlllist --pid=<pid>
```

#### Network Connections

```bash
volatility -f memdump.mem netscan
```

#### Open Files

```bash
volatility -f memdump.mem filescan
```

#### Registry Keys

```bash
volatility -f memdump.mem printkey --key=<key>
```

#### Malware Analysis

##### Detecting Hidden Processes

```bash
volatility -f memdump.mem psxview
```

##### Detecting Hidden DLLs

```bash
volatility -f memdump.mem ldrmodules
```

##### Detecting Hidden Sockets

```bash
volatility -f memdump.mem sockets
```

##### Detecting Hidden Registry Keys

```bash
volatility -f memdump.mem hivelist
volatility -f memdump.mem hivedump --hive=<hive_offset> -o <output_file>
```

##### Detecting Hidden Files

```bash
volatility -f memdump.mem filescan | grep -i '\.pdf'
```

##### Detecting Hidden Network Connections

```bash
volatility -f memdump.mem connscan
```

##### Detecting Hidden Processes Using Rootkit Techniques

```bash
volatility -f memdump.mem malfind
```

##### Detecting Hidden Processes Using API Hooking

```bash
volatility -f memdump.mem apihooks
```

##### Detecting Hidden Processes Using SSDT Hooking

```bash
volatility -f memdump.mem ssdt
```

##### Detecting Hidden Processes Using IRP Hooking

```bash
volatility -f memdump.mem irpfind
```

##### Detecting Hidden Processes Using Inline Hooking

```bash
volatility -f memdump.mem inlined
```

##### Detecting Hidden Processes Using Code Injection

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.dll"
```

##### Detecting Hidden Processes Using Process Hollowing

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.exe"
```

##### Detecting Hidden Processes Using Process Doppelgänging

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.exe"
```

##### Detecting Hidden Processes Using AtomBombing

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.dll"
```

##### Detecting Hidden Processes Using APC Injection

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.dll"
```

##### Detecting Hidden Processes Using User-Mode Rootkits

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.dll"
```

##### Detecting Hidden Processes Using Kernel-Mode Rootkits

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.sys"
```

##### Detecting Hidden Processes Using Hypervisor-Based Rootkits

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.sys"
```

##### Detecting Hidden Processes Using Firmware Rootkits

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.rom"
```

##### Detecting Hidden Processes Using Virtualization-Based Rootkits

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.dll"
```

##### Detecting Hidden Processes Using Hardware-Based Rootkits

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.rom"
```

##### Detecting Hidden Processes Using Memory-Based Rootkits

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.dll"
```

##### Detecting Hidden Processes Using Bootkits

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.sys"
```

##### Detecting Hidden Processes Using BIOS Rootkits

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.rom"
```

##### Detecting Hidden Processes Using MBR Rootkits

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.sys"
```

##### Detecting Hidden Processes Using UEFI Rootkits

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.efi"
```

##### Detecting Hidden Processes Using Firmware-Based Rootkits

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.rom"
```

##### Detecting Hidden Processes Using Hardware-Based Covert Channels

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.dll"
```

##### Detecting Hidden Processes Using Software-Based Covert Channels

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.dll"
```

##### Detecting Hidden Processes Using Network-Based Covert Channels

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.dll"
```

##### Detecting Hidden Processes Using Timing-Based Covert Channels

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.dll"
```

##### Detecting Hidden Processes Using Acoustic-Based Covert Channels

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.dll"
```

##### Detecting Hidden Processes Using Electromagnetic-Based Covert Channels

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.dll"
```

##### Detecting Hidden Processes Using Thermal-Based Covert Channels

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.dll"
```

##### Detecting Hidden Processes Using Optical-Based Covert Channels

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.dll"
```

##### Detecting Hidden Processes Using Magnetic-Based Covert Channels

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.dll"
```

##### Detecting Hidden Processes Using Chemical-Based Covert Channels

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.dll"
```

##### Detecting Hidden Processes Using Biological-Based Covert Channels

```bash
volatility -f memdump.mem malfind --dump-dir=/tmp/ --dump-regex=".*\.dll"
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility Plugins](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
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

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> handles
volatility -f <memory_dump> filescan
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> privs
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> userassist
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> malfind
volatility -f <memory_dump> mftparser
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> printkey
volatility -f <memory_dump> hashdump
volatility -f <memory_dump> envars
volatility -f <memory_dump> dumpregistry
volatility -f <memory_dump> dumpfiles
volatility -f <memory_dump> memdump
```

### Advanced Commands

```bash
volatility -f <memory_dump> --profile=<profile> <plugin> <options>
volatility -f <memory_dump> --profile=<profile> -H <path_to_header_file> <plugin> <options>
volatility -f <memory_dump> --profile=<profile> -P <path_to_plugin_directory> <plugin> <options>
volatility -f <memory_dump> --profile=<profile> -o <offset> <plugin> <options>
volatility -f <memory_dump> --profile=<profile> -g <path_to_kdbg> <plugin> <options>
volatility -f <memory_dump> --profile=<profile> -K <kernel_address_space> <plugin> <options>
volatility -f <memory_dump> --profile=<profile> -f <path_to_config_file> <plugin> <options>
```

### Common Profiles

- WinXPSP2x86
- WinXPSP3x86
- Win7SP0x64
- Win7SP1x64
- Win10x64_10586
- Win10x64_14393
- Win10x64_16299
- Win10x64_17134
- Win10x64_17763
- Win10x64_18362
- Win10x64_18363

### Useful Plugins

- pslist
- pstree
- psscan
- netscan
- connscan
- dlllist
- handles
- filescan
- cmdline
- consoles
- getsids
- getservicesids
- privs
- apihooks
- malfind
- mftparser
- hivelist
- hashdump
- envars
- dumpregistry
- dumpfiles
- memdump

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
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
{% endtab %}
{% tab title="volatility-cheatsheet.md" %}

### Escaneando con yara

Utilice este script para descargar y fusionar todas las reglas de malware de yara desde github: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Cree el directorio _**rules**_ y ejecútelo. Esto creará un archivo llamado _**malware\_rules.yar**_ que contiene todas las reglas de yara para malware.

{% endtab %}
{% endtabs %}
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

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
volatility -f <memory_dump> filescan
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
volatility -f <memory_dump> malfind
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> ldrmodules
volatility -f <memory_dump> modscan
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> handles
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> ssdt
volatility -f <memory_dump> driverscan
volatility -f <memory_dump> fileinfo -F <file_path>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yarascan
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yarascan --yara-rules <yara_rules>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yarascan --yara-rules <yara_rules> --yara-strings
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yarascan --yara-rules <yara_rules> --yara-strings --yara-scan-args <yara_scan_args>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yarascan --yara-rules <yara_rules> --yara-strings --yara-scan-args <yara_scan_args> --yara-process-memory
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yarascan --yara-rules <yara_rules> --yara-strings --yara-scan-args <yara_scan_args> --yara-process-memory --yara-process-memory-args <yara_process_memory_args>
```

### Advanced Commands

```bash
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yarascan
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yarascan --yara-rules <yara_rules>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yarascan --yara-rules <yara_rules> --yara-strings
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yarascan --yara-rules <yara_rules> --yara-strings --yara-scan-args <yara_scan_args>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yarascan --yara-rules <yara_rules> --yara-strings --yara-scan-args <yara_scan_args> --yara-process-memory
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir <dump_directory> --name <file_name> --unzip --output <output_format> --no-strings --no-metadata --phys-offset <physical_offset> --suffix <suffix> --overwrite --use-mmap --use-volshell --use-magic --use-yarascan --yara-rules <yara_rules> --yara-strings --yara-scan-args <yara_scan_args> --yara-process-memory --yara-process-memory-args <yara_process_memory_args>
```

### Plugins

```bash
volatility --plugins=<path_to_plugins_directory> -f <memory_dump> <plugin_name> <plugin_options>
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
### Plugins externos

Si desea utilizar plugins externos, asegúrese de que las carpetas relacionadas con los plugins sean el primer parámetro utilizado.
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
volatility -f <memory_dump> filescan
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
volatility -f <memory_dump> malfind
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> ldrmodules
volatility -f <memory_dump> modscan
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> handles
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> ssdt
volatility -f <memory_dump> driverscan
volatility -f <memory_dump> fileinfo -D <directory> -S <suffix>
volatility -f <memory_dump> dumpfiles -Q <file_offset> -u <file_size> -n <file_name> -f <output_directory>
volatility -f <memory_dump> memdump -p <pid> -D <directory> -u <user_space_address> -s <user_space_size>
```

### Advanced Commands

```bash
volatility -f <memory_dump> --profile=<profile> <plugin> <plugin_options>
```

### Plugins

#### Malware Analysis

```bash
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malsysproc
volatility -f <memory_dump> malprocfind
volatility -f <memory_dump> maldrivers
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malheap
volatility -f <memory_dump> malpscan
volatility -f <memory_dump> malwaredetect
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> ldrmodules
volatility -f <memory_dump> modscan
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> callbacks
```

#### Memory Analysis

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
volatility -f <memory_dump> filescan
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> ssdt
volatility -f <memory_dump> driverscan
volatility -f <memory_dump> fileinfo -D <directory> -S <suffix>
volatility -f <memory_dump> dumpfiles -Q <file_offset> -u <file_size> -n <file_name> -f <output_directory>
volatility -f <memory_dump> memdump -p <pid> -D <directory> -u <user_space_address> -s <user_space_size>
```

#### Network Analysis

```bash
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
```

#### Process Analysis

```bash
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> psxview
volatility -f <memory_dump> cmdscan
volatility -f <memory_dump> consoles
volatility -f <memory_dump> consoles -p <pid>
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> handles
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
```

#### Registry Analysis

```bash
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
```

#### System Information

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> kdbgscan
volatility -f <memory_dump> kpcrscan
volatility -f <memory_dump> kpcrspace
volatility -f <memory_dump> kdtree
volatility -f <memory_dump> kpcr
volatility -f <memory_dump> kpcr -p <pid>
volatility -f <memory_dump> kpcr -t <thread>
volatility -f <memory_dump> kpcr -c <cpu>
volatility -f <memory_dump> kpcr -a <address>
volatility -f <memory_dump> kpcr -s <symbol>
volatility -f <memory_dump> kpcr -l <level>
volatility -f <memory_dump> kpcr -d <debugger>
volatility -f <memory_dump> kpcr -o <output_format>
volatility -f <memory_dump> kpcr -v <verbose_level>
volatility -f <memory_dump> kpcr -h
volatility -f <memory_dump> kpcr -V
volatility -f <memory_dump> kpcr -L
volatility -f <memory_dump> kpcr -D
volatility -f <memory_dump> kpcr -O
volatility -f <memory_dump> kpcr -S
volatility -f <memory_dump> kpcr -P
volatility -f <memory_dump> kpcr -T
volatility -f <memory_dump> kpcr -C
volatility -f <memory_dump> kpcr -A
volatility -f <memory_dump> kpcr -I
volatility -f <memory_dump> kpcr -E
volatility -f <memory_dump> kpcr -F
volatility -f <memory_dump> kpcr -R
volatility -f <memory_dump> kpcr -N
volatility -f <memory_dump> kpcr -M
volatility -f <memory_dump> kpcr -U
volatility -f <memory_dump> kpcr -W
volatility -f <memory_dump> kpcr -X
volatility -f <memory_dump> kpcr -Y
volatility -f <memory_dump> kpcr -Z
volatility -f <memory_dump> kpcr -Q
volatility -f <memory_dump> kpcr -G
volatility -f <memory_dump> kpcr -B
volatility -f <memory_dump> kpcr -j
volatility -f <memory_dump> kpcr -i
volatility -f <memory_dump> kpcr -e
volatility -f <memory_dump> kpcr -w
volatility -f <memory_dump> kpcr -x
volatility -f <memory_dump> kpcr -y
volatility -f <memory_dump> kpcr -z
volatility -f <memory_dump> kpcr -q
volatility -f <memory_dump> kpcr -g
volatility -f <memory_dump> kpcr -b
volatility -f <memory_dump> kpcr -f
volatility -f <memory_dump> kpcr -r
volatility -f <memory_dump> kpcr -n
volatility -f <memory_dump> kpcr -m
volatility -f <memory_dump> kpcr -u
volatility -f <memory_dump> kpcr -k
volatility -f <memory_dump> kpcr -j
volatility -f <memory_dump> kpcr -i
volatility -f <memory_dump> kpcr -e
volatility -f <memory_dump> kpcr -w
volatility -f <memory_dump> kpcr -x
volatility -f <memory_dump> kpcr -y
volatility -f <memory_dump> kpcr -z
volatility -f <memory_dump> kpcr -q
volatility -f <memory_dump> kpcr -g
volatility -f <memory_dump> kpcr -b
volatility -f <memory_dump> kpcr -f
volatility -f <memory_dump> kpcr -r
volatility -f <memory_dump> kpcr -n
volatility -f <memory_dump> kpcr -m
volatility -f <memory_dump> kpcr -u
volatility -f <memory_dump> kpcr -k
volatility -f <memory_dump> kpcr -j
volatility -f <memory_dump> kpcr -i
volatility -f <memory_dump> kpcr -e
volatility -f <memory_dump> kpcr -w
volatility -f <memory_dump> kpcr -x
volatility -f <memory_dump> kpcr -y
volatility -f <memory_dump> kpcr -z
volatility -f <memory_dump> kpcr -q
volatility -f <memory_dump> kpcr -g
volatility -f <memory_dump> kpcr -b
volatility -f <memory_dump> kpcr -f
volatility -f <memory_dump> kpcr -r
volatility -f <memory_dump> kpcr -n
volatility -f <memory_dump> kpcr -m
volatility -f <memory_dump> kpcr -u
volatility -f <memory_dump> kpcr -k
volatility -f <memory_dump> kpcr -j
volatility -f <memory_dump> kpcr -i
volatility -f <memory_dump> kpcr -e
volatility -f <memory_dump> kpcr -w
volatility -f <memory_dump> kpcr -x
volatility -f <memory_dump> kpcr -y
volatility -f <memory_dump> kpcr -z
volatility -f <memory_dump> kpcr -q
volatility -f <memory_dump> kpcr -g
volatility -f <memory_dump> kpcr -b
volatility -f <memory_dump> kpcr -f
volatility -f <memory_dump> kpcr -r
volatility -f <memory_dump> kpcr -n
volatility -f <memory_dump> kpcr -m
volatility -f <memory_dump> kpcr -u
volatility -f <memory_dump> kpcr -k
volatility -f <memory_dump> kpcr -j
volatility -f <memory_dump> kpcr -i
volatility -f <memory_dump> kpcr -e
volatility -f <memory_dump> kpcr -w
volatility -f <memory_dump> kpcr -x
volatility -f <memory_dump> kpcr -y
volatility -f <memory_dump> kpcr -z
volatility -f <memory_dump> kpcr -q
volatility -f <memory_dump> kpcr -g
volatility -f <memory_dump> kpcr -b
volatility -f <memory_dump> kpcr -f
volatility -f <memory_dump> kpcr -r
volatility -f <memory_dump> kpcr -n
volatility -f <memory_dump> kpcr -m
volatility -f <memory_dump> kpcr -u
volatility -f <memory_dump> kpcr -k
volatility -f <memory_dump> kpcr -j
volatility -f <memory_dump> kpcr -i
volatility -f <memory_dump> kpcr -e
volatility -f <memory_dump> kpcr -w
volatility -f <memory_dump> kpcr -x
volatility -f <memory_dump> kpcr -y
volatility -f <memory_dump> kpcr -z
volatility -f <memory_dump> kpcr -q
volatility -f <memory_dump> kpcr -g
volatility -f <memory_dump> kpcr -b
volatility -f <memory_dump> kpcr -f
volatility -f <memory_dump> kpcr -r
volatility -f <memory_dump> kpcr -n
volatility -f <memory_dump> kpcr -m
volatility -f <memory_dump> kpcr -u
volatility -f <memory_dump> kpcr -k
volatility -f <memory_dump> kpcr -j
volatility -f <memory_dump> kpcr -i
volatility -f <memory_dump> kpcr -e
volatility -f <memory_dump> kpcr -w
volatility -f <memory_dump> kpcr -x
volatility -f <memory_dump> kpcr -y
volatility -f <memory_dump> kpcr -z
volatility -f <memory_dump> kpcr -q
volatility -f <memory_dump> kpcr -g
volatility -f <memory_dump> kpcr -b
volatility -f <memory_dump> kpcr -f
volatility -f <memory_dump> kpcr -r
volatility -f <memory_dump> kpcr -n
volatility -f <memory_dump> kpcr -m
volatility -f <memory_dump> kpcr -u
volatility -f <memory_dump> kpcr -k
volatility -f <memory_dump> kpcr -j
volatility -f <memory_dump> kpcr -i
volatility -f <memory_dump> kpcr -e
volatility -f <memory_dump> kpcr -w
volatility -f <memory_dump> kpcr -x
volatility -f <memory_dump> kpcr -y
volatility -f <memory_dump> kpcr -z
volatility -f <memory_dump> kpcr -q
volatility -f <memory_dump> kpcr -g
volatility -f <memory_dump> kpcr -b
volatility -f <memory_dump> kpcr -f
volatility -f <memory_dump> kpcr -r
volatility -f <memory_dump> kpcr -n
volatility -f <memory_dump> kpcr -m
volatility -f <memory_dump> kpcr -u
volatility -f <memory_dump> kpcr -k
volatility -f <memory_dump> kpcr -j
volatility -f <memory_dump> kpcr -i
volatility -f <memory_dump> kpcr -e
volatility -f <memory_dump> kpcr -w
volatility -f <memory_dump> kpcr -x
volatility -f <memory_dump> kpcr -y
volatility -f <memory_dump> kpcr -z
volatility -f <memory_dump> kpcr -q
volatility -f <memory_dump> kpcr -g
volatility -f <memory_dump> kpcr -b
volatility -f <memory_dump> kpcr -f
volatility -f <memory_dump> kpcr -r
volatility -f <memory_dump> kpcr -n
volatility -f <memory_dump> kpc
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
Los mutexes son objetos de sincronización que se utilizan para evitar que varios procesos accedan simultáneamente a un recurso compartido. En los volcados de memoria, los mutexes pueden ser útiles para identificar procesos que estaban activos en el momento del volcado y para determinar qué procesos estaban compitiendo por recursos compartidos. Volatility proporciona varios comandos para trabajar con mutexes, incluyendo `mutantscan`, `mutantscan2` y `mutantscan3`. Estos comandos escanean el volcado de memoria en busca de objetos de mutex y muestran información sobre ellos, como su nombre, el proceso que los creó y el número de hilos que están esperando para adquirir el mutex.
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
volatility -f <memory_dump> filescan
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
volatility -f <memory_dump> malfind
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> ldrmodules
volatility -f <memory_dump> modscan
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> handles
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> ssdt
volatility -f <memory_dump> driverscan
volatility -f <memory_dump> fileinfo -D <directory> -S <suffix>
volatility -f <memory_dump> dumpfiles -Q <file_offset> -u <file_size> -n <file_name> -f <output_directory>
volatility -f <memory_dump> memdump -p <pid> -D <directory> -u <user_space_address> -s <user_space_size>
```

### Advanced Commands

```bash
volatility -f <memory_dump> --profile=<profile> <plugin> <plugin_options>
```

### Plugins

#### Malware Analysis

```bash
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malsysproc
volatility -f <memory_dump> malprocfind
volatility -f <memory_dump> maldrivers
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malheap
volatility -f <memory_dump> malpscan
volatility -f <memory_dump> malwaredetect
volatility -f <memory_dump> malstack
volatility -f <memory_dump> malstrings
volatility -f <memory_dump> maltrie
volatility -f <memory_dump> malurl
```

#### Network Analysis

```bash
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
volatility -f <memory_dump> connscan
volatility -f <memory_dump> connscan
```

#### Process Analysis

```bash
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> psxview
volatility -f <memory_dump> cmdscan
volatility -f <memory_dump> consoles
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> handles
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
```

#### Registry Analysis

```bash
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
```

#### File Analysis

```bash
volatility -f <memory_dump> filescan
volatility -f <memory_dump> fileinfo -D <directory> -S <suffix>
volatility -f <memory_dump> dumpfiles -Q <file_offset> -u <file_size> -n <file_name> -f <output_directory>
```

#### Memory Analysis

```bash
volatility -f <memory_dump> memdump -p <pid> -D <directory> -u <user_space_address> -s <user_space_size>
volatility -f <memory_dump> memmap
volatility -f <memory_dump> memstrings
volatility -f <memory_dump> memdump
volatility -f <memory_dump> memdiff
volatility -f <memory_dump> memimage
volatility -f <memory_dump> memdump2
volatility -f <memory_dump> memdump --dump-dir=<directory> --dump-headers --dump-dir=<directory> --dump-headers
```

#### Other Analysis

```bash
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> ldrmodules
volatility -f <memory_dump> modscan
volatility -f <memory_dump> gdt
volatility -f <memory_dump> idt
volatility -f <memory_dump> ssdt
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
```

## Volatility Profiles

### Windows

```bash
volatility -f <memory_dump> imageinfo
```

### Linux

```bash
volatility -f <memory_dump> linux_banner
volatility -f <memory_dump> linux_pslist
volatility -f <memory_dump> linux_pstree
volatility -f <memory_dump> linux_psaux
volatility -f <memory_dump> linux_netstat
volatility -f <memory_dump> linux_lsmod
volatility -f <memory_dump> linux_ifconfig
volatility -f <memory_dump> linux_route
volatility -f <memory_dump> linux_mount
volatility -f <memory_dump> linux_idt
volatility -f <memory_dump> linux_crashinfo
volatility -f <memory_dump> linux_syscall
volatility -f <memory_dump> linux_proc_maps
volatility -f <memory_dump> linux_proc_exe
volatility -f <memory_dump> linux_proc_environ
volatility -f <memory_dump> linux_check_afinfo
volatility -f <memory_dump> linux_check_creds
volatility -f <memory_dump> linux_check_syscall
volatility -f <memory_dump> linux_check_syscall_generic
volatility -f <memory_dump> linux_check_tty
volatility -f <memory_dump> linux_find_file
volatility -f <memory_dump> linux_find_file_fd
volatility -f <memory_dump> linux_find_inode
volatility -f <memory_dump> linux_find_module
volatility -f <memory_dump> linux_find_task_mm
volatility -f <memory_dump> linux_find_vma
volatility -f <memory_dump> linux_list_files
volatility -f <memory_dump> linux_list_files_fd
volatility -f <memory_dump> linux_list_tasks
volatility -f <memory_dump> linux_lsof
volatility -f <memory_dump> linux_memmap
volatility -f <memory_dump> linux_mountinfo
volatility -f <memory_dump> linux_netstat
volatility -f <memory_dump> linux_psenv
volatility -f <memory_dump> linux_pslist
volatility -f <memory_dump> linux_pstree
volatility -f <memory_dump> linux_sockstat
volatility -f <memory_dump> linux_taskstats
volatility -f <memory_dump> linux_uname
volatility -f <memory_dump> linux_usb
volatility -f <memory_dump> linux_version
volatility -f <memory_dump> linux_vmstat
volatility -f <memory_dump> linux_wchan
```

## Volatility Plugins

### Windows

#### Malware Analysis

```bash
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malsysproc
volatility -f <memory_dump> malprocfind
volatility -f <memory_dump> maldrivers
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malheap
volatility -f <memory_dump> malpscan
volatility -f <memory_dump> malwaredetect
volatility -f <memory_dump> malstack
volatility -f <memory_dump> malstrings
volatility -f <memory_dump> maltrie
volatility -f <memory_dump> malurl
```

#### Network Analysis

```bash
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> sockets
volatility -f <memory_dump> connscan
volatility -f <memory_dump> connscan
```

#### Process Analysis

```bash
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> psxview
volatility -f <memory_dump> cmdscan
volatility -f <memory_dump> consoles
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> handles
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
```

#### Registry Analysis

```bash
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> dumpregistry -o <offset> -s <size> -k <key> -f <output_file>
```

#### File Analysis

```bash
volatility -f <memory_dump> filescan
volatility -f <memory_dump> fileinfo -D <directory> -S <suffix>
volatility -f <memory_dump> dumpfiles -Q <file_offset> -u <file_size> -n <file_name> -f <output_directory>
```

#### Memory Analysis

```bash
volatility -f <memory_dump> memdump -p <pid> -D <directory> -u <user_space_address> -s <user_space_size>
volatility -f <memory_dump> memmap
volatility -f <memory_dump> memstrings
volatility -f <memory_dump> memdump
volatility -f <memory_dump> memdiff
volatility -f <memory_dump> memimage
volatility -f <memory_dump> memdump2
volatility -f <memory_dump> memdump --dump-dir=<directory> --dump-headers --dump-dir=<directory> --dump-headers
```

#### Other Analysis

```bash
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> ldrmodules
volatility -f <memory_dump> modscan
volatility -f <memory_dump> gdt
volatility -f <memory_dump> idt
volatility -f <memory_dump> ssdt
volatility -f <memory_dump> mutantscan
volatility -f <memory_dump> driverirp
volatility -f <memory_dump> devicetree
volatility -f <memory_dump> callbacks
```

### Linux

```bash
volatility -f <memory_dump> linux_banner
volatility -f <memory_dump> linux_pslist
volatility -f <memory_dump> linux_pstree
volatility -f <memory_dump> linux_psaux
volatility -f <memory_dump> linux_netstat
volatility -f <memory_dump> linux_lsmod
volatility -f <memory_dump> linux_ifconfig
volatility -f <memory_dump> linux_route
volatility -f <memory_dump> linux_mount
volatility -f <memory_dump> linux_idt
volatility -f <memory_dump> linux_crashinfo
volatility -f <memory_dump> linux_syscall
volatility -f <memory_dump> linux_proc_maps
volatility -f <memory_dump> linux_proc_exe
volatility -f <memory_dump> linux_proc_environ
volatility -f <memory_dump> linux_check_afinfo
volatility -f <memory_dump> linux_check_creds
volatility -f <memory_dump> linux_check_syscall
volatility -f <memory_dump> linux_check_syscall_generic
volatility -f <memory_dump> linux_check_tty
volatility -f <memory_dump> linux_find_file
volatility -f <memory_dump> linux_find_file_fd
volatility -f <memory_dump> linux_find_inode
volatility -f <memory_dump> linux_find_module
volatility -f <memory_dump> linux_find_task_mm
volatility -f <memory_dump> linux_find_vma
volatility -f <memory_dump> linux_list_files
volatility -f <memory_dump> linux_list_files_fd
volatility -f <memory_dump> linux_list_tasks
volatility -f <memory_dump> linux_lsof
volatility -f <memory_dump> linux_memmap
volatility -f <memory_dump> linux_mountinfo
volatility -f <memory_dump> linux_netstat
volatility -f <memory_dump> linux_psenv
volatility -f <memory_dump> linux_pslist
volatility -f <memory_dump> linux_pstree
volatility -f <memory_dump> linux_sockstat
volatility -f <memory_dump> linux_taskstats
volatility -f <memory_dump> linux_uname
volatility -f <memory_dump> linux_usb
volatility -f <memory_dump> linux_version
volatility -f <memory_dump> linux_vmstat
volatility -f <memory_dump> linux_wchan
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
{% endtab %}
{% endtabs %}

### Enlaces simbólicos

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{% endtab %}

{% tab title="volatility-cheatsheet" %}
# Volatility Cheatsheet

## Basic Commands

### Image Identification

```bash
volatility -f <image> imageinfo
```

### Profile Identification

```bash
volatility -f <image> imageinfo | grep Profile
```

### Process List

```bash
volatility -f <image> --profile=<profile> pslist
```

### Process Tree

```bash
volatility -f <image> --profile=<profile> pstree
```

### DLL List

```bash
volatility -f <image> --profile=<profile> dlllist
```

### Handles

```bash
volatility -f <image> --profile=<profile> handles
```

### Network Connections

```bash
volatility -f <image> --profile=<profile> netscan
```

### Open Files

```bash
volatility -f <image> --profile=<profile> filescan
```

### Registry Analysis

```bash
volatility -f <image> --profile=<profile> hivelist
volatility -f <image> --profile=<profile> printkey -K <key>
volatility -f <image> --profile=<profile> printval -K <key> -V <value>
```

### Dumping Processes

```bash
volatility -f <image> --profile=<profile> procdump -p <pid> -D <output_directory>
```

### Dumping Files

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <address_space> -D <output_directory>
```

### Strings

```bash
volatility -f <image> --profile=<profile> strings -s <address_space> -o <offset>
```

### Malware Analysis

```bash
volatility -f <image> --profile=<profile> malfind
volatility -f <image> --profile=<profile> malsysproc
volatility -f <image> --profile=<profile> malprocfind
```

## Advanced Commands

### Finding Hidden Processes

```bash
volatility -f <image> --profile=<profile> psxview
```

### Finding Hidden DLLs

```bash
volatility -f <image> --profile=<profile> ldrmodules
```

### Finding Hidden Sockets

```bash
volatility -f <image> --profile=<profile> sockets
```

### Finding Hidden Registry Keys

```bash
volatility -f <image> --profile=<profile> hivescan
```

### Finding Hidden Files

```bash
volatility -f <image> --profile=<profile> filescan -S -u
```

### Finding Hidden Processes and DLLs

```bash
volatility -f <image> --profile=<profile> mutantscan
```

### Finding Hidden Code Injection

```bash
volatility -f <image> --profile=<profile> malfind -Y <dll_name>
```

### Finding Hidden Rootkits

```bash
volatility -f <image> --profile=<profile> linux_check_afinfo
volatility -f <image> --profile=<profile> linux_check_creds
volatility -f <image> --profile=<profile> linux_check_fop
volatility -f <image> --profile=<profile> linux_check_idt
volatility -f <image> --profile=<profile> linux_check_modules
volatility -f <image> --profile=<profile> linux_check_syscall
volatility -f <image> --profile=<profile> linux_check_syscalltbl
volatility -f <image> --profile=<profile> linux_check_tty
volatility -f <image> --profile=<profile> linux_check_vdso
volatility -f <image> --profile=<profile> linux_hidden_modules
volatility -f <image> --profile=<profile> linux_hidden_procs
volatility -f <image> --profile=<profile> linux_hidden_syscall
volatility -f <image> --profile=<profile> linux_hidden_syscalltbl
volatility -f <image> --profile=<profile> linux_hidden_tty
volatility -f <image> --profile=<profile> linux_hidden_vdso
```
{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
### Bash

Es posible **leer desde la memoria el historial de bash**. También se podría volcar el archivo _.bash\_history_, pero si está desactivado, te alegrará saber que puedes utilizar este módulo de Volatility.
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% tab title="volatility-cheatsheet" %}
# Volatility Cheatsheet

## Basic Commands

### Image Identification

```bash
volatility -f <image> imageinfo
```

### Profile Identification

```bash
volatility -f <image> imageinfo | grep Profile
```

### Process List

```bash
volatility -f <image> --profile=<profile> pslist
```

### Process Tree

```bash
volatility -f <image> --profile=<profile> pstree
```

### DLL List

```bash
volatility -f <image> --profile=<profile> dlllist
```

### Handles

```bash
volatility -f <image> --profile=<profile> handles
```

### Network Connections

```bash
volatility -f <image> --profile=<profile> netscan
```

### Open Files

```bash
volatility -f <image> --profile=<profile> filescan
```

### Registry Analysis

```bash
volatility -f <image> --profile=<profile> hivelist
volatility -f <image> --profile=<profile> printkey -K <offset>
volatility -f <image> --profile=<profile> printkey -o <offset>
volatility -f <image> --profile=<profile> printval -K <offset>
volatility -f <image> --profile=<profile> printval -o <offset>
```

### Dumping Processes

```bash
volatility -f <image> --profile=<profile> procdump -p <pid> -D <output_directory>
```

### Dumping Files

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <string> -D <output_directory>
```

### Strings

```bash
volatility -f <image> --profile=<profile> strings -s <address> -e <address>
```

### Malware Analysis

```bash
volatility -f <image> --profile=<profile> malfind
volatility -f <image> --profile=<profile> malfind -Y <output_directory>
volatility -f <image> --profile=<profile> malfind -D <output_directory>
volatility -f <image> --profile=<profile> malfind -p <pid> -D <output_directory>
```

## Advanced Commands

### Finding Hidden Processes

```bash
volatility -f <image> --profile=<profile> psxview
```

### Finding Hidden DLLs

```bash
volatility -f <image> --profile=<profile> ldrmodules
```

### Finding Hidden Sockets

```bash
volatility -f <image> --profile=<profile> sockets
```

### Finding Hidden Registry Keys

```bash
volatility -f <image> --profile=<profile> hivescan
```

### Finding Hidden Files

```bash
volatility -f <image> --profile=<profile> filescan -S -D <output_directory>
```

### Finding Hidden Processes and DLLs

```bash
volatility -f <image> --profile=<profile> mutantscan
```

### Finding Hidden Code Injection

```bash
volatility -f <image> --profile=<profile> malfind -Y <output_directory>
volatility -f <image> --profile=<profile> malfind -D <output_directory>
volatility -f <image> --profile=<profile> malfind -p <pid> -D <output_directory>
```

### Finding Hidden Rootkits

```bash
volatility -f <image> --profile=<profile> linux_check_afinfo
volatility -f <image> --profile=<profile> linux_check_creds
volatility -f <image> --profile=<profile> linux_check_fop
volatility -f <image> --profile=<profile> linux_check_idt
volatility -f <image> --profile=<profile> linux_check_modules
volatility -f <image> --profile=<profile> linux_check_syscall
volatility -f <image> --profile=<profile> linux_check_syscalltbl
volatility -f <image> --profile=<profile> linux_check_tty
volatility -f <image> --profile=<profile> linux_check_uname
volatility -f <image> --profile=<profile> linux_check_syscall_generic
volatility -f <image> --profile=<profile> linux_hidden_modules
volatility -f <image> --profile=<profile> linux_hidden_procs
volatility -f <image> --profile=<profile> linux_hidden_files
volatility -f <image> --profile=<profile> linux_hidden_ports
volatility -f <image> --profile=<profile> linux_hidden_registries
volatility -f <image> --profile=<profile> linux_hidden_sockets
volatility -f <image> --profile=<profile> linux_hidden_syscall
volatility -f <image> --profile=<profile> linux_hidden_tty
volatility -f <image> --profile=<profile> linux_hidden_modules
volatility -f <image> --profile=<profile> linux_hidden_syscalltbl
volatility -f <image> --profile=<profile> linux_hidden_uname
```

### Finding Hidden Processes and DLLs (Windows 10)

```bash
volatility -f <image> --profile=<profile> pslist --apply-rules
volatility -f <image> --profile=<profile> dlllist --apply-rules
```

### Finding Hidden Code Injection (Windows 10)

```bash
volatility -f <image> --profile=<profile> malfind --apply-rules
```

### Finding Hidden Rootkits (Windows 10)

```bash
volatility -f <image> --profile=<profile> autoruns --apply-rules
volatility -f <image> --profile=<profile> driverirp --apply-rules
volatility -f <image> --profile=<profile> drivermodule --apply-rules
volatility -f <image> --profile=<profile> driverobject --apply-rules
volatility -f <image> --profile=<profile> driverscan --apply-rules
volatility -f <image> --profile=<profile> filescan --apply-rules
volatility -f <image> --profile=<profile> getsids --apply-rules
volatility -f <image> --profile=<profile> hivelist --apply-rules
volatility -f <image> --profile=<profile> hivescan --apply-rules
volatility -f <image> --profile=<profile> idt --apply-rules
volatility -f <image> --profile=<profile> imagecopy --apply-rules
volatility -f <image> --profile=<profile> imageinfo --apply-rules
volatility -f <image> --profile=<profile> ldrmodules --apply-rules
volatility -f <image> --profile=<profile> lsadump --apply-rules
volatility -f <image> --profile=<profile> malfind --apply-rules
volatility -f <image> --profile=<profile> mutantscan --apply-rules
volatility -f <image> --profile=<profile> netscan --apply-rules
volatility -f <image> --profile=<profile> printkey --apply-rules
volatility -f <image> --profile=<profile> privs --apply-rules
volatility -f <image> --profile=<profile> pslist --apply-rules
volatility -f <image> --profile=<profile> psscan --apply-rules
volatility -f <image> --profile=<profile> pstree --apply-rules
volatility -f <image> --profile=<profile> regdiff --apply-rules
volatility -f <image> --profile=<profile> registry --apply-rules
volatility -f <image> --profile=<profile> sockets --apply-rules
volatility -f <image> --profile=<profile> ssdt --apply-rules
volatility -f <image> --profile=<profile> symlinkscan --apply-rules
volatility -f <image> --profile=<profile> thrdscan --apply-rules
volatility -f <image> --profile=<profile> userassist --apply-rules
volatility -f <image> --profile=<profile> vadinfo --apply-rules
volatility -f <image> --profile=<profile> vadtree --apply-rules
volatility -f <image> --profile=<profile> windows --apply-rules
volatility -f <image> --profile=<profile> wintree --apply-rules
```

## References

- [Volatility Cheat Sheet](https://github.com/sans-dfir/sift/blob/master/Cheat%20Sheets/Volatility%20Cheat%20Sheet.pdf)
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
{% endtab %}
{% endtabs %}

### Línea de tiempo

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% endtab %}

{% tab title="volatility-cheatsheet" %}
# Volatility Cheatsheet

## Basic Commands

### Image Identification

```bash
volatility -f <image> imageinfo
```

### Profile Identification

```bash
volatility -f <image> imageinfo | grep Profile
```

### Process List

```bash
volatility -f <image> --profile=<profile> pslist
```

### Process Tree

```bash
volatility -f <image> --profile=<profile> pstree
```

### DLL List

```bash
volatility -f <image> --profile=<profile> dlllist
```

### Handles

```bash
volatility -f <image> --profile=<profile> handles
```

### Network Connections

```bash
volatility -f <image> --profile=<profile> netscan
```

### Open Files

```bash
volatility -f <image> --profile=<profile> filescan
```

### Registry Analysis

```bash
volatility -f <image> --profile=<profile> hivelist
volatility -f <image> --profile=<profile> printkey -K <offset>
volatility -f <image> --profile=<profile> printkey -o <offset>
volatility -f <image> --profile=<profile> printval -K <offset>
volatility -f <image> --profile=<profile> printval -o <offset>
```

### Dumping Processes

```bash
volatility -f <image> --profile=<profile> procdump -p <pid> -D <output_directory>
```

### Dumping Files

```bash
volatility -f <image> --profile=<profile> dumpfiles -Q <string> -D <output_directory>
```

### Strings

```bash
volatility -f <image> --profile=<profile> strings -s <address> -e <address>
```

### Malware Analysis

```bash
volatility -f <image> --profile=<profile> malfind
volatility -f <image> --profile=<profile> malfind -Y <output_directory>
volatility -f <image> --profile=<profile> malfind -D <output_directory>
volatility -f <image> --profile=<profile> malfind -p <pid> -D <output_directory>
```

## Advanced Commands

### Finding Hidden Processes

```bash
volatility -f <image> --profile=<profile> psxview
```

### Finding Hidden DLLs

```bash
volatility -f <image> --profile=<profile> ldrmodules
```

### Finding Hidden Sockets

```bash
volatility -f <image> --profile=<profile> sockets
```

### Finding Hidden Registry Keys

```bash
volatility -f <image> --profile=<profile> hivescan
```

### Finding Hidden Files

```bash
volatility -f <image> --profile=<profile> filescan -S -D <output_directory>
```

### Finding Hidden Processes and DLLs

```bash
volatility -f <image> --profile=<profile> mutantscan
```

### Finding Hidden Code Injection

```bash
volatility -f <image> --profile=<profile> malfind -Y <output_directory>
volatility -f <image> --profile=<profile> malfind -D <output_directory>
volatility -f <image> --profile=<profile> malfind -p <pid> -D <output_directory>
```

### Finding Hidden Rootkits

```bash
volatility -f <image> --profile=<profile> linux_check_afinfo
volatility -f <image> --profile=<profile> linux_check_creds
volatility -f <image> --profile=<profile> linux_check_fop
volatility -f <image> --profile=<profile> linux_check_idt
volatility -f <image> --profile=<profile> linux_check_modules
volatility -f <image> --profile=<profile> linux_check_syscall
volatility -f <image> --profile=<profile> linux_check_syscalltbl
volatility -f <image> --profile=<profile> linux_check_tty
volatility -f <image> --profile=<profile> linux_check_uname
volatility -f <image> --profile=<profile> linux_check_syscall_generic
volatility -f <image> --profile=<profile> linux_hidden_modules
volatility -f <image> --profile=<profile> linux_hidden_procs
volatility -f <image> --profile=<profile> linux_hidden_files
volatility -f <image> --profile=<profile> linux_hidden_ports
volatility -f <image> --profile=<profile> linux_hidden_registries
volatility -f <image> --profile=<profile> linux_hidden_sockets
volatility -f <image> --profile=<profile> linux_hidden_syscall
volatility -f <image> --profile=<profile> linux_hidden_tty
volatility -f <image> --profile=<profile> linux_hidden_modules
volatility -f <image> --profile=<profile> linux_hidden_syscalltbl
volatility -f <image> --profile=<profile> linux_hidden_uname
```

### Finding Hidden Processes and DLLs (Windows 10)

```bash
volatility -f <image> --profile=<profile> pslist --apply-rules
volatility -f <image> --profile=<profile> dlllist --apply-rules
```

### Finding Hidden Code Injection (Windows 10)

```bash
volatility -f <image> --profile=<profile> malfind --apply-rules
```

### Finding Hidden Rootkits (Windows 10)

```bash
volatility -f <image> --profile=<profile> autoruns --apply-rules
volatility -f <image> --profile=<profile> driverirp --apply-rules
volatility -f <image> --profile=<profile> drivermodule --apply-rules
volatility -f <image> --profile=<profile> driverobject --apply-rules
volatility -f <image> --profile=<profile> driverscan --apply-rules
volatility -f <image> --profile=<profile> filescan --apply-rules
volatility -f <image> --profile=<profile> getsids --apply-rules
volatility -f <image> --profile=<profile> hivelist --apply-rules
volatility -f <image> --profile=<profile> hivescan --apply-rules
volatility -f <image> --profile=<profile> idt --apply-rules
volatility -f <image> --profile=<profile> imagecopy --apply-rules
volatility -f <image> --profile=<profile> imageinfo --apply-rules
volatility -f <image> --profile=<profile> ldrmodules --apply-rules
volatility -f <image> --profile=<profile> lsadump --apply-rules
volatility -f <image> --profile=<profile> malfind --apply-rules
volatility -f <image> --profile=<profile> mutantscan --apply-rules
volatility -f <image> --profile=<profile> netscan --apply-rules
volatility -f <image> --profile=<profile> printkey --apply-rules
volatility -f <image> --profile=<profile> privs --apply-rules
volatility -f <image> --profile=<profile> pslist --apply-rules
volatility -f <image> --profile=<profile> psscan --apply-rules
volatility -f <image> --profile=<profile> pstree --apply-rules
volatility -f <image> --profile=<profile> regdiff --apply-rules
volatility -f <image> --profile=<profile> registry --apply-rules
volatility -f <image> --profile=<profile> sockets --apply-rules
volatility -f <image> --profile=<profile> ssdt --apply-rules
volatility -f <image> --profile=<profile> symlinkscan --apply-rules
volatility -f <image> --profile=<profile> thrdscan --apply-rules
volatility -f <image> --profile=<profile> userassist --apply-rules
volatility -f <image> --profile=<profile> vadinfo --apply-rules
volatility -f <image> --profile=<profile> vadtree --apply-rules
volatility -f <image> --profile=<profile> windows --apply-rules
volatility -f <image> --profile=<profile> wintree --apply-rules
```

## References

- [Volatility Cheat Sheet](https://github.com/sans-dfir/sift/blob/master/Cheat%20Sheets/Volatility%20Cheat%20Sheet.pdf)
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{% endtab %}
{% tab title="volatility" %}
# Volatility Cheat Sheet

## Drivers

### List loaded drivers

```
volatility -f <memory_dump> --profile=<profile> driverlist
```

### Dump a driver

```
volatility -f <memory_dump> --profile=<profile> moddump -D <output_directory> -n <driver_name>
```

### Scan for hidden drivers

```
volatility -f <memory_dump> --profile=<profile> ldrmodules
```

### Dump a hidden driver

```
volatility -f <memory_dump> --profile=<profile> moddump -D <output_directory> -n <driver_name> -m
```

### Check for unsigned drivers

```
volatility -f <memory_dump> --profile=<profile> ldrmodules | grep -i unsigned
```

### Dump a specific driver

```
volatility -f <memory_dump> --profile=<profile> moddump -D <output_directory> -n <driver_name>
```

### Dump all drivers

```
volatility -f <memory_dump> --profile=<profile> moddump -D <output_directory> --dump-dir=<output_directory>
```

### Check for driver hooks

```
volatility -f <memory_dump> --profile=<profile> callbacks
```

### Check for SSDT hooks

```
volatility -f <memory_dump> --profile=<profile> ssdt
```

### Check for inline hooks

```
volatility -f <memory_dump> --profile=<profile> apihooks
```

### Check for driver objects

```
volatility -f <memory_dump> --profile=<profile> driverirp
```

### Check for driver objects by driver name

```
volatility -f <memory_dump> --profile=<profile> driverirp -n <driver_name>
```

### Check for driver objects by device name

```
volatility -f <memory_dump> --profile=<profile> driverirp -d <device_name>
```

### Check for driver objects by driver object address

```
volatility -f <memory_dump> --profile=<profile> driverirp -a <driver_object_address>
```

### Check for driver objects by file object address

```
volatility -f <memory_dump> --profile=<profile> driverirp -f <file_object_address>
```

### Check for driver objects by driver start address

```
volatility -f <memory_dump> --profile=<profile> driverirp -s <driver_start_address>
```

### Check for driver objects by driver extension address

```
volatility -f <memory_dump> --profile=<profile> driverirp -e <driver_extension_address>
```

### Check for driver objects by driver device object address

```
volatility -f <memory_dump> --profile=<profile> driverirp -o <driver_device_object_address>
```

### Check for driver objects by driver device object name

```
volatility -f <memory_dump> --profile=<profile> driverirp -v <driver_device_object_name>
```

### Check for driver objects by driver device object type

```
volatility -f <memory_dump> --profile=<profile> driverirp -t <driver_device_object_type>
```

### Check for driver objects by driver device object driver name

```
volatility -f <memory_dump> --profile=<profile> driverirp -u <driver_device_object_driver_name>
```

### Check for driver objects by driver device object driver type

```
volatility -f <memory_dump> --profile=<profile> driverirp -y <driver_device_object_driver_type>
```

### Check for driver objects by driver device object driver extension address

```
volatility -f <memory_dump> --profile=<profile> driverirp -x <driver_device_object_driver_extension_address>
```

### Check for driver objects by driver device object driver extension name

```
volatility -f <memory_dump> --profile=<profile> driverirp -z <driver_device_object_driver_extension_name>
```

### Check for driver objects by driver device object driver extension type

```
volatility -f <memory_dump> --profile=<profile> driverirp -w <driver_device_object_driver_extension_type>
```

### Check for driver objects by driver device object driver extension driver name

```
volatility -f <memory_dump> --profile=<profile> driverirp -q <driver_device_object_driver_extension_driver_name>
```

### Check for driver objects by driver device object driver extension driver type

```
volatility -f <memory_dump> --profile=<profile> driverirp -p <driver_device_object_driver_extension_driver_type>
```

### Check for driver objects by driver device object driver extension driver object address

```
volatility -f <memory_dump> --profile=<profile> driverirp -r <driver_device_object_driver_extension_driver_object_address>
```

### Check for driver objects by driver device object driver extension driver object name

```
volatility -f <memory_dump> --profile=<profile> driverirp -i <driver_device_object_driver_extension_driver_object_name>
```

### Check for driver objects by driver device object driver extension driver object type

```
volatility -f <memory_dump> --profile=<profile> driverirp -j <driver_device_object_driver_extension_driver_object_type>
```

### Check for driver objects by driver device object driver extension driver object driver name

```
volatility -f <memory_dump> --profile=<profile> driverirp -k <driver_device_object_driver_extension_driver_object_driver_name>
```

### Check for driver objects by driver device object driver extension driver object driver type

```
volatility -f <memory_dump> --profile=<profile> driverirp -l <driver_device_object_driver_extension_driver_object_driver_type>
```

### Check for driver objects by driver device object driver extension driver object driver object address

```
volatility -f <memory_dump> --profile=<profile> driverirp -m <driver_device_object_driver_extension_driver_object_driver_object_address>
```

### Check for driver objects by driver device object driver extension driver object driver object name

```
volatility -f <memory_dump> --profile=<profile> driverirp -n <driver_device_object_driver_extension_driver_object_driver_object_name>
```

### Check for driver objects by driver device object driver extension driver object driver object type

```
volatility -f <memory_dump> --profile=<profile> driverirp -o <driver_device_object_driver_extension_driver_object_driver_object_type>
```

### Check for driver objects by driver device object driver extension driver object driver object driver name

```
volatility -f <memory_dump> --profile=<profile> driverirp -p <driver_device_object_driver_extension_driver_object_driver_object_driver_name>
```

### Check for driver objects by driver device object driver extension driver object driver object driver type

```
volatility -f <memory_dump> --profile=<profile> driverirp -q <driver_device_object_driver_extension_driver_object_driver_object_driver_type>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object address

```
volatility -f <memory_dump> --profile=<profile> driverirp -r <driver_device_object_driver_extension_driver_object_driver_object_driver_object_address>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object name

```
volatility -f <memory_dump> --profile=<profile> driverirp -s <driver_device_object_driver_extension_driver_object_driver_object_driver_object_name>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object type

```
volatility -f <memory_dump> --profile=<profile> driverirp -t <driver_device_object_driver_extension_driver_object_driver_object_driver_object_type>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver name

```
volatility -f <memory_dump> --profile=<profile> driverirp -u <driver_device_object_driver_extension_driver_object_driver_object_driver_name>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver type

```
volatility -f <memory_dump> --profile=<profile> driverirp -v <driver_device_object_driver_extension_driver_object_driver_object_driver_type>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object address

```
volatility -f <memory_dump> --profile=<profile> driverirp -w <driver_device_object_driver_extension_driver_object_driver_object_driver_object_address>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object name

```
volatility -f <memory_dump> --profile=<profile> driverirp -x <driver_device_object_driver_extension_driver_object_driver_object_driver_object_name>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object type

```
volatility -f <memory_dump> --profile=<profile> driverirp -y <driver_device_object_driver_extension_driver_object_driver_object_driver_object_type>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver name

```
volatility -f <memory_dump> --profile=<profile> driverirp -z <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_name>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver type

```
volatility -f <memory_dump> --profile=<profile> driverirp -a <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_type>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object address

```
volatility -f <memory_dump> --profile=<profile> driverirp -b <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_address>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object name

```
volatility -f <memory_dump> --profile=<profile> driverirp -c <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_name>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object type

```
volatility -f <memory_dump> --profile=<profile> driverirp -d <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_type>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver name

```
volatility -f <memory_dump> --profile=<profile> driverirp -e <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_name>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver type

```
volatility -f <memory_dump> --profile=<profile> driverirp -f <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_type>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object address

```
volatility -f <memory_dump> --profile=<profile> driverirp -g <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_address>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object name

```
volatility -f <memory_dump> --profile=<profile> driverirp -h <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_name>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object type

```
volatility -f <memory_dump> --profile=<profile> driverirp -i <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_type>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver name

```
volatility -f <memory_dump> --profile=<profile> driverirp -j <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_driver_name>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver type

```
volatility -f <memory_dump> --profile=<profile> driverirp -k <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_driver_type>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver address

```
volatility -f <memory_dump> --profile=<profile> driverirp -l <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_driver_address>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver name

```
volatility -f <memory_dump> --profile=<profile> driverirp -m <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_driver_name>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver type

```
volatility -f <memory_dump> --profile=<profile> driverirp -n <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_type>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver object address

```
volatility -f <memory_dump> --profile=<profile> driverirp -o <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_address>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver object name

```
volatility -f <memory_dump> --profile=<profile> driverirp -p <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_driver_name>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver object type

```
volatility -f <memory_dump> --profile=<profile> driverirp -q <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_driver_type>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver object address

```
volatility -f <memory_dump> --profile=<profile> driverirp -r <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_driver_address>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver object name

```
volatility -f <memory_dump> --profile=<profile> driverirp -s <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_driver_name>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver object type

```
volatility -f <memory_dump> --profile=<profile> driverirp -t <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_driver_type>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver object driver name

```
volatility -f <memory_dump> --profile=<profile> driverirp -u <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_driver_object_name>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver object driver type

```
volatility -f <memory_dump> --profile=<profile> driverirp -v <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_driver_object_type>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver object address

```
volatility -f <memory_dump> --profile=<profile> driverirp -w <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_driver_address>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver object name

```
volatility -f <memory_dump> --profile=<profile> driverirp -x <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_driver_name>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver object type

```
volatility -f <memory_dump> --profile=<profile> driverirp -y <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_driver_type>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver object address

```
volatility -f <memory_dump> --profile=<profile> driverirp -z <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_driver_address>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver object name

```
volatility -f <memory_dump> --profile=<profile> driverirp -a <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_driver_name>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver object type

```
volatility -f <memory_dump> --profile=<profile> driverirp -b <driver_device_object_driver_extension_driver_object_driver_object_driver_object_driver_object_driver_object_driver_type>
```

### Check for driver objects by driver device object driver extension driver object driver object driver object driver object driver object driver object driver object address

```
volatility -f <memory_dump> --profile=<profile> driverirp -c <driver_device_object_driver
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Volatility Installation

### Linux

```bash
sudo apt-get install volatility
```

### Windows

Download the latest version from the [official website](https://www.volatilityfoundation.org/releases).

## Volatility Usage

### Basic Commands

```bash
volatility -f <memory_dump> imageinfo
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> handles
volatility -f <memory_dump> filescan
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> privs
volatility -f <memory_dump> apihooks
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> userassist
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> malfind
volatility -f <memory_dump> mftparser
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> printkey
volatility -f <memory_dump> hashdump
volatility -f <memory_dump> envars
volatility -f <memory_dump> dumpregistry
volatility -f <memory_dump> dumpfiles
volatility -f <memory_dump> memdump
```

### Advanced Commands

```bash
volatility -f <memory_dump> --profile=<profile> <plugin> <options>
```

### Plugins

#### Malware Analysis

```bash
volatility -f <memory_dump> malfind
volatility -f <memory_dump> malfind -Y <path_to_yara_rules>
volatility -f <memory_dump> malfind -D <path_to_dump_directory>
volatility -f <memory_dump> malfind -p <pid>
volatility -f <memory_dump> malfind -u <user>
volatility -f <memory_dump> malfind -P <process_name>
volatility -f <memory_dump> malfind -Y <path_to_yara_rules> -D <path_to_dump_directory> -p <pid> -u <user> -P <process_name>
```

```bash
volatility -f <memory_dump> mftparser
volatility -f <memory_dump> mftparser -o <output_directory>
volatility -f <memory_dump> mftparser -f <filename>
volatility -f <memory_dump> mftparser -o <output_directory> -f <filename>
```

#### Registry Analysis

```bash
volatility -f <memory_dump> hivelist
volatility -f <memory_dump> hivelist -o <output_directory>
volatility -f <memory_dump> hivelist -o <output_directory> -p <pid>
volatility -f <memory_dump> hivelist -o <output_directory> -p <pid> -u <user>
```

```bash
volatility -f <memory_dump> printkey -K <key>
volatility -f <memory_dump> printkey -K <key> -o <output_directory>
volatility -f <memory_dump> printkey -K <key> -o <output_directory> -p <pid>
volatility -f <memory_dump> printkey -K <key> -o <output_directory> -p <pid> -u <user>
```

```bash
volatility -f <memory_dump> hashdump -s <system_hive> -s <software_hive>
volatility -f <memory_dump> hashdump -s <system_hive> -s <software_hive> -o <output_directory>
volatility -f <memory_dump> hashdump -s <system_hive> -s <software_hive> -o <output_directory> -p <pid>
volatility -f <memory_dump> hashdump -s <system_hive> -s <software_hive> -o <output_directory> -p <pid> -u <user>
```

#### Network Analysis

```bash
volatility -f <memory_dump> netscan
volatility -f <memory_dump> connscan
```

#### Process Analysis

```bash
volatility -f <memory_dump> pslist
volatility -f <memory_dump> pstree
volatility -f <memory_dump> psscan
volatility -f <memory_dump> handles
volatility -f <memory_dump> cmdline
volatility -f <memory_dump> consoles
volatility -f <memory_dump> getsids
volatility -f <memory_dump> getservicesids
volatility -f <memory_dump> privs
volatility -f <memory_dump> apihooks
```

#### File Analysis

```bash
volatility -f <memory_dump> dlllist
volatility -f <memory_dump> filescan
volatility -f <memory_dump> dumpfiles -Q <file_path>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> -p <pid>
volatility -f <memory_dump> dumpfiles -Q <file_path> -D <output_directory> -p <pid> -u <user>
```

#### Memory Analysis

```bash
volatility -f <memory_dump> memdump -p <pid>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
volatility -f <memory_dump> memdump -p <pid> -D <output_directory> --dump-dir=<dump_directory>
```

#### Other

```bash
volatility -f <memory_dump> shimcache
volatility -f <memory_dump> userassist
volatility -f <memory_dump> idt
volatility -f <memory_dump> gdt
volatility -f <memory_dump> envars
```

## Volatility Profiles

### Linux

```bash
volatility --info | grep Linux
```

### Windows

```bash
volatility --info | grep Win
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
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
### Obtener el historial de Internet Explorer
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
### Registro de arranque principal (MBR)
```
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
El MBR contiene información sobre cómo se organizan las particiones lógicas, que contienen sistemas de archivos, en ese medio. El MBR también contiene código ejecutable para funcionar como cargador del sistema operativo instalado, generalmente pasando el control al segundo nivel del cargador o en conjunto con el registro de arranque del volumen de cada partición (VBR). Este código MBR se conoce comúnmente como cargador de arranque. De aquí.

RootedCON es el evento de ciberseguridad más relevante en España y uno de los más importantes en Europa. Con la misión de promover el conocimiento técnico, este congreso es un punto de encuentro para profesionales de la tecnología y la ciberseguridad en todas las disciplinas.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una empresa de ciberseguridad? ¿Quieres ver tu empresa anunciada en HackTricks? ¿O quieres tener acceso a la última versión de PEASS o descargar HackTricks en PDF? ¡Consulta los PLANES DE SUSCRIPCIÓN!
* Descubre The PEASS Family, nuestra colección exclusiva de NFTs
* Obtén el swag oficial de PEASS y HackTricks
* Únete al grupo de Discord o al grupo de Telegram o sígueme en Twitter @carlospolopm.
* Comparte tus trucos de hacking enviando PR al repositorio de hacktricks y al repositorio de hacktricks-cloud.

</details>
