# Volatility - Hoja de trucos

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro candente para profesionales de la tecnología y ciberseguridad en todas las disciplinas.

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

Esto hace que los plugins "list" sean bastante rápidos, pero igual de vulnerables que la API de Windows a la manipulación por malware. Por ejemplo, si el malware utiliza DKOM para desvincular un proceso de la lista enlazada de `_EPROCESS`, no aparecerá en el Administrador de tareas ni en la lista de procesos.

Los plugins "scan", por otro lado, tomarán un enfoque similar a tallar la memoria en busca de cosas que podrían tener sentido al desreferenciarlas como estructuras específicas. `psscan`, por ejemplo, leerá la memoria e intentará crear objetos `_EPROCESS` a partir de ella (utiliza el escaneo de etiquetas de grupo, que busca cadenas de 4 bytes que indiquen la presencia de una estructura de interés). La ventaja es que puede descubrir procesos que han salido, e incluso si el malware manipula la lista enlazada de `_EPROCESS`, el plugin seguirá encontrando la estructura en la memoria (ya que aún necesita existir para que el proceso se ejecute). La desventaja es que los plugins "scan" son un poco más lentos que los plugins "list" y a veces pueden dar falsos positivos (un proceso que salió hace mucho tiempo y tuvo partes de su estructura sobrescritas por otras operaciones).

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

[**Desde aquí**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): A diferencia de imageinfo que simplemente proporciona sugerencias de perfil, **kdbgscan** está diseñado para identificar positivamente el perfil correcto y la dirección KDBG correcta (si hay múltiples). Este complemento escanea las firmas de encabezado KDBG vinculadas a perfiles de Volatility y aplica controles de integridad para reducir falsos positivos. La verbosidad de la salida y la cantidad de controles de integridad que se pueden realizar dependen de si Volatility puede encontrar un DTB, por lo que si ya conoce el perfil correcto (o si tiene una sugerencia de perfil de imageinfo), asegúrese de usarlo desde .

Siempre eche un vistazo al **número de procesos que kdbgscan ha encontrado**. A veces imageinfo y kdbgscan pueden encontrar **más de un** **perfil adecuado** pero solo el **válido tendrá algunos procesos relacionados** (Esto se debe a que para extraer procesos se necesita la dirección KDBG correcta)
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

El **bloque del depurador del kernel**, conocido como **KDBG** por Volatility, es crucial para las tareas forenses realizadas por Volatility y varios depuradores. Identificado como `KdDebuggerDataBlock` y del tipo `_KDDEBUGGER_DATA64`, contiene referencias esenciales como `PsActiveProcessHead`. Esta referencia específica apunta a la cabecera de la lista de procesos, lo que permite la enumeración de todos los procesos, lo cual es fundamental para un análisis exhaustivo de la memoria.

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
- **volatility -f <archivo> malfind**: Encuentra procesos sospechosos en el volcado de memoria.
- **volatility -f <archivo> yarascan**: Escanea el volcado de memoria en busca de patrones YARA.
- **volatility -f <archivo> consoles**: Muestra las consolas interactivas encontradas en el volcado de memoria.
- **volatility -f <archivo> hivelist**: Enumera los archivos de registro presentes en el volcado de memoria.
- **volatility -f <archivo> printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <archivo> userassist**: Muestra las entradas de UserAssist en el volcado de memoria.
- **volatility -f <archivo> shimcache**: Muestra la información de ShimCache en el volcado de memoria.
- **volatility -f <archivo> ldrmodules**: Enumera los módulos cargados en el espacio de usuario.
- **volatility -f <archivo> modscan**: Escanea módulos en el volcado de memoria.
- **volatility -f <archivo> getsids**: Enumera los SID de usuario en el volcado de memoria.
- **volatility -f <archivo> hivescan**: Escanea los archivos de registro en busca de subprocesos.
- **volatility -f <archivo> apihooks**: Enumera los ganchos de API en el volcado de memoria.
- **volatility -f <archivo> callbacks**: Enumera los callbacks en el volcado de memoria.
- **volatility -f <archivo> driverirp**: Enumera los IRP manejadores de un driver en el volcado de memoria.
- **volatility -f <archivo> ssdt**: Enumera los servicios del Sistema de Tabla de Descriptores en el volcado de memoria.
- **volatility -f <archivo> driverscan**: Escanea los drivers en busca de discrepancias.
- **volatility -f <archivo> svcscan**: Escanea los servicios en busca de discrepancias.
- **volatility -f <archivo> mutantscan**: Escanea los objetos de mutante en el volcado de memoria.
- **volatility -f <archivo> envars**: Enumera las variables de entorno en el volcado de memoria.
- **volatility -f <archivo> atomscan**: Escanea los objetos de átomos en el volcado de memoria.
- **volatility -f <archivo> deskscan**: Escanea los objetos de escritorio en el volcado de memoria.
- **volatility -f <archivo> vadinfo -o <offset>**: Muestra información sobre un área de memoria específica.
- **volatility -f <archivo> vadtree -o <offset>**: Muestra un árbol de áreas de memoria.
- **volatility -f <archivo> memmap -o <offset>**: Muestra el mapeo de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D
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

Intenta encontrar procesos **sospechosos** (por nombre) o **inesperados** procesos secundarios (por ejemplo, un cmd.exe como proceso secundario de iexplorer.exe).\
Podría ser interesante **comparar** el resultado de pslist con el de psscan para identificar procesos ocultos.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
### Volatility Cheatsheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Extracting Files**
  - `volatility -f <memory_dump> --profile=<profile> file -S <start_address> -E <end_address> --output=<output_directory>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Identifying Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing Packed Binaries**
  - `volatility -f <memory_dump> --profile=<profile> mpp`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Pools**
  - `volatility -f <memory_dump> --profile=<profile> poolscanner`

- **Analyzing Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Analyzing User Sessions**
  - `volatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing User Accounts**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing API Calls**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing VAD Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing VAD Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
### Volcar proc

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
- **volatility -f <archivo> psscan**: Escanea procesos a través del volcado de memoria.
- **volatility -f <archivo> dlllist -p <PID>**: Muestra las DLL cargadas por un proceso específico.
- **volatility -f <archivo> cmdline -p <PID>**: Muestra el comando utilizado para ejecutar un proceso específico.
- **volatility -f <archivo> filescan**: Escanea descriptores de archivos en el volcado de memoria.
- **volatility -f <archivo> netscan**: Escanea conexiones de red en el volcado de memoria.
- **volatility -f <archivo> connections**: Muestra las conexiones de red en el volcado de memoria.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código en procesos.
- **volatility -f <archivo> yarascan**: Escanea el volcado de memoria en busca de cadenas con Yara.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> hivelist**: Enumera los registros del sistema en el volcado de memoria.
- **volatility -f <archivo> printkey -o <offset>**: Imprime una clave del registro en el volcado de memoria.
- **volatility -f <archivo> userassist**: Recupera entradas de UserAssist del registro.
- **volatility -f <archivo> shimcache**: Recupera información de ShimCache del registro.
- **volatility -f <archivo> ldrmodules**: Enumera los módulos cargados en el espacio de usuario.
- **volatility -f <archivo> modscan**: Escanea módulos en el volcado de memoria.
- **volatility -f <archivo> getsids**: Enumera los SID de usuario en el volcado de memoria.
- **volatility -f <archivo> apihooks**: Enumera los ganchos de API en el volcado de memoria.
- **volatility -f <archivo> callbacks**: Enumera los callbacks en el volcado de memoria.
- **volatility -f <archivo> driverirp**: Enumera los IRP manejadores de un driver en el volcado de memoria.
- **volatility -f <archivo> svcscan**: Escanea servicios en el volcado de memoria.
- **volatility -f <archivo> svcscan -s**: Escanea servicios ocultos en el volcado de memoria.
- **volatility -f <archivo> drivermodule**: Enumera los módulos de driver en el volcado de memoria.
- **volatility -f <archivo> devicetree**: Enumera el árbol de dispositivos en el volcado de memoria.
- **volatility -f <archivo> hivescan**: Escanea registros en busca de subkeys.
- **volatility -f <archivo> printkey -K <key>**: Imprime una clave específica del registro en el volcado de memoria.
- **volatility -f <archivo> printkey -f <file>**: Imprime una clave del registro desde un archivo en el volcado de memoria.
- **volatility -f <archivo> hashdump**: Extrae hashes de contraseñas del volcado de memoria.
- **volatility -f <archivo> mimikatz**: Ejecuta Mimikatz en el volcado de memoria.
- **volatility -f <archivo> truecryptmaster**: Recupera la clave maestra de TrueCrypt del volcado de memoria.
- **volatility -f <archivo> truecryptpassphrase**: Recupera la frase de contraseña de TrueCrypt del volcado de memoria.
- **volatility -f <archivo> truecryptsummary**: Muestra un resumen de TrueCrypt en el volcado de memoria.
- **volatility -f <archivo> envars**: Enumera las variables de entorno en el volcado de memoria.
- **volatility -f <archivo> consoles**: Enumera las consolas interactivas en el volcado de memoria.
- **volatility -f <archivo> consoles -s**: Enumera las consolas de servicios en el volcado de memoria.
- **volatility -f <archivo> deskscan**: Escanea escritorios en el volcado de memoria.
- **volatility -f <archivo> deskscan -D <desktop>**: Escanea un escritorio específico en el volcado de memoria.
- **volatility -f <archivo> screenshot**: Toma una captura de pantalla del escritorio actual en el volcado de memoria.
- **volatility -f <archivo> memmap**: Muestra un mapa de memoria del volcado de memoria.
- **volatility -f <archivo> memdump -p <PID> -D <destino>**: Realiza un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -b <dirección> -D <destino>**: Realiza un volcado de memoria de una región de memoria específica.
- **volatility -f <archivo> memstrings -s <tamaño>**: Escanea el volcado de memoria en busca de cadenas ASCII.
- **volatility -f <archivo> memstrings -s <tamaño> -o <offset>**: Escanea el volcado de memoria en busca de cadenas ASCII desde una ubicación específica.
- **volatility -f <archivo> memstrings -s <tamaño> -p <PID>**: Escanea el volcado de memoria de un proceso específico en busca de cadenas ASCII.
- **volatility -f <archivo> memstrings -s <tamaño> -o <offset> -p <PID>**: Escanea el volcado de memoria de un proceso específico en busca de cadenas ASCII desde una ubicación específica.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código en procesos.
- **volatility -f <archivo> malfind -p <PID>**: Encuentra inyecciones de código en un proceso específico.
- **volatility -f <archivo> malfind -D <destino>**: Escanea el volcado de memoria en busca de inyecciones de código y las extrae al destino especificado.
- **volatility -f <archivo> malfind -Y <ruta>**: Escanea el volcado de memoria en busca de inyecciones de código y las extrae a una carpeta temporal.
- **volatility -f <archivo> malfind -p <PID> -D <destino>**: Escanea un proceso específico en busca de inyecciones de código y las extrae al destino especificado.
- **volatility -f <archivo> malfind -p <PID> -Y <ruta>**: Escanea un proceso específico en busca de inyecciones de código y las extrae a una carpeta temporal.
- **volatility -f <archivo> malfind -D <destino> -Y <ruta>**: Escanea el volcado de memoria en busca de inyecciones de código y las extrae al destino especificado y a una carpeta temporal.
- **volatility -f <archivo> malfind -p <PID> -D <destino> -Y <ruta>**: Escanea un proceso específico en busca de inyecciones de código y las extrae al destino especificado y a una carpeta temporal.
- **volatility -f <archivo> malfind -D <destino> -Y <ruta> -U**: Escanea el volcado de memoria en busca de inyecciones de código y las extrae al destino especificado y a una carpeta temporal, sobrescribiendo los archivos existentes.
- **volatility -f <archivo> malfind -p <PID> -D <destino> -Y <ruta> -U**: Escanea un proceso específico en busca de inyecciones de código y las extrae al destino especificado y a una carpeta temporal, sobrescribiendo los archivos existentes.

#### Plugins de Volatility

- **apihooks**: Enumera los ganchos de API en el volcado de memoria.
- **atoms**: Enumera los átomos del sistema en el volcado de memoria.
- **atomscan**: Escanea átomos del sistema en el volcado de memoria.
- **atomscan -s**: Escanea átomos del sistema ocultos en el volcado de memoria.
- **bigpools**: Enumera los big pools en el volcado de memoria.
- **callbacks**: Enumera los callbacks en el volcado de memoria.
- **clipboard**: Recupera el contenido del portapapeles del sistema.
- **cmdline**: Muestra el comando utilizado para ejecutar un proceso específico.
- **cmdscan**: Escanea comandos en el volcado de memoria.
- **connections**: Muestra las conexiones de red en el volcado de memoria.
- **connscan**: Escanea conexiones de red en el volcado de memoria.
- **consoles**: Enumera las consolas interactivas en el volcado de memoria.
- **consoles -s**: Enumera las consolas de servicios en el volcado de memoria.
- **crashinfo**: Muestra información de bloqueo del sistema.
- **deskscan**: Escanea escritorios en el volcado de memoria.
- **devicetree**: Enumera el árbol de dispositivos en el volcado de memoria.
- **dlllist**: Muestra las DLL cargadas por un proceso específico.
- **driverirp**: Enumera los IRP manejadores de un driver en el volcado de memoria.
- **drivermodule**: Enumera los módulos de driver en el volcado de memoria.
- **driverscan**: Escanea drivers en el volcado de memoria.
- **envars**: Enumera las variables de entorno en el volcado de memoria.
- **eventhooks**: Enumera los ganchos de eventos en el volcado de memoria.
- **filescan**: Escanea descriptores de archivos en el volcado de memoria.
- **gahti**: Enumera los objetos de kernel en el volcado de memoria.
- **gditimers**: Enumera los temporizadores de GDI en el volcado de memoria.
- **getservicesids**: Enumera los SID de usuario en el volcado de memoria.
- **getsids**: Enumera los SID de usuario en el volcado de memoria.
- **handles**: Enumera los handles abiertos en el volcado de memoria.
- **hashdump**: Extrae hashes de contraseñas del volcado de memoria.
- **hivelist**: Enumera los registros del sistema en el volcado de memoria.
- **hivescan**: Escanea registros en busca de subkeys.
- **idt**: Enumera la IDT (Interrupt Descriptor Table) en el volcado de memoria.
- **iehistory**: Recupera el historial de Internet Explorer.
- **imagecopy**: Copia secciones de memoria a un archivo.
- **imageinfo**: Muestra información básica sobre el volcado de memoria.
- **impscan**: Escanea procesos en busca de módulos importados.
- **joblinks**: Enumera los enlaces de trabajos en el volcado de memoria.
- **kdbgscan**: Escanea el volcado de memoria en busca de estructuras KDBG.
- **kpcrscan**: Escanea el volcado de memoria en busca de estructuras KPCR.
- **ldrmodules**: Enumera los módulos cargados en el espacio de usuario.
- **lsadump**: Extrae información de seguridad de la base de datos de LSA.
- **machoinfo**: Muestra información sobre binarios Mach-O.
- **malfind**: Encuentra inyecciones de código en procesos.
- **mbrparser**: Analiza el registro maestro de arranque.
- **memdump**: Realiza un volcado de memoria de un proceso específico.
- **memmap**: Muestra un mapa de memoria del volcado de memoria.
- **memstrings**: Escanea el volcado de memoria en busca de cadenas ASCII.
- **messagehooks**: Enumera los ganchos de mensajes en el volcado de memoria.
- **moddump**: Extrae un módulo del volcado de memoria.
- **modscan**: Escanea módulos en el volcado de memoria.
- **modules**: Enumera los módulos cargados en el volcado de memoria.
- **mutantscan**: Escanea mutantes en el volcado de memoria.
- **mutantscan -s**: Escanea mutantes ocultos en el volcado de memoria.
- **netscan**: Escanea conexiones de red en el volcado de memoria.
- **notepad**: Recupera el contenido del Bloc de notas del sistema.
- **objtypescan**: Escanea tipos de objetos en el volcado de memoria.
- **patcher**: Parchea un binario en el volcado de memoria.
- **printkey**: Imprime una clave del registro en el volcado de memoria.
- **privs**: Enumera los privilegios del sistema.
- **procdump**: Realiza un volcado de memoria de un proceso específico.
- **procexedump**: Extrae el ejecutable de un proceso del volcado de memoria.
- **procmemdump**: Realiza un volcado de memoria de un proceso específico.
- **pslist**: Muestra una lista de procesos en el volcado de memoria.
- **psscan**: Escanea procesos a través del volcado de memoria.
- **pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **psxview**: Enumera procesos ocultos en el volcado de memoria.
- **raw2dmp**: Convierte un archivo de volcado de memoria en formato RAW a formato DMP.
- **raw2dmp -f <formato>**: Convierte un archivo de volcado de memoria en formato RAW a formato DMP con un formato específico.
- **screenshot**: Toma una captura de pantalla del escritorio actual en el volcado de memoria.
- **sessions**: Enumera las sesiones del sistema.
- **shellbags**: Recupera información de ShellBags del registro.
- **shimcache**: Recupera información de ShimCache del registro.
- **sockets**: Enumera los sockets abiertos en el volcado de memoria.
- **ssdt**: Enumera la SSDT (System Service Descriptor Table) en el volcado de memoria.
- **strings**: Escanea el volcado de memoria en busca de cadenas ASCII y Unicode.
- **svcscan**: Escanea servicios en el volcado de memoria.
- **svcscan -s**: Escanea servicios ocultos en el volcado de memoria.
- **symlinkscan**: Escanea enlaces simbólicos en el volcado de memoria.
- **thrdscan**: Escanea hilos en el volcado de memoria.
- **threads**: Enumera los hilos en el volcado de memoria.
- **timeliner**: Crea una línea de tiempo de eventos basada en la información del volcado de memoria.
- **timers**: Enumera los temporizadores en el volcado de memoria.
- **truecryptmaster**: Recupera la clave maestra de TrueCrypt del volcado de memoria.
- **truecryptpassphrase**: Recupera la frase de contraseña de TrueCrypt del volcado de memoria.
- **truecryptsummary**: Muestra un resumen de TrueCrypt en el volcado de memoria.
- **unloadedmodules**: Enumera los módulos descargados en el volcado de memoria.
- **userassist**: Recupera entradas de UserAssist del registro.
- **vadinfo**: Muestra información sobre los descriptores de áreas de memoria virtuales.
- **vaddump**: Extrae una región de memoria virtual del volcado de memoria.
- **vadtree**: Muestra un árbol de descriptores de áreas de memoria virtuales.
- **vadwalk**: Muestra las direcciones de memoria en una región de memoria virtual.
- **vboxinfo**: Muestra información sobre máquinas virtuales VirtualBox.
- **vmwareinfo**: Muestra información sobre máquinas virtuales VMware.
- **volshell**: Inicia un shell interactivo de Volatility.
- **windows**: Enumera los procesos de Windows en el volcado de memoria.
- **wndscan**: Escanea ventanas en el volcado de memoria.
- **yarascan**: Escanea el volcado de memoria en busca de cadenas con Yara.

#### Ejemplos de Uso

- **volatility -f memdump.mem memdump -p 123 -D /tmp/**: Realiza un volcado de memoria del proceso con PID 123 y lo guarda en /tmp/.
- **volatility -f memdump.mem pslist**: Muestra una lista de procesos en el volcado de memoria.
- **volatility -f memdump.mem dlllist -p 456**: Muestra las DLL cargadas por el proceso con PID 456.
- **volatility -f memdump.mem filescan**: Escanea descriptores de archivos en el volcado de memoria.
- **volatility -f memdump.mem hashdump**: Extrae hashes de contraseñas del volcado de memoria.
- **volatility -f memdump.mem malfind -Y /tmp/**: Escanea el volcado de memoria en busca de inyecciones de código y las extrae a /tmp/.
- **volatility -f memdump.mem truecryptmaster
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

### Línea de comandos

¿Se ejecutó algo sospechoso?
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Comandos básicos de Volatility

- **volatility -f <archivo> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: Muestra una lista de procesos en el volcado de memoria.
- **volatility -f <archivo> pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **volatility -f <archivo> psscan**: Escanea procesos en el volcado de memoria.
- **volatility -f <archivo> dlllist -p <PID>**: Muestra una lista de DLL cargadas por un proceso específico.
- **volatility -f <archivo> cmdline -p <PID>**: Muestra el comando utilizado para ejecutar un proceso específico.
- **volatility -f <archivo> filescan**: Escanea descriptores de archivos en el volcado de memoria.
- **volatility -f <archivo> netscan**: Escanea sockets de red en el volcado de memoria.
- **volatility -f <archivo> connections**: Muestra conexiones de red en el volcado de memoria.
- **volatility -f <archivo> consoles**: Muestra consolas interactivas abiertas por procesos en el volcado de memoria.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código malicioso en el volcado de memoria.
- **volatility -f <archivo> yarascan**: Escanea la memoria en busca de patrones utilizando reglas YARA.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> memdump -p <PID> -D <destino>**: Crea un volcado de memoria para un proceso específico.
- **volatility -f <archivo> linux_bash**: Recupera comandos de Bash eliminados de la memoria en sistemas Linux.
- **volatility -f <archivo> linux_check_tty -p <PID>**: Verifica si un proceso en Linux está asociado a una terminal.
- **volatility -f <archivo> linux_lsof**: Muestra archivos abiertos por procesos en sistemas Linux.
- **volatility -f <archivo> linux_psaux**: Muestra información detallada sobre procesos en sistemas Linux.
- **volatility -f <archivo> linux_proc_maps -p <PID>**: Muestra mapas de memoria de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_pslist**: Muestra una lista de procesos en sistemas Linux.
- **volatility -f <archivo> linux_check_afinfo**: Verifica información de sockets en sistemas Linux.
- **volatility -f <archivo> linux_netstat**: Muestra información de red en sistemas Linux.
- **volatility -f <archivo> linux_ifconfig**: Muestra información de interfaces de red en sistemas Linux.
- **volatility -f <archivo> linux_route**: Muestra información de enrutamiento en sistemas Linux.
- **volatility -f <archivo> linux_dump_map -p <PID> -D <destino>**: Extrae el mapa de memoria de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_find_file -S <ruta> -D <destino>**: Busca un archivo en sistemas Linux.
- **volatility -f <archivo> linux_lsmod**: Muestra módulos cargados en sistemas Linux.
- **volatility -f <archivo> linux_check_creds -p <PID>**: Verifica credenciales de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_dentry_cache**: Muestra información de caché de directorios en sistemas Linux.
- **volatility -f <archivo> linux_get_filedesc**: Muestra descriptores de archivos en sistemas Linux.
- **volatility -f <archivo> linux_get_task_mm -p <PID>**: Muestra estructuras de gestión de memoria de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_files -p <PID>**: Muestra archivos abiertos por un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_creds -p <PID>**: Muestra credenciales de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_exe -p <PID>**: Muestra la ruta del ejecutable de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_cmdline -p <PID>**: Muestra la línea de comandos utilizada para ejecutar un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_environ -p <PID>**: Muestra variables de entorno de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_sched -p <PID>**: Muestra información de planificación de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_parent -p <PID>**: Muestra el proceso padre de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_children -p <PID>**: Muestra los procesos hijos de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_sibling -p <PID>**: Muestra los procesos hermanos de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_vma -p <PID>**: Muestra áreas de memoria virtual de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_leader -p <PID>**: Muestra el líder del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_members -p <PID>**: Muestra los miembros del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_pids -p <PID>**: Muestra los PID del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_processes -p <PID>**: Muestra los procesos del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_threads -p <PID>**: Muestra los hilos del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_ids -p <PID>**: Muestra los IDs de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_info -p <PID>**: Muestra información de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_times -p <PID>**: Muestra tiempos de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_context -p <PID>**: Muestra contexto de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack -p <PID>**: Muestra pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_data -p <PID>**: Muestra datos de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings -p <PID>**: Muestra cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_count -p <PID>**: Muestra recuento de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data -p <PID>**: Muestra datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_count -p <PID>**: Muestra recuento de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings -p <PID>**: Muestra cadenas de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_count -p <PID>**: Muestra recuento de cadenas de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data -p <PID>**: Muestra datos de cadenas de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_count -p <PID>**: Muestra recuento de datos de cadenas de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings -p <PID>**: Muestra cadenas de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_count -p <PID>**: Muestra recuento de cadenas de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_data -p <PID>**: Muestra datos de cadenas de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_data_count -p <PID>**: Muestra recuento de datos de cadenas de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_data_strings -p <PID>**: Muestra cadenas de datos de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_data_strings_count -p <PID>**: Muestra recuento de cadenas de datos de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_data_strings_data -p <PID>**: Muestra datos de cadenas de datos de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_data_strings_data_count -p <PID>**: Muestra recuento de datos de cadenas de datos de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_data_strings_data_strings -p <PID>**: Muestra cadenas de datos de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_data_strings_data_strings_count -p <PID>**: Muestra recuento de cadenas de datos de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_data_strings_data_strings_data -p <PID>**: Muestra datos de cadenas de datos de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_data_strings_data_strings_data_count -p <PID>**: Muestra recuento de datos de cadenas de datos de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_data_strings_data_strings_data_strings -p <PID>**: Muestra cadenas de datos de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_data_strings_data_strings_data_strings_count -p <PID>**: Muestra recuento de cadenas de datos de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_data_strings_data_strings_data_strings_data -p <PID>**: Muestra datos de cadenas de datos de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_data_strings_data_strings_data_strings_data_count -p <PID>**: Muestra recuento de datos de cadenas de datos de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_data_strings_data_strings_data_strings_data_strings -p <PID>**: Muestra cadenas de datos de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_data_strings_data_strings_data_strings_data_strings_count -p <PID>**: Muestra recuento de cadenas de datos de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_data_strings_data_strings_data_strings_data_strings_data -p <PID>**: Muestra datos de cadenas de datos de datos de datos de cadenas de pila de hilo del grupo de un proceso en sistemas Linux.
- **volatility -f <archivo> linux_get_task_group_thread_stack_strings_data_strings_data_strings_data_strings_data_strings_data_strings_data
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

Los comandos ejecutados en `cmd.exe` son gestionados por **`conhost.exe`** (o `csrss.exe` en sistemas anteriores a Windows 7). Esto significa que si **`cmd.exe`** es terminado por un atacante antes de obtener un volcado de memoria, aún es posible recuperar el historial de comandos de la sesión desde la memoria de **`conhost.exe`**. Para hacer esto, si se detecta actividad inusual dentro de los módulos de la consola, se debe volcar la memoria del proceso asociado de **`conhost.exe`**. Luego, al buscar **cadenas de texto** dentro de este volcado, potencialmente se pueden extraer las líneas de comandos utilizadas en la sesión.

### Entorno

Obtener las variables de entorno de cada proceso en ejecución. Puede haber valores interesantes.
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% endtab %}

{% tab title="vol2" %} 

## Hoja de trucos de Volatility

### Análisis de volcado de memoria

#### Comandos básicos

- **volatility -f <file> imageinfo**: Escanea el volcado de memoria y muestra información básica sobre la imagen.
- **volatility -f <file> pslist**: Enumera los procesos en ejecución.
- **volatility -f <file> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> psscan**: Escanea los procesos a nivel de kernel.
- **volatility -f <file> dlllist**: Lista las DLL cargadas en los procesos.
- **volatility -f <file> cmdscan**: Busca comandos en la memoria.
- **volatility -f <file> consoles**: Enumera las consolas interactivas detectadas.
- **volatility -f <file> filescan**: Escanea los descriptores de archivo.
- **volatility -f <file> netscan**: Escanea los sockets de red.
- **volatility -f <file> connections**: Muestra las conexiones de red.
- **volatility -f <file> svcscan**: Enumera los servicios.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <file> yarascan**: Escanea la memoria en busca de patrones con Yara.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos del volcado de memoria.
- **volatility -f <file> memdump -p <pid> -D <output_directory>**: Crea un volcado de memoria para un proceso específico.

#### Plugins adicionales

- **volatility -f <file> --profile=<profile> <plugin>**: Utiliza un perfil específico para ejecutar un plugin.
- **volatility -f <file> --plugins=<directory> <plugin>**: Carga plugins desde un directorio personalizado.
- **volatility -f <file> --output-file=<output_file> <plugin>**: Guarda la salida del plugin en un archivo.

#### Ejemplos de uso

- **volatility -f memdump.mem imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f memdump.mem pslist**: Enumera los procesos en ejecución.
- **volatility -f memdump.mem dlllist -p <pid>**: Lista las DLL cargadas en un proceso específico.

{% endtab %}
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

{% tab title="vol2" %} 

## Hoja de trucos de Volatility

### Comandos básicos

- **volatility -f <file> imageinfo**: Escanea el volcado de memoria para obtener información básica.
- **volatility -f <file> pslist**: Enumera los procesos en ejecución.
- **volatility -f <file> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> psscan**: Escanea los procesos eliminados.
- **volatility -f <file> dlllist -p <pid>**: Lista las DLL cargadas por un proceso.
- **volatility -f <file> cmdline -p <pid>**: Muestra el comando utilizado para ejecutar un proceso.
- **volatility -f <file> filescan**: Escanea los descriptores de archivo.
- **volatility -f <file> netscan**: Escanea los sockets de red.
- **volatility -f <file> connections**: Muestra las conexiones de red.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <file> apihooks**: Detecta ganchos de API.
- **volatility -f <file> yarascan**: Escanea la memoria en busca de patrones con Yara.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos de memoria.
- **volatility -f <file> memdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.

### Plugins adicionales

- **malware**: Detecta malware en la memoria.
- **timeliner**: Crea una línea de tiempo de la actividad del sistema.
- **mftparser**: Analiza la Tabla Maestra de Archivos (MFT).
- **shellbags**: Analiza las entradas de Shellbags.
- **userassist**: Recupera información sobre programas ejecutados por el usuario.
- **psxview**: Detecta procesos ocultos.
- **autoruns**: Enumera los programas que se inician automáticamente.
- **truecrypt**: Recupera claves de TrueCrypt.
- **hashdump**: Extrae contraseñas en texto claro.
- **hivelist**: Lista las ubicaciones del Registro en memoria.
- **getsids**: Enumera los SID de usuario.
- **dumpregistry**: Extrae secciones del Registro.
- **dumpcerts**: Extrae certificados del sistema.
- **consoles**: Enumera las consolas interactivas.
- **desktops**: Enumera los escritorios.
- **idt**: Muestra la IDT (Tabla de Descriptores de Interrupción).
- **gdt**: Muestra la GDT (Tabla de Descriptores Globales).
- **ldrmodules**: Enumera los módulos cargados.
- **atomscan**: Escanea por objetos de espacio de usuario atómicos.
- **ssdt**: Muestra la SSDT (Tabla de Descriptores de Servicio del Sistema).
- **callbacks**: Enumera los callbacks del kernel.
- **driverirp**: Enumera los IRP manejados por los controladores.
- **printkey**: Muestra las subclaves y valores de una clave de Registro.
- **deskscan**: Escanea los objetos de escritorio.
- **devicetree**: Muestra el árbol de dispositivos.
- **modscan**: Escanea los módulos del kernel.
- **ssdeep**: Calcula hash de fragmentos de memoria.
- **yarascan**: Escanea la memoria en busca de patrones con Yara.
- **dumpfiles**: Extrae archivos de memoria.
- **memdump**: Crea un volcado de memoria de un proceso específico.

{% endtab %}
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

- **volatility -f <archivo> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: Muestra una lista de procesos en el volcado de memoria.
- **volatility -f <archivo> pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **volatility -f <archivo> psscan**: Escanea procesos a través del volcado de memoria.
- **volatility -f <archivo> dlllist -p <PID>**: Muestra las DLL cargadas por un proceso específico.
- **volatility -f <archivo> cmdscan**: Escanea los procesos en busca de comandos ejecutados.
- **volatility -f <archivo> filescan**: Escanea el volcado de memoria en busca de objetos de archivos.
- **volatility -f <archivo> netscan**: Escanea el volcado de memoria en busca de artefactos de red.
- **volatility -f <archivo> connections**: Muestra las conexiones de red en el volcado de memoria.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código malicioso en procesos.
- **volatility -f <archivo> yarascan**: Escanea el volcado de memoria en busca de patrones YARA.
- **volatility -f <archivo> cmdline**: Muestra los argumentos de línea de comandos de procesos.
- **volatility -f <archivo> consoles**: Muestra las consolas interactivas detectadas.
- **volatility -f <archivo> hivelist**: Enumera los registros del sistema en el volcado de memoria.
- **volatility -f <archivo> printkey -o <offset>**: Imprime una clave del registro en un desplazamiento específico.
- **volatility -f <archivo> userassist**: Recupera las entradas de UserAssist del Registro.
- **volatility -f <archivo> shimcache**: Recupera información de ShimCache del Registro.
- **volatility -f <archivo> ldrmodules**: Enumera los módulos cargados en el espacio de usuario.
- **volatility -f <archivo> modscan**: Escanea el volcado de memoria en busca de módulos.
- **volatility -f <archivo> getsids**: Enumera los SID de seguridad en el volcado de memoria.
- **volatility -f <archivo> getservicesids**: Enumera los SID de servicios en el volcado de memoria.
- **volatility -f <archivo> apihooks**: Detecta ganchos de API en el volcado de memoria.
- **volatility -f <archivo> callbacks**: Enumera los callbacks del kernel en el volcado de memoria.
- **volatility -f <archivo> driverirp**: Enumera los controladores y las IRP en el volcado de memoria.
- **volatility -f <archivo> ssdt**: Enumera la Service Descriptor Table en el volcado de memoria.
- **volatility -f <archivo> gdt**: Enumera la Global Descriptor Table en el volcado de memoria.
- **volatility -f <archivo> idt**: Enumera la Interrupt Descriptor Table en el volcado de memoria.
- **volatility -f <archivo> threads**: Enumera los hilos en el volcado de memoria.
- **volatility -f <archivo> handles**: Enumera los descriptores de archivo y los objetos de proceso.
- **volatility -f <archivo> mutantscan**: Escanea el volcado de memoria en busca de objetos de mutante.
- **volatility -f <archivo> envars**: Enumera las variables de entorno en el volcado de memoria.
- **volatility -f <archivo> vadinfo -o <offset>**: Muestra información sobre un área de memoria específica.
- **volatility -f <archivo> vadtree**: Muestra un árbol de áreas de memoria virtuales.
- **volatility -f <archivo> memmap**: Muestra un mapa de memoria del volcado de memoria.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio> --name**: Volcado de memoria de un proceso específico con el nombre del proceso.
- **volatility -f <archivo> memdump -p <PID> -D <directorio> --dump-dir**: Volcado de memoria de un proceso específico en un directorio.
- **volvolatility -f <archivo> memdump -p <PID> -D <directorio> --dump-dir --name**: Volcado de memoria de un proceso específico en un directorio con el nombre del proceso.

#### Plugins de Volatility

- **apihooks**: Detecta ganchos de API en el volcado de memoria.
- **atoms**: Enumera los átomos del sistema en el volcado de memoria.
- **atomscan**: Escanea el volcado de memoria en busca de átomos.
- **atomscan**: Escanea el volcado de memoria en busca de átomos.
- **bigpools**: Enumera los bloques de memoria grandes en el volcado de memoria.
- **callbacks**: Enumera los callbacks del kernel en el volcado de memoria.
- **clipboard**: Recupera el contenido del portapapeles del sistema.
- **cmdline**: Muestra los argumentos de línea de comandos de procesos.
- **connections**: Muestra las conexiones de red en el volcado de memoria.
- **connscan**: Escanea el volcado de memoria en busca de conexiones de red.
- **consoles**: Muestra las consolas interactivas detectadas.
- **crashinfo**: Muestra información sobre un posible bloqueo del sistema.
- **deskscan**: Escanea el volcado de memoria en busca de objetos de escritorio.
- **devicetree**: Enumera el árbol de dispositivos del kernel.
- **dlldump**: Extrae una DLL específica del volcjson.
- **dlllist**: Enumera las DLL cargadas en el espacio de usuario.
- **driverirp**: Enumera los controladores y las IRP en el volcado de memoria.
- **driverscan**: Escanea el volcado de memoria en busca de controladores.
- **dumpcerts**: Extrae certificados del volcado de memoria.
- **dumpfiles**: Extrae archivos del volcado de memoria.
- **editbox**: Recupera el contenido de cuadros de edición de texto.
- **envars**: Enumera las variables de entorno en el volcado de memoria.
- **eventhooks**: Enumera los ganchos de eventos en el volcado de memoria.
- **evtlogs**: Extrae registros de eventos del volcado de memoria.
- **filescan**: Escanea el volcado de memoria en busca de objetos de archivos.
- **gahti**: Enumera los objetos de tiempo de ejecución de gráficos.
- **gditimers**: Enumera los temporizadores de GDI en el volcado de memoria.
- **getservicesids**: Enumera los SID de servicios en el volcado de memoria.
- **getsids**: Enumera los SID de seguridad en el volcado de memoria.
- **handles**: Enumera los descriptores de archivo y los objetos de proceso.
- **hashdump**: Extrae contraseñas hash de Windows.
- **hibinfo**: Muestra información sobre un archivo de hibernación.
- **hivelist**: Enumera los registros del sistema en el volcado de memoria.
- **hivescan**: Escanea el volcado de memoria en busca de registros del sistema.
- **idt**: Enumera la Interrupt Descriptor Table en el volcado de memoria.
- **imagecopy**: Copia secciones de memoria a un archivo.
- **imageinfo**: Muestra información básica sobre el volcado de memoria.
- **impscan**: Escanea el volcado de memoria en busca de objetos de proceso.
- **joblinks**: Enumera los enlaces de trabajos en el volcado de memoria.
- **kdbgscan**: Escanea el volcado de memoria en busca de estructuras de depuración del kernel.
- **kpcrscan**: Escanea el volcado de memoria en busca de estructuras de registro de control de procesador.
- **ldrmodules**: Enumera los módulos cargados en el espacio de usuario.
- **lsadump**: Extrae información de seguridad de la base de datos de LSA.
- **machoinfo**: Muestra información sobre archivos Mach-O.
- **malfind**: Encuentra inyecciones de código malicioso en procesos.
- **mbrparser**: Analiza el registro maestro de arranque.
- **memdump**: Realiza un volcado de memoria de un proceso específico.
- **memmap**: Muestra un mapa de memoria del volcado de memoria.
- **messagehooks**: Enumera los ganchos de mensajes en el volcado de memoria.
- **moddump**: Extrae un módulo específico del volcado de memoria.
- **modscan**: Escanea el volcado de memoria en busca de módulos.
- **modules**: Enumera los módulos cargados en el espacio de kernel.
- **mutantscan**: Escanea el volcado de memoria en busca de objetos de mutante.
- **netscan**: Escanea el volcado de memoria en busca de artefactos de red.
- **notepad**: Recupera el contenido del Bloc de notas del sistema.
- **objtypescan**: Escanea el volcado de memoria en busca de tipos de objetos.
- **patcher**: Encuentra parches en el volcado de memoria.
- **printkey**: Imprime una clave del registro en un desplazamiento específico.
- **privs**: Enumera los privilegios de proceso en el volcado de memoria.
- **procdump**: Realiza un volcado de memoria de un proceso específico.
- **pslist**: Enumera los procesos en el volcado de memoria.
- **psscan**: Escanea procesos a través del volcado de memoria.
- **pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **psxview**: Detecta procesos ocultos.
- **raw2dmp**: Convierte un archivo de volcado de memoria en un archivo de volcado crudo.
- **raw2dmp**: Convierte un archivo de volcado de memoria en un archivo de volcado crudo.
- **screenshot**: Captura una captura de pantalla del sistema.
- **scanzw**: Escanea el volcado de memoria en busca de objetos de zona de trabajo.
- **sessions**: Enumera las sesiones de usuario en el volcado de memoria.
- **shellbags**: Enumera las carpetas abiertas recientemente.
- **shimcache**: Recupera información de ShimCache del Registro.
- **sockets**: Enumera los sockets abiertos en el volcado de memoria.
- **ssdt**: Enumera la Service Descriptor Table en el volcado de memoria.
- **strings**: Extrae cadenas ASCII e Unicode del volcado de memoria.
- **svcscan**: Escanea el volcado de memoria en busca de objetos de servicio.
- **symlinkscan**: Escanea el volcado de memoria en busca de enlaces simbólicos.
- **thrdscan**: Escanea el volcado de memoria en busca de objetos de hilo.
- **threads**: Enumera los hilos en el volcado de memoria.
- **timeliner**: Crea una línea de tiempo de actividad del sistema.
- **timers**: Enumera los temporizadores del sistema en el volcado de memoria.
- **truecryptmaster**: Recupera la clave maestra de TrueCrypt.
- **truecryptpassphrase**: Recupera la frase de contraseña de TrueCrypt.
- **unloadedmodules**: Enumera los módulos descargados en el espacio de usuario.
- **userassist**: Recupera las entradas de UserAssist del Registro.
- **vaddump**: Extrae un área de memoria virtual específica del volcado de memoria.
- **vadinfo**: Muestra información sobre un área de memoria específica.
- **vadtree**: Muestra un árbol de áreas de memoria virtuales.
- **vadwalk**: Muestra las regiones de memoria accesibles.
- **vboxinfo**: Muestra información sobre máquinas virtuales VirtualBox.
- **vmwareinfo**: Muestra información sobre máquinas virtuales VMware.
- **volshell**: Inicia un shell interactivo de Volatility.
- **windows**: Enumera los procesos de Windows en el volcado de memoria.
- **wndscan**: Escanea el volcado de memoria en busca de objetos de ventana.
- **yarascan**: Escanea el volcado de memoria en busca de patrones YARA.

#### Ejemplos de Uso

- **volatility -f memdump.mem --profile=Win7SP1x64 pslist**: Enumera los procesos en un volcado de memoria de Windows 7 SP1 de 64 bits.
- **volatility -f memdump.mem --profile=Win7SP1x64 pstree**: Muestra un árbol de procesos en un volcado de memoria de Windows 7 SP1 de 64 bits.
- **volatility -f memdump.mem --profile=Win7SP1x64 cmdline -p 1234**: Muestra los argumentos de línea de comandos del proceso con PID 1234 en un volcado de memoria de Windows 7 SP1 de 64 bits.

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

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Comandos básicos de Volatility

- **volatility.exe -f memory.raw imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility.exe -f memory.raw pslist**: Lista los procesos en el volcado de memoria.
- **volatility.exe -f memory.raw pstree**: Muestra los procesos en forma de árbol.
- **volatility.exe -f memory.raw psscan**: Escanea los procesos.
- **volatility.exe -f memory.raw dlllist -p PID**: Lista las DLL cargadas por un proceso específico.
- **volatility.exe -f memory.raw filescan**: Escanea los descriptores de archivo.
- **volatility.exe -f memory.raw cmdline -p PID**: Muestra el comando ejecutado por un proceso específico.
- **volatility.exe -f memory.raw consoles**: Lista las consolas interactivas.
- **volatility.exe -f memory.raw connections**: Muestra las conexiones de red.
- **volatility.exe -f memory.raw svcscan**: Escanea los servicios.
- **volatility.exe -f memory.raw netscan**: Escanea los sockets de red.
- **volatility.exe -f memory.raw hivelist**: Lista los registros del sistema.
- **volatility.exe -f memory.raw printkey -o OFFSET**: Muestra las subclaves de un registro.
- **volatility.exe -f memory.raw hashdump -y SYSKEY**: Extrae las contraseñas hash.
- **volatility.exe -f memory.raw mimikatz**: Ejecuta Mimikatz en el volcado de memoria.
- **volatility.exe -f memory.raw truecryptpassphrase**: Busca la frase de contraseña de TrueCrypt.
- **volatility.exe -f memory.raw shimcacheparser**: Analiza la caché de compatibilidad de aplicaciones.
- **volatility.exe -f memory.raw ldrmodules**: Lista los módulos cargados.
- **volatility.exe -f memory.raw modscan**: Escanea los módulos.
- **volatility.exe -f memory.raw malfind**: Encuentra procesos sospechosos.
- **volatility.exe -f memory.raw apihooks**: Muestra los ganchos de API.
- **volatility.exe -f memory.raw callbacks**: Lista los callbacks del kernel.
- **volatility.exe -f memory.raw driverirp**: Enumera los IRP manejadores de un driver.
- **volatility.exe -f memory.raw ssdt**: Muestra la Service Descriptor Table.
- **volatility.exe -f memory.raw devicetree**: Muestra el árbol de dispositivos.
- **volatility.exe -f memory.raw threads**: Lista los hilos.
- **volatility.exe -f memory.raw handles**: Muestra los descriptores de archivo y registro.
- **volatility.exe -f memory.raw mutantscan**: Escanea los objetos de mutante.
- **volatility.exe -f memory.raw yarascan -Y "rule_file.yar"**: Escanea con reglas YARA.
- **volatility.exe -f memory.raw memmap -p PID**: Muestra el mapeo de memoria de un proceso.
- **volatility.exe -f memory.raw memdump -p PID -D dump_directory**: Volcado de memoria de un proceso.
- **volatility.exe -f memory.raw memdump -p PID -D dump_directory --name**: Volcado de memoria de un proceso con nombre.
- **volatility.exe -f memory.raw memdump -p PID -D dump_directory --name --dump-dir**: Volcado de memoria de un proceso con nombre en un directorio específico.
- **volatility.exe -f memory.raw memdump -p PID -D dump_directory --name --dump-dir --output**: Volcado de memoria de un proceso con nombre en un directorio específico con formato de salida.
- **volatility.exe -f memory.raw memdump --pid-offset OFFSET -D dump_directory**: Volcado de memoria de un proceso con un desplazamiento de PID.
- **volatility.exe -f memory.raw memdump --pid-offset OFFSET -D dump_directory --name**: Volcado de memoria de un proceso con un desplazamiento de PID y nombre.
- **volatility.exe -f memory.raw memdump --pid-offset OFFSET -D dump_directory --name --dump-dir**: Volcado de memoria de un proceso con un desplazamiento de PID y nombre en un directorio específico.
- **volatility.exe -f memory.raw memdump --pid-offset OFFSET -D dump_directory --name --dump-dir --output**: Volcado de memoria de un proceso con un desplazamiento de PID y nombre en un directorio específico con formato de salida.

#### Plugins de Volatility

- **apihooks**: Muestra los ganchos de API.
- **atomscan**: Escanea los objetos de atom.
- **atomtable**: Muestra la tabla de átomos.
- **callbacks**: Lista los callbacks del kernel.
- **clipboard**: Muestra el contenido del portapapeles.
- **cmdscan**: Escanea los comandos ejecutados.
- **connections**: Muestra las conexiones de red.
- **connscan**: Escanea las conexiones de red.
- **consoles**: Lista las consolas interactivas.
- **crashinfo**: Muestra información sobre un volcado de memoria de un sistema que falló.
- **deskscan**: Escanea los objetos de escritorio.
- **devicetree**: Muestra el árbol de dispositivos.
- **dlldump**: Extrae una DLL específica.
- **dlllist**: Lista las DLL cargadas.
- **driverirp**: Enumera los IRP manejadores de un driver.
- **driverscan**: Escanea los drivers.
- **envars**: Muestra las variables de entorno.
- **eventhooks**: Lista los ganchos de eventos.
- **evtlogs**: Extrae los registros de eventos.
- **filescan**: Escanea los descriptores de archivo.
- **gahti**: Enumera los objetos de Gahti.
- **gditimers**: Lista los temporizadores de GDI.
- **getservicesids**: Muestra los identificadores de servicios.
- **handles**: Muestra los descriptores de archivo y registro.
- **hashdump**: Extrae las contraseñas hash.
- **hibinfo**: Muestra información sobre el archivo de hibernación.
- **hivelist**: Lista los registros del sistema.
- **hivescan**: Escanea los registros del sistema.
- **idt**: Muestra la Interrupt Descriptor Table.
- **imagecopy**: Copia secciones de memoria a un archivo.
- **imageinfo**: Muestra información básica sobre el volcado de memoria.
- **impscan**: Escanea los objetos de importación.
- **joblinks**: Lista los enlaces de trabajos.
- **kdbgscan**: Escanea los depuradores del kernel.
- **kpcrscan**: Escanea los registros de control de procesos del kernel.
- **ldrmodules**: Lista los módulos cargados.
- **lsadump**: Extrae las credenciales de LSA.
- **machoinfo**: Muestra información sobre archivos Mach-O.
- **malfind**: Encuentra procesos sospechosos.
- **mbrparser**: Analiza el registro de arranque maestro.
- **memdump**: Volcado de memoria de un proceso.
- **memmap**: Muestra el mapeo de memoria de un proceso.
- **messagehooks**: Lista los ganchos de mensajes.
- **moddump**: Extrae un módulo específico.
- **modscan**: Escanea los módulos.
- **modules**: Lista los módulos cargados.
- **mutantscan**: Escanea los objetos de mutante.
- **netscan**: Escanea los sockets de red.
- **notepad**: Muestra el contenido del bloc de notas.
- **objtypescan**: Escanea los tipos de objetos.
- **patcher**: Parchea un proceso en memoria.
- **printkey**: Muestra las subclaves de un registro.
- **privs**: Muestra los privilegios.
- **procdump**: Volcado de memoria de un proceso.
- **pslist**: Lista los procesos.
- **psscan**: Escanea los procesos.
- **pstree**: Muestra los procesos en forma de árbol.
- **psxview**: Enumera los procesos ocultos.
- **qemuinfo**: Muestra información sobre una imagen de QEMU.
- **raw2dmp**: Convierte un volcado de memoria en un archivo DMP.
- **registry**: Muestra el contenido de un registro.
- **screenshot**: Toma una captura de pantalla de la máquina virtual.
- **sessions**: Lista las sesiones.
- **shellbags**: Lista las carpetas abiertas recientemente.
- **shimcache**: Muestra la caché de compatibilidad de aplicaciones.
- **sockets**: Lista los sockets.
- **ssdt**: Muestra la Service Descriptor Table.
- **strings**: Busca cadenas ASCII y Unicode en memoria.
- **svcscan**: Escanea los servicios.
- **symlinkscan**: Escanea los enlaces simbólicos.
- **thrdscan**: Escanea los hilos.
- **threads**: Lista los hilos.
- **timeliner**: Crea una línea de tiempo de los artefactos encontrados.
- **timers**: Lista los temporizadores.
- **truecryptpassphrase**: Busca la frase de contraseña de TrueCrypt.
- **unloadedmodules**: Lista los módulos descargados.
- **userassist**: Muestra las entradas de UserAssist.
- **userhandles**: Lista los descriptores de usuario.
- **vadinfo**: Muestra información sobre los descriptores de área de memoria.
- **vaddump**: Volcado de un descriptor de área de memoria.
- **vadtree**: Muestra los descriptores de área de memoria en forma de árbol.
- **vadwalk**: Muestra los descriptores de área de memoria en forma de lista.
- **vboxinfo**: Muestra información sobre una imagen de VirtualBox.
- **vmwareinfo**: Muestra información sobre una imagen de VMware.
- **volshell**: Inicia un shell interactivo de Volatility.
- **windows**: Enumera las estaciones de ventana.
- **wndscan**: Escanea las estaciones de ventana.
- **yarascan**: Escanea con reglas YARA.

#### Ejemplos de Uso

- **volatility.exe -f memory.raw pslist**: Lista los procesos en el volcado de memoria.
- **volatility.exe -f memory.raw pstree**: Muestra los procesos en forma de árbol.
- **volatility.exe -f memory.raw dlllist -p PID**: Lista las DLL cargadas por un proceso específico.
- **volatility.exe -f memory.raw filescan**: Escanea los descriptores de archivo.
- **volatility.exe -f memory.raw cmdline -p PID**: Muestra el comando ejecutado por un proceso específico.
- **volatility.exe -f memory.raw netscan**: Escanea los sockets de red.
- **volatility.exe -f memory.raw malfind**: Encuentra procesos sospechosos.
- **volatility.exe -f memory.raw hashdump -y SYSKEY**: Extrae las contraseñas hash.
- **volatility.exe -f memory.raw mimikatz**: Ejecuta Mimikatz en el volcado de memoria.
- **volatility.exe -f memory.raw truecryptpassphrase**: Busca la frase de contraseña de TrueCrypt.
- **volatility.exe -f memory.raw shimcacheparser**: Analiza la caché de compatibilidad de aplicaciones.
- **volatility.exe -f memory.raw ldrmodules**: Lista los módulos cargados.
- **volatility.exe -f memory.raw modscan**: Escanea los módulos.
- **volatility.exe -f memory.raw apihooks**: Muestra los ganchos de API.
- **volatility.exe -f memory.raw ssdt**: Muestra la Service Descriptor Table.
- **volatility.exe -f memory.raw devicetree**: Muestra el árbol de dispositivos.
- **volatility.exe -f memory.raw handles**: Muestra los descriptores de archivo y registro.
- **volatility.exe -f memory.raw yarascan -Y "rule_file.yar"**: Escanea con reglas YARA.
- **volatility.exe -f memory.raw memmap -p PID**: Muestra el mapeo de memoria de un proceso.
- **volatility.exe -f memory.raw memdump -p PID -D dump_directory**: Volcado de memoria de un proceso.
- **volatility.exe -f memory.raw memdump -p PID -D dump_directory --name**: Volcado de memoria de un proceso con nombre.
- **volatility.exe -f memory.raw memdump -p PID -D dump_directory --name --dump-dir**: Volcado de memoria de un proceso con nombre en un directorio específico.
- **volatility.exe -f memory.raw memdump -p PID -D dump_directory --name --dump-dir --output**: Volcado de memoria de un proceso con nombre en un directorio específico con formato de salida.
- **volatility.exe -f memory.raw memdump --pid-offset OFFSET -D dump_directory**: Volcado de memoria de un proceso con un desplazamiento de PID.
- **volatility.exe -f memory.raw memdump --pid-offset OFFSET -D dump_directory --name**: Volcado de memoria de un proceso con un desplazamiento de PID y nombre.
- **volatility.exe -f memory.raw memdump --pid-offset OFFSET -D dump_directory --name --dump-dir**: Volcado de memoria de un proceso con un desplazamiento de PID y nombre en un directorio específico.
- **volatility.exe -f memory.raw memdump --pid-offset OFFSET -D dump_directory --name --dump-dir --output**: Volcado de memoria de un proceso con un desplazamiento de PID y nombre en un directorio específico con formato de salida.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
### DLLs

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% endtab %}

{% tab title="vol2" %} 

## Hoja de trucos de Volatility

### Comandos básicos

- **volatility -f <archivo> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: Muestra una lista de procesos en el volcado de memoria.
- **volatility -f <archivo> pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **volatility -f <archivo> psscan**: Escanea procesos a través del volcado de memoria.
- **volatility -f <archivo> dlllist -p <PID>**: Muestra una lista de DLL cargadas por un proceso específico.
- **volatility -f <archivo> cmdline -p <PID>**: Muestra el comando utilizado para ejecutar un proceso específico.
- **volatility -f <archivo> filescan**: Escanea la memoria en busca de estructuras de archivos.
- **volatility -f <archivo> netscan**: Escanea la memoria en busca de artefactos de red.
- **volatility -f <archivo> connections**: Muestra las conexiones de red en el volcado de memoria.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código malicioso en procesos.
- **volatility -f <archivo> yarascan**: Escanea la memoria en busca de patrones con Yara.
- **volatility -f <archivo> consoles**: Muestra las consolas interactivas encontradas en el volcado de memoria.

### Plugins adicionales

- **apihooks**: Detecta ganchos de API en procesos.
- **malthfind**: Encuentra inyecciones de código malicioso en procesos.
- **mbrparser**: Analiza el Registro de arranque maestro (MBR).
- **modscan**: Escanea la memoria en busca de módulos del kernel.
- **timeliner**: Crea una línea de tiempo de actividad del sistema.
- **vadinfo**: Muestra información sobre los Descriptores de área de memoria virtual (VAD).
- **windows**: Enumera procesos, conexiones de red y controladores cargados.

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

#### Comandos básicos de Volatility

- **volatility -f <archivo> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: Muestra una lista de procesos en el volcado de memoria.
- **volatility -f <archivo> pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **volatility -f <archivo> psscan**: Escanea procesos en el volcado de memoria.
- **volatility -f <archivo> dlllist -p <PID>**: Lista los módulos DLL cargados por un proceso específico.
- **volatility -f <archivo> cmdline -p <PID>**: Muestra el comando utilizado para ejecutar un proceso específico.
- **volatility -f <archivo> filescan**: Escanea descriptores de archivos en el volcado de memoria.
- **volatility -f <archivo> netscan**: Escanea sockets de red en el volcado de memoria.
- **volatility -f <archivo> connections**: Muestra las conexiones de red en el volcado de memoria.
- **volatility -f <archivo> consoles**: Muestra las consolas interactivas abiertas por procesos.
- **volatility -f <archivo> hivelist**: Enumera los archivos de volcado de registro en el volcado de memoria.
- **volatility -f <archivo> printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código sospechosas en el volcado de memoria.
- **volatility -f <archivo> apihooks**: Muestra los ganchos de API en el volcado de memoria.
- **volatility -f <archivo> ldrmodules**: Enumera los módulos cargados en el espacio de usuario.
- **volatility -f <archivo> modscan**: Escanea módulos en el volcado de memoria.
- **volatility -f <archivo> shimcache**: Extrae información de la caché de compatibilidad de aplicaciones.
- **volatility -f <archivo> userassist**: Extrae entradas de UserAssist del registro.
- **volatility -f <archivo> getsids**: Enumera los SID de usuario en el volcado de memoria.
- **volatility -f <archivo> hivescan**: Escanea los archivos de volcado de registro en busca de subclaves y valores.
- **volatility -f <archivo> hashdump**: Extrae hashes de contraseñas de SAM y SYSTEM.
- **volatility -f <archivo> mimikatz**: Ejecuta el plugin Mimikatz en el volcado de memoria.
- **volatility -f <archivo> truecryptmaster**: Extrae la clave maestra de TrueCrypt.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> procdump -p <PID> -D <destino>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <destino>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memmap -p <PID>**: Muestra el mapeo de memoria de un proceso específico.
- **volatility -f <archivo> memmap**: Muestra el mapeo de memoria de todos los procesos.
- **volatility -f <archivo> vadinfo -p <PID>**: Muestra información sobre los descriptores de área de memoria virtual de un proceso específico.
- **volatility -f <archivo> vadtree -p <PID>**: Muestra un árbol de descriptores de área de memoria virtual de un proceso específico.
- **volatility -f <archivo> vadwalk -p <PID> -V**: Realiza un recorrido en profundidad de los descriptores de área de memoria virtual de un proceso específico.
- **volatility -f <archivo> handles -p <PID>**: Enumera los identificadores de objetos abiertos por un proceso específico.
- **volatility -f <archivo> mutantscan**: Escanea objetos de mutante en el volcado de memoria.
- **volatility -f <archivo> envars -p <PID>**: Muestra las variables de entorno de un proceso específico.
- **volatility -f <archivo> envars**: Muestra las variables de entorno de todos los procesos.
- **volatility -f <archivo> cmdline**: Muestra los comandos utilizados para ejecutar todos los procesos.
- **volatility -f <archivo> consoles -p <PID>**: Muestra las consolas abiertas por un proceso específico.
- **volatility -f <archivo> dumpregistry -o <offset> -D <destino>**: Extrae una sección del registro del volcado de memoria.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño específico.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos y muestra los valores Unicode.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos, muestra los valores Unicode y los guarda en un archivo.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -H <hive> -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos, muestra los valores Unicode, los guarda en un archivo y especifica el tipo de colmena.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -H <hive> -key <clave> -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos, muestra los valores Unicode, los guarda en un archivo, especifica el tipo de colmena y la clave de registro.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -H <hive> -key <clave> -v -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos, muestra los valores Unicode, los guarda en un archivo, especifica el tipo de colmena, la clave de registro y muestra los valores.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -H <hive> -key <clave> -v -r -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos, muestra los valores Unicode, los guarda en un archivo, especifica el tipo de colmena, la clave de registro, muestra los valores y muestra los valores RAW.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -H <hive> -key <clave> -v -r -a -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos, muestra los valores Unicode, los guarda en un archivo, especifica el tipo de colmena, la clave de registro, muestra los valores, muestra los valores RAW y muestra todos los valores.
- **volvolatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -H <hive> -key <clave> -v -r -a -w -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos, muestra los valores Unicode, los guarda en un archivo, especifica el tipo de colmena, la clave de registro, muestra los valores, muestra los valores RAW, muestra todos los valores y muestra los valores no ASCII.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -H <hive> -key <clave> -v -r -a -w -K <keyword> -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos, muestra los valores Unicode, los guarda en un archivo, especifica el tipo de colmena, la clave de registro, muestra los valores, muestra los valores RAW, muestra todos los valores, muestra los valores no ASCII y muestra solo los valores que contienen una palabra clave específica.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -H <hive> -key <clave> -v -r -a -w -K <keyword> -U -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos, muestra los valores Unicode, los guarda en un archivo, especifica el tipo de colmena, la clave de registro, muestra los valores, muestra los valores RAW, muestra todos los valores, muestra los valores no ASCII, muestra solo los valores que contienen una palabra clave específica y muestra solo los valores únicos.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -H <hive> -key <clave> -v -r -a -w -K <keyword> -U -c -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos, muestra los valores Unicode, los guarda en un archivo, especifica el tipo de colmena, la clave de registro, muestra los valores, muestra los valores RAW, muestra todos los valores, muestra los valores no ASCII, muestra solo los valores que contienen una palabra clave específica, muestra solo los valores únicos y cuenta los valores.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -H <hive> -key <clave> -v -r -a -w -K <keyword> -U -c -z -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos, muestra los valores Unicode, los guarda en un archivo, especifica el tipo de colmena, la clave de registro, muestra los valores, muestra los valores RAW, muestra todos los valores, muestra los valores no ASCII, muestra solo los valores que contienen una palabra clave específica, muestra solo los valores únicos, cuenta los valores y comprime el archivo de salida.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -H <hive> -key <clave> -v -r -a -w -K <keyword> -U -c -z -t -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos, muestra los valores Unicode, los guarda en un archivo, especifica el tipo de colmena, la clave de registro, muestra los valores, muestra los valores RAW, muestra todos los valores, muestra los valores no ASCII, muestra solo los valores que contienen una palabra clave específica, muestra solo los valores únicos, cuenta los valores, comprime el archivo de salida y muestra la hora de inicio y finalización del proceso.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -H <hive> -key <clave> -v -r -a -w -K <keyword> -U -c -z -t -M -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos, muestra los valores Unicode, los guarda en un archivo, especifica el tipo de colmena, la clave de registro, muestra los valores, muestra los valores RAW, muestra todos los valores, muestra los valores no ASCII, muestra solo los valores que contienen una palabra clave específica, muestra solo los valores únicos, cuenta los valores, comprime el archivo de salida, muestra la hora de inicio y finalización del proceso y muestra la información de la máquina.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -H <hive> -key <clave> -v -r -a -w -K <keyword> -U -c -z -t -M -m -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos, muestra los valores Unicode, los guarda en un archivo, especifica el tipo de colmena, la clave de registro, muestra los valores, muestra los valores RAW, muestra todos los valores, muestra los valores no ASCII, muestra solo los valores que contienen una palabra clave específica, muestra solo los valores únicos, cuenta los valores, comprime el archivo de salida, muestra la hora de inicio y finalización del proceso, muestra la información de la máquina y muestra la información de la memoria.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -H <hive> -key <clave> -v -r -a -w -K <keyword> -U -c -z -t -M -m -i -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos, muestra los valores Unicode, los guarda en un archivo, especifica el tipo de colmena, la clave de registro, muestra los valores, muestra los valores RAW, muestra todos los valores, muestra los valores no ASCII, muestra solo los valores que contienen una palabra clave específica, muestra solo los valores únicos, cuenta los valores, comprime el archivo de salida, muestra la hora de inicio y finalización del proceso, muestra la información de la máquina, muestra la información de la memoria y muestra la información de la imagen.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -H <hive> -key <clave> -v -r -a -w -K <keyword> -U -c -z -t -M -m -i -b -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos, muestra los valores Unicode, los guarda en un archivo, especifica el tipo de colmena, la clave de registro, muestra los valores, muestra los valores RAW, muestra todos los valores, muestra los valores no ASCII, muestra solo los valores que contienen una palabra clave específica, muestra solo los valores únicos, cuenta los valores, comprime el archivo de salida, muestra la hora de inicio y finalización del proceso, muestra la información de la máquina, muestra la información de la memoria, muestra la información de la imagen y muestra la información de la base de datos.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -H <hive> -key <clave> -v -r -a -w -K <keyword> -U -c -z -t -M -m -i -b -d -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos, muestra los valores Unicode, los guarda en un archivo, especifica el tipo de colmena, la clave de registro, muestra los valores, muestra los valores RAW, muestra todos los valores, muestra los valores no ASCII, muestra solo los valores que contienen una palabra clave específica, muestra solo los valores únicos, cuenta los valores, comprime el archivo de salida, muestra la hora de inicio y finalización del proceso, muestra la información de la máquina, muestra la información de la memoria, muestra la información de la imagen, muestra la información de la base de datos y muestra la información de la red.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -H <hive> -key <clave> -v -r -a -w -K <keyword> -U -c -z -t -M -m -i -b -d -n -D <destino>**: Extrae una sección del registro del volcado de memoria con un tamaño y formato específicos, muestra los valores Unicode, los guarda en un archivo, especifica el tipo de colmena, la clave de registro, muestra los valores, muestra los valores RAW, muestra todos los valores, muestra los valores no ASCII, muestra solo los valores que contienen una palabra clave específica, muestra solo los valores únicos, cuenta los valores, comprime el archivo de salida, muestra la hora de inicio y finalización del proceso, muestra la información de la máquina, muestra la información de la memoria, muestra la información de la imagen, muestra la información de la base de datos, muestra la información de la red y muestra la información de los procesos.
- **volatility -f <archivo> dumpregistry -o <offset> -s <tamaño> -f <formato> -y -H <hive> -key <clave> -v -r -a -w -
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

{% tab title="vol2" %}Volatility Cheatsheet

### Basic Commands

- **Image info:** `vol.py -f <memory_dump> imageinfo`
- **Profile:** `vol.py -f <memory_dump> imageinfo | grep Profile`
- **Processes:** `vol.py -f <memory_dump> --profile=<profile> pslist`
- **Process tree:** `vol.py -f <memory_dump> --profile=<profile> pstree`
- **Dump process:** `vol.py -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
- **Netscan:** `vol.py -f <memory_dump> --profile=<profile> netscan`
- **Connections:** `vol.py -f <memory_dump> --profile=<profile> connscan`
- **DLL list:** `vol.py -f <memory_dump> --profile=<profile> dlllist -p <pid>`
- **Handles:** `vol.py -f <memory_dump> --profile=<profile> handles -p <pid>`
- **Registry hives:** `vol.py -f <memory_dump> --profile=<profile> hivelist`
- **Dump registry:** `vol.py -f <memory_dump> --profile=<profile> printkey -o <output_directory> -K <registry_key>`
- **Filescan:** `vol.py -f <memory_dump> --profile=<profile> filescan`
- **Dump file:** `vol.py -f <memory_dump> --profile=<profile> dumpfiles -Q <file_address> -D <output_directory>`
- **Strings:** `vol.py -f <memory_dump> --profile=<profile> strings -s <string_length>`
- **User accounts:** `vol.py -f <memory_dump> --profile=<profile> useraccounts`
- **Malware scan:** `vol.py -f <memory_dump> --profile=<profile> malscan`

### Advanced Commands

- **Yarascan:** `vol.py -f <memory_dump> --profile=<profile> yarascan --yara-rules=<path_to_rules>`
- **API hooks:** `vol.py -f <memory_dump> --profile=<profile> apihooks`
- **SSDT:** `vol.py -f <memory_dump> --profile=<profile> ssdt`
- **Driver modules:** `vol.py -f <memory_dump> --profile=<profile> modscan`
- **Kernel drivers:** `vol.py -f <memory_dump> --profile=<profile> kdbgscan`
- **SSDT hooks:** `vol.py -f <memory_dump> --profile=<profile> ssdt`
- **Hidden processes:** `vol.py -f <memory_dump> --profile=<profile> psxview`
- **Rootkit detection:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **API audit:** `vol.py -f <memory_dump> --profile=<profile> apihooks`
- **Dump all processes:** `vol.py -f <memoryjson> --profile=<profile> procdump --dump-dir=<output_directory>`
- **Dump all threads:** `vol.py -f <memory_dump> --profile=<profile> threads --dump`
- **Dump all modules:** `vol.py -f <memory_dump> --profile=<profile> moddump --dump-dir=<output_directory>`

### Plugin Output Analysis

- **Volatility Output:** Analyze the output of Volatility plugins to identify suspicious or malicious activities in memory dumps.

### Memory Forensics

- **Memory Analysis:** Use Volatility to perform memory forensics and extract valuable information from memory dumps.

### Memory Dump Analysis

- **Memory Dump:** Analyze memory dumps to investigate security incidents and identify potential threats in a system.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
### UserAssist

**Windows** registra los programas que ejecutas utilizando una característica en el registro llamada **claves UserAssist**. Estas claves registran cuántas veces se ejecuta cada programa y cuándo se ejecutó por última vez.
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% endtab %}

{% tab title="vol2" %} 

## Hoja de trucos de Volatility

### Comandos básicos

- **volatility -f <file> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <file> pslist**: Lista los procesos en ejecución.
- **volatility -f <file> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> psscan**: Escanea los procesos.
- **volatility -f <file> dlllist -p <pid>**: Lista las DLL cargadas por un proceso.
- **volatility -f <file> cmdscan**: Escanea los procesos en busca de comandos ejecutados.
- **volatility -f <file> consoles**: Muestra las consolas interactivas.
- **volatility -f <file> filescan**: Escanea los descriptores de archivos.
- **volatility -f <file> netscan**: Escanea los sockets de red.
- **volatility -f <file> connections**: Muestra las conexiones de red.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <file> apihooks**: Muestra los ganchos de API.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> modscan**: Escanea los módulos.
- **volatility -f <file> shimcache**: Muestra la caché de Shim.
- **volatility -f <file> userassist**: Muestra las entradas de UserAssist.
- **volatility -f <file> hivelist**: Enumera los archivos de volcado del registro.
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro.
- **volatility -f <file> hashdump**: Extrae las contraseñas hash.
- **volatility -f <file> truecryptpassphrase**: Encuentra frases de contraseña TrueCrypt.
- **volatility -f <file> envars**: Muestra las variables de entorno.
- **volatility -f <file> cmdline**: Muestra los argumentos de línea de comandos.
- **volatility -f <file> consoles -f**: Extrae las consolas interactivas.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos del espacio de memoria.
- **volatility -f <file> procdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap -p <pid>**: Muestra el mapeo de memoria de un proceso.
- **volatility -f <file> memmap -p <pid> -t**: Muestra el mapeo de memoria de un proceso con direcciones traducidas.
- **volatility -f <file> memdump --dump-dir <output_directory> -p <pid>**: Crea un volcado de memoria de un proceso específico en un directorio de salida.
- **volatility -f <file> memdump --dump-dir <output_directory> -p <pid> --name**: Crea un volcado de memoria de un proceso específico en un directorio de salida con el nombre del proceso.
- **volatility -f <file> memdump --dump-dir <output_directory> -p <pid> --name --dump-dir**: Cjsonfigura un volcado de memoria de un proceso específico en un directorio de salida con el nombre del proceso y el directorio de salida.
- **volatility -f <file> memdump --dump-dir <output_directory> -p <pid> --name --dump-dir --output**: Cjsonfigura un volcado de memoria de un proceso específico en un directorio de salida con el nombre del proceso y el directorio de salida, y muestra la ruta del archivo de salida.
- **volatility -f <file> memdump --dump-dir <output_directory> -p <pid> --name --dump-dir --output --output-file**: Cjsonfigura un volcado de memoria de un proceso específico en un directorio de salida con el nombre del proceso y el directorio de salida, muestra la ruta del archivo de salida y el nombre del archivo de salida.
- **volatility -f <file> memdump --dump-dir <output_directory> -p <pid> --name --dump-dir --output --output-file --output-file-name**: Cjsonfigura un volcado de memoria de un proceso específico en un directorio de salida con el nombre del proceso y el directorio de salida, muestra la ruta del archivo de salida, el nombre del archivo de salida y el nombre del archivo de salida.
- **volatility -f <file> memdump --dump-dir <output_directory> -p <pid> --name --dump-dir --output --output-file --output-file-name --output-file-name-prefix**: Cjsonfigura un volcado de memoria de un proceso específico en un directorio de salida con el nombre del proceso y el directorio de salida, muestra la ruta del archivo de salida, el nombre del archivo de salida, el nombre del archivo de salida y el prefijo del nombre del archivo de salida.
- **volatility -f <file> memdump --dump-dir <output_directory> -p <pid> --name --dump-dir --output --output-file --output-file-name --output-file-name-prefix --output-file-name-suffix**: Cjsonfigura un volcado de memoria de un proceso específico en un directorio de salida con el nombre del proceso y el directorio de salida, muestra la ruta del archivo de salida, el nombre del archivo de salida, el nombre del archivo de salida, el prefijo del nombre del archivo de salida y el sufijo del nombre del archivo de salida.

### Plugins adicionales

- **apihooks**: Muestra los ganchos de API.
- **atoms**: Enumera los átomos del sistema.
- **atomscan**: Escanea los átomos del sistema.
- **callbacks**: Enumera los callbacks del sistema.
- **clipboard**: Muestra el contenido del portapapeles.
- **cmdline**: Muestra los argumentos de línea de comandos.
- **cmdscan**: Escanea los procesos en busca de comandos ejecutados.
- **consoles**: Muestra las consolas interactivas.
- **connections**: Muestra las conexiones de red.
- **connscan**: Escanea las conexiones de red.
- **crashinfo**: Muestra información sobre un volcado de memoria de un sistema que ha fallado.
- **deskscan**: Escanea los objetos de escritorio.
- **devicetree**: Muestra el árbol de dispositivos.
- **dlldump**: Extrae una DLL específica.
- **dlllist**: Lista las DLL cargadas por un proceso.
- **driverirp**: Enumera los IRP manejados por un controlador.
- **drivermodule**: Enumera los módulos de kernel cargados.
- **driverscan**: Escanea los controladores cargados.
- **editbox**: Muestra el contenido de los cuadros de edición.
- **envars**: Muestra las variables de entorno.
- **eventhooks**: Enumera los ganchos de eventos.
- **evtlogs**: Enumera los registros de eventos.
- **filescan**: Escanea los descriptores de archivos.
- **gahti**: Enumera los objetos de kernel.
- **gditimers**: Enumera los temporizadores GDI.
- **getservicesids**: Enumera los identificadores de servicios.
- **handles**: Enumera los descriptores de archivos y registros.
- **hashdump**: Extrae las contraseñas hash.
- **hibinfo**: Muestra información sobre un archivo de hibernación.
- **hivelist**: Enumera los archivos de volcado del registro.
- **hivescan**: Escanea los archivos de volcado del registro.
- **idt**: Muestra la tabla de descriptores de interrupciones.
- **impscan**: Escanea los objetos de kernel.
- **joblinks**: Enumera los enlaces de trabajos.
- **ldrmodules**: Lista los módulos cargados.
- **lsadump**: Extrae las credenciales de LSA.
- **malfind**: Encuentra inyecciones de código malicioso.
- **mbrparser**: Analiza el registro de arranque maestro.
- **memmap**: Muestra el mapeo de memoria de un proceso.
- **memdump**: Crea un volcado de memoria de un proceso específico.
- **messagehooks**: Enumera los ganchos de mensajes.
- **moddump**: Extrae un módulo específico.
- **modscan**: Escanea los módulos.
- **modules**: Lista los módulos cargados.
- **mutantscan**: Escanea los mutantes del sistema.
- **netscan**: Escanea los sockets de red.
- **notepad**: Muestra el contenido del bloc de notas.
- **objtypescan**: Escanea los tipos de objetos.
- **patcher**: Enumera los parches aplicados.
- **printkey**: Imprime una clave de registro.
- **privs**: Enumera los privilegios del sistema.
- **procdump**: Crea un volcado de memoria de un proceso específico.
- **pslist**: Lista los procesos en ejecución.
- **psscan**: Escanea los procesos.
- **pstree**: Muestra los procesos en forma de árbol.
- **psxview**: Enumera los procesos ocultos.
- **qemuinfo**: Muestra información sobre una imagen de QEMU.
- **raw2dmp**: Convierte un archivo de volcado en un archivo de volcado de memoria.
- **registry**: Muestra el contenido de una clave de registro.
- **screenshot**: Toma una captura de pantalla de la consola.
- **sessions**: Enumera las sesiones del sistema.
- **shellbags**: Enumera las bolsas de la shell.
- **shimcache**: Muestra la caché de Shim.
- **sockets**: Enumera los sockets del sistema.
- **ssdt**: Muestra la tabla de descriptores de servicios.
- **strings**: Escanea la memoria en busca de cadenas.
- **svcscan**: Escanea los servicios del sistema.
- **symlinkscan**: Escanea los enlaces simbólicos.
- **thrdscan**: Escanea los hilos del sistema.
- **threads**: Enumera los hilos del sistema.
- **timeliner**: Crea una línea de tiempo de la actividad del sistema.
- **truecryptpassphrase**: Encuentra frases de contraseña TrueCrypt.
- **unloadedmodules**: Lista los módulos descargados.
- **userassist**: Muestra las entradas de UserAssist.
- **userhandles**: Enumera los descriptores de archivos y registros de usuario.
- **vadinfo**: Muestra información sobre los descriptores de áreas de memoria.
- **vaddump**: Extrae un descriptor de área de memoria específico.
- **vadtree**: Muestra los descriptores de áreas de memoria en forma de árbol.
- **vadwalk**: Muestra los descriptores de áreas de memoria en forma de lista.
- **vboxinfo**: Muestra información sobre una imagen de VirtualBox.
- **vmwareinfo**: Muestra información sobre una imagen de VMware.
- **volshell**: Inicia una shell interactiva de Volatility.
- **windows**: Enumera los procesos de Windows.
- **wndscan**: Escanea las ventanas del sistema.

### Ejemplos de uso

- **volatility -f memdump.mem --profile=Win7SP1x64 memmap -p 1234**: Muestra el mapeo de memoria del proceso con ID 1234 en un volcado de memoria.
- **volatility -f memdump.mem --profile=Win7SP1x64 memdump -p 1234 -D dumpdir**: Crea un volcado de memoria del proceso con ID 1234 en un directorio llamado dumpdir.
- **volatility -f memdump.mem --profile=Win7SP1x64 pslist**: Lista los procesos en un volcado de memoria.
- **volatility -f memdump.mem --profile=Win7SP1x64 pstree**: Muestra los procesos en forma de árbol en un volcado de memoria.
- **volatility -f memdump.mem --profile=Win7SP1x64 dlllist -p 1234**: Lista las DLL cargadas por el proceso con ID 1234 en un volcado de memoria.

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

- **volatility -f <archivo> imageinfo**: Escanea el volcado de memoria para obtener información básica.
- **volatility -f <archivo> pslist**: Enumera los procesos en ejecución.
- **volatility -f <archivo> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <archivo> psscan**: Escanea los procesos a nivel de kernel.
- **volatility -f <archivo> dlllist -p <PID>**: Lista las DLL cargadas por un proceso específico.
- **volatility -f <archivo> cmdline -p <PID>**: Muestra el comando utilizado para ejecutar un proceso.
- **volatility -f <archivo> filescan**: Escanea los descriptores de archivo.
- **volatility -f <archivo> netscan**: Escanea los sockets de red.
- **volatility -f <archivo> connections**: Muestra las conexiones de red.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código malicioso en procesos.
- **volatility -f <archivo> yarascan**: Escanea la memoria en busca de patrones utilizando reglas YARA.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> memdump -p <PID> -D <destino>**: Crea un volcado de memoria para un proceso específico.
- **volatility -f <archivo> hivelist**: Enumera los archivos de volcado de registro.
- **volatility -f <archivo> printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <archivo> hashdump**: Extrae las contraseñas hash de Windows.
- **volatility -f <archivo> truecryptpassphrase**: Recupera la frase de contraseña TrueCrypt.
- **volatility -f <archivo> clipboard**: Muestra el contenido del portapapeles.
- **volatility -f <archivo> screenshot**: Captura una captura de pantalla de la máquina comprometida.

#### Plugins adicionales de Volatility

- **volatility -f <archivo> <nombre_del_plugin>**: Ejecuta un plugin específico.
- **volatility --info | grep <nombre_del_plugin>**: Obtiene información sobre un plugin específico.
- **volatility --plugins=<directorio>**: Carga plugins adicionales desde un directorio específico.

#### Análisis avanzado con Volatility

- **volatility -f <archivo> --profile=<perfil> <comando>**: Especifica un perfil para el análisis.
- **volatility -f <archivo> kdbgscan**: Encuentra el valor KDBG para el análisis del kernel.
- **volatility -f <archivo> vadinfo -p <PID>**: Muestra información sobre regiones de memoria virtuales.
- **volatility -f <archivo> apihooks**: Detecta ganchos de API en procesos.
- **volatility -f <archivo> ldrmodules**: Enumera los módulos cargados en procesos.
- **volatility -f <archivo> shimcache**: Analiza la caché de compatibilidad de la aplicación.
- **volatility -f <archivo> userassist**: Recupera información sobre programas utilizados por usuarios.
- **volatility -f <archivo> getsids**: Enumera los identificadores de seguridad (SIDs) de procesos.
- **volatility -f <archivo> envars**: Muestra las variables de entorno de procesos.
- **volatility -f <archivo> consoles**: Enumera las sesiones de consola activas.
- **volatility -f <archivo> hivescan**: Escanea los archivos de volcado de registro en busca de subclaves.
- **volatility -f <archivo> dumpregistry -o <offset> -D <destino>**: Extrae una clave de registro del volcado de memoria.
- **volatility -f <archivo> dumpcerts -D <destino>**: Extrae certificados del volcado de memoria.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> mftparser**: Analiza la tabla maestra de archivos (MFT) para recuperar información de archivos.
- **volatility -f <archivo> shimcachemem**: Analiza la caché de compatibilidad de la aplicación en la memoria.
- **volatility -f <archivo> modscan**: Escanea los módulos del kernel.
- **volatility -f <archivo> moddump -b <dirección> -D <destino>**: Extrae un módulo del kernel del volcado de memoria.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> dumpregistry -o <offset> -D <destino>**: Extrae una clave de registro del volcado de memoria.
- **volatility -f <archivo> dumpcerts -D <destino>**: Extrae certificados del volcado de memoria.
- **volatility -f <archivo> mftparser**: Analiza la tabla maestra de archivos (MFT) para recuperar información de archivos.
- **volatility -f <archivo> shimcachemem**: Analiza la caché de compatibilidad de la aplicación en la memoria.
- **volatility -f <archivo> modscan**: Escanea los módulos del kernel.
- **volatility -f <archivo> moddump -b <dirección> -D <destino>**: Extrae un módulo del kernel del volcado de memoria.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> dumpregistry -o <offset> -D <destino>**: Extrae una clave de registro del volcado de memoria.
- **volatility -f <archivo> dumpcerts -D <destino>**: Extrae certificados del volcado de memoria.
- **volatility -f <archivo> mftparser**: Analiza la tabla maestra de archivos (MFT) para recuperar información de archivos.
- **volatility -f <archivo> shimcachemem**: Analiza la caché de compatibilidad de la aplicación en la memoria.
- **volatility -f <archivo> modscan**: Escanea los módulos del kernel.
- **volatility -f <archivo> moddump -b <dirección> -D <destino>**: Extrae un módulo del kernel del volcado de memoria.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> dumpregistry -o <offset> -D <destino>**: Extrae una clave de registro del volcado de memoria.
- **volatility -f <archivo> dumpcerts -D <destino>**: Extrae certificados del volcado de memoria.
- **volatility -f <archivo> mftparser**: Analiza la tabla maestra de archivos (MFT) para recuperar información de archivos.
- **volatility -f <archivo> shimcachemem**: Analiza la caché de compatibilidad de la aplicación en la memoria.
- **volatility -f <archivo> modscan**: Escanea los módulos del kernel.
- **volatility -f <archivo> moddump -b <dirección> -D <destino>**: Extrae un módulo del kernel del volcado de memoria.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> dumpregistry -o <offset> -D <destino>**: Extrae una clave de registro del volcado de memoria.
- **volatility -f <archivo> dumpcerts -D <destino>**: Extrae certificados del volcado de memoria.
- **volatility -f <archivo> mftparser**: Analiza la tabla maestra de archivos (MFT) para recuperar información de archivos.
- **volatility -f <archivo> shimcachemem**: Analiza la caché de compatibilidad de la aplicación en la memoria.
- **volatility -f <archivo> modscan**: Escanea los módulos del kernel.
- **volatility -f <archivo> moddump -b <dirección> -D <destino>**: Extrae un módulo del kernel del volcado de memoria.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> dumpregistry -o <offset> -D <destino>**: Extrae una clave de registro del volcado de memoria.
- **volatility -f <archivo> dumpcerts -D <destino>**: Extrae certificados del volcado de memoria.
- **volatility -f <archivo> mftparser**: Analiza la tabla maestra de archivos (MFT) para recuperar información de archivos.
- **volatility -f <archivo> shimcachemem**: Analiza la caché de compatibilidad de la aplicación en la memoria.
- **volatility -f <archivo> modscan**: Escanea los módulos del kernel.
- **volatility -f <archivo> moddump -b <dirección> -D <destino>**: Extrae un módulo del kernel del volcado de memoria.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> dumpregistry -o <offset> -D <destino>**: Extrae una clave de registro del volcado de memoria.
- **volatility -f <archivo> dumpcerts -D <destino>**: Extrae certificados del volcado de memoria.
- **volatility -f <archivo> mftparser**: Analiza la tabla maestra de archivos (MFT) para recuperar información de archivos.
- **volatility -f <archivo> shimcachemem**: Analiza la caché de compatibilidad de la aplicación en la memoria.
- **volatility -f <archivo> modscan**: Escanea los módulos del kernel.
- **volatility -f <archivo> moddump -b <dirección> -D <destino>**: Extrae un módulo del kernel del volcado de memoria.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> dumpregistry -o <offset> -D <destino>**: Extrae una clave de registro del volcado de memoria.
- **volatility -f <archivo> dumpcerts -D <destino>**: Extrae certificados del volcado de memoria.
- **volatility -f <archivo> mftparser**: Analiza la tabla maestra de archivos (MFT) para recuperar información de archivos.
- **volatility -f <archivo> shimcachemem**: Analiza la caché de compatibilidad de la aplicación en la memoria.
- **volatility -f <archivo> modscan**: Escanea los módulos del kernel.
- **volatility -f <archivo> moddump -b <dirección> -D <destino>**: Extrae un módulo del kernel del volcado de memoria.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> dumpregistry -o <offset> -D <destino>**: Extrae una clave de registro del volcado de memoria.
- **volatility -f <archivo> dumpcerts -D <destino>**: Extrae certificados del volcado de memoria.
- **volatility -f <archivo> mftparser**: Analiza la tabla maestra de archivos (MFT) para recuperar información de archivos.
- **volatility -f <archivo> shimcachemem**: Analiza la caché de compatibilidad de la aplicación en la memoria.
- **volatility -f <archivo> modscan**: Escanea los módulos del kernel.
- **volatility -f <archivo> moddump -b <dirección> -D <destino>**: Extrae un módulo del kernel del volcado de memoria.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> dumpregistry -o <offset> -D <destino>**: Extrae una clave de registro del volcado de memoria.
- **volatility -f <archivo> dumpcerts -D <destino>**: Extrae certificados del volcado de memoria.
- **volatility -f <archivo> mftparser**: Analiza la tabla maestra de archivos (MFT) para recuperar información de archivos.
- **volatility -f <archivo> shimcachemem**: Analiza la caché de compatibilidad de la aplicación en la memoria.
- **volatility -f <archivo> modscan**: Escanea los módulos del kernel.
- **volatility -f <archivo> moddump -b <dirección> -D <destino>**: Extrae un módulo del kernel del volcado de memoria.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> dumpregistry -o <offset> -D <destino>**: Extrae una clave de registro del volcado de memoria.
- **volatility -f <archivo> dumpcerts -D <destino>**: Extrae certificados del volcado de memoria.
- **volatility -f <archivo> mftparser**: Analiza la tabla maestra de archivos (MFT) para recuperar información de archivos.
- **volatility -f <archivo> shimcachemem**: Analiza la caché de compatibilidad de la aplicación en la memoria.
- **volatility -f <archivo> modscan**: Escanea los módulos del kernel.
- **volatility -f <archivo> moddump -b <dirección> -D <destino>**: Extrae un módulo del kernel del volcado de memoria.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> dumpregistry -o <offset> -D <destino>**: Extrae una clave de registro del volcado de memoria.
- **volatility -f <archivo> dumpcerts -D <destino>**: Extrae certificados del volcado de memoria.
- **volatility -f <archivo> mftparser**: Analiza la tabla maestra de archivos (MFT) para recuperar información de archivos.
- **volatility -f <archivo> shimcachemem**: Analiza la caché de compatibilidad de la aplicación en la memoria.
- **volatility -f <archivo> modscan**: Escanea los módulos del kernel.
- **volatility -f <archivo> moddump -b <dirección> -D <destino>**: Extrae un módulo del kernel del volcado de memoria.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> dumpregistry -o <offset> -D <destino>**: Extrae una clave de registro del volcado de memoria.
- **volatility -f <archivo> dumpcerts -D <destino>**: Extrae certificados del volcado de memoria.
- **volatility -f <archivo> mftparser**: Analiza la tabla maestra de archivos (MFT) para recuperar información de archivos.
- **volatility -f <archivo> shimcachemem**: Analiza la caché de compatibilidad de la aplicación en la memoria.
- **volatility -f <archivo> modscan**: Escanea los módulos del kernel.
- **volatility -f <archivo> moddump -b <dirección> -D <destino>**: Extrae un módulo del kernel del volcado de memoria.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> dumpregistry -o <offset> -D <destino>**: Extrae una clave de registro del volcado de memoria.
- **volatility -f <archivo> dumpcerts -D <destino>**: Extrae certificados del volcado de memoria.
- **volatility -f <archivo> mftparser**: Analiza la tabla maestra de archivos (MFT) para recuperar información de archivos.
- **volatility -f <archivo> shimcachemem**: Analiza la caché de compatibilidad de la aplicación en la memoria.
- **volatility -f <archivo> modscan**: Escanea los módulos del kernel.
- **volatility -f <archivo> moddump -b <dirección> -D <destino>**: Extrae un módulo del kernel del volcado de memoria.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> dumpregistry -o <offset> -D <destino>**: Extrae una clave de registro del vol
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
## Red

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{% endtab %}

{% tab title="vol2" %} 

## Hoja de trucos de Volatility

### Comandos básicos

- **volatility -f <archivo> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: Lista los procesos en ejecución.
- **volatility -f <archivo> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <archivo> psscan**: Escanea los procesos.
- **volatility -f <archivo> dlllist -p <PID>**: Lista las DLL cargadas por un proceso específico.
- **volatility -f <archivo> cmdscan**: Escanea los procesos en busca de comandos de consola.
- **volatility -f <archivo> filescan**: Escanea los descriptores de archivo.
- **volatility -f <archivo> netscan**: Escanea los sockets de red.
- **volatility -f <archivo> connections**: Muestra las conexiones de red.
- **volatility -f <archivo> consoles**: Lista las consolas interactivas.
- **volatility -f <archivo> hivelist**: Enumera los registros del sistema en vivo.
- **volatility -f <archivo> userassist**: Extrae las entradas de UserAssist del Registro.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <archivo> apihooks**: Busca API hooks en los procesos.
- **volatility -f <archivo> ldrmodules**: Lista los módulos cargados en los procesos.
- **volatility -f <archivo> modscan**: Escanea los módulos del kernel.
- **volatility -f <archivo> shimcache**: Extrae información de ShimCache del Registro.
- **volatility -f <archivo> getsids**: Enumera los SID de los procesos.
- **volatility -f <archivo> envars**: Muestra las variables de entorno de los procesos.
- **volatility -f <archivo> cmdline**: Muestra los argumentos de línea de comandos de los procesos.
- **volatility -f <archivo> consoles -v**: Muestra información detallada de las consolas.
- **volatility -f <archivo> hivelist -v**: Muestra información detallada de los registros del sistema en vivo.

### Plugins adicionales

- **apihooks**: Busca hooks de API en los procesos.
- **malfind**: Encuentra inyecciones de código malicioso en los procesos.
- **mftparser**: Analiza el MFT (Master File Table) para encontrar archivos eliminados.
- **dumpfiles -Q <dirección> -D <destino>**: Extrae archivos de memoria.
- **hashdump**: Extrae los hashes de contraseñas de LSASS.
- **memdump -p <PID> -D <destino>**: Crea un volcado de memoria de un proceso específico.
- **cmdscan**: Escanea los procesos en busca de comandos de consola.
- **consoles**: Lista las consolas interactivas.
- **hivelist**: Enumera los registros del sistema en vivo.
- **userassist**: Extrae las entradas de UserAssist del Registro.
- **shimcache**: Extrae información de ShimCache del Registro.
- **getsids**: Enumera los SID de los procesos.
- **envars**: Muestra las variables de entorno de los procesos.
- **cmdline**: Muestra los argumentos de línea de comandos de los procesos.

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

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Comandos básicos de Volatility

- **volatility -f <archivo de volcado> imageinfo**: Escanea el archivo de volcado de memoria para obtener información básica.
- **volatility -f <archivo de volcado> pslist**: Enumera los procesos en ejecución.
- **volatility -f <archivo de volcado> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <archivo de volcado> psscan**: Escanea los procesos a nivel de kernel.
- **volatility -f <archivo de volcado> dlllist -p <PID>**: Lista las DLL cargadas por un proceso específico.
- **volatility -f <archivo de volcado> filescan**: Escanea los descriptores de archivo.
- **volatility -f <archivo de volcado> cmdline -p <PID>**: Muestra el comando utilizado para ejecutar un proceso.
- **volatility -f <archivo de volcado> connections**: Enumera las conexiones de red.
- **volatility -f <archivo de volcado> connscan**: Escanea las conexiones de red.
- **volatility -f <archivo de volcado> netscan**: Escanea los sockets de red.
- **volatility -f <archivo de volcado> hashdump**: Extrae los hashes de contraseñas.
- **volatility -f <archivo de volcado> userassist**: Recupera las entradas de UserAssist.
- **volatility -f <archivo de volcado> malfind**: Encuentra procesos sospechosos.
- **volatility -f <archivo de volcado> apihooks**: Detecta ganchos de API.
- **volatility -f <archivo de volcado> ldrmodules**: Enumera los módulos cargados.
- **volatility -f <archivo de volcado> shimcache**: Recupera información de ShimCache.
- **volatility -f <archivo de volcado> getsids**: Enumera los SID de usuario.
- **volatility -f <archivo de volcado> hivelist**: Enumera los archivos de volcado del registro.
- **volatility -f <archivo de volcado> printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <archivo de volcado> hivedump -o <offset> -s <tamaño> -f <nombre_archivo>**: Extrae un archivo de volcado del registro.
- **volatility -f <archivo de volcado> memmap -p <PID>**: Muestra el mapeo de memoria de un proceso.
- **volatility -f <archivo de volcado> memdump -p <PID> -D <directorio_destino>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <archivo de volcado> memdump --dump-dir <directorio_destino>**: Crea volcados de memoria de todos los procesos.
- **volatility -f <archivo de volcado> linux_bash**: Recupera el historial de comandos de Bash en sistemas Linux.
- **volatility -f <archivo de volcado> linux_netstat**: Enumera las conexiones de red en sistemas Linux.
- **volatility -f <archivo de volcado> linux_pslist**: Enumera los procesos en ejecución en sistemas Linux.
- **volatility -f <archivo de volcado> linux_psaux**: Enumera los procesos con detalles adicionales en sistemas Linux.
- **volatility -f <archivo de volcado> linux_ifconfig**: Muestra la configuración de red en sistemas Linux.
- **volatility -f <archivo de volcado> linux_lsmod**: Lista los módulos cargados en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_afinfo**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_creds**: Verifica la presencia de credenciales en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_fop**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_idt**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_modules**: Verifica la integridad de los módulos en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_syscall**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_syscalltbl**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_tty**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_tty_audit**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_tty_dir**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_tty_log**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_tty_write**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_vma**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_hidden_modules**: Enumera los módulos ocultos en sistemas Linux.
- **volatility -f <archivo de volcado> linux_hidden_procs**: Enumera los procesos ocultos en sistemas Linux.
- **volatility -f <archivo de volcado> linux_hidden_files**: Enumera los archivos ocultos en sistemas Linux.
- **volatility -f <archivo de volcado> linux_lsof**: Muestra los archivos abiertos en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_fop**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_idt**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_modules**: Verifica la integridad de los módulos en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_syscall**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_syscalltbl**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_tty**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_tty_audit**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_tty_dir**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_tty_log**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_tty_write**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_check_vma**: Verifica la presencia de backdoors en sistemas Linux.
- **volatility -f <archivo de volcado> linux_hidden_modules**: Enumera los módulos ocultos en sistemas Linux.
- **volatility -f <archivo de volcado> linux_hidden_procs**: Enumera los procesos ocultos en sistemas Linux.
- **volatility -f <archivo de volcado> linux_hidden_files**: Enumera los archivos ocultos en sistemas Linux.
- **volatility -f <archivo de volcado> linux_lsof**: Muestra los archivos abiertos en sistemas Linux.
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

- **volatility -f <file> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <file> pslist**: Lista los procesos en ejecución.
- **volatility -f <file> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> psscan**: Escanea los procesos.
- **volatility -f <file> dlllist -p <pid>**: Lista las DLL cargadas por un proceso.
- **volatility -f <file> cmdscan**: Escanea los procesos en busca de comandos de consola.
- **volatility -f <file> consoles**: Muestra las consolas interactivas.
- **volatility -f <file> filescan**: Escanea los descriptores de archivo.
- **volatility -f <file> netscan**: Escanea los sockets de red.
- **volatility -f <file> connections**: Muestra las conexiones de red.
- **volatility -f <file> svcscan**: Escanea los servicios.
- **volatility -f <file> hivelist**: Lista los archivos de volcado del registro.
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro.
- **volatility -f <file> hashdump**: Extrae los hashes de contraseñas.
- **volatility -f <file> mimikatz**: Ejecuta Mimikatz en el espacio de memoria.
- **volatility -f <file> cmdline**: Muestra los argumentos de línea de comandos de los procesos.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <file> apihooks**: Muestra los ganchos de API.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> modscan**: Escanea los módulos.
- **volatility -f <file> shimcache**: Analiza la caché de Shim.
- **volatility -f <file> getsids**: Obtiene los SID de los procesos.
- **volatility -f <file> getservicesids**: Obtiene los SID de los servicios.
- **volatility -f <file> yarascan**: Escanea la memoria en busca de patrones Yara.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos del espacio de memoria.
- **volatility -f <file> memdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria del proceso.
- **volatility -f <file> memstrings -p <pid>**: Encuentra cadenas ASCII en el espacio de memoria de un proceso.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <file> malfind -p <pid>**: Encuentra inyecciones de código malicioso en un proceso específico.
- **volatility -f <file> malfind -D <output_directory>**: Escanea la memoria en busca de inyecciones de código malicioso y las guarda en un directorio de salida.
- **volatility -f <file> malfind -p <pid> -D <output_directory>**: Escanea la memoria en busca de inyecciones de código malicioso en un proceso específico y las guarda en un directorio de salida.
- **volatility -f <file> malfind -Y <yara_rule>**: Escanea la memoria en busca de inyecciones de código malicioso que coincidan con una regla Yara.
- **volatility -f <file> malfind -p <pid> -Y <yara_rule>**: Escanea la memoria en busca de inyecciones de código malicioso en un proceso específico que coincidan con una regla Yara.
- **volatility -f <file> malfind -D <output_directory> -Y <yara_rule>**: Escanea la memoria en busca de inyecciones de código malicioso que coincidan con una regla Yara y las guarda en un directorio de salida.
- **volatility -f <file> malfind -p <pid> -D <output_directory> -Y <yara_rule>**: Escanea la memoria en busca de inyecciones de código malicioso en un proceso específico que coincidan con una regla Yara y las guarda en un directorio de salida.

### Plugins adicionales

- **apihooks**: Muestra los ganchos de API.
- **malfind**: Encuentra inyecciones de código malicioso.
- **mimikatz**: Ejecuta Mimikatz en el espacio de memoria.
- **yarascan**: Escanea la memoria en busca de patrones Yara.

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

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Comandos básicos
- **volatility -f <archivo> imageinfo**: muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: lista los procesos en ejecución.
- **volatility -f <archivo> pstree**: muestra los procesos en forma de árbol.
- **volatility -f <archivo> psscan**: escanea los procesos.
- **volatility -f <archivo> dlllist -p <PID>**: lista las DLL cargadas por un proceso.
- **volatility -f <archivo> cmdscan**: busca comandos en la memoria.
- **volatility -f <archivo> filescan**: escanea los descriptores de archivo.
- **volatility -f <archivo> netscan**: busca información de red.
- **volatility -f <archivo> connections**: muestra las conexiones de red.
- **volatility -f <archivo> consoles**: lista las consolas interactivas.
- **volatility -f <archivo> hivelist**: muestra las ubicaciones del Registro de Windows.
- **volatility -f <archivo> printkey -o <offset>**: muestra las subclaves y valores de una clave del Registro.
- **volatility -f <archivo> cmdline**: muestra los argumentos de línea de comandos de los procesos.
- **volatility -f <archivo> malfind**: busca inyecciones de código malicioso.
- **volatility -f <archivo> yarascan**: escanea la memoria en busca de patrones con YARA.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: crea un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio> --name**: crea un volcado de memoria de un proceso específico con el nombre del proceso en el archivo.
- **volatility -f <archivo> memdump -p <PID> -D <directorio> --name --dump-dir <directorio>**: crea un volcado de memoria de un proceso específico con el nombre del proceso en el archivo y lo guarda en un directorio específico.

#### Plugins adicionales
- **apihooks**: muestra los ganchos de API.
- **malfind**: busca inyecciones de código malicioso.
- **mimikatz**: busca credenciales con Mimikatz.
- **autoruns**: muestra programas que se ejecutan al inicio.
- **svcscan**: escanea los servicios.
- **modscan**: escanea los módulos del kernel.
- **ldrmodules**: muestra los módulos cargados.
- **atomscan**: busca objetos atómicos.
- **callbacks**: muestra los callbacks del kernel.
- **devicetree**: muestra el árbol de dispositivos.
- **driverirp**: muestra las IRP de los controladores.
- **getsids**: muestra los SID de los procesos.
- **handles**: muestra los descriptores de archivo y claves del Registro abiertos.
- **hollowfind**: busca procesos huecos.
- **idt**: muestra la IDT.
- **impscan**: escanea las importaciones de DLL.
- **privs**: muestra los privilegios de los procesos.
- **psxview**: muestra procesos ocultos.
- **ssdt**: muestra la SSDT.
- **thrdscan**: escanea los hilos.
- **userassist**: muestra programas abiertos recientemente.
- **vadinfo**: muestra información sobre los espacios de direcciones virtuales.
- **vaddump**: crea un volcado de un espacio de direcciones virtuales.
- **vadtree**: muestra los espacios de direcciones virtuales en forma de árbol.
- **wndscan**: escanea las ventanas.
- **yarascan**: escanea la memoria en busca de patrones con YARA.

#### Ejemplos de uso
- **volatility -f mem.raw imageinfo**: muestra información básica del volcado de memoria "mem.raw".
- **volatility -f mem.raw pslist**: lista los procesos en ejecución en "mem.raw".
- **volatility -f mem.raw memdump -p 123 -D dumpdir/**: crea un volcado de memoria del proceso con PID 123 en el directorio "dumpdir".
- **volatility -f mem.raw --profile=Win7SP1x64 pslist**: lista los procesos en un volcado de memoria con perfil Windows 7 SP1 de 64 bits.
- **volatility -f mem.raw --profile=Win7SP1x64 cmdscan**: busca comandos en un volcado de memoria con perfil Windows 7 SP1 de 64 bits.

{% endtab %}
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

#### Volatility es una herramienta de análisis de memoria que es utilizada en la investigación forense digital para extraer información de los volcados de memoria adquiridos de sistemas Windows, macOS y Linux.

#### Comandos básicos de Volatility:

- **volatility -f <archivo> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: Lista los procesos en ejecución.
- **volatility -f <archivo> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <archivo> cmdline**: Muestra los comandos ejecutados.
- **volatility -f <archivo> filescan**: Escanea en busca de descriptores de archivos.
- **volatility -f <archivo> netscan**: Muestra las conexiones de red.
- **volatility -f <archivo> connections**: Muestra las conexiones de red.
- **volatility -f <archivo> consoles**: Muestra las consolas interactivas.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <archivo> dlllist**: Lista las DLL cargadas en los procesos.
- **volatility -f <archivo> getsids**: Muestra los SID de los procesos.
- **volatility -f <archivo> userassist**: Muestra programas usados frecuentemente.
- **volatility -f <archivo> hivelist**: Enumera los archivos de registro cargados.
- **volatility -f <archivo> printkey**: Imprime una clave de registro.
- **volatility -f <archivo> cmdline**: Muestra los comandos ejecutados.
- **volatility -f <archivo> consoles**: Muestra las consolas interactivas.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <archivo> dlllist**: Lista las DLL cargadas en los procesos.
- **volatility -f <archivo> getsids**: Muestra los SID de los procesos.
- **volatility -f <archivo> userassist**: Muestra programas usados frecuentemente.
- **volatility -f <archivo> hivelist**: Enumera los archivos de registro cargados.
- **volatility -f <archivo> printkey**: Imprime una clave de registro.

#### Estos son solo algunos de los comandos básicos que se pueden utilizar con Volatility para analizar volcados de memoria en la investigación forense digital. Se recomienda explorar más comandos y opciones para obtener una comprensión más profunda de las capacidades de esta herramienta.

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

#### Comandos básicos de Volatility

- **volatility -f <archivo> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: Muestra una lista de procesos en el volcado de memoria.
- **volatility -f <archivo> pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **volatility -f <archivo> psscan**: Escanea procesos a través del volcado de memoria.
- **volatility -f <archivo> dlllist -p <PID>**: Muestra las DLL cargadas por un proceso específico.
- **volatility -f <archivo> cmdscan**: Escanea los procesos en busca de comandos de consola.
- **volatility -f <archivo> filescan**: Escanea el volcado de memoria en busca de objetos de archivo.
- **volatility -f <archivo> netscan**: Escanea el volcado de memoria en busca de artefactos de red.
- **volatility -f <archivo> connections**: Muestra las conexiones de red en el volcado de memoria.
- **volatility -f <archivo> consoles**: Muestra las consolas interactivas abiertas por procesos.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código malicioso en procesos.
- **volatility -f <archivo> yarascan**: Escanea el volcado de memoria en busca de patrones YARA.
- **volatility -f <archivo> cmdline**: Muestra los argumentos de línea de comandos de procesos.
- **volatility -f <archivo> hivelist**: Enumera los archivos de registro cargados en memoria.
- **volatility -f <archivo> printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <archivo> userassist**: Muestra programas utilizados con frecuencia por usuarios.
- **volatility -f <archivo> shimcache**: Muestra entradas de la caché de compatibilidad de aplicaciones.
- **volatility -f <archivo> ldrmodules**: Enumera los módulos cargados en procesos.
- **volatility -f <archivo> modscan**: Escanea el volcado de memoria en busca de módulos.
- **volatility -f <archivo> getsids**: Enumera los SID de seguridad de procesos.
- **volatility -f <archivo> getservicesids**: Enumera los SID de seguridad de servicios.
- **volatility -f <archivo> apihooks**: Detecta ganchos de API en procesos.
- **volatility -f <archivo> callbacks**: Enumera los callbacks de registro en el volcado de memoria.
- **volatility -f <archivo> mutantscan**: Escanea el volcado de memoria en busca de objetos de mutante.
- **volatility -f <archivo> envars**: Muestra variables de entorno de procesos.
- **volatility -f <archivo> vadinfo -o <offset>**: Muestra información sobre un área de descriptor de memoria virtual.
- **volatility -f <archivo> vadtree -o <offset>**: Muestra un árbol de áreas de descriptor de memoria virtual.
- **volatility -f <archivo> memmap**: Muestra un mapa de memoria del volcado.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio> -r <rango>**: Volcado de memoria de un rango de direcciones de un proceso.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso.
- **volatility -f <archivo> memstrings -Q <cantidad>**: Extrae las primeras N cadenas ASCII del volcado de memoria.
- **volatility -f <archivo> memstrings -s <tamaño>**: Extrae cadenas ASCII de un tamaño específico del volcado de memoria.
- **volatility -f <archivo> memstrings -o <offset>**: Extrae cadenas ASCII de un desplazamiento específico del volcado de memoria.

#### Plugins adicionales de Volatility

- **volatility -f <archivo> <nombre_del_plugin>**: Ejecuta un plugin adicional de Volatility.
- **volatility --info**: Muestra información sobre todos los plugins disponibles.
- **volatility --plugins=<directorio>**: Carga plugins desde un directorio específico.
- **volatility --profile=<perfil> -f <archivo> <nombre_del_plugin>**: Ejecuta un plugin con un perfil específico.
- **volatility --info | grep <término>**: Busca plugins que contengan un término específico en su descripción.
- **volatility --output-file=<archivo> -f <archivo> <nombre_del_plugin>**: Guarda la salida de un plugin en un archivo.

{% endtab %}
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

{% tab title="vol2" %} 

## Hoja de trucos de Volatility

### Análisis de volcado de memoria

#### Comandos básicos

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
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <file> apihooks**: Busca ganchos de API.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> modscan**: Escanea los módulos cargados.
- **volatility -f <file> shimcache**: Muestra la caché de Shim.
- **volatility -f <file> getsids**: Obtiene los SID de los procesos.
- **volatility -f <file> hivelist**: Enumera los archivos de volcado del registro.
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro.
- **volatility -f <file> userassist**: Muestra las entradas de UserAssist.
- **volatility -f <file> cmdline**: Muestra los argumentos de línea de comandos.
- **volatility -f <file> consoles -v**: Muestra información detallada de las consolas.
- **volatility -f <file> envars**: Muestra las variables de entorno.
- **volatility -f <file> hivelist**: Enumera los archivos de volcado del registro.
- **volatility -f <file> hivedump -o <offset> -s <size> -f <output>**: Extrae un archivo de volcado del registro.
- **volatility -f <file> hashdump**: Muestra las contraseñas hash.
- **volatility -f <file> mimikatz**: Ejecuta Mimikatz en el espacio de memoria.
- **volatility -f <file> yarascan**: Escanea la memoria en busca de patrones Yara.
- **volatility -f <file> memmap -p <pid>**: Muestra el mapeo de memoria de un proceso.
- **volatility -f <file> memdump -p <pid> -D <output>**: Crea un volcado de memoria de un proceso.
- **volatility -f <file> memdump -p <pid> -o <offset> -s <size> -D <output>**: Crea un volcado de memoria de un proceso con offset y tamaño específicos.
- **volatility -f <file> memstrings -p <pid>**: Encuentra cadenas ASCII en la memoria de un proceso.
- **volatility -f <file> malfind -p <pid>**: Encuentra inyecciones de código malicioso en un proceso.
- **volatility -f <file> malfind -p <pid> --dump-dir <output>**: Extrae inyecciones de código malicioso en un proceso a un directorio.
- **volatility -f <file> malfind -p <pid> --dump-dir <output> --dump-addr <address>**: Extrae inyecciones de código malicioso en un proceso a un directorio con una dirección específica.
- **volatility -f <file> malfind -p <pid> --dump-dir <output> --dump-addr <address> --dump-size <size>**: Extrae inyecciones de código malicioso en un proceso a un directorio con una dirección y tamaño específicos.

#### Plugins adicionales

- **volatility -f <file> <plugin> --profile=<profile>**: Ejecuta un plugin específico con un perfil determinado.
- **volatility -f <file> --plugins=<path> <plugin>**: Ejecuta un plugin específico desde una ubicación personalizada.
- **volatility --info**: Muestra información sobre los perfiles disponibles.
- **volatility --plugins=<path> --info**: Muestra información sobre los plugins disponibles en una ubicación personalizada.

{% endtab %}
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

- **volatility -f <file> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <file> pslist**: Lista los procesos en ejecución.
- **volatility -f <file> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> psscan**: Escanea los procesos.
- **volatility -f <file> dlllist -p <pid>**: Lista las DLL cargadas por un proceso específico.
- **volatility -f <file> cmdscan**: Escanea los procesos en busca de comandos ejecutados.
- **volatility -f <file> filescan**: Escanea los descriptores de archivo.
- **volatility -f <file> netscan**: Escanea los sockets de red.
- **volatility -f <file> connections**: Muestra las conexiones de red.
- **volatility -f <file> consoles**: Lista las consolas interactivas.
- **volatility -f <file> hivelist**: Enumera los archivos de volcado del registro.
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro específica.
- **volatility -f <file> hashdump**: Extrae los hashes de contraseñas.
- **volatility -f <file> userassist**: Recupera las entradas de UserAssist.
- **volatility -f <file> malfind**: Encuentra procesos sospechosos.
- **volatility -f <file> apihooks**: Muestra los ganchos de API.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> modscan**: Escanea los módulos.
- **volatility -f <file> shimcache**: Recupera la información de ShimCache.
- **volatility -f <file> getsids**: Obtiene los SID de los procesos.
- **volatility -f <file> getservicesids**: Obtiene los SID de los servicios.
- **volatility -f <file> svcscan**: Escanea los servicios.
- **volatility -f <file> driverirp**: Enumera los IRP de los controladores.
- **volatility -f <file> callbacks**: Enumera los callbacks del kernel.
- **volatility -f <file> ssdt**: Enumera la tabla de descriptores de servicios del sistema.
- **volatility -f <file> idt**: Enumera la tabla de descriptores de interrupciones.
- **volatility -f <file> gdt**: Enumera la tabla de descriptores globales.
- **volatility -f <file> threads**: Lista los hilos.
- **volatility -f <file> mutantscan**: Escanea los objetos de mutante.
- **volatility -f <file> mutantscan**: Escanea los objetos de mutante.
- **volatility -f <file> envars**: Muestra las variables de entorno.
- **volatility -f <file> vadinfo -o <offset>**: Muestra información sobre un área de memoria específica.
- **volatility -f <file> vadtree -o <offset>**: Muestra un árbol de áreas de memoria.
- **volatility -f <file> memmap**: Muestra un mapa de memoria.
- **volatility -f <file> memdump -p <pid> -D <output_directory>**: Volcado de memoria de un proceso específico.
- **volatility -f <file> memdump -p <pid> -D <output_directory> -r <range>**: Volcado de memoria de un proceso en un rango específico.
- **volatility -f <file> memstrings -p <pid>**: Busca cadenas ASCII en la memoria de un proceso.
- **volatility -f <file> memstrings -s <min_length>**: Busca cadenas ASCII en toda la memoria.
- **volatility -f <file> yarascan -Y "<yara_rule>"**: Escanea la memoria en busca de patrones YARA.
- **volatility -f <file> yarascan -f <yara_file>**: Escanea la memoria en busca de patrones YARA utilizando un archivo de reglas.
- **volatility -f <file> malfind**: Encuentra procesos sospechosos.
- **volatility -f <file> malfind**: Encuentra procesos sospechosos.

### Plugins adicionales

- **apihooks**: Muestra los ganchos de API.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospe
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

{% tab title="vol2" %} 

## Hoja de trucos de Volatility

### Comandos básicos

- **volatility -f <file> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <file> pslist**: Lista los procesos en ejecución.
- **volatility -f <file> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> psscan**: Escanea los procesos.
- **volatility -f <file> dlllist -p <pid>**: Lista las DLL cargadas por un proceso.
- **volatility -f <file> cmdscan**: Escanea los procesos en busca de comandos de consola.
- **volatility -f <file> filescan**: Escanea los descriptores de archivo.
- **volatility -f <file> netscan**: Escanea los sockets de red.
- **volatility -f <file> connections**: Muestra las conexiones de red.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <file> apihooks**: Muestra los ganchos de API.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> modscan**: Escanea los módulos cargados.
- **volatility -f <file> shimcache**: Muestra la caché de Shim.
- **volatility -f <file> userassist**: Muestra las entradas de UserAssist.
- **volatility -f <file> hivelist**: Enumera los archivos de volcado del registro.
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro.
- **volatility -f <file> cmdline**: Muestra los argumentos de línea de comandos.
- **volatility -f <file> consoles**: Enumera las consolas interactivas.
- **volatility -f <file> getsids**: Enumera los SID de usuario.
- **volatility -f <file> envars**: Muestra las variables de entorno.
- **volatility -f <file> svcscan**: Escanea los servicios.
- **volatility -f <file> driverirp**: Enumera los IRP de controlador.
- **volatility -f <file> devicetree**: Muestra el árbol de dispositivos.
- **volatility -f <file> handles**: Enumera los descriptores de archivo.
- **volatility -f <file> mutantscan**: Escanea los objetos mutantes.
- **volatility -f <file> threads**: Lista los hilos.
- **volatility -f <file> callbacks**: Enumera los callbacks.
- **volatility -f <file> timers**: Lista los temporizadores.
- **volatility -f <file> idt**: Muestra la tabla de descriptores de interrupción.
- **volatility -f <file> gdt**: Muestra la tabla de descriptores globales.
- **volatility -f <file> ssdt**: Muestra la tabla de descriptores de servicios.
- **volatility -f <file> driverscan**: Escanea los controladores.
- **volatility -f <file> psxview**: Muestra los procesos ocultos.
- **volatility -f <file> yarascan**: Escanea con reglas Yara.
- **volatility -f <file> mutantscan**: Escanea los objetos mutantes.
- **volatility -f <file> threads**: Lista los hilos.
- **volatility -f <file> callbacks**: Enumera los callbacks.
- **volatility -f <file> timers**: Lista los temporizadores.
- **volatility -f <file> idt**: Muestra la tabla de descriptores de interrupción.
- **volatility -f <file> gdt**: Muestra la tabla de descriptores globales.
- **volatility -f <file> ssdt**: Muestra la tabla de descriptores de servicios.
- **volatility -f <file> driverscan**: Escanea los controladores.
- **volatility -f <file> psxview**: Muestra los procesos ocultos.
- **volatility -f <file> yarascan**: Escanea con reglas Yara.

### Plugins adicionales

- **malprocfind**: Encuentra procesos maliciosos.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malsysproc**: Encuentra procesos del sistema maliciosos.
- **maldrvfind**: Encuentra controladores maliciosos.
- **malfind**: Encuentra malware.
- **malthfind**: Encuentra manejadores de tareas maliciosos.
- **malwaredetect**: Detecta malware.
- **malwarescan**: Escanea en busca de malware.
- **malstrings**: Busca cadenas maliciosas.
- **malfind**: Encuentra inyecciones de código malicioso.
- **malsysproc**: Encuentra procesos del sistema maliciosos.
- **maldrvfind**: Encuentra controladores maliciosos.
- **malfind**: Encuentra malware.
- **malthfind**: Encuentra manejadores de tareas maliciosos.
- **malwaredetect**: Detecta malware.
- **malwarescan**: Escanea en busca de malware.
- **malstrings**: Busca cadenas maliciosas.

{% endtab %}
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

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Metodología básica de análisis de volcado de memoria

1. **Adquisición de memoria**
   - **Windows:** `winpmem`, `FTK Imager`, `DumpIt`
   - **Linux:** `LiME`, `Rekall`, `Magnet RAM Capture`

2. **Identificación del perfil**
   - `imageinfo`, `kdbgscan`, `kpcrscan`

3. **Análisis de procesos**
   - `pslist`, `psscan`, `pstree`

4. **Análisis de sockets de red**
   - `netscan`, `sockets`

5. **Análisis de controladores**
   - `driverlist`, `ldrmodules`

6. **Análisis de registros**
   - `hivelist`, `printkey`, `hashdump`

7. **Análisis de volcado de memoria**
   - `volshell`, `memdump`, `volatility`

8. **Análisis de malware**
   - `malfind`, `apihooks`, `yarascan`

9. **Análisis de rootkits**
   - `ssdt`, `callbacks`, `idt`

10. **Análisis de caché**
    - `cachedump`, `userassist`, `shellbags`

11. **Análisis de la estructura del sistema**
    - `modules`, `modscan`, `callbacks`

12. **Análisis de la estructura del kernel**
    - `ssdt`, `gdt`, `idt`

13. **Análisis de la estructura del proceso**
    - `threads`, `handles`, `vad`

14. **Análisis de la estructura del sistema de archivos**
    - `mftparser`, `filescan`, `moddump`

15. **Análisis de la estructura de red**
    - `connscan`, `connections`, `sockscan`

16. **Análisis de la estructura de registro**
    - `printkey`, `userassist`, `shellbags`

17. **Análisis de la estructura de la memoria**
    - `memmap`, `memdump`, `memstrings`

18. **Análisis de la estructura de la red**
    - `netscan`, `connections`, `sockscan`

19. **Análisis de la estructura de malware**
    - `malfind`, `apihooks`, `yarascan`

20. **Análisis de la estructura de rootkits**
    - `ssdt`, `callbacks`, `idt`

21. **Análisis de la estructura de caché**
    - `cachedump`, `userassist`, `shellbags`

22. **Análisis de la estructura de la memoria virtual**
    - `vadinfo`, `vaddump`, `vadtree`

23. **Análisis de la estructura de la memoria física**
    - `memmap`, `memdump`, `memstrings`

24. **Análisis de la estructura de la memoria del kernel**
    - `ssdt`, `gdt`, `idt`

25. **Análisis de la estructura de la memoria del proceso**
    - `threads`, `handles`, `vad`

26. **Análisis de la estructura de la memoria del sistema de archivos**
    - `mftparser`, `filescan`, `moddump`

27. **Análisis de la estructura de la memoria de red**
    - `connscan`, `connections`, `sockscan`

28. **Análisis de la estructura de la memoria del registro**
    - `printkey`, `userassist`, `shellbags`

29. **Análisis de la estructura de la memoria de malware**
    - `malfind`, `apihooks`, `yarascan`

30. **Análisis de la estructura de la memoria de rootkits**
    - `ssdt`, `callbacks`, `idt`

31. **Análisis de la estructura de la memoria de caché**
    - `cachedump`, `userassist`, `shellbags`

32. **Análisis de la estructura de la memoria de la red**
    - `netscan`, `connections`, `sockscan`

33. **Análisis de la estructura de la memoria virtual de malware**
    - `malfind`, `apihooks`, `yarascan`

34. **Análisis de la estructura de la memoria virtual de rootkits**
    - `ssdt`, `callbacks`, `idt`

35. **Análisis de la estructura de la memoria virtual de caché**
    - `cachedump`, `userassist`, `shellbags`

36. **Análisis de la estructura de la memoria virtual de la red**
    - `netscan`, `connections`, `sockscan`

37. **Análisis de la estructura de la memoria física de malware**
    - `malfind`, `apihooks`, `yarascan`

38. **Análisis de la estructura de la memoria física de rootkits**
    - `ssdt`, `callbacks`, `idt`

39. **Análisis de la estructura de la memoria física de caché**
    - `cachedump`, `userassist`, `shellbags`

40. **Análisis de la estructura de la memoria física de la red**
    - `netscan`, `connections`, `sockscan`

41. **Análisis de la estructura de la memoria del kernel de malware**
    - `malfind`, `apihooks`, `yarascan`

42. **Análisis de la estructura de la memoria del kernel de rootkits**
    - `ssdt`, `callbacks`, `idt`

43. **Análisis de la estructura de la memoria del kernel de caché**
    - `cachedump`, `userassist`, `shellbags`

44. **Análisis de la estructura de la memoria del kernel de la red**
    - `netscan`, `connections`, `sockscan`

45. **Análisis de la estructura de la memoria del proceso de malware**
    - `malfind`, `apihooks`, `yarascan`

46. **Análisis de la estructura de la memoria del proceso de rootkits**
    - `ssdt`, `callbacks`, `idt`

47. **Análisis de la estructura de la memoria del proceso de caché**
    - `cachedump`, `userassist`, `shellbags`

48. **Análisis de la estructura de la memoria del proceso de la red**
    - `netscan`, `connections`, `sockscan`

49. **Análisis de la estructura de la memoria del sistema de archivos de malware**
    - `mftparser`, `filescan`, `moddump`

50. **Análisis de la estructura de la memoria del sistema de archivos de rootkits**
    - `ssdt`, `callbacks`, `idt`

51. **Análisis de la estructura de la memoria del sistema de archivos de caché**
    - `cachedump`, `userassist`, `shellbags`

52. **Análisis de la estructura de la memoria del sistema de archivos de la red**
    - `netscan`, `connections`, `sockscan`

53. **Análisis de la estructura de la memoria de red de malware**
    - `malfind`, `apihooks`, `yarascan`

54. **Análisis de la estructura de la memoria de red de rootkits**
    - `ssdt`, `callbacks`, `idt`

55. **Análisis de la estructura de la memoria de red de caché**
    - `cachedump`, `userassist`, `shellbags`

56. **Análisis de la estructura de la memoria de red del kernel**
    - `netscan`, `connections`, `sockscan`

57. **Análisis de la estructura de la memoria de red del proceso**
    - `netscan`, `connections`, `sockscan`

58. **Análisis de la estructura de la memoria de red del sistema de archivos**
    - `netscan`, `connections`, `sockscan`

59. **Análisis de la estructura de la memoria del registro de malware**
    - `malfind`, `apihooks`, `yarascan`

60. **Análisis de la estructura de la memoria del registro de rootkits**
    - `ssdt`, `callbacks`, `idt`

61. **Análisis de la estructura de la memoria del registro de caché**
    - `cachedump`, `userassist`, `shellbags`

62. **Análisis de la estructura de la memoria del registro de la red**
    - `netscan`, `connections`, `sockscan`

63. **Análisis de la estructura de la memoria virtual de malware**
    - `malfind`, `apihooks`, `yarascan`

64. **Análisis de la estructura de la memoria virtual de rootkits**
    - `ssdt`, `callbacks`, `idt`

65. **Análisis de la estructura de la memoria virtual de caché**
    - `cachedump`, `userassist`, `shellbags`

66. **Análisis de la estructura de la memoria virtual de la red**
    - `netscan`, `connections`, `sockscan`

67. **Análisis de la estructura de la memoria física de malware**
    - `malfind`, `apihooks`, `yarascan`

68. **Análisis de la estructura de la memoria física de rootkits**
    - `ssdt`, `callbacks`, `idt`

69. **Análisis de la estructura de la memoria física de caché**
    - `cachedump`, `userassist`, `shellbags`

70. **Análisis de la estructura de la memoria física de la red**
    - `netscan`, `connections`, `sockscan`

71. **Análisis de la estructura de la memoria del kernel de malware**
    - `malfind`, `apihooks`, `yarascan`

72. **Análisis de la estructura de la memoria del kernel de rootkits**
    - `ssdt`, `callbacks`, `idt`

73. **Análisis de la estructura de la memoria del kernel de caché**
    - `cachedump`, `userassist`, `shellbags`

74. **Análisis de la estructura de la memoria del kernel de la red**
    - `netscan`, `connections`, `sockscan`

75. **Análisis de la estructura de la memoria del proceso de malware**
    - `malfind`, `apihooks`, `yarascan`

76. **Análisis de la estructura de la memoria del proceso de rootkits**
    - `ssdt`, `callbacks`, `idt`

77. **Análisis de la estructura de la memoria del proceso de caché**
    - `cachedump`, `userassist`, `shellbags`

78. **Análisis de la estructura de la memoria del proceso de la red**
    - `netscan`, `connections`, `sockscan`

79. **Análisis de la estructura de la memoria del sistema de archivos de malware**
    - `mftparser`, `filescan`, `moddump`

80. **Análisis de la estructura de la memoria del sistema de archivos de rootkits**
    - `ssdt`, `callbacks`, `idt`

81. **Análisis de la estructura de la memoria del sistema de archivos de caché**
    - `cachedump`, `userassist`, `shellbags`

82. **Análisis de la estructura de la memoria del sistema de archivos de la red**
    - `netscan`, `connections`, `sockscan`

83. **Análisis de la estructura de la memoria de red de malware**
    - `malfind`, `apihooks`, `yarascan`

84. **Análisis de la estructura de la memoria de red de rootkits**
    - `ssdt`, `callbacks`, `idt`

85. **Análisis de la estructura de la memoria de red de caché**
    - `cachedump`, `userassist`, `shellbags`

86. **Análisis de la estructura de la memoria de red del kernel**
    - `netscan`, `connections`, `sockscan`

87. **Análisis de la estructura de la memoria de red del proceso**
    - `netscan`, `connections`, `sockscan`

88. **Análisis de la estructura de la memoria de red del sistema de archivos**
    - `netscan`, `connections`, `sockscan`

89. **Análisis de la estructura de la memoria del registro de malware**
    - `malfind`, `apihooks`, `yarascan`

90. **Análisis de la estructura de la memoria del registro de rootkits**
    - `ssdt`, `callbacks`, `idt`

91. **Análisis de la estructura de la memoria del registro de caché**
    - `cachedump`, `userassist`, `shellbags`

92. **Análisis de la estructura de la memoria del registro de la red**
    - `netscan`, `connections`, `sockscan`

93. **Análisis de la estructura de la memoria virtual de malware**
    - `malfind`, `apihooks`, `yarascan`

94. **Análisis de la estructura de la memoria virtual de rootkits**
    - `ssdt`, `callbacks`, `idt`

95. **Análisis de la estructura de la memoria virtual de caché**
    - `cachedump`, `userassist`, `shellbags`

96. **Análisis de la estructura de la memoria virtual de la red**
    - `netscan`, `connections`, `sockscan`

97. **Análisis de la estructura de la memoria física de malware**
    - `malfind`, `apihooks`, `yarascan`

98. **Análisis de la estructura de la memoria física de rootkits**
    - `ssdt`, `callbacks`, `idt`

99. **Análisis de la estructura de la memoria física de caché**
    - `cachedump`, `userassist`, `shellbags`

100. **Análisis de la estructura de la memoria física de la red**
    - `netscan`, `connections`, `sockscan`
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

- **volatility -f <file> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <file> pslist**: Lista los procesos en ejecución.
- **volatility -f <file> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> psscan**: Escanea los procesos.
- **volatility -f <file> dlllist -p <pid>**: Lista las DLL cargadas por un proceso específico.
- **volatility -f <file> cmdscan**: Escanea los procesos en busca de comandos ejecutados.
- **volatility -f <file> filescan**: Escanea los descriptores de archivo.
- **volatility -f <file> netscan**: Escanea los sockets de red.
- **volatility -f <file> connections**: Muestra las conexiones de red.
- **volatility -f <file> consoles**: Lista las consolas interactivas.
- **volatility -f <file> hivelist**: Enumera los archivos de volcado del registro.
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro específica.
- **volatility -f <file> hashdump**: Extrae los hashes de contraseñas.
- **volatility -f <file> userassist**: Recupera las entradas de UserAssist.
- **volatility -f <file> malfind**: Encuentra procesos sospechosos.
- **volatility -f <file> apihooks**: Detecta ganchos de API.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> shimcache**: Recupera información de ShimCache.
- **volatility -f <file> getsids**: Obtiene los SID de los procesos.
- **volatility -f <file> modscan**: Escanea los módulos del kernel.
- **volatility -f <file> mutantscan**: Escanea los objetos de mutante.
- **volatility -f <file> yarascan**: Escanea la memoria en busca de patrones YARA.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos del espacio de memoria.
- **volatility -f <file> memdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> cmdline -p <pid>**: Muestra la línea de comandos de un proceso.
- **volatility -f <file> procdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> screenshot -p <pid> -D <output_directory>**: Captura una captura de pantalla de un proceso.
- **volatility -f <file> timeliner**: Crea una línea de tiempo de la actividad del sistema.
- **volatility -f <file> truecryptmaster**: Recupera la clave maestra de TrueCrypt.
- **volatility -f <file> truecryptpassphrase**: Recupera la frase de contraseña de TrueCrypt.
- **volatility -f <file> truecryptsummary**: Muestra un resumen de TrueCrypt.
- **volatility -f <file> windows**: Enumera los procesos de Windows.
- **volatility -f <file> wintree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> vadinfo -p <pid>**: Muestra información sobre el espacio de direcciones virtuales de un proceso.
- **volatility -f <file> vadtree -p <pid>**: Muestra el árbol de estructuras de direcciones virtuales de un proceso.
- **volatility -f <file> vadwalk -p <pid>**: Muestra las regiones de memoria de un proceso.
- **volatility -f <file> handles -p <pid>**: Muestra los descriptores de archivo de un proceso.
- **volatility -f <file> hivedump -o <offset> -s <size> -D <output_directory>**: Extrae un archivo de volcado de registro específico.
- **volatility -f <file> hivelist**: Enumera los archivos de volcado del registro.
- **volatility -f <file> hivescan**: Escanea los archivos de volcado del registro en busca de subclaves.
- **voljson**: Convierte la salida de Volatility en formato JSON.
- **volshell**: Inicia un shell interactivo de Volatility.
- **volshell -f <file>**: Inicia un shell interactivo de Volatility con un archivo de volcado de memoria cargado.
- **volatility -f <file> --profile=<profile> <command>**: Especifica un perfil de sistema para el análisis.
- **volatility -f <file> --plugins=<directory> <command>**: Carga plugins personalizados.
- **volatility -f <file> --output-file=<output_file> <command>**: Guarda la salida en un archivo.
- **volatility -f <file> --output=html <command>**: Guarda la salida en formato HTML.
- **volatility -f <file> --output=sqlite <command>**: Guarda la salida en una base de datos SQLite.
- **volatility -f <file> --output=json <command>**: Guarda la salida en formato JSON.
- **volatility -f <file> --output=transient=<directory> <command>**: Guarda la salida en un directorio temporal.
- **volatility -f <file> --cache <command>**: Habilita el almacenamiento en caché para acelerar el análisis.
- **volatility -f <file> --cache-directory=<directory> <command>**: Especifica un directorio para almacenar la caché.
- **volatility -f <file> --cache-size=<size> <command>**: Especifica el tamaño máximo de la caché.
- **volatility -f <file> --cache-path=<path> <command>**: Especifica una ruta para almacenar la caché.
- **volatility -f <file> --debug <command>**: Habilita la salida de depuración.
- **volatility -f <file> --verbose <command>**: Proporciona información detallada durante el análisis.
- **volatility -f <file> --conf-file=<file> <command>**: Especifica un archivo de configuración personalizado.
- **volatility -f <file> --tz=<timezone> <command>**: Especifica la zona horaria para mostrar las marcas de tiempo.
- **volatility -f <file> --dtb=<address> <command>**: Especifica la dirección de la tabla de traducción de direcciones.
- **volatility -f <file> --dtb=auto <command>**: Detecta automáticamente la dirección de la tabla de traducción de direcciones.
- **volatility -f <file> --dtb=<profile> <command>**: Utiliza la dirección de la tabla de traducción de direcciones del perfil especificado.
- **volatility -f <file> --kdbg=<address> <command>**: Especifica la dirección de la tabla de depuración del kernel.
- **volatility -f <file> --kpcr=<address> <command>**: Especifica la dirección del registro de control de procesador del kernel.
- **volatility -f <file> --profile=<profile> --output-file=<output_file> <command>**: Especifica un perfil de sistema y guarda la salida en un archivo.
- **volatility -f <file> --profile=<profile> --output=html <command>**: Especifica un perfil de sistema y guarda la salida en formato HTML.
- **volatility -f <file> --profile=<profile> --output=sqlite <command>**: Especifica un perfil de sistema y guarda la salida en una base de datos SQLite.
- **volatility -f <file> --profile=<profile> --output=json <command>**: Especifica un perfil de sistema y guarda la salida en formato JSON.
- **volatility -f <file> --profile=<profile> --output=transient=<directory> <command>**: Especifica un perfil de sistema y guarda la salida en un directorio temporal.

#### Perfiles de sistema compatibles con Volatility

- **WinXPSP2x86**: Windows XP SP2 (x86)
- **WinXPSP3x86**: Windows XP SP3 (x86)
- **Win7SP0x86**: Windows 7 SP0 (x86)
- **Win7SP1x86**: Windows 7 SP1 (x86)
- **Win7SP0x64**: Windows 7 SP0 (x64)
- **Win7SP1x64**: Windows 7 SP1 (x64)
- **Win2003SP0x86**: Windows Server 2003 SP0 (x86)
- **Win2003SP1x86**: Windows Server 2003 SP1 (x86)
- **Win2003SP2x86**: Windows Server 2003 SP2 (x86)
- **Win2003SP0x64**: Windows Server 2003 SP0 (x64)
- **Win2003SP1x64**: Windows Server 2003 SP1 (x64)
- **Win2003SP2x64**: Windows Server 2003 SP2 (x64)
- **Win2008SP1x86**: Windows Server 2008 SP1 (x86)
- **Win2008SP1x64**: Windows Server 2008 SP1 (x64)
- **Win2008SP2x86**: Windows Server 2008 SP2 (x86)
- **Win2008SP2x64**: Windows Server 2008 SP2 (x64)
- **WinVistaSP0x86**: Windows Vista SP0 (x86)
- **WinVistaSP1x86**: Windows Vista SP1 (x86)
- **WinVistaSP2x86**: Windows Vista SP2 (x86)
- **WinVistaSP0x64**: Windows Vista SP0 (x64)
- **WinVistaSP1x64**: Windows Vista SP1 (x64)
- **WinVistaSP2x64**: Windows Vista SP2 (x64)
- **Win8SP0x86**: Windows 8 SP0 (x86)
- **Win8SP0x64**: Windows 8 SP0 (x64)
- **Win81U1x64**: Windows 8.1 U1 (x64)
- **Win10x64_10586**: Windows 10 (x64) build 10586
- **Win10x64_14393**: Windows 10 (x64) build 14393
- **Win10x64_15063**: Windows 10 (x64) build 15063
- **Win10x64_16299**: Windows 10 (x64) build 16299
- **Win10x64_17134**: Windows 10 (x64) build 17134
- **Win10x64_17763**: Windows 10 (x64) build 17763
- **Win10x64_18362**: Windows 10 (x64) build 18362
- **Win10x64_18363**: Windows 10 (x64) build 18363
- **Win10x64_19041**: Windows 10 (x64) build 19041
- **Win10x64_19042**: Windows 10 (x64) build 19042
- **Win10x64_19043**: Windows 10 (x64) build 19043
- **Win10x64_19044**: Windows 10 (x64) build 19044
- **Win10x64_19041**: Windows 10 (x64) build 19041
- **Win10x64_19042**: Windows 10 (x64) build 19042
- **Win10x64_19043**: Windows 10 (x64) build 19043
- **Win10x64_19044**: Windows 10 (x64) build 19044
- **Win10x64_19041**: Windows 10 (x64) build 19041
- **Win10x64_19042**: Windows 10 (x64) build 19042
- **Win10x64_19043**: Windows 10 (x64) build 19043
- **Win10x64_19044**: Windows 10 (x64) build 19044
- **Win10x64_19041**: Windows 10 (x64) build 19041
- **Win10x64_19042**: Windows 10 (x64) build 19042
- **Win10x64_19043**: Windows 10 (x64) build 19043
- **Win10x64_19044**: Windows 10 (x64) build 19044
- **Win10x64_19041**: Windows 10 (x64) build 19041
- **Win10x64_19042**: Windows 10 (x64) build 19042
- **Win10x64_19043**: Windows 10 (x64) build 19043
- **Win10x64_19044**: Windows 10 (x64) build 19044
- **Win10x64_19041**: Windows 10 (x64) build 19041
- **Win10x64_19042**: Windows 10 (x64) build 19042
- **Win10x64_19043**: Windows 10 (x64) build 19043
- **Win10x64_19044**: Windows 10 (x64) build 19044
- **Win10x64_19041**: Windows 10 (x64) build 19041
- **Win10x64_19042**: Windows 10 (x64) build 19042
- **Win10x64_19043**: Windows 10 (x64) build 19043
- **Win10x64_19044**: Windows 10 (x64) build 19044
- **Win10x64_19041**: Windows 10 (x64) build 19041
- **Win10x64_19042**: Windows 10 (x64) build 19042
- **Win10x64_19043**: Windows 10 (x64) build 19043
- **Win10x64_19044**: Windows 10 (x64) build 19044
- **Win10x64_19041**: Windows 10 (x64) build 19041
- **Win10x64_19042**: Windows 10 (x64) build 19042
- **Win10x64_19043**: Windows 10 (x64) build 19043
- **Win10x64_19044**: Windows 10 (x64) build 19044
- **Win10x64_19041**: Windows 10 (x64) build 19041
- **Win10x64_19042**: Windows 10 (x64) build 19042
- **Win10x64_19043**: Windows 10 (x64) build 19043
- **Win10x64_19044**: Windows 10 (x64) build 19044
- **Win10x64_19041**: Windows 10 (x64) build 19041
- **Win10x64_19042**: Windows 10 (x64) build 19042
- **Win10x64_19043**: Windows 10 (x64) build 19043
- **Win10x64_19044**: Windows 10 (x64) build 19044
- **Win10x64_19041**: Windows 10 (x64) build 19041
- **Win10x64_19042**: Windows 10 (x64) build 19042
- **Win10x64_19043**: Windows 10 (x64) build 19043
- **Win10x64_19044**: Windows 10 (x64) build 19044
- **Win10x64_19041**: Windows 10 (x64) build 19041
- **Win10x64_19042**: Windows 10 (x64) build 19042
- **Win10x64_19043**: Windows 10 (x64) build 19043
- **Win10x64_19044**: Windows 10 (x64) build 19044
- **Win10x64_19041**: Windows 10 (x64) build 19041
- **Win10x64_19042**: Windows 10 (x64) build 19042
- **Win10x64_19043**: Windows 10 (x64) build 19043
- **Win10x64_19044**: Windows 10 (x64) build 19044
- **Win10x64_19041**: Windows 10 (x64) build 19041
- **Win10x64_19042**: Windows 10 (x64) build 19042
- **Win10x64_19043**: Windows 10 (x64) build 19043
- **Win10x64_19044**: Windows 10 (x64) build 19044
- **Win10x64_19041**: Windows 10 (x64) build 19041
- **Win10x64_19042**: Windows 10 (x64) build 19042
- **Win10x64_19043**: Windows 10 (x64) build 19043
- **Win10x64_19044**: Windows 10 (x64) build 19044
- **Win10x64_19041**: Windows 10 (x64) build 19041
- **Win10x64_19042**: Windows 10 (x64) build 19042
- **Win10x64_19043**: Windows 10 (x64) build 19043
- **Win10x64_19044**: Windows 10 (x
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

### Análisis de volcado de memoria

#### Comandos básicos

- **volatility -f <file> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <file> pslist**: Muestra la lista de procesos en el volcado de memoria.
- **volatility -f <file> pstree**: Muestra la estructura de árbol de procesos en el volcado de memoria.
- **volatility -f <file> psscan**: Escanea procesos a través del volcado de memoria.
- **volatility -f <file> dlllist -p <pid>**: Muestra las DLL cargadas por un proceso específico.
- **volatility -f <file> cmdscan**: Escanea la memoria en busca de cadenas de texto que parezcan comandos.
- **volatility -f <file> filescan**: Escanea la memoria en busca de estructuras de datos de archivos.
- **volatility -f <file> netscan**: Escanea la memoria en busca de artefactos de red.
- **volatility -f <file> connections**: Muestra las conexiones de red en el volcado de memoria.
- **volatility -f <file> consoles**: Muestra información sobre las consolas interactivas detectadas.
- **volatility -f <file> hivelist**: Enumera los registros del sistema en el volcado de memoria.
- **volatility -f <file> userassist**: Muestra las entradas de UserAssist en el volcado de memoria.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso en procesos.
- **volatility -f <file> apihooks**: Detecta ganchos de API en el volcado de memoria.
- **volatility -f <file> ldrmodules**: Enumera los módulos cargados en el espacio de usuario.
- **volatility -f <file> modscan**: Escanea la memoria en busca de módulos del kernel.
- **volatility -f <file> shimcache**: Muestra la información almacenada en la caché de Shim en el volcado de memoria.
- **volatility -f <file> getsids**: Enumera los SID de seguridad en el volcado de memoria.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos del volcado de memoria.
- **volatility -f <file> cmdline**: Muestra los argumentos de línea de comandos de procesos.
- **volatility -f <file> consoles**: Muestra información sobre las consolas interactivas detectadas.
- **volatility -f <file> hivelist**: Enumera los registros del sistema en el volcado de memoria.
- **volatility -f <file> userassist**: Muestra las entradas de UserAssist en el volcado de memoria.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso en procesos.
- **volatility -f <file> apihooks**: Detecta ganchos de API en el volcado de memoria.
- **volatility -f <file> ldrmodules**: Enumera los módulos cargados en el espacio de usuario.
- **volatility -f <file> modscan**: Escanea la memoria en busca de módulos del kernel.
- **volatility -f <file> shimcache**: Muestra la información almacenada en la caché de Shim en el volcado de memoria.
- **volatility -f <file> getsids**: Enumera los SID de seguridad en el volcado de memoria.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos del volcado de memoria.
- **volatility -f <file> cmdline**: Muestra los argumentos de línea de comandos de procesos.

#### Plugins adicionales

- **volatility -f <file> windows.lsadump.Lsadump**: Extrae las credenciales almacenadas en LSASS.
- **volatility -f <file> windows.registry.registryapi.RegistryApi**: Enumera las claves del registro.
- **volatility -f <file> windows.dumpcerts.DumpCerts**: Extrae certificados del sistema.
- **volatility -f <file> windows.hivelist.HiveList**: Enumera los registros del sistema.
- **volatility -f <file> windows.printkey.PrintKey -o <offset>**: Imprime una clave de registro específica.
- **volatility -f <file> windows.hashdump.Hashdump**: Extrae hashes de contraseñas almacenadas.
- **volatility -f <file> windows.filescan.FileScan**: Escanea la memoria en busca de estructuras de archivos.
- **volatility -f <file> windows.cmdscan.CmdScan**: Escanea la memoria en busca de comandos.
- **volatility -f <file> windows.netscan.NetScan**: Escanea la memoria en busca de artefactos de red.
- **volatility -f <file> windows.connections.Connections**: Muestra las conexiones de red.
- **volatility -f <file> windows.pslist.PsList**: Muestra la lista de procesos.
- **volatility -f <file> windows.pstree.PsTree**: Muestra la estructura de árbol de procesos.
- **volatility -f <file> windows.modules.Modules**: Enumera los módulos cargados.
- **volatility -f <file> windows.modscan.ModScan**: Escanea la memoria en busca de módulos.
- **volatility -f <file> windows.apihooks.ApiHooks**: Detecta ganchos de API.
- **volatility -f <file> windows.shimcache.ShimCache**: Muestra la información de la caché de Shim.
- **volatility -f <file> windows.getsids.GetSids**: Enumera los SID de seguridad.
- **volatility -f <file> windows.envars.Envars**: Muestra las variables de entorno.
- **volatility -f <file> windows.userassist.UserAssist**: Muestra las entradas de UserAssist.
- **volatility -f <file> windows.malfind.Malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <file> windows.apihooks.DetectApiHooks**: Detecta ganchos de API.
- **volatility -f <file> windows.ldrmodules.LdrModules**: Enumera los módulos cargados en el espacio de usuario.
- **volatility -f <file> windows.shimcache.ShimCache**: Muestra la información almacenada en la caché de Shim.
- **volatility -f <file> windows.getsids.GetSids**: Enumera los SID de seguridad.
- **volatility -f <file> windows.dumpfiles.DumpFiles -Q <address> -D <output_directory>**: Extrae archivos del volcado de memoria.
- **volatility -f <file> windows.cmdline.CmdLine**: Muestra los argumentos de línea de comandos de procesos.
- **volatility -f <file> windows.consoles.Consoles**: Muestra información sobre las consolas interactivas detectadas.
- **volatility -f <file> windows.hivelist.HiveList**: Enumera los registros del sistema en el volcado de memoria.
- **volatility -f <file> windows.userassist.UserAssist**: Muestra las entradas de UserAssist en el volcado de memoria.
- **volatility -f <file> windows.malfind.Malfind**: Encuentra inyecciones de código malicioso en procesos.
- **volatility -f <file> windows.apihooks.ApiHooks**: Detecta ganchos de API en el volcado de memoria.
- **volatility -f <file> windows.ldrmodules.LdrModules**: Enumera los módulos cargados en el espacio de usuario.
- **volatility -f <file> windows.modscan.ModScan**: Escanea la memoria en busca de módulos del kernel.
- **volatility -f <file> windows.shimcache.ShimCache**: Muestra la información almacenada en la caché de Shim en el volcado de memoria.
- **volatility -f <file> windows.getsids.GetSids**: Enumera los SID de seguridad en el volcado de memoria.
- **volatility -f <file> windows.dumpfiles.DumpFiles -Q <address> -D <output_directory>**: Extrae archivos del volcado de memoria.
- **volatility -f <file> windows.cmdline.CmdLine**: Muestra los argumentos de línea de comandos de procesos.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
### Bash

Es posible **leer desde la memoria el historial de bash**. También podrías volcar el archivo _.bash\_history_, pero si está deshabilitado, te alegrará saber que puedes usar este módulo de Volatility.
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% tab title="vol2" %} 

## Hoja de trucos de Volatility

### Análisis de volcado de memoria

#### Comandos básicos

- **volatility -f <file> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <file> pslist**: Lista los procesos en ejecución.
- **volatility -f <file> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> psscan**: Escanea los procesos.
- **volatility -f <file> dlllist -p <pid>**: Lista las DLL cargadas por un proceso.
- **volatility -f <file> cmdscan**: Busca comandos en la memoria.
- **volatility -f <file> consoles**: Muestra las consolas interactivas.
- **volatility -f <file> filescan**: Escanea los descriptores de archivo.
- **volatility -f <file> netscan**: Escanea los sockets de red.
- **volatility -f <file> connections**: Muestra las conexiones de red.
- **volatility -f <file> svcscan**: Escanea los servicios.
- **volatility -f <file> hivelist**: Lista los registros del sistema.
- **volatility -f <file> printkey -o <offset>**: Imprime una clave del registro.
- **volatility -f <file> cmdline**: Muestra los argumentos de línea de comandos.
- **volatility -f <file> malfind**: Encuentra procesos sospechosos.
- **volatility -f <file> apihooks**: Muestra los ganchos de API.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> modscan**: Escanea los módulos.
- **volatility -f <file> shimcache**: Analiza la caché de Shim.
- **volatility -f <file> getsids**: Obtiene los SID de los procesos.
- **volatility -f <file> getservicesids**: Obtiene los SID de los servicios.
- **volatility -f <file> yarascan**: Escanea la memoria en busca de patrones YARA.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos de memoria.
- **volatility -f <file> memdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memstrings -s <min_length>**: Encuentra cadenas en la memoria.
- **volatility -f <file> messagehooks**: Muestra los ganchos de mensajes.
- **volatility -f <file> mutantscan**: Escanea los objetos de mutante.
- **volatility -f <file> userassist**: Analiza las entradas de UserAssist.
- **volatility -f <file> vadinfo -o <offset>**: Muestra información sobre un área de memoria.
- **volatility -f <file> vadtree**: Muestra el árbol de áreas de memoria.
- **volatility -f <file> handles**: Muestra los descriptores de archivo y claves del registro abiertos.
- **volatility -f <file> hivelist**: Lista los registros del sistema.
- **volatility -f <file> hivescan**: Escanea los registros del sistema.
- **volatility -f <file> hivedump -o <offset> -s <size> -D <output_directory>**: Extrae un registro del sistema.
- **volatility -f <file> hashdump**: Extrae contraseñas hash.
- **volatility -f <file> userassist**: Analiza las entradas de UserAssist.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza la caché de Shim en el registro.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> shimcachereg**: Analiza
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
- **volatility -f <file> consoles**: Lista las consolas interactivas.
- **volatility -f <file> hivelist**: Lista los archivos de volcado del registro.
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro específica.
- **volatility -f <file> hashdump**: Extrae los hashes de contraseñas.
- **volatility -f <file> mimikatz**: Ejecuta Mimikatz en el volcado de memoria.
- **volatility -f <file> yarascan**: Escanea en busca de patrones Yara.
- **volatility -f <file> malfind**: Encuentra procesos sospechosos.
- **volatility -f <file> apihooks**: Muestra los ganchos de API.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> modscan**: Escanea los módulos.
- **volatility -f <file> getsids**: Obtiene los SID de los procesos.
- **volatility -f <file> getservicesids**: Obtiene los SID de los servicios.
- **volatility -f <file> shimcache**: Analiza la caché de Shim.
- **volatility -f <file> userassist**: Analiza las entradas de UserAssist.
- **volatility -f <file> cmdline**: Muestra los argumentos de línea de comandos de los procesos.
- **volatility -f <file> consoles -v**: Muestra información detallada de las consolas.
- **volatility -f <file> mftparser**: Analiza la tabla maestra de archivos.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos del espacio de direcciones.
- **volatility -f <file> dumpregistry -o <output_directory>**: Extrae el registro del sistema.
- **volatility -f <file> screenshot -D <output_directory>**: Captura pantallazos de las ventanas abiertas.
- **volatility -f <file> memdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap -p <pid>**: Muestra el mapeo de memoria de un proceso.
- **volatility -f <file> memdump --profile=<profile> -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico con un perfil específico.
- **volatility -f <file> memdump --profile=<profile> -p <pid> -b <base_address> -c <size> -D <output_directory>**: Crea un volcado de memoria de un proceso específico con un perfil específico y un tamaño específico.
- **volatility -f <file> memdump --profile=<profile> -p <pid> -b <base_address> -c <size> -f <format> -D <output_directory>**: Crea un volcado de memoria de un proceso específico con un perfil específico, un tamaño y formato específicos.
- **volatility -f <file> memdump --profile=<profile> -p <pid> -b <base_address> -c <size> -f <format> -t <type> -D <output_directory>**: Crea un volcado de memoria de un proceso específico con un perfil, tamaño, formato y tipo específicos.

#### Plugins de Volatility

- **volatility --plugins=<directory>**: Especifica un directorio de plugins personalizado.
- **volatility --info**: Muestra información sobre los plugins disponibles.
- **volatility --info <plugin>**: Muestra información detallada sobre un plugin específico.
- **volatility --output-file=<file>**: Guarda la salida en un archivo.
- **volatility --output=html**: Guarda la salida en formato HTML.
- **volatility --output=json**: Guarda la salida en formato JSON.
- **volatility --output=sqlite**: Guarda la salida en una base de datos SQLite.
- **volatility --profile=<profile>**: Especifica el perfil de memoria a utilizar.
- **volatility --profile=<profile> <plugin>**: Especifica el perfil de memoria para un plugin específico.
- **volatility --plugins=<directory> --profile=<profile> <plugin>**: Especifica un directorio de plugins y un perfil de memoria para un plugin específico.
- **volatility --conf-file=<file>**: Carga un archivo de configuración personalizado.
- **volatility --cache-directory=<directory>**: Especifica un directorio para almacenar la caché.
- **volatility --tz=<timezone>**: Especifica la zona horaria a utilizar.
- **volatility --dtb=<address>**: Especifica la dirección de la tabla de páginas del directorio.
- **volatility --debug**: Activa el modo de depuración.
- **volatility --verbose**: Activa el modo detallado.
- **volatility --quiet**: Desactiva la salida estándar.
- **volatility --help**: Muestra la ayuda y la lista de comandos disponibles.

{% endtab %}
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

#### Comandos básicos de Volatility

- **volatility -f <archivo> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: Lista los procesos en ejecución.
- **volatility -f <archivo> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <archivo> psscan**: Escanea los procesos.
- **volatility -f <archivo> dlllist -p <PID>**: Lista las DLL cargadas por un proceso específico.
- **volatility -f <archivo> cmdscan**: Escanea los procesos en busca de comandos ejecutados.
- **volatility -f <archivo> filescan**: Escanea los descriptores de archivos.
- **volatility -f <archivo> netscan**: Escanea los sockets de red.
- **volatility -f <archivo> connections**: Muestra las conexiones de red.
- **volatility -f <archivo> consoles**: Lista las consolas interactivas.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <archivo> apihooks**: Muestra los ganchos de API.
- **volatility -f <archivo> ldrmodules**: Lista los módulos cargados.
- **volatility -f <archivo> modscan**: Escanea los módulos.
- **volatility -f <archivo> shimcache**: Muestra la caché de Shim.
- **volatility -f <archivo> userassist**: Muestra las entradas de UserAssist.
- **volatility -f <archivo> hivelist**: Enumera las ubicaciones del Registro cargadas.
- **volatility -f <archivo> printkey -o <offset>**: Imprime una clave de Registro en un desplazamiento específico.
- **volatility -f <archivo> cmdline**: Muestra los argumentos de línea de comandos de los procesos.
- **volatility -f <archivo> consoles**: Lista las consolas interactivas.
- **volatility -f <archivo> getsids**: Enumera los SID de usuario.
- **volatility -f <archivo> hivescan**: Escanea las ubicaciones del Registro.
- **volatility -f <archivo> hashdump**: Extrae los hashes de contraseñas.
- **volatility -f <archivo> truecryptmaster**: Encuentra la clave maestra de TrueCrypt.
- **volatility -f <archivo> truecryptpassphrase**: Encuentra la frase de contraseña de TrueCrypt.
- **volatility -f <archivo> clipboard**: Muestra el contenido del portapapeles.
- **volatility -f <archivo> screenshot**: Captura una captura de pantalla de la máquina comprometida.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria de un proceso específico.
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
El **Registro de Arranque Principal (MBR)** juega un papel crucial en la gestión de las particiones lógicas de un medio de almacenamiento, que están estructuradas con diferentes [sistemas de archivos](https://es.wikipedia.org/wiki/Sistema_de_archivos). No solo contiene información de diseño de particiones, sino que también contiene código ejecutable que actúa como cargador de arranque. Este cargador de arranque inicia directamente el proceso de carga de la segunda etapa del sistema operativo (ver [cargador de arranque de segunda etapa](https://es.wikipedia.org/wiki/Cargador_de_arranque_de_segunda_etapa)) o trabaja en armonía con el [registro de arranque de volumen](https://es.wikipedia.org/wiki/Registro_de_arranque_de_volumen) (VBR) de cada partición. Para obtener un conocimiento más profundo, consulta la [página de Wikipedia del MBR](https://es.wikipedia.org/wiki/Registro_de_arranque_principal).

# Referencias
* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro clave para profesionales de la tecnología y ciberseguridad en todas las disciplinas.

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
