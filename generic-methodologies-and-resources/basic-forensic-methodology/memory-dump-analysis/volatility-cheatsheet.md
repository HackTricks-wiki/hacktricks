# Volatility - Hoja de trucos

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

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

Volatility tiene dos enfoques principales para los plugins, que a veces se reflejan en sus nombres. Los plugins "list" intentarán navegar a través de las estructuras del Kernel de Windows para recuperar información como procesos (localizar y recorrer la lista enlazada de estructuras `_EPROCESS` en la memoria), manijas del sistema operativo (localizar y enumerar la tabla de manijas, desreferenciar cualquier puntero encontrado, etc). Más o menos se comportan como lo haría la API de Windows si se solicita, por ejemplo, listar procesos.

Esto hace que los plugins "list" sean bastante rápidos, pero igual de vulnerables que la API de Windows a la manipulación por malware. Por ejemplo, si el malware utiliza DKOM para desvincular un proceso de la lista enlazada de `_EPROCESS`, no aparecerá en el Administrador de tareas ni en la lista de procesos.

Los plugins "scan", por otro lado, tomarán un enfoque similar a tallar la memoria en busca de cosas que podrían tener sentido al desreferenciarlas como estructuras específicas. `psscan`, por ejemplo, leerá la memoria e intentará crear objetos `_EPROCESS` a partir de ella (utiliza el escaneo de etiquetas de grupo, que busca cadenas de 4 bytes que indiquen la presencia de una estructura de interés). La ventaja es que puede desenterrar procesos que han salido, e incluso si el malware manipula la lista enlazada de `_EPROCESS`, el plugin seguirá encontrando la estructura en la memoria (ya que aún necesita existir para que el proceso se ejecute). La desventaja es que los plugins "scan" son un poco más lentos que los plugins "list", y a veces pueden dar falsos positivos (un proceso que salió hace mucho tiempo y tuvo partes de su estructura sobrescritas por otras operaciones).

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

A diferencia de imageinfo que simplemente proporciona sugerencias de perfil, **kdbgscan** está diseñado para identificar positivamente el perfil correcto y la dirección KDBG correcta (si hay varias). Este complemento escanea las firmas de KDBGHeader vinculadas a los perfiles de Volatility y aplica controles de integridad para reducir falsos positivos. La verbosidad de la salida y la cantidad de controles de integridad que se pueden realizar dependen de si Volatility puede encontrar un DTB, por lo que si ya conoce el perfil correcto (o si tiene una sugerencia de perfil de imageinfo), asegúrese de usarlo (de [aquí](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)).

Siempre eche un vistazo al **número de procesos que ha encontrado kdbgscan**. A veces imageinfo y kdbgscan pueden encontrar **más de un** perfil **adecuado**, pero solo el **válido tendrá algunos procesos relacionados** (Esto se debe a que para extraer procesos se necesita la dirección KDBG correcta).
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

El **bloque depurador del kernel** (llamado KdDebuggerDataBlock del tipo \_KDDEBUGGER\_DATA64, o **KDBG** por Volatility) es importante para muchas cosas que Volatility y los depuradores hacen. Por ejemplo, tiene una referencia al PsActiveProcessHead que es la cabecera de lista de todos los procesos necesaria para la lista de procesos.

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
- **Análisis de la caché de credenciales:** `volatility -f <archivo> --profile=<perfil> cachedump`
- **Análisis de la tabla de enrutamiento ARP:** `volatility -f <archivo> --profile=<perfil> arp`
- **Análisis de la caché de LSA:** `volatility -f <archivo> --profile=<perfil> lsadump`
- **Análisis de la caché de SAM:** `volatility -f <archivo> --profile=<perfil> samdump`
- **Análisis de la caché de seguridad:** `volatility -f <archivo> --profile=<perfil> security`
- **Análisis de la caché de software:** `volatility -f <archivo> --profile=<perfil> getsids`
- **Análisis de la caché de sistema:** `volatility -f <archivo> --profile=<perfil> getsids`
- **Análisis de la caché de tokens:** `volatility -f <archivo> --profile=<perfil> tokens`
- **Análisis de la caché de escritorio remoto:** `volatility -f <archivo> --profile=<perfil> rdpscan`
- **Análisis de la caché de VAD:** `volatility -f <archivo> --profile=<perfil> vadinfo`
- **Análisis de la caché de escritorio:** `volatility -f <archivo> --profile=<perfil> desktops`
- **Análisis de la caché de ventanas:** `volatility -f <archivo> --profile=<perfil> windows`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `volatility -f <archivo> --profile=<perfil> wintree`
- **Análisis de la caché de ventanas de escritorio:** `vol
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
## Volcado de Memoria

El volcado de memoria de un proceso **extraerá todo** del estado actual del proceso. El módulo **procdump** solo **extraerá** el **código**.
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
{% endtab %}

{% tab title="vol2" %}La siguiente es una hoja de trucos de Volatility que resume los comandos y opciones más comunes utilizados para el análisis de volcado de memoria:

### Comandos Básicos
- **imageinfo**: Muestra información básica sobre la imagen de memoria.
- **pslist**: Lista los procesos en ejecución.
- **pstree**: Muestra los procesos en forma de árbol.
- **psscan**: Escanea los procesos.
- **dlllist**: Lista las DLL cargadas por cada proceso.
- **handles**: Muestra los handles abiertos por cada proceso.
- **cmdline**: Muestra la línea de comandos de cada proceso.
- **filescan**: Escanea los file handles.
- **netscan**: Escanea las conexiones de red.
- **connections**: Muestra las conexiones de red.
- **sockets**: Muestra los sockets de red.
- **svcscan**: Escanea los servicios.
- **driverirp**: Muestra las IRP manejadas por los drivers.
- **modscan**: Escanea los módulos del kernel.
- **ssdt**: Muestra la Service Descriptor Table.
- **callbacks**: Muestra los callbacks del kernel.
- **gdt**: Muestra la Global Descriptor Table.
- **idt**: Muestra la Interrupt Descriptor Table.
- **devicetree**: Muestra el árbol de dispositivos.
- **privs**: Muestra los privilegios de cada proceso.
- **malfind**: Encuentra procesos sospechosos.
- **yarascan**: Escanea la memoria en busca de patrones YARA.
- **dumpfiles**: Extrae archivos del volcado de memoria.
- **dumpregistry**: Extrae el registro del sistema del volcado de memoria.
- **dlldump**: Extrae una DLL específica del volcado de memoria.
- **memmap**: Muestra el mapeo de memoria.
- **vadinfo**: Muestra información sobre los Virtual Address Descriptors.
- **vaddump**: Extrae un VAD específico.
- **vadtree**: Muestra los VADs en forma de árbol.
- **vadwalk**: Muestra las direcciones de memoria en un VAD.
- **apihooks**: Muestra los hooks de API.
- **ldrmodules**: Muestra los módulos cargados por el Loader.
- **atomscan**: Escanea los objetos atómicos.
- **atomtable**: Muestra la tabla de objetos atómicos.
- **deskscan**: Escanea los objetos de escritorio.
- **wndscan**: Escanea las ventanas.
- **thrdscan**: Escanea los hilos.
- **callbacks**: Muestra los callbacks del kernel.
- **gdt**: Muestra la Global Descriptor Table.
- **idt**: Muestra la Interrupt Descriptor Table.
- **devicetree**: Muestra el árbol de dispositivos.
- **privs**: Muestra los privilegios de cada proceso.
- **malfind**: Encuentra procesos sospechosos.
- **yarascan**: Escanea la memoria en busca de patrones YARA.
- **dumpfiles**: Extrae archivos del volcado de memoria.
- **dumpregistry**: Extrae el registro del sistema del volcado de memoria.
- **dlldump**: Extrae una DLL específica del volcado de memoria.
- **memmap**: Muestra el mapeo de memoria.
- **vadinfo**: Muestra información sobre los Virtual Address Descriptors.
- **vaddump**: Extrae un VAD específico.
- **vadtree**: Muestra los VADs en forma de árbol.
- **vadwalk**: Muestra las direcciones de memoria en un VAD.
- **apihooks**: Muestra los hooks de API.
- **ldrmodules**: Muestra los módulos cargados por el Loader.
- **atomscan**: Escanea los objetos atómicos.
- **atomtable**: Muestra la tabla de objetos atómicos.
- **deskscan**: Escanea los objetos de escritorio.
- **wndscan**: Escanea las ventanas.
- **thrdscan**: Escanea los hilos.

### Opciones Útiles
- **-f, --file**: Especifica el archivo de volcado de memoria a analizar.
- **-p, --pid**: Especifica el PID del proceso a analizar.
- **-D, --dump-dir**: Especifica el directorio donde se guardarán los archivos extraídos.
- **-h, --help**: Muestra la ayuda y la lista de comandos disponibles.

Estos son solo algunos de los comandos y opciones más utilizados en Volatility para el análisis de volcado de memoria. Consulta la documentación oficial para obtener más información y opciones avanzadas.{% endtab %}
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

#### Metodología básica de análisis de volcado de memoria

1. **Adquisición de memoria**
   - **Volatility**: `imageinfo`, `kdbgscan`, `memmap`, `malfind`, `apihooks`

2. **Análisis de procesos**
   - **Volatility**: `pslist`, `pstree`, `psscan`, `psxview`, `dlllist`

3. **Análisis de red**
   - **Volatility**: `connections`, `sockets`, `connscan`, `netscan`

4. **Análisis de registro**
   - **Volatility**: `hivelist`, `printkey`, `hashdump`, `userassist`

5. **Análisis de archivos**
   - **Volatility**: `filescan`, `fileinfo`, `mftparser`, `dumpfiles`

6. **Análisis de caché**
   - **Volatility**: `cachedump`, `shellbags`, `shimcache`, `mimikatz`

7. **Análisis de kernel**
   - **Volatility**: `modules`, `modscan`, `driverscan`, `callbacks`

8. **Análisis de rootkit**
   - **Volatility**: `ssdt`, `gdt`, `idt`, `dt`

9. **Análisis de malware**
   - **Volatility**: `malfind`, `apihooks`, `yarascan`, `impscan`

10. **Análisis de volcado completo**
    - **Volatility**: `imagecopy`, `hashdump`, `kdbgscan`, `memdump`

11. **Análisis de volcado diferencial**
    - **Volatility**: `memdmp`, `memmap`, `memdiff`, `memstrings`

12. **Análisis de volcado en vivo**
    - **Volatility**: `procdump`, `memdump`, `memmap`, `memstrings`

13. **Análisis de volcado en frío**
    - **Volatility**: `imagecopy`, `hashdump`, `kdbgscan`, `memdump`

14. **Análisis de volcado en caliente**
    - **Volatility**: `procdump`, `memdump`, `memmap`, `memstrings`

15. **Análisis de volcado en memoria física**
    - **Volatility**: `imagecopy`, `hashdump`, `kdbgscan`, `memdump`

16. **Análisis de volcado en memoria virtual**
    - **Volatility**: `procdump`, `memdump`, `memmap`, `memstrings`

17. **Análisis de volcado en memoria paginada**
    - **Volatility**: `imagecopy`, `hashdump`, `kdbgscan`, `memdump`

18. **Análisis de volcado en memoria swap**
    - **Volatility**: `procdump`, `memdump`, `memmap`, `memstrings`

19. **Análisis de volcado en memoria compartida**
    - **Volatility**: `imagecopy`, `hashdump`, `kdbgscan`, `memdump`

20. **Análisis de volcado en memoria distribuida**
    - **Volatility**: `procdump`, `memdump`, `memmap`, `memstrings`
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
### Línea de comandos

¿Se ejecutó algo sospechoso?
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
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
- **Análisis de objetos de sincronización:** `volatility -f <archivo> --profile=<perfil> syncscan`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
- **Análisis de objetos de sincronización de notificación:** `volatility -f <archivo> --profile=<perfil> synctimeline`
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
Las instrucciones introducidas en cmd.exe son procesadas por **conhost.exe** (csrss.exe antes de Windows 7). Por lo tanto, incluso si un atacante logró **finalizar el cmd.exe** antes de que obtuviéramos un **volcado de memoria**, todavía hay una buena posibilidad de **recuperar el historial** de la sesión de línea de comandos desde la **memoria de conhost.exe**. Si encuentras algo **extraño** (usando los módulos de la consola), intenta **volcar** la **memoria** del proceso asociado a **conhost.exe** y **buscar** cadenas dentro de ella para extraer las líneas de comandos.

### Entorno

Obtén las variables de entorno de cada proceso en ejecución. Podría haber valores interesantes.
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
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
- **volatility -f <archivo> yarascan**: Escanea el volcado de memoria en busca de patrones YARA.
- **volatility -f <archivo> consoles**: Muestra las consolas interactivas encontradas en el volcado de memoria.
- **volatility -f <archivo> hivelist**: Enumera los archivos de volcado de registro en memoria.
- **volatility -f <archivo> printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <archivo> userassist**: Extrae y decodifica las entradas de UserAssist.
- **volatility -f <archivo> shimcache**: Extrae la información de la caché de Shim.
- **volatility -f <archivo> ldrmodules**: Enumera los módulos cargados en el espacio de usuario.
- **volatility -f <archivo> modscan**: Escanea módulos en el volcado de memoria.
- **volatility -f <archivo> getsids**: Enumera los SID de usuario en el volcado de memoria.
- **volatility -f <archivo> hivescan**: Escanea los archivos de volcado de registro en busca de subclaves y valores.
- **volatility -f <archivo> apihooks**: Detecta ganchos de API en el volcado de memoria.
- **volatility -f <archivo> callbacks**: Enumera los callbacks de registro en el volcado de memoria.
- **volatility -f <archivo> driverirp**: Enumera las IRP manejadas por los controladores en el volcado de memoria.
- **volatility -f <archivo> ssdt**: Enumera los descriptores de tabla de servicios del sistema en el volcado de memoria.
- **volatility -f <archivo> devicetree**: Enumera el árbol de dispositivos en el volcado de memoria.
- **volatility -f <archivo> drivermodule**: Enumera los módulos de controlador en el volcado de memoria.
- **volatility -f <archivo> handles**: Enumera los descriptores de archivo en el volcado de memoria.
- **volatility -f <archivo> mutantscan**: Escanea objetos de mutante en el volcado de memoria.
- **volatility -f <archivo> envars**: Enumera las variables de entorno en el volcado de memoria.
- **volatility -f <archivo> atomscan**: Escanea tablas de átomos en el volcado de memoria.
- **volatility -f <archivo> gdt**: Enumera la tabla de descriptores globales en el volcado de memoria.
- **volatility -f <archivo> idt**: Enumera la tabla de descriptores de interrupciones en el volcado de memoria.
- **volatility -f <archivo> threads**: Enumera los hilos en el volcado de memoria.
- **volatility -f <archivo> thrdscan**: Escanea estructuras de hilo en el volcado de memoria.
- **volatility -f <archivo> vadinfo -o <offset>**: Muestra información sobre un área de memoria virtual específica.
- **volatility -f <archivo> vadtree -o <offset>**: Muestra un árbol de áreas de memoria virtual.
- **volatility -f <archivo> vadwalk -o <offset>**: Realiza un seguimiento de las áreas de memoria virtual.
- **volatility -f <archivo> memmap**: Muestra un mapa de memoria del volcado.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio> -r <rango>**: Volcado de memoria de un rango de direcciones de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memstrings -Q <cantidad>**: Extrae las primeras N cadenas ASCII del volcado de memoria.
- **volatility -f <archivo> memstrings -E**: Extrae todas las cadenas ASCII del volcado de memoria.
- **volatility -f <archivo> memdump**: Volcado de todo el contenido del volcado de memoria.
- **volatility -f <archivo> memdump --dump-dir <directorio>**: Volcado de todo el contenido del volcado de memoria en un directorio específico.

#### Plugins adicionales de Volatility

- **volatility -f <archivo> malfind**: Encuentra inyecciones de código en procesos.
- **volatility -f <archivo> yarascan**: Escanea el volcado de memoria en busca de patrones YARA.
- **volatility -f <archivo> apihooks**: Detecta ganchos de API en el volcado de memoria.
- **volatility -f <archivo> shimcache**: Extrae la información de la caché de Shim.
- **volatility -f <archivo> userassist**: Extrae y decodifica las entradas de UserAssist.
- **volatility -f <archivo> ldrmodules**: Enumera los módulos cargados en el espacio de usuario.
- **volatility -f <archivo> modscan**: Escanea módulos en el volcado de memoria.
- **volatility -f <archivo> getsids**: Enumera los SID de usuario en el volcado de memoria.
- **volatility -f <archivo> hivescan**: Escanea los archivos de volcado de registro en busca de subclaves y valores.
- **volatility -f <archivo> callbacks**: Enumera los callbacks de registro en el volcado de memoria.
- **volatility -f <archivo> driverirp**: Enumera las IRP manejadas por los controladores en el volcado de memoria.
- **volatility -f <archivo> ssdt**: Enumera los descriptores de tabla de servicios del sistema en el volcado de memoria.
- **volatility -f <archivo> devicetree**: Enumera el árbol de dispositivos en el volcado de memoria.
- **volatility -f <archivo> drivermodule**: Enumera los módulos de controlador en el volcado de memoria.
- **volatility -f <archivo> mutantscan**: Escanea objetos de mutante en el volcado de memoria.
- **volatility -f <archivo> atomscan**: Escanea tablas de átomos en el volcado de memoria.
- **volatility -f <archivo> gdt**: Enumera la tabla de descriptores globales en el volcado de memoria.
- **volatility -f <archivo> idt**: Enumera la tabla de descriptores de interrupciones en el volcado de memoria.
- **volatility -f <archivo> threads**: Enumera los hilos en el volcado de memoria.
- **volatility -f <archivo> thrdscan**: Escanea estructuras de hilo en el volcado de memoria.
- **volatility -f <archivo> vadinfo -o <offset>**: Muestra información sobre un área de memoria virtual específica.
- **volatility -f <archivo> vadtree -o <offset>**: Muestra un árbol de áreas de memoria virtual.
- **volatility -f <archivo> vadwalk -o <offset>**: Realiza un seguimiento de las áreas de memoria virtual.
- **volatility -f <archivo> memmap**: Muestra un mapa de memoria del volcado.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio> -r <rango>**: Volcado de memoria de un rango de direcciones de un proceso específico.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso específico.
- **volatility -f <archivo> memstrings -Q <cantidad>**: Extrae las primeras N cadenas ASCII del volcado de memoria.
- **volatility -f <archivo> memstrings -E**: Extrae todas las cadenas ASCII del volcado de memoria.
- **volatility -f <archivo> memdump**: Volcado de todo el contenido del volcado de memoria.
- **volatility -f <archivo> memdump --dump-dir <directorio>**: Volcado de todo el contenido del volcado de memoria en un directorio específico.
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

- **volatility -f <file> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <file> pslist**: Lista los procesos en ejecución.
- **volatility -f <file> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> psscan**: Escanea los procesos.
- **volatility -f <file> dlllist -p <pid>**: Lista las DLL cargadas por un proceso.
- **volatility -f <file> cmdscan**: Escanea los procesos en busca de comandos de consola.
- **volatility -f <file> filescan**: Escanea los descriptores de archivo.
- **volatility -f <file> netscan**: Escanea los sockets de red.
- **volatility -f <file> connections**: Muestra las conexiones de red.
- **volatility -f <file> consoles**: Lista las consolas interactivas.
- **volatility -f <file> hivelist**: Enumera los archivos de volcado del registro.
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> hashdump**: Extrae los hashes de contraseñas.
- **volatility -f <file> userassist**: Muestra las entradas de UserAssist.
- **volatility -f <file> shimcache**: Muestra la información de ShimCache.
- **volatility -f <file> malfind**: Encuentra procesos sospechosos.
- **volatility -f <file> apihooks**: Muestra los ganchos de API.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> modscan**: Escanea los módulos.
- **volatility -f <file> getsids**: Obtiene los SID de los procesos.
- **volatility -f <file> getservicesids**: Obtiene los SID de los servicios.
- **volatility -f <file> envars**: Muestra las variables de entorno de los procesos.
- **volatility -f <file> cmdline**: Muestra los argumentos de línea de comandos de los procesos.
- **volatility -f <file> consoles -v**: Muestra información detallada de las consolas.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos del espacio de memoria.
- **volatility -f <file> memdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump --dump-dir <output_directory>**: Crea un volcado de memoria completo.
- **volatility -f <file> procdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> procdump -p <pid> --dump-dir <output_directory>**: Crea un volcado de memoria de un proceso específico en un directorio específico.

### Plugins adicionales

- **apihooks**: Muestra los ganchos de API.
- **malfind**: Encuentra procesos sospechosos.
- **malsysproc**: Encuentra procesos del sistema sospechosos.
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
- **malfind**: Encuentra procesos sospechos
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

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Volatility

- **Volatility** es un marco de trabajo de análisis de memoria.
- **Volatility** es un proyecto de código abierto.
- **Volatility** es compatible con la mayoría de los sistemas operativos.
- **Volatility** es ampliamente utilizado en la comunidad de análisis forense.

#### Uso básico

- `volatility -f <archivo_memoria> <comando>`
- Ejemplo: `volatility -f memdump.mem imageinfo`

#### Comandos comunes

- `imageinfo`: muestra información básica sobre la imagen de memoria.
- `pslist`: lista los procesos en la imagen de memoria.
- `pstree`: muestra los procesos en forma de árbol.
- `dlllist`: lista las DLL cargadas en los procesos.
- `cmdline`: muestra los argumentos de línea de comandos de los procesos.
- `filescan`: escanea en busca de objetos de archivo en la memoria.
- `netscan`: muestra información de red.
- `connections`: muestra las conexiones de red.
- `malfind`: encuentra posibles inyecciones de malware en procesos.
- `dump`: permite volcar procesos específicos de la memoria.

#### Recursos adicionales

- Documentación oficial: [Volatility Docs](https://github.com/volatilityfoundation/volatility/wiki)
- Perfiles de memoria: [Volatility Profiles](https://github.com/volatilityfoundation/profiles)
- Comunidad: [Volatility Community](https://volatility-slack.herokuapp.com/)

#### Ejemplo de uso

```bash
volatility -f memdump.mem imageinfo
volatility -f memdump.mem pslist
volatility -f memdump.mem cmdline -p <PID>
```
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

- **volatility -f <archivo> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: Muestra una lista de procesos en el volcado de memoria.
- **volatility -f <archivo> pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **volatility -f <archivo> psscan**: Escanea procesos a través del volcado de memoria.
- **volatility -f <archivo> dlllist -p <PID>**: Muestra las DLL cargadas por un proceso específico.
- **volatility -f <archivo> cmdscan**: Escanea los procesos en busca de comandos de consola.
- **volatility -f <archivo> consoles**: Muestra información sobre las consolas interactivas.
- **volatility -f <archivo> filescan**: Escanea en busca de objetos de archivo en el volcado de memoria.
- **volatility -f <archivo> netscan**: Escanea en busca de artefactos de red.
- **volatility -f <archivo> connections**: Muestra información sobre conexiones de red.
- **volatility -f <archivo> timeliner**: Crea una línea de tiempo de actividad del sistema.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código malicioso en procesos.
- **volatility -f <archivo> apihooks**: Muestra información sobre ganchos de API.
- **volatility -f <archivo> ldrmodules**: Muestra información sobre módulos cargados en procesos.
- **volatility -f <archivo> modscan**: Escanea en busca de módulos del kernel.
- **volatility -f <archivo> ssdt**: Muestra la Service Descriptor Table del kernel.
- **volatility -f <archivo> callbacks**: Muestra información sobre los callbacks del kernel.
- **volatility -f <archivo> driverirp**: Muestra información sobre los controladores y las IRP.
- **volatility -f <archivo> devicetree**: Muestra información sobre el árbol de dispositivos.
- **volatility -f <archivo> hivelist**: Enumera los archivos de volcado del registro.
- **volatility -f <archivo> printkey -o <offset>**: Muestra una clave de registro en un desplazamiento específico.
- **volatility -f <archivo> cmdline**: Muestra la línea de comandos de un proceso.
- **volatility -f <archivo> consoles -p <PID>**: Muestra las consolas asociadas con un proceso.
- **volatility -f <archivo> screenshot -D <directorio> -p <PID>**: Captura una captura de pantalla de la ventana de un proceso.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria para un proceso específico.
- **volatility -f <archivo> memmap -p <PID>**: Muestra el mapeo de memoria de un proceso.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria para un proceso específico.
- **volatility -f <archivo> memmap -p <PID>**: Muestra el mapeo de memoria de un proceso.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria para un proceso específico.
- **volatility -f <archivo> memmap -p <PID>**: Muestra el mapeo de memoria de un proceso.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria para un proceso específico.
- **volatility -f <archivo> memmap -p <PID>**: Muestra el mapeo de memoria de un proceso.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria para un proceso específico.
- **volatility -f <archivo> memmap -p <PID>**: Muestra el mapeo de memoria de un proceso.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria para un proceso específico.
- **volatility -f <archivo> memmap -p <PID>**: Muestra el mapeo de memoria de un proceso.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria para un proceso específico.
- **volatility -f <archivo> memmap -p <PID>**: Muestra el mapeo de memoria de un proceso.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria para un proceso específico.
- **volatility -f <archivo> memmap -p <PID>**: Muestra el mapeo de memoria de un proceso.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Crea un volcado de memoria para un proceso específico.
- **volatility -f <archivo> memmap -p <PID>**: Muestra el mapeo de memoria de un proceso.
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
{% endtab %}
{% endtabs %}

### Bibliotecas de enlace dinámico

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
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
- `pstree`: muestra una representación en árbol de los procesos en el volcado de memoria.
- `dlllist`: muestra una lista de DLL cargadas en los procesos.
- `cmdline`: muestra la línea de comandos de los procesos.
- `filescan`: escanea en busca de objetos de archivo en la memoria.
- `netscan`: escanea en busca de artefactos de red en la memoria.

#### Plugins

- **Volatility** tiene una amplia gama de plugins para realizar análisis forense de memoria.
- Los plugins de **Volatility** pueden extraer información sobre procesos, redes, registros, etc.

#### Recursos adicionales

- Documentación oficial de **Volatility**: [https://github.com/volatilityfoundation/volatility/wiki](https://github.com/volatilityfoundation/volatility/wiki)
- Lista de plugins de **Volatility**: [https://github.com/volatilityfoundation/volatility/wiki/Command-Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)

#### Ejemplo de uso

- `volatility -f memdump.mem imageinfo`
- `volatility -f memdump.mem pslist`
- `volatility -f memdump.mem cmdline`

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
- **volatility -f <archivo> psscan**: Escanea los procesos en busca de colas ocultas.
- **volatility -f <archivo> dlllist -p <PID>**: Muestra las DLL cargadas por un proceso específico.
- **volatility -f <archivo> cmdscan**: Escanea la memoria en busca de comandos de consola.
- **volatility -f <archivo> filescan**: Escanea la memoria en busca de objetos de archivo.
- **volatility -f <archivo> netscan**: Escanea la memoria en busca de artefactos de red.
- **volatility -f <archivo> connections**: Muestra las conexiones de red.
- **volatility -f <archivo> consoles**: Muestra las consolas interactivas abiertas por procesos.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código malicioso en procesos.
- **volatility -f <archivo> yarascan**: Escanea la memoria en busca de patrones con Yara.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> cmdline -p <PID>**: Muestra el comando utilizado para iniciar un proceso.
- **volatility -f <archivo> hivelist**: Enumera los registros del sistema cargados en memoria.
- **volatility -f <archivo> printkey -o <offset>**: Imprime una clave del registro a partir de una dirección de memoria.
- **volatility -f <archivo> userassist**: Recupera información sobre programas ejecutados por el usuario.
- **volatility -f <archivo> shimcache**: Extrae información de la caché de compatibilidad de aplicaciones.
- **volatility -f <archivo> ldrmodules**: Enumera los módulos cargados en un proceso.
- **volatility -f <archivo> modscan**: Escanea la memoria en busca de módulos del kernel.
- **volatility -f <archivo> getsids**: Enumera los identificadores de seguridad (SIDs) de los procesos.
- **volatility -f <archivo> getservicesids**: Enumera los SIDs de los servicios.
- **volatility -f <archivo> apihooks**: Detecta ganchos de API en procesos.
- **volatility -f <archivo> callbacks**: Enumera los callbacks del kernel.
- **volatility -f <archivo> driverirp**: Enumera los controladores y las direcciones IRP.
- **volatility -f <archivo> devicetree**: Enumera el árbol de dispositivos.
- **volatility -f <archivo> ssdt**: Enumera las entradas de la tabla de descriptores de servicios del sistema (SSDT).
- **volatility -f <archivo> idt**: Enumera la tabla de descriptores de interrupciones (IDT).
- **volvolatility -f <archivo> gdt**: Enumera la tabla de descriptores globales (GDT).
- **volatility -f <archivo> threads**: Enumera los hilos en un proceso.
- **volatility -f <archivo> handles -p <PID>**: Enumera los descriptores de archivo y claves del registro abiertos por un proceso.
- **volatility -f <archivo> mutantscan**: Escanea la memoria en busca de objetos de mutante.
- **volatility -f <archivo> envars -p <PID>**: Enumera las variables de entorno de un proceso.
- **volatility -f <archivo> atomscan**: Escanea la memoria en busca de objetos de átomos.
- **volatility -f <archivo> gac -p <PID>**: Enumera los objetos de acceso genérico (GAC) de un proceso.
- **volatility -f <archivo> svcscan**: Escanea la memoria en busca de registros de servicios.
- **volatility -f <archivo> qxl -p <PID>**: Enumera los objetos de cola de mensajes (QXL) de un proceso.
- **volatility -f <archivo> wndscan**: Escanea la memoria en busca de objetos de ventana.
- **volatility -f <archivo> thrdscan**: Escanea la memoria en busca de objetos de hilo.
- **volatility -f <archivo> drivermodule**: Enumera los módulos de controlador.
- **volatility -f <archivo> timers**: Enumera los temporizadores en un sistema.
- **volatility -f <archivo> callbacks -p <PID>**: Enumera los callbacks de un proceso.
- **volatility -f <archivo> gditimers**: Enumera los temporizadores de GDI.
- **volatility -f <archivo> deskscan**: Escanea la memoria en busca de objetos de escritorio.
- **volatility -f <archivo> deskpins**: Enumera los objetos de anclaje de escritorio.
- **volatility -f <archivo> vadinfo -p <PID>**: Muestra información sobre regiones de memoria virtuales de un proceso.
- **volatility -f <archivo> vadtree -p <PID>**: Muestra un árbol de regiones de memoria virtuales de un proceso.
- **volatility -f <archivo> dlldump -p <PID> -D <destino>**: Extrae una DLL de un proceso.
- **volatility -f <archivo> dlldump -b <dirección> -D <destino>**: Extrae una DLL de memoria.
- **volatility -f <archivo> memmap**: Muestra un mapa de memoria.
- **volatility -f <archivo> memdump -p <PID> -D <destino>**: Volcado de memoria de un proceso.
- **volatility -f <archivo> memdump -b <dirección> -l <tamaño> -D <destino>**: Volcado de memoria de una dirección específica.
- **volatility -f <archivo> memstrings -p <PID>**: Busca cadenas ASCII en la memoria de un proceso.
- **volatility -f <archivo> memstrings -Q <dirección>**: Busca cadenas ASCII en una dirección de memoria.
- **volatility -f <archivo> memmap -p <PID>**: Muestra un mapa de memoria de un proceso.
- **volatility -f <archivo> memdump -p <PID> -D <destino>**: Volcado de memoria de un proceso.
- **volatility -f <archivo> memdump -b <dirección> -l <tamaño> -D <destino>**: Volcado de memoria de una dirección específica.
- **volatility -f <archivo> memstrings -p <PID>**: Busca cadenas ASCII en la memoria de un proceso.
- **volatility -f <archivo> memstrings -Q <dirección>**: Busca cadenas ASCII en una dirección de memoria.

#### Plugins de Volatility

- **apihooks**: Detecta ganchos de API en procesos.
- **atoms**: Enumera los átomos del sistema.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
- **atomscan**: Escanea la memoria en busca de objetos de átomos.
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
- **volatility -f <file> shimcache**: Recupera la información de ShimCache.
- **volatility -f <file> malfind**: Encuentra procesos sospechosos.
- **volatility -f <file> apihooks**: Muestra los ganchos de API.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> modscan**: Escanea los módulos cargados.
- **volatility -f <file> getsids**: Enumera los SID de seguridad.
- **volatility -f <file> getservicesids**: Enumera los SID de servicios.
- **volatility -f <file> svcscan**: Escanea los servicios.
- **volatility -f <file> driverirp**: Enumera los IRP manejadores de controladores.
- **volatility -f <file> callbacks**: Enumera los callbacks del kernel.
- **volatility -f <file> ssdt**: Enumera la tabla de descriptores de servicios del sistema.
- **volatility -f <file> devicetree**: Enumera el árbol de dispositivos.
- **volatility -f <file> filescan**: Escanea los descriptores de archivo.
- **volatility -f <file> handles**: Enumera los handles del sistema.
- **volatility -f <file> mutantscan**: Escanea los objetos mutantes.
- **volatility -f <file> yarascan**: Escanea la memoria en busca de patrones YARA.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos del espacio de memoria.
- **volatility -f <file> memdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap -p <pid>**: Muestra el mapeo de memoria de un proceso.
- **volatility -f <file> memdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap -p <pid>**: Muestra el mapeo de memoria de un proceso.

#### Plugins de Volatility

- **pslist**: Lista los procesos en ejecución.
- **pstree**: Muestra los procesos en forma de árbol.
- **psscan**: Escanea los procesos.
- **dlllist**: Lista las DLL cargadas.
- **cmdscan**: Escanea los procesos en busca de comandos ejecutados.
- **filescan**: Escanea los descriptores de archivo.
- **netscan**: Escanea los sockets de red.
- **connections**: Muestra las conexiones de red.
- **consoles**: Lista las consolas interactivas.
- **hivelist**: Enumera los archivos de volcado del registro.
- **hashdump**: Extrae los hashes de contraseñas.
- **userassist**: Recupera las entradas de UserAssist.
- **shimcache**: Recupera la información de ShimCache.
- **malfind**: Encuentra procesos sospechosos.
- **apihooks**: Muestra los ganchos de API.
- **ldrmodules**: Lista los módulos cargados.
- **modscan**: Escanea los módulos cargados.
- **getsids**: Enumera los SID de seguridad.
- **getservicesids**: Enumera los SID de servicios.
- **svcscan**: Escanea los servicios.
- **driverirp**: Enumera los IRP manejadores de controladores.
- **callbacks**: Enumera los callbacks del kernel.
- **ssdt**: Enumera la tabla de descriptores de servicios del sistema.
- **devicetree**: Enumera el árbol de dispositivos.
- **filescan**: Escanea los descriptores de archivo.
- **handles**: Enumera los handles del sistema.
- **mutantscan**: Escanea los objetos mutantes.
- **yarascan**: Escanea la memoria en busca de patrones YARA.
- **dumpfiles**: Extrae archivos del espacio de memoria.
- **memdump**: Crea un volcado de memoria de un proceso específico.
- **memmap**: Muestra el mapeo de memoria de un proceso.
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
### UserAssist

Los sistemas **Windows** mantienen un conjunto de **claves** en la base de datos del registro (**claves UserAssist**) para hacer un seguimiento de los programas que se ejecutan. El número de ejecuciones y la fecha y hora de la última ejecución están disponibles en estas **claves**.
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% endtab %}

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Comandos básicos de Volatility

- **volatility -f <archivo_memoria> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo_memoria> pslist**: Lista los procesos en ejecución.
- **volatility -f <archivo_memoria> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <archivo_memoria> psscan**: Escanea los procesos.
- **volatility -f <archivo_memoria> dlllist -p <PID>**: Lista las DLL cargadas por un proceso específico.
- **volatility -f <archivo_memoria> cmdscan**: Escanea los procesos en busca de comandos ejecutados.
- **volatility -f <archivo_memoria> filescan**: Escanea los descriptores de archivos.
- **volatility -f <archivo_memoria> netscan**: Escanea los sockets de red.
- **volatility -f <archivo_memoria> connections**: Muestra las conexiones de red.
- **volatility -f <archivo_memoria> consoles**: Lista las consolas interactivas.
- **volatility -f <archivo_memoria> hivelist**: Enumera los registros del sistema.
- **volatility -f <archivo_memoria> userassist**: Extrae las entradas de UserAssist.
- **volatility -f <archivo_memoria> shimcache**: Extrae la información de ShimCache.
- **volatility -f <archivo_memoria> mftparser**: Analiza el MFT.
- **volatility -f <archivo_memoria> dumpfiles -Q <dirección> -D <directorio_destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo_memoria> cmdline**: Muestra los comandos ejecutados por los procesos.
- **volatility -f <archivo_memoria> consoles**: Lista las consolas interactivas.
- **volatility -f <archivo_memoria> hivelist**: Enumera los registros del sistema.
- **volatility -f <archivo_memoria> userassist**: Extrae las entradas de UserAssist.
- **volatility -f <archivo_memoria> shimcache**: Extrae la información de ShimCache.
- **volatility -f <archivo_memoria> mftparser**: Analiza el MFT.
- **volatility -f <archivo_memoria> dumpfiles -Q <dirección> -D <directorio_destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo_memoria> cmdline**: Muestra los comandos ejecutados por los procesos.
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

{% tab title="vol2" %} 

## Hoja de trucos de Volatility

### Comandos básicos

- **volatility -f <file> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <file> pslist**: Lista los procesos en ejecución.
- **volatility -f <file> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> psscan**: Escanea los procesos.
- **volatility -f <file> dlllist -p <pid>**: Lista las DLL cargadas por un proceso.
- **volatility -f <file> cmdline -p <pid>**: Muestra el comando utilizado para ejecutar un proceso.
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
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> hashdump**: Muestra las contraseñas almacenadas en memoria.
- **volatility -f <file> truecryptmaster**: Encuentra la clave maestra de TrueCrypt.
- **volatility -f <file> clipboard**: Muestra el contenido del portapapeles.
- **volatility -f <file> screenshot**: Toma una captura de pantalla de la pantalla de la víctima.

### Plugins adicionales

- **apihooks**: Muestra los ganchos de API.
- **malfind**: Encuentra inyecciones de código malicioso.
- **truecryptmaster**: Encuentra la clave maestra de TrueCrypt.
- **clipboard**: Muestra el contenido del portapapeles.
- **screenshot**: Toma una captura de pantalla de la pantalla de la víctima.

{% endtab %}
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
- **volatility -f <archivo> pslist**: Muestra una lista de procesos en el volcado de memoria.
- **volatility -f <archivo> pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **volatility -f <archivo> psscan**: Escanea procesos a través del volcado de memoria.
- **volatility -f <archivo> dlllist -p <PID>**: Muestra una lista de DLL cargadas por un proceso específico.
- **volatility -f <archivo> cmdline -p <PID>**: Muestra el comando utilizado para ejecutar un proceso específico.
- **volatility -f <archivo> filescan**: Escanea descriptores de archivos en el volcado de memoria.
- **volatility -f <archivo> netscan**: Escanea conexiones de red en el volcado de memoria.
- **volatility -f <archivo> connections**: Muestra conexiones de red en el volcado de memoria.
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

{% tab title="vol2" %} 

## Hoja de trucos de Volatility

### Comandos básicos

- **volatility -f <file> imageinfo**: Escanea el volcado de memoria para obtener información básica.
- **volatility -f <file> pslist**: Enumera los procesos en ejecución.
- **volatility -f <file> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> psscan**: Escanea los procesos ocultos.
- **volatility -f <file> dlllist -p <pid>**: Lista las DLL cargadas por un proceso.
- **volatility -f <file> cmdline -p <pid>**: Muestra el comando utilizado para ejecutar un proceso.
- **volatility -f <file> filescan**: Escanea los descriptores de archivo.
- **volatility -f <file> netscan**: Muestra las conexiones de red.
- **volatility -f <file> connections**: Enumera las conexiones de red.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <file> yarascan**: Escanea la memoria en busca de patrones con Yara.
- **volatility -f <file> consoles**: Enumera las consolas interactivas.
- **volatility -f <file> hivelist**: Enumera los archivos de volcado del registro.
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> hashdump**: Extrae las contraseñas hash.
- **volatility -f <file> userassist**: Enumera las entradas de UserAssist.
- **volatility -f <file> shimcache**: Enumera las entradas de ShimCache.
- **volatility -f <file> ldrmodules**: Enumera los módulos cargados.
- **volatility -f <file> modscan**: Escanea los módulos cargados.
- **volatility -f <file> getsids**: Enumera los SID de los procesos.
- **volatility -f <file> getservicesids**: Enumera los SID de los servicios.
- **volatility -f <file> apihooks**: Enumera los ganchos de API.
- **volatility -f <file> callbacks**: Enumera los callbacks del kernel.
- **volatility -f <file> driverirp**: Enumera las IRP de los controladores.
- **volatility -f <file> ssdt**: Enumera la Service Descriptor Table.
- **volatility -f <file> gdt**: Enumera la Global Descriptor Table.
- **volatility -f <file> idt**: Enumera la Interrupt Descriptor Table.
- **volatility -f <file> threads**: Enumera los hilos.
- **volatility -f <file> mutantscan**: Escanea los objetos de mutante.
- **volatility -f <file> mutantscan -s**: Escanea los objetos de mutante compartidos.
- **volatility -f <file> envars**: Enumera las variables de entorno.
- **volatility -f <file> consoles -p <pid>**: Muestra las consolas asociadas a un proceso.
- **volatility -f <file> dumpfiles -Q <dir> -D <out_dir>**: Extrae archivos del volcado de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memdump -p <pid> -D <out_dir>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file>
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
### Obtener un valor

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{% endtab %}

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Volatility es una herramienta de análisis de memoria que es utilizada en la investigación forense digital para extraer información de los volcados de memoria adquiridos. A continuación se presenta una hoja de trucos con comandos comunes de Volatility:

---

#### Comandos básicos

- **volatility -f <archivo> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: Lista los procesos en ejecución.
- **volatility -f <archivo> psscan**: Escanea todos los procesos activos en la memoria.
- **volatility -f <archivo> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <archivo> dlllist -p <PID>**: Lista las DLL cargadas por un proceso específico.
- **volatility -f <archivo> cmdline -p <PID>**: Muestra el comando utilizado para ejecutar un proceso.
- **volatility -f <archivo> filescan**: Escanea los descriptores de archivo en memoria.
- **volatility -f <archivo> netscan**: Muestra las conexiones de red.
- **volatility -f <archivo> connections**: Muestra las conexiones de red en forma detallada.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código malicioso en procesos.
- **volatility -f <archivo> yarascan**: Escanea la memoria en busca de patrones utilizando reglas YARA.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos de memoria.
- **volatility -f <archivo> memdump -p <PID> -D <destino>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <archivo> hivelist**: Enumera los archivos de volcado de registro en memoria.
- **volatility -f <archivo> printkey -o <offset>**: Muestra el contenido de una clave de registro.
- **volatility -f <archivo> userassist**: Muestra las entradas de UserAssist del Registro de Windows.
- **volatility -f <archivo> shimcache**: Muestra la información almacenada en la caché de compatibilidad de aplicaciones.

---

#### Plugins adicionales

- **volatility -f <archivo> <nombre_del_plugin>**: Ejecuta un plugin específico de Volatility.

---

Estos son solo algunos de los comandos y plugins disponibles en Volatility. La herramienta es extremadamente versátil y puede ser utilizada para una amplia gama de análisis forenses en volcados de memoria. Se recomienda explorar más a fondo la documentación oficial de Volatility para aprovechar al máximo sus capacidades.

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

#### Análisis de volcado de memoria

- **Escaneo de procesos:** `volatility -f <archivo> --profile=<perfil> pslist`
- **Análisis de DLLs cargadas:** `volatility -f <archivo> --profile=<perfil> dlllist -p <PID>`
- **Análisis de puertos y conexiones:** `volatility -f <archivo> --profile=<perfil> connscan`
- **Análisis de registros de red:** `volatility -f <archivo> --profile=<perfil> netscan`
- **Análisis de caché de DNS:** `volatility -f <archivo> --profile=<perfil> dnscache`
- **Análisis de conexiones de red:** `volatility -f <archivo> --profile=<perfil> connections`
- **Análisis de registros de eventos:** `volatility -f <archivo> --profile=<perfil> evnets`
- **Análisis de registros de registro:** `volatility -f <archivo> --profile=<perfil> printkey -K <Registro>`
- **Análisis de procesos y módulos:** `volatility -f <archivo> --profile=<perfil> psscan`
- **Análisis de colas de eventos:** `volatility -f <archivo> --profile=<perfil> handles`
- **Análisis de tareas programadas:** `volatility -f <archivo> --profile=<perfil> getsids`
- **Análisis de tareas programadas:** `volatility -f <archivo> --profile=<perfil> getsids`
- **Análisis de tareas programadas:** `volatility -f <archivo> --profile=<perfil> getsids`
- **Análisis de tareas programadas:** `volatility -f <archivo> --profile=<perfil> getsids`
- **Análisis de tareas programadas:** `volatility -f <archivo> --profile=<perfil> getsids`
- **Análisis de tareas programadas:** `volatility -f <archivo> --profile=<perfil> getsids`
- **Análisis de tareas programadas:** `volatility -f <archivo> --profile=<perfil> getsids`
- **Análisis de tareas programadas:** `volatility -f <archivo> --profile=<perfil> getsids`
- **Análisis de tareas programadas:** `volatility -f <archivo> --profile=<perfil> getsids`
- **Análisis de tareas programadas:** `volatility -f <archivo> --profile=<perfil> getsids`
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
- **volatility -f <file> userassist**: Recupera las entradas de UserAssist.
- **volatility -f <file> malfind**: Encuentra procesos sospechosos.
- **volatility -f <file> apihooks**: Muestra los ganchos de API.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> modscan**: Escanea los módulos.
- **volatility -f <file> shimcache**: Recupera la caché de Shim.
- **volatility -f <file> getsids**: Enumera los SID de usuario.
- **volatility -f <file> getservicesids**: Enumera los SID de servicio.
- **volatility -f <file> svcscan**: Escanea los servicios.
- **volatility -f <file> driverirp**: Enumera los IRP de controlador.
- **volatility -f <file> ssdt**: Enumera la tabla de descriptores de servicios del sistema.
- **volatility -f <file> callbacks**: Enumera los callbacks del kernel.
- **volatility -f <file> mutantscan**: Escanea los objetos de mutante.
- **volatility -f <file> yarascan**: Escanea la memoria en busca de patrones YARA.
- **volatility -f <file> memmap**: Muestra un mapa de memoria.
- **volatility -f <file> memdump -p <pid> -D <output_directory>**: Volcado de memoria de un proceso específico.
- **volatility -f <file> memdump -p <pid> -D <output_directory> -r <range>**: Volcado de memoria de un proceso en un rango específico.
- **volatility -f <file> memdump -p <pid> -D <output_directory> -R <pid_range>**: Volcado de memoria de varios procesos en un rango específico.
- **volatility -f <file> memstrings -p <pid>**: Extrae cadenas de texto de un proceso específico.
- **volatility -f <file> memstrings -s -o <offset>**: Extrae cadenas de texto de un desplazamiento específico.
- **volatility -f <file> memstrings -E**: Extrae todas las cadenas de texto de la memoria.
- **volatility -f <file> memdump**: Volcado de toda la memoria.
- **volatility -f <file> memdump --dump-dir <output_directory>**: Volcado de toda la memoria en un directorio específico.

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
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra procesos sospechosos.
- **malfind**: Encuentra
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
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro específica.
- **volatility -f <file> hashdump**: Extrae los hashes de contraseñas.
- **volatility -f <file> userassist**: Muestra las entradas de UserAssist.
- **volatility -f <file> malfind**: Encuentra procesos sospechosos.
- **volatility -f <file> apihooks**: Muestra los ganchos de API.
- **volatility -f <file> shimcache**: Muestra la caché de Shim.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> modscan**: Escanea los módulos cargados.
- **volatility -f <file> getsids**: Obtiene los SID de los procesos.
- **volatility -f <file> getservicesids**: Obtiene los SID de los servicios.
- **volatility -f <file> envars**: Muestra las variables de entorno de los procesos.
- **volatility -f <file> cmdline**: Muestra los argumentos de línea de comandos de los procesos.
- **volatility -f <file> consoles**: Muestra las consolas interactivas.
- **volatility -f <file> dumpfiles -Q <pid> -D <output_directory>**: Extrae archivos del espacio de memoria de un proceso.
- **volatility -f <file> procdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memstrings**: Encuentra cadenas ASCII en el espacio de memoria.
- **volatility -f <file> malfind**: Encuentra procesos sospechosos.
- **volatility -f <file> yarascan -Y "<rule>"**: Escanea la memoria en busca de patrones con YARA.
- **volatility -f <file> mftparser**: Analiza la tabla maestra de archivos.
- **volatility -f <file> shimcachemem**: Analiza la caché de Shim en la memoria.
- **volatility -f <file> dumpregistry -o <output_directory>**: Crea un volcado del registro.
- **volatility -f <file> dumpcerts -D <output_directory>**: Extrae certificados.
- **volatility -f <file> dumpfiles -Q <pid> -D <output_directory>**: Extrae archivos del espacio de memoria de un proceso.
- **volatility -f <file> dumpregistry -o <output_directory>**: Crea un volcado del registro.
- **volatility -f <file> dumpcerts -D <output_directory>**: Extrae certificados.
- **volatility -f <file> dumpfiles -Q <pid> -D <output_directory>**: Extrae archivos del espacio de memoria de un proceso.
- **volatility -f <file> dumpregistry -o <output_directory>**: Crea un volcado del registro.
- **volatility -f <file> dumpcerts -D <output_directory>**: Extrae certificados.

### Plugins adicionales

- **apihooks**: Muestra los ganchos de API.
- **malfind**: Encuentra procesos sospechosos.
- **mftparser**: Analiza la tabla maestra de archivos.
- **shimcachemem**: Analiza la caché de Shim en la memoria.
- **yarascan**: Escanea la memoria en busca de patrones con YARA.

### Ejemplos de uso

- **volatility -f memdump.mem memmap**: Muestra el mapeo de memoria del volcado de memoria "memdump.mem".
- **volatility -f memdump.mem memstrings**: Encuentra cadenas ASCII en el espacio de memoria del volcado "memdump.mem".
- **volatility -f memdump.mem malfind**: Encuentra procesos sospechosos en el volcado de memoria "memdump.mem".

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

El sistema de archivos NTFS contiene un archivo llamado la _tabla maestra de archivos_, o MFT. Existe al menos una entrada en el MFT para cada archivo en un volumen del sistema de archivos NTFS, incluido el MFT en sí. **Toda la información sobre un archivo, incluido su tamaño, marcas de tiempo, permisos y contenido de datos**, se almacena en las entradas del MFT o en espacio fuera del MFT que es descrito por las entradas del MFT. Desde [aquí](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### Claves/Certificados SSL
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% endtab %}

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Comandos básicos de Volatility

- **volatility -f <file> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <file> pslist**: Lista los procesos en ejecución.
- **volatility -f <file> pstree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> psscan**: Escanea los procesos.
- **volatility -f <file> dlllist -p <pid>**: Lista las DLL cargadas por un proceso.
- **volatility -f <file> cmdline -p <pid>**: Muestra el comando utilizado para ejecutar un proceso.
- **volatility -f <file> filescan**: Escanea los descriptores de archivo.
- **volatility -f <file> netscan**: Escanea los sockets de red.
- **volatility -f <file> connections**: Muestra las conexiones de red.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <file> apihooks**: Muestra los ganchos de API.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> consoles**: Muestra las consolas interactivas.
- **volatility -f <file> getsids**: Obtiene los SID de los procesos.
- **volatility -f <file> hivelist**: Enumera los archivos de volcado del registro.
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> userassist**: Analiza las entradas de UserAssist.
- **volatility -f <file> shimcache**: Analiza la caché de Shim.
- **volatility -f <file> lsa_secrets**: Extrae secretos de LSA.
- **volatility -f <file> hashdump**: Extrae contraseñas hash.
- **volatility -f <file> truecryptmaster**: Encuentra la clave maestra de TrueCrypt.
- **volatility -f <file> truecryptpassphrase**: Encuentra la frase de contraseña de TrueCrypt.
- **volatility -f <file> bitlocker**: Encuentra las claves de recuperación de BitLocker.
- **volatility -f <file> dumpcerts**: Extrae certificados.
- **volatility -f <file> dumpfiles -Q <string>**: Busca y extrae archivos que contienen una cadena específica.
- **volatility -f <file> memdump -p <pid> -D <output_directory>**: Crea un volcado de memoria para un proceso específico.
- **volatility -f <file> memdump -p <pid> -D <output_directory> -u <username>**: Crea un volcado de memoria para un proceso específico y un usuario específico.
- **volatility -f <file> memdump --profile=<profile> -p <pid> -D <output_directory>**: Crea un volcado de memoria para un proceso específico con un perfil específico.
- **volatility -f <file> memdump --profile=<profile> -p <pid> -D <output_directory> -u <username>**: Crea un volcado de memoria para un proceso específico con un perfil específico y un usuario específico.

#### Plugins adicionales de Volatility

- **volatility -f <file> windows.lsadump.Lsadump**: Extrae secretos de LSA.
- **volatility -f <file> windows.hashdump.Hashdump**: Extrae contraseñas hash.
- **volatility -f <file> windows.pslist.PsList**: Lista los procesos en ejecución.
- **volatility -f <file> windows.pstree.PsTree**: Muestra los procesos en forma de árbol.
- **volatility -f <file> windows.netscan.NetScan**: Escanea los sockets de red.
- **volatility -f <file> windows.cmdline.CmdLine**: Muestra el comando utilizado para ejecutar un proceso.
- **volatility -f <file> windows.filescan.FileScan**: Escanea los descriptores de archivo.
- **volatility -f <file> windows.connections.Connections**: Muestra las conexiones de red.
- **volatility -f <file> windows.apihooks.ApiHooks**: Muestra los ganchos de API.
- **volatility -f <file> windows.printkey.PrintKey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <file> windows.userassist.UserAssist**: Analiza las entradas de UserAssist.
- **volatility -f <file> windows.shimcache.ShimCache**: Analiza la caché de Shim.
- **volatility -f <file> windows.truecryptmaster.TrueCryptMaster**: Encuentra la clave maestra de TrueCrypt.
- **volatility -f <file> windows.truecryptpassphrase.TrueCryptPassphrase**: Encuentra la frase de contraseña de TrueCrypt.
- **volatility -f <file> windows.bitlocker.BitLocker**: Encuentra las claves de recuperación de BitLocker.
- **volatility -f <file> windows.dumpcerts.DumpCerts**: Extrae certificados.
- **volatility -f <file> windows.dumpfiles.DumpFiles -Q <string>**: Busca y extrae archivos que contienen una cadena específica.
- **volatility -f <file> windows.memdump.MemDump -p <pid> -D <output_directory>**: Crea un volcado de memoria para un proceso específico.
- **volatility -f <file> windows.memdump.MemDump -p <pid> -D <output_directory> -u <username>**: Crea un volcado de memoria para un proceso específico y un usuario específico.
- **volatility -f <file> windows.memdump.MemDump --profile=<profile> -p <pid> -D <output_directory>**: Crea un volcado de memoria para un proceso específico con un perfil específico.
- **volatility -f <file> windows.memdump.MemDump --profile=<profile> -p <pid> -D <output_directory> -u <username>**: Crea un volcado de memoria para un proceso específico con un perfil específico y un usuario específico.

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

{% tab title="vol2" %}### Hoja de trucos de Volatility

#### Comandos básicos de Volatility

- **volatility -f <archivo> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: Muestra una lista de procesos en el volcado de memoria.
- **volatility -f <archivo> pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **volatility -f <archivo> psscan**: Escanea procesos a través del volcado de memoria.
- **volatility -f <archivo> dlllist -p <PID>**: Muestra una lista de DLL cargadas por un proceso específico.
- **volatility -f <archivo> cmdline -p <PID>**: Muestra el comando utilizado para ejecutar un proceso específico.
- **volatility -f <archivo> filescan**: Escanea en busca de objetos de archivo en el volcado de memoria.
- **volatility -f <archivo> netscan**: Escanea en busca de artefactos de red en el volcado de memoria.
- **volatility -f <archivo> connections**: Muestra conexiones de red en el volcado de memoria.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código malicioso en procesos.
- **volatility -f <archivo> yarascan**: Escanea en busca de patrones YARA en el volcado de memoria.
- **volatility -f <archivo> dumpfiles -Q <dirección> -D <destino>**: Extrae archivos del volcado de memoria.
- **volatility -f <archivo> memdump -p <PID> -D <destino>**: Crea un volcado de memoria para un proceso específico.
- **volatility -f <archivo> linux_bash**: Recupera comandos de Bash eliminados de la memoria.
- **volatility -f <archivo> linux_netstat**: Muestra información de netstat en sistemas Linux.
- **volatility -f <archivo> linux_lsmod**: Muestra información sobre módulos del kernel en sistemas Linux.

#### Plugins adicionales de Volatility

- **volatility -f <archivo> --profile=<perfil> <nombre_del_plugin>**: Ejecuta un plugin específico en el volcado de memoria.
- **volatility -f <archivo> --profile=<perfil> --output-file=<salida> <nombre_del_plugin>**: Guarda la salida de un plugin en un archivo.
- **volatility -f <archivo> --profile=<perfil> --output=dot --output-file=<salida> pstree**: Genera un gráfico de árbol de procesos en formato DOT.
- **volatility -f <archivo> --profile=<perfil> --output=html --output-file=<salida> pstree**: Genera un gráfico de árbol de procesos en formato HTML.
- **volatility -f <archivo> --profile=<perfil> --output=sqlite --output-file=<salida> pstree**: Guarda la salida en una base de datos SQLite.
- **volatility -f <archivo> --profile=<perfil> --output=json --output-file=<salida> pstree**: Guarda la salida en formato JSON.
- **volatility -f <archivo> --profile=<perfil> --output=plist --output-file=<salida> pstree**: Guarda la salida en formato de lista de propiedades.

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

{% tab title="vol2" %}Volatility Hoja de trucos

### Volatility Comandos Básicos

- **volatility -f dump.mem imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f dump.mem pslist**: Muestra una lista de procesos en el volcado de memoria.
- **volatility -f dump.mem pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **volatility -f dump.mem psscan**: Escanea el volcado de memoria en busca de procesos.
- **volatility -f dump.mem dlllist -p PID**: Muestra una lista de DLL cargadas en un proceso específico.
- **volatility -f dump.mem cmdline -p PID**: Muestra el comando utilizado para ejecutar un proceso específico.
- **volatility -f dump.mem filescan**: Escanea el volcado de memoria en busca de archivos.
- **volatility -f dump.mem netscan**: Escanea el volcado de memoria en busca de conexiones de red.
- **volatility -f dump.mem connections**: Muestra las conexiones de red en el volcado de memoria.
- **volatility -f dump.mem malfind**: Encuentra inyecciones de código malicioso en el volcado de memoria.
- **volatility -f dump.mem cmdline**: Muestra los comandos utilizados para ejecutar procesos en el volcado de memoria.
- **volatility -f dump.mem consoles**: Muestra las consolas interactivas abiertas en el volcado de memoria.
- **volatility -f dump.mem hivelist**: Enumera los archivos de registro presentes en el volcado de memoria.
- **volatility -f dump.mem printkey -o hiveoffset -K key**: Imprime el contenido de una clave de registro específica.
- **volatility -f dump.mem userassist**: Extrae y decodifica las entradas de UserAssist del registro.
- **volatility -f dump.mem shimcache**: Extrae y decodifica la información de ShimCache del registro.
- **volatility -f dump.mem ldrmodules**: Enumera los módulos cargados en el espacio de usuario.
- **volatility -f dump.mem modscan**: Escanea el volcado de memoria en busca de módulos.
- **volatility -f dump.mem getsids**: Enumera los SID de usuario presentes en el volcado de memoria.
- **volatility -f dump.mem hivescan**: Escanea el volcado de memoria en busca de archivos de registro.
- **volatility -f dump.mem apihooks**: Enumera los ganchos de API en el volcado de memoria.
- **volatility -f dump.mem callbacks**: Enumera los callbacks de registro en el volcado de memoria.
- **volatility -f dump.mem driverirp**: Enumera las IRP manejadas por los controladores en el volcado de memoria.
- **volatility -f dump.mem svcscan**: Escanea el volcado de memoria en busca de servicios.
- **volatility -f dump.mem mutantscan**: Escanea el volcado de memoria en busca de objetos de mutante.
- **volatility -f dump.mem yarascan -Y 'rule'**: Escanea el volcado de memoria en busca de patrones YARA.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcjsonado de memoria.
- **volatility -f dump.mem memdump -p PID -D outputdir**: Crea un volcado de memoria para un proceso específico.
- **volatility -f dump.mem memmap -p PID**: Muestra el mapeo de memoria de un proceso específico.
- **volatility -f dump.mem malfind -p PID**: Encuentra inyecciones de código malicioso en un proceso específico.
- **volatility -f dump.mem mftparser -o offset**: Analiza el archivo de tabla maestra (MFT) en el volcado de memoria.
- **volatility -f dump.mem shimcachemem -o offset**: Extrae y decodifica la información de ShimCache de un archivo específico en el volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **voltability -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts -o hiveoffset -D outputdir**: Extrae certificados del volcado de memoria.
- **volatility -f dump.mem dumpfiles -Q addressrange -D outputdir**: Extrae archivos del volcado de memoria.
- **volatility -f dump.mem dumpregistry -o hiveoffset -D outputdir**: Extrae un archivo de registro específico del volcado de memoria.
- **volatility -f dump.mem dumpcerts
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

#### Comandos básicos de Volatility

- **volatility -f <archivo> imageinfo**: Muestra información básica sobre el volcado de memoria.
- **volatility -f <archivo> pslist**: Muestra una lista de procesos en el volcado de memoria.
- **volatility -f <archivo> pstree**: Muestra un árbol de procesos en el volcado de memoria.
- **volatility -f <archivo> psscan**: Escanea procesos a través del volcado de memoria.
- **volatility -f <archivo> dlllist -p <PID>**: Muestra las DLL cargadas por un proceso específico.
- **volatility -f <archivo> cmdscan**: Escanea los procesos en busca de comandos de consola.
- **volatility -f <archivo> filescan**: Escanea en busca de objetos de archivo en el volcado de memoria.
- **volatility -f <archivo> netscan**: Escanea en busca de artefactos de red en el volcado de memoria.
- **volatility -f <archivo> connections**: Muestra las conexiones de red en el volcado de memoria.
- **volatility -f <archivo> malfind**: Encuentra inyecciones de código malicioso en procesos.
- **volatility -f <archivo> yarascan**: Escanea en busca de patrones YARA en el volcado de memoria.
- **volatility -f <archivo> cmdline**: Muestra los argumentos de línea de comandos de procesos.
- **volatility -f <archivo> consoles**: Muestra las consolas interactivas detectadas.
- **volatility -f <archivo> hivelist**: Enumera los registros del sistema en el volcado de memoria.
- **volatility -f <archivo> printkey -o <offset>**: Imprime una clave de registro en un desplazamiento específico.
- **volatility -f <archivo> userassist**: Recupera entradas de UserAssist del Registro.
- **volatility -f <archivo> shimcache**: Recupera entradas de ShimCache del Registro.
- **volatility -f <archivo> ldrmodules**: Enumera los módulos cargados en el espacio de usuario.
- **volatility -f <archivo> modscan**: Escanea en busca de módulos en el volcado de memoria.
- **volatility -f <archivo> getsids**: Enumera los SIDs de los procesos.
- **volatility -f <archivo> getservicesids**: Enumera los SIDs de los servicios.
- **volatility -f <archivo> svcscan**: Escanea en busca de servicios en el volcado de memoria.
- **volatility -f <archivo> driverirp**: Enumera los controladores y las IRP asociadas.
- **volatility -f <archivo> devicetree**: Enumera el árbol de dispositivos.
- **volatility -f <archivo> callbacks**: Enumera las rutinas de devolución de llamada.
- **volatility -f <archivo> mutantscan**: Escanea en busca de objetos de mutante en el volcado de memoria.
- **volatility -f <archivo> threads**: Enumera los hilos de un proceso.
- **volatility -f <archivo> handles**: Enumera los descriptores de archivo y claves del Registro abiertos.
- **volatility -f <archivo> vadinfo -o <offset>**: Muestra información sobre un área de memoria específica.
- **volatility -f <archivo> vadtree -o <offset>**: Muestra un árbol de áreas de memoria.
- **volatility -f <archivo> memmap**: Muestra un mapa de memoria.
- **volatility -f <archivo> memdump -p <PID> -D <directorio>**: Volcado de memoria de un proceso específico.
- **volatility -f <archivo> memdump -p <PID> -D <directorio> -r <rango>**: Volcado de memoria de un rango de direcciones de un proceso.
- **volatility -f <archivo> memstrings -p <PID>**: Extrae cadenas ASCII de un proceso.
- **volatility -f <archivo> memstrings -Q <cantidad>**: Extrae las primeras N cadenas ASCII del volcado de memoria.
- **volatility -f <archivo> memstrings -E**: Extrae todas las cadenas ASCII del volcado de memoria.
- **volatility -f <archivo> memdump**: Volcado de todo el contenido del volcado de memoria.
- **volatility -f <archivo> linux_bash**: Recupera comandos Bash eliminados.
- **volatility -f <archivo> linux_netstat**: Muestra conexiones de red en sistemas Linux.
- **volatility -f <archivo> linux_pslist**: Muestra procesos en sistemas Linux.
- **volatility -f <archivo> linux_psaux**: Muestra procesos con detalles adicionales en sistemas Linux.
- **volatility -f <archivo> linux_lsmod**: Muestra módulos cargados en sistemas Linux.
- **volatility -f <archivo> linux_ifconfig**: Muestra información de configuración de red en sistemas Linux.
- **volatility -f <archivo> linux_check_afinfo**: Enumera las estructuras de socket en sistemas Linux.
- **volatility -f <archivo> linux_route**: Muestra la tabla de enrutamiento en sistemas Linux.
- **volatility -f <archivo> linux_ifconfig**: Muestra información de configuración de red en sistemas Linux.
- **volatility -f <archivo> linux_check_afinfo**: Enumera las estructuras de socket en sistemas Linux.
- **volatility -f <archivo> linux_route**: Muestra la tabla de enrutamiento en sistemas Linux.
- **volatility -f <archivo> linux_check_creds**: Enumera las credenciales en sistemas Linux.
- **volatility -f <archivo> linux_check_fop**: Enumera las operaciones de archivo en sistemas Linux.
- **volatility -f <archivo> linux_check_idt**: Enumera las entradas de la tabla de descriptores de interrupciones en sistemas Linux.
- **volatility -f <archivo> linux_check_syscall**: Enumera las llamadas al sistema en sistemas Linux.
- **volatility -f <archivo> linux_check_syscalltbl**: Enumera la tabla de llamadas al sistema en sistemas Linux.
- **volatility -f <archivo> linux_check_tty**: Enumera las estructuras de terminal en sistemas Linux.
- **volatility -f <archivo> linux_check_creds**: Enumera las credenciales en sistemas Linux.
- **volatility -f <archivo> linux_check_fop**: Enumera las operaciones de archivo en sistemas Linux.
- **volatility -f <archivo> linux_check_idt**: Enumera las entradas de la tabla de descriptores de interrupciones en sistemas Linux.
- **volatility -f <archivo> linux_check_syscall**: Enumera las llamadas al sistema en sistemas Linux.
- **volatility -f <archivo> linux_check_syscalltbl**: Enumera la tabla de llamadas al sistema en sistemas Linux.
- **volatility -f <archivo> linux_check_tty**: Enumera las estructuras de terminal en sistemas Linux.

#### Plugins de Volatility

- **volatility --plugins=<directorio>**: Especifica un directorio de complementos personalizados.
- **volatility --info**: Muestra información sobre todos los complementos disponibles.
- **volatility --info=<nombre_del_plugin>**: Muestra información sobre un complemento específico.
- **volatility --output-file=<archivo>**: Guarda la salida en un archivo.
- **volatility --profile=<perfil>**: Especifica el perfil de sistema para el volcado de memoria.
- **volatility --location=<ruta>**: Especifica la ruta de la memoria volátil.
- **volatility --cache-directory=<directorio>**: Especifica un directorio para almacenar en caché los perfiles.
- **volatility --tz=<zona_horaria>**: Especifica la zona horaria para mostrar las marcas de tiempo.
- **volatility --debug**: Muestra mensajes de depuración.
- **volatility --verbosity=<nivel>**: Especifica el nivel de verbosidad de la salida.
- **volatility --conf-file=<archivo>**: Especifica un archivo de configuración personalizado.
- **volatility --plugins=<directorio>**: Especifica un directorio de complementos personalizados.
- **volatility --info**: Muestra información sobre todos los complementos disponibles.
- **volatility --info=<nombre_del_plugin>**: Muestra información sobre un complemento específico.
- **volatility --output-file=<archivo>**: Guarda la salida en un archivo.
- **volatility --profile=<perfil>**: Especifica el perfil de sistema para el volcado de memoria.
- **volatility --location=<ruta>**: Especifica la ruta de la memoria volátil.
- **volatility --cache-directory=<directorio>**: Especifica un directorio para almacenar en caché los perfiles.
- **volatility --tz=<zona_horaria>**: Especifica la zona horaria para mostrar las marcas de tiempo.
- **volatility --debug**: Muestra mensajes de depuración.
- **volatility --verbosity=<nivel>**: Especifica el nivel de verbosidad de la salida.
- **volatility --conf-file=<archivo>**: Especifica un archivo de configuración personalizado.
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

#### Metodología básica de análisis de volcado de memoria

1. **Adquisición de memoria**
   - **Volatility**: `imageinfo`, `kdbgscan`, `memmap`, `malfind`, `memdump`, `filescan`

2. **Perfilado de memoria**
   - **Volatility**: `imageinfo`, `kdbgscan`, `pslist`, `pstree`, `psscan`, `dlllist`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `getsids`, `gets
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

{% tab title="vol2" %}La siguiente es una hoja de trucos de Volatility que resume los comandos y opciones más comunes utilizados para el análisis de volcados de memoria:

### Comandos Básicos
- **imageinfo**: Muestra información básica sobre la imagen de memoria.
- **pslist**: Lista los procesos en la imagen de memoria.
- **pstree**: Muestra los procesos en forma de árbol.
- **psscan**: Escanea los procesos en la imagen de memoria.
- **dlllist**: Lista las DLL cargadas en los procesos.
- **handles**: Muestra los descriptores de archivo abiertos por cada proceso.
- **filescan**: Escanea la memoria en busca de estructuras de archivos.
- **cmdline**: Muestra los argumentos de línea de comandos de los procesos.
- **consoles**: Muestra las consolas de los procesos.
- **vadinfo**: Muestra información sobre los espacios de direcciones virtuales (VAD).
- **vadtree**: Muestra los VAD en forma de árbol.
- **vaddump**: Vuelca un VAD específico.
- **malfind**: Encuentra posibles inyecciones de malware en los procesos.
- **yarascan**: Escanea la memoria en busca de patrones con Yara.
- **memmap**: Muestra el mapeo de memoria física y virtual.
- **memdump**: Vuelca un rango de memoria a un archivo.
- **hashdump**: Extrae contraseñas hash de SAM y SYSTEM.
- **hivelist**: Enumera los archivos de registro presentes en la memoria.
- **printkey**: Imprime una clave del registro.
- **dumpregistry**: Vuelca una parte o todo el registro a un archivo.
- **apihooks**: Muestra los ganchos de API en los procesos.
- **ldrmodules**: Lista los módulos cargados en los procesos.
- **devicetree**: Muestra el árbol de dispositivos.
- **modscan**: Escanea la memoria en busca de módulos del kernel.
- **ssdt**: Muestra la Service Descriptor Table (SDT).
- **callbacks**: Muestra los callbacks del kernel.
- **gdt**: Muestra la Global Descriptor Table (GDT).
- **idt**: Muestra la Interrupt Descriptor Table (IDT).
- **driverscan**: Escanea la memoria en busca de estructuras de control de controladores.
- **filescan**: Escanea la memoria en busca de estructuras de archivos.
- **netscan**: Escanea la memoria en busca de conexiones de red.
- **connections**: Muestra las conexiones de red.
- **sockets**: Muestra los sockets de red.
- **svcscan**: Escanea la memoria en busca de registros de servicios.
- **svcscan**: Escanea la memoria en busca de registros de servicios.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **getsids**: Enumera los SID de los procesos.
- **gets
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
- **volatility -f <file> dlllist -p <pid>**: Lista las DLL cargadas por un proceso.
- **volatility -f <file> cmdscan**: Escanea los procesos en busca de comandos de consola.
- **volatility -f <file> filescan**: Escanea los descriptores de archivo.
- **volatility -f <file> netscan**: Escanea los sockets de red.
- **volatility -f <file> connections**: Muestra las conexiones de red.
- **volatility -f <file> consoles**: Lista las consolas interactivas.
- **volatility -f <file> hivelist**: Enumera los archivos de volcado del registro.
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro a partir de un desplazamiento.
- **volatility -f <file> hashdump**: Extrae los hashes de contraseñas.
- **volatility -f <file> malfind**: Encuentra procesos sospechosos.
- **volatility -f <file> apihooks**: Muestra los ganchos de API.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> modscan**: Escanea los módulos.
- **volatility -f <file> shimcache**: Analiza la caché de Shim.
- **volatility -f <file> getsids**: Obtiene los SID de los procesos.
- **volatility -f <file> userassist**: Analiza las entradas de UserAssist.
- **volatility -f <file> cmdline**: Muestra los argumentos de línea de comandos de los procesos.
- **volatility -f <file> consoles -v**: Muestra información detallada de las consolas.
- **volatility -f <file> envars**: Muestra las variables de entorno de los procesos.
- **volatility -f <file> handles -p <pid>**: Lista los identificadores de los objetos abiertos por un proceso.
- **volatility -f <file> handles**: Lista los identificadores de los objetos abiertos.
- **volatility -f <file> mutantscan**: Escanea los objetos de tipo Mutant.
- **volatility -f <file> mutantscan -s**: Escanea los objetos de tipo Mutant y muestra información detallada.
- **volatility -f <file> mutantscan -t**: Escanea los objetos de tipo Mutant y muestra los hilos que lo poseen.
- **volatility -f <file> svcscan**: Escanea los servicios.
- **volatility -f <file> svcscan -v**: Escanea los servicios y muestra información detallada.
- **volatility -f <file> yarascan**: Escanea la memoria en busca de patrones YARA.
- **volatility -f <file> yarascan -Y "<rule>"**: Escanea la memoria en busca de un patrón YARA específico.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos del volcado de memoria.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory> -S <size>**: Extrae archivos del volcado de memoria con un tamaño específico.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory> -U <user>**: Extrae archivos del volcado de memoria pertenecientes a un usuario específico.

### Plugins adicionales

- **apihooks**: Muestra los ganchos de API.
- **malfind**: Encuentra procesos sospechosos.
- **malfind -p <pid>**: Encuentra procesos sospechosos asociados a un PID específico.
- **malfind -v**: Muestra información detallada sobre procesos sospechosos.
- **malfind -D <output_directory>**: Guarda la información de procesos sospechosos en un directorio.
- **malfind -Y "<rule>"**: Encuentra procesos sospechosos que coincidan con un patrón YARA específico.
- **malfind -D <output_directory> -Y "<rule>"**: Guarda la información de procesos sospechosos que coincidan con un patrón YARA en un directorio.
- **malfind -p <pid> -D <output_directory>**: Guarda la información de procesos sospechosos asociados a un PID específico en un directorio.
- **malfind -p <pid> -v**: Muestra información detallada sobre procesos sospechosos asociados a un PID específico.
- **malfind -p <pid> -D <output_directory> -Y "<rule>"**: Guarda la información de procesos sospechosos asociados a un PID específico que coincidan con un patrón YARA en un directorio.
- **malfind -p <pid> -D <output_directory> -Y "<rule>" -v**: Muestra información detallada sobre procesos sospechosos asociados a un PID específico que coincidan con un patrón YARA en un directorio.

{% endtab %}
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
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro específica.
- **volatility -f <file> hashdump**: Extrae los hashes de contraseñas.
- **volatility -f <file> userassist**: Muestra las entradas de UserAssist.
- **volatility -f <file> malfind**: Encuentra procesos sospechosos.
- **volatility -f <file> apihooks**: Enumera los ganchos de API.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> modscan**: Escanea los módulos.
- **volatility -f <file> shimcache**: Muestra la caché de Shim.
- **volatility -f <file> getsids**: Obtiene los SID de los procesos.
- **volatility -f <file> getservicesids**: Obtiene los SID de los servicios.
- **volatility -f <file> yarascan**: Escanea la memoria en busca de patrones YARA.
- **volatility -f <file> dumpfiles -Q <address> -D <output_directory>**: Extrae archivos del espacio de memoria.
- **volatility -f <file> memdump -p <pid> -D <output_directory>**: Crea un volcado de memoria de un proceso específico.
- **volatility -f <file> memmap**: Muestra el mapeo de memoria.
- **volatility -f <file> memstrings -p <pid>**: Encuentra cadenas ASCII en el espacio de memoria de un proceso.
- **volatility -f <file> cmdline -p <pid>**: Muestra el comando utilizado para iniciar un proceso.
- **volatility -f <file> consoles -p <pid>**: Muestra las consolas asociadas a un proceso.
- **volatility -f <file> envars -p <pid>**: Muestra las variables de entorno de un proceso.
- **volatility -f <file> handles -p <pid>**: Muestra los identificadores de los objetos abiertos por un proceso.
- **volatility -f <file> privs -p <pid>**: Muestra los privilegios de un proceso.
- **volatility -f <file> psxview**: Muestra procesos ocultos.
- **volatility -f <file> vadinfo -p <pid>**: Muestra información sobre el espacio de direcciones virtuales de un proceso.
- **volatility -f <file> vadtree -p <pid>**: Muestra el árbol de estructuras de direcciones virtuales de un proceso.
- **volatility -f <file> vadwalk -p <pid>**: Muestra las regiones de memoria asignadas a un proceso.
- **volatility -f <file> yarascan -Y <rule_file>**: Escanea la memoria en busca de patrones YARA definidos en un archivo de reglas.
- **volatility -f <file> malfind -D <output_directory>**: Escanea la memoria en busca de procesos sospechosos y los extrae en un directorio de salida.
- **volatility -f <file> malfind -p <pid>**: Escanea la memoria en busca de procesos sospechosos asociados a un PID específico.
- **volatility -f <file> malfind -V**: Escanea la memoria en busca de procesos sospechosos y muestra información detallada.
- **volatility -f <file> malfind -p <pid> -D <output_directory>**: Escanea la memoria en busca de procesos sospechosos asociados a un PID específico y los extrae en un directorio de salida.
- **volatility -f <file> malfind -p <pid> -D <output_directory> -V**: Escanea la memoria en busca de procesos sospechosos asociados a un PID específico, los extrae en un directorio de salida y muestra información detallada.

### Plugins adicionales

- **apihooks**: Enumera los ganchos de API.
- **malfind**: Encuentra procesos sospechosos.
- **malsysproc**: Encuentra procesos del sistema sospechosos.
- **malthfind**: Encuentra manejadores de archivos sospechosos.
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
- **malfind**:
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
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro específica.
- **volatility -f <file> cmdline -p <pid>**: Muestra el comando utilizado para iniciar un proceso.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <file> apihooks**: Muestra los ganchos de API.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> modscan**: Escanea los módulos del kernel.
- **volatility -f <file> getsids**: Enumera los SID de seguridad.
- **volatility -f <file> userassist**: Analiza las entradas de UserAssist.
- **volatility -f <file> shimcache**: Analiza la caché de Shim.
- **volatility -f <file> hivelist**: Enumera los archivos de volcado del registro.
- **volatility -f <file> printkey -o <offset>**: Imprime una clave de registro específica.
- **volatility -f <file> cmdline -p <pid>**: Muestra el comando utilizado para iniciar un proceso.
- **volatility -f <file> malfind**: Encuentra inyecciones de código malicioso.
- **volatility -f <file> apihooks**: Muestra los ganchos de API.
- **volatility -f <file> ldrmodules**: Lista los módulos cargados.
- **volatility -f <file> modscan**: Escanea los módulos del kernel.
- **volatility -f <file> getsids**: Enumera los SID de seguridad.
- **volatility -f <file> userassist**: Analiza las entradas de UserAssist.
- **volatility -f <file> shimcache**: Analiza la caché de Shim.

### Plugins adicionales

- **malware**: Analiza malware en memoria.
- **malfind**: Encuentra inyecciones de código malicioso.
- **apihooks**: Muestra los ganchos de API.
- **ldrmodules**: Lista los módulos cargados.
- **modscan**: Escanea los módulos del kernel.
- **getsids**: Enumera los SID de seguridad.
- **userassist**: Analiza las entradas de UserAssist.
- **shimcache**: Analiza la caché de Shim.

### Ejemplos de uso

- **volatility -f memdump.mem imageinfo**: Muestra información básica sobre el volcado de memoria "memdump.mem".
- **volatility -f memdump.mem pslist**: Lista los procesos en ejecución en el volcado de memoria "memdump.mem".
- **volatility -f memdump.mem pstree**: Muestra los procesos en forma de árbol en el volcado de memoria "memdump.mem".

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
```
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
El MBR contiene la información sobre cómo están organizadas las particiones lógicas, que contienen [sistemas de archivos](https://es.wikipedia.org/wiki/Sistema_de_archivos), en ese medio. El MBR también contiene código ejecutable para funcionar como cargador del sistema operativo instalado, generalmente pasando el control al [segundo estado](https://es.wikipedia.org/wiki/Cargador_de_segundo_estado) del cargador, o en conjunto con el [registro de arranque del volumen](https://es.wikipedia.org/wiki/Registro_de_arranque_del_volumen) (VBR) de cada partición. Este código MBR suele denominarse [cargador de arranque](https://es.wikipedia.org/wiki/Cargador_de_arranque). De [aquí](https://es.wikipedia.org/wiki/Registro_de_arranque_principal).

​

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
