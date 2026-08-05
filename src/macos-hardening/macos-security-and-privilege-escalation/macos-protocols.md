# Servicios y protocolos de red de macOS

{{#include ../../banners/hacktricks-training.md}}

## Servicios de acceso remoto

Estos son los servicios comunes de macOS para acceder al sistema de forma remota.\
Puedes activar o desactivar estos servicios en `System Settings` --> `Sharing`

- **VNC**, conocido como “Screen Sharing” (tcp:5900)
- **SSH**, denominado “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), o “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, conocido como “Remote Apple Event” (tcp:3031)

Comprueba si alguno está activado ejecutando:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Enumerando la configuración de sharing localmente

Cuando ya tienes ejecución de código local en un Mac, **comprueba el estado configurado**, no solo los sockets en escucha. `systemsetup` y `launchctl` normalmente indican si el servicio está habilitado administrativamente, mientras que `kickstart` y `system_profiler` ayudan a confirmar la configuración efectiva de ARD/Sharing:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) es una versión mejorada de [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) adaptada para macOS, que ofrece funciones adicionales. Una vulnerabilidad destacable en ARD es su método de autenticación para la contraseña de la pantalla de control, que solo utiliza los primeros 8 caracteres de la contraseña, lo que la hace susceptible a [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) con herramientas como Hydra o [GoRedShell](https://github.com/ahhh/GoRedShell/), ya que no existen límites de intentos predeterminados.<sup>[[3]](#references)</sup>

Las instancias vulnerables pueden identificarse utilizando el script `vnc-info` de **nmap**. Los servicios compatibles con `VNC Authentication (2)` son especialmente susceptibles a brute force attacks debido al truncamiento de la contraseña a 8 caracteres.

Para habilitar ARD para diversas tareas administrativas, como privilege escalation, acceso a la GUI o monitorización de usuarios, utiliza el siguiente comando:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD proporciona niveles de control versátiles, incluidos observación, control compartido y control total, con sesiones que persisten incluso después de cambiar la contraseña del usuario. Permite enviar comandos Unix directamente y ejecutarlos como root para usuarios administrativos. La programación de tareas y la búsqueda Remote Spotlight son funciones destacables, ya que facilitan búsquedas remotas y de bajo impacto de archivos sensibles en varias máquinas.

Desde la perspectiva del operador, **Monterey 12.1+ cambió los workflows de habilitación remota** en flotas administradas. Si ya controlas el MDM de la víctima, el comando `EnableRemoteDesktop` de Apple suele ser la forma más limpia de activar la funcionalidad de escritorio remoto en sistemas más recientes. Si ya tienes un foothold en el host, `kickstart` sigue siendo útil para inspeccionar o reconfigurar los privilegios de ARD desde la línea de comandos.

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

Investigaciones recientes sobre `screensharingd` demostraron que Apple Screen Sharing no siempre utiliza únicamente la autenticación VNC clásica: las builds más recientes hablan **RFB `003.889`** y anuncian el **security type `36`**, donde **SRP** realiza primero la autenticación y **ChaCha20-Poly1305** solo se instala después de que `ccsrp_server_verify_session` se ejecuta correctamente. El write-up público informa que el bug fue corregido en **macOS Tahoe 26.6** (**27 de julio de 2026**).<sup>[[8]](#references)[[9]](#references)</sup>

Un patrón útil para recordar es el **stale-status parser bypass**: después de una lectura de longitud de 4 bytes exitosa, cada rama de error o de tamaño excesivo debe devolver un error nuevo. En las builds afectadas, una longitud de frame SRP en big-endian **`>= 32768`** hace que la ruta de rechazo reutilice el resultado anterior de éxito de `NetBufferRead` (`0`), por lo que el caller establece la sesión como autenticada aunque no se haya ejecutado ninguna prueba de contraseña ni se haya instalado el cifrado de transporte. Como los bytes no leídos permanecen en el buffer de socket compartido, un atacante puede **pipelinear datos SRP malformados y mensajes RFB post-auth en el mismo burst TCP** y conseguir que se analicen como **tráfico autenticado en cleartext**.<sup>[[8]](#references)</sup>

Después del bypass, el mensaje propietario de Apple **file-copy** **`0x22`** se convierte en una **primitive de lectura/escritura de archivos como root** porque `screensharingd` se ejecuta como root:<sup>[[8]](#references)</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: lectura arbitraria de archivos
- `kind=2` / `StartFileReceive`: escritura arbitraria de archivos
- Distintos valores de `sid` permiten canalizar varias transacciones en una misma conexión
- En `kind=101` (`NewItem`), establece el byte `14` / `arg[0]` en `0x01` para un archivo normal, el offset de payload `+42` en un tamaño de archivo big-endian **distinto de cero**, y el offset de payload `+0x5a` en el modo Unix deseado (`0600` si el objetivo es un crontab)

Los pivots interesantes posteriores a la escritura en rutas escribibles incluyen **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`** y **`/var/root/.ssh/authorized_keys`**. **SIP no detiene el auth bypass ni la lectura de archivos como root**, pero sí bloquea algunos objetivos de escritura como **`/var/at`**, por lo que la ejecución basada en cron solo funciona con SIP deshabilitado. En hosts con SIP habilitado por defecto, piensa en términos de **"escritura de archivos como root en archivos privilegiados consumidos automáticamente"** en lugar de ejecución inmediata de código.<sup>[[8]](#references)</sup>

Otro problema de SRP de la misma investigación: los servidores deben validar **`A mod N != 0`** (según RFC 5054), no solo `A > 0`. Aceptar **`A = N`** puede forzar el secreto compartido a cero y comprometer la verificación de la contraseña.<sup>[[8]](#references)[[10]](#references)</sup>

**Ideas de detección**

- Sesiones de tipo de seguridad `36` en las que la longitud del primer frame de SRP sea **`>= 32768`**
- Sesiones que comiencen a procesar tráfico de copia de archivos en texto claro **`0x22`** antes de cualquier prueba de SRP exitosa / instalación de cifrado
- Reintentos frecuentes y de corta duración contra **TCP/5900**, junto con varios valores de `sid` de copia de archivos en una misma ráfaga
- Creación inesperada de **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`** o **`/var/root/.ssh/authorized_keys`** después de la exposición de Screen Sharing

### Pentesting Remote Apple Events (RAE / EPPC)

Apple denomina esta función **Remote Application Scripting** en System Settings modernas. Internamente, expone el **Apple Event Manager** de forma remota mediante **EPPC** en **TCP/3031**, a través del servicio `com.apple.AEServer`. Palo Alto Unit 42 volvió a destacarla como un primitive práctico de **movimiento lateral en macOS**, ya que unas credenciales válidas y un servicio RAE habilitado permiten a un operador controlar aplicaciones con capacidad de scripting en un Mac remoto.<sup>[[6]](#references)</sup>

Comprobaciones útiles:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Si ya tienes admin/root en el objetivo y quieres habilitarlo:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Prueba básica de conectividad desde otro Mac:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
En la práctica, el caso de abuso no se limita a Finder. Cualquier **scriptable application** que acepte los Apple events necesarios se convierte en una superficie de ataque remota, lo que hace que RAE sea especialmente interesante después del robo de credenciales en redes macOS internas.

#### Vulnerabilidades recientes de Screen-Sharing / ARD (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Una representación incorrecta de la sesión podía provocar que se transmitiera el escritorio o la ventana *equivocados*, resultando en leakage de información sensible|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Un usuario con acceso a screen sharing podía ver **la pantalla de otro usuario** debido a un problema de gestión del estado|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Consejos de hardening**

* Deshabilita *Screen Sharing*/*Remote Management* cuando no sea estrictamente necesario.
* Mantén macOS completamente actualizado (Apple generalmente publica security fixes para las tres versiones principales más recientes).
* Usa una **Strong Password** y, cuando sea posible, mantén deshabilitada la opción *“VNC viewers may control screen with password”*.
* Coloca el servicio detrás de una VPN en lugar de exponer TCP 5900/3283 a Internet.
* Añade una regla de Application Firewall para limitar `ARDAgent` a la subred local:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Protocolo Bonjour

Bonjour, una tecnología diseñada por Apple, permite que **los dispositivos de la misma red detecten los servicios que ofrecen los demás**. También conocida como Rendezvous, **Zero Configuration** o Zeroconf, permite que un dispositivo se una a una red TCP/IP, **elija automáticamente una dirección IP** y anuncie sus servicios a otros dispositivos de la red.

Zero Configuration Networking, proporcionado por Bonjour, garantiza que los dispositivos puedan:

- **Obtener automáticamente una dirección IP** incluso en ausencia de un servidor DHCP.
- Realizar la **traducción de nombre a dirección** sin necesitar un servidor DNS.
- **Descubrir servicios** disponibles en la red.

Los dispositivos que utilizan Bonjour se asignan a sí mismos una **dirección IP del rango 169.254/16** y verifican su unicidad en la red. Los Macs mantienen una entrada en la tabla de enrutamiento para esta subred, que se puede comprobar mediante `netstat -rn | grep 169`.

Para DNS, Bonjour utiliza el **protocolo Multicast DNS (mDNS)**. mDNS opera sobre el **puerto 5353/UDP**, empleando **consultas DNS estándar**, pero dirigidas a la **dirección multicast 224.0.0.251**. Este enfoque garantiza que todos los dispositivos en escucha de la red puedan recibir y responder a las consultas, facilitando la actualización de sus registros.

Al unirse a la red, cada dispositivo selecciona por sí mismo un nombre, que normalmente termina en **.local** y puede derivarse del hostname o generarse aleatoriamente.

El descubrimiento de servicios dentro de la red se realiza mediante **DNS Service Discovery (DNS-SD)**. Aprovechando el formato de los registros DNS SRV, DNS-SD utiliza **registros DNS PTR** para permitir el listado de varios servicios. Un cliente que busca un servicio específico solicitará un registro PTR para `<Service>.<Domain>` y recibirá como respuesta una lista de registros PTR con el formato `<Instance>.<Service>.<Domain>` si el servicio está disponible desde varios hosts.

La utilidad `dns-sd` puede emplearse para **descubrir y anunciar servicios de red**. A continuación se muestran algunos ejemplos de uso:

### Búsqueda de servicios SSH

Para buscar servicios SSH en la red, se utiliza el siguiente comando:
```bash
dns-sd -B _ssh._tcp
```
Este comando inicia la búsqueda de servicios \_ssh.\_tcp y muestra detalles como la marca de tiempo, los indicadores, la interfaz, el dominio, el tipo de servicio y el nombre de la instancia.

### Anunciar un servicio HTTP

Para anunciar un servicio HTTP, puedes usar:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Este comando registra un servicio HTTP llamado "Index" en el puerto 80 con una ruta de `/index.html`.

Para buscar servicios HTTP en la red:
```bash
dns-sd -B _http._tcp
```
Cuando un servicio se inicia, anuncia su disponibilidad a todos los dispositivos de la subred mediante una multidifusión de su presencia. Los dispositivos interesados en estos servicios no necesitan enviar solicitudes, sino que simplemente escuchan estos anuncios.

Para disponer de una interfaz más fácil de usar, la aplicación **Discovery - DNS-SD Browser**, disponible en Apple App Store, puede visualizar los servicios ofrecidos en tu red local.

Como alternativa, se pueden escribir scripts personalizados para explorar y descubrir servicios mediante la biblioteca `python-zeroconf`. El script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) demuestra cómo crear un navegador de servicios para servicios `_http._tcp.local.`, mostrando los servicios añadidos o eliminados:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Hunting de Bonjour específico de macOS

En las redes macOS, Bonjour suele ser la forma más sencilla de encontrar **superficies de administración remota** sin interactuar directamente con el objetivo. Apple Remote Desktop puede descubrir clientes mediante Bonjour, por lo que los mismos datos de descubrimiento resultan útiles para un atacante.
```bash
# Enumerate every advertised service type first
dns-sd -B _services._dns-sd._udp local

# Then look for common macOS admin surfaces
dns-sd -B _rfb._tcp local      # Screen Sharing / VNC
dns-sd -B _ssh._tcp local      # Remote Login
dns-sd -B _eppc._tcp local     # Remote Apple Events / EPPC

# Resolve a specific instance to hostname, port and TXT data
dns-sd -L "<Instance>" _rfb._tcp local
dns-sd -L "<Instance>" _eppc._tcp local
```
Para obtener técnicas más amplias de **mDNS spoofing, impersonation y cross-subnet discovery**, consulta la página dedicada:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Enumeración de Bonjour en la red

* **Nmap NSE** – descubre servicios anunciados por un único host:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

El script `dns-service-discovery` envía una consulta `_services._dns-sd._udp.local` y después enumera cada tipo de servicio anunciado.

* **mdns_recon** – herramienta de Python que analiza rangos completos en busca de responders mDNS *mal configurados* que respondan a consultas unicast (útil para encontrar dispositivos accesibles a través de subredes/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Esto devolverá hosts que exponen SSH mediante Bonjour fuera del enlace local.

### Consideraciones de seguridad y vulnerabilidades recientes (2024-2025)

| Año | CVE | Severidad | Problema | Corregido en |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Media|Un error lógico en *mDNSResponder* permitía que un paquete diseñado provocara una **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (sep. de 2024) |
|2025|CVE-2025-31222|Alta|Un problema de corrección en *mDNSResponder* podía explotarse para realizar una **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (mayo de 2025) |

**Guía de mitigación**

1. Restringe UDP 5353 al alcance *link-local*: bloquéalo o limita su tasa en controladores inalámbricos, routers y firewalls basados en host.
2. Desactiva Bonjour por completo en los sistemas que no requieran service discovery:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. En entornos donde Bonjour sea necesario internamente, pero nunca deba atravesar los límites de la red, utiliza restricciones del perfil de *AirPlay Receiver* (MDM) o un proxy mDNS.
4. Activa **System Integrity Protection (SIP)** y mantén macOS actualizado: ambas vulnerabilidades se corrigieron rápidamente, pero dependían de que SIP estuviera activado para ofrecer una protección completa.

### Desactivación de Bonjour

Si existen preocupaciones de seguridad u otros motivos para desactivar Bonjour, puede apagarse mediante el siguiente comando:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Referencias

- [1] [Manual del hacker de Mac](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Volume I: Análisis - Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx - Red Teaming de macOS 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD - CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD - CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 - Movimiento lateral en macOS: técnicas únicas y populares y ejemplos reales](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - Acerca del contenido de seguridad de macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - Acerca del contenido de seguridad de macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Uso del protocolo Secure Remote Password (SRP) para la autenticación TLS](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
