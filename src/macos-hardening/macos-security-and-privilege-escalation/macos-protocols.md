# Servicios y protocolos de red de macOS

{{#include ../../banners/hacktricks-training.md}}

## Servicios de acceso remoto

Estos son los servicios comunes de macOS para acceder a ellos de forma remota.\
Puedes habilitar/deshabilitar estos servicios en `Configuración del Sistema` --> `Compartir`

- **VNC**, conocido como “Compartir pantalla” (tcp:5900)
- **SSH**, llamado “Inicio de sesión remoto” (tcp:22)
- **Apple Remote Desktop** (ARD), o “Gestión remota” (tcp:3283, tcp:5900)
- **AppleEvent**, conocido como “Evento Apple remoto” (tcp:3031)

Comprueba si alguno está habilitado ejecutando:
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

Cuando ya tienes ejecución de código local en un Mac, **comprueba el estado configurado**, no solo los sockets de escucha. `systemsetup` y `launchctl` suelen indicar si el servicio está habilitado administrativamente, mientras que `kickstart` y `system_profiler` ayudan a confirmar la configuración efectiva de ARD/Sharing:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) es una versión mejorada de [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) adaptada para macOS, que ofrece funciones adicionales. Una vulnerabilidad destacable de ARD es su método de autenticación para la contraseña de la pantalla de control, que solo utiliza los primeros 8 caracteres de la contraseña, lo que la hace susceptible a [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) con herramientas como Hydra o [GoRedShell](https://github.com/ahhh/GoRedShell/), ya que no existen límites de tasa predeterminados.<sup>[3]</sup>

Las instancias vulnerables pueden identificarse mediante el script `vnc-info` de **nmap**. Los servicios compatibles con `VNC Authentication (2)` son especialmente susceptibles a brute force attacks debido al truncamiento de la contraseña a 8 caracteres.

Para habilitar ARD para diversas tareas administrativas, como privilege escalation, acceso a la GUI o monitorización de usuarios, utiliza el siguiente comando:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD proporciona niveles de control versátiles, incluidos observación, control compartido y control total, con sesiones que persisten incluso después de cambios en la contraseña del usuario. Permite enviar comandos Unix directamente y ejecutarlos como root para usuarios administrativos. La programación de tareas y la búsqueda remota de Spotlight son funciones destacables, ya que facilitan búsquedas remotas y de bajo impacto de archivos sensibles en varias máquinas.

Desde la perspectiva del operador, **Monterey 12.1+ cambió los flujos de trabajo de habilitación remota** en flotas gestionadas. Si ya controlas el MDM de la víctima, el comando `EnableRemoteDesktop` de Apple suele ser la forma más limpia de activar la funcionalidad de escritorio remoto en sistemas más recientes. Si ya tienes un foothold en el host, `kickstart` sigue siendo útil para inspeccionar o reconfigurar los privilegios de ARD desde la línea de comandos.

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

Investigaciones recientes sobre `screensharingd` demostraron que Apple Screen Sharing no siempre utiliza únicamente la autenticación VNC clásica: las compilaciones más recientes hablan **RFB `003.889`** y anuncian el **security type `36`**, donde **SRP** autentica primero y **ChaCha20-Poly1305** solo se instala después de que `ccsrp_server_verify_session` finaliza correctamente. El informe público indica que el bug se corrigió en **macOS Tahoe 26.6** (**27 de julio de 2026**).<sup>[8][9]</sup>

Un patrón útil que conviene recordar es el **stale-status parser bypass**: después de una lectura correcta de longitud de 4 bytes, cada rama de error o tamaño excesivo debe devolver un error nuevo. En las compilaciones afectadas, una longitud de frame SRP big-endian **`>= 32768`** hace que la ruta de rechazo reutilice el resultado correcto anterior de `NetBufferRead` (`0`), por lo que el caller establece la sesión como autenticada aunque no se haya ejecutado ninguna prueba de contraseña ni se haya instalado el cifrado de transporte. Como los bytes no leídos permanecen en el búfer de socket compartido, un atacante puede **pipelinear datos SRP malformados y mensajes RFB post-auth en la misma ráfaga TCP** y conseguir que se analicen como **tráfico autenticado en texto claro**.<sup>[8]</sup>

Después del bypass, el mensaje propietario de Apple de **file-copy** **`0x22`** se convierte en una **primitiva de lectura/escritura de archivos como root** porque `screensharingd` se ejecuta como root:<sup>[8]</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: lectura arbitraria de archivos
- `kind=2` / `StartFileReceive`: escritura arbitraria de archivos
- Los distintos valores de `sid` permiten poner en pipeline varias transacciones en una sola conexión
- En `kind=101` (`NewItem`), establece el byte `14` / `arg[0]` en `0x01` para un archivo normal, el offset de payload `+42` en un tamaño de archivo big-endian **distinto de cero**, y el offset de payload `+0x5a` en el modo Unix deseado (`0600` si el objetivo es un crontab)

Los pivots post-write interesantes en rutas escribibles incluyen **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`** y **`/var/root/.ssh/authorized_keys`**. **SIP no detiene el auth bypass ni la lectura de archivos como root**, pero sí bloquea algunos destinos de escritura, como **`/var/at`**, por lo que la ejecución basada en cron solo funciona con SIP deshabilitado. En hosts con SIP habilitado por defecto, piensa en términos de **"escritura de archivos como root en archivos privilegiados consumidos automáticamente"** en lugar de ejecución inmediata de código.<sup>[8]</sup>

Otro problema de SRP de la misma investigación: los servidores deben validar **`A mod N != 0`** (según RFC 5054), no solo `A > 0`. Aceptar **`A = N`** puede forzar que el secreto compartido sea cero y debilitar la verificación de la contraseña.<sup>[8][10]</sup>

**Ideas de detección**

- Sesiones de tipo de seguridad `36` donde la longitud del primer frame de SRP sea **`>= 32768`**
- Sesiones que comiencen a procesar tráfico de copia de archivos en texto claro **`0x22`** antes de cualquier prueba de SRP exitosa / instalación del cifrado
- Reintentos frecuentes y de corta duración contra **TCP/5900**, junto con múltiples valores de `sid` de copia de archivos en un mismo burst
- Creación inesperada de **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`** o **`/var/root/.ssh/authorized_keys`** después de exponer Screen Sharing

### Pentesting Remote Apple Events (RAE / EPPC)

Apple denomina esta función **Remote Application Scripting** en System Settings modernas. Internamente, expone el **Apple Event Manager** de forma remota mediante **EPPC** en **TCP/3031**, a través del servicio `com.apple.AEServer`. Palo Alto Unit 42 volvió a destacarla como un primitive práctico de **lateral movement en macOS**, porque unas credenciales válidas y un servicio RAE habilitado permiten a un operador controlar aplicaciones scriptables en un Mac remoto.<sup>[6]</sup>

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
En la práctica, el caso de abuso no se limita a Finder. Cualquier **scriptable application** que acepte los Apple events requeridos se convierte en una superficie de ataque remota, lo que hace que RAE sea especialmente interesante después del robo de credenciales en redes macOS internas.

#### Vulnerabilidades recientes de Screen-Sharing / ARD (2023-2025)

| Año | CVE | Componente | Impacto | Corregido en |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Una renderización incorrecta de la sesión podía provocar que se transmitiera el escritorio o la ventana *equivocados*, lo que resultaba en una filtración de información sensible|macOS Sonoma 14.2.1 (diciembre de 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Un usuario con acceso a screen sharing podía ver **la pantalla de otro usuario** debido a un problema de gestión del estado|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (octubre-diciembre de 2024) |

**Consejos de hardening**

* Desactiva *Screen Sharing*/*Remote Management* cuando no sean estrictamente necesarios.
* Mantén macOS completamente actualizado (Apple generalmente publica security fixes para las tres versiones principales más recientes).
* Usa una **Strong Password** y, cuando sea posible, mantén **desactivada** la opción *“VNC viewers may control screen with password”*.
* Coloca el servicio detrás de una VPN en lugar de exponer TCP 5900/3283 a Internet.
* Añade una regla de Application Firewall para limitar `ARDAgent` a la subred local:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Bonjour, una tecnología diseñada por Apple, permite que los **dispositivos de la misma red detecten los servicios ofrecidos por los demás**. También conocido como Rendezvous, **Zero Configuration** o Zeroconf, permite que un dispositivo se una a una red TCP/IP, **elija automáticamente una dirección IP** y anuncie sus servicios a otros dispositivos de la red.

Zero Configuration Networking, proporcionado por Bonjour, garantiza que los dispositivos puedan:

- **Obtener automáticamente una dirección IP**, incluso en ausencia de un servidor DHCP.
- Realizar la **traducción de nombres a direcciones** sin requerir un servidor DNS.
- **Descubrir servicios** disponibles en la red.

Los dispositivos que utilizan Bonjour se asignarán una **dirección IP del rango 169.254/16** y verificarán su unicidad en la red. Los Macs mantienen una entrada en la tabla de routing para esta subred, que puede verificarse mediante `netstat -rn | grep 169`.

Para DNS, Bonjour utiliza el **protocolo Multicast DNS (mDNS)**. mDNS opera sobre el **puerto 5353/UDP**, empleando **consultas DNS estándar**, pero dirigidas a la **dirección multicast 224.0.0.251**. Este enfoque garantiza que todos los dispositivos que escuchan en la red puedan recibir y responder a las consultas, facilitando la actualización de sus registros.

Al unirse a la red, cada dispositivo selecciona automáticamente un nombre, que normalmente termina en **.local** y puede derivarse del hostname o generarse aleatoriamente.

El descubrimiento de servicios dentro de la red se facilita mediante **DNS Service Discovery (DNS-SD)**. Aprovechando el formato de los registros DNS SRV, DNS-SD utiliza **registros DNS PTR** para permitir la enumeración de múltiples servicios. Un cliente que busca un servicio específico solicitará un registro PTR para `<Service>.<Domain>` y, si el servicio está disponible desde varios hosts, recibirá a cambio una lista de registros PTR con el formato `<Instance>.<Service>.<Domain>`.

La utilidad `dns-sd` puede emplearse para **descubrir y anunciar servicios de red**. Estos son algunos ejemplos de uso:

### Búsqueda de SSH Services

Para buscar SSH services en la red, se utiliza el siguiente comando:
```bash
dns-sd -B _ssh._tcp
```
Este comando inicia la búsqueda de servicios \_ssh.\_tcp y muestra detalles como la marca de tiempo, los flags, la interfaz, el dominio, el tipo de servicio y el nombre de la instancia.

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
Cuando un servicio se inicia, anuncia su disponibilidad a todos los dispositivos de la subred mediante multicast. Los dispositivos interesados en estos servicios no necesitan enviar solicitudes, sino simplemente escuchar estos anuncios.

Para ofrecer una interfaz más fácil de usar, la aplicación **Discovery - DNS-SD Browser**, disponible en la Apple App Store, puede visualizar los servicios ofrecidos en la red local.

Como alternativa, se pueden escribir scripts personalizados para explorar y descubrir servicios mediante la biblioteca `python-zeroconf`. El script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) muestra cómo crear un explorador de servicios para los servicios `_http._tcp.local.`, e imprimir los servicios añadidos o eliminados:
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
### Búsqueda de Bonjour específica de macOS

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
Para conocer técnicas más amplias de **mDNS spoofing, impersonation y cross-subnet discovery**, consulta la página dedicada:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Enumeración de Bonjour en la red

* **Nmap NSE** – descubre los servicios anunciados por un único host:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

El script `dns-service-discovery` envía una consulta `_services._dns-sd._udp.local` y, después, enumera cada tipo de servicio anunciado.

* **mdns_recon** – herramienta Python que analiza rangos completos en busca de responders mDNS *mal configurados* que respondan a consultas unicast (útil para encontrar dispositivos accesibles desde otras subredes/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Esto devolverá los hosts que exponen SSH mediante Bonjour fuera del enlace local.

### Consideraciones de seguridad y vulnerabilidades recientes (2024-2025)

| Año | CVE | Severidad | Problema | Corregido en |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Media|Un error lógico en *mDNSResponder* permitía que un paquete manipulado provocara un **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (sep. de 2024) |
|2025|CVE-2025-31222|Alta|Un problema de corrección en *mDNSResponder* podía aprovecharse para realizar una **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (mayo de 2025) |

**Guía de mitigación**

1. Restringe UDP 5353 al alcance *link-local*: bloquéalo o limita su tasa en controladores wireless, routers y firewalls basados en host.
2. Deshabilita Bonjour por completo en los sistemas que no requieran service discovery:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. En entornos donde Bonjour sea necesario internamente, pero nunca deba atravesar los límites de la red, utiliza restricciones del perfil *AirPlay Receiver* (MDM) o un proxy mDNS.
4. Habilita **System Integrity Protection (SIP)** y mantén macOS actualizado; ambas vulnerabilidades se corrigieron rápidamente, pero dependían de que SIP estuviera habilitado para ofrecer protección completa.

### Deshabilitar Bonjour

Si existen preocupaciones de seguridad u otros motivos para deshabilitar Bonjour, puede desactivarse mediante el siguiente comando:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Referencias

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Volume I: Analysis - Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 - Movimiento lateral en macOS: técnicas únicas y populares, y ejemplos reales](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - Sobre el contenido de seguridad de macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - Sobre el contenido de seguridad de macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Uso del protocolo Secure Remote Password (SRP) para la autenticación TLS](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
