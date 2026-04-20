# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

Estos son los servicios comunes de macOS para acceder a ellos de forma remota.\
Puedes habilitar/deshabilitar estos servicios en `System Settings` --> `Sharing`

- **VNC**, conocido como “Screen Sharing” (tcp:5900)
- **SSH**, llamado “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), o “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, conocido como “Remote Apple Event” (tcp:3031)

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
### Enumerando la configuración de compartición localmente

Cuando ya tienes ejecución de código local en un Mac, **comprueba el estado configurado**, no solo los sockets en escucha. `systemsetup` y `launchctl` suelen indicar si el servicio está habilitado administrativamente, mientras que `kickstart` y `system_profiler` ayudan a confirmar la configuración efectiva de ARD/Sharing:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) es una versión mejorada de [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) adaptada para macOS, que ofrece funciones adicionales. Una vulnerabilidad notable en ARD es su método de autenticación para la contraseña de control de pantalla, que solo usa los primeros 8 caracteres de la contraseña, lo que la hace propensa a [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) con herramientas como Hydra o [GoRedShell](https://github.com/ahhh/GoRedShell/), ya que no hay límites de velocidad predeterminados.

Las instancias vulnerables pueden identificarse usando el script `vnc-info` de **nmap**. Los servicios que soportan `VNC Authentication (2)` son especialmente susceptibles a ataques de brute force debido a la truncación de contraseñas a 8 caracteres.

Para habilitar ARD para varias tareas administrativas como privilege escalation, acceso GUI o monitoreo de usuarios, usa el siguiente comando:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD proporciona niveles de control versátiles, incluyendo observation, shared control y full control, con sesiones que persisten incluso después de cambios en la contraseña del usuario. Permite enviar Unix commands directamente, ejecutándolos como root para usuarios administrativos. La programación de tareas y la Remote Spotlight search son funciones destacadas, que facilitan búsquedas remotas y de bajo impacto de archivos sensibles en múltiples máquinas.

Desde la perspectiva del operador, **Monterey 12.1+ cambió los workflows de remote-enablement** en flotas gestionadas. Si ya controlas el MDM de la víctima, el comando `EnableRemoteDesktop` de Apple suele ser la forma más limpia de activar la funcionalidad de remote desktop en sistemas más nuevos. Si ya tienes un foothold en el host, `kickstart` sigue siendo útil para inspeccionar o reconfigurar los privilegios de ARD desde la línea de comandos.

### Pentesting Remote Apple Events (RAE / EPPC)

Apple llama a esta función **Remote Application Scripting** en System Settings modernos. Internamente expone el **Apple Event Manager** de forma remota sobre **EPPC** en **TCP/3031** a través del servicio `com.apple.AEServer`. Palo Alto Unit 42 lo destacó de nuevo como un primitivo práctico de **macOS lateral movement** porque credenciales válidas más un servicio RAE habilitado permiten a un operador controlar aplicaciones scriptables en un Mac remoto.

Useful checks:
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
En la práctica, el caso de abuso no se limita a Finder. Cualquier **aplicación scriptable** que acepte los Apple events requeridos se convierte en una superficie de ataque remota, lo que hace que RAE sea especialmente interesante después del robo de credenciales en redes internas de macOS.

#### Vulnerabilidades recientes de Screen-Sharing / ARD (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|La renderización incorrecta de la sesión podría hacer que se transmitiera el escritorio o la ventana *equivocados*, lo que provocaría la filtración de información sensible|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Un usuario con acceso a screen sharing podría ser capaz de ver **la pantalla de otro usuario** debido a un problema de gestión de estado|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Consejos de hardening**

* Deshabilita *Screen Sharing*/*Remote Management* cuando no sea estrictamente necesario.
* Mantén macOS totalmente parcheado (Apple generalmente publica correcciones de seguridad para las tres últimas versiones principales).
* Usa una **Strong Password** *y* aplica la opción *“VNC viewers may control screen with password”* **deshabilitada** cuando sea posible.
* Coloca el servicio detrás de una VPN en lugar de exponer TCP 5900/3283 a Internet.
* Añade una regla de Application Firewall para limitar `ARDAgent` a la subred local:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Bonjour, una tecnología diseñada por Apple, permite que **dispositivos en la misma red detecten los servicios ofrecidos por los demás**. También conocido como Rendezvous, **Zero Configuration** o Zeroconf, permite que un dispositivo se una a una red TCP/IP, **elija automáticamente una dirección IP** y anuncie sus servicios a otros dispositivos de la red.

Zero Configuration Networking, proporcionado por Bonjour, garantiza que los dispositivos puedan:

- **Obtener automáticamente una dirección IP** incluso en ausencia de un servidor DHCP.
- Realizar **traducción de nombre a dirección** sin requerir un servidor DNS.
- **Descubrir servicios** disponibles en la red.

Los dispositivos que usan Bonjour se asignarán una **dirección IP del rango 169.254/16** y verificarán su unicidad en la red. Los Macs mantienen una entrada de la tabla de rutas para esta subred, verificable mediante `netstat -rn | grep 169`.

Para DNS, Bonjour utiliza el **protocolo Multicast DNS (mDNS)**. mDNS funciona sobre **el puerto 5353/UDP**, empleando **consultas DNS estándar** pero apuntando a la **dirección multicast 224.0.0.251**. Este enfoque garantiza que todos los dispositivos en escucha de la red puedan recibir y responder a las consultas, facilitando la actualización de sus registros.

Al unirse a la red, cada dispositivo se autoasigna un nombre, normalmente terminado en **.local**, que puede derivarse del hostname o generarse aleatoriamente.

El descubrimiento de servicios dentro de la red se facilita mediante **DNS Service Discovery (DNS-SD)**. Aprovechando el formato de los registros DNS SRV, DNS-SD usa **registros DNS PTR** para permitir el listado de múltiples servicios. Un cliente que busque un servicio específico solicitará un registro PTR para `<Service>.<Domain>`, recibiendo a cambio una lista de registros PTR con el formato `<Instance>.<Service>.<Domain>` si el servicio está disponible desde varios hosts.

La utilidad `dns-sd` puede emplearse para **descubrir y anunciar servicios de red**. Aquí hay algunos ejemplos de su uso:

### Buscando servicios SSH

Para buscar servicios SSH en la red, se utiliza el siguiente comando:
```bash
dns-sd -B _ssh._tcp
```
Este comando inicia la exploración de servicios \_ssh.\_tcp y muestra detalles como la marca de tiempo, flags, interfaz, dominio, tipo de servicio y nombre de instancia.

### Anunciando un servicio HTTP

Para anunciar un servicio HTTP, puedes usar:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Este comando registra un servicio HTTP llamado "Index" en el puerto 80 con una ruta de `/index.html`.

Para luego buscar servicios HTTP en la red:
```bash
dns-sd -B _http._tcp
```
Cuando un servicio se inicia, anuncia su disponibilidad a todos los dispositivos en la subred mediante multicast de su presencia. Los dispositivos interesados en estos servicios no necesitan enviar requests, sino simplemente escuchar estos anuncios.

Para una interfaz más fácil de usar, la app **Discovery - DNS-SD Browser** disponible en el Apple App Store puede visualizar los services ofrecidos en tu red local.

Alternativamente, se pueden escribir scripts personalizados para explorar y descubrir services usando la librería `python-zeroconf`. El script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) demuestra cómo crear un service browser para services `_http._tcp.local.`, imprimiendo los services añadidos o eliminados:
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
### caza de Bonjour específica de macOS

En redes macOS, Bonjour suele ser la forma más fácil de encontrar **superficies de administración remota** sin tocar directamente el objetivo. Apple Remote Desktop puede descubrir clientes a través de Bonjour, así que los mismos datos de descubrimiento también son útiles para un atacante.
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
Para técnicas más amplias de **mDNS spoofing, impersonation y cross-subnet discovery**, consulta la página dedicada:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Enumerando Bonjour en la red

* **Nmap NSE** – descubre servicios anunciados por un solo host:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

El script `dns-service-discovery` envía una consulta `_services._dns-sd._udp.local` y luego enumera cada tipo de servicio anunciado.

* **mdns_recon** – herramienta en Python que escanea rangos completos buscando respondedores mDNS *mal configurados* que responden a consultas unicast (útil para encontrar dispositivos accesibles a través de subnets/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Esto devolverá hosts que exponen SSH mediante Bonjour fuera del enlace local.

### Consideraciones de seguridad y vulnerabilidades recientes (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|A logic error in *mDNSResponder* allowed a crafted packet to trigger a **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|A correctness issue in *mDNSResponder* could be abused for **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Guía de mitigación**

1. Restringe UDP 5353 al alcance *link-local* – bloquéalo o limita su tasa en controladores inalámbricos, routers y firewalls basados en host.
2. Deshabilita Bonjour por completo en sistemas que no requieran descubrimiento de servicios:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Para entornos donde Bonjour se requiera internamente pero nunca deba cruzar límites de red, usa restricciones del perfil *AirPlay Receiver* (MDM) o un proxy mDNS.
4. Activa **System Integrity Protection (SIP)** y mantén macOS actualizado – ambas vulnerabilidades anteriores se parchearon rápido, pero dependían de que SIP estuviera habilitado para una protección completa.

### Deshabilitando Bonjour

Si hay preocupaciones de seguridad u otras razones para deshabilitar Bonjour, se puede apagar con el siguiente comando:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [**Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples**](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [**Apple Support - About the security content of macOS Sonoma 14.7.2**](https://support.apple.com/en-us/121840)

{{#include ../../banners/hacktricks-training.md}}
