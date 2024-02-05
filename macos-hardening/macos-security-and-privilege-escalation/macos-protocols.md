# Servicios y Protocolos de Red de macOS

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Servicios de Acceso Remoto

Estos son los servicios comunes de macOS para acceder a ellos de forma remota.\
Puedes habilitar/deshabilitar estos servicios en `Configuración del Sistema` --> `Compartir`

* **VNC**, conocido como "Compartir Pantalla" (tcp:5900)
* **SSH**, llamado "Inicio de Sesión Remoto" (tcp:22)
* **Apple Remote Desktop** (ARD), o "Administración Remota" (tcp:3283, tcp:5900)
* **AppleEvent**, conocido como "Evento Remoto de Apple" (tcp:3031)

Verifica si alguno está habilitado ejecutando:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) es una versión mejorada de [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) adaptada para macOS, que ofrece características adicionales. Una vulnerabilidad notable en ARD es su método de autenticación para la contraseña de la pantalla de control, que solo utiliza los primeros 8 caracteres de la contraseña, lo que la hace propensa a [ataques de fuerza bruta](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) con herramientas como Hydra o [GoRedShell](https://github.com/ahhh/GoRedShell/), ya que no hay límites de velocidad predeterminados.

Las instancias vulnerables pueden ser identificadas utilizando el script `vnc-info` de **nmap**. Los servicios que admiten `VNC Authentication (2)` son especialmente susceptibles a ataques de fuerza bruta debido a la truncación de la contraseña a 8 caracteres.

Para habilitar ARD para diversas tareas administrativas como escalada de privilegios, acceso GUI o monitoreo de usuarios, utiliza el siguiente comando:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD proporciona niveles de control versátiles, incluyendo observación, control compartido y control total, con sesiones que persisten incluso después de cambios de contraseña de usuario. Permite enviar comandos Unix directamente, ejecutándolos como root para usuarios administrativos. La programación de tareas y la búsqueda remota de Spotlight son características destacadas, facilitando búsquedas remotas de bajo impacto de archivos sensibles en múltiples máquinas.

## Protocolo Bonjour

Bonjour, una tecnología diseñada por Apple, permite que **los dispositivos en la misma red detecten los servicios ofrecidos por otros**. Conocido también como Rendezvous, **Zero Configuration** o Zeroconf, permite que un dispositivo se una a una red TCP/IP, **elija automáticamente una dirección IP** y difunda sus servicios a otros dispositivos de red.

La Red de Configuración Cero, proporcionada por Bonjour, garantiza que los dispositivos puedan:
* **Obtener automáticamente una dirección IP** incluso en ausencia de un servidor DHCP.
* Realizar **traducción de nombres a direcciones** sin necesidad de un servidor DNS.
* **Descubrir servicios** disponibles en la red.

Los dispositivos que utilizan Bonjour se asignarán a sí mismos una **dirección IP del rango 169.254/16** y verificarán su unicidad en la red. Las Mac mantienen una entrada de tabla de enrutamiento para esta subred, verificable a través de `netstat -rn | grep 169`.

Para DNS, Bonjour utiliza el **protocolo de Multicast DNS (mDNS)**. mDNS opera sobre **el puerto 5353/UDP**, empleando **consultas DNS estándar** pero apuntando a la **dirección de multidifusión 224.0.0.251**. Este enfoque garantiza que todos los dispositivos receptores en la red puedan recibir y responder a las consultas, facilitando la actualización de sus registros.

Al unirse a la red, cada dispositivo se autoasigna un nombre, que generalmente termina en **.local**, el cual puede derivarse del nombre de host o generarse aleatoriamente.

El descubrimiento de servicios dentro de la red es facilitado por **Descubrimiento de Servicios DNS (DNS-SD)**. Aprovechando el formato de los registros SRV de DNS, DNS-SD utiliza **registros PTR de DNS** para permitir la lista de múltiples servicios. Un cliente que busca un servicio específico solicitará un registro PTR para `<Servicio>.<Dominio>`, recibiendo a cambio una lista de registros PTR formateados como `<Instancia>.<Servicio>.<Dominio>` si el servicio está disponible desde múltiples hosts.

La utilidad `dns-sd` se puede emplear para **descubrir y anunciar servicios de red**. Aquí hay algunos ejemplos de su uso:

### Buscando Servicios SSH

Para buscar servicios SSH en la red, se utiliza el siguiente comando:
```bash
dns-sd -B _ssh._tcp
```
Este comando inicia la búsqueda de servicios _ssh._tcp y muestra detalles como la marca de tiempo, banderas, interfaz, dominio, tipo de servicio y nombre de la instancia.

### Publicar un Servicio HTTP

Para publicar un servicio HTTP, puedes usar:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Este comando registra un servicio HTTP llamado "Index" en el puerto 80 con una ruta de `/index.html`.

Para luego buscar servicios HTTP en la red:
```bash
dns-sd -B _http._tcp
```
Cuando un servicio se inicia, anuncia su disponibilidad a todos los dispositivos en la subred mediante la difusión de su presencia. Los dispositivos interesados en estos servicios no necesitan enviar solicitudes, sino simplemente escuchar estas notificaciones.

Para una interfaz más amigable para el usuario, la aplicación ****Discovery - DNS-SD Browser** disponible en la App Store de Apple puede visualizar los servicios ofrecidos en su red local.

Alternativamente, se pueden escribir scripts personalizados para explorar y descubrir servicios utilizando la biblioteca `python-zeroconf`. El script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) demuestra la creación de un navegador de servicios para servicios `_http._tcp.local.`, imprimiendo servicios añadidos o eliminados:
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
### Deshabilitar Bonjour
Si existen preocupaciones sobre la seguridad u otras razones para deshabilitar Bonjour, se puede apagar usando el siguiente comando:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Referencias

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
