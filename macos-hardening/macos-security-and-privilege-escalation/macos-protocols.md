# Servicios y Protocolos de Red en macOS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Servicios de Acceso Remoto

Estos son los servicios comunes de macOS para acceder a ellos de forma remota.\
Puedes habilitar/deshabilitar estos servicios en `Configuración del Sistema` --> `Compartir`

* **VNC**, conocido como "Compartir Pantalla" (tcp:5900)
* **SSH**, llamado "Acceso Remoto" (tcp:22)
* **Apple Remote Desktop** (ARD), o "Gestión Remota" (tcp:3283, tcp:5900)
* **AppleEvent**, conocido como "Evento Apple Remoto" (tcp:3031)

Comprueba si alguno está habilitado ejecutando:
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

(Esta parte fue [**tomada de este post de blog**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html))

Es esencialmente un [VNC](https://en.wikipedia.org/wiki/Virtual\_Network\_Computing) modificado con algunas **características específicas de macOS**.\
Sin embargo, la **opción de Compartir Pantalla** es solo un servidor **VNC básico**. También hay una opción avanzada de ARD o Gestión Remota para **establecer una contraseña de control de pantalla** que hará que ARD sea **compatible hacia atrás con clientes VNC**. Sin embargo, hay una debilidad en este método de autenticación que **limita** esta **contraseña** a un **buffer de autenticación de 8 caracteres**, lo que la hace muy fácil de **fuerza bruta** con una herramienta como [Hydra](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) o [GoRedShell](https://github.com/ahhh/GoRedShell/) (también **no hay límites de tasa por defecto**).\
Puedes identificar **instancias vulnerables de Compartir Pantalla** o Gestión Remota con **nmap**, usando el script `vnc-info`, y si el servicio soporta `Autenticación VNC (2)` entonces es probable que sean **vulnerables a fuerza bruta**. El servicio truncará todas las contraseñas enviadas por la red a 8 caracteres, de tal manera que si estableces la autenticación VNC a "password", tanto "passwords" como "password123" se autenticarán.

<figure><img src="../../.gitbook/assets/image (9) (3).png" alt=""><figcaption></figcaption></figure>

Si quieres habilitarlo para escalar privilegios (aceptar promociones TCC), acceder con una GUI o espiar al usuario, es posible habilitarlo con:

{% code overflow="wrap" %}
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
{% endcode %}

Puedes alternar entre el modo de **observación**, **control compartido** y **control total**, pasando de espiar a un usuario a tomar control de su escritorio con solo hacer clic. Además, si obtienes acceso a una sesión de ARD, esa sesión permanecerá abierta hasta que se termine, incluso si la contraseña del usuario cambia durante la sesión.

También puedes **enviar comandos unix directamente** a través de ARD y puedes especificar al usuario root para ejecutar cosas como root si eres un usuario administrativo. Incluso puedes usar este método de comandos unix para programar tareas remotas para que se ejecuten en un momento específico, sin embargo, esto ocurre como una conexión de red en el tiempo especificado (en lugar de almacenarse y ejecutarse en el servidor objetivo). Finalmente, Spotlight remoto es una de mis características favoritas. Es realmente genial porque puedes realizar una búsqueda indexada de bajo impacto de forma rápida y remota. Esto es oro para buscar archivos sensibles porque es rápido, te permite realizar búsquedas concurrentemente en múltiples máquinas y no aumentará el uso de la CPU.

## Protocolo Bonjour

**Bonjour** es una tecnología diseñada por Apple que permite a computadoras y **dispositivos ubicados en la misma red conocer los servicios ofrecidos** por otras computadoras y dispositivos. Está diseñado de tal manera que cualquier dispositivo consciente de Bonjour puede conectarse a una red TCP/IP y **elegirá una dirección IP** y hará que otras computadoras en esa red **sean conscientes de los servicios que ofrece**. A veces, Bonjour se conoce como Rendezvous, **Zero Configuration** o Zeroconf.\
La Red de Configuración Cero, como la que proporciona Bonjour, requiere:

* Debe poder **obtener una Dirección IP** (incluso sin un servidor DHCP)
* Debe poder realizar la **traducción de nombre a dirección** (incluso sin un servidor DNS)
* Debe poder **descubrir servicios en la red**

El dispositivo obtendrá una **dirección IP en el rango 169.254/16** y verificará si algún otro dispositivo está usando esa dirección IP. Si no es así, mantendrá la dirección IP. Los Macs mantienen una entrada en su tabla de enrutamiento para esta subred: `netstat -rn | grep 169`

Para DNS se utiliza el **protocolo Multicast DNS (mDNS)**. [**Los servicios mDNS** escuchan en el puerto **5353/UDP**](../../network-services-pentesting/5353-udp-multicast-dns-mdns.md), utilizan **consultas DNS regulares** y usan la **dirección multicast 224.0.0.251** en lugar de enviar la solicitud solo a una dirección IP. Cualquier máquina que escuche estas solicitudes responderá, generalmente a una dirección multicast, para que todos los dispositivos puedan actualizar sus tablas.\
Cada dispositivo **seleccionará su propio nombre** al acceder a la red, el dispositivo elegirá un nombre **terminado en .local** (puede basarse en el nombre de host o ser uno completamente aleatorio).

Para **descubrir servicios se utiliza DNS Service Discovery (DNS-SD)**.

El requisito final de la Red de Configuración Cero se cumple con **DNS Service Discovery (DNS-SD)**. DNS Service Discovery utiliza la sintaxis de los registros SRV de DNS, pero usa **registros PTR de DNS para que se puedan devolver múltiples resultados** si más de un host ofrece un servicio en particular. Un cliente solicita la búsqueda PTR para el nombre `<Service>.<Domain>` y **recibe** una lista de cero o más registros PTR en la forma `<Instance>.<Service>.<Domain>`.

El binario `dns-sd` se puede usar para **anunciar servicios y realizar búsquedas** de servicios:
```bash
#Search ssh services
dns-sd -B _ssh._tcp

Browsing for _ssh._tcp
DATE: ---Tue 27 Jul 2021---
12:23:20.361  ...STARTING...
Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
12:23:20.362  Add        3   1 local.               _ssh._tcp.           M-C02C934RMD6R
12:23:20.362  Add        3  10 local.               _ssh._tcp.           M-C02C934RMD6R
12:23:20.362  Add        2  16 local.               _ssh._tcp.           M-C02C934RMD6R
```

```bash
#Announce HTTP service
dns-sd -R "Index" _http._tcp . 80 path=/index.html

#Search HTTP services
dns-sd -B _http._tcp
```
Cuando se inicia un nuevo servicio, **el nuevo servicio transmite su presencia a todos** en la subred. El oyente no tuvo que preguntar; solo tenía que estar escuchando.

Puedes usar [**esta herramienta**](https://apps.apple.com/us/app/discovery-dns-sd-browser/id1381004916?mt=12) para ver los **servicios ofrecidos** en tu red local actual.\
O puedes escribir tus propios scripts en python con [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf):
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
Si crees que Bonjour podría estar más seguro **deshabilitado**, puedes hacerlo con:
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

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
