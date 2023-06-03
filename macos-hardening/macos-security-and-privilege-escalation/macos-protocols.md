# Servicios y protocolos de red de macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Servicios de acceso remoto

Estos son los servicios comunes de macOS para acceder a ellos de forma remota.\
Puedes habilitar/deshabilitar estos servicios en `Preferencias del sistema` --> `Compartir`

* **VNC**, conocido como "Compartir pantalla"
* **SSH**, llamado "Inicio de sesión remoto"
* **Apple Remote Desktop** (ARD), o "Administración remota"
* **AppleEvent**, conocido como "Evento remoto de Apple"

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
## Protocolo Bonjour

**Bonjour** es una tecnología diseñada por Apple que permite a las computadoras y **dispositivos ubicados en la misma red conocer los servicios ofrecidos** por otras computadoras y dispositivos. Está diseñado de tal manera que cualquier dispositivo compatible con Bonjour puede conectarse a una red TCP/IP y **elegir una dirección IP** y hacer que otras computadoras en esa red **conozcan los servicios que ofrece**. A veces se hace referencia a Bonjour como Rendezvous, **Zero Configuration** o Zeroconf.\
La Red de Configuración Cero, como la que proporciona Bonjour, ofrece:

* Debe ser capaz de **obtener una dirección IP** (incluso sin un servidor DHCP)
* Debe ser capaz de hacer **traducción de nombres a direcciones** (incluso sin un servidor DNS)
* Debe ser capaz de **descubrir servicios en la red**

El dispositivo obtendrá una **dirección IP en el rango 169.254/16** y comprobará si algún otro dispositivo está utilizando esa dirección IP. Si no, mantendrá la dirección IP. Los Mac mantienen una entrada en su tabla de enrutamiento para esta subred: `netstat -rn | grep 169`

Para DNS se utiliza el **protocolo Multicast DNS (mDNS)**. [**Los servicios mDNS** escuchan en el puerto **5353/UDP**](../../network-services-pentesting/5353-udp-multicast-dns-mdns.md), utilizan **consultas DNS regulares** y utilizan la **dirección multicast 224.0.0.251** en lugar de enviar la solicitud solo a una dirección IP. Cualquier máquina que escuche estas solicitudes responderá, generalmente a una dirección multicast, para que todos los dispositivos puedan actualizar sus tablas.\
Cada dispositivo **seleccionará su propio nombre** al acceder a la red, el dispositivo elegirá un nombre **que termine en .local** (puede basarse en el nombre del host o ser completamente aleatorio).

Para **descubrir servicios se utiliza el Descubrimiento de Servicios DNS (DNS-SD)**.

El requisito final de la Red de Configuración Cero se cumple mediante el **Descubrimiento de Servicios DNS (DNS-SD)**. El Descubrimiento de Servicios DNS utiliza la sintaxis de los registros SRV de DNS, pero utiliza **registros PTR de DNS para que se puedan devolver múltiples resultados** si más de un host ofrece un servicio en particular. Un cliente solicita la búsqueda PTR para el nombre `<Servicio>.<Dominio>` y **recibe** una lista de cero o más registros PTR de la forma `<Instancia>.<Servicio>.<Dominio>`.

El binario `dns-sd` se puede utilizar para **anunciar servicios y realizar búsquedas** de servicios:
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
Cuando se inicia un nuevo servicio, **el nuevo servicio difunde su presencia a todos** en la subred. El oyente no tuvo que preguntar; solo tenía que estar escuchando.

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
Si sientes que Bonjour podría ser más seguro **desactivado**, puedes hacerlo con:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Referencias

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
