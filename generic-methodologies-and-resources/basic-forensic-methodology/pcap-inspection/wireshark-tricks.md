# Trucos de Wireshark

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) es un motor de búsqueda alimentado por la **dark web** que ofrece funcionalidades **gratuitas** para verificar si una empresa o sus clientes han sido **comprometidos** por **malwares de robo**.

El objetivo principal de WhiteIntel es combatir los secuestros de cuentas y los ataques de ransomware resultantes de malwares que roban información.

Puedes visitar su sitio web y probar su motor de forma **gratuita** en:

{% embed url="https://whiteintel.io" %}

***

## Mejora tus habilidades en Wireshark

### Tutoriales

Los siguientes tutoriales son increíbles para aprender algunos trucos básicos geniales:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Información Analizada

**Información de Expertos**

Al hacer clic en _**Analyze** --> **Expert Information**_ tendrás una **visión general** de lo que está sucediendo en los paquetes **analizados**:

![](<../../../.gitbook/assets/image (256).png>)

**Direcciones Resueltas**

Bajo _**Statistics --> Resolved Addresses**_ puedes encontrar varias **informaciones** que fueron "**resueltas**" por Wireshark, como puerto/transporte a protocolo, MAC al fabricante, etc. Es interesante saber qué está implicado en la comunicación.

![](<../../../.gitbook/assets/image (893).png>)

**Jerarquía de Protocolos**

Bajo _**Statistics --> Protocol Hierarchy**_ puedes encontrar los **protocolos** **involucrados** en la comunicación y datos sobre ellos.

![](<../../../.gitbook/assets/image (586).png>)

**Conversaciones**

Bajo _**Statistics --> Conversations**_ puedes encontrar un **resumen de las conversaciones** en la comunicación y datos sobre ellas.

![](<../../../.gitbook/assets/image (453).png>)

**Puntos Finales**

Bajo _**Statistics --> Endpoints**_ puedes encontrar un **resumen de los puntos finales** en la comunicación y datos sobre cada uno de ellos.

![](<../../../.gitbook/assets/image (896).png>)

**Información de DNS**

Bajo _**Statistics --> DNS**_ puedes encontrar estadísticas sobre la solicitud de DNS capturada.

![](<../../../.gitbook/assets/image (1063).png>)

**Gráfico de E/S**

Bajo _**Statistics --> I/O Graph**_ puedes encontrar un **gráfico de la comunicación**.

![](<../../../.gitbook/assets/image (992).png>)

### Filtros

Aquí puedes encontrar filtros de Wireshark dependiendo del protocolo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Otros filtros interesantes:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* Tráfico HTTP e HTTPS inicial
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* Tráfico HTTP e HTTPS inicial + SYN TCP
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* Tráfico HTTP e HTTPS inicial + SYN TCP + solicitudes DNS

### Búsqueda

Si deseas **buscar** **contenido** dentro de los **paquetes** de las sesiones, presiona _CTRL+f_. Puedes agregar nuevas capas a la barra de información principal (N.º, Hora, Origen, etc.) presionando el botón derecho y luego editar columna.

### Laboratorios pcap gratuitos

**Practica con los desafíos gratuitos de:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identificación de Dominios

Puedes agregar una columna que muestre el encabezado Host HTTP:

![](<../../../.gitbook/assets/image (639).png>)

Y una columna que agregue el nombre del servidor desde una conexión HTTPS inicial (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identificación de nombres de host locales

### Desde DHCP

En el Wireshark actual en lugar de `bootp` debes buscar `DHCP`

![](<../../../.gitbook/assets/image (1013).png>)

### Desde NBNS

![](<../../../.gitbook/assets/image (1003).png>)

## Descifrado de TLS

### Descifrado de tráfico https con clave privada del servidor

_editar>preferencias>protocolo>ssl>_

![](<../../../.gitbook/assets/image (1103).png>)

Presiona _Editar_ y agrega todos los datos del servidor y la clave privada (_IP, Puerto, Protocolo, Archivo de clave y contraseña_)

### Descifrado de tráfico https con claves de sesión simétricas

Tanto Firefox como Chrome tienen la capacidad de registrar claves de sesión TLS, que pueden ser utilizadas con Wireshark para descifrar el tráfico TLS. Esto permite un análisis detallado de las comunicaciones seguras. Se puede encontrar más detalles sobre cómo realizar este descifrado en una guía en [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Para detectar esto, busca dentro del entorno la variable `SSLKEYLOGFILE`

Un archivo de claves compartidas se verá así:

![](<../../../.gitbook/assets/image (820).png>)

Para importar esto en Wireshark ve a \_editar > preferencias > protocolo > ssl > e impórtalo en (Pre)-Master-Secret log filename:

![](<../../../.gitbook/assets/image (989).png>)
## Comunicación ADB

Extraer un APK de una comunicación ADB donde se envió el APK:
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) es un motor de búsqueda alimentado por la **dark web** que ofrece funcionalidades **gratuitas** para verificar si una empresa o sus clientes han sido **comprometidos** por **malwares robadores**.

Su objetivo principal es combatir los secuestros de cuentas y los ataques de ransomware resultantes de malwares que roban información.

Puedes visitar su sitio web y probar su motor de búsqueda de forma **gratuita** en:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
