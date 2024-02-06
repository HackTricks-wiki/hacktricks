# Trucos de Wireshark

## Trucos de Wireshark

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

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

![](<../../../.gitbook/assets/image (570).png>)

**Direcciones Resueltas**

Bajo _**Statistics --> Resolved Addresses**_ puedes encontrar varias **informaciones** que fueron "**resueltas**" por Wireshark, como puerto/transporte a protocolo, MAC al fabricante, etc. Es interesante saber qué está implicado en la comunicación.

![](<../../../.gitbook/assets/image (571).png>)

**Jerarquía de Protocolos**

Bajo _**Statistics --> Protocol Hierarchy**_ puedes encontrar los **protocolos** **involucrados** en la comunicación y datos sobre ellos.

![](<../../../.gitbook/assets/image (572).png>)

**Conversaciones**

Bajo _**Statistics --> Conversations**_ puedes encontrar un **resumen de las conversaciones** en la comunicación y datos sobre ellas.

![](<../../../.gitbook/assets/image (573).png>)

**Puntos Finales**

Bajo _**Statistics --> Endpoints**_ puedes encontrar un **resumen de los puntos finales** en la comunicación y datos sobre cada uno de ellos.

![](<../../../.gitbook/assets/image (575).png>)

**Información de DNS**

Bajo _**Statistics --> DNS**_ puedes encontrar estadísticas sobre la solicitud de DNS capturada.

![](<../../../.gitbook/assets/image (577).png>)

**Gráfico de E/S**

Bajo _**Statistics --> I/O Graph**_ puedes encontrar un **gráfico de la comunicación**.

![](<../../../.gitbook/assets/image (574).png>)

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

Práctica: [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net)

## Identificación de Dominios

Puedes agregar una columna que muestre el encabezado Host HTTP:

![](<../../../.gitbook/assets/image (403).png>)

Y una columna que agregue el nombre del servidor desde una conexión HTTPS inicial (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identificación de nombres de host locales

### Desde DHCP

En el Wireshark actual en lugar de `bootp` debes buscar `DHCP`

![](<../../../.gitbook/assets/image (404).png>)

### Desde NBNS

![](<../../../.gitbook/assets/image (405).png>)

## Descifrado de TLS

### Descifrar tráfico https con la clave privada del servidor

_editar>preferencias>protocolo>ssl>_

![](<../../../.gitbook/assets/image (98).png>)

Presiona _Editar_ y agrega todos los datos del servidor y la clave privada (_IP, Puerto, Protocolo, Archivo de clave y contraseña_)

### Descifrar tráfico https con claves de sesión simétricas

Resulta que tanto Firefox como Chrome admiten registrar la clave de sesión simétrica utilizada para cifrar el tráfico TLS en un archivo. Luego puedes apuntar Wireshark a dicho archivo y ¡listo! tráfico TLS descifrado. Más en: [https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)\
Para detectar esto, busca dentro del entorno la variable `SSLKEYLOGFILE`

Un archivo de claves compartidas se verá así:

![](<../../../.gitbook/assets/image (99).png>)

Para importar esto en Wireshark ve a \_editar > preferencias > protocolo > ssl > e impórtalo en (Pre)-Master-Secret log filename:

![](<../../../.gitbook/assets/image (100).png>)

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
<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
