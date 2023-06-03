# Trucos de Wireshark

## Trucos de Wireshark

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Mejora tus habilidades en Wireshark

### Tutoriales

Los siguientes tutoriales son excelentes para aprender algunos trucos básicos interesantes:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Información analizada

**Información de expertos**

Al hacer clic en _**Analyze** --> **Expert Information**_ tendrás una **visión general** de lo que está sucediendo en los paquetes **analizados**:

![](<../../../.gitbook/assets/image (570).png>)

**Direcciones resueltas**

En _**Statistics --> Resolved Addresses**_ puedes encontrar varias **informaciones** que fueron "**resueltas**" por Wireshark, como el puerto/transporte al protocolo, la MAC al fabricante, etc. Es interesante saber qué está implicado en la comunicación.

![](<../../../.gitbook/assets/image (571).png>)

**Jerarquía de protocolos**

En _**Statistics --> Protocol Hierarchy**_ puedes encontrar los **protocolos** **involucrados** en la comunicación y datos sobre ellos.

![](<../../../.gitbook/assets/image (572).png>)

**Conversaciones**

En _**Statistics --> Conversations**_ puedes encontrar un **resumen de las conversaciones** en la comunicación y datos sobre ellas.

![](<../../../.gitbook/assets/image (573).png>)

**Puntos finales**

En _**Statistics --> Endpoints**_ puedes encontrar un **resumen de los puntos finales** en la comunicación y datos sobre cada uno de ellos.

![](<../../../.gitbook/assets/image (575).png>)

**Información DNS**

En _**Statistics --> DNS**_ puedes encontrar estadísticas sobre la solicitud DNS capturada.

![](<../../../.gitbook/assets/image (577).png>)

**Gráfico de E/S**

En _**Statistics --> I/O Graph**_ puedes encontrar un **gráfico de la comunicación**.

![](<../../../.gitbook/assets/image (574).png>)

### Filtros

Aquí puedes encontrar filtros de Wireshark según el protocolo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Otros filtros interesantes:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
  * Tráfico HTTP e inicial de HTTPS
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  * Tráfico HTTP e inicial de HTTPS + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  * Tráfico HTTP e inicial de HTTPS + TCP SYN + solicitudes DNS

### Búsqueda

Si deseas **buscar** **contenido** dentro de los **paquetes** de las sesiones, presiona _CTRL+f_. Puedes agregar nuevas capas a la barra de información principal (No., Tiempo, Origen, etc.) presionando el botón derecho y luego la opción de editar columna.

Práctica: [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net)

## Identificación de dominios

Puedes agregar una columna que muestre el encabezado Host HTTP:

![](<../../../.gitbook/assets/image (403).png>)

Y una columna que agregue el nombre del servidor desde una conexión HTTPS iniciada (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identificación de nombres de host locales

### Desde DHCP

En la versión actual de Wireshark, en lugar de `bootp`, debes buscar `DHCP`

![](<../../../.gitbook/assets/image (404).png>)

### Desde NBNS

![](<../../../.gitbook/assets/image (405).png>)

## Descifrando TLS

### Descifrando tráfico https con clave privada del servidor

_editar>preferencia>protocolo>ssl>_

![](<../../../.gitbook/assets/image (98).png>)

Presiona _Editar_ y agrega todos los datos del servidor y la clave privada (_IP, Puerto, Protocolo, Archivo de clave y contraseña_)

### Descifrando tráfico https con claves de sesión simétricas

Resulta que tanto Firefox como Chrome admiten registrar la clave de sesión simétrica utilizada para cifrar el tráfico TLS en un archivo. Luego puedes apuntar Wireshark a dicho archivo y ¡listo! tráfico TLS descifrado. Más en: [https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)\
Para detectar esto, busca dentro del entorno la variable `SSLKEYLOGFILE`

Un archivo de claves compartidas se verá así:

![](<../../../.gitbook/assets/image (99).png>)

Para importar esto en Wireshark, ve a \_editar > preferencia > protocolo > ssl > e impórtalo en (Pre)-Master-Secret log filename:

![](<../../../.gitbook/assets/image (100).png>)

## Comunicación ADB

Extrae un APK de una comunicación ADB donde se envió el APK:
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
