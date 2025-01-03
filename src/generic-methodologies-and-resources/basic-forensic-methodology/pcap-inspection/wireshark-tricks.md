# Trucos de Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Mejora tus habilidades en Wireshark

### Tutoriales

Los siguientes tutoriales son increíbles para aprender algunos trucos básicos geniales:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Información Analizada

**Información Experta**

Al hacer clic en _**Analizar** --> **Información Experta**_ tendrás una **visión general** de lo que está sucediendo en los paquetes **analizados**:

![](<../../../images/image (256).png>)

**Direcciones Resueltas**

Bajo _**Estadísticas --> Direcciones Resueltas**_ puedes encontrar varias **informaciones** que fueron "**resueltas**" por Wireshark, como puerto/transporte a protocolo, MAC al fabricante, etc. Es interesante saber qué está implicado en la comunicación.

![](<../../../images/image (893).png>)

**Jerarquía de Protocolos**

Bajo _**Estadísticas --> Jerarquía de Protocolos**_ puedes encontrar los **protocolos** **involucrados** en la comunicación y datos sobre ellos.

![](<../../../images/image (586).png>)

**Conversaciones**

Bajo _**Estadísticas --> Conversaciones**_ puedes encontrar un **resumen de las conversaciones** en la comunicación y datos sobre ellas.

![](<../../../images/image (453).png>)

**Puntos Finales**

Bajo _**Estadísticas --> Puntos Finales**_ puedes encontrar un **resumen de los puntos finales** en la comunicación y datos sobre cada uno de ellos.

![](<../../../images/image (896).png>)

**Información DNS**

Bajo _**Estadísticas --> DNS**_ puedes encontrar estadísticas sobre la solicitud DNS capturada.

![](<../../../images/image (1063).png>)

**Gráfico I/O**

Bajo _**Estadísticas --> Gráfico I/O**_ puedes encontrar un **gráfico de la comunicación.**

![](<../../../images/image (992).png>)

### Filtros

Aquí puedes encontrar filtros de Wireshark dependiendo del protocolo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Otros filtros interesantes:

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- Tráfico HTTP y HTTPS inicial
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- Tráfico HTTP y HTTPS inicial + TCP SYN
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- Tráfico HTTP y HTTPS inicial + TCP SYN + solicitudes DNS

### Búsqueda

Si deseas **buscar** **contenido** dentro de los **paquetes** de las sesiones, presiona _CTRL+f_. Puedes agregar nuevas capas a la barra de información principal (No., Hora, Origen, etc.) presionando el botón derecho y luego editando la columna.

### Laboratorios pcap gratuitos

**Practica con los desafíos gratuitos de:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identificación de Dominios

Puedes agregar una columna que muestre el encabezado HTTP del Host:

![](<../../../images/image (639).png>)

Y una columna que agregue el nombre del Servidor de una conexión HTTPS iniciada (**ssl.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

## Identificación de nombres de host locales

### Desde DHCP

En la versión actual de Wireshark, en lugar de `bootp`, necesitas buscar `DHCP`

![](<../../../images/image (1013).png>)

### Desde NBNS

![](<../../../images/image (1003).png>)

## Desencriptación de TLS

### Desencriptación del tráfico https con la clave privada del servidor

_edit>preferencia>protocolo>ssl>_

![](<../../../images/image (1103).png>)

Presiona _Editar_ y agrega todos los datos del servidor y la clave privada (_IP, Puerto, Protocolo, Archivo de clave y contraseña_)

### Desencriptación del tráfico https con claves de sesión simétricas

Tanto Firefox como Chrome tienen la capacidad de registrar claves de sesión TLS, que se pueden usar con Wireshark para desencriptar el tráfico TLS. Esto permite un análisis profundo de las comunicaciones seguras. Más detalles sobre cómo realizar esta desencriptación se pueden encontrar en una guía en [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Para detectar esto, busca dentro del entorno la variable `SSLKEYLOGFILE`

Un archivo de claves compartidas se verá así:

![](<../../../images/image (820).png>)

Para importar esto en Wireshark, ve a _editar > preferencia > protocolo > ssl > e impórtalo en (Pre)-Master-Secret log filename:

![](<../../../images/image (989).png>)

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
{{#include ../../../banners/hacktricks-training.md}}
