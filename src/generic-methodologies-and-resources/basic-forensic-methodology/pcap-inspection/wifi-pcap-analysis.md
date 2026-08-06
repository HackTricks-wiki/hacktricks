# Análisis de Pcap de Wifi

{{#include ../../../banners/hacktricks-training.md}}

## Comprobar BSSID

Cuando recibas una captura cuyo tráfico principal sea Wifi, usando WireShark puedes empezar a investigar todos los SSID de la captura con _Wireless --> WLAN Traffic_:

![Análisis de Pcap de Wifi - Comprobar BSSID: Cuando recibas una captura cuyo tráfico principal sea Wifi, usando WireShark puedes empezar a investigar todos los SSID de la captura con Wireless --...](<../../../images/image (106).png>)

![Análisis de Pcap de Wifi - Comprobar BSSID: Cuando recibas una captura cuyo tráfico principal sea Wifi, usando WireShark puedes empezar a investigar todos los SSID de la captura con Wireless --...](<../../../images/image (492).png>)

### Brute Force

Una de las columnas de esa pantalla indica si **se encontró alguna autenticación dentro del pcap**. Si ese es el caso, puedes intentar hacer Brute Force usando `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Por ejemplo, recuperará la frase de contraseña WPA que protege una PSK (pre-shared key), necesaria para descifrar el tráfico posteriormente.

## Datos en Beacons / Side Channel

Si sospechas que se están **filtrando datos dentro de los beacons de una red Wifi**, puedes comprobar los beacons de la red usando un filtro como el siguiente: `wlan contains <NAMEofNETWORK>`, o `wlan.ssid == "NAMEofNETWORK"` y buscar cadenas sospechosas dentro de los paquetes filtrados.

## Encontrar direcciones MAC desconocidas en una red Wifi

El siguiente enlace será útil para encontrar las **máquinas que envían datos dentro de una red Wifi**:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Si ya conoces **direcciones MAC**, puedes eliminarlas de la salida añadiendo comprobaciones como esta: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Una vez que hayas detectado **direcciones MAC desconocidas** comunicándose dentro de la red, puedes usar **filtros** como el siguiente: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` para filtrar su tráfico. Ten en cuenta que los filtros ftp/http/ssh/telnet son útiles si has descifrado el tráfico.

## Descifrar tráfico

Editar --> Preferencias --> Protocolos --> IEEE 802.11--> Editar

![Encontrar direcciones MAC desconocidas en una red Wifi - Descifrar tráfico: Una vez que hayas detectado direcciones MAC desconocidas comunicándose dentro de la red, puedes usar filtros como el siguiente:...](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
