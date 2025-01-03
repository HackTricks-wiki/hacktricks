{{#include ../../../banners/hacktricks-training.md}}

# Verificar BSSIDs

Cuando recibas una captura cuyo tráfico principal es Wifi usando WireShark, puedes comenzar a investigar todos los SSIDs de la captura con _Wireless --> WLAN Traffic_:

![](<../../../images/image (424).png>)

![](<../../../images/image (425).png>)

## Fuerza Bruta

Una de las columnas de esa pantalla indica si **se encontró alguna autenticación dentro del pcap**. Si ese es el caso, puedes intentar forzarla usando `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Por ejemplo, recuperará la frase de paso WPA que protege un PSK (clave precompartida), que será necesaria para descifrar el tráfico más tarde.

# Datos en Beacons / Canal Lateral

Si sospechas que **los datos están siendo filtrados dentro de los beacons de una red Wifi**, puedes verificar los beacons de la red utilizando un filtro como el siguiente: `wlan contains <NAMEofNETWORK>`, o `wlan.ssid == "NAMEofNETWORK"` busca dentro de los paquetes filtrados cadenas sospechosas.

# Encontrar Direcciones MAC Desconocidas en una Red Wifi

El siguiente enlace será útil para encontrar las **máquinas que envían datos dentro de una Red Wifi**:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Si ya conoces **las direcciones MAC, puedes eliminarlas de la salida** añadiendo comprobaciones como esta: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Una vez que hayas detectado **direcciones MAC desconocidas** comunicándose dentro de la red, puedes usar **filtros** como el siguiente: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` para filtrar su tráfico. Ten en cuenta que los filtros ftp/http/ssh/telnet son útiles si has descifrado el tráfico.

# Desencriptar Tráfico

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![](<../../../images/image (426).png>)

{{#include ../../../banners/hacktricks-training.md}}
