# Análisis de Pcap Wi-Fi

{{#include ../../../banners/hacktricks-training.md}}

## Comprobar los BSSID

Con una captura de Wi-Fi abierta en Wireshark, selecciona _Wireless → WLAN Traffic_ para resumir las redes inalámbricas observadas en la captura; cada fila representa una red inalámbrica.<sup>[[1]](#references)</sup>

![Análisis de Pcap Wi-Fi - Comprobar los BSSID: Cuando recibes una captura cuyo tráfico principal es Wi-Fi usando WireShark, puedes comenzar a investigar todos los SSID de la captura con Wireless --...](<../../../images/image (106).png>)

![Análisis de Pcap Wi-Fi - Comprobar los BSSID: Cuando recibes una captura cuyo tráfico principal es Wi-Fi usando WireShark, puedes comenzar a investigar todos los SSID de la captura con Wireless --...](<../../../images/image (492).png>)

### Brute Force

Para capturas WPA/WPA2-PSK, `aircrack-ng` requiere un handshake EAPOL de cuatro vías utilizable y prueba frases de contraseña candidatas con un diccionario. Usa `-w` para proporcionar la wordlist y `-b` para dirigirte al BSSID del access point:<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Si un candidato coincide, Aircrack-ng recupera la clave precompartida; la contraseña y el SSID coincidentes se pueden configurar entonces en los ajustes de descifrado 802.11 de Wireshark cuando la captura y el modo de seguridad lo admiten.<sup>[[2]](#references)[[5]](#references)</sup>

## Datos en Beacons / Side Channel

Si sospechas que **se están filtrando datos en el tráfico del beacon-side-channel**, empieza con un filtro de visualización como `wlan contains "NAMEofNETWORK"` o `wlan.ssid == "NAMEofNETWORK"`, y luego inspecciona los frames coincidentes en busca de cadenas sospechosas. La primera forma realiza una búsqueda amplia de bytes; la segunda coincide con el campo SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Encontrar direcciones MAC desconocidas en una red Wi-Fi

Wireshark expone `wlan.ta` como la dirección del transmisor y `wlan.addr` como una dirección de hardware/MAC; los filtros de visualización pueden combinar estos campos con operadores lógicos:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Si ya conoces **las direcciones MAC, elimínalas de la salida** añadiendo comprobaciones como `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Una vez detectadas **direcciones MAC desconocidas** comunicándose dentro de la red, utiliza un filtro como `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` para limitar su tráfico. Los filtros FTP, HTTP, SSH y Telnet solo son útiles cuando Wireshark puede diseccionar el payload descifrado correspondiente.<sup>[[3]](#references)[[5]](#references)</sup>

## Descifrar tráfico

Para añadir una clave de descifrado 802.11 en Wireshark, abre _Edit → Preferences → Protocols → IEEE 802.11_ y haz clic en _Edit_ junto a _Decryption Keys_.<sup>[[5]](#references)</sup>

![Encontrar direcciones MAC desconocidas en una red Wi-Fi - Descifrar tráfico: Una vez detectadas direcciones MAC desconocidas comunicándose dentro de la red, puedes utilizar filtros como el siguiente:...](<../../../images/image (499).png>)

Para WPA/WPA2, Wireshark normalmente necesita el handshake de cuatro vías EAPOL y la contraseña/SSID coincidentes; proporcionar la clave transitoria puede evitar el requisito del handshake. El descifrado por conexión de WPA3 requiere la PMK de la conexión.<sup>[[5]](#references)</sup>

## References

- [1] [Guía del usuario de Wireshark: tráfico WLAN](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Guía del usuario de Wireshark: creación de expresiones de filtros de visualización](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Referencia de filtros de visualización de Wireshark: LAN inalámbrica IEEE 802.11](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Guía del usuario de Wireshark: claves de descifrado WLAN IEEE 802.11](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
