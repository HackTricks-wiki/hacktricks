# Análisis de Pcap de WiFi

## Comprobar los BSSID

Con una captura de Wi-Fi abierta en Wireshark, selecciona _Wireless → WLAN Traffic_ para resumir las redes inalámbricas observadas en la captura; cada fila representa una red inalámbrica.<sup>[[1]](#references)</sup>

![Análisis de Pcap de WiFi - Comprobar BSSID: Cuando recibes una captura cuyo tráfico principal es WiFi usando WireShark, puedes comenzar a investigar todos los SSID de la captura con Wireless --...](<../../../images/image (106).png>)

![Análisis de Pcap de WiFi - Comprobar BSSID: Cuando recibes una captura cuyo tráfico principal es WiFi usando WireShark, puedes comenzar a investigar todos los SSID de la captura con Wireless --...](<../../../images/image (492).png>)

### Fuerza bruta

Para capturas WPA/WPA2-PSK, `aircrack-ng` requiere un handshake EAPOL de cuatro vías utilizable y prueba las frases de contraseña candidatas con un diccionario. Usa `-w` para proporcionar la wordlist y `-b` para establecer como objetivo el BSSID del access point:<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Si coincide un candidato, Aircrack-ng recupera la clave precompartida; la contraseña y el SSID coincidentes pueden configurarse entonces en los ajustes de descifrado 802.11 de Wireshark cuando la captura y el modo de seguridad lo permitan.<sup>[[2]](#references)[[5]](#references)</sup>

## Datos en Beacons / Side Channel

Si sospechas que **se están filtrando datos en el tráfico de beacon-side-channel**, comienza con un display filter como `wlan contains "NAMEofNETWORK"` o `wlan.ssid == "NAMEofNETWORK"`, y después inspecciona los frames coincidentes en busca de cadenas sospechosas. La primera forma realiza una búsqueda amplia de bytes; la segunda coincide con el campo SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Encontrar direcciones MAC desconocidas en una red Wi-Fi

Wireshark expone `wlan.ta` como la dirección del transmisor y `wlan.addr` como una dirección de hardware/MAC; los display filters pueden combinar estos campos con operadores lógicos:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Si ya conoces **las direcciones MAC, elimínalas de la salida** añadiendo comprobaciones como `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Una vez que hayas detectado direcciones **MAC desconocidas** comunicándose dentro de la red, utiliza un filtro como `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` para limitar su tráfico. Los filtros FTP, HTTP, SSH y Telnet solo son útiles cuando Wireshark puede diseccionar el payload descifrado correspondiente.<sup>[[3]](#references)[[5]](#references)</sup>

## Descifrar tráfico

Para añadir una clave de descifrado 802.11 en Wireshark, abre _Edit → Preferences → Protocols → IEEE 802.11_ y haz clic en _Edit_ junto a _Decryption Keys_.<sup>[[5]](#references)</sup>

![Encontrar direcciones MAC desconocidas en una red Wi-Fi - Descifrar tráfico: una vez que hayas detectado direcciones MAC desconocidas comunicándose dentro de la red, puedes utilizar filtros como el siguiente:...](<../../../images/image (499).png>)

Para WPA/WPA2, Wireshark normalmente necesita el handshake de cuatro vías EAPOL y la contraseña/SSID coincidentes; proporcionar la clave transitoria puede evitar el requisito del handshake. El descifrado por conexión de WPA3 requiere la PMK de la conexión.<sup>[[5]](#references)</sup>

## References

- [1] [Guía del usuario de Wireshark: tráfico WLAN](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Guía del usuario de Wireshark: creación de expresiones de display filters](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Referencia de display filters de Wireshark: IEEE 802.11 wireless LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Guía del usuario de Wireshark: claves de descifrado IEEE 802.11 WLAN](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
