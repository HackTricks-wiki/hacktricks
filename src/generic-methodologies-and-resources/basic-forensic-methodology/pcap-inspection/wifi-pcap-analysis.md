# Análisis de Pcap de Wifi

{{#include ../../../banners/hacktricks-training.md}}

## Comprobar BSSID

Con una captura de Wi-Fi abierta en Wireshark, selecciona _Wireless → WLAN Traffic_ para resumir las redes inalámbricas observadas en la captura; cada fila representa una red inalámbrica.<sup>[[1]](#references)</sup>

![Wifi Pcap Analysis - Check BSSIDs: When you receive a capture whose principal traffic is Wifi using WireShark you can start investigating all the SSIDs of the capture with Wireless --...](<../../../images/image (106).png>)

![Wifi Pcap Analysis - Check BSSIDs: When you receive a capture whose principal traffic is Wifi using WireShark you can start investigating all the SSIDs of the capture with Wireless --...](<../../../images/image (492).png>)

### Brute Force

Para capturas WPA/WPA2-PSK, `aircrack-ng` requiere un handshake EAPOL de cuatro vías utilizable y prueba frases de contraseña candidatas con un diccionario. Usa `-w` para proporcionar la wordlist y `-b` para indicar el BSSID del punto de acceso:<sup>[[2]](#references)</sup>

```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```

Si hay una coincidencia, Aircrack-ng recupera la clave precompartida; luego, si la captura y el modo de seguridad lo permiten, puedes configurar la contraseña y el SSID coincidentes en los ajustes de descifrado 802.11 de Wireshark.<sup>[[2]](#references)[[5]](#references)</sup>

## Datos en beacons / canal lateral

Si sospechas que **se están filtrando datos mediante tráfico de canal lateral en beacons**, empieza con un filtro de visualización como `wlan contains "NAMEofNETWORK"` o `wlan.ssid == "NAMEofNETWORK"` y luego inspecciona las tramas coincidentes para encontrar cadenas sospechosas. La primera forma busca bytes de manera amplia; la segunda coincide con el campo SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Encontrar direcciones MAC desconocidas en una red Wi-Fi

Wireshark expone `wlan.ta` como la dirección del transmisor y `wlan.addr` como una dirección de hardware/MAC; los filtros de visualización pueden combinar estos campos con operadores lógicos:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Si ya conoces **direcciones MAC, elimínalas de los resultados** agregando comprobaciones como `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Una vez que hayas detectado direcciones **MAC desconocidas** que se comunican dentro de la red, usa un filtro como `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` para limitar el tráfico. Los filtros FTP, HTTP, SSH y Telnet solo son útiles cuando Wireshark puede diseccionar la carga útil descifrada correspondiente.<sup>[[3]](#references)[[5]](#references)</sup>

## Descifrar tráfico

Para añadir una clave de descifrado 802.11 en Wireshark, abre _Edit → Preferences → Protocols → IEEE 802.11_ y haz clic en _Edit_ junto a _Decryption Keys_.<sup>[[5]](#references)</sup>

![Encontrar direcciones MAC desconocidas en una red Wi-Fi - Descifrar tráfico: Una vez que hayas detectado direcciones MAC desconocidas que se comunican dentro de la red, puedes usar filtros como el siguiente:...](<../../../images/image (499).png>)

Para WPA/WPA2, Wireshark normalmente necesita el handshake de cuatro vías EAPOL y la contraseña/SSID correspondientes; proporcionar la clave transitoria puede evitar el requisito del handshake. El descifrado de WPA3 por conexión requiere la PMK de la conexión.<sup>[[5]](#references)</sup>

Para descifrar TLS de la capa de aplicación después de recuperar el tráfico Wi-Fi, consulta [Trucos de Wireshark](wireshark-tricks.md#decrypting-tls).

## References

- [1] [Guía del usuario de Wireshark: tráfico WLAN](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Guía del usuario de Wireshark: creación de expresiones de filtros de visualización](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Referencia de filtros de visualización de Wireshark: LAN inalámbrica IEEE 802.11](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Guía del usuario de Wireshark: claves de descifrado WLAN IEEE 802.11](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
