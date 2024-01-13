<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Verificar BSSIDs

Cuando recibes una captura cuyo tráfico principal es Wifi usando WireShark, puedes comenzar a investigar todos los SSIDs de la captura con _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Fuerza Bruta

Una de las columnas de esa pantalla indica si **se encontró alguna autenticación dentro del pcap**. Si ese es el caso, puedes intentar hacer Fuerza Bruta usando `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Por ejemplo, recuperará la frase de contraseña WPA que protege una PSK (clave precompartida), que será necesaria para descifrar el tráfico más tarde.

# Datos en Beacons / Canal Lateral

Si sospechas que **datos están siendo filtrados dentro de los beacons de una red Wifi** puedes verificar los beacons de la red usando un filtro como el siguiente: `wlan contains <NAMEofNETWORK>`, o `wlan.ssid == "NAMEofNETWORK"` busca dentro de los paquetes filtrados cadenas sospechosas.

# Encontrar Direcciones MAC Desconocidas en Una Red Wifi

El siguiente enlace será útil para encontrar las **máquinas enviando datos dentro de una Red Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Si ya conoces **direcciones MAC puedes eliminarlas de la salida** añadiendo comprobaciones como esta: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Una vez que hayas detectado direcciones **MAC desconocidas** comunicándose dentro de la red puedes usar **filtros** como el siguiente: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` para filtrar su tráfico. Nota que los filtros ftp/http/ssh/telnet son útiles si has descifrado el tráfico.

# Descifrar Tráfico

Editar --> Preferencias --> Protocolos --> IEEE 802.11--> Editar

![](<../../../.gitbook/assets/image (426).png>)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en github.

</details>
