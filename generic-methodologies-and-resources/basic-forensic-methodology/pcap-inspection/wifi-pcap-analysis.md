# Análisis de Wifi Pcap

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Verificar BSSIDs

Cuando recibes una captura cuyo tráfico principal es Wifi utilizando WireShark, puedes comenzar investigando todos los SSIDs de la captura con _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (106).png>)

![](<../../../.gitbook/assets/image (492).png>)

### Fuerza Bruta

Una de las columnas de esa pantalla indica si se encontró **alguna autenticación dentro del pcap**. Si ese es el caso, puedes intentar realizar un ataque de fuerza bruta utilizando `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
## Datos en Beacons / Canal Lateral

Si sospechas que **los datos se están filtrando dentro de los beacons de una red Wifi**, puedes verificar los beacons de la red usando un filtro como el siguiente: `wlan contains <NOMBREdeRED>`, o `wlan.ssid == "NOMBREdeRED"` busca dentro de los paquetes filtrados cadenas sospechosas.

## Encontrar Direcciones MAC Desconocidas en una Red Wifi

El siguiente enlace será útil para encontrar las **máquinas que envían datos dentro de una Red Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Si ya conoces las **direcciones MAC, puedes eliminarlas del resultado** agregando comprobaciones como esta: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Una vez que hayas detectado **direcciones MAC desconocidas** comunicándose dentro de la red, puedes usar **filtros** como el siguiente: `wlan.addr==<dirección MAC> && (ftp || http || ssh || telnet)` para filtrar su tráfico. Ten en cuenta que los filtros ftp/http/ssh/telnet son útiles si has descifrado el tráfico.

## Descifrar Tráfico

Editar --> Preferencias --> Protocolos --> IEEE 802.11 --> Editar

![](<../../../.gitbook/assets/image (499).png>)

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
