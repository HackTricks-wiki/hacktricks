# Aplicaciones Defensivas para macOS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Firewalls

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Monitorea cada conexión realizada por cada proceso. Dependiendo del modo (permitir conexiones en silencio, denegar conexiones en silencio y alerta) te **mostrará una alerta** cada vez que se establezca una nueva conexión. También tiene una interfaz gráfica muy agradable para ver toda esta información.
* [**LuLu**](https://objective-see.org/products/lulu.html): Firewall de Objective-See. Es un firewall básico que te alertará sobre conexiones sospechosas (tiene una interfaz gráfica pero no es tan sofisticada como la de Little Snitch).

## Detección de persistencia

* [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplicación de Objective-See que buscará en varias ubicaciones donde el **malware podría estar persistiendo** (es una herramienta de un solo uso, no un servicio de monitoreo).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html): Como KnockKnock pero monitoreando procesos que generan persistencia.

## Detección de keyloggers

* [**ReiKey**](https://objective-see.org/products/reikey.html): Aplicación de Objective-See para encontrar **keyloggers** que instalan "event taps" de teclado.

## Detección de ransomware

* [**RansomWhere**](https://objective-see.org/products/ransomwhere.html): Aplicación de Objective-See para detectar acciones de **cifrado de archivos**.

## Detección de micrófono y cámara web

* [**OverSight**](https://objective-see.org/products/oversight.html): Aplicación de Objective-See para detectar **aplicaciones que comienzan a usar la cámara web y el micrófono**.

## Detección de inyección de procesos

* [**Shield**](https://theevilbit.github.io/shield/): Aplicación que **detecta diferentes técnicas de inyección de procesos**.

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
