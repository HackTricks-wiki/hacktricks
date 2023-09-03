# FZ - NFC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra las vulnerabilidades que más importan para que puedas solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en toda tu pila tecnológica, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Introducción <a href="#9wrzi" id="9wrzi"></a>

Para obtener información sobre RFID y NFC, consulta la siguiente página:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Tarjetas NFC compatibles <a href="#9wrzi" id="9wrzi"></a>

{% hint style="danger" %}
Además de las tarjetas NFC, Flipper Zero admite **otros tipos de tarjetas de alta frecuencia** como varias tarjetas **Mifare** Classic y Ultralight y **NTAG**.
{% endhint %}

Se agregarán nuevos tipos de tarjetas NFC a la lista de tarjetas compatibles. Flipper Zero admite los siguientes **tipos de tarjetas NFC tipo A** (ISO 14443A):

* ﻿**Tarjetas bancarias (EMV)**: solo lee UID, SAK y ATQA sin guardar.
* ﻿**Tarjetas desconocidas**: lee (UID, SAK, ATQA) y emula un UID.

Para las **tarjetas NFC tipo B, tipo F y tipo V**, Flipper Zero puede leer un UID sin guardarlo.

### Tarjetas NFC tipo A <a href="#uvusf" id="uvusf"></a>

#### Tarjeta bancaria (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero solo puede leer un UID, SAK, ATQA y datos almacenados en tarjetas bancarias **sin guardar**.

Pantalla de lectura de tarjeta bancariaPara las tarjetas bancarias, Flipper Zero solo puede leer datos **sin guardar y sin emularlos**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Tarjetas desconocidas <a href="#37eo8" id="37eo8"></a>

Cuando Flipper Zero es **incapaz de determinar el tipo de tarjeta NFC**, solo se puede **leer y guardar** un **UID, SAK y ATQA**.

Pantalla de lectura de tarjeta desconocidaPara las tarjetas NFC desconocidas, Flipper Zero solo puede emular un UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Tarjetas NFC tipo B, F y V <a href="#wyg51" id="wyg51"></a>

Para las **tarjetas NFC tipo B, tipo F y tipo V**, Flipper Zero solo puede **leer y mostrar un UID** sin guardarlo.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Acciones

Para obtener una introducción sobre NFC, [**lee esta página**](../../../radio-hacking/pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Leer

Flipper Zero puede **leer tarjetas NFC**, sin embargo, **no comprende todos los protocolos** basados en ISO 14443. Sin embargo, dado que el **UID es un atributo de bajo nivel**, es posible que te encuentres en una situación en la que el **UID ya se haya leído, pero el protocolo de transferencia de datos de alto nivel aún sea desconocido**. Puedes leer, emular e ingresar manualmente el UID utilizando Flipper para los lectores primitivos que utilizan el UID para la autorización.
#### Lectura del UID vs Lectura de los Datos Internos <a href="#lectura-del-uid-vs-lectura-de-los-datos-internos" id="lectura-del-uid-vs-lectura-de-los-datos-internos"></a>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

En Flipper, la lectura de etiquetas de 13.56 MHz se puede dividir en dos partes:

* **Lectura de bajo nivel** - lee solo el UID, SAK y ATQA. Flipper intenta adivinar el protocolo de alto nivel basado en estos datos leídos de la tarjeta. No se puede estar 100% seguro de esto, ya que es solo una suposición basada en ciertos factores.
* **Lectura de alto nivel** - lee los datos de la memoria de la tarjeta utilizando un protocolo de alto nivel específico. Esto sería leer los datos en una Mifare Ultralight, leer los sectores de una Mifare Classic o leer los atributos de la tarjeta de PayPass/Apple Pay.

### Lectura Específica

En caso de que Flipper Zero no sea capaz de encontrar el tipo de tarjeta a partir de los datos de bajo nivel, en `Acciones Extra` puedes seleccionar `Leer Tipo de Tarjeta Específico` e **indicar manualmente el tipo de tarjeta que deseas leer**.

#### Tarjetas Bancarias EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#tarjetas-bancarias-emv-paypass-paywave-apple-pay-google-pay" id="tarjetas-bancarias-emv-paypass-paywave-apple-pay-google-pay"></a>

Además de simplemente leer el UID, puedes extraer muchos más datos de una tarjeta bancaria. Es posible **obtener el número completo de la tarjeta** (los 16 dígitos en la parte frontal de la tarjeta), la **fecha de validez** e incluso en algunos casos el **nombre del propietario** junto con una lista de las **transacciones más recientes**.\
Sin embargo, no puedes leer el CVV de esta manera (los 3 dígitos en la parte posterior de la tarjeta). Además, las tarjetas bancarias están protegidas contra ataques de reproducción, por lo que copiarla con Flipper y luego intentar emularla para pagar algo no funcionará.

## Referencias

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra las vulnerabilidades que más importan para que puedas solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos de amenazas proactivos, encuentra problemas en toda tu pila tecnológica, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy mismo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
