# FZ - NFC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com).
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introducción <a href="#9wrzi" id="9wrzi"></a>

Para obtener información sobre RFID y NFC, consulte la siguiente página:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Tarjetas NFC compatibles <a href="#9wrzi" id="9wrzi"></a>

{% hint style="danger" %}
Además de las tarjetas NFC, Flipper Zero admite **otros tipos de tarjetas de alta frecuencia** como varias tarjetas **Mifare** Classic y Ultralight y **NTAG**.
{% endhint %}

Se agregarán nuevos tipos de tarjetas NFC a la lista de tarjetas compatibles admitidas. Flipper Zero admite los siguientes **tipos de tarjetas NFC tipo A** (ISO 14443A):

* **Tarjetas bancarias (EMV)**: solo lee UID, SAK y ATQA sin guardar.
* **Tarjetas desconocidas**: lee (UID, SAK, ATQA) y emula un UID.

Para las **tarjetas NFC tipo B, tipo F y tipo V**, Flipper Zero puede leer un UID sin guardarlo.

### Tarjetas NFC tipo A <a href="#uvusf" id="uvusf"></a>

#### Tarjeta bancaria (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero solo puede leer un UID, SAK, ATQA y datos almacenados en tarjetas bancarias **sin guardar**.

Pantalla de lectura de tarjeta bancariaPara las tarjetas bancarias, Flipper Zero solo puede leer datos **sin guardar y emularlos**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Tarjetas desconocidas <a href="#37eo8" id="37eo8"></a>

Cuando Flipper Zero es **incapaz de determinar el tipo de tarjeta NFC**, solo se puede **leer y guardar** un **UID, SAK y ATQA**.

Pantalla de lectura de tarjeta desconocidaPara las tarjetas NFC desconocidas, Flipper Zero solo puede emular un UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Tarjetas NFC tipo B, tipo F y tipo V <a href="#wyg51" id="wyg51"></a>

Para las **tarjetas NFC tipo B, tipo F y tipo V**, Flipper Zero solo puede **leer y mostrar un UID** sin guardarlo.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Acciones

Para obtener una introducción sobre NFC, [**lea esta página**](../../../radio-hacking/pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Leer

Flipper Zero puede **leer tarjetas NFC**, sin embargo, **no entiende todos los protocolos** que se basan en ISO 14443. Sin embargo, dado que **UID es un atributo de bajo nivel**, es posible que se encuentre en una situación en la que **ya se haya leído el UID, pero el protocolo de transferencia de datos de alto nivel aún sea desconocido**. Puede leer, emular e ingresar manualmente el UID utilizando Flipper para los lectores primitivos que usan UID para la autorización.

#### Lectura del UID vs. Lectura de los datos internos <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

En Flipper, la lectura de etiquetas de 13,56 MHz se puede dividir en dos partes:

* **Lectura de bajo nivel** - lee solo el UID, SAK y ATQA. Flipper intenta
