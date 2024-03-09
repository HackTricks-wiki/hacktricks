# FZ - NFC

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introducción <a href="#9wrzi" id="9wrzi"></a>

Para obtener información sobre RFID y NFC, consulta la siguiente página:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Tarjetas NFC compatibles <a href="#9wrzi" id="9wrzi"></a>

{% hint style="danger" %}
Además de las tarjetas NFC, Flipper Zero admite **otros tipos de tarjetas de alta frecuencia** como varias tarjetas **Mifare** Classic y Ultralight y **NTAG**.
{% endhint %}

Se agregarán nuevos tipos de tarjetas NFC a la lista de tarjetas admitidas. Flipper Zero admite los siguientes **tipos de tarjetas NFC tipo A** (ISO 14443A):

* **Tarjetas bancarias (EMV)** — solo lee UID, SAK y ATQA sin guardar.
* **Tarjetas desconocidas** — lee (UID, SAK, ATQA) y emula un UID.

Para las **tarjetas NFC tipo B, tipo F y tipo V**, Flipper Zero puede leer un UID sin guardarlo.

### Tarjetas NFC tipo A <a href="#uvusf" id="uvusf"></a>

#### Tarjeta bancaria (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero solo puede leer un UID, SAK, ATQA y datos almacenados en tarjetas bancarias **sin guardar**.

Pantalla de lectura de tarjetas bancarias Para las tarjetas bancarias, Flipper Zero solo puede leer datos **sin guardarlos ni emularlos**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Tarjetas desconocidas <a href="#37eo8" id="37eo8"></a>

Cuando Flipper Zero es **incapaz de determinar el tipo de tarjeta NFC**, solo se puede **leer y guardar** un **UID, SAK y ATQA**.

Pantalla de lectura de tarjetas desconocidas Para las tarjetas NFC desconocidas, Flipper Zero solo puede emular un UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Tipos de tarjetas NFC B, F y V <a href="#wyg51" id="wyg51"></a>

Para los **tipos de tarjetas NFC B, F y V**, Flipper Zero solo puede **leer y mostrar un UID** sin guardarlo.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Acciones

Para una introducción sobre NFC [**lee esta página**](../../../radio-hacking/pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Leer

Flipper Zero puede **leer tarjetas NFC**, sin embargo, **no comprende todos los protocolos** basados en ISO 14443. Sin embargo, dado que el **UID es un atributo de bajo nivel**, podrías encontrarte en una situación en la que el **UID ya está leído, pero el protocolo de transferencia de datos de alto nivel sigue siendo desconocido**. Puedes leer, emular e introducir manualmente el UID usando Flipper para los lectores primitivos que utilizan el UID para la autorización.

#### Leer el UID VS Leer los Datos Internos <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

En Flipper, la lectura de etiquetas de 13.56 MHz se puede dividir en dos partes:

* **Lectura de bajo nivel** — lee solo el UID, SAK y ATQA. Flipper intenta adivinar el protocolo de alto nivel basado en estos datos leídos de la tarjeta. No se puede estar al 100% seguro con esto, ya que es solo una suposición basada en ciertos factores.
* **Lectura de alto nivel** — lee los datos de la memoria de la tarjeta utilizando un protocolo de alto nivel específico. Esto sería leer los datos en un Mifare Ultralight, leer los sectores de un Mifare Classic o leer los atributos de la tarjeta de PayPass/Apple Pay.

### Leer Específico

En caso de que Flipper Zero no sea capaz de encontrar el tipo de tarjeta a partir de los datos de bajo nivel, en `Acciones Extra` puedes seleccionar `Leer Tipo de Tarjeta Específico` e **indicar manualmente** **el tipo de tarjeta que te gustaría leer**.

#### Tarjetas Bancarias EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Además de simplemente leer el UID, puedes extraer muchos más datos de una tarjeta bancaria. Es posible **obtener el número completo de la tarjeta** (los 16 dígitos en el frente de la tarjeta), la **fecha de validez** e incluso en algunos casos el **nombre del propietario** junto con una lista de las **transacciones más recientes**.\
Sin embargo, **no puedes leer el CVV de esta manera** (los 3 dígitos en la parte trasera de la tarjeta). Además, **las tarjetas bancarias están protegidas contra ataques de repetición**, por lo que copiarla con Flipper y luego intentar emularla para pagar algo no funcionará.
## Referencias

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>Aprende hacking de AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión del PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
