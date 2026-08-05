# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

Para obtener información sobre RFID y NFC, consulta la siguiente página:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Tarjetas NFC compatibles <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Además de las tarjetas NFC, Flipper Zero es compatible con **otros tipos de tarjetas de alta frecuencia**, como varias tarjetas **Mifare** Classic y Ultralight, y **NTAG**.

Se añadirán nuevos tipos de tarjetas NFC a la lista de tarjetas compatibles. Flipper Zero es compatible con los siguientes **tipos de tarjetas NFC A** (ISO 14443A):

- **Tarjetas bancarias (EMV)**: solo lee el UID, SAK y ATQA sin guardar.
- **Tarjetas desconocidas**: lee (UID, SAK, ATQA) y emula un UID.

Para las **tarjetas NFC de tipo B, tipo F y tipo V**, Flipper Zero puede leer un UID sin guardarlo.

### Tarjetas NFC de tipo A <a href="#uvusf" id="uvusf"></a>

#### Tarjeta bancaria (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero solo puede leer un UID, SAK, ATQA y los datos almacenados en tarjetas bancarias **sin guardarlos**.

Pantalla de lectura de tarjetas bancariasPara las tarjetas bancarias, Flipper Zero solo puede leer los datos **sin guardarlos ni emularlos**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Tarjetas desconocidas <a href="#id-37eo8" id="id-37eo8"></a>

Cuando Flipper Zero **no puede determinar el tipo de tarjeta NFC**, solo se pueden **leer y guardar** el **UID, SAK y ATQA**.

Pantalla de lectura de tarjetas desconocidasPara las tarjetas NFC desconocidas, Flipper Zero solo puede emular un UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Tarjetas NFC de tipos B, F y V <a href="#wyg51" id="wyg51"></a>

Para las **tarjetas NFC de tipos B, F y V**, Flipper Zero solo puede **leer y mostrar un UID** sin guardarlo.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Acciones

Para una introducción a NFC, [**lee esta página**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Leer

Flipper Zero puede **leer tarjetas NFC**; sin embargo, **no entiende todos los protocolos** basados en ISO 14443. No obstante, dado que el **UID es un atributo de bajo nivel**, podrías encontrarte en una situación en la que el **UID ya se haya leído, pero el protocolo de transferencia de datos de alto nivel siga siendo desconocido**. Puedes leer, emular e introducir manualmente el UID usando Flipper para los lectores primitivos que utilizan el UID para la autorización.<sup>[[1]](#references)</sup>

#### Leer el UID VS Leer los datos internos <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

En Flipper, la lectura de etiquetas de 13.56 MHz puede dividirse en dos partes:<sup>[[1]](#references)</sup>

- **Lectura de bajo nivel**: solo lee el UID, SAK y ATQA. Flipper intenta adivinar el protocolo de alto nivel basándose en estos datos leídos de la tarjeta. No puedes tener una certeza del 100 % con esto, ya que solo es una suposición basada en determinados factores.
- **Lectura de alto nivel**: lee los datos de la memoria de la tarjeta utilizando un protocolo de alto nivel específico. Esto incluye leer los datos de una Mifare Ultralight, leer los sectores de una Mifare Classic o leer los atributos de la tarjeta de PayPass/Apple Pay.

### Lectura específica

En caso de que Flipper Zero no pueda encontrar el tipo de tarjeta a partir de los datos de bajo nivel, en `Extra Actions` puedes seleccionar `Read Specific Card Type` e **indicar** **manualmente** el tipo de tarjeta que deseas leer.

#### Tarjetas bancarias EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Además de simplemente leer el UID, puedes extraer muchos más datos de una tarjeta bancaria. Es posible **obtener el número completo de la tarjeta** (los 16 dígitos de la parte frontal), la **fecha de validez** y, en algunos casos, incluso el **nombre del titular**, junto con una lista de las **transacciones más recientes**.\
Sin embargo, **no puedes leer el CVV de esta forma** (los 3 dígitos de la parte posterior de la tarjeta). Además, **las tarjetas bancarias están protegidas contra replay attacks**, por lo que copiarla con Flipper y luego intentar emularla para pagar algo no funcionará.<sup>[[1]](#references)</sup>

## Referencias

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
