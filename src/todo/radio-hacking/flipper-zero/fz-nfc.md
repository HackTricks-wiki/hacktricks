# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Introducción <a href="#id-9wrzi" id="id-9wrzi"></a>

Para obtener información sobre RFID y NFC, consulta la siguiente página:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Tarjetas NFC compatibles <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Además de las tarjetas NFC, Flipper Zero admite **otros tipos de tarjetas de alta frecuencia**, como varias tarjetas **Mifare** Classic y Ultralight y **NTAG**.

La lista de capacidades que aparece a continuación describe el firmware documentado por el artículo original y no debe considerarse una matriz exhaustiva de compatibilidad actual. El firmware de Flipper ha añadido protocolos y modificado el comportamiento de NFC con el tiempo; consulta la documentación oficial actual correspondiente al firmware instalado.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Tarjetas bancarias (EMV)** — solo leen el UID, SAK y ATQA sin guardarlos.
- **Tarjetas desconocidas** — leen el UID, SAK y ATQA y emulan un UID.

Para las **tarjetas NFC de tipo B, F y V**, el firmware documentado podía leer un UID sin guardarlo.

### Tarjetas NFC de tipo A <a href="#uvusf" id="uvusf"></a>

#### Tarjeta bancaria (EMV) <a href="#kzmrp" id="kzmrp"></a>

El firmware documentado podía leer un UID, SAK, ATQA y los datos de aplicación disponibles de una tarjeta bancaria **sin guardarlos**.

Para estas tarjetas bancarias, el firmware mostraba los datos sin guardar ni emular la tarjeta.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Tarjetas desconocidas <a href="#id-37eo8" id="id-37eo8"></a>

Cuando Flipper Zero **no puede determinar el tipo de tarjeta NFC**, solo se pueden **leer y guardar** un **UID, SAK y ATQA**.

Para una tarjeta NFC desconocida, este modo solo puede emular su UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Tarjetas NFC de tipos B, F y V <a href="#wyg51" id="wyg51"></a>

En el firmware documentado por el artículo original, en las tarjetas NFC de tipos B, F y V solo se podía leer y mostrar un identificador sin guardarlo.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Acciones

Para una introducción sobre NFC, [**lee esta página**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Lectura

Flipper Zero puede leer tarjetas NFC, pero no implementa todos los protocolos de nivel superior basados en ISO 14443. Por lo tanto, puede recuperar el UID, SAK y ATQA de bajo nivel, mientras mantiene desconocido el protocolo de aplicación. En sistemas de acceso primitivos que autorizan únicamente mediante el UID, la herramienta puede leer, introducir manualmente y emular ese identificador; los sistemas con autenticación criptográfica requieren más que un UID copiado.<sup>[[1]](#references)</sup>

#### Leer el UID frente a leer los datos internos <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

En Flipper, la lectura de tags de 13.56 MHz se puede dividir en dos partes:<sup>[[1]](#references)</sup>

- **Lectura de bajo nivel** — solo lee el UID, SAK y ATQA. Flipper intenta adivinar el protocolo de alto nivel basándose en estos datos leídos de la tarjeta. No puedes estar 100 % seguro, ya que solo es una suposición basada en determinados factores.
- **Lectura de alto nivel** — lee los datos de la memoria de la tarjeta mediante un protocolo de alto nivel específico. Esto puede consistir en leer los datos de una Mifare Ultralight, leer los sectores de una Mifare Classic o leer los atributos de la tarjeta desde PayPass/Apple Pay.

### Lectura específica

Si Flipper Zero no puede encontrar el tipo de tarjeta a partir de los datos de bajo nivel, en `Extra Actions` puedes seleccionar `Read Specific Card Type` e **indicar** **manualmente el tipo de tarjeta que quieres leer**.

#### Tarjetas bancarias EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

El firmware antiguo de Flipper y las tarjetas EMV compatibles podían exponer más información que el UID, posiblemente incluidos el PAN, la fecha de caducidad, el nombre del titular o el registro de transacciones cuando la tarjeta ponía esos registros a disposición. La disponibilidad varía según la tarjeta, la aplicación y el firmware. El CVV de la banda magnética impreso en la tarjeta no se expone de esta forma, y la lectura de estos registros no clona la capacidad criptográfica de transacción necesaria para realizar un pago sin contacto.<sup>[[1]](#references)</sup>

## References

- [1] [Explorando los protocolos RFID con Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Documentación de Flipper Zero - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
