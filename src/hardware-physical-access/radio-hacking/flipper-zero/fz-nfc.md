# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Introducción <a href="#id-9wrzi" id="id-9wrzi"></a>

Para obtener información sobre RFID y NFC, consulta la siguiente página:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Tarjetas NFC compatibles <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Además de tarjetas NFC, Flipper Zero admite **otros tipos de tarjetas de alta frecuencia**, como varias tarjetas **Mifare** Classic y Ultralight, y **NTAG**.

La lista de capacidades que aparece a continuación describe el firmware documentado en el artículo original y no debe considerarse una matriz exhaustiva de compatibilidad actual. El firmware de Flipper ha añadido protocolos y modificado el comportamiento de NFC con el tiempo; consulta la documentación oficial actual para el firmware instalado.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Tarjetas bancarias (EMV)** — solo lee el UID, SAK y ATQA, sin guardarlos.
- **Tarjetas desconocidas** — lee el UID, SAK y ATQA, y emula un UID.

Para las **tarjetas NFC de tipo B, F y V**, el firmware documentado podía leer un UID sin guardarlo.

### Tarjetas NFC de tipo A <a href="#uvusf" id="uvusf"></a>

#### Tarjetas bancarias (EMV) <a href="#kzmrp" id="kzmrp"></a>

El firmware documentado podía leer el UID, SAK, ATQA y los datos de aplicación disponibles de una tarjeta bancaria **sin guardarlos**.

En el caso de estas tarjetas bancarias, el firmware mostraba los datos sin guardar ni emular la tarjeta.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Tarjetas desconocidas <a href="#id-37eo8" id="id-37eo8"></a>

Cuando Flipper Zero **no puede determinar el tipo de una tarjeta NFC**, solo se pueden **leer y guardar** el **UID, SAK y ATQA**.

En el caso de una tarjeta NFC desconocida, este modo solo puede emular su UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Tarjetas NFC de tipo B, F y V <a href="#wyg51" id="wyg51"></a>

En el firmware documentado en el artículo original, solo se podía leer y mostrar el identificador de las tarjetas NFC de tipo B, F y V, sin guardarlo.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Acciones

Para una introducción a NFC, [**lee esta página**](../pentesting-rfid.md#high-frequency-rfid-tags-1356-mhz-1).

### Leer

Flipper Zero puede leer tarjetas NFC, pero no implementa todos los protocolos de nivel superior basados en ISO 14443. Por tanto, puede recuperar el UID, SAK y ATQA de bajo nivel, pero dejar sin identificar el protocolo de aplicación. En sistemas de control de acceso básicos que autorizan únicamente por UID, la herramienta puede leer, introducir manualmente y emular ese identificador; los sistemas que requieren autenticación criptográfica necesitan algo más que un UID copiado.<sup>[[1]](#references)</sup>

#### Leer el UID VS leer los datos internos <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

En Flipper, la lectura de etiquetas de 13,56 MHz se puede dividir en dos partes:<sup>[[1]](#references)</sup>

- **Lectura de bajo nivel** — lee solo el UID, SAK y ATQA. Flipper intenta deducir el protocolo de alto nivel a partir de estos datos leídos de la tarjeta. No se puede tener una certeza absoluta, ya que es solo una suposición basada en ciertos factores.
- **Lectura de alto nivel** — lee los datos de la memoria de la tarjeta mediante un protocolo de alto nivel específico. Esto puede consistir en leer los datos de una Mifare Ultralight, leer los sectores de una Mifare Classic o leer los atributos de la tarjeta en PayPass/Apple Pay.

### Lectura específica

Si Flipper Zero no puede determinar el tipo de tarjeta a partir de los datos de bajo nivel, puedes seleccionar `Read Specific Card Type` en `Extra Actions` e **indicar manualmente el tipo de tarjeta que quieres leer**.

#### Tarjetas bancarias EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

El firmware antiguo de Flipper y algunas tarjetas EMV compatibles podían exponer más datos que el UID, como el PAN, la fecha de caducidad, el nombre del titular o el registro de transacciones, si la tarjeta proporcionaba esos registros. La disponibilidad varía según la tarjeta, la aplicación y el firmware. El CVV de la banda magnética impreso en la tarjeta no se expone de este modo, y leer estos registros no clona la capacidad criptográfica de transacción necesaria para realizar un pago sin contacto.<sup>[[1]](#references)</sup>

## References

- [1] [Exploración de los protocolos RFID con Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Documentación de Flipper Zero - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
