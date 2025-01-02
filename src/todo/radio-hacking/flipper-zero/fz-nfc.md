# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

Para información sobre RFID y NFC, consulta la siguiente página:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Tarjetas NFC soportadas <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Aparte de las tarjetas NFC, Flipper Zero soporta **otro tipo de tarjetas de alta frecuencia** como varias **Mifare** Classic y Ultralight y **NTAG**.

Se agregarán nuevos tipos de tarjetas NFC a la lista de tarjetas soportadas. Flipper Zero soporta los siguientes **tipos de tarjetas NFC A** (ISO 14443A):

- **Tarjetas bancarias (EMV)** — solo lee UID, SAK y ATQA sin guardar.
- **Tarjetas desconocidas** — lee (UID, SAK, ATQA) y emula un UID.

Para **tarjetas NFC tipo B, tipo F y tipo V**, Flipper Zero puede leer un UID sin guardarlo.

### Tarjetas NFC tipo A <a href="#uvusf" id="uvusf"></a>

#### Tarjeta bancaria (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero solo puede leer un UID, SAK, ATQA y datos almacenados en tarjetas bancarias **sin guardar**.

Pantalla de lectura de tarjeta bancaria. Para tarjetas bancarias, Flipper Zero solo puede leer datos **sin guardar ni emular**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Tarjetas desconocidas <a href="#id-37eo8" id="id-37eo8"></a>

Cuando Flipper Zero es **incapaz de determinar el tipo de tarjeta NFC**, solo se puede **leer y guardar un UID,
