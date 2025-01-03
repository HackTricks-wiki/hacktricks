# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Für weitere Informationen darüber, was ein iButton ist, siehe:

{{#ref}}
../ibutton.md
{{#endref}}

## Design

Der **blaue** Teil des folgenden Bildes zeigt, wie Sie den **echten iButton** platzieren müssen, damit der Flipper ihn **lesen** kann. Der **grüne** Teil zeigt, wie Sie den Flipper Zero **an den Leser** halten müssen, um **korrekt einen iButton zu emulieren**.

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Aktionen

### Lesen

Im Lesemodus wartet der Flipper darauf, dass der iButton berührt wird, und kann jeden der drei Schlüsseltypen verarbeiten: **Dallas, Cyfral und Metakom**. Der Flipper wird **selbstständig den Typ des Schlüssels erkennen**. Der Name des Schlüsselprotokolls wird auf dem Bildschirm über der ID-Nummer angezeigt.

### Manuell hinzufügen

Es ist möglich, einen iButton des Typs **Dallas, Cyfral und Metakom** **manuell hinzuzufügen**.

### **Emulieren**

Es ist möglich, gespeicherte iButtons (gelesen oder manuell hinzugefügt) zu **emulieren**.

> [!NOTE]
> Wenn Sie die erwarteten Kontakte des Flipper Zero nicht an den Leser bringen können, können Sie **die externen GPIO verwenden:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## Referenzen

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
