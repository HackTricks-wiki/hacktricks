# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Einleitung

Weitere Informationen darüber, was ein iButton ist:


{{#ref}}
../ibutton.md
{{#endref}}

## Aufbau

Der **blaue** Teil des folgenden Bildes zeigt, wie du den **echten iButton** platzieren musst, damit der Flipper ihn **lesen kann.** Der **grüne** Teil zeigt, wie du den Reader mit dem Flipper Zero **berühren musst, um einen iButton korrekt zu emulieren.**<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Aktionen

### Lesen

Im Lesemodus wartet der Flipper darauf, dass der iButton-Schlüssel den Reader berührt, und kann drei Arten von Schlüsseln verarbeiten: **Dallas, Cyfral und Metakom**. Der Flipper **ermittelt den Typ des Schlüssels selbst.** Der Name des Schlüsselprotokolls wird auf dem Bildschirm über der ID-Nummer angezeigt.<sup>[[1]](#references)</sup>

### Manuell hinzufügen

Es ist möglich, einen iButton des Typs **Dallas, Cyfral oder Metakom manuell hinzuzufügen.**

### **Emulieren**

Es ist möglich, gespeicherte iButtons zu **emulieren** (gelesene oder manuell hinzugefügte).

> [!TIP]
> Wenn du die erwarteten Kontakte des Flipper Zero nicht mit dem Reader in Kontakt bringen kannst, kannst du den **externen GPIO verwenden:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## Referenzen

- [1] [Taming iButton Keys with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
