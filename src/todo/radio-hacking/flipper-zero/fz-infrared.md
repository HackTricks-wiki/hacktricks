# FZ - Infrarot

{{#include ../../../banners/hacktricks-training.md}}

## Einleitung <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Für weitere Informationen darüber, wie Infrarot funktioniert, siehe:

{{#ref}}
../infrared.md
{{#endref}}

## IR-Signalempfänger im Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper verwendet einen digitalen IR-Signalempfänger TSOP, der **das Abfangen von Signalen von IR-Fernbedienungen ermöglicht**. Es gibt einige **Smartphones** wie Xiaomi, die ebenfalls einen IR-Port haben, aber beachten Sie, dass **die meisten von ihnen nur senden** können und **nicht empfangen** können.

Der Infrarot-**Empfänger von Flipper ist ziemlich empfindlich**. Sie können sogar **das Signal empfangen**, während Sie **irgendwo dazwischen** der Fernbedienung und dem Fernseher bleiben. Es ist nicht notwendig, die Fernbedienung direkt auf den IR-Port von Flipper zu richten. Dies ist nützlich, wenn jemand die Kanäle wechselt, während er in der Nähe des Fernsehers steht, und sowohl Sie als auch Flipper sich in einiger Entfernung befinden.

Da die **Dekodierung des Infrarotsignals** auf der **Software**-Seite erfolgt, unterstützt Flipper Zero potenziell die **Empfang und Übertragung von beliebigen IR-Fernbedienungscodes**. Im Falle von **unbekannten** Protokollen, die nicht erkannt werden konnten, **zeichnet es das rohe Signal genau so auf, wie es empfangen wurde, und spielt es ab**.

## Aktionen

### Universelle Fernbedienungen

Flipper Zero kann als **universelle Fernbedienung verwendet werden, um jeden Fernseher, Klimaanlage oder Mediencenter zu steuern**. In diesem Modus **bruteforced** Flipper alle **bekannten Codes** aller unterstützten Hersteller **laut dem Wörterbuch von der SD-Karte**. Sie müssen keine bestimmte Fernbedienung auswählen, um einen Restaurantfernseher auszuschalten.

Es reicht aus, die Einschalttaste im Modus Universelle Fernbedienung zu drücken, und Flipper wird **nacheinander "Power Off"**-Befehle aller Fernseher senden, die er kennt: Sony, Samsung, Panasonic... und so weiter. Wenn der Fernseher sein Signal empfängt, wird er reagieren und sich ausschalten.

Solch ein Brute-Force benötigt Zeit. Je größer das Wörterbuch, desto länger dauert es, bis es abgeschlossen ist. Es ist unmöglich herauszufinden, welches Signal der Fernseher genau erkannt hat, da es kein Feedback vom Fernseher gibt.

### Neue Fernbedienung lernen

Es ist möglich, ein **Infrarotsignal** mit Flipper Zero **aufzufangen**. Wenn es **das Signal in der Datenbank findet**, wird Flipper automatisch **wissen, welches Gerät das ist** und Ihnen erlauben, damit zu interagieren.\
Wenn nicht, kann Flipper das **Signal speichern** und Ihnen erlauben, es **wiederzugeben**.

## Referenzen

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
