# FZ - Infrarot

{{#include ../../../banners/hacktricks-training.md}}

## Einleitung <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Weitere Informationen zur Funktionsweise von Infrarot findest du hier:


{{#ref}}
../infrared.md
{{#endref}}

## IR-Signalempfänger im Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper verwendet einen digitalen IR-Signalempfänger vom Typ TSOP, der **das Abfangen von Signalen von IR-Fernbedienungen ermöglicht**. Es gibt einige **Smartphones** wie Xiaomi, die ebenfalls über einen IR-Anschluss verfügen. Beachte jedoch, dass **die meisten von ihnen nur Signale senden** und **nicht empfangen können**.<sup>[[1]](#references)</sup>

Der Infrarot-**empfänger des Flipper ist sehr empfindlich**. Du kannst das **Signal sogar auffangen**, während du dich **irgendwo zwischen** der Fernbedienung und dem Fernseher befindest. Es ist nicht notwendig, die Fernbedienung direkt auf den IR-Anschluss des Flipper zu richten. Das ist praktisch, wenn jemand in der Nähe des Fernsehers die Kanäle wechselt und du und der Flipper sich in einiger Entfernung befinden.

Da die **Decodierung des Infrarot**signals auf der **Software**seite erfolgt, unterstützt Flipper Zero potenziell den **Empfang und die Übertragung beliebiger IR-Fernbedienungscodes**. Bei **unbekannten** Protokollen, die nicht erkannt werden konnten, **zeichnet Flipper das Rohsignal exakt so auf, wie es empfangen wurde, und spielt es wieder ab**.<sup>[[1]](#references)</sup>

## Aktionen

### Universelle Fernbedienungen

Flipper Zero kann als **universelle Fernbedienung zur Steuerung jedes Fernsehers, jeder Klimaanlage oder jedes Media Centers** verwendet werden. In diesem Modus **bruteforces** Flipper **alle bekannten Codes** aller unterstützten Hersteller **gemäß dem Wörterbuch auf der SD-Karte**. Du musst keine bestimmte Fernbedienung auswählen, um den Fernseher eines Restaurants auszuschalten.<sup>[[1]](#references)</sup>

Es genügt, im Modus „Universal Remote“ die Einschalttaste zu drücken. Flipper sendet dann **nacheinander „Power Off“-Befehle** für alle ihm bekannten Fernseher: Sony, Samsung, Panasonic ... und so weiter. Wenn der Fernseher das Signal empfängt, reagiert er und schaltet sich aus.

Dieser brute-force-Vorgang benötigt Zeit. Je größer das Wörterbuch ist, desto länger dauert die Ausführung. Es ist unmöglich herauszufinden, welches Signal der Fernseher genau erkannt hat, da es keine Rückmeldung vom Fernseher gibt.

### Neue Fernbedienung lernen

Es ist möglich, mit dem Flipper Zero ein **Infrarotsignal aufzuzeichnen**. Wenn Flipper **das Signal in der Datenbank findet**, **erkennt er automatisch, um welches Gerät es sich handelt**, und ermöglicht dir die Interaktion damit.\
Wenn dies nicht der Fall ist, kann Flipper das **Signal speichern** und dir ermöglichen, **es wieder abzuspielen**.<sup>[[1]](#references)</sup>

## Referenzen

- [1] [Fernseher mit dem Infrarotanschluss des Flipper Zero übernehmen](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
