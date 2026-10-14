# FZ - Infrarot

{{#include ../../../banners/hacktricks-training.md}}

## Einführung <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Weitere Informationen zur Funktionsweise von Infrarot findest du hier:


{{#ref}}
../infrared.md
{{#endref}}

## IR-Signalempfänger im Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Der Flipper Zero verwendet einen demodulierenden IR-Empfänger, um Signale von gängigen IR-Fernbedienungen aufzuzeichnen. Einige Smartphones, darunter bestimmte Xiaomi-Modelle, verfügen über einen IR-Sender, aber die meisten können keine Fernbedienungssignale empfangen und decodieren.<sup>[[1]](#references)</sup>

Der Infrarot-**Empfänger des Flipper ist recht empfindlich**. Du kannst das **Signal sogar empfangen**, wenn du dich **irgendwo zwischen** der Fernbedienung und dem Fernseher befindest. Es ist nicht nötig, die Fernbedienung direkt auf den IR-Anschluss des Flipper zu richten. Das ist praktisch, wenn jemand in der Nähe des Fernsehers den Sender wechselt und du und der Flipper euch in einiger Entfernung befindet.

Die Protokolldecodierung erfolgt per Software. Erkannte Protokolle können als decodierte Befehle gespeichert werden; nicht unterstützte Protokolle lassen sich als rohe Zeitdaten aufzeichnen und wiedergeben, innerhalb der Grenzen der Trägerfrequenz und des Timings der Hardware.<sup>[[1]](#references)</sup>

## Aktionen

### Universalfernbedienungen

Der Universalfernbedienungsmodus des Flipper Zero durchläuft bekannte Befehle aus seiner Infrarotdatenbank für unterstützte Fernseher, Audiogeräte, Projektoren und Klimaanlagen. Es ist nicht garantiert, dass damit jedes Gerät gesteuert werden kann. Verwende den Modus nur für Geräte, die dir gehören oder die du testen darfst.<sup>[[1]](#references)</sup>

Im Universalfernbedienungsmodus genügt es, die Ein-/Aus-Taste zu drücken. Der Flipper sendet dann **nacheinander „Power Off“-Befehle** für alle Fernseher, die er kennt: Sony, Samsung, Panasonic … und so weiter. Wenn der Fernseher das Signal empfängt, reagiert er und schaltet sich aus.

Ein solcher Brute-Force-Vorgang braucht Zeit. Je größer das Wörterbuch ist, desto länger dauert es. Es lässt sich nicht herausfinden, welches Signal der Fernseher genau erkannt hat, da der Fernseher keine Rückmeldung gibt.

### Neue Fernbedienung anlernen

Der Flipper Zero kann ein **Infrarotsignal aufzeichnen**. Erkennt er das Protokoll und den Befehl, speichert er eine decodierte Darstellung; andernfalls kann er die rohen Zeitdaten zur späteren Wiedergabe speichern.<sup>[[1]](#references)</sup>

## References

- [1] [Fernseher mit dem Infrarotanschluss des Flipper Zero übernehmen](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
