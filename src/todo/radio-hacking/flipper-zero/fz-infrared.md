# FZ - Infrarot

{{#include ../../../banners/hacktricks-training.md}}

## Einleitung <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Weitere Informationen zur Funktionsweise von Infrarot findest du hier:


{{#ref}}
../infrared.md
{{#endref}}

## IR-Signalempfänger im Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Der Flipper Zero verwendet einen demodulierenden IR-Empfänger, um Signale von gängigen IR-Fernbedienungen aufzuzeichnen. Einige Telefone, darunter bestimmte Xiaomi-Modelle, verfügen über einen IR-Sender, die meisten können jedoch Signale von Fernbedienungen weder empfangen noch decodieren.<sup>[[1]](#references)</sup>

Der **Empfänger des Flipper-Infrarotmoduls ist sehr empfindlich**. Du kannst das **Signal sogar auffangen**, während du dich **irgendwo zwischen** der Fernbedienung und dem Fernseher befindest. Es ist nicht erforderlich, die Fernbedienung direkt auf den IR-Anschluss des Flippers zu richten. Das ist nützlich, wenn jemand in der Nähe des Fernsehers die Kanäle wechselt und du sowie der Flipper sich in einiger Entfernung befinden.

Die Protokolldecodierung erfolgt in Software. Erkannte Protokolle können als decodierte Befehle gespeichert werden; nicht unterstützte Protokolle können als rohe Zeitdaten aufgezeichnet und wiedergegeben werden, vorbehaltlich der Grenzen der Trägerfrequenz und des Timings der Hardware.<sup>[[1]](#references)</sup>

## Aktionen

### Universalfernbedienungen

Der Universalfernbedienungsmodus des Flipper Zero durchläuft bekannte Befehle aus seiner Infrarot-Datenbank für unterstützte Fernseher, Audiogeräte, Projektoren und Klimaanlagen. Es ist nicht garantiert, dass jedes Gerät gesteuert werden kann, und der Modus sollte nur für Geräte verwendet werden, die dir gehören oder für deren Test du autorisiert bist.<sup>[[1]](#references)</sup>

Im Universalfernbedienungsmodus genügt es, die Einschalttaste zu drücken, und der Flipper sendet **nacheinander „Ausschalten“-Befehle** für alle ihm bekannten Fernseher: Sony, Samsung, Panasonic usw. Wenn der Fernseher sein Signal empfängt, reagiert er und schaltet sich aus.

Dieser Brute-Force-Angriff benötigt Zeit. Je größer das Wörterbuch ist, desto länger dauert die Ausführung. Es ist unmöglich festzustellen, welches Signal der Fernseher genau erkannt hat, da es kein Feedback vom Fernseher gibt.

### Neue Fernbedienung lernen

Der Flipper Zero kann **ein Infrarotsignal aufzeichnen**. Wenn er das Protokoll und den Befehl erkennt, speichert er eine decodierte Darstellung. Andernfalls kann er die rohen Zeitdaten zur späteren Wiedergabe speichern.<sup>[[1]](#references)</sup>

## References

- [1] [Übernahme von Fernsehern mit dem Infrarotanschluss des Flipper Zero](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
