# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Es überwacht jede Verbindung, die von jedem Prozess hergestellt wird. Abhängig vom Modus (stille Erlaubung von Verbindungen, stille Ablehnung von Verbindungen und Warnung) wird es **eine Warnung anzeigen**, jedes Mal, wenn eine neue Verbindung hergestellt wird. Es hat auch eine sehr schöne GUI, um all diese Informationen zu sehen.
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See Firewall. Dies ist eine grundlegende Firewall, die Sie bei verdächtigen Verbindungen warnt (sie hat eine GUI, ist aber nicht so schick wie die von Little Snitch).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Objective-See-Anwendung, die an mehreren Orten sucht, wo **Malware persistieren könnte** (es ist ein Einmal-Tool, kein Überwachungsdienst).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Wie KnockKnock, indem Prozesse überwacht werden, die Persistenz erzeugen.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Objective-See-Anwendung zur Auffindung von **Keyloggern**, die "Event Taps" für die Tastatur installieren. 

{{#include ../../banners/hacktricks-training.md}}
