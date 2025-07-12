# Das Modbus-Protokoll

{{#include ../../banners/hacktricks-training.md}}

## Einführung in das Modbus-Protokoll

Das Modbus-Protokoll ist ein weit verbreitetes Protokoll in der industriellen Automatisierung und Steuerungssystemen. Modbus ermöglicht die Kommunikation zwischen verschiedenen Geräten wie programmierbaren Logiksteuerungen (PLCs), Sensoren, Aktuatoren und anderen industriellen Geräten. Das Verständnis des Modbus-Protokolls ist entscheidend, da es das am häufigsten verwendete Kommunikationsprotokoll in der ICS ist und eine große potenzielle Angriffsfläche für das Abhören und sogar das Injizieren von Befehlen in PLCs bietet.

Hier werden die Konzepte punktuell dargestellt, um den Kontext des Protokolls und seine Funktionsweise zu erläutern. Die größte Herausforderung in der Sicherheit von ICS-Systemen ist die Kosten für Implementierung und Aktualisierung. Diese Protokolle und Standards wurden in den frühen 80er und 90er Jahren entwickelt und werden immer noch weit verbreitet verwendet. Da eine Industrie viele Geräte und Verbindungen hat, ist die Aktualisierung von Geräten sehr schwierig, was Hackern einen Vorteil im Umgang mit veralteten Protokollen verschafft. Angriffe auf Modbus sind praktisch unvermeidlich, da es ohne Aktualisierung verwendet wird und seine Funktionsweise für die Industrie kritisch ist.

## Die Client-Server-Architektur

Das Modbus-Protokoll wird typischerweise in einer Client-Server-Architektur verwendet, bei der ein Master-Gerät (Client) die Kommunikation mit einem oder mehreren Slave-Geräten (Servern) initiiert. Dies wird auch als Master-Slave-Architektur bezeichnet, die in der Elektronik und IoT mit SPI, I2C usw. weit verbreitet ist.

## Serielle und Ethernet-Versionen

Das Modbus-Protokoll ist sowohl für die serielle Kommunikation als auch für die Ethernet-Kommunikation konzipiert. Die serielle Kommunikation wird häufig in Legacy-Systemen verwendet, während moderne Geräte Ethernet unterstützen, das hohe Datenraten bietet und besser für moderne industrielle Netzwerke geeignet ist.

## Datenrepräsentation

Daten werden im Modbus-Protokoll als ASCII oder Binär übertragen, obwohl das Binärformat aufgrund seiner Kompatibilität mit älteren Geräten verwendet wird.

## Funktionscodes

Das ModBus-Protokoll funktioniert mit der Übertragung spezifischer Funktionscodes, die zur Steuerung der PLCs und verschiedener Steuergeräte verwendet werden. Dieser Abschnitt ist wichtig zu verstehen, da Wiederholungsangriffe durch das erneute Übertragen von Funktionscodes durchgeführt werden können. Legacy-Geräte unterstützen keine Verschlüsselung der Datenübertragung und haben normalerweise lange Drähte, die sie verbinden, was zu Manipulationen dieser Drähte und zum Abfangen/injizieren von Daten führt.

## Adressierung von Modbus

Jedes Gerät im Netzwerk hat eine eindeutige Adresse, die für die Kommunikation zwischen den Geräten unerlässlich ist. Protokolle wie Modbus RTU, Modbus TCP usw. werden verwendet, um die Adressierung zu implementieren und dienen als Transportschicht für die Datenübertragung. Die übertragenen Daten sind im Modbus-Protokollformat, das die Nachricht enthält.

Darüber hinaus implementiert Modbus auch Fehlerprüfungen, um die Integrität der übertragenen Daten sicherzustellen. Aber vor allem ist Modbus ein offener Standard, und jeder kann ihn in seinen Geräten implementieren. Dies hat dazu geführt, dass dieses Protokoll zum globalen Standard wurde und in der industriellen Automatisierungsindustrie weit verbreitet ist.

Aufgrund seiner großflächigen Nutzung und des Mangels an Aktualisierungen bietet ein Angriff auf Modbus einen erheblichen Vorteil mit seiner Angriffsfläche. ICS ist stark von der Kommunikation zwischen Geräten abhängig, und Angriffe auf diese können gefährlich für den Betrieb der industriellen Systeme sein. Angriffe wie Wiederholung, Dateninjektion, Datenschnüffeln und Leaks, Denial of Service, Datenfälschung usw. können durchgeführt werden, wenn das Übertragungsmedium vom Angreifer identifiziert wird.

{{#include ../../banners/hacktricks-training.md}}
