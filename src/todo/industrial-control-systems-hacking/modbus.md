# Das Modbus-Protokoll

{{#include ../../banners/hacktricks-training.md}}

## Einführung in das Modbus-Protokoll

Das Modbus-Protokoll ist ein weit verbreitetes Protokoll in der industriellen Automatisierung und in Steuerungssystemen. Modbus ermöglicht die Kommunikation zwischen verschiedenen Geräten wie speicherprogrammierbaren Steuerungen (PLCs), Sensoren, Aktoren und anderen industriellen Geräten. Das Verständnis des Modbus-Protokolls ist wichtig, da es das meistgenutzte Kommunikationsprotokoll in ICS ist und eine große potenzielle Angriffsfläche für das Sniffing und sogar das Injizieren von Befehlen in PLCs bietet.

Hier werden die Konzepte punktweise dargestellt, um Kontext zum Protokoll und seiner Funktionsweise zu vermitteln. Die größte Herausforderung bei der Sicherheit von ICS-Systemen sind die Kosten für Implementierung und Upgrades. Diese Protokolle und Standards wurden in den frühen 80er- und 90er-Jahren entwickelt und werden noch immer weit verbreitet eingesetzt. Da eine Industrieanlage über viele Geräte und Verbindungen verfügt, ist das Upgrade der Geräte sehr schwierig. Dies verschafft Hackern einen Vorteil beim Umgang mit veralteten Protokollen. Angriffe auf Modbus sind praktisch unvermeidbar, da das Protokoll ohne Upgrade weiterverwendet wird, wenn sein Betrieb für die Industrie kritisch ist.

## Die Client-Server-Architektur

Das Modbus-Protokoll wird typischerweise in einer Client-Server-Architektur verwendet, bei der ein Master-Gerät (Client) die Kommunikation mit einem oder mehreren Slave-Geräten (Servern) initiiert. Dies wird auch als Master-Slave-Architektur bezeichnet und ist in der Elektronik sowie im IoT bei SPI, I2C usw. weit verbreitet.

## Serielle und Etherent-Versionen

Das Modbus-Protokoll ist sowohl für serielle Kommunikation als auch für Ethernet-Kommunikation ausgelegt. Die serielle Kommunikation wird häufig in Legacy-Systemen verwendet, während moderne Geräte Ethernet unterstützen, das hohe Datenraten bietet und besser für moderne industrielle Netzwerke geeignet ist.

## Datendarstellung

Daten werden im Modbus-Protokoll als ASCII oder Binärdaten übertragen, wobei das Binärformat aufgrund seiner Kompaktheit und Kompatibilität mit älteren Geräten verwendet wird.

## Funktionscodes

Das Modbus-Protokoll arbeitet mit der Übertragung spezifischer Funktionscodes, die zur Steuerung der PLCs und verschiedener Steuerungsgeräte verwendet werden. Dieser Abschnitt ist wichtig zu verstehen, da Replay-Angriffe durch die erneute Übertragung von Funktionscodes durchgeführt werden können. Legacy-Geräte unterstützen bei der Datenübertragung keine Verschlüsselung und sind üblicherweise über lange Leitungen verbunden. Dies ermöglicht die Manipulation dieser Leitungen sowie das Abfangen und Injizieren von Daten.

## Adressierung von Modbus

Jedes Gerät im Netzwerk verfügt über eine eindeutige Adresse, die für die Kommunikation zwischen den Geräten erforderlich ist. Protokolle wie Modbus RTU, Modbus TCP usw. werden zur Implementierung der Adressierung verwendet und dienen bei der Datenübertragung als Transportschicht. Die übertragenen Daten liegen im Modbus-Protokollformat vor, das die Nachricht enthält.

Darüber hinaus implementiert Modbus Fehlerprüfungen, um die Integrität der übertragenen Daten sicherzustellen. Vor allem aber ist Modbus ein offener Standard, den jeder in seinen Geräten implementieren kann. Dadurch entwickelte sich dieses Protokoll zu einem globalen Standard und ist in der industriellen Automatisierungsbranche weit verbreitet.

Aufgrund seiner großflächigen Nutzung und fehlender Upgrades bietet ein Angriff auf Modbus durch seine Angriffsfläche erhebliche Vorteile. ICS ist stark von der Kommunikation zwischen Geräten abhängig, und Angriffe auf diese Geräte können für den Betrieb der Industriesysteme gefährlich sein. Angriffe wie Replay, Dateninjektion, Data Sniffing und leaking, Denial of Service, Datenfälschung usw. können durchgeführt werden, wenn der Übertragungsweg vom Angreifer identifiziert wurde.

{{#include ../../banners/hacktricks-training.md}}
