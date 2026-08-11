# Das Modbus-Protokoll

{{#include ../../banners/hacktricks-training.md}}

## Einführung in Modbus

Modbus ist ein offenes Protokoll der Anwendungsschicht, das von SPS, Sensoren, Aktoren und anderen industriellen Geräten weit verbreitet eingesetzt wird. Sein Request/Response-Modell stellt Spulen und Register über Funktionscodes bereit. Sicherheitstests konzentrieren sich daher auf nicht autorisierte Lese-/Schreibzugriffe, Traffic-Beobachtung, Replay und unsicheres Geräteverhalten – nicht lediglich auf das Auffinden von TCP-Port 502.<sup>[[1]](#references)</sup>

Viele Installationen behalten ältere serielle Geräte bei, weil Upgrades Ausfallzeiten, eine erneute Zertifizierung oder den Austausch von Feldgeräten erfordern. Das herkömmliche Modbus bietet weder Vertraulichkeit noch Peer-Authentifizierung; Modbus Security ist ein separates TLS-basiertes Profil, das X.509-Zertifikate und TCP-Port 802 verwendet. Da die Spezifikation öffentlich und unabhängig implementierbar ist, unterscheiden sich das Verhalten der Hersteller und die Unterstützung optionaler Funktionen. Sie sollten daher per Fingerprinting ermittelt und nicht vorausgesetzt werden.<sup>[[1]](#references)[[2]](#references)</sup>

## Die Client-Server-Architektur

In der aktuellen Terminologie initiiert ein **client** eine Transaktion und ein **server** gibt eine Antwort zurück. Ältere Dokumentation verwendet **master/slave**. Verwechseln Sie diese Anwendungsbeziehung nicht mit SPI oder I2C: Dabei handelt es sich um andere Busprotokolle.<sup>[[1]](#references)</sup>

## Serielle und Ethernet-Transporte

Dieselben Modbus-Anwendungsdaten können über serielle Varianten (RTU- oder ASCII-Framing) und über Modbus TCP übertragen werden. Modbus TCP fügt einen MBAP-Header hinzu und verwendet normalerweise TCP-Port 502; serielles RTU verwendet ein kompaktes binäres Framing und eine CRC, während serielles ASCII Bytes als hexadezimale Zeichen darstellt und ein LRC verwendet.<sup>[[1]](#references)[[3]](#references)</sup>

## Datendarstellung

Das Datenmodell besteht aus einzelnen Bit-Spulen/diskreten Eingängen sowie 16-Bit-Eingangs-/Holding-Registern. Werte über mehrere Register, Byte-Reihenfolge, Skalierung und semantische Bedeutung sind gerätespezifisch und müssen anhand der Registerübersicht des Herstellers bestätigt werden.<sup>[[1]](#references)</sup>

## Funktionscodes

Funktionscodes wählen Operationen wie das Lesen von Spulen (`0x01`), das Lesen von Holding-Registern (`0x03`), das Schreiben einer einzelnen Spule/eines einzelnen Registers (`0x05`/`0x06`) und das Schreiben mehrerer Spulen/Register (`0x0F`/`0x10`) aus. Eine aufgezeichnete Schreibanforderung kann wiederholbar sein, wenn die Installation keine kompensierende Authentifizierung oder Prüfungen des Prozesszustands verwendet. Bei autorisiertem physischem Zugriff auf lange serielle Leitungen kann ein Prüfer Frames auch direkt über die Verkabelung aufzeichnen oder einschleusen, nachdem die elektrische Schnittstelle, Terminierung und sichere Anschlussmethode identifiziert wurden. Beide Aktionen können den physischen Prozess beeinflussen; verwenden Sie daher ein Labor oder eine ausdrückliche betriebliche Genehmigung.<sup>[[1]](#references)[[3]](#references)</sup>

## Adressierung

Serielle Geräte verwenden eine Unit-Adresse. Modbus TCP verwendet IP-Adressierung sowie einen Unit Identifier im MBAP-Header, was besonders relevant ist, wenn ein TCP-zu-Seriell-Gateway Anforderungen an nachgelagerte Units weiterleitet. In der Produktdokumentation angegebene Registerreferenzen können einsbasiert (`40001`) sein, während Protokolladressen nullbasiert sind – eine häufige Ursache für Off-by-one-Fehler.<sup>[[1]](#references)[[3]](#references)</sup>

Serielles Framing umfasst Prüfungen auf Übertragungsfehler (CRC für RTU und LRC für ASCII), und TCP stellt seine normale Transportsumme bereit. Diese erkennen versehentliche Beschädigungen; sie bieten weder kryptografische Integrität noch eine Authentifizierung des Ursprungs.<sup>[[3]](#references)</sup>

Testen Sie während einer autorisierten Prüfung die Angriffsfläche, zulässige Funktionscodes, beschreibbare Adressbereiche, die Ausnahmebehandlung, Ratenbegrenzungen sowie, ob Netzwerksegmentierung oder eine Modbus-fähige Firewall die Clients einschränkt. Relevante Bedrohungen umfassen passive Offenlegung, nicht autorisierte Befehlsinjektion, Replay, Datenfälschung und Denial of Service. Stimmen Sie alle aktiven Tests mit den Prozessverantwortlichen ab, da scheinbar kleine Registeränderungen einen physischen Prozess verändern können.

## References

- [1] [Modbus Organization — Spezifikation des Modbus-Anwendungsprotokolls V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)
- [2] [Modbus Organization — Modbus-Sicherheitsprotokoll und Implementierungsleitfäden](https://www.modbus.org/modbus-specifications)
- [3] [Modbus Organization — Spezifikation und Implementierungsleitfaden für Modbus über serielle Leitungen V1.02](https://www.modbus.org/file/secure/modbusoverserial.pdf)
{{#include ../../banners/hacktricks-training.md}}
