{{#include ../../banners/hacktricks-training.md}}

Es gibt mehrere Blogs im Internet, die **die Gefahren hervorheben, Drucker mit LDAP mit Standard-/schwachen** Anmeldeinformationen konfiguriert zu lassen.\
Das liegt daran, dass ein Angreifer **den Drucker dazu bringen könnte, sich gegen einen bösartigen LDAP-Server zu authentifizieren** (typischerweise reicht ein `nc -vv -l -p 444`) und die **Anmeldeinformationen des Druckers im Klartext** zu erfassen.

Außerdem enthalten mehrere Drucker **Protokolle mit Benutzernamen** oder könnten sogar in der Lage sein, **alle Benutzernamen** vom Domänencontroller herunterzuladen.

All diese **sensiblen Informationen** und der allgemeine **Mangel an Sicherheit** machen Drucker für Angreifer sehr interessant.

Einige Blogs zu diesem Thema:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Druckerkonfiguration

- **Standort**: Die LDAP-Serverliste befindet sich unter: `Network > LDAP Setting > Setting Up LDAP`.
- **Verhalten**: Die Schnittstelle ermöglicht LDAP-Serveränderungen, ohne die Anmeldeinformationen erneut einzugeben, was die Benutzerfreundlichkeit erhöht, aber Sicherheitsrisiken birgt.
- **Ausnutzung**: Die Ausnutzung besteht darin, die LDAP-Serveradresse auf eine kontrollierte Maschine umzuleiten und die Funktion "Verbindung testen" zu nutzen, um Anmeldeinformationen zu erfassen.

## Anmeldeinformationen erfassen

**Für detailliertere Schritte siehe die ursprüngliche [Quelle](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Methode 1: Netcat Listener

Ein einfacher Netcat-Listener könnte ausreichen:
```bash
sudo nc -k -v -l -p 386
```
Allerdings variiert der Erfolg dieser Methode.

### Methode 2: Vollständiger LDAP-Server mit Slapd

Ein zuverlässigerer Ansatz besteht darin, einen vollständigen LDAP-Server einzurichten, da der Drucker eine Nullbindung durchführt, gefolgt von einer Abfrage, bevor er versucht, die Anmeldeinformationen zu binden.

1. **LDAP-Server-Einrichtung**: Der Leitfaden folgt den Schritten aus [dieser Quelle](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Wichtige Schritte**:
- OpenLDAP installieren.
- Admin-Passwort konfigurieren.
- Grundlegende Schemata importieren.
- Domainnamen in der LDAP-Datenbank festlegen.
- LDAP TLS konfigurieren.
3. **Ausführung des LDAP-Dienstes**: Nach der Einrichtung kann der LDAP-Dienst mit folgendem Befehl ausgeführt werden:
```bash
slapd -d 2
```
## Referenzen

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)

{{#include ../../banners/hacktricks-training.md}}
