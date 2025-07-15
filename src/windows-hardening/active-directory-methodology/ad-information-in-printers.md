# Informationen in Druckern

{{#include ../../banners/hacktricks-training.md}}

Es gibt mehrere Blogs im Internet, die **die Gefahren hervorheben, Drucker mit LDAP mit Standard-/schwachen** Anmeldeinformationen konfiguriert zu lassen. \
Das liegt daran, dass ein Angreifer **den Drucker dazu bringen könnte, sich gegen einen bösartigen LDAP-Server zu authentifizieren** (typischerweise reicht ein `nc -vv -l -p 389` oder `slapd -d 2`) und die Drucker-**Anmeldeinformationen im Klartext** abzufangen.

Außerdem enthalten mehrere Drucker **Protokolle mit Benutzernamen** oder könnten sogar in der Lage sein, **alle Benutzernamen** vom Domänencontroller herunterzuladen.

All diese **sensiblen Informationen** und der allgemeine **Mangel an Sicherheit** machen Drucker für Angreifer sehr interessant.

Einige einführende Blogs zu diesem Thema:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

---
## Druckerkonfiguration

- **Standort**: Die LDAP-Serverliste befindet sich normalerweise in der Weboberfläche (z. B. *Netzwerk ➜ LDAP-Einstellungen ➜ LDAP einrichten*).
- **Verhalten**: Viele eingebettete Webserver erlauben LDAP-Serveränderungen **ohne erneute Eingabe der Anmeldeinformationen** (Usability-Funktion → Sicherheitsrisiko).
- **Ausnutzen**: Leiten Sie die LDAP-Serveradresse an einen vom Angreifer kontrollierten Host um und verwenden Sie die Schaltfläche *Verbindung testen* / *Adressbuch synchronisieren*, um den Drucker dazu zu bringen, sich mit Ihnen zu verbinden.

---
## Anmeldeinformationen erfassen

### Methode 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Kleine/alte MFPs senden möglicherweise ein einfaches *simple-bind* im Klartext, das netcat erfassen kann. Moderne Geräte führen normalerweise zuerst eine anonyme Abfrage durch und versuchen dann das Bind, sodass die Ergebnisse variieren.

### Methode 2 – Vollständiger Rogue LDAP-Server (empfohlen)

Da viele Geräte eine anonyme Suche *vor* der Authentifizierung durchführen, liefert das Einrichten eines echten LDAP-Daemons viel zuverlässigere Ergebnisse:
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Wenn der Drucker seine Abfrage durchführt, sehen Sie die Klartext-Anmeldeinformationen in der Debug-Ausgabe.

> 💡  Sie können auch `impacket/examples/ldapd.py` (Python rogue LDAP) oder `Responder -w -r -f` verwenden, um NTLMv2-Hashes über LDAP/SMB zu ernten.

---
## Aktuelle Pass-Back-Sicherheitsanfälligkeiten (2024-2025)

Pass-back ist *kein* theoretisches Problem – Anbieter veröffentlichen weiterhin Hinweise in 2024/2025, die genau diese Angriffsart beschreiben.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 der Xerox VersaLink C70xx MFPs erlaubte einem authentifizierten Administrator (oder jedem, wenn die Standardanmeldeinformationen bestehen bleiben):

* **CVE-2024-12510 – LDAP pass-back**: Ändern der LDAP-Serveradresse und Auslösen einer Abfrage, wodurch das Gerät die konfigurierten Windows-Anmeldeinformationen an den vom Angreifer kontrollierten Host weitergibt.
* **CVE-2024-12511 – SMB/FTP pass-back**: identisches Problem über *scan-to-folder*-Ziele, das NetNTLMv2 oder FTP-Klartext-Anmeldeinformationen preisgibt.

Ein einfacher Listener wie:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
oder ein bösartiger SMB-Server (`impacket-smbserver`) reicht aus, um die Anmeldeinformationen zu ernten.

### Canon imageRUNNER / imageCLASS – Advisory 20. Mai 2025

Canon bestätigte eine **SMTP/LDAP Pass-Back** Schwachstelle in Dutzenden von Laser- und MFP-Produktlinien. Ein Angreifer mit Administratorzugriff kann die Serverkonfiguration ändern und die gespeicherten Anmeldeinformationen für LDAP **oder** SMTP abrufen (viele Organisationen verwenden ein privilegiertes Konto, um das Scannen per E-Mail zu ermöglichen).

Die Empfehlungen des Anbieters lauten ausdrücklich:

1. Aktualisieren Sie die Firmware so schnell wie möglich auf die gepatchte Version.
2. Verwenden Sie starke, einzigartige Administratorpasswörter.
3. Vermeiden Sie privilegierte AD-Konten für die Druckerintegration.

---
## Automatisierte Aufzählungs- / Ausnutzungstools

| Tool | Zweck | Beispiel |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Missbrauch von PostScript/PJL/PCL, Dateisystemzugriff, Überprüfung der Standardanmeldeinformationen, *SNMP-Entdeckung* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Ernte der Konfiguration (einschließlich Adressbücher & LDAP-Anmeldeinformationen) über HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Erfassen & Weiterleiten von NetNTLM-Hashes aus SMB/FTP-Pass-Back | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Leichter bösartiger LDAP-Dienst zum Empfangen von Klartext-Bindungen | `python ldapd.py -debug` |

---
## Härtung & Erkennung

1. **Patch / Firmware-Update** MFPs umgehend (prüfen Sie die PSIRT-Bulletins des Anbieters).
2. **Least-Privilege Service Accounts** – niemals Domain Admin für LDAP/SMB/SMTP verwenden; auf *nur lesen* OU-Bereiche beschränken.
3. **Zugriff auf die Verwaltung einschränken** – Drucker-Web-/IPP/SNMP-Schnittstellen in ein Verwaltungs-VLAN oder hinter einer ACL/VPN platzieren.
4. **Deaktivieren Sie ungenutzte Protokolle** – FTP, Telnet, raw-9100, ältere SSL-Verschlüsselungen.
5. **Aktivieren Sie die Protokollierung** – einige Geräte können LDAP/SMTP-Fehler sysloggen; unerwartete Bindungen korrelieren.
6. **Überwachen Sie auf Klartext-LDAP-Bindungen** von ungewöhnlichen Quellen (Drucker sollten normalerweise nur mit DCs kommunizieren).
7. **SNMPv3 oder SNMP deaktivieren** – die Community `public` leakt oft Geräte- & LDAP-Konfiguration.

---
## Referenzen

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)
- Rapid7. “Xerox VersaLink C7025 MFP Pass-Back Attack Vulnerabilities.” Februar 2025.
- Canon PSIRT. “Vulnerability Mitigation Against SMTP/LDAP Passback for Laser Printers and Small Office Multifunction Printers.” Mai 2025.

{{#include ../../banners/hacktricks-training.md}}
