# Informationen in Druckern

{{#include ../../banners/hacktricks-training.md}}

Im Internet gibt es mehrere Blogs, die die **Gefahren hervorheben, die entstehen, wenn Drucker mit LDAP und standardmäßigen/schwachen** Anmeldedaten konfiguriert bleiben.  \
Dies liegt daran, dass ein Angreifer **den Drucker dazu bringen könnte, sich bei einem rogue LDAP-Server zu authentifizieren** (typischerweise reicht ein `nc -vv -l -p 389` oder `slapd -d 2` aus), und die **Anmeldedaten des Druckers im Klartext** abfangen könnte.

Außerdem enthalten mehrere Drucker **Protokolle mit Benutzernamen** oder könnten sogar in der Lage sein, **alle Benutzernamen** vom Domain Controller herunterzuladen.

All diese **sensiblen Informationen** und der häufige **Mangel an Sicherheit** machen Drucker für Angreifer sehr interessant.

Einige einführende Blogs zu diesem Thema:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Druckerkonfiguration

- **Ort**: Die LDAP-Serverliste befindet sich normalerweise in der Weboberfläche (z. B. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Verhalten**: Viele eingebettete Webserver erlauben Änderungen am LDAP-Server **ohne erneute Eingabe der Anmeldedaten** (Benutzerfreundlichkeitsfunktion → Sicherheitsrisiko).
- **Exploit**: Leite die Adresse des LDAP-Servers auf einen vom Angreifer kontrollierten Host um und verwende die Schaltfläche *Test Connection* / *Address Book Sync*, um den Drucker zu zwingen, eine Verbindung zu dir herzustellen.

---

## Abfangen von Anmeldedaten

### Methode 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Kleine/alte MFPs senden möglicherweise einen einfachen *simple-bind* im Klartext, den netcat mitschneiden kann. Moderne Geräte führen normalerweise zuerst eine anonyme Abfrage durch und versuchen anschließend den Bind, daher können die Ergebnisse variieren.<sup>[[1]](#references)</sup>

### Methode 2 – Vollständiger Rogue-LDAP-Server (empfohlen)

Da viele Geräte vor der Authentifizierung eine anonyme Suche durchführen, liefert das Einrichten eines echten LDAP-Daemons wesentlich zuverlässigere Ergebnisse:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Wenn der Drucker seine Abfrage durchführt, sehen Sie die Klartext-Anmeldedaten in der Debug-Ausgabe.

> 💡  Sie können auch `impacket/examples/ldapd.py` (Python rogue LDAP) oder `Responder -w -r -f` verwenden, um NTLMv2-Hashes über LDAP/SMB zu sammeln.

---

## Aktuelle Pass-Back-Schwachstellen (2024-2025)

Pass-back ist *kein* theoretisches Problem – Anbieter veröffentlichen auch 2024/2025 weiterhin Advisories, die genau diese Angriffsklasse beschreiben.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 von Xerox VersaLink C70xx MFPs erlaubte es einem authentifizierten Administrator (oder jedem, wenn die Standardanmeldedaten noch aktiv sind):

* **CVE-2024-12510 – LDAP pass-back**: die LDAP-Serveradresse zu ändern und eine Abfrage auszulösen, wodurch das Gerät die konfigurierten Windows-Anmeldedaten an den vom Angreifer kontrollierten Host leakt.
* **CVE-2024-12511 – SMB/FTP pass-back**: identisches Problem über *scan-to-folder*-Ziele, wodurch NetNTLMv2- oder FTP-Klartext-Anmeldedaten geleakt werden.<sup>[[2]](#references)</sup>

Ein einfacher Listener wie:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
oder ein rogue SMB server (`impacket-smbserver`) reicht aus, um die Credentials abzugreifen.

### Canon imageRUNNER / imageCLASS – Advisory 20 May 2025

Canon bestätigte eine **SMTP/LDAP pass-back**-Schwachstelle in Dutzenden Laser- und MFP-Produktlinien. Ein Angreifer mit Admin-Zugriff kann die Serverkonfiguration ändern und die gespeicherten Credentials für LDAP **oder** SMTP abrufen (viele Organisationen verwenden ein privilegiertes Konto, um Scan-to-Mail zu ermöglichen).<sup>[[3]](#references)</sup>

Die Herstellerhinweise empfehlen ausdrücklich:

1. So bald wie verfügbar auf gepatchte Firmware aktualisieren.
2. Starke, eindeutige Admin-Passwörter verwenden.
3. Privilegierte AD-Konten für die Druckerintegration vermeiden.

---

## Automatisierte Enumeration- / Exploitation-Tools

| Tool | Zweck | Beispiel |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL-Missbrauch, Dateisystemzugriff, Prüfung auf Default-Credentials, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Konfiguration über HTTP/HTTPS abgreifen (einschließlich Adressbüchern und LDAP-Credentials) | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | NetNTLM-Hashes aus SMB/FTP-pass-back erfassen und weiterleiten | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Leichtgewichtiger rogue LDAP service zum Empfangen von Klartext-Binds | `python ldapd.py -debug` |

---

## Hardening & Detection

1. **MFPs zeitnah patchen / Firmware aktualisieren** (Hersteller-PSIRT-Bulletins prüfen).
2. **Service Accounts mit geringsten Rechten** – niemals Domain Admin für LDAP/SMB/SMTP verwenden; auf *read-only* OU-Bereiche beschränken.
3. **Management-Zugriff beschränken** – Web-/IPP-/SNMP-Schnittstellen der Drucker in einem Management-VLAN oder hinter einer ACL/VPN platzieren.
4. **Nicht verwendete Protokolle deaktivieren** – FTP, Telnet, raw-9100 und ältere SSL-Chiffren.
5. **Audit Logging aktivieren** – einige Geräte können LDAP-/SMTP-Fehler per Syslog protokollieren; unerwartete Binds korrelieren.
6. Auf **Klartext-LDAP-Binds** von ungewöhnlichen Quellen achten (Drucker sollten normalerweise nur mit DCs kommunizieren).
7. **SNMPv3 verwenden oder SNMP deaktivieren** – die Community `public` leakt häufig Geräte- und LDAP-Konfigurationen.

---

## References

- [1] [It's just a printer… What's the worst that could happen?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back Attack Vulnerabilities (Fixed)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Vulnerability Mitigation/Remediation for Production Printers, Office/Small Office Multifunction Printers and Laser Printers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtaining Domain Credentials through a Printer with Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting Multifunction Printers During A Penetration Test Engagement](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

{{#include ../../banners/hacktricks-training.md}}
