# Informationen in Druckern

{{#include ../../banners/hacktricks-training.md}}

Im Internet gibt es mehrere Blogs, die die **Gefahren hervorheben, die entstehen, wenn Drucker mit LDAP und standardmäßigen/schwachen** Anmeldeinformationen konfiguriert sind.  \
Dies liegt daran, dass ein Angreifer **den Drucker dazu bringen könnte, sich bei einem bösartigen LDAP-Server zu authentifizieren** (normalerweise reicht ein `nc -vv -l -p 389` oder `slapd -d 2` aus), und die **Anmeldeinformationen des Druckers im Klartext** abfangen könnte.

Außerdem enthalten mehrere Drucker **Protokolle mit Benutzernamen** oder sind möglicherweise sogar in der Lage, **alle Benutzernamen** vom Domain Controller herunterzuladen.

All diese **sensiblen Informationen** und der häufige **Mangel an Sicherheit** machen Drucker für Angreifer sehr interessant.

Einige einführende Blogs zu diesem Thema:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Druckerkonfiguration

- **Standort**: Die LDAP-Serverliste befindet sich normalerweise in der Weboberfläche (z. B. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Verhalten**: Viele eingebettete Webserver erlauben Änderungen am LDAP-Server **ohne erneute Eingabe der Anmeldeinformationen** (Benutzerfreundlichkeitsfunktion → Sicherheitsrisiko).
- **Exploit**: Leite die Adresse des LDAP-Servers auf einen vom Angreifer kontrollierten Host um und verwende die Schaltfläche *Test Connection* / *Address Book Sync*, um den Drucker zu zwingen, eine Bindung zu dir herzustellen.

---

## Abfangen von Anmeldeinformationen

### Methode 1 – Netcat-Listener
```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```
Kleine/alte MFPs senden möglicherweise einen einfachen *simple-bind*, dessen Bind-DN und Passwort im rohen BER-Stream sichtbar sind. Moderne Geräte führen in der Regel zuerst eine anonyme Abfrage durch und versuchen anschließend den Bind, daher variieren die Ergebnisse.<sup>[[1]](#references)</sup>

Ein einfacher `nc`-Listener auf 636/3269 empfängt nur TLS-Chiffretext; das Testen von LDAPS erfordert einen TLS-fähigen LDAP-Endpunkt, und eine Umleitung sollte fehlschlagen, wenn das Gerät das Serverzertifikat korrekt validiert.

### Methode 2 – Vollständiger Rogue LDAP server (empfohlen)

Da viele Geräte vor der Authentifizierung eine anonyme Suche durchführen, liefert das Aufsetzen eines echten LDAP-Daemons deutlich zuverlässigere Ergebnisse:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Wenn der Drucker seine Abfrage durchführt, werden die Klartext-Anmeldedaten in der Debug-Ausgabe angezeigt.

> 💡  Responder umfasst rogue LDAP- und SMB-Authentifizierungsdienste. Ein einfacher LDAP-Bind kann das konfigurierte Passwort offenlegen, während die NTLM-Authentifizierung Challenge-Response-Material erzeugt; beschreibe beide Ergebnisse nicht als Klartextpasswort.

---

## Aktuelle Pass-Back-Schwachstellen (2024–2025)

Pass-back ist *kein* theoretisches Problem – Anbieter veröffentlichen 2024/2025 weiterhin Advisories, die diese Angriffsklasse genau beschreiben.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 von Xerox VersaLink C70xx MFPs erlaubte es einem authentifizierten Administrator (oder jedem, wenn die Standardanmeldedaten noch verwendet werden), Folgendes zu tun:

* **CVE-2024-12510 – LDAP pass-back**: Die LDAP-Serveradresse ändern und eine Abfrage auslösen, wodurch das Gerät die konfigurierten Windows-Anmeldedaten an den vom Angreifer kontrollierten Host leak.
* **CVE-2024-12511 – SMB/FTP pass-back**: Identisches Problem über *scan-to-folder*-Ziele, wobei NetNTLMv2- oder FTP-Klartext-Anmeldedaten geleakt werden.<sup>[[2]](#references)</sup>

Ein einfacher Listener wie:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
oder ein rogue SMB server (`impacket-smbserver`) reicht aus, um die Credentials abzugreifen.

### Canon imageRUNNER / imageCLASS – Advisory vom 20. Mai 2025

Canon bestätigte eine **SMTP/LDAP pass-back**-Schwachstelle in Dutzenden Laser- und MFP-Produktlinien. Ein Angreifer mit administrativem Zugriff kann die Serverkonfiguration ändern und die gespeicherten Credentials für LDAP **oder** SMTP abrufen (viele Organisationen verwenden ein privilegiertes Konto, um Scan-to-Mail zu ermöglichen).<sup>[[3]](#references)</sup>

Die Herstellerempfehlungen enthalten ausdrücklich:

1. So bald wie verfügbar auf gepatchte Firmware aktualisieren.
2. Starke, eindeutige Admin-Passwörter verwenden.
3. Privilegierte AD-Konten für die Druckerintegration vermeiden.

---

### Brother-Geräte und OEM-Varianten – vom Serial abgeleiteter Admin-Zugriff auf Service-Credentials

Eine koordinierte Offenlegung im Jahr 2025 demonstrierte eine besonders nützliche Angriffskette auf betroffenen Brother-Geräten; Teile der Schwachstellen betreffen auch OEM-Modelle. Daher sollte das genaue Modell anhand des Advisories des jeweiligen Herstellers überprüft werden. Ein nicht authentifizierter Angreifer kann bei verwundbarer Firmware die Geräte-Serial über HTTP/HTTPS/IPP abrufen, während Serials auch über Management-Protokolle wie SNMP oder PJL verfügbar sein können. Wenn das werkseitige Passwort nie geändert wurde, ergibt sich aus der Serial deterministisch das Administratorpasswort. Nach der Authentifizierung gibt die separate pass-back-Schwachstelle CVE-2024-51984 konfigurierte Passwörter externer Services wie LDAP oder FTP im Klartext preis. Dadurch wird der Zugriff auf die Druckerverwaltung zu wiederverwendbaren Netzwerk-Credentials. Die Firmware behebt die Offenlegung der Service-Passwörter, bereits hergestellte Geräte erfordern jedoch weiterhin, dass der Betreiber das anfängliche, von der Serial abgeleitete Administratorpasswort ersetzt.<sup>[[6]](#references)</sup>

Metasploit enthält inzwischen ein Auxiliary-Modul, das die Serial über HTTP, SNMP oder PJL ermittelt, das mögliche anfängliche Passwort generiert und es optional gegen die Webkonsole überprüft. `DiscoverSerialVia=AUTO` versucht die unterstützten Ermittlungspfade; `TargetSerial` sollte stattdessen angegeben werden, wenn das Asset-Inventar die Serial bereits enthält.<sup>[[7]](#references)</sup>
```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```
Verwende das Ergebnis nur zur Validierung autorisierter Assets. Ob das Passwort funktioniert, hängt vom genauen Modell und – entscheidend – davon ab, ob das werkseitige Administratorpasswort bereits geändert wurde.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Automatisierte Enumeration- / Exploitation-Tools

| Tool | Zweck | Beispiel |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Missbrauch von PostScript/PJL/PCL, Zugriff auf das Dateisystem, Prüfung auf Standard-Credentials, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Auslesen der Konfiguration (einschließlich Adressbüchern und LDAP-Credentials) über HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Ausführen von Rogue-Authentication-Services sowie Erfassen/Relaying von NetNTLM über SMB-Callbacks | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Ermitteln einer Seriennummer, Ableiten des möglichen werkseitigen Administratorpassworts und Überprüfen des Zugriffs auf die Webkonsole | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Härtung & Detection

1. **MFPs zeitnah patchen / Firmware aktualisieren** (Hersteller-PSIRT-Bulletins prüfen).
2. **Werkseitige Administratorpasswörter ersetzen** – die Firmware allein entfernt keine aus der Seriennummer abgeleiteten initialen Passwörter von zuvor hergestellten betroffenen Brother-/OEM-Geräten.<sup>[[6]](#references)</sup>
3. **Service Accounts mit geringsten Privilegien** – niemals Domain Admin für LDAP/SMB/SMTP verwenden; auf *read-only*-OU-Bereiche beschränken.
4. **Managementzugriff beschränken** – Web-/IPP-/SNMP-Schnittstellen der Drucker in einem Management-VLAN oder hinter einer ACL/VPN platzieren.
5. **Ausgehenden Datenverkehr der Drucker beschränken** – jedem Gerät nur die erwarteten DC-/LDAP-, Mail-, DNS/NTP-, Druck- und Scan-Dateiziele erlauben. Pass-back erfordert einen Callback an einen vom Angreifer ausgewählten Endpunkt.
6. **Nicht verwendete Protokolle deaktivieren** – FTP, Telnet, Raw-9100 und ältere SSL-Cipher.
7. **Audit-Logging aktivieren** – einige Geräte können LDAP-/SMTP-Fehler per Syslog protokollieren; unerwartete Binds korrelieren.
8. **Authentifizierungsziele überwachen** – alarmieren, wenn ein Drucker LDAP, SMB, SMTP oder FTP an einen Host außerhalb seiner Allowlist initiiert, insbesondere unmittelbar nach einer Managementanmeldung oder einer Konfigurationsänderung.
9. **SNMPv3 verwenden oder SNMP deaktivieren** – die Community `public` leakt häufig Geräte- und Seriennummern.

---



---

## References

- [1] [Es ist nur ein Drucker … Was könnte schon Schlimmstes passieren?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunktionsdrucker: Pass-Back-Angriffsschwachstellen (behoben)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Maßnahmen zur Schwachstellenminderung/-behebung für Produktionsdrucker, Multifunktionsdrucker für Büro/Heimbüro und Laserdrucker](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Domain-Credentials über einen Drucker mit Netcat erlangen](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Ausnutzen von Multifunktionsdruckern während eines Penetration-Testing-Auftrags](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Mehrere Brother-Geräte: Mehrere Schwachstellen (BEHOBEN)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Modul zum Umgehen der Standard-Administratorauthentifizierung von Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
