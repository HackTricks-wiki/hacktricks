# Informationen in Druckern

{{#include ../../banners/hacktricks-training.md}}

Ein Drucker mit gespeicherten LDAP-Anmeldedaten kann diese preisgeben, wenn seine Servereinstellung geändert wird und er sich anschließend bei einem rogue Endpoint authentifiziert.<sup>[[2]](#references)</sup> Das Ergebnis hängt von der Bind-Methode ab: Ein ungeschützter Simple Bind gibt das Passwort preis, während ein SASL-Challenge-Response-Bind es nicht im Klartext preisgibt.<sup>[[8]](#references)</sup> Siehe [LDAP authentication and transport security](../../network-services-pentesting/pentesting-ldap.md#cleartext-credentials-and-tls-downgrade-risks).

Außerdem enthalten viele Drucker **Protokolle mit Benutzernamen** oder können sogar **alle Benutzernamen** vom Domain Controller **herunterladen**.

All diese **sensiblen Informationen** und der weitverbreitete **Sicherheitsmangel** machen Drucker für Angreifer sehr interessant.

Einige einführende Blogbeiträge zu diesem Thema:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Druckerkonfiguration

- **Standort**: Die LDAP-Serverliste befindet sich normalerweise in der Weboberfläche (z. B. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Verhalten**: Viele eingebettete Webserver erlauben Änderungen am LDAP-Server, **ohne dass die Anmeldedaten erneut eingegeben werden müssen** (Komfortfunktion → Sicherheitsrisiko).
- **Exploit**: Leite die LDAP-Serveradresse zu einem vom Angreifer kontrollierten Host um und verwende die Schaltfläche *Test Connection* / *Address Book Sync*, um den Drucker zu zwingen, einen Bind zu dir herzustellen.

---

## Anmeldedaten abfangen

### Methode 1 – Netcat-Listener

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

Ein einfacher BindRequest kann den Bind-DN und das Passwort im BER-Datenstrom offenlegen, selbst wenn der Server die Anmeldung später ablehnt. Eine anonyme Abfrage oder eine SASL-Aushandlung allein legt dieses gespeicherte Passwort nicht offen.<sup>[[8]](#references)</sup>

Ein einfacher `nc`-Listener auf Port 636/3269 sieht einen TLS-Handshake, keinen LDAP-Bind. LDAPS erfordert einen TLS-fähigen Endpunkt. Die Zertifikatsvalidierung allein verhindert keinen Pass-back, wenn der Drucker einen geänderten Hostnamen akzeptiert und der neue Endpunkt ein gültiges Zertifikat für diesen Hostnamen besitzt; der Client muss außerdem einschränken, welcher Server die gespeicherten Zugangsdaten empfangen darf.<sup>[[8]](#references)</sup>

### Methode 2 – Vollständiger Rogue-LDAP-Server (empfohlen)

Ein Drucker benötigt möglicherweise eine gültige LDAP-Antwort, bevor er einen Bind versucht.<sup>[[10]](#references)</sup> Ein vollständiger LDAP-Server kann diesen vorläufigen Austausch abwickeln, aber er kann einen Client, der auf einen starken SASL-Mechanismus oder den vorgesehenen TLS-Server festgelegt ist, nicht dazu bringen, sein Passwort offenzulegen.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # use a base DN compatible with the printer lookup

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Behandle eine Abfrage als Beleg für eine Verbindung, nicht als Nachweis für die Offenlegung eines Passworts. Ein Passwort wird nur offengelegt, wenn der Client bei einem Bind ein Passwort im Klartext sendet; prüfe den tatsächlichen Bind-Mechanismus und den TLS-Status.<sup>[[8]](#references)</sup>

> 💡  Responder umfasst Rogue-LDAP- und SMB-Authentifizierungsdienste. Ein einfacher LDAP-Bind kann das konfigurierte Passwort offenlegen, während die NTLM-Authentifizierung Challenge-Response-Material erzeugt. Beschreibe nicht beide Ergebnisse als Passwort im Klartext.

### Auswahl des SASL-Mechanismus

Einige LDAP-Clients von Druckern wählen aus den Mechanismen, die ein LDAP-Server anbietet.<sup>[[8]](#references)[[10]](#references)</sup> Untersuchungen zeigten, dass ein Client, der einen angebotenen SASL-Mechanismus akzeptiert, der Passwörter im Klartext übertragen kann, ein Passwort senden könnte, während seine übliche NTLM-Aushandlung nur Challenge-Response-Daten liefern würde.<sup>[[9]](#references)[[10]](#references)</sup> Dies ist ein **Fehler in der Client-Richtlinie** und keine Eigenschaft aller SASL-Binds: Ein Client, der einen stärkeren Mechanismus voraussetzt oder den vorgesehenen TLS-Server festlegt, sollte stattdessen die Verbindung sicher abbrechen.<sup>[[8]](#references)</sup> OpenLDAP deaktiviert SASL-Mechanismen, die Klartextübertragung ermöglichen, standardmäßig. Ein unveränderter Daemon belegt daher nicht, dass dieses Verhalten bei einem Drucker auftritt.<sup>[[11]](#references)</sup>

---

## Aktuelle Pass-Back-Schwachstellen (2024-2025)

Pass-Back ist *kein* theoretisches Problem – Hersteller veröffentlichen auch 2024/2025 weiterhin Hinweise, die diese Angriffsklasse genau beschreiben.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 der Xerox VersaLink C70xx MFPs ermöglichte es einem authentifizierten Admin (oder jedem, wenn die Standard-Zugangsdaten noch gültig waren):

* **CVE-2024-12510 – LDAP-Pass-Back**: Die LDAP-Serveradresse ändern und eine Abfrage auslösen, wodurch das Gerät die konfigurierten Windows-Zugangsdaten an den vom Angreifer kontrollierten Host übermittelt.
* **CVE-2024-12511 – SMB/FTP-Pass-Back**: Dasselbe Problem über *Scan-to-Folder*-Ziele, wodurch NetNTLMv2- oder FTP-Zugangsdaten im Klartext offengelegt werden.<sup>[[2]](#references)</sup>

Ein einfacher Listener wie:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

oder ein Rogue-SMB-Server (`impacket-smbserver`) reicht aus, um die Zugangsdaten abzugreifen.  

### Canon imageRUNNER / imageCLASS – Advisory vom 20. Mai 2025

Canon bestätigte eine **SMTP/LDAP-pass-back**-Schwachstelle in Dutzenden Produktreihen von Laserdruckern und MFPs. Ein Angreifer mit Administratorzugriff kann die Serverkonfiguration ändern und die gespeicherten Zugangsdaten für LDAP **oder** SMTP auslesen (viele Unternehmen verwenden ein privilegiertes Konto für die Scan-to-Mail-Funktion).<sup>[[3]](#references)</sup>

Der Hersteller empfiehlt ausdrücklich:

1. So bald wie verfügbar ein gepatchtes Firmware-Update installieren.
2. Starke, einzigartige Administratorpasswörter verwenden.
3. Für die Druckerintegration keine privilegierten AD-Konten verwenden.

---

### Brother-Geräte und OEM-Varianten – aus der Seriennummer abgeleiteter Administratorzugriff auf Dienstzugangsdaten

Eine koordinierte Offenlegung im Jahr 2025 demonstrierte eine besonders nützliche Angriffskette auf betroffenen Brother-Geräten; Teile der Schwachstellen betreffen auch OEM-Modelle. Prüfen Sie daher das genaue Modell anhand des Sicherheitshinweises des Herstellers. Ein nicht authentifizierter Angreifer kann bei anfälliger Firmware die Geräteseriennummer über HTTP/HTTPS/IPP abrufen. Seriennummern können außerdem über Verwaltungsprotokolle wie SNMP oder PJL verfügbar sein. Wurde das werkseitige Passwort nie geändert, lässt sich daraus deterministisch das Administratorpasswort ableiten. Nach der Authentifizierung gibt die separate pass-back-Schwachstelle CVE-2024-51984 konfigurierte Passwörter für externe Dienste wie LDAP oder FTP im Klartext preis. So wird der Zugriff auf die Druckerverwaltung zur Quelle wiederverwendbarer Netzwerkzugangsdaten. Die Firmware behebt das Offenlegen der Dienstpasswörter, aber bei bereits hergestellten Geräten muss der Betreiber weiterhin das aus der Seriennummer abgeleitete anfängliche Administratorpasswort ersetzen.<sup>[[6]](#references)</sup>

Die aktuelle Metasploit-Version enthält ein Auxiliary-Modul, das die Seriennummer über HTTP, SNMP oder PJL ermittelt, das mögliche anfängliche Passwort generiert und es optional an der Webkonsole überprüft. `DiscoverSerialVia=AUTO` versucht die unterstützten Ermittlungsmethoden; ist die Seriennummer bereits im Anlagenverzeichnis enthalten, geben Sie stattdessen `TargetSerial` an.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Verwende das Ergebnis ausschließlich zur Validierung autorisierter Assets. Ob das Passwort funktioniert, hängt vom genauen Modell ab und vor allem davon, ob das werkseitige Administratorpasswort bereits geändert wurde.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Automatisierte Enumeration- / Exploitation-Tools

| Tool | Zweck | Beispiel |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Missbrauch von PostScript/PJL/PCL, Dateisystemzugriff, Prüfung von Standard-Credentials, *SNMP-Erkennung*; siehe [PJL assessment](../../network-services-pentesting/9100-pjl.md) | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Auslesen von Konfigurationen (einschließlich Adressbüchern und LDAP-Credentials) über HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Rogue-Authentifizierungsdienste ausführen und NetNTLM von SMB-Callbacks abfangen/weiterleiten | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Seriennummer ermitteln, daraus das mögliche werkseitige Administratorpasswort ableiten und den Zugriff auf die Webkonsole überprüfen | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Härtung & Erkennung

1. **MFPs zeitnah patchen / Firmware aktualisieren** (Bulletins des Hersteller-PSIRT prüfen).
2. **Werkseitige Administratorpasswörter ersetzen** – allein durch Firmware werden seriennummernbasierte Initialpasswörter auf bereits hergestellten betroffenen Brother-/OEM-Geräten nicht entfernt.<sup>[[6]](#references)</sup>
3. **Dienstkonten mit den geringsten Berechtigungen** – niemals Domain Admin für LDAP/SMB/SMTP verwenden; auf *schreibgeschützte* OU-Bereiche beschränken.
4. **Verwaltungszugriff einschränken** – Web-/IPP-/SNMP-Schnittstellen des Druckers in ein Management-VLAN oder hinter eine ACL/VPN platzieren.
5. **Ausgehenden Datenverkehr des Druckers begrenzen** – jedem Gerät nur Verbindungen zu den erwarteten DC-/LDAP-, Mail-, DNS/NTP-, Druck- und Scan-Dateizielen erlauben. Pass-back erfordert einen Callback an einen vom Angreifer ausgewählten Endpunkt.
6. **Nicht verwendete Protokolle deaktivieren** – FTP, Telnet, raw-9100, ältere SSL-Chiffren.
7. **Audit-Logging aktivieren** – manche Geräte können LDAP-/SMTP-Fehler per Syslog protokollieren; unerwartete Binds korrelieren.
8. **Authentifizierungsziele überwachen** – Alarm auslösen, wenn ein Drucker LDAP, SMB, SMTP oder FTP zu einem Host außerhalb seiner Allowlist initiiert, insbesondere unmittelbar nach einer Verwaltungsanmeldung oder einer Konfigurationsänderung.
9. **SNMPv3 verwenden oder SNMP deaktivieren** – die Community `public` gibt häufig Geräte- und Seriennummerninformationen preis.

---



---



## References

- [1] [Es ist doch nur ein Drucker … Was könnte schon passieren?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunktionsdrucker: Pass-Back-Angriffsschwachstellen (behoben)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Maßnahmen zur Minderung/Behebung von Schwachstellen bei Produktionsdruckern, Multifunktionsdruckern für Büro und Kleinbüro sowie Laserdruckern](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Domain-Credentials über einen Drucker mit Netcat erhalten](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Multifunktionsdrucker während eines Penetrationstests ausnutzen](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Mehrere Brother-Geräte: Mehrere Schwachstellen (BEHOBEN)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Modul zum Umgehen der Standard-Administrator-Authentifizierung bei Brother-Geräten](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
- [8] [RFC 4513 – LDAP-Authentifizierungsmethoden und Sicherheitsmechanismen](https://datatracker.ietf.org/doc/html/rfc4513)
- [9] [LDAP-passback-Docker-Server](https://github.com/cybertrinchera/ldap-passback-docker)
- [10] [LDAP-Pass-back-Angriff – ACCEIS](https://www.acceis.fr/ldap-pass-back-attack/)
- [11] [slapd-config(5) – SASL-Sicherheitseigenschaften](https://man7.org/linux/man-pages/man5/slapd-config.5.html)
{{#include ../../banners/hacktricks-training.md}}
