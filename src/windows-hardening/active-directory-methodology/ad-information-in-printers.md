# Πληροφορίες σε Εκτυπωτές

{{#include ../../banners/hacktricks-training.md}}

Υπάρχουν αρκετά blogs στο Internet που **επισημαίνουν τους κινδύνους από την παραμονή εκτυπωτών ρυθμισμένων με LDAP και default/weak** credentials σύνδεσης.  \
Αυτό συμβαίνει επειδή ένας attacker θα μπορούσε να **εξαπατήσει τον εκτυπωτή ώστε να πραγματοποιήσει authenticate σε έναν rogue LDAP server** (συνήθως αρκεί ένα `nc -vv -l -p 389` ή `slapd -d 2`) και να καταγράψει τα **credentials του εκτυπωτή σε clear-text**.

Επίσης, αρκετοί εκτυπωτές περιέχουν **logs με usernames** ή μπορεί ακόμη και να έχουν τη δυνατότητα **λήψης όλων των usernames** από το Domain Controller.

Όλες αυτές οι **sensitive πληροφορίες** και η συνηθισμένη **έλλειψη ασφάλειας** καθιστούν τους εκτυπωτές ιδιαίτερα ενδιαφέροντες για τους attackers.

Μερικά εισαγωγικά blogs σχετικά με το θέμα:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Διαμόρφωση Εκτυπωτή

- **Τοποθεσία**: Η λίστα των LDAP servers βρίσκεται συνήθως στο web interface (π.χ. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Συμπεριφορά**: Πολλοί embedded web servers επιτρέπουν τροποποιήσεις του LDAP server **χωρίς εκ νέου εισαγωγή credentials** (χαρακτηριστικό usability → security risk).
- **Exploit**: Ανακατευθύνετε τη διεύθυνση του LDAP server σε έναν attacker-controlled host και χρησιμοποιήστε το κουμπί *Test Connection* / *Address Book Sync* για να εξαναγκάσετε τον εκτυπωτή να κάνει bind σε εσάς.

---

## Συλλογή Credentials

### Μέθοδος 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```
Μικρά/παλιά MFPs ενδέχεται να στέλνουν ένα απλό *simple-bind*, του οποίου το bind DN και το password είναι ορατά στο raw BER stream. Οι σύγχρονες συσκευές συνήθως εκτελούν πρώτα ένα anonymous query και στη συνέχεια επιχειρούν το bind, επομένως τα αποτελέσματα διαφέρουν.<sup>[[1]](#references)</sup>

Ένας απλός listener `nc` στις θύρες 636/3269 λαμβάνει μόνο TLS ciphertext· για τη δοκιμή LDAPS απαιτείται ένα TLS-capable LDAP endpoint, ενώ η ανακατεύθυνση θα πρέπει να αποτυγχάνει όταν η συσκευή επικυρώνει σωστά το server certificate.

### Μέθοδος 2 – Full Rogue LDAP server (συνιστάται)

Επειδή πολλές συσκευές εκτελούν ένα anonymous search *πριν* από την authentication, η εγκατάσταση ενός πραγματικού LDAP daemon παρέχει πολύ πιο αξιόπιστα αποτελέσματα:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Όταν ο printer εκτελεί το lookup του, θα δείτε τα credentials σε clear-text στο debug output.

> 💡  Το Responder περιλαμβάνει rogue LDAP και SMB authentication services. Ένα απλό LDAP bind μπορεί να εκθέσει το configured password, ενώ το NTLM authentication παράγει challenge-response material· μην περιγράφετε και τα δύο αποτελέσματα ως password σε clear-text.

---

## Πρόσφατα Pass-Back Vulnerabilities (2024-2025)

Το pass-back *δεν* είναι θεωρητικό ζήτημα – οι vendors συνεχίζουν να δημοσιεύουν advisories το 2024/2025 που περιγράφουν ακριβώς αυτή την attack class.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Το firmware ≤ 57.69.91 των Xerox VersaLink C70xx MFPs επέτρεπε σε έναν authenticated admin (ή σε οποιονδήποτε, όταν παρέμεναν τα default creds) να:

* **CVE-2024-12510 – LDAP pass-back**: αλλάξει τη διεύθυνση του LDAP server και να ενεργοποιήσει ένα lookup, προκαλώντας στη συσκευή να κάνει leak τα configured Windows credentials προς το host που ελέγχει ο attacker.
* **CVE-2024-12511 – SMB/FTP pass-back**: ίδιο ζήτημα μέσω προορισμών *scan-to-folder*, με διαρροή NetNTLMv2 ή FTP clear-text creds.<sup>[[2]](#references)</sup>

Ένας απλός listener όπως:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
ή ένας rogue SMB server (`impacket-smbserver`) αρκεί για τη συλλογή των credentials.

### Canon imageRUNNER / imageCLASS – Advisory 20 May 2025

Η Canon επιβεβαίωσε μια αδυναμία **SMTP/LDAP pass-back** σε δεκάδες σειρές προϊόντων Laser & MFP. Ένας attacker με admin access μπορεί να τροποποιήσει τη διαμόρφωση του server και να ανακτήσει τα αποθηκευμένα credentials για LDAP **ή** SMTP (πολλοί οργανισμοί χρησιμοποιούν privileged account για να επιτρέπουν τη λειτουργία scan-to-mail).<sup>[[3]](#references)</sup>

Οι οδηγίες του vendor συνιστούν ρητά:

1. Ενημέρωση σε patched firmware μόλις είναι διαθέσιμο.
2. Χρήση ισχυρών και μοναδικών admin passwords.
3. Αποφυγή privileged AD accounts για την ενσωμάτωση με τον printer.

---

### Brother devices και OEM variants – πρόσβαση admin που προκύπτει από το serial σε service credentials

Μια coordinated disclosure του 2025 απέδειξε μια ιδιαίτερα χρήσιμη αλυσίδα σε επηρεαζόμενες συσκευές Brother· τμήματα του vulnerability set επηρεάζουν επίσης μοντέλα OEM, επομένως επαληθεύστε το ακριβές μοντέλο σύμφωνα με το advisory του vendor. Ένας unauthenticated attacker μπορεί να αποκτήσει το serial της συσκευής μέσω HTTP/HTTPS/IPP σε vulnerable firmware, ενώ τα serials μπορεί επίσης να είναι διαθέσιμα μέσω management protocols όπως SNMP ή PJL. Αν το factory password δεν έχει αλλάξει ποτέ, το serial παράγει ντετερμινιστικά το administrator password. Μετά το authentication, το ξεχωριστό pass-back flaw CVE-2024-51984 εκθέτει σε plaintext τα διαμορφωμένα passwords εξωτερικών services, όπως LDAP ή FTP, μετατρέποντας την πρόσβαση στο printer management σε επαναχρησιμοποιήσιμα network credentials. Το firmware διορθώνει την αποκάλυψη των service passwords, όμως οι συσκευές που είχαν κατασκευαστεί προηγουμένως εξακολουθούν να απαιτούν από τον operator την αντικατάσταση του αρχικού administrator password που προκύπτει από το serial.<sup>[[6]](#references)</sup>

Το τρέχον Metasploit περιλαμβάνει auxiliary module που εντοπίζει το serial μέσω HTTP, SNMP ή PJL, δημιουργεί το υποψήφιο αρχικό password και προαιρετικά το επαληθεύει στο web console. Το `DiscoverSerialVia=AUTO` δοκιμάζει τις υποστηριζόμενες διαδρομές discovery· χρησιμοποιήστε `TargetSerial` όταν το asset inventory περιέχει ήδη το serial.<sup>[[7]](#references)</sup>
```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```
Χρησιμοποιήστε το αποτέλεσμα μόνο για την επικύρωση εξουσιοδοτημένων assets. Το αν λειτουργεί ο κωδικός πρόσβασης εξαρτάται από το ακριβές μοντέλο και, κυρίως, από το αν ο εργοστασιακός κωδικός πρόσβασης administrator έχει ήδη αλλάξει.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Automated Enumeration / Exploitation Tools

| Tool | Purpose | Example |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Κατάχρηση PostScript/PJL/PCL, πρόσβαση στο file system, έλεγχος default-creds, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Συλλογή configuration (συμπεριλαμβανομένων address books και LDAP creds) μέσω HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Εκτέλεση rogue authentication services και capture/relay NetNTLM από SMB callbacks | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Εντοπισμός serial, derivation του υποψήφιου εργοστασιακού κωδικού πρόσβασης administrator και επαλήθευση πρόσβασης στην web console | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Hardening & Detection

1. **Κάντε άμεσα patch / firmware-update** στα MFPs (ελέγξτε τα PSIRT bulletins του vendor).
2. **Αντικαταστήστε τους εργοστασιακούς κωδικούς πρόσβασης administrator** – το firmware από μόνο του δεν αφαιρεί τους αρχικούς κωδικούς πρόσβασης που προκύπτουν από το serial number σε ήδη κατασκευασμένες επηρεαζόμενες συσκευές Brother/OEM.<sup>[[6]](#references)</sup>
3. **Service Accounts με Least Privilege** – μην χρησιμοποιείτε ποτέ Domain Admin για LDAP/SMB/SMTP· περιορίστε τα σε *read-only* OU scopes.
4. **Περιορίστε την πρόσβαση διαχείρισης** – τοποθετήστε τα web/IPP/SNMP interfaces του printer σε management VLAN ή πίσω από ACL/VPN.
5. **Περιορίστε το egress του printer** – επιτρέψτε σε κάθε συσκευή να επικοινωνεί μόνο με τους αναμενόμενους προορισμούς DC/LDAP, mail, DNS/NTP, print και scan-file. Το pass-back απαιτεί callback σε endpoint που επιλέγει ο attacker.
6. **Απενεργοποιήστε τα μη χρησιμοποιούμενα πρωτόκολλα** – FTP, Telnet, raw-9100, παλαιότερα SSL ciphers.
7. **Ενεργοποιήστε Audit Logging** – ορισμένες συσκευές μπορούν να καταγράφουν αποτυχίες LDAP/SMTP μέσω syslog· συσχετίστε μη αναμενόμενα binds.
8. **Παρακολουθείτε τους authentication destinations** – δημιουργήστε alert όταν ένας printer ξεκινά LDAP, SMB, SMTP ή FTP προς host εκτός της allowlist του, ειδικά αμέσως μετά από management login ή αλλαγή configuration.
9. **SNMPv3 ή απενεργοποίηση του SNMP** – το community `public` συχνά κάνει leak πληροφορίες συσκευής και serial.

---



---

## References

- [1] [Είναι απλώς ένας printer… Ποιο είναι το χειρότερο που θα μπορούσε να συμβεί;](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Ευπάθειες Pass-Back Attack (Fixed)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Mitigation/Remediation ευπάθειας για Production Printers, Office/Small Office Multifunction Printers και Laser Printers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Απόκτηση Domain Credentials μέσω Printer με Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Εκμετάλλευση Multifunction Printers κατά τη διάρκεια Penetration Test Engagement](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Multiple Brother Devices: Multiple Vulnerabilities (FIXED)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Brother default administrator authentication bypass module](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
