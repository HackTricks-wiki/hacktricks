# Πληροφορίες στους Εκτυπωτές

{{#include ../../banners/hacktricks-training.md}}

Υπάρχουν αρκετά blogs στο Διαδίκτυο που **επισημαίνουν τους κινδύνους από την παραμονή εκτυπωτών ρυθμισμένων με LDAP και προεπιλεγμένα/αδύναμα** credentials σύνδεσης.  \
Αυτό συμβαίνει επειδή ένας attacker θα μπορούσε να **ξεγελάσει τον εκτυπωτή ώστε να κάνει authenticate σε έναν rogue LDAP server** (συνήθως αρκεί ένα `nc -vv -l -p 389` ή `slapd -d 2`) και να καταγράψει τα **credentials του εκτυπωτή σε clear-text**.

Επίσης, αρκετοί εκτυπωτές περιέχουν **logs με usernames** ή μπορεί ακόμη και να έχουν τη δυνατότητα **λήψης όλων των usernames** από τον Domain Controller.

Όλες αυτές οι **ευαίσθητες πληροφορίες** και η συνηθισμένη **έλλειψη ασφάλειας** καθιστούν τους εκτυπωτές ιδιαίτερα ενδιαφέροντες για τους attackers.

Μερικά εισαγωγικά blogs σχετικά με το θέμα:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Ρύθμιση Εκτυπωτή

- **Τοποθεσία**: Η λίστα των LDAP servers βρίσκεται συνήθως στο web interface (π.χ. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Συμπεριφορά**: Πολλοί embedded web servers επιτρέπουν τροποποιήσεις του LDAP server **χωρίς εκ νέου εισαγωγή credentials** (χαρακτηριστικό ευχρηστίας → κίνδυνος ασφάλειας).
- **Exploit**: Ανακατευθύνετε τη διεύθυνση του LDAP server σε έναν host που ελέγχεται από τον attacker και χρησιμοποιήστε το κουμπί *Test Connection* / *Address Book Sync* για να εξαναγκάσετε τον εκτυπωτή να κάνει bind σε εσάς.

---

## Συλλογή Credentials

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Μικρές/παλιές MFPs ενδέχεται να στέλνουν ένα απλό *simple-bind* σε clear-text, το οποίο μπορεί να καταγράψει το netcat. Οι σύγχρονες συσκευές συνήθως εκτελούν πρώτα ένα anonymous query και στη συνέχεια επιχειρούν το bind, επομένως τα αποτελέσματα διαφέρουν.<sup>[[1]](#references)</sup>

### Method 2 – Πλήρης Rogue LDAP server (recommended)

Επειδή πολλές συσκευές εκτελούν ένα anonymous search *πριν* από την authenticating διαδικασία, η εγκατάσταση ενός πραγματικού LDAP daemon παρέχει πολύ πιο αξιόπιστα αποτελέσματα:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Κατά την εκτέλεση του lookup από τον printer, θα δείτε τα clear-text credentials στο debug output.

> 💡  Μπορείτε επίσης να χρησιμοποιήσετε το `impacket/examples/ldapd.py` (Python rogue LDAP) ή το `Responder -w -r -f` για να συλλέξετε NTLMv2 hashes μέσω LDAP/SMB.

---

## Πρόσφατα Pass-Back Vulnerabilities (2024-2025)

Το Pass-back *δεν* είναι θεωρητικό ζήτημα – οι vendors συνεχίζουν να δημοσιεύουν advisories το 2024/2025 που περιγράφουν ακριβώς αυτή την κατηγορία επίθεσης.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Τα firmware ≤ 57.69.91 των Xerox VersaLink C70xx MFPs επέτρεπαν σε έναν authenticated admin (ή σε οποιονδήποτε, όταν παρέμεναν τα default creds) να:

* **CVE-2024-12510 – LDAP pass-back**: αλλάξει τη διεύθυνση του LDAP server και να triggerάρει ένα lookup, προκαλώντας στο device να κάνει leak τα configured Windows credentials προς το host που ελέγχει ο attacker.
* **CVE-2024-12511 – SMB/FTP pass-back**: ίδιο ζήτημα μέσω destinations *scan-to-folder*, κάνοντας leak NetNTLMv2 ή FTP clear-text creds.<sup>[[2]](#references)</sup>

Ένας απλός listener, όπως ο εξής:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
ή ένας rogue SMB server (`impacket-smbserver`) αρκεί για τη συλλογή των credentials.

### Canon imageRUNNER / imageCLASS – Advisory 20 May 2025

Η Canon επιβεβαίωσε μια αδυναμία **SMTP/LDAP pass-back** σε δεκάδες σειρές προϊόντων Laser & MFP. Ένας attacker με admin access μπορεί να τροποποιήσει τη ρύθμιση του server και να ανακτήσει τα αποθηκευμένα credentials για LDAP **ή** SMTP (πολλοί οργανισμοί χρησιμοποιούν privileged account για να επιτρέπουν τη λειτουργία scan-to-mail).<sup>[[3]](#references)</sup>

Οι οδηγίες του vendor συνιστούν ρητά:

1. Ενημέρωση σε patched firmware το συντομότερο δυνατό.
2. Χρήση ισχυρών και μοναδικών admin passwords.
3. Αποφυγή privileged AD accounts για την ενσωμάτωση των printers.

---

## Automated Enumeration / Exploitation Tools

| Tool | Purpose | Example |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Κατάχρηση PostScript/PJL/PCL, πρόσβαση στο file-system, έλεγχος default-creds, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Συλλογή configuration (συμπεριλαμβανομένων address books και LDAP creds) μέσω HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Capture και relay NetNTLM hashes από SMB/FTP pass-back | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Lightweight rogue LDAP service για λήψη clear-text binds | `python ldapd.py -debug` |

---

## Hardening & Detection

1. **Patch / firmware-update** των MFPs άμεσα (ελέγχετε τα vendor PSIRT bulletins).
2. **Least-Privilege Service Accounts** – μην χρησιμοποιείτε ποτέ Domain Admin για LDAP/SMB/SMTP· περιορίστε τα σε *read-only* OU scopes.
3. **Restrict Management Access** – τοποθετήστε τα printer web/IPP/SNMP interfaces σε management VLAN ή πίσω από ACL/VPN.
4. **Disable Unused Protocols** – FTP, Telnet, raw-9100, παλαιότερα SSL ciphers.
5. **Enable Audit Logging** – ορισμένες συσκευές μπορούν να καταγράφουν αποτυχίες LDAP/SMTP μέσω syslog· συσχετίστε μη αναμενόμενα binds.
6. **Monitor for Clear-Text LDAP binds** από ασυνήθιστες πηγές (οι printers κανονικά θα πρέπει να επικοινωνούν μόνο με DCs).
7. **SNMPv3 or disable SNMP** – το community `public` συχνά κάνει leak το device & LDAP config.

---

## References

- [1] [It's just a printer… What's the worst that could happen?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back Attack Vulnerabilities (Fixed)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Vulnerability Mitigation/Remediation for Production Printers, Office/Small Office Multifunction Printers and Laser Printers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtaining Domain Credentials through a Printer with Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting Multifunction Printers During A Penetration Test Engagement](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

{{#include ../../banners/hacktricks-training.md}}
