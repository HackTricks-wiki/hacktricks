# Ανάλυση memory dump

## Έναρξη

Ξεκινήστε **αναζητώντας** **malware** μέσα στο pcap. Χρησιμοποιήστε τα **εργαλεία** που αναφέρονται στο [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Το Volatility είναι ένα open-source framework για την ανάλυση memory dump**. Αυτό το εργαλείο Python αναλύει dump από εξωτερικές πηγές ή VMware VMs, εντοπίζοντας δεδομένα όπως processes και passwords, με βάση το OS profile του dump. Είναι επεκτάσιμο μέσω plugins, γεγονός που το καθιστά ιδιαίτερα ευέλικτο για forensic investigations.<sup>[[1]](#references)[[2]](#references)</sup>

[**Βρείτε εδώ ένα cheatsheet**](volatility-cheatsheet.md)

## Αναφορά σφάλματος από mini dump

Όταν το dump είναι μικρό (μόλις μερικά KB, ίσως λίγα MB), μπορεί να είναι αναφορά σφάλματος από mini dump και όχι πλήρες memory dump.<sup>[[3]](#references)</sup>

![Volatility - Αναφορά σφάλματος από mini dump: Ένα μικρό αρχείο dump που αναγνωρίστηκε ως αναφορά σφάλματος Mini DuMP](<../../../images/image (532).png>)

Αν έχετε εγκατεστημένο το Visual Studio, μπορείτε να ανοίξετε αυτό το αρχείο για να δείτε βασικές πληροφορίες, όπως το όνομα του process, την αρχιτεκτονική, τις λεπτομέρειες του exception και τα loaded modules:<sup>[[4]](#references)</sup>

![Volatility - Αναφορά σφάλματος από mini dump: Αν έχετε εγκατεστημένο το Visual Studio, μπορείτε να ανοίξετε αυτό το αρχείο και να ανακτήσετε βασικές πληροφορίες, όπως το όνομα του process, την αρχιτεκτονική, τις πληροφορίες του exception και...](<../../../images/image (263).png>)

Μπορείτε επίσης να εξετάσετε το exception και να δείτε το disassembly του module.<sup>[[4]](#references)</sup>

![Πίνακας Actions του Visual Studio για minidump, με επιλογές για native debugging και ορισμό paths συμβόλων](<../../../images/image (142).png>)

![Disassembly του Visual Studio με instructions από το exception του minidump](<../../../images/image (610).png>)

Σε κάθε περίπτωση, το Visual Studio δεν είναι το καλύτερο εργαλείο για ανάλυση σε βάθος του dump.

Θα πρέπει να το **ανοίξετε** χρησιμοποιώντας **IDA** ή **Radare**, για να το εξετάσετε σε **βάθος**.

## References

- [1] [Framework Volatility](https://github.com/volatilityfoundation/volatility)
- [2] [Χρήση του Volatility](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Αρχεία Minidump](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Χρήση αρχείων dump στο πρόγραμμα εντοπισμού σφαλμάτων του Visual Studio](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
