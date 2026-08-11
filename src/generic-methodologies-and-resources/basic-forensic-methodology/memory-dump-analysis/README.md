# Ανάλυση memory dump

{{#include ../../../banners/hacktricks-training.md}}

## Έναρξη

Ξεκινήστε να **αναζητάτε** **malware** μέσα στο pcap. Χρησιμοποιήστε τα **tools** που αναφέρονται στο [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

Το **Volatility είναι ένα open-source framework για την ανάλυση memory dump**. Αυτό το Python tool αναλύει dumps από εξωτερικές πηγές ή VMware VMs, εντοπίζοντας δεδομένα όπως processes και passwords με βάση το OS profile του dump. Είναι επεκτάσιμο με plugins, γεγονός που το καθιστά ιδιαίτερα ευέλικτο για forensic investigations.<sup>[[1]](#references)[[2]](#references)</sup>

[**Βρείτε εδώ ένα cheatsheet**](volatility-cheatsheet.md)

## Αναφορά crash από mini dump

Όταν το dump είναι μικρό (μόνο μερικά KB, ίσως λίγα MB), μπορεί να είναι αναφορά crash από mini dump και όχι πλήρες memory dump.<sup>[[3]](#references)</sup>

![Volatility - Αναφορά crash από mini dump: Ένα μικρό dump file που αναγνωρίστηκε ως αναφορά crash Mini DuMP](<../../../images/image (532).png>)

Αν έχετε εγκατεστημένο το Visual Studio, μπορείτε να ανοίξετε αυτό το file για να δείτε βασικές πληροφορίες, όπως το όνομα του process, την αρχιτεκτονική, τις λεπτομέρειες του exception και τα loaded modules:<sup>[[4]](#references)</sup>

![Volatility - Αναφορά crash από mini dump: Αν έχετε εγκατεστημένο το Visual Studio, μπορείτε να ανοίξετε αυτό το file και να δείτε βασικές πληροφορίες, όπως το όνομα του process, την αρχιτεκτονική, τις πληροφορίες του exception και...](<../../../images/image (263).png>)

Μπορείτε επίσης να επιθεωρήσετε το exception και να δείτε το disassembly του module.<sup>[[4]](#references)</sup>

![Πίνακας Actions του Visual Studio minidump με επιλογές για native debugging και ορισμό symbol paths](<../../../images/image (142).png>)

![Disassembly του Visual Studio με instructions από το exception του minidump](<../../../images/image (610).png>)

Σε κάθε περίπτωση, το Visual Studio δεν είναι το καλύτερο tool για να πραγματοποιήσετε ανάλυση σε βάθος του dump.

Θα πρέπει να το **ανοίξετε** χρησιμοποιώντας **IDA** ή **Radare**, για να το επιθεωρήσετε σε **βάθος**.

## References

- [1] [Volatility Framework](https://github.com/volatilityfoundation/volatility)
- [2] [Χρήση του Volatility](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Αρχεία Minidump](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Χρήση dump files στο Visual Studio debugger](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
