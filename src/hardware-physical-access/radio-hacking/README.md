# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

Οι δοκιμές ασφάλειας ραδιοεπικοινωνιών εξετάζουν τον τρόπο με τον οποίο μια συσκευή εκπέμπει, λαμβάνει και ερμηνεύει ασύρματα σήματα. Ένα software-defined radio (SDR) μπορεί να βοηθήσει στον εντοπισμό ενός σήματος, στην καταγραφή δειγμάτων in-phase/quadrature (I/Q) και στη δοκιμή demodulation και decoding, χωρίς να απαιτείται εξειδικευμένο hardware για συγκεκριμένα πρωτόκολλα.<sup>[[1]](#references)</sup>

Μια πρακτική ροή εργασίας είναι να προσδιορίσετε τη ζώνη συχνοτήτων και το εύρος καναλιού, να καταγράψετε διάφορες γνωστές ενέργειες της συσκευής, να συγκρίνετε τα σήματα που προκύπτουν και, στη συνέχεια, να προσδιορίσετε τη διαμόρφωση και τη δομή των πακέτων. Δοκιμάστε αναπαραγωγή ή μετάδοση μόνο σε απομονωμένο περιβάλλον και σε συχνότητες και εξοπλισμό για τους οποίους έχετε εξουσιοδότηση. Οι σελίδες αυτής της ενότητας καλύπτουν RFID, NFC, sub-GHz radio, infrared, BLE και σχετικά εργαλεία.<sup>[[1]](#references)</sup>

## Βρείτε το κατάλληλο interface

- Για κάρτα πρόσβασης ή κλειδί επαφής, ξεκινήστε με τους [τύπους ετικετών RFID/NFC και τις επιθέσεις](pentesting-rfid.md), τις [ροές εργασίας Proxmark3](proxmark-3.md) ή τα [κλειδιά iButton και 1-Wire](ibutton.md). Ο [οδηγός Flipper Zero](flipper-zero/README.md) παραπέμπει σε ενέργειες ειδικές για το interface του.
- Για σήμα τηλεχειριστηρίου, χρησιμοποιήστε το [RF sub-GHz και τους κυλιόμενους κωδικούς](sub-ghz-rf.md) ή τα [πρωτόκολλα και τις επιθέσεις infrared](infrared.md).
- Για κοντινές συσκευές και αισθητήρες, χρησιμοποιήστε τις [δοκιμές BLE advertising, GATT και mesh](pentesting-ble-bluetooth-low-energy.md) ή την [ασφάλεια LPWAN/LoRaWAN](low-power-wide-area-network.md).
- Για καταγεγραμμένα ή άγνωστα RF σήματα, χρησιμοποιήστε την [ανάλυση σημάτων SigDigger](../hardware-hacking/radio.md#sigdigger) ή το [framework FISSURE](fissure-the-rf-framework.md).
- Για downlinks δορυφορικών τερματικών, δείτε την [έγχυση σήματος στην προωθητική ζεύξη VSAT](vsat-forward-link-injection.md).



## References

- [1] [Great Scott Gadgets - Ραδιόφωνο οριζόμενο από λογισμικό με HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
