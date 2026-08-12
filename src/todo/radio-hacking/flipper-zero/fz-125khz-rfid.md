# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή

Για βασικές πληροφορίες σχετικά με τον τρόπο λειτουργίας των tags 125 kHz, δείτε:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

Η [εισαγωγή στα RFID χαμηλής συχνότητας](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) εξηγεί τις συνήθεις οικογένειες tags και τις μορφές των δεδομένων τους.

## Ενέργειες

### Read

Χρησιμοποιήστε το **Read** για να καταγράψετε τα δεδομένα του tag. Μετά από μια επιτυχημένη ανάγνωση, το Flipper Zero μπορεί να προσομοιώσει το αποθηκευμένο tag.<sup>[[1]](#references)</sup>

> [!WARNING]
> Ορισμένοι readers ενδοεπικοινωνίας προσπαθούν να εντοπίσουν εγγράψιμα duplicate tags εκδίδοντας μια εντολή εγγραφής πριν από την ανάγνωση. Μια προσομοίωση Flipper Zero δεν παρέχει πρόσβαση στη μνήμη εγγράψιμου tag με τον ίδιο τρόπο.<sup>[[1]](#references)</sup>

### Προσθήκη χειροκίνητα

Μπορείτε να εισαγάγετε χειροκίνητα τα δεδομένα του tag στο Flipper Zero, να τα αποθηκεύσετε και στη συνέχεια να το προσομοιώσετε.<sup>[[1]](#references)</sup>

#### IDs σε κάρτες

Μερικές φορές μια κάρτα έχει τυπωμένο στο εξωτερικό της ολόκληρο ή μέρος του ID της.

- **EM Marin**

Για παράδειγμα, η απεικονιζόμενη κάρτα EM-Marin εμφανίζει τα τρία τελευταία από τα πέντε bytes του ID της. Αν δεν είναι δυνατή η ανάγνωση του tag, τα δύο bytes που λείπουν μπορούν να υποβληθούν σε brute-force.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Παρομοίως, η απεικονιζόμενη κάρτα HID εμφανίζει μόνο δύο από τα τρία bytes του ID της.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

Μετά την ανάγνωση ενός tag ή τη χειροκίνητη εισαγωγή του ID του, το Flipper Zero μπορεί να προσομοιώσει το αποθηκευμένο credential. Για υποστηριζόμενα εγγράψιμα tags, μπορεί επίσης να γράψει τα αποθηκευμένα δεδομένα σε μια συμβατή κάρτα.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Εμβάθυνση στα πρωτόκολλα RFID](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
