# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή

Για βασικές πληροφορίες σχετικά με την τεχνολογία iButton, δείτε:

{{#ref}}
../ibutton.md
{{#endref}}

## Σχεδιασμός

Στην παρακάτω εικόνα, η **μπλε** περιοχή δείχνει πώς να τοποθετήσετε ένα φυσικό iButton επάνω στις επαφές του Flipper Zero για ανάγνωση. Η **πράσινη** περιοχή δείχνει ποιες επαφές πρέπει να αγγίζουν έναν reader κατά την emulation.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Ενέργειες

### Ανάγνωση

Στη λειτουργία ανάγνωσης, το Flipper Zero περιμένει να αγγίξει μια επαφή ένα κλειδί, ανιχνεύει το protocol και εμφανίζει το protocol πάνω από το ID του κλειδιού. Η ενσωματωμένη εφαρμογή υποστηρίζει access-control keys των Dallas, Cyfral και Metakom.<sup>[[2]](#references)</sup>

### Χειροκίνητη προσθήκη

Μπορείτε να εισαγάγετε χειροκίνητα τα δεδομένα κλειδιού για τα protocols Dallas, Cyfral και Metakom.<sup>[[2]](#references)</sup>

### Emulate

Μπορείτε να κάνετε emulate ένα αποθηκευμένο κλειδί, είτε αυτό διαβάστηκε από ένα φυσικό κλειδί είτε εισήχθη χειροκίνητα.<sup>[[2]](#references)</sup>

> [!TIP]
> Αν οι ενσωματωμένες επαφές δεν μπορούν να φτάσουν τον reader, συνδέστε τις επαφές data και ground μέσω των ακροδεκτών GPIO.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Εξοικείωση με τα iButton Keys μέσω του Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Τεκμηρίωση Flipper Zero - Ανάγνωση iButton Keys](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}
