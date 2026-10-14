# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή

Για πληροφορίες σχετικά με την τεχνολογία iButton, δείτε:

{{#ref}}
../ibutton.md
{{#endref}}

## Σχεδιασμός

Στην παρακάτω εικόνα, η **μπλε** περιοχή δείχνει πώς να τοποθετήσετε ένα φυσικό iButton στις επαφές του Flipper Zero για ανάγνωση. Η **πράσινη** περιοχή δείχνει ποιες επαφές πρέπει να ακουμπούν σε έναν reader κατά την εξομοίωση.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Ενέργειες

### Ανάγνωση

Στη λειτουργία Read, το Flipper Zero περιμένει να ακουμπήσει ένα κλειδί στις επαφές του, ανιχνεύει το πρωτόκολλο και εμφανίζει το πρωτόκολλο πάνω από το ID του κλειδιού. Η ενσωματωμένη εφαρμογή υποστηρίζει κλειδιά ελέγχου πρόσβασης Dallas, Cyfral και Metakom.<sup>[[2]](#references)</sup>

### Μη αυτόματη προσθήκη

Μπορείτε να εισαγάγετε μη αυτόματα τα δεδομένα κλειδιών για τα πρωτόκολλα Dallas, Cyfral και Metakom.<sup>[[2]](#references)</sup>

### Εξομοίωση

Μπορείτε να εξομοιώσετε ένα αποθηκευμένο κλειδί, είτε διαβάστηκε από φυσικό κλειδί είτε καταχωρίστηκε μη αυτόματα.<sup>[[2]](#references)</sup>

> [!TIP]
> Αν οι ενσωματωμένες επαφές δεν φτάνουν στον reader, συνδέστε τις επαφές δεδομένων και γείωσης μέσω των ακίδων GPIO.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Εξημερώνοντας τα κλειδιά iButton με το Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Τεκμηρίωση Flipper Zero - Ανάγνωση κλειδιών iButton](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}

