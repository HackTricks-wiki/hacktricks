# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή

Για περισσότερες πληροφορίες σχετικά με το iButton, δείτε:


{{#ref}}
../ibutton.md
{{#endref}}

## Σχεδιασμός

Το **μπλε** τμήμα της παρακάτω εικόνας δείχνει πώς πρέπει να **τοποθετήσετε το πραγματικό iButton**, ώστε το Flipper να μπορεί να **το διαβάσει.** Το **πράσινο** τμήμα δείχνει πώς πρέπει να **αγγίξετε τον reader** με το Flipper Zero, ώστε να **προσομοιώσετε σωστά ένα iButton**.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Ενέργειες

### Ανάγνωση

Στη λειτουργία ανάγνωσης, το Flipper περιμένει να αγγίξει το iButton key και μπορεί να επεξεργαστεί οποιονδήποτε από τους τρεις τύπους keys: **Dallas, Cyfral και Metakom**. Το Flipper θα **εντοπίσει μόνο του τον τύπο του key**. Το όνομα του πρωτοκόλλου του key θα εμφανιστεί στην οθόνη, πάνω από τον αριθμό ID.<sup>[[1]](#references)</sup>

### Μη αυτόματη προσθήκη

Είναι δυνατή η **μη αυτόματη προσθήκη** ενός iButton τύπου: **Dallas, Cyfral και Metakom**

### **Προσομοίωση**

Είναι δυνατή η **προσομοίωση** αποθηκευμένων iButtons (που διαβάστηκαν ή προστέθηκαν μη αυτόματα).

> [!TIP]
> Αν δεν μπορείτε να επιτύχετε τις αναμενόμενες επαφές του Flipper Zero με τον reader, μπορείτε να **χρησιμοποιήσετε το εξωτερικό GPIO:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## Αναφορές

- [1] [Taming iButton Keys with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
