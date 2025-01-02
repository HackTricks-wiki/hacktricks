# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Για περισσότερες πληροφορίες σχετικά με το τι είναι ένα iButton, δείτε:

{{#ref}}
../ibutton.md
{{#endref}}

## Design

Το **μπλε** μέρος της παρακάτω εικόνας είναι πώς θα πρέπει να **τοποθετήσετε το πραγματικό iButton** ώστε το Flipper να **μπορεί να το διαβάσει.** Το **πράσινο** μέρος είναι πώς πρέπει να **αγγίξετε τον αναγνώστη** με το Flipper zero για να **προσομοιώσετε σωστά ένα iButton**.

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Read

Στη λειτουργία Read, το Flipper περιμένει το κλειδί iButton να αγγίξει και είναι ικανό να επεξεργαστεί οποιονδήποτε από τους τρεις τύπους κλειδιών: **Dallas, Cyfral, και Metakom**. Το Flipper θα **καταλάβει τον τύπο του κλειδιού από μόνο του**. Το όνομα του πρωτοκόλλου του κλειδιού θα εμφανίζεται στην οθόνη πάνω από τον αριθμό ID.

### Add manually

Είναι δυνατόν να **προσθέσετε χειροκίνητα** ένα iButton τύπου: **Dallas, Cyfral, και Metakom**

### **Emulate**

Είναι δυνατόν να **προσομοιώσετε** αποθηκευμένα iButtons (διαβασμένα ή προστιθέμενα χειροκίνητα).

> [!NOTE]
> Εάν δεν μπορείτε να κάνετε τις αναμενόμενες επαφές του Flipper Zero να αγγίξουν τον αναγνώστη, μπορείτε να **χρησιμοποιήσετε το εξωτερικό GPIO:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
