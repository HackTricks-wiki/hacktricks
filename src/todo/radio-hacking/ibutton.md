# iButton

{{#include ../../banners/hacktricks-training.md}}

## Εισαγωγή

Το iButton είναι μια γενική ονομασία για ένα ηλεκτρονικό κλειδί αναγνώρισης, τοποθετημένο σε ένα **μεταλλικό περίβλημα σε σχήμα νομίσματος**. Ονομάζεται επίσης μνήμη **Dallas Touch** ή μνήμη επαφής. Παρόλο που συχνά αναφέρεται λανθασμένα ως «μαγνητικό» κλειδί, δεν περιέχει **τίποτα μαγνητικό**. Στην πραγματικότητα, στο εσωτερικό του κρύβεται ένα πλήρες **microchip** που λειτουργεί με ψηφιακό πρωτόκολλο.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Τι είναι το iButton; <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Η ονομασία iButton περιγράφει το ανθεκτικό περίβλημα σε σχήμα νομίσματος και τη διάταξη των επαφών. Οι υποδοχές περιλαμβάνουν πλαστικά fobs, δαχτυλίδια και μενταγιόν.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Όταν και οι δύο επαφές έρθουν σε επαφή με τον reader, η συσκευή λαμβάνει ρεύμα και ανταλλάσσει δεδομένα. Αν η εσοχή στη γεωμετρία των επαφών εμποδίζει την επαφή των εξωτερικών επαφών γείωσης, η κλίση του κλειδιού πάνω στο τοίχωμα του reader μπορεί να αποκαταστήσει την επαφή.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Πρωτόκολλο 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Τα κλειδιά Dallas/Maxim χρησιμοποιούν το πρωτόκολλο 1-Wire: μία επαφή δεδομένων μεταφέρει αμφίδρομη επικοινωνία και μπορεί επίσης να παρέχει παρασιτική τροφοδοσία, ενώ το μεταλλικό περίβλημα αποτελεί την επαφή επιστροφής. Ο controller ξεκινά τις συναλλαγές και η συσκευή αποκρίνεται.<sup>[[2]](#references)</sup>

Όταν το κλειδί (Slave) έρθει σε επαφή με το intercom (Master), το chip στο εσωτερικό του κλειδιού ενεργοποιείται, τροφοδοτούμενο από το intercom, και το κλειδί αρχικοποιείται. Στη συνέχεια, το intercom ζητά το ID του κλειδιού. Παρακάτω θα εξετάσουμε αυτή τη διαδικασία λεπτομερέστερα.

Το Flipper μπορεί να λειτουργήσει ως controller κατά την ανάγνωση ενός κλειδιού και ως emulated device όταν παρουσιάζει ένα αποθηκευμένο identifier σε έναν reader.<sup>[[1]](#references)</sup>

### Κλειδιά Dallas, Cyfral & Metakom

Για πληροφορίες σχετικά με τον τρόπο λειτουργίας αυτών των κλειδιών, δείτε τη σελίδα [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Επιθέσεις

Τα iButton μπορούν να αποτελέσουν στόχο επίθεσης με το Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Εξοικείωση με το iButton μέσω του Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — Επικοινωνία 1-Wire μέσω λογισμικού](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
