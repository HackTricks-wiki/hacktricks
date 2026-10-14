# iButton

{{#include ../../banners/hacktricks-training.md}}

## Εισαγωγή

Το iButton είναι μια γενική ονομασία για ένα ηλεκτρονικό κλειδί αναγνώρισης, συσκευασμένο σε ένα **μεταλλικό περίβλημα σε σχήμα νομίσματος**. Ονομάζεται επίσης μνήμη Dallas Touch ή μνήμη επαφής. Αν και συχνά αποκαλείται λανθασμένα «μαγνητικό» κλειδί, **δεν περιέχει τίποτα μαγνητικό**. Στην πραγματικότητα, κρύβει στο εσωτερικό του ένα πλήρες **microchip** που λειτουργεί με ψηφιακό πρωτόκολλο.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Τι είναι το iButton; <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Η ονομασία iButton περιγράφει την ανθεκτική συσκευασία σε σχήμα νομίσματος και τη διάταξη επαφών. Οι θήκες περιλαμβάνουν πλαστικά μπρελόκ, δαχτυλίδια και μενταγιόν.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Όταν και οι δύο επαφές ακουμπήσουν στον αναγνώστη, η συσκευή τροφοδοτείται και ανταλλάσσει δεδομένα. Αν η εσοχή της επαφής εμποδίζει τις εξωτερικές επαφές γείωσης να ακουμπήσουν, η κλίση του κλειδιού πάνω στο τοίχωμα του αναγνώστη μπορεί να αποκαταστήσει την επαφή.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Πρωτόκολλο 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Τα κλειδιά Dallas/Maxim χρησιμοποιούν το πρωτόκολλο 1-Wire: μία επαφή δεδομένων μεταφέρει αμφίδρομη κίνηση και μπορεί επίσης να παρέχει παρασιτική τροφοδοσία, ενώ το μεταλλικό περίβλημα αποτελεί την επαφή επιστροφής. Ο controller ξεκινά τις συναλλαγές και η συσκευή αποκρίνεται.<sup>[[2]](#references)</sup>

Όταν το κλειδί (Slave) έρθει σε επαφή με το θυροτηλέφωνο (Master), το chip στο εσωτερικό του κλειδιού ενεργοποιείται με τροφοδοσία από το θυροτηλέφωνο και το κλειδί αρχικοποιείται. Έπειτα, το θυροτηλέφωνο ζητά το ID του κλειδιού. Στη συνέχεια, θα εξετάσουμε τη διαδικασία λεπτομερέστερα.

Το Flipper μπορεί να λειτουργήσει ως controller κατά την ανάγνωση ενός κλειδιού και ως εξομοιωμένη συσκευή όταν παρουσιάζει ένα αποθηκευμένο αναγνωριστικό σε έναν αναγνώστη.<sup>[[1]](#references)</sup>

### Κλειδιά Dallas, Cyfral & Metakom

Για πληροφορίες σχετικά με τον τρόπο λειτουργίας αυτών των κλειδιών, δείτε τη σελίδα [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Επιθέσεις

Τα iButton μπορούν να δεχτούν επιθέσεις με το Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Εξημέρωση του iButton με το Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — Επικοινωνία 1-Wire μέσω λογισμικού](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
