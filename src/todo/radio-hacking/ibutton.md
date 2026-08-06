# iButton

{{#include ../../banners/hacktricks-training.md}}

## Εισαγωγή

Το iButton είναι μια γενική ονομασία για ένα ηλεκτρονικό κλειδί αναγνώρισης, τοποθετημένο σε ένα **μεταλλικό περίβλημα σε σχήμα νομίσματος**. Ονομάζεται επίσης **Dallas Touch** Memory ή contact memory. Παρόλο που συχνά αποκαλείται λανθασμένα «μαγνητικό» κλειδί, δεν υπάρχει **τίποτα μαγνητικό** σε αυτό. Στην πραγματικότητα, στο εσωτερικό του κρύβεται ένα πλήρες **microchip** που λειτουργεί με ψηφιακό protocol.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Τι είναι το iButton; <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Συνήθως, το iButton αναφέρεται στη φυσική μορφή του κλειδιού και του reader - ένα στρογγυλό νόμισμα με δύο επαφές. Όσον αφορά το πλαίσιο που το περιβάλλει, υπάρχουν πολλές παραλλαγές, από την πιο συνηθισμένη πλαστική θήκη με οπή έως δαχτυλίδια, μενταγιόν κ.λπ.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Όταν το κλειδί φτάσει στον reader, οι **επαφές έρχονται σε επαφή** και το κλειδί τροφοδοτείται για να **μεταδώσει** το ID του. Μερικές φορές το κλειδί **δεν διαβάζεται** αμέσως, επειδή το **contact PSD ενός intercom είναι μεγαλύτερο** από όσο θα έπρεπε. Έτσι, τα εξωτερικά περιγράμματα του κλειδιού και του reader δεν μπορούσαν να έρθουν σε επαφή. Σε αυτή την περίπτωση, θα πρέπει να πιέσετε το κλειδί πάνω σε έναν από τους τοίχους του reader.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Τα Dallas keys ανταλλάσσουν δεδομένα χρησιμοποιώντας το 1-wire protocol. Με μόνο μία επαφή για τη μεταφορά δεδομένων (!!) και προς τις δύο κατευθύνσεις, από το Master προς το Slave και αντίστροφα. Το 1-wire protocol λειτουργεί σύμφωνα με το μοντέλο Master-Slave. Σε αυτή την τοπολογία, το Master ξεκινά πάντα την επικοινωνία και το Slave ακολουθεί τις οδηγίες του.

Όταν το κλειδί (Slave) έρθει σε επαφή με το intercom (Master), το chip στο εσωτερικό του κλειδιού ενεργοποιείται, τροφοδοτούμενο από το intercom, και το κλειδί αρχικοποιείται. Στη συνέχεια, το intercom ζητά το ID του κλειδιού. Παρακάτω θα εξετάσουμε αυτή τη διαδικασία με περισσότερες λεπτομέρειες.

Το Flipper μπορεί να λειτουργήσει τόσο σε λειτουργία Master όσο και σε λειτουργία Slave. Στη λειτουργία ανάγνωσης κλειδιού, το Flipper λειτουργεί ως reader, δηλαδή ως Master. Και στη λειτουργία εξομοίωσης κλειδιού, το Flipper προσποιείται ότι είναι κλειδί και βρίσκεται σε λειτουργία Slave.<sup>[[1]](#references)</sup>

### Κλειδιά Dallas, Cyfral & Metakom

Για πληροφορίες σχετικά με το πώς λειτουργούν αυτά τα κλειδιά, δείτε τη σελίδα [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Επιθέσεις

Τα iButtons μπορούν να δεχθούν επιθέσεις με το Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Αναφορές

- [1] [Taming iButton with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
