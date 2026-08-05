# iButton

{{#include ../../banners/hacktricks-training.md}}

## Εισαγωγή

Το iButton είναι μια γενική ονομασία για ένα ηλεκτρονικό κλειδί ταυτοποίησης τοποθετημένο σε ένα **μεταλλικό δοχείο σε σχήμα νομίσματος**. Ονομάζεται επίσης Dallas Touch Memory ή contact memory. Παρόλο που συχνά αναφέρεται λανθασμένα ως «μαγνητικό» κλειδί, **δεν υπάρχει τίποτα μαγνητικό** σε αυτό. Στην πραγματικότητα, στο εσωτερικό του είναι κρυμμένο ένα πλήρες **microchip** που λειτουργεί με ένα digital protocol.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Τι είναι το iButton; <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Συνήθως, το iButton αναφέρεται στη φυσική μορφή του key και του reader - ένα στρογγυλό νόμισμα με δύο επαφές. Για το πλαίσιο που το περιβάλλει, υπάρχουν πολλές παραλλαγές, από την πιο συνηθισμένη πλαστική θήκη με οπή έως δαχτυλίδια, μενταγιόν κ.λπ.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Όταν το key φτάσει στον reader, οι **επαφές έρχονται σε επαφή** και το key τροφοδοτείται για να **μεταδώσει** το ID του. Μερικές φορές το key **δεν διαβάζεται** αμέσως, επειδή το **contact PSD ενός intercom είναι μεγαλύτερο** από όσο θα έπρεπε. Έτσι, τα εξωτερικά περιγράμματα του key και του reader δεν μπορούν να έρθουν σε επαφή. Σε αυτή την περίπτωση, θα πρέπει να πιέσετε το key πάνω σε έναν από τους τοίχους του reader.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Πρωτόκολλο 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Τα Dallas keys ανταλλάσσουν δεδομένα χρησιμοποιώντας το 1-wire protocol. Υπάρχει μόνο μία επαφή για τη μεταφορά δεδομένων (!!) και προς τις δύο κατευθύνσεις, από το Master προς το Slave και αντίστροφα. Το 1-wire protocol λειτουργεί σύμφωνα με το μοντέλο Master-Slave. Σε αυτή την τοπολογία, το Master ξεκινά πάντα την επικοινωνία και το Slave ακολουθεί τις οδηγίες του.

Όταν το key (Slave) έρθει σε επαφή με το intercom (Master), το chip μέσα στο key ενεργοποιείται, τροφοδοτούμενο από το intercom, και το key αρχικοποιείται. Στη συνέχεια, το intercom ζητά το ID του key. Παρακάτω θα εξετάσουμε αυτή τη διαδικασία πιο αναλυτικά.

Το Flipper μπορεί να λειτουργήσει τόσο σε Master όσο και σε Slave modes. Στο key reading mode, το Flipper λειτουργεί ως reader, δηλαδή ως Master. Και στο key emulation mode, το Flipper προσποιείται ότι είναι key και βρίσκεται σε Slave mode.

### Κλειδιά Dallas, Cyfral & Metakom

Για πληροφορίες σχετικά με τον τρόπο λειτουργίας αυτών των keys, δείτε τη σελίδα [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Επιθέσεις

Τα iButtons μπορούν να δεχθούν επίθεση με το Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Αναφορές

- [1] [Taming iButton](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
