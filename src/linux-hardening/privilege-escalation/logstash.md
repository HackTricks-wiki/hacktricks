{{#include ../../banners/hacktricks-training.md}}

## Logstash

Το Logstash χρησιμοποιείται για να **συγκεντρώνει, μετασχηματίζει και αποστέλλει αρχεία καταγραφής** μέσω ενός συστήματος που ονομάζεται **pipelines**. Αυτές οι pipelines αποτελούνται από στάδια **input**, **filter** και **output**. Ένα ενδιαφέρον στοιχείο προκύπτει όταν το Logstash λειτουργεί σε μια παραβιασμένη μηχανή.

### Pipeline Configuration

Οι pipelines ρυθμίζονται στο αρχείο **/etc/logstash/pipelines.yml**, το οποίο απαριθμεί τις τοποθεσίες των ρυθμίσεων των pipelines:
```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
Αυτό το αρχείο αποκαλύπτει πού βρίσκονται τα αρχεία **.conf**, που περιέχουν ρυθμίσεις pipeline. Όταν χρησιμοποιείται ένα **Elasticsearch output module**, είναι συνηθισμένο τα **pipelines** να περιλαμβάνουν **Elasticsearch credentials**, οι οποίες συχνά διαθέτουν εκτενή δικαιώματα λόγω της ανάγκης του Logstash να γράφει δεδομένα στο Elasticsearch. Οι χαρακτήρες μπαλαντέρ στις διαδρομές ρύθμισης επιτρέπουν στο Logstash να εκτελεί όλα τα αντίστοιχα pipelines στον καθορισμένο φάκελο.

### Privilege Escalation via Writable Pipelines

Για να προσπαθήσετε να αποκτήσετε δικαιώματα, πρώτα εντοπίστε τον χρήστη υπό τον οποίο εκτελείται η υπηρεσία Logstash, συνήθως ο χρήστης **logstash**. Βεβαιωθείτε ότι πληροίτε **ένα** από αυτά τα κριτήρια:

- Έχετε **δικαίωμα εγγραφής** σε ένα αρχείο pipeline **.conf** **ή**
- Το αρχείο **/etc/logstash/pipelines.yml** χρησιμοποιεί έναν χαρακτήρα μπαλαντέρ και μπορείτε να γράψετε στον στόχο φάκελο

Επιπλέον, **μία** από αυτές τις προϋποθέσεις πρέπει να πληρούται:

- Δυνατότητα επανεκκίνησης της υπηρεσίας Logstash **ή**
- Το αρχείο **/etc/logstash/logstash.yml** έχει ρυθμιστεί σε **config.reload.automatic: true**

Δεδομένου ενός χαρακτήρα μπαλαντέρ στη ρύθμιση, η δημιουργία ενός αρχείου που ταιριάζει με αυτόν τον χαρακτήρα μπαλαντέρ επιτρέπει την εκτέλεση εντολών. Για παράδειγμα:
```bash
input {
exec {
command => "whoami"
interval => 120
}
}

output {
file {
path => "/tmp/output.log"
codec => rubydebug
}
}
```
Εδώ, **interval** καθορίζει τη συχνότητα εκτέλεσης σε δευτερόλεπτα. Στο δοθέν παράδειγμα, η εντολή **whoami** εκτελείται κάθε 120 δευτερόλεπτα, με την έξοδό της να κατευθύνεται στο **/tmp/output.log**.

Με **config.reload.automatic: true** στο **/etc/logstash/logstash.yml**, το Logstash θα ανιχνεύει και θα εφαρμόζει αυτόματα νέες ή τροποποιημένες ρυθμίσεις pipeline χωρίς να απαιτείται επανεκκίνηση. Αν δεν υπάρχει wildcard, μπορούν να γίνουν τροποποιήσεις σε υπάρχουσες ρυθμίσεις, αλλά συνιστάται προσοχή για να αποφευχθούν διαταραχές.

## References

{{#include ../../banners/hacktricks-training.md}}
