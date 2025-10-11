# SeManageVolumePrivilege: Ακατέργαστη πρόσβαση σε τόμο για αυθαίρετη ανάγνωση αρχείων

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Δικαίωμα χρήστη των Windows: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

Οι κάτοχοι μπορούν να εκτελούν λειτουργίες σε χαμηλό επίπεδο στον τόμο, όπως defragmentation, δημιουργία/αφαίρεση τόμων και maintenance I/O. Σημαντικό για τους επιτιθέμενους, αυτό το δικαίωμα επιτρέπει το άνοιγμα raw volume device handles (π.χ. \\.\C:) και την εκτέλεση άμεσου disk I/O που παρακάμπτει τα NTFS file ACLs. Με ακατέργαστη πρόσβαση μπορείτε να αντιγράψετε bytes οποιουδήποτε αρχείου στον τόμο ακόμα και αν αρνηθείται από DACL, αναλύοντας τις δομές του filesystem εκτός σύνδεσης ή χρησιμοποιώντας εργαλεία που διαβάζουν σε επίπεδο block/cluster.

Προεπιλογή: Η ομάδα Administrators σε servers και domain controllers.

## Σενάρια κατάχρησης

- Αυθαίρετη ανάγνωση αρχείων παρακάμπτοντας ACLs με ανάγνωση της συσκευής δίσκου (π.χ., εξαγωγή ευαίσθητου συστήματος-προστατευμένου υλικού όπως machine private keys κάτω από %ProgramData%\Microsoft\Crypto\RSA\MachineKeys και %ProgramData%\Microsoft\Crypto\Keys, registry hives, DPAPI masterkeys, SAM, ntds.dit μέσω VSS, κ.α.).
- Παράκαμψη κλειδωμένων/προνομιακών διαδρομών (C:\Windows\System32\…) αντιγράφοντας bytes απευθείας από τη raw device.
- Σε περιβάλλοντα AD CS, εξαγωγή του CA’s key material (machine key store) για τη δημιουργία “Golden Certificates” και προσποίηση οποιουδήποτε domain principal μέσω PKINIT. Δείτε τον σύνδεσμο παρακάτω.

Σημείωση: Ακόμα χρειάζεστε parser για τις δομές NTFS εκτός αν βασιστείτε σε βοηθητικά εργαλεία. Πολλά off-the-shelf εργαλεία αφαιρούν την πολυπλοκότητα της raw πρόσβασης.

## Πρακτικές τεχνικές

- Open a raw volume handle and read clusters:

<details>
<summary>Κάντε κλικ για να επεκταθεί</summary>
```powershell
# PowerShell – read first MB from C: raw device (requires SeManageVolumePrivilege)
$fs = [System.IO.File]::Open("\\.\\C:",[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
$buf = New-Object byte[] (1MB)
$null = $fs.Read($buf,0,$buf.Length)
$fs.Close()
[IO.File]::WriteAllBytes("C:\\temp\\c_first_mb.bin", $buf)
```

```csharp
// C# (compile with Add-Type) – read an arbitrary offset of \\.\nusing System;
using System.IO;
class R {
static void Main(string[] a){
using(var fs = new FileStream("\\\\.\\C:", FileMode.Open, FileAccess.Read, FileShare.ReadWrite)){
fs.Position = 0x100000; // seek
var buf = new byte[4096];
fs.Read(buf,0,buf.Length);
File.WriteAllBytes("C:\\temp\\blk.bin", buf);
}
}
}
```
</details>

- Χρησιμοποιήστε ένα εργαλείο που καταλαβαίνει NTFS για να ανακτήσετε συγκεκριμένα αρχεία από τον raw volume:
- RawCopy/RawCopy64 (αντιγραφή σε επίπεδο sector των αρχείων που είναι σε χρήση)
- FTK Imager ή The Sleuth Kit (read-only imaging, στη συνέχεια carve αρχείων)
- vssadmin/diskshadow + shadow copy, στη συνέχεια αντιγράψτε το στοχευόμενο αρχείο από το snapshot (εάν μπορείτε να δημιουργήσετε VSS· συχνά απαιτεί admin αλλά συνήθως διαθέσιμο στους ίδιους χειριστές που έχουν SeManageVolumePrivilege)

Τυπικά ευαίσθητα μονοπάτια-στόχοι:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## Σύνδεση με AD CS: Forging a Golden Certificate

Αν μπορείτε να διαβάσετε το private key της Enterprise CA από το machine key store, μπορείτε να δημιουργήσετε client‑auth certificates για οποιουσδήποτε principals και να αυθεντικοποιηθείτε μέσω PKINIT/Schannel. Αυτό συχνά αναφέρεται ως Golden Certificate. Δείτε:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Ενότητα: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detection and hardening

- Περιορίστε αυστηρά την ανάθεση του SeManageVolumePrivilege (Perform volume maintenance tasks) μόνο σε εμπιστευμένους admins.
- Monitor Sensitive Privilege Use και τα ανοίγματα process handle σε device objects όπως \\.\C:, \\.\PhysicalDrive0.
- Προτιμήστε CA keys backed by HSM/TPM ή χρήση DPAPI-NG ώστε οι raw file reads να μην μπορούν να ανακτήσουν υλικό κλειδιού σε χρησιμοποιήσιμη μορφή.
- Κρατήστε τα uploads, temp και extraction μονοπάτια μη‑εκτελέσιμα και διαχωρισμένα (web context defense που συχνά συνδυάζεται με αυτή την αλυσίδα post‑exploitation).

## References

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
