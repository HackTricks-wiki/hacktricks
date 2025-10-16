# SeManageVolumePrivilege: Πρόσβαση ακατέργαστου τόμου για αυθαίρετη ανάγνωση αρχείων

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Windows user right: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

Οι κάτοχοι μπορούν να εκτελέσουν λειτουργίες χαμηλού επιπέδου στον τόμο, όπως αποσυγκρότηση (defragmentation), δημιουργία/αφαίρεση τόμων και εργασίες συντήρησης I/O. Κρίσιμο για επιτιθέμενους, αυτό το δικαίωμα επιτρέπει το άνοιγμα handles συσκευής ακατέργαστου τόμου (π.χ., \\.\C:) και την εκτέλεση άμεσων δίσκων I/O που παρακάμπτουν τα NTFS file ACLs. Με ακατέργαστη πρόσβαση μπορείτε να αντιγράψετε bytes οποιουδήποτε αρχείου στον τόμο ακόμη κι αν το απαγορεύει η DACL, αναλύοντας τις δομές του filesystem εκτός σύνδεσης ή χρησιμοποιώντας εργαλεία που διαβάζουν σε επίπεδο block/cluster.

Default: Administrators on servers and domain controllers.

## Σενάρια καταχρήσης

- Αυθαίρετη ανάγνωση αρχείων παρακάμπτοντας ACLs διαβάζοντας τη συσκευή δίσκου (π.χ., εξαγωγή ευαίσθητου συστημικά προστατευμένου υλικού όπως τα ιδιωτικά κλειδιά μηχανής κάτω από %ProgramData%\Microsoft\Crypto\RSA\MachineKeys και %ProgramData%\Microsoft\Crypto\Keys, registry hives, DPAPI masterkeys, SAM, ntds.dit μέσω VSS, κ.λπ.).
- Παράκαμψη κλειδωμένων/προνομιακών διαδρομών (C:\Windows\System32\…) με αντιγραφή bytes απευθείας από τη συσκευή ακατέργαστου τόμου.
- Σε περιβάλλοντα AD CS, εξαγωγή του key material της CA (machine key store) για την έκδοση “Golden Certificates” και την προσποίηση οποιουδήποτε domain principal μέσω PKINIT. Δείτε το σύνδεσμο παρακάτω.

Σημείωση: Ακόμα χρειάζεστε έναν parser για τις δομές NTFS εκτός αν βασιστείτε σε βοηθητικά εργαλεία. Πολλά off-the-shelf εργαλεία αφαιρούν την πολυπλοκότητα της ακατέργαστης πρόσβασης.

## Πρακτικές τεχνικές

- Άνοιγμα handle ακατέργαστου τόμου και ανάγνωση clusters:

<details>
<summary>Κάντε κλικ για εμφάνιση</summary>
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

- Χρησιμοποιήστε εργαλείο με υποστήριξη NTFS για να ανακτήσετε συγκεκριμένα αρχεία από ακατέργαστο volume:
- RawCopy/RawCopy64 (αντιγραφή σε επίπεδο τομέα αρχείων σε χρήση)
- FTK Imager or The Sleuth Kit (read-only imaging, στη συνέχεια carve αρχεία)
- vssadmin/diskshadow + shadow copy, στη συνέχεια αντιγράψτε το στοχευόμενο αρχείο από το στιγμιότυπο (αν μπορείτε να δημιουργήσετε VSS· συχνά απαιτεί admin αλλά συνήθως διαθέσιμο στους ίδιους χειριστές που κατέχουν SeManageVolumePrivilege)

Τυπικές ευαίσθητες διαδρομές-στόχοι:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## Σύνδεση με AD CS: Forging a Golden Certificate

Αν μπορείτε να διαβάσετε το ιδιωτικό κλειδί της Enterprise CA από το machine key store, μπορείτε να πλαστογραφήσετε client‑auth πιστοποιητικά για αυθαίρετους principals και να αυθεντικοποιηθείτε μέσω PKINIT/Schannel. Αυτό συχνά αναφέρεται ως Golden Certificate. Δείτε:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Ενότητα: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Ανίχνευση και σκληροποίηση

- Περιορίστε αυστηρά την ανάθεση του SeManageVolumePrivilege (Perform volume maintenance tasks) μόνο σε αξιόπιστους admins.
- Παρακολουθείτε το Sensitive Privilege Use και τα ανοίγματα handle διεργασιών προς αντικείμενα συσκευής όπως \\.\C:, \\.\PhysicalDrive0.
- Προτιμήστε CA keys με υποστήριξη HSM/TPM ή DPAPI-NG ώστε οι ακατέργαστες αναγνώσεις αρχείων να μην μπορούν να ανακτήσουν το υλικό των κλειδιών σε μορφή έτοιμη για χρήση.
- Κρατήστε τα paths για uploads, temp και extraction μη εκτελέσιμα και διαχωρισμένα (defense σε web context που συχνά συνδυάζεται με αυτήν την αλυσίδα post‑exploitation).

## References

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
