# SeManageVolumePrivilege: Πρόσβαση σε raw volume για ανάγνωση αυθαίρετων αρχείων

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Δικαίωμα χρήστη των Windows: Perform volume maintenance tasks (σταθερά: SeManageVolumePrivilege).

Οι κάτοχοι μπορούν να εκτελούν λειτουργίες volume χαμηλού επιπέδου, όπως defragmentation, δημιουργία/αφαίρεση volumes και maintenance IO. Κρίσιμα για τους attackers, αυτό το δικαίωμα επιτρέπει το άνοιγμα raw volume device handles (π.χ. \\.\C:) και την εκτέλεση direct disk I/O που παρακάμπτει τα NTFS file ACLs. Με raw access μπορείτε να αντιγράψετε bytes οποιουδήποτε αρχείου στο volume, ακόμη και αν αποκλείεστε από το DACL, αναλύοντας offline τις filesystem structures ή αξιοποιώντας tools που διαβάζουν σε επίπεδο block/cluster.

Προεπιλογή: Administrators σε servers και domain controllers.<sup>[[1]](#references)</sup>

## Σενάρια abuse

- Αυθαίρετη ανάγνωση αρχείων με παράκαμψη ACLs μέσω ανάγνωσης της disk device (π.χ. exfiltrate ευαίσθητο system-protected υλικό, όπως machine private keys στο %ProgramData%\Microsoft\Crypto\RSA\MachineKeys και %ProgramData%\Microsoft\Crypto\Keys, registry hives, DPAPI masterkeys, SAM, ntds.dit μέσω VSS κ.λπ.).
- Παράκαμψη locked/privileged paths (C:\Windows\System32\…) μέσω απευθείας αντιγραφής bytes από το raw device.
- Σε περιβάλλοντα AD CS, exfiltrate το key material της CA (machine key store) για τη δημιουργία “Golden Certificates” και την impersonation οποιουδήποτε domain principal μέσω PKINIT. Δείτε το link παρακάτω.<sup>[[2]](#references)</sup>

Σημείωση: Εξακολουθείτε να χρειάζεστε parser για τις NTFS structures, εκτός αν βασίζεστε σε helper tools. Πολλά off-the-shelf tools αφαιρούν την πολυπλοκότητα του raw access.

## Πρακτικές τεχνικές

- Ανοίξτε ένα raw volume handle και διαβάστε clusters:

<details>
<summary>Κάντε κλικ για ανάπτυξη</summary>
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

- Χρησιμοποιήστε ένα εργαλείο με υποστήριξη NTFS για την ανάκτηση συγκεκριμένων αρχείων από raw volume:
- RawCopy/RawCopy64 (αντιγραφή σε επίπεδο sector αρχείων που χρησιμοποιούνται)
- FTK Imager ή The Sleuth Kit (imaging μόνο για ανάγνωση και, στη συνέχεια, file carving)
- vssadmin/diskshadow + shadow copy και, στη συνέχεια, αντιγραφή του αρχείου-στόχου από το snapshot (αν μπορείτε να δημιουργήσετε VSS· συχνά απαιτούνται δικαιώματα admin, αλλά είναι συνήθως διαθέσιμα στους ίδιους operators που διαθέτουν SeManageVolumePrivilege)

Τυπικά ευαίσθητα paths-στόχοι:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – μέσω shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs· τα private keys αποθηκεύονται στο machine key store παραπάνω)

## AD CS σύνδεση: Forging a Golden Certificate

Αν μπορείτε να διαβάσετε το private key του Enterprise CA από το machine key store, μπορείτε να δημιουργήσετε forged client-auth certificates για αυθαίρετους principals και να πραγματοποιήσετε authentication μέσω PKINIT/Schannel. Αυτό συχνά αναφέρεται ως Golden Certificate.<sup>[[2]](#references)</sup> Δείτε:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Ενότητα: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detection και hardening

- Περιορίστε αυστηρά την εκχώρηση του SeManageVolumePrivilege (Perform volume maintenance tasks) μόνο σε trusted admins.
- Παρακολουθείτε το Sensitive Privilege Use και τα process handle opens σε device objects όπως τα \\.\C:, \\.\PhysicalDrive0.
- Προτιμήστε CA keys που υποστηρίζονται από HSM/TPM ή DPAPI-NG, ώστε τα raw file reads να μην μπορούν να ανακτήσουν key material σε αξιοποιήσιμη μορφή.
- Διατηρείτε τα upload, temp και extraction paths non-executable και διαχωρισμένα (web context defense που συχνά συνδυάζεται με αυτή την post-exploitation chain).

## References

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
