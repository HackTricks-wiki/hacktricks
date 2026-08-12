# SeManageVolumePrivilege: Κατάχρηση συντήρησης τόμων και επικύρωση raw-access

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Δικαίωμα χρήστη Windows: Εκτέλεση εργασιών συντήρησης τόμων (σταθερά: SeManageVolumePrivilege).

Το δικαίωμα εξουσιοδοτεί λειτουργίες συντήρησης τόμων, όπως ανασυγκρότηση και δημιουργία ή κατάργηση τόμων. Η Microsoft προειδοποιεί ότι ένας κάτοχος ενδέχεται να μπορεί να επεκτείνει αρχεία σε χώρο αποθήκευσης που περιέχει άλλα δεδομένα και, στη συνέχεια, να διαβάσει ή να τροποποιήσει τα αποκτηθέντα bytes.<sup>[[1]](#references)</sup>

Μην εξισώνετε την κατοχή του `SeManageVolumePrivilege` με εγγυημένη πρόσβαση σε raw disk. Η Microsoft τεκμηριώνει ότι το άνοιγμα ενός physical disk ή volume μέσω `CreateFile` για direct access απαιτεί administrative privileges, ενώ εξακολουθούν να εφαρμόζονται οι κανονικοί έλεγχοι πρόσβασης σε objects/devices. Σε μια συγκεκριμένη build ή product, ελέγξτε αν το token, το device ACL, η ζητούμενη πρόσβαση, τα share flags και η κατάσταση του volume επιτρέπουν raw handle, πριν ισχυριστείτε αυθαίρετη ανάγνωση αρχείων.<sup>[[3]](#references)</sup>

Προεπιλογή: Administrators σε servers και domain controllers.<sup>[[1]](#references)</sup>

## Σενάρια κατάχρησης

- Αν ο λογαριασμός μπορεί πράγματι να αποκτήσει readable raw-volume handle, ένας NTFS-aware parser μπορεί να παρακάμψει τα per-file ACLs και να ανακτήσει προστατευμένα ή κλειδωμένα αρχεία από allocated clusters.
- Πιθανοί στόχοι περιλαμβάνουν κλειδωμένο ή ACL-protected περιεχόμενο στο `C:\Windows\System32`, registry hives, DPAPI master keys, το SAM και —όταν είναι ξεχωριστά προσβάσιμο μέσω snapshot ή offline volume— το `ntds.dit`.
- Σε certificate services hosts, χρήσιμες τοποθεσίες software-key περιλαμβάνουν τα `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` και `%ProgramData%\Microsoft\Crypto\Keys`. Η ανάκτηση ενός αρχείου είναι χρήσιμη μόνο όταν το key material του είναι exportable και μπορεί επίσης να γίνει decrypt.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Σε έναν AD CS host, ένα private key CA που έχει ανακτηθεί επιτυχώς και είναι **exportable/software-backed** μπορεί να επιτρέψει Golden Certificate abuse. Σχεδιασμοί με hardware-backed ή non-exportable keys αλλάζουν αυτή τη διαδρομή.<sup>[[2]](#references)</sup>

Σημείωση: Εξακολουθείτε να χρειάζεστε parser για τις δομές NTFS, εκτός αν βασίζεστε σε helper tools. Πολλά off-the-shelf tools αφαιρούν την πολυπλοκότητα του raw access.

## Πρακτικές τεχνικές

- Ανοίξτε ένα raw volume handle και διαβάστε clusters:

<details>
<summary>Κάντε κλικ για επέκταση</summary>
```powershell
# Validation attempt: current Windows versions normally require an administrative token
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

- Χρησιμοποιήστε ένα εργαλείο με υποστήριξη NTFS για να ανακτήσετε συγκεκριμένα αρχεία από raw volume:
- RawCopy/RawCopy64 (αντιγραφή αρχείων που χρησιμοποιούνται, σε επίπεδο τομέα)
- FTK Imager ή The Sleuth Kit (εικόνα μόνο για ανάγνωση και, στη συνέχεια, file carving)
- vssadmin/diskshadow + shadow copy και, στη συνέχεια, αντιγράψτε το αρχείο-στόχο από το snapshot (αν μπορείτε να δημιουργήσετε VSS· συχνά απαιτούνται δικαιώματα administrator, αλλά είναι συνήθως διαθέσιμα στους ίδιους operators που διαθέτουν SeManageVolumePrivilege)

Τυπικές ευαίσθητες διαδρομές-στόχοι:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (τοπικά secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – μέσω shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certificates/CRLs· τα private keys βρίσκονται στο machine key store παραπάνω)

## Σύνδεση με AD CS: Forging a Golden Certificate

Αν μπορείτε να διαβάσετε το private key του Enterprise CA από το machine key store, μπορείτε να δημιουργήσετε client-auth certificates για αυθαίρετους principals και να πραγματοποιήσετε authentication μέσω PKINIT/Schannel. Αυτό συχνά αναφέρεται ως Golden Certificate.<sup>[[2]](#references)</sup> Δείτε:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Ενότητα: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Ανίχνευση και hardening

- Περιορίστε αυστηρά την εκχώρηση του SeManageVolumePrivilege (Perform volume maintenance tasks) μόνο σε έμπιστους admins.
- Παρακολουθείτε τη χρήση ευαίσθητων δικαιωμάτων και τα ανοίγματα process handles σε device objects όπως τα \\.\C:, \\.\PhysicalDrive0.
- Προτιμήστε σωστά ρυθμισμένα HSM- ή TPM-backed, non-exportable CA keys, ώστε η αντιγραφή ενός key-container file να μην επαρκεί για την ανάκτηση αξιοποιήσιμου private-key material.
- Για application secrets εκτός της διαδρομής του CA key, τα DPAPI ή DPAPI-NG μπορούν να καταστήσουν ένα αντιγραμμένο data file ανεπαρκές, προστατεύοντάς το σε user, machine, group ή άλλο authorized principal. Αυτό δεν προστατεύει plaintext που είναι ήδη προσβάσιμο στο compromised principal.<sup>[[4]](#references)</sup>
- Διατηρείτε τα uploads, τα temp και τα extraction paths ως non-executable και διαχωρισμένα (web context defense που συχνά συνδυάζεται με αυτό το chain στο post‑exploitation).

## References

- [1] [Microsoft – Εκτέλεση εργασιών συντήρησης τόμων (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` physical disks and volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation and DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
