# SeManageVolumePrivilege: Κατάχρηση συντήρησης τόμων και επικύρωση ακατέργαστης πρόσβασης

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Δικαίωμα χρήστη των Windows: Εκτέλεση εργασιών συντήρησης τόμων (σταθερά: SeManageVolumePrivilege).

Το δικαίωμα εξουσιοδοτεί λειτουργίες συντήρησης τόμων, όπως την ανασυγκρότηση και τη δημιουργία ή κατάργηση τόμων. Η Microsoft προειδοποιεί ότι όποιος έχει αυτό το δικαίωμα ενδέχεται να μπορεί να επεκτείνει αρχεία σε χώρο αποθήκευσης που περιέχει άλλα δεδομένα και, στη συνέχεια, να διαβάσει ή να τροποποιήσει τα byte που απέκτησε.<sup>[[1]](#references)</sup>

Μην θεωρείτε ότι η κατοχή του `SeManageVolumePrivilege` συνεπάγεται εγγυημένη πρόσβαση σε ακατέργαστο δίσκο. Η Microsoft τεκμηριώνει ότι το άνοιγμα φυσικού δίσκου ή τόμου μέσω `CreateFile` για άμεση πρόσβαση απαιτεί δικαιώματα διαχειριστή, ενώ εξακολουθούν να ισχύουν οι κανονικοί έλεγχοι πρόσβασης αντικειμένων/συσκευών. Σε συγκεκριμένη έκδοση ή προϊόν, ελέγξτε αν το token, το ACL της συσκευής, η αιτούμενη πρόσβαση, οι σημαίες κοινής χρήσης και η κατάσταση του τόμου επιτρέπουν τη δημιουργία ακατέργαστης λαβής, προτού ισχυριστείτε ότι είναι δυνατή η αυθαίρετη ανάγνωση αρχείων.<sup>[[3]](#references)</sup>

Προεπιλογή: Διαχειριστές σε διακομιστές και ελεγκτές τομέα.<sup>[[1]](#references)</sup>

## Σενάρια κατάχρησης

- Αν ο λογαριασμός μπορεί πράγματι να αποκτήσει λαβή ακατέργαστου τόμου με δικαίωμα ανάγνωσης, ένας parser με επίγνωση του NTFS μπορεί να παρακάμψει τα ACL ανά αρχείο και να ανακτήσει προστατευμένα ή κλειδωμένα αρχεία από εκχωρημένα clusters.
- Πιθανοί στόχοι περιλαμβάνουν προστατευμένο περιεχόμενο ή περιεχόμενο με περιορισμένη πρόσβαση κάτω από το `C:\Windows\System32`, τις ομάδες μητρώου, τα κύρια κλειδιά DPAPI, το SAM και —όταν είναι ξεχωριστά προσβάσιμο μέσω snapshot ή offline τόμου— το `ntds.dit`.
- Σε κεντρικούς υπολογιστές υπηρεσιών πιστοποιητικών, χρήσιμες τοποθεσίες κλειδιών λογισμικού περιλαμβάνουν τις `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` και `%ProgramData%\Microsoft\Crypto\Keys`· η ανάκτηση ενός αρχείου είναι χρήσιμη μόνο όταν το υλικό του κλειδιού είναι εξαγώγιμο και μπορεί επίσης να αποκρυπτογραφηθεί.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Σε έναν κεντρικό υπολογιστή AD CS, η επιτυχής ανάκτηση ιδιωτικού κλειδιού CA **εξαγώγιμου και αποθηκευμένου μέσω λογισμικού** μπορεί να επιτρέψει κατάχρηση Golden Certificate. Οι σχεδιασμοί με κλειδιά που βασίζονται σε υλικό ή δεν είναι εξαγώγιμα αλλάζουν αυτήν τη διαδρομή.<sup>[[2]](#references)</sup>
- Ορισμένα εργαλεία συντήρησης τόμων χρησιμοποιούν το `FSCTL_SD_GLOBAL_CHANGE` για να αντικαταστήσουν καταχωρίσεις ACL του συστήματος αρχείων, όταν επιτρέπεται αυτή η λειτουργία. Αυτό αλλάζει τα στοιχεία ελέγχου πρόσβασης αντί να διαβάζει παθητικά ακατέργαστα blocks, μπορεί να επηρεάσει μεγάλο μέρος ενός τόμου και πρέπει να επικυρώνεται με βάση το πραγματικό token και τη συμπεριφορά της συσκευής. Ο [πηγαίος κώδικας του εργαλείου](https://github.com/CsEnox/SeManageVolumeExploit) δείχνει αυτόν τον συγκεκριμένο μηχανισμό· η κατοχή του δικαιώματος από μόνη της δεν αποδεικνύει ότι θα πετύχει.
- Η απόκτηση πρόσβασης σε αρχεία μέσω αλλαγών ACL δεν αποκρυπτογραφεί ένα αρχείο κρυπτογραφημένο με EFS. Για την ανάκτηση απλού κειμένου εξακολουθεί να απαιτείται το αντίστοιχο ιδιωτικό κλειδί χρήστη ή ανάκτησης. Ομοίως, η εξαγωγή ενός κλειδιού CA που βασίζεται σε λογισμικό με [`certutil -exportPFX`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) εξαρτάται από το αν το κλειδί είναι διαθέσιμο τοπικά, εξαγώγιμο και προσβάσιμο.

Σημείωση: Εξακολουθείτε να χρειάζεστε έναν parser για τις δομές NTFS, εκτός αν βασίζεστε σε βοηθητικά εργαλεία. Πολλά έτοιμα εργαλεία αφαιρούν την πολυπλοκότητα της ακατέργαστης πρόσβασης.

## Πρακτικές τεχνικές

- Ανοίξτε μια λαβή ακατέργαστου τόμου και διαβάστε clusters:

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

- Χρησιμοποιήστε ένα εργαλείο με υποστήριξη NTFS για να ανακτήσετε συγκεκριμένα αρχεία από τον raw τόμο:
  - RawCopy/RawCopy64 (αντιγραφή αρχείων που χρησιμοποιούνται σε επίπεδο τομέα)
  - FTK Imager ή The Sleuth Kit (εικόνα μόνο για ανάγνωση και, στη συνέχεια, εξαγωγή αρχείων)
  - vssadmin/diskshadow + shadow copy και, στη συνέχεια, αντιγράψτε το αρχείο-στόχο από το snapshot (αν μπορείτε να δημιουργήσετε VSS· συχνά απαιτούνται δικαιώματα admin, αλλά συνήθως είναι διαθέσιμο σε ίδιους operators που έχουν SeManageVolumePrivilege)

Τυπικές ευαίσθητες διαδρομές-στόχοι:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (τοπικά secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – μέσω shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certificates/CRLs· τα private keys βρίσκονται στο machine key store παραπάνω)

## Σύνδεση με AD CS: Σφυρηλάτηση Golden Certificate

Αν μπορείτε να διαβάσετε το private key της Enterprise CA από το machine key store, μπορείτε να σφυρηλατήσετε certificates για client authentication για αυθαίρετα principals και να κάνετε authentication μέσω PKINIT/Schannel. Αυτό συχνά αναφέρεται ως Golden Certificate.<sup>[[2]](#references)</sup> Δείτε:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Ενότητα: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Ανίχνευση και ενίσχυση ασφάλειας

- Περιορίστε αυστηρά την εκχώρηση του SeManageVolumePrivilege (Perform volume maintenance tasks) μόνο σε έμπιστους admins.
- Παρακολουθείτε τη χρήση ευαίσθητων δικαιωμάτων και τα ανοίγματα process handle σε device objects όπως \\.\C:, \\.\PhysicalDrive0.
- Προτιμήστε σωστά διαμορφωμένα CA keys που υποστηρίζονται από HSM ή TPM και δεν είναι εξαγώγιμα, ώστε η αντιγραφή ενός αρχείου key-container να μην επαρκεί για την ανάκτηση αξιοποιήσιμου υλικού private key.
- Για application secrets εκτός της διαδρομής CA-key, τα DPAPI ή DPAPI-NG μπορούν να διασφαλίσουν ότι η αντιγραφή ενός αρχείου δεδομένων δεν αρκεί, προστατεύοντάς το για έναν χρήστη, υπολογιστή, ομάδα ή άλλο εξουσιοδοτημένο principal. Αυτό δεν προστατεύει plaintext που είναι ήδη προσβάσιμο στο παραβιασμένο principal.<sup>[[4]](#references)</sup>
- Διατηρείτε τα paths για uploads, προσωρινά αρχεία και εξαγωγή μη εκτελέσιμα και διαχωρισμένα (άμυνα στο web context που συχνά συνοδεύει αυτή την αλυσίδα post-exploitation).

## References

- [1] [Microsoft – Εκτέλεση εργασιών συντήρησης τόμου (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (χρήση του SeManageVolumePrivilege για ανάγνωση του CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` για φυσικούς δίσκους και τόμους](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation και DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
