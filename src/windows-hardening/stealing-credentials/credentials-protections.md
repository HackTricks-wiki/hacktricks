# Προστασίες διαπιστευτηρίων Windows

{{#include ../../banners/hacktricks-training.md}}

## WDigest

The [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) protocol, introduced with Windows XP, is designed for authentication via the HTTP Protocol and is **ενεργοποιημένο εξ ορισμού στα Windows XP έως τα Windows 8.0 και στα Windows Server 2003 έως τα Windows Server 2012**. Αυτή η προεπιλεγμένη ρύθμιση οδηγεί σε **αποθήκευση κωδικών σε απλό κείμενο στο LSASS** (Local Security Authority Subsystem Service). Ένας επιτιθέμενος μπορεί να χρησιμοποιήσει το Mimikatz για να **εξαγάγει αυτά τα διαπιστευτήρια** εκτελώντας:
```bash
sekurlsa::wdigest
```
Για να **απενεργοποιήσετε ή να ενεργοποιήσετε αυτή τη λειτουργία**, τα _**UseLogonCredential**_ και _**Negotiate**_ κλειδιά μητρώου στο _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ πρέπει να έχουν τιμή "1". Εάν αυτά τα κλειδιά **απουσιάζουν ή έχουν τιμή "0"**, το WDigest είναι **απενεργοποιημένο**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Προστασία LSA (PP & PPL protected processes)

**Protected Process (PP)** και **Protected Process Light (PPL)** είναι **προστασίες σε επίπεδο kernel των Windows** σχεδιασμένες να αποτρέπουν μη εξουσιοδοτημένη πρόσβαση σε ευαίσθητες διεργασίες όπως η **LSASS**. Εισήχθησαν στα **Windows Vista**, το **PP model** δημιουργήθηκε αρχικά για επιβολή **DRM** και επέτρεπε να προστατεύονται μόνο δυαδικά υπογεγραμμένα με ένα ειδικό πιστοποιητικό μέσων. Μια διεργασία που επισημαίνεται ως **PP** μπορεί να προσπελαστεί μόνο από άλλες διεργασίες που είναι επίσης **PP** και έχουν ίσο ή υψηλότερο επίπεδο προστασίας, και ακόμα και τότε, μόνο με περιορισμένα δικαιώματα πρόσβασης εκτός αν επιτρέπεται ρητά.

**PPL**, που εισήχθη στα **Windows 8.1**, είναι μια πιο ευέλικτη έκδοση του PP. Επιτρέπει ευρύτερες περιπτώσεις χρήσης (π.χ., **LSASS**, **Defender**) εισάγοντας «επίπεδα προστασίας» βασισμένα στο πεδίο EKU (Enhanced Key Usage) της ψηφιακής υπογραφής. Το επίπεδο προστασίας αποθηκεύεται στο πεδίο `EPROCESS.Protection`, το οποίο είναι μια δομή `PS_PROTECTION` με:
- **Type** (`Protected` ή `ProtectedLight`)
- **Signer** (π.χ., `WinTcb`, `Lsa`, `Antimalware`, κ.λπ.)

Αυτή η δομή πακετάρεται σε ένα μόνο byte και καθορίζει **ποιος μπορεί να προσπελάσει ποιον**:
- **Υψηλότερες τιμές signer μπορούν να προσπελάσουν χαμηλότερες**
- **Οι PPL δεν μπορούν να προσπελάσουν PP**
- **Οι μη προστατευμένες διεργασίες δεν μπορούν να προσπελάσουν καμία PPL/PP**

### Τι πρέπει να γνωρίζετε από επιθετική σκοπιά

- Όταν η **LSASS** τρέχει ως **PPL**, προσπάθειες να την ανοίξετε μέσω `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` από ένα κανονικό admin context **αποτυγχάνουν με `0x5 (Access Denied)`**, ακόμα και αν το `SeDebugPrivilege` είναι ενεργό.
- Μπορείτε να **ελέγξετε το επίπεδο προστασίας της LSASS** χρησιμοποιώντας εργαλεία όπως το Process Hacker ή προγραμματιστικά διαβάζοντας την τιμή `EPROCESS.Protection`.
- Η LSASS συνήθως θα έχει `PsProtectedSignerLsa-Light` (`0x41`), η οποία μπορεί να προσπελαστεί **μόνο από διεργασίες υπογεγραμμένες με υπογράφοντα υψηλότερου επιπέδου**, όπως `WinTcb` (`0x61` ή `0x62`).
- Η **PPL είναι περιορισμός μόνο στο Userland**· ο κώδικας σε επίπεδο kernel μπορεί να τον παρακάμψει πλήρως.
- Το ότι η LSASS είναι PPL **δεν αποτρέπει το credential dumping** εάν μπορείτε να εκτελέσετε `kernel shellcode` ή να αξιοποιήσετε μια διεργασία με υψηλά προνόμια που έχει τα κατάλληλα δικαιώματα πρόσβασης.
- Η ενεργοποίηση ή η αφαίρεση της PPL απαιτεί επανεκκίνηση ή ρυθμίσεις Secure Boot/UEFI, οι οποίες μπορούν να διατηρήσουν την ρύθμιση PPL ακόμη και μετά την αναίρεση αλλαγών στο registry.

### Create a PPL process at launch (documented API)

Τα Windows εκθέτουν έναν τεκμηριωμένο τρόπο για να ζητηθεί ένα επίπεδο Protected Process Light για μια child process κατά τη δημιουργία χρησιμοποιώντας την extended startup attribute list. Αυτό δεν παρακάμπτει τις απαιτήσεις υπογραφής — το target image πρέπει να είναι υπογεγραμμένο για την ζητούμενη κλάση signer.

Ελάχιστη ροή σε C/C++:
```c
// Request a PPL protection level for the child process at creation time
// Requires Windows 8.1+ and a properly signed image for the selected level
#include <windows.h>

int wmain(int argc, wchar_t **argv) {
STARTUPINFOEXW si = {0};
PROCESS_INFORMATION pi = {0};
si.StartupInfo.cb = sizeof(si);

SIZE_T attrSize = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
if (!si.lpAttributeList) return 1;

if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) return 1;

DWORD level = PROTECTION_LEVEL_ANTIMALWARE_LIGHT; // or WINDOWS_LIGHT/LSA_LIGHT/WINTCB_LIGHT
if (!UpdateProcThreadAttribute(
si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
&level, sizeof(level), NULL, NULL)) {
return 1;
}

DWORD flags = EXTENDED_STARTUPINFO_PRESENT;
if (!CreateProcessW(L"C\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
flags, NULL, NULL, &si.StartupInfo, &pi)) {
// If the image isn't signed appropriately for the requested level,
// CreateProcess will fail with ERROR_INVALID_IMAGE_HASH (577).
return 1;
}

// cleanup
DeleteProcThreadAttributeList(si.lpAttributeList);
HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
return 0;
}
```
Σημειώσεις και περιορισμοί:
- Χρησιμοποιήστε `STARTUPINFOEX` με `InitializeProcThreadAttributeList` και `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, στη συνέχεια περάστε `EXTENDED_STARTUPINFO_PRESENT` στο `CreateProcess*`.
- Το protection `DWORD` μπορεί να οριστεί σε constants όπως `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, ή `PROTECTION_LEVEL_LSA_LIGHT`.
- Η child ξεκινά ως PPL μόνο εάν το image της είναι signed για εκείνη την signer class· διαφορετικά η δημιουργία διεργασίας αποτυγχάνει, συνήθως με `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Αυτό δεν είναι bypass — είναι ένα υποστηριζόμενο API προορισμένο για κατάλληλα signed images. Χρήσιμο για την ενίσχυση εργαλείων ή την επικύρωση PPL-protected configurations.

Παράδειγμα CLI με έναν minimal loader:
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Επιλογές για bypass των PPL προστασιών:**

Αν θέλετε να dump το LSASS παρά το PPL, έχετε 3 κύριες επιλογές:
1. **Use a signed kernel driver (e.g., Mimikatz + mimidrv.sys)** για να **αφαιρέσετε το protection flag του LSASS**:

![](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** για να τρέξετε custom kernel code και να απενεργοποιήσετε την προστασία. Εργαλεία όπως **PPLKiller**, **gdrv-loader**, ή **kdmapper** το καθιστούν εφικτό.
3. **Steal an existing LSASS handle** από άλλη διεργασία που το έχει ανοιχτό (π.χ., μια AV process), και στη συνέχεια **duplicate** αυτό στη διεργασία σας. Αυτό είναι η βάση της τεχνικής `pypykatz live lsa --method handledup`.
4. **Abuse some privileged process** που θα σας επιτρέψει να load arbitrary code στον address space του ή μέσα σε άλλη privileged process, ουσιαστικά bypassing τους περιορισμούς του PPL. Μπορείτε να δείτε ένα παράδειγμα σε [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) ή [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Ελέγξτε την τρέχουσα κατάσταση της LSA προστασίας (PPL/PP) για το LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
When you runing **`mimikatz privilege::debug sekurlsa::logonpasswords`** it'll probably fail with the error code `0x00000005` becasue of this.

- For more information about this check [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard**, a feature exclusive to **Windows 10 (Enterprise and Education editions)**, enhances the security of machine credentials using **Virtual Secure Mode (VSM)** and **Virtualization Based Security (VBS)**. It leverages CPU virtualization extensions to isolate key processes within a protected memory space, away from the main operating system's reach. This isolation ensures that even the kernel cannot access the memory in VSM, effectively safeguarding credentials from attacks like **pass-the-hash**. The **Local Security Authority (LSA)** operates within this secure environment as a trustlet, while the **LSASS** process in the main OS acts merely as a communicator with the VSM's LSA.

Από προεπιλογή, το **Credential Guard** δεν είναι ενεργό και απαιτεί χειροκίνητη ενεργοποίηση εντός μιας οργάνωσης. Είναι κρίσιμο για την ενίσχυση της ασφάλειας απέναντι σε εργαλεία όπως το **Mimikatz**, τα οποία δυσχεραίνουν την εξαγωγή διαπιστευτηρίων. Ωστόσο, ευπάθειες μπορούν ακόμα να εκμεταλλευτούν μέσω της προσθήκης προσαρμοσμένων **Security Support Providers (SSP)** για την καταγραφή διαπιστευτηρίων σε απλό κείμενο κατά τις προσπάθειες σύνδεσης.

Για να επαληθεύσετε την κατάσταση ενεργοποίησης του **Credential Guard**, μπορείτε να ελέγξετε το registry key _**LsaCfgFlags**_ κάτω από _**HKLM\System\CurrentControlSet\Control\LSA**_. Μια τιμή "**1**" υποδεικνύει ενεργοποίηση με **UEFI lock**, "**2**" χωρίς lock, και "**0**" δηλώνει ότι δεν είναι ενεργοποιημένο. Αυτός ο έλεγχος registry, παρότι είναι ισχυρός δείκτης, δεν είναι το μόνο απαιτούμενο βήμα για την ενεργοποίηση του Credential Guard. Λεπτομερείς οδηγίες και ένα PowerShell script για την ενεργοποίηση αυτής της λειτουργίας είναι διαθέσιμα online.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Για πλήρη κατανόηση και οδηγίες για την ενεργοποίηση του **Credential Guard** στα Windows 10 και την αυτόματη ενεργοποίησή του σε συμβατά συστήματα των **Windows 11 Enterprise and Education (version 22H2)**, επισκεφθείτε [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Περαιτέρω λεπτομέρειες για την υλοποίηση custom SSPs για την καταγραφή διαπιστευτηρίων παρέχονται σε [this guide](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

Τα **Windows 8.1 και Windows Server 2012 R2** εισήγαγαν αρκετά νέα μέτρα ασφαλείας, συμπεριλαμβανομένης της _**Restricted Admin mode for RDP**_. Αυτή η λειτουργία σχεδιάστηκε για να ενισχύσει την ασφάλεια μειώνοντας τους κινδύνους που συνδέονται με επιθέσεις [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Παραδοσιακά, όταν συνδέεστε σε έναν απομακρυσμένο υπολογιστή μέσω RDP, τα διαπιστευτήριά σας αποθηκεύονται στον υπολογιστή-στόχο. Αυτό δημιουργεί σημαντικό κίνδυνο ασφάλειας, ειδικά όταν χρησιμοποιούνται λογαριασμοί με αυξημένα προνόμια. Ωστόσο, με την εισαγωγή της _**Restricted Admin mode**_, αυτός ο κίνδυνος μειώνεται σημαντικά.

Όταν ξεκινάτε μια σύνδεση RDP χρησιμοποιώντας την εντολή **mstsc.exe /RestrictedAdmin**, η αυθεντικοποίηση στον απομακρυσμένο υπολογιστή γίνεται χωρίς να αποθηκεύονται τα διαπιστευτήριά σας σ' αυτόν. Αυτή η προσέγγιση διασφαλίζει ότι, σε περίπτωση μόλυνσης από malware ή αν ένας κακόβουλος χρήστης αποκτήσει πρόσβαση στον απομακρυσμένο server, τα διαπιστευτήριά σας δεν εκτίθενται, καθώς δεν αποθηκεύονται στον server.

Είναι σημαντικό να σημειωθεί ότι στη **Restricted Admin mode**, οι προσπάθειες πρόσβασης σε δικτυακούς πόρους από τη RDP συνεδρία δεν θα χρησιμοποιήσουν τα προσωπικά σας διαπιστευτήρια· αντίθετα χρησιμοποιείται η ταυτότητα του μηχανήματος.

Αυτή η δυνατότητα αποτελεί σημαντικό βήμα προόδου στην ασφάλεια των απομακρυσμένων desktop συνδέσεων και στην προστασία ευαίσθητων πληροφοριών σε περίπτωση παραβίασης ασφαλείας.

![](../../images/RAM.png)

Για πιο αναλυτικές πληροφορίες επισκεφθείτε [this resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Αποθηκευμένα διαπιστευτήρια

Τα Windows προστατεύουν τα **domain credentials** μέσω της **Local Security Authority (LSA)**, υποστηρίζοντας τις διαδικασίες logon με πρωτόκολλα ασφαλείας όπως **Kerberos** και **NTLM**. Μία βασική δυνατότητα των Windows είναι η ικανότητά τους να cache-άρουν τα **τελευταία δέκα domain logins** ώστε οι χρήστες να μπορούν ακόμα να έχουν πρόσβαση στους υπολογιστές τους ακόμη κι αν ο **domain controller είναι offline** — ιδιαίτερα χρήσιμο για χρήστες laptop που συχνά βρίσκονται εκτός του εταιρικού δικτύου.

Ο αριθμός των αποθηκευμένων logins μπορεί να ρυθμιστεί μέσω συγκεκριμένου **κλειδιού μητρώου ή group policy**. Για να δείτε ή να αλλάξετε αυτήν τη ρύθμιση, χρησιμοποιείται η ακόλουθη εντολή:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Η πρόσβαση σε αυτά τα cached credentials ελέγχεται αυστηρά, με μόνο τον λογαριασμό **SYSTEM** να έχει τα απαραίτητα δικαιώματα για να τα δει. Οι διαχειριστές που χρειάζονται πρόσβαση σε αυτές τις πληροφορίες πρέπει να το κάνουν με δικαιώματα χρήστη SYSTEM. Τα credentials αποθηκεύονται στο: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** μπορεί να χρησιμοποιηθεί για εξαγωγή αυτών των cached credentials χρησιμοποιώντας την εντολή `lsadump::cache`.

Για περισσότερες λεπτομέρειες, η αρχική [source](http://juggernaut.wikidot.com/cached-credentials) παρέχει αναλυτικές πληροφορίες.

## Protected Users

Η συμμετοχή στην ομάδα **Protected Users group** εισάγει πολλές βελτιώσεις ασφάλειας για τους χρήστες, προσφέροντας υψηλότερα επίπεδα προστασίας έναντι κλοπής και κατάχρησης credentials:

- **Credential Delegation (CredSSP)**: Ακόμα και αν το Group Policy setting για **Allow delegating default credentials** είναι ενεργό, τα plain text credentials των Protected Users δεν θα αποθηκεύονται στην cache.
- **Windows Digest**: Από **Windows 8.1 and Windows Server 2012 R2**, το σύστημα δεν θα αποθηκεύει στην cache plain text credentials των Protected Users, ανεξάρτητα από την κατάσταση του Windows Digest.
- **NTLM**: Το σύστημα δεν θα αποθηκεύει στην cache τα plain text credentials των Protected Users ούτε τις NT one-way functions (NTOWF).
- **Kerberos**: Για τους Protected Users, η Kerberos authentication δεν θα δημιουργεί **DES** ή **RC4 keys**, ούτε θα αποθηκεύει στην cache plain text credentials ή long-term keys πέρα από την αρχική απόκτηση του Ticket-Granting Ticket (TGT).
- **Offline Sign-In**: Οι Protected Users δεν θα έχουν cached verifier που δημιουργείται κατά το sign-in ή unlock, που σημαίνει ότι το offline sign-in δεν υποστηρίζεται για αυτούς τους λογαριασμούς.

Αυτές οι προστασίες ενεργοποιούνται τη στιγμή που ένας χρήστης, μέλος της ομάδας **Protected Users group**, συνδεθεί στη συσκευή. Αυτό διασφαλίζει ότι κρίσιμα μέτρα ασφάλειας είναι σε ισχύ για την προστασία έναντι διαφόρων μεθόδων συμβιβασμού credentials.

Για πιο λεπτομερείς πληροφορίες, συμβουλευτείτε την επίσημη [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Table from** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

## Αναφορές

- [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)

{{#include ../../banners/hacktricks-training.md}}
