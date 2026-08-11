# Windows Credentials Protections

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Το πρωτόκολλο [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), που παρουσιάστηκε με τα Windows XP, έχει σχεδιαστεί για authentication μέσω του HTTP Protocol και είναι **ενεργοποιημένο από προεπιλογή στα Windows XP έως και τα Windows 8.0, καθώς και στα Windows Server 2003 έως και τα Windows Server 2012**. Αυτή η προεπιλεγμένη ρύθμιση έχει ως αποτέλεσμα την **αποθήκευση κωδικών πρόσβασης σε plain text στο LSASS** (Local Security Authority Subsystem Service). Ένας attacker μπορεί να χρησιμοποιήσει το Mimikatz για να **εξαγάγει αυτά τα credentials** εκτελώντας:<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
Για να **ενεργοποιήσετε ή απενεργοποιήσετε αυτήν τη δυνατότητα**, τα registry keys _**UseLogonCredential**_ και _**Negotiate**_ στο _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ πρέπει να έχουν οριστεί σε "1". Αν αυτά τα keys **απουσιάζουν ή έχουν οριστεί σε "0"**, το WDigest είναι **απενεργοποιημένο**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (PP & PPL protected processes)

Οι **Protected Process (PP)** και **Protected Process Light (PPL)** είναι **προστασίες σε επίπεδο Windows kernel** που έχουν σχεδιαστεί για να αποτρέπουν τη μη εξουσιοδοτημένη πρόσβαση σε ευαίσθητες διεργασίες όπως η **LSASS**. Το μοντέλο **PP**, το οποίο εισήχθη στα **Windows Vista**, δημιουργήθηκε αρχικά για την επιβολή του **DRM** και επέτρεπε την προστασία μόνο binaries που ήταν υπογεγραμμένα με **ειδικό media certificate**. Μια διεργασία που έχει επισημανθεί ως **PP** μπορεί να προσπελαστεί μόνο από άλλες διεργασίες που είναι **επίσης PP** και διαθέτουν **ίδιο ή υψηλότερο επίπεδο προστασίας**, και ακόμη και τότε, **μόνο με περιορισμένα δικαιώματα πρόσβασης**, εκτός αν επιτρέπεται ρητά.

Το **PPL**, το οποίο εισήχθη στα **Windows 8.1**, είναι μια πιο ευέλικτη έκδοση του PP. Επιτρέπει **ευρύτερες περιπτώσεις χρήσης** (π.χ. LSASS, Defender), εισάγοντας **"επίπεδα προστασίας"** με βάση το πεδίο **EKU (Enhanced Key Usage)** της **digital signature**. Το επίπεδο προστασίας αποθηκεύεται στο πεδίο `EPROCESS.Protection`, το οποίο είναι μια δομή `PS_PROTECTION` με:
- **Type** (`Protected` ή `ProtectedLight`)
- **Signer** (π.χ. `WinTcb`, `Lsa`, `Antimalware`, κ.λπ.)

Αυτή η δομή συσκευάζεται σε ένα μόνο byte και καθορίζει **ποιος μπορεί να προσπελάσει ποιον**:
- **Οι υψηλότερες τιμές signer μπορούν να προσπελάσουν τις χαμηλότερες**
- **Τα PPL δεν μπορούν να προσπελάσουν τα PP**
- **Οι μη προστατευμένες διεργασίες δεν μπορούν να προσπελάσουν κανένα PPL/PP**

### Τι πρέπει να γνωρίζετε από offensive perspective

- Όταν το **LSASS εκτελείται ως PPL**, οι προσπάθειες ανοίγματός του με χρήση `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` από ένα κανονικό admin context **αποτυγχάνουν με `0x5 (Access Denied)`**, ακόμη και αν είναι ενεργοποιημένο το `SeDebugPrivilege`.
- Μπορείτε να **ελέγξετε το επίπεδο προστασίας του LSASS** χρησιμοποιώντας εργαλεία όπως το Process Hacker ή προγραμματιστικά, διαβάζοντας την τιμή `EPROCESS.Protection`.
- Το LSASS διαθέτει συνήθως `PsProtectedSignerLsa-Light` (`0x41`), στο οποίο μπορούν να έχουν πρόσβαση **μόνο διεργασίες υπογεγραμμένες με signer υψηλότερου επιπέδου**, όπως το `WinTcb` (`0x61` ή `0x62`).
- Το PPL είναι περιορισμός **μόνο σε Userland**· κώδικας σε **kernel level** μπορεί να το παρακάμψει πλήρως.
- Το γεγονός ότι το LSASS είναι PPL **δεν αποτρέπει το credential dumping**, εφόσον μπορείτε να εκτελέσετε kernel shellcode ή να αξιοποιήσετε μια διεργασία με υψηλά προνόμια και την κατάλληλη πρόσβαση.
- Η **ρύθμιση ή αφαίρεση του PPL** απαιτεί reboot ή ρυθμίσεις **Secure Boot/UEFI**, οι οποίες μπορούν να διατηρήσουν τη ρύθμιση PPL ακόμη και μετά την αντιστροφή των αλλαγών στο registry.

### Δημιουργία διεργασίας PPL κατά την εκκίνησή της (documented API)

Τα Windows παρέχουν έναν documented τρόπο για να ζητήσετε ένα επίπεδο Protected Process Light για μια child process κατά τη δημιουργία της, χρησιμοποιώντας τη λίστα extended startup attribute. Αυτό δεν παρακάμπτει τις απαιτήσεις signing — το target image πρέπει να είναι υπογεγραμμένο για την κλάση signer που ζητήθηκε.

Minimal flow σε C/C++:
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
- Χρησιμοποιήστε το `STARTUPINFOEX` με `InitializeProcThreadAttributeList` και `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, έπειτα περάστε το `EXTENDED_STARTUPINFO_PRESENT` στο `CreateProcess*`.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Το `DWORD` προστασίας μπορεί να οριστεί σε constants όπως `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` ή `PROTECTION_LEVEL_LSA_LIGHT`.
- Το child ξεκινά ως PPL μόνο αν το image του είναι signed για τη συγκεκριμένη signer class· διαφορετικά, η δημιουργία του process αποτυγχάνει, συνήθως με `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Αυτό δεν είναι bypass — είναι ένα υποστηριζόμενο API που προορίζεται για appropriately signed images. Είναι χρήσιμο για το hardening εργαλείων ή την επικύρωση configurations που προστατεύονται από PPL.

Παράδειγμα CLI με χρήση minimal loader:<sup>[[1]](#references)</sup>
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Επιλογές για bypass των PPL protections:**

Αν θέλετε να κάνετε dump του LSASS παρά το PPL, έχετε 3 βασικές επιλογές:
1. **Χρησιμοποιήστε έναν signed kernel driver (π.χ. Mimikatz + mimidrv.sys)** για να **αφαιρέσετε το protection flag του LSASS**:

![Έξοδος του Mimikatz mimidrv driver που δείχνει την αλληλεπίδραση με την credential protection](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** για να εκτελέσετε custom kernel code και να απενεργοποιήσετε την protection. Εργαλεία όπως τα **PPLKiller**, **gdrv-loader** ή **kdmapper** το καθιστούν εφικτό.
3. **Κλέψτε ένα υπάρχον LSASS handle** από άλλο process που το έχει ανοιχτό (π.χ. ένα AV process) και έπειτα **κάντε duplicate το handle** στο δικό σας process. Αυτή είναι η βάση της τεχνικής `pypykatz live lsa --method handledup`.
4. **Κάντε abuse σε κάποιο privileged process** που σας επιτρέπει να φορτώσετε arbitrary code στον address space του ή μέσα σε άλλο privileged process, παρακάμπτοντας ουσιαστικά τους περιορισμούς του PPL. Μπορείτε να δείτε ένα παράδειγμα στο [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) ή στο [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Έλεγχος της τρέχουσας κατάστασης της LSA protection (PPL/PP) για το LSASS:**
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
Κατά την εκτέλεση των **`mimikatz privilege::debug sekurlsa::logonpasswords`**, πιθανότατα θα αποτύχει με τον κωδικό σφάλματος `0x00000005` λόγω αυτής της προστασίας.

- Για περισσότερες πληροφορίες σχετικά με αυτόν τον έλεγχο: [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>


## Credential Guard

Το **Credential Guard**, μια δυνατότητα αποκλειστική για τα **Windows 10 (Enterprise και Education editions)**, ενισχύει την ασφάλεια των διαπιστευτηρίων του μηχανήματος χρησιμοποιώντας τα **Virtual Secure Mode (VSM)** και **Virtualization Based Security (VBS)**. Αξιοποιεί τις επεκτάσεις εικονικοποίησης της CPU για να απομονώνει βασικές διεργασίες μέσα σε έναν προστατευμένο χώρο μνήμης, μακριά από την πρόσβαση του κύριου λειτουργικού συστήματος. Αυτή η απομόνωση διασφαλίζει ότι ακόμη και ο kernel δεν μπορεί να αποκτήσει πρόσβαση στη μνήμη του VSM, προστατεύοντας αποτελεσματικά τα διαπιστευτήρια από επιθέσεις όπως το **pass-the-hash**. Το **Local Security Authority (LSA)** λειτουργεί μέσα σε αυτό το ασφαλές περιβάλλον ως trustlet, ενώ η διεργασία **LSASS** στο κύριο λειτουργικό σύστημα λειτουργεί απλώς ως επικοινωνητής με το LSA του VSM.

Από προεπιλογή, το **Credential Guard** δεν είναι ενεργό και απαιτεί χειροκίνητη ενεργοποίηση μέσα σε έναν οργανισμό. Είναι κρίσιμο για την ενίσχυση της ασφάλειας απέναντι σε εργαλεία όπως το **Mimikatz**, των οποίων η δυνατότητα εξαγωγής διαπιστευτηρίων περιορίζεται. Ωστόσο, οι ευπάθειες μπορούν ακόμη να αξιοποιηθούν μέσω της προσθήκης προσαρμοσμένων **Security Support Providers (SSP)** για την καταγραφή διαπιστευτηρίων σε clear text κατά τις προσπάθειες σύνδεσης.

Για την επαλήθευση της κατάστασης ενεργοποίησης του **Credential Guard**, μπορείτε να ελέγξετε το registry key _**LsaCfgFlags**_ στη θέση _**HKLM\System\CurrentControlSet\Control\LSA**_. Η τιμή "**1**" υποδεικνύει ενεργοποίηση με **UEFI lock**, η "**2**" ενεργοποίηση χωρίς lock και η "**0**" ότι δεν είναι ενεργοποιημένο. Αυτός ο έλεγχος του registry, αν και αποτελεί ισχυρή ένδειξη, δεν είναι το μοναδικό βήμα για την ενεργοποίηση του Credential Guard. Λεπτομερείς οδηγίες και ένα PowerShell script για την ενεργοποίηση αυτής της δυνατότητας είναι διαθέσιμα online.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Για μια ολοκληρωμένη κατανόηση και οδηγίες σχετικά με την ενεργοποίηση του **Credential Guard** στα Windows 10 και την αυτόματη ενεργοποίησή του σε συμβατά συστήματα των **Windows 11 Enterprise και Education (έκδοση 22H2)**, επισκεφθείτε την [τεκμηρίωση της Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).<sup>[[9]](#references)</sup>

Περισσότερες λεπτομέρειες σχετικά με την υλοποίηση προσαρμοσμένων SSPs για credential capture παρέχονται [σε αυτόν τον οδηγό](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

Τα **Windows 8.1 και Windows Server 2012 R2** εισήγαγαν αρκετές νέες δυνατότητες ασφάλειας, συμπεριλαμβανομένου του _**Restricted Admin mode for RDP**_. Αυτή η λειτουργία σχεδιάστηκε για την ενίσχυση της ασφάλειας, περιορίζοντας τους κινδύνους που σχετίζονται με επιθέσεις [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Παραδοσιακά, κατά τη σύνδεση σε έναν απομακρυσμένο υπολογιστή μέσω RDP, τα διαπιστευτήριά σας αποθηκεύονται στο target machine. Αυτό αποτελεί σημαντικό κίνδυνο ασφάλειας, ιδιαίτερα κατά τη χρήση λογαριασμών με αυξημένα δικαιώματα. Ωστόσο, με την εισαγωγή του _**Restricted Admin mode**_, αυτός ο κίνδυνος μειώνεται σημαντικά.

Κατά την έναρξη μιας σύνδεσης RDP με την εντολή **mstsc.exe /RestrictedAdmin**, η authentication στον απομακρυσμένο υπολογιστή πραγματοποιείται χωρίς να αποθηκεύονται τα διαπιστευτήριά σας σε αυτόν. Αυτή η προσέγγιση διασφαλίζει ότι, σε περίπτωση μόλυνσης από malware ή εάν ένας malicious user αποκτήσει πρόσβαση στον απομακρυσμένο server, τα διαπιστευτήριά σας δεν θα παραβιαστούν, καθώς δεν αποθηκεύονται στον server.

Είναι σημαντικό να σημειωθεί ότι στο **Restricted Admin mode**, οι προσπάθειες πρόσβασης σε network resources από τη συνεδρία RDP δεν χρησιμοποιούν τα προσωπικά σας διαπιστευτήρια· αντίθετα, χρησιμοποιείται η **ταυτότητα του machine**.

Αυτή η δυνατότητα αποτελεί σημαντικό βήμα για την ασφάλιση των remote desktop connections και την προστασία ευαίσθητων πληροφοριών από την έκθεσή τους σε περίπτωση security breach.

![Διάγραμμα μνήμης RAM των Windows για το context εξαγωγής credentials](../../images/RAM.png)

Για πιο λεπτομερείς πληροφορίες, επισκεφθείτε [αυτή την resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).<sup>[[6]](#references)</sup>

## Cached Credentials

Τα Windows προστατεύουν τα **domain credentials** μέσω του **Local Security Authority (LSA)**, υποστηρίζοντας τις διαδικασίες logon με security protocols όπως τα **Kerberos** και **NTLM**. Βασική δυνατότητα των Windows είναι η αποθήκευση σε cache των **δέκα τελευταίων domain logins**, ώστε οι χρήστες να μπορούν να συνεχίσουν να έχουν πρόσβαση στους υπολογιστές τους ακόμη και όταν ο **domain controller είναι offline** — κάτι ιδιαίτερα χρήσιμο για χρήστες laptop που βρίσκονται συχνά εκτός του δικτύου της εταιρείας τους.

Ο αριθμός των cached logins μπορεί να ρυθμιστεί μέσω ενός συγκεκριμένου **registry key ή group policy**. Για την προβολή ή την αλλαγή αυτής της ρύθμισης χρησιμοποιείται η ακόλουθη εντολή:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Η πρόσβαση σε αυτά τα cached credentials ελέγχεται αυστηρά, με μόνο τον λογαριασμό **SYSTEM** να διαθέτει τα απαραίτητα δικαιώματα για την προβολή τους. Οι administrators που χρειάζεται να αποκτήσουν πρόσβαση σε αυτές τις πληροφορίες πρέπει να το κάνουν με δικαιώματα χρήστη SYSTEM. Τα credentials αποθηκεύονται στη θέση: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

Το **Mimikatz** μπορεί να χρησιμοποιηθεί για την εξαγωγή αυτών των cached credentials με την εντολή `lsadump::cache`.

Για περισσότερες λεπτομέρειες, η αρχική [πηγή](http://juggernaut.wikidot.com/cached-credentials) παρέχει umfassείς πληροφορίες.<sup>[[7]](#references)</sup>

## Protected Users

Η συμμετοχή στην **Protected Users group** παρέχει αρκετές βελτιώσεις ασφαλείας για τους χρήστες, εξασφαλίζοντας υψηλότερα επίπεδα προστασίας απέναντι σε κλοπή και κακή χρήση credentials:

- **Credential Delegation (CredSSP)**: Ακόμη και αν είναι ενεργοποιημένη η ρύθμιση Group Policy για **Allow delegating default credentials**, τα plain text credentials των Protected Users δεν θα αποθηκεύονται σε cache.
- **Windows Digest**: Από τα **Windows 8.1 και Windows Server 2012 R2**, το σύστημα δεν θα αποθηκεύει σε cache τα plain text credentials των Protected Users, ανεξάρτητα από την κατάσταση του Windows Digest.
- **NTLM**: Το σύστημα δεν θα αποθηκεύει σε cache τα plain text credentials ή τις NT one-way functions (NTOWF) των Protected Users.
- **Kerberos**: Για τους Protected Users, το Kerberos authentication δεν θα δημιουργεί **DES** ή **RC4 keys**, ούτε θα αποθηκεύει σε cache plain text credentials ή long-term keys πέρα από την αρχική απόκτηση του Ticket-Granting Ticket (TGT).
- **Offline Sign-In**: Για τους Protected Users δεν θα δημιουργείται cached verifier κατά το sign-in ή το unlock, επομένως το offline sign-in δεν υποστηρίζεται για αυτούς τους λογαριασμούς.

Αυτές οι προστασίες ενεργοποιούνται τη στιγμή που ένας χρήστης, ο οποίος είναι μέλος της **Protected Users group**, πραγματοποιεί sign-in στη συσκευή. Έτσι διασφαλίζεται ότι εφαρμόζονται κρίσιμα μέτρα ασφαλείας για την προστασία από διάφορες μεθόδους παραβίασης credentials.

Για πιο λεπτομερείς πληροφορίες, συμβουλευτείτε την επίσημη [τεκμηρίωση](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).<sup>[[10]](#references)</sup>

**Πίνακας από** [**την τεκμηρίωση**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**<sup>[[11]](#references)</sup>

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators         | Backup Operators         | Backup Operators                                                              | Backup Operators             |
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

## References

- [1] [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [2] [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [3] [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [4] [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)
- [6] [Restricted Admin Mode for RDP](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)
- [7] [Cached Credentials - Juggernaut AppSec Wiki](http://juggernaut.wikidot.com/cached-credentials)
- [8] [WDigest Authentication (Microsoft TechNet)](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)
- [9] [Manage Windows Defender Credential Guard (Microsoft Learn)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [10] [Protected Users Security Group (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [11] [Appendix C: Protected Accounts and Groups in Active Directory (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
{{#include ../../banners/hacktricks-training.md}}
