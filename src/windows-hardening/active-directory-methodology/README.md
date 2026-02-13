# Active Directory Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Temel genel bakış

**Active Directory**, ağ yöneticilerinin bir ağ içinde **domain**leri, **kullanıcıları** ve **nesneleri** verimli bir şekilde oluşturup yönetmesini sağlayan temel bir teknolojidir. Ölçeklenebilir şekilde tasarlanmıştır; geniş kullanıcı kitlesini yönetilebilir **gruplar** ve **alt gruplar** halinde organize etmeye ve farklı seviyelerde **erişim haklarını** kontrol etmeye olanak tanır.

**Active Directory** yapısı üç ana katmandan oluşur: **domain**ler, **tree**ler ve **forest**lar. Bir **domain**, ortak bir veritabanını paylaşan **kullanıcılar** veya **cihazlar** gibi nesneler koleksiyonunu kapsar. **Tree**ler, ortak bir yapıyla bağlı domain gruplarıdır ve bir **forest**, birden fazla tree'in **trust relationships** aracılığıyla birbirine bağlandığı en üst organizasyonel katmandır. Bu seviyelerin her birinde belirli **erişim** ve **iletişim hakları** atanabilir.

Active Directory içindeki temel kavramlar şunlardır:

1. **Directory** – Active Directory nesnelerine ilişkin tüm bilgileri barındırır.
2. **Object** – Dizin içindeki varlıkları ifade eder; örneğin **kullanıcılar**, **gruplar** veya **paylaşılan klasörler**.
3. **Domain** – Dizin nesneleri için bir kapsayıcı görevi görür; bir **forest** içinde birden fazla domain bulunabilir ve her bir domain kendi nesne koleksiyonuna sahiptir.
4. **Tree** – Ortak bir root domain'i paylaşan domain gruplamasıdır.
5. **Forest** – Active Directory'deki organizasyonel yapının en üst seviyesi olup, aralarında **trust relationships** bulunan birden fazla tree'den oluşur.

**Active Directory Domain Services (AD DS)**, ağ içinde merkezi yönetim ve iletişim için kritik olan çeşitli servisleri kapsar. Bu servisler şunlardır:

1. **Domain Services** – Veri depolamayı merkezileştirir ve **kullanıcılar** ile **domain**ler arasındaki etkileşimleri, **authentication** ve **search** işlevleri dahil olmak üzere yönetir.
2. **Certificate Services** – Güvenli **dijital sertifikaların** oluşturulmasını, dağıtılmasını ve yönetilmesini denetler.
3. **Lightweight Directory Services** – **LDAP protocol**ü aracılığıyla dizin özellikli uygulamaları destekler.
4. **Directory Federation Services** – Web uygulamaları arasında kullanıcıların tek oturumda doğrulanmasını sağlayan **single-sign-on** yetenekleri sunar.
5. **Rights Management** – Telif hakkı korumalı materyalin yetkisiz dağıtımını ve kullanımını kontrol etmeye yardımcı olur.
6. **DNS Service** – **domain name**lerin çözümü için hayati öneme sahiptir.

Daha ayrıntılı açıklama için bakınız: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Bir **AD**'ye nasıl saldırılacağını öğrenmek için **Kerberos authentication process**ini gerçekten iyi anlamanız gerekir.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Hangi komutları kullanarak bir AD'yi enumerate/istismar edebileceğinize hızlıca bakmak için [https://wadcoms.github.io/](https://wadcoms.github.io) adresinden faydalanabilirsiniz.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Eğer bir AD ortamına erişiminiz var ancak hiçbir credential/session yoksa yapabilecekleriniz:

- **Pentest the network:**
- Ağı tarayın, cihazları ve açık portları bulun ve **vulnerabilities**leri **exploit** etmeye veya üzerlerinden **credentials** çıkarmaya çalışın (örneğin, [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS'in enumerate edilmesi, domain içindeki web, yazıcılar, paylaşımlar, vpn, medya vb. gibi önemli sunucular hakkında bilgi verebilir.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Bunu nasıl yapacağınız hakkında daha fazla bilgi için Genel [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) sayfasına bakın.
- **Check for null and Guest access on smb services** (bu modern Windows sürümlerinde çalışmayabilir):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bir SMB sunucusunu nasıl enumerate edeceğinize dair daha ayrıntılı bir rehber şu adreste bulunabilir:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP'ı nasıl enumerate edeceğinize dair daha ayrıntılı bir rehber burada bulunabilir (**anonymous access**'e özellikle dikkat edin):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder ile **impersonating services** yaparak credential toplayın (gather credentials) ([**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md))
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ile hostlara erişin
- evil-S ile sahte UPnP servisleri **exposing** yaparak credential toplayın ([**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856))
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- İç belge, sosyal medya, domain içindeki servisler (özellikle web) ve kamuya açık kaynaklardan kullanıcı adları/isimler çıkarın.
- Şirket çalışanlarının tam isimlerini bulursanız, farklı AD **username conventions** denemeyi düşünebilirsiniz ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). En yaygın konvansiyonlar: _NameSurname_, _Name.Surname_, _NamSur_ (her birinden 3 harf), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Araçlar:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) ve [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) sayfalarına bakın.
- **Kerbrute enum**: Geçersiz bir username sorgulandığında sunucu **Kerberos error** kodu _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ ile yanıt verir; bu sayede username'in geçersiz olduğu belirlenebilir. **Valid usernames**, ya bir **TGT in a AS-REP** yanıtı aldırır ya da kullanıcıdan pre-authentication istenildiğini gösteren _KRB5KDC_ERR_PREAUTH_REQUIRED_ hatası döner.
- **No Authentication against MS-NRPC**: Domain controller'larda MS-NRPC (Netlogon) arayüzüne auth-level = 1 (No authentication) ile bağlanarak kimlik doğrulaması olmadan kullanıcı veya bilgisayarın varlığını kontrol eden `DsrGetDcNameEx2` fonksiyonunun çağrılması yöntemi. Bu tür enumarasyonları uygulayan araçlardan biri [NauthNRPC](https://github.com/sud0Ru/NauthNRPC). Araştırma için bakınız [buraya](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ağda bu sunuculardan birini bulduysanız, ayrıca **user enumeration against it** gerçekleştirebilirsiniz. Örneğin, [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Bir veya birkaç kullanıcı adını bilmek

Tamam, yani zaten geçerli bir kullanıcı adına sahip olduğunuzu ama şifrelerin olmadığını biliyorsunuz... O zaman deneyin:

- [**ASREPRoast**](asreproast.md): Eğer bir kullanıcı _DONT_REQ_PREAUTH_ özniteliğine **sahip değilse**, o kullanıcı için bir **AS_REP message** isteyebilir ve bu mesaj, kullanıcının şifresinin türetilmiş haliyle şifrelenmiş bazı veriler içerebilir.
- [**Password Spraying**](password-spraying.md): Keşfedilen her kullanıcıyla en **yaygın şifreleri** deneyin, belki bazı kullanıcılar kötü bir şifre kullanıyordur (şifre politikasını unutmayın!).
- OWA sunucularına da **spray** uygulayarak kullanıcıların mail sunucularına erişim elde etmeye çalışabilirsiniz.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ağın bazı protokollerini **poisoning** yaparak kırmak üzere bazı challenge **hash'leri** elde edebilirsiniz:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory'yi enumerate etmeyi başardıysanız, **daha fazla e-posta ve ağ hakkında daha iyi bir anlayış** elde etmiş olacaksınız. NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) zorlayarak AD ortamına erişim sağlayabilirsiniz.

### Steal NTLM Creds

Eğer **null veya guest user** ile **diğer PC'lere veya paylaşımlara erişim** sağlayabiliyorsanız, erişildiğinde sizin üzerine NTLM authentication tetikleyecek (ör. bir SCF dosyası gibi) **dosyalar yerleştirerek** NTLM challenge'ını **çalarak** kırabilirsiniz:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**, elinizdeki her NT hash'ini, anahtar maddesi doğrudan NT hash'ten türetilen daha yavaş formatlar için bir aday parola olarak ele alır. Kerberos RC4 biletlerinde, NetNTLM challenge'larında veya cached credential'larda uzun parola denemelerini brute-force etmek yerine, NT hash'lerini Hashcat’in NT-candidate modlarına beslersiniz ve plaintext'i hiçbir zaman öğrenmeden parola yeniden kullanımını doğrularsınız. Bu, bir domain ele geçirildikten sonra binlerce güncel ve geçmiş NT hash'ini hasat edebildiğinizde özellikle etkilidir.

Shucking'i şu durumlarda kullanın:

- DCSync, SAM/SECURITY dump'ları veya credential vault'lardan bir NT corpus'una sahipsiniz ve diğer domain/forest'larda yeniden kullanım test etmeniz gerekiyor.
- RC4 tabanlı Kerberos materyali (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM cevapları veya DCC/DCC2 blob'ları yakaladınız.
- Uzun, kırılması zor passphrase'lerin yeniden kullanımını hızlıca kanıtlayıp hemen Pass-the-Hash ile pivot yapmak istiyorsunuz.

Teknik, anahtarları NT hash olmayan şifreleme türlerine (ör. Kerberos etype 17/18 AES) karşı **çalışmaz**. Bir domain yalnızca AES uyguluyorsa, normal parola modlarına dönmelisiniz.

#### NT hash korpusu oluşturma

- **DCSync/NTDS** – Geçmişi ile birlikte mümkün olan en geniş NT hash kümesini almak için `secretsdump.py` kullanın (ve önceki değerler):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History girdileri aday havuzunu dramatik olarak genişletir çünkü Microsoft her hesap için 24'e kadar önceki hash saklayabilir. NTDS sırlarını hasat etmenin diğer yolları için bakınız:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dump'ları** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (veya Mimikatz `lsadump::sam /patch`) yerel SAM/SECURITY verilerini ve cached domain logon'ları (DCC/DCC2) çıkarır. Bu hash'leri dedupe edip aynı `nt_candidates.txt` listesine ekleyin.
- **Meta veriyi takip edin** – Her hash'i üreten kullanıcı/ad domain bilgisini saklayın (wordlist yalnızca hex olsa bile). Eşleşen hash'ler, Hashcat kazanan adayı yazdırdığında hangi principal'in şifreyi yeniden kullandığını hemen söyler.
- Shucking yaparken aynı forest veya trust'lu forest'ten adayları tercih edin; böylece örtüşme şansı artar.

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

- NT-candidate girdileri **ham 32-hex NT hash** olarak kalmalıdır. Rule engine'leri devre dışı bırakın (`-r` yok, hybrid modlar yok) çünkü mangling aday anahtar maddesini bozar.
- Bu modlar doğal olarak daha hızlı değildir, fakat NTLM anahtar alanı (~30,000 MH/s bir M3 Max üzerinde) Kerberos RC4 (~300 MH/s) göre ~100× daha hızlıdır. Kurgulanmış bir NT listesi test etmek, yavaş formatta tüm parola alanını keşfetmekten çok daha ucuzdur.
- Her zaman **en son Hashcat build'ini** çalıştırın (`git clone https://github.com/hashcat/hashcat && make install`) çünkü 31500/31600/35300/35400 modları yakın zamanda eklendi.
- Şu anda AS-REQ Pre-Auth için bir NT modu yok ve AES etype'ları (19600/19700) plaintext parolayı gerektirir çünkü anahtarları PBKDF2 ile UTF-16LE parolalardan türetilir, ham NT hashlerden değil.

#### Örnek – Kerberoast RC4 (mode 35300)

1. Hedef SPN için düşük ayrıcalıklı bir kullanıcıyla bir RC4 TGS yakalayın (detaylar için Kerberoast sayfasına bakın):

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

Hashcat her NT adayı için RC4 anahtarını türetir ve `$krb5tgs$23$...` blob'unu doğrular. Bir eşleşme, servis hesabının mevcut NT hash'lerinizden birini kullandığını doğrular.

3. Hemen PtH ile pivot yapın:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Gerekirse sonradan plaintext'i `hashcat -m 1000 <matched_hash> wordlists/` ile kurtarabilirsiniz.

#### Örnek – Cached credentials (mode 31600)

1. Kompromize edilmiş bir workstation'dan cached logon'ları dump edin:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. İlgili domain kullanıcı için DCC2 satırını `dcc2_highpriv.txt` içine kopyalayın ve shuck edin:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Başarılı bir eşleşme, listenizde zaten bilinen NT hash'ini verir ve cached kullanıcının şifreyi yeniden kullandığını kanıtlar. Bunu doğrudan PtH için kullanın (`nxc smb <dc_ip> -u highpriv -H <hash>`) veya string'i kurtarmak için hızlı NTLM modunda brute-force edin.

Aynı iş akışı NetNTLM challenge-response'ları (`-m 27000/27100`) ve DCC (`-m 31500`) için de geçerlidir. Bir eşleşme tanımlandıktan sonra relay, SMB/WMI/WinRM PtH başlatabilir veya NT hash'i offline mask/rule'larla yeniden kırabilirsiniz.



## Enumerating Active Directory WITH credentials/session

Bu aşama için geçerli bir domain hesabının **kimlik bilgilerini veya bir oturumunu** compromise etmiş olmanız gerekir. Eğer bazı geçerli kimlik bilgilerine veya bir domain kullanıcısı olarak bir shell'e sahipseniz, **önceden verilen seçeneklerin diğer kullanıcıları compromise etmek için hâlâ seçenekler olduğunu** unutmayın.

Authenticated enumeration'a başlamadan önce **Kerberos double hop problem**'in ne olduğunu bilmelisiniz.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Bir hesabı compromise etmek, tüm domain'i compromise etmeye başlamak için **büyük bir adım**dır, çünkü Active Directory Enumeration'a başlayabileceksiniz:

[**ASREPRoast**](asreproast.md) ile artık her olası savunmasız kullanıcıyı bulabilirsiniz ve [**Password Spraying**](password-spraying.md) ile tüm kullanıcı adlarının bir listesini alıp compromise olmuş hesabın şifresini, boş şifreleri ve yeni umut verici şifreleri deneyebilirsiniz.

- Temel reconnaissance için [**CMD** kullanabilirsiniz](../basic-cmd-for-pentesters.md#domain-info)
- Daha stealthy olması için [**powershell ile recon**](../basic-powershell-for-pentesters/index.html) da kullanabilirsiniz
- Daha detaylı bilgi çıkarmak için [**powerview**](../basic-powershell-for-pentesters/powerview.md) kullanabilirsiniz
- Active Directory'de recon için başka harika bir araç da [**BloodHound**](bloodhound.md). Kullanım yöntemlerine bağlı olarak **çok stealthy değildir**, ama eğer bunun umurunuzda değilse kesinlikle denemelisiniz. Kullanıcıların nereden RDP yapabildiğini, diğer gruplara yolları bulun vb.
- **Diğer otomatik AD enumeration araçları:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- AD'nin [**DNS kayıtları**](ad-dns-records.md) ilginç bilgiler içerebilir.
- Dizini enumerate etmek için GUI tabanlı bir araç olarak **SysInternal** Suite'ten **AdExplorer.exe** kullanılabilir.
- LDAP veritabanında _userPassword_ & _unixUserPassword_ alanlarında veya hatta _Description_ içinde credential aramak için **ldapsearch** kullanabilirsiniz. Diğer yöntemler için bkz. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- **Linux** kullanıyorsanız, domain'i enumerate etmek için [**pywerview**](https://github.com/the-useless-one/pywerview) kullanabilirsiniz.
- Ayrıca otomatik araçlar deneyebilirsiniz:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Tüm domain kullanıcılarını çıkarmak**

Windows'ta tüm domain kullanıcı adlarını elde etmek çok kolaydır (`net user /domain` ,`Get-DomainUser` veya `wmic useraccount get name,sid`). Linux'ta ise `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` veya `enum4linux -a -u "user" -p "password" <DC IP>` kullanabilirsiniz.

> Bu Enumeration bölümü kısa görünse bile bu en önemli kısımdır. Linklere (özellikle cmd, powershell, powerview ve BloodHound olanlara) erişin, bir domain'i nasıl enumerate edeceğinizi öğrenin ve kendinizi rahat hissedene kadar pratik yapın. Bir assessment sırasında burası DA'ya ulaşmak ya da hiçbir şey yapılamayacağına karar vermek için kilit an olacaktır.

### Kerberoast

Kerberoasting, servislere bağlı kullanıcı hesapları tarafından kullanılan **TGS ticket'larını** elde etmeyi ve bunların şifreye dayalı olarak yapılan şifrelemelerini **offline** olarak kırmayı içerir.

Detaylar için:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Bazı kimlik bilgileri elde ettikten sonra herhangi bir **makineye** erişiminiz olup olmadığını kontrol edebilirsiniz. Bunun için port taramalarınıza göre çeşitli protokollerle birden fazla sunucuya bağlanmayı denemek üzere **CrackMapExec** kullanabilirsiniz.

### Local Privilege Escalation

Eğer bir regular domain kullanıcısı olarak kimlik bilgilerini veya bir oturumu compromise ettiyseniz ve bu kullanıcı ile domain içindeki **herhangi bir makineye** erişim sağlayabiliyorsanız, yerel ayrıcalıkları yükseltip credential'lar için loot aramaya çalışmalısınız. Çünkü yalnızca lokal administrator ayrıcalıkları ile diğer kullanıcıların hash'lerini bellekte (LSASS) ve localde (SAM) dump edebilirsiniz.

Bu kitapta [**Windows için local privilege escalation**](../windows-local-privilege-escalation/index.html) hakkında tam bir sayfa ve bir [**checklist**](../checklist-windows-privilege-escalation.md) bulunmaktadır. Ayrıca [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kullanmayı unutmayın.

### Current Session Tickets

Mevcut kullanıcıda beklenmeyen kaynaklara erişim izni veren **ticket'lar** bulma olasılığınız çok **düşük** olsa da kontrol edebilirsiniz:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

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

## Privilege escalation on Active Directory WITH privileged credentials/session

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

If you have the **hash** or **password** of a **local administrato**r you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Bunun oldukça **gürültülü** olduğunu ve **LAPS** bunun **azaltacağını** unutmayın.

### MSSQL Abuse & Trusted Links

Eğer bir kullanıcının **MSSQL örneklerine erişme** ayrıcalıkları varsa, MSSQL hostunda (SA olarak çalışıyorsa) **komut çalıştırmak**, NetNTLM **hash**'ini **çalmak** veya hatta bir **relay** **attack** gerçekleştirmek için bunu kullanabilir.\
Ayrıca, bir MSSQL örneği başka bir MSSQL örneği tarafından trusted (database link) ise, kullanıcı trusted veritabanı üzerinde ayrıcalıklara sahipse **trust ilişkisinden faydalanıp diğer instance üzerinde de sorgu çalıştırabilecek**. Bu trust’lar zincirlenebilir ve bir noktada kullanıcının komut çalıştırabileceği yanlış yapılandırılmış bir veritabanı bulması mümkün olabilir.\
**Veritabanları arasındaki linkler forest trust'ları üzerinden bile çalışır.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Üçüncü taraf envanter ve dağıtım suite’leri genellikle kimlik bilgilerine ve kod yürütmeye güçlü erişim yolları açar. Bakınız:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Eğer herhangi bir Computer objesinde [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) özniteliği bulunuyorsa ve bilgisayar üzerinde domain ayrıcalıklarınız varsa, o bilgisayara oturum açan her kullanıcının belleğinden TGT'leri dökebilirsiniz.\
Dolayısıyla, eğer bir **Domain Admin o bilgisayara giriş yaparsa**, onun TGT'sini dökerek [Pass the Ticket](pass-the-ticket.md) kullanıp onun adına işlem yapabilirsiniz.\
constrained delegation sayesinde **otomatik olarak bir Print Server'ı kompromize edebilirsiniz** (umarız DC olur).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Eğer bir kullanıcı veya bilgisayar "Constrained Delegation" için yetkilendirildiyse, **bir bilgisayardaki bazı servislere erişmek için herhangi bir kullanıcıyı taklit edebilir**.\
Sonrasında, eğer bu kullanıcı/bilgisayarın **hash'ini kompromize ederseniz**, bazı servislere erişmek için **herhangi bir kullanıcıyı** (hatta domain adminleri) **taklit edebilirsiniz**.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Uzak bir bilgisayarın Active Directory nesnesi üzerinde **WRITE** ayrıcalığına sahip olmak, **yüksek ayrıcalıklı** kod yürütme elde etmeyi mümkün kılar:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Kompromize olmuş kullanıcı, size daha sonra yatay hareket/ayrıcalık yükseltme (move laterally/escalate privileges) sağlayabilecek bazı **alan nesneleri** üzerinde ilginç ayrıcalıklara sahip olabilir.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain içinde **Spool servisi dinleyen** bir nokta keşfetmek, **yeni kimlik bilgileri elde etmek** ve **ayrıcalıkları yükseltmek** için **kötüye kullanılabilir**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Eğer **diğer kullanıcılar** **kompromize olmuş** makineye erişiyorsa, bellekten **kimlik bilgileri toplayabilir** ve hatta **işlemlerine beacon enjekte ederek** onları taklit edebilirsiniz.\
Kullanıcılar genellikle sisteme RDP ile erişir, bu yüzden üçüncü taraf RDP oturumlarına karşı birkaç saldırı nasıl yapılır burada:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**, domain’e katılmış bilgisayarlarda **local Administrator password** yönetimi sağlayan bir sistemdir; parolanın **rastgele**, benzersiz ve sıkça **değiştirilmesini** garanti eder. Bu parolalar Active Directory içinde saklanır ve erişim sadece ACL’ler ile yetkilendirilmiş kullanıcılara verilir. Bu parolalara erişmek için yeterli izinlere sahipseniz, diğer bilgisayarlara pivot yapmak mümkün hale gelir.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Kompromize makineden **sertifikaları toplamak**, ortam içinde ayrıcalıkları yükseltmenin bir yolu olabilir:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Eğer **zayıf template'ler** yapılandırılmışsa, bunları ayrıcalık yükseltme için kötüye kullanmak mümkündür:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Bir kere **Domain Admin** veya daha iyi **Enterprise Admin** ayrıcalıklarını elde ettiğinizde, **domain veritabanını**: _ntds.dit_ **dökebilirsiniz**.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Önceki bölümlerde tartışılan bazı teknikler kalıcılık için kullanılabilir.\
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

**Silver Ticket attack**, belirli bir servis için **meşru bir TGS bileti** oluşturmak için **NTLM hash** (ör. **PC account hash**) kullanır. Bu yöntem, servisin ayrıcalıklarına **erişmek** için kullanılır.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Bir **Golden Ticket attack**, saldırganın Active Directory ortamında **krbtgt hesabının NTLM hash'ine** erişim sağlamasını içerir. Bu hesap, tüm **Ticket Granting Ticket (TGT)**'leri imzalamak için kullanıldığı için özeldir ve AD ağı içinde kimlik doğrulama için kritiktir.

Saldırgan bu hash'i elde ettiğinde, herhangi bir hesap için **TGT** oluşturabilir (Silver ticket attack yöntemiyle).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Bunlar, yaygın golden ticket tespit mekanizmalarını **atlatacak şekilde** el yapımı golden ticket'lara benzer.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Bir hesabın sertifikalarına sahip olmak veya onları talep edebilmek**, kullanıcının hesabında kalıcılık sağlamak için (şifre değiştirse bile) çok iyi bir yoldur:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Sertifikalar kullanılarak domain içinde yüksek ayrıcalıklarla kalıcılık sağlamak** de mümkündür:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory'deki **AdminSDHolder** nesnesi, **Domain Admins** ve **Enterprise Admins** gibi **ayrıcalıklı grupların** güvenliğini sağlamak için bu gruplar üzerinde standart bir **Access Control List (ACL)** uygular ve yetkisiz değişiklikleri engeller. Ancak bu özellik kötüye kullanılabilir; bir saldırgan AdminSDHolder'ın ACL'ini düzenleyerek normal bir kullanıcıya tam erişim verir ise, o kullanıcı tüm ayrıcalıklı gruplar üzerinde geniş kontrole sahip olur. Bu güvenlik önlemi, yakından izlenmediği takdirde istenmeyen erişime yol açabilir.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Her **Domain Controller (DC)** içinde bir **local administrator** hesabı bulunur. Böyle bir makinede admin hakları elde ederek, local Administrator hash'ini **mimikatz** ile çıkarabilirsiniz. Ardından, bu parolanın **kullanılmasını etkinleştirmek** için bir registry değişikliği yapmak gerekir; böylece local Administrator hesabına uzaktan erişim mümkün olur.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Bir kullanıcıya bazı **özel izinler** vererek, o kullanıcının **ileride ayrıcalıkları yükseltmesine** imkan sağlayabilirsiniz.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors**, bir nesnenin üzerindeki **izinleri** saklamak için kullanılır. Bir nesnenin security descriptor'unda **küçük bir değişiklik** yapabilirseniz, o nesne üzerinde üyelik gerektirmeden çok ilginç ayrıcalıklar elde edebilirsiniz.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Bellekte **LSASS**'ı değiştirerek tüm domain hesapları için **evrensel bir parola** oluşturun ve erişim sağlayın.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Kendi **SSP**'nizi oluşturarak makineye erişimde kullanılan **kimlik bilgilerini açık metin** olarak yakalayabilirsiniz.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Yeni bir **Domain Controller** kaydeder ve bunu kullanarak belirtilen nesnelere (SIDHistory, SPNs...) **log bırakmadan** attribute'ları **push** eder. Bunun için **DA** ayrıcalıklarına ve **root domain** içinde olmaya ihtiyacınız vardır.\
Yanlış veri kullanırsanız, çok çirkin loglar oluşacağını unutmayın.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Önceden LAPS parolalarını **okuma** hakkına sahip olduğunuzda ayrıcalık yükseltme konusunu tartışmıştık. Ancak bu parolalar aynı zamanda **kalıcılık** sağlamak için de kullanılabilir.\
Bakınız:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft, **Forest**'ı güvenlik sınırı olarak görür. Bu, **tek bir domain'in kompromize edilmesinin tüm Forest'ın kompromize edilmesine yol açabileceği** anlamına gelir.

### Basic Information

Bir [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>), bir domain'den bir kullanıcının başka bir domain'deki kaynaklara erişmesini sağlayan bir güvenlik mekanizmasıdır. Temelde iki domain'in kimlik doğrulama sistemleri arasında bir bağlantı oluşturur ve doğrulama kontrollerinin akmasını sağlar. Domain'ler trust kurduğunda, trust'un bütünlüğü için kritik olan belirli **anahtarları** kendi **Domain Controller (DC)**'lerinde değiş tokuş eder ve saklarlar.

Tipik bir senaryoda, bir kullanıcı trusted domain'deki bir servise erişmek istediğinde, önce kendi domain'in DC'sinden özel bir bilet olan **inter-realm TGT**'yi talep etmelidir. Bu TGT, her iki domainin üzerinde anlaştığı paylaşılan bir **anahtar** ile şifrelenir. Kullanıcı bu inter-realm TGT'yi trusted domain'in DC'sine sunar ve DC doğrulama yapıp uygun görürse hedef servis için bir **TGS** (service ticket) verir. Inter-realm TGT başarıyla doğrulandığında, TGS hizmete erişimi sağlar.

**Adımlar**:

1. Bir **client bilgisayar** **Domain 1** içinde, **NTLM hash**'ini kullanarak **Ticket Granting Ticket (TGT)**'yi kendi **Domain Controller (DC1)**'den talep eder.
2. DC1, client doğrulanırsa yeni bir TGT verir.
3. Ardından client, **Domain 2** kaynaklarına erişmek için DC1'den bir **inter-realm TGT** talep eder.
4. Inter-realm TGT, iki yönlü domain trust kapsamında DC1 ve DC2 arasında paylaşılan bir **trust key** ile şifrelenir.
5. Client inter-realm TGT'yi **Domain 2'nin Domain Controller (DC2)**'sine götürür.
6. DC2, inter-realm TGT'yi kendi paylaşılan trust key'i ile doğrular ve geçerliyse client'ın erişmek istediği Domain 2 içindeki server için bir **Ticket Granting Service (TGS)** verir.
7. Son olarak client, bu TGS'yi server'a sunar; TGS server’ın account hash'i ile şifrelenmiştir ve böylece Domain 2'deki servise erişim sağlanır.

### Different trusts

Önemli olan bir trust'ın **tek yönlü veya çift yönlü** olabileceğidir. Çift yönlü seçenekte her iki domain birbirine güvenir, ancak **tek yönlü** trust ilişkisinde bir domain **trusted**, diğeri **trusting** olur. Bu durumda, **trusted** domain'den sadece **trusting** domain içindeki kaynaklara erişebilirsiniz.

Eğer Domain A, Domain B'ye güveniyorsa, A trusting domain; B ise trusted domain'dir. Ayrıca **Domain A** içinde bunun bir **Outbound trust**, **Domain B** içinde ise bir **Inbound trust** olduğunu düşünün.

**Different trusting relationships**

- **Parent-Child Trusts**: Aynı forest içinde yaygın bir yapı olup, child domain otomatik olarak parent domain ile iki yönlü transitif bir trust'a sahiptir. Bu, parent ve child arasında authentication taleplerinin sorunsuz akabileceği anlamına gelir.
- **Cross-link Trusts**: "shortcut trusts" olarak da adlandırılır; child domainler arasında referral süreçlerini hızlandırmak için kurulur. Karmaşık forest'larda authentication yönlendirmeleri genellikle forest root'a kadar çıkıp hedef domaine inmek zorunda kalır; cross-link'ler bu yolu kısaltır, özellikle coğrafi olarak dağılmış ortamlarda faydalıdır.
- **External Trusts**: Farklı, ilişkisiz domainler arasında kurulan ve doğası gereği non-transitive olan trust'lardır. [Microsoft dokümantasyonuna göre](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), dış trust'lar forest dışında kalan ve forest trust ile bağlı olmayan bir domain'deki kaynaklara erişim için kullanışlıdır. Security, external trust'larda SID filtering ile güçlendirilir.
- **Tree-root Trusts**: Forest root domain ile yeni eklenen bir tree root arasında otomatik olarak oluşturulan trust'lardır. Yaygın karşılaşılan bir durum olmasa da, yeni domain ağaçları eklerken önemlidir; iki yönlü transitiviteyi sağlar ve benzersiz domain adının korunmasına yardımcı olur. Daha fazla bilgi için [Microsoft rehberine](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) bakın.
- **Forest Trusts**: İki forest root domain arasında kurulan iki yönlü transitif trust türüdür ve güvenliği artırmak için SID filtering uygular.
- **MIT Trusts**: Bu trust'lar, non-Windows, [RFC4120-uyumlu](https://tools.ietf.org/html/rfc4120) Kerberos domain'leri ile kurulur. MIT trust'lar daha spesifik ortamlara yöneliktir ve Windows ekosistemi dışındaki Kerberos tabanlı sistemlerle entegrasyon gerektiren durumlar için kullanılır.

#### Other differences in **trusting relationships**

- Bir trust ilişkisi ayrıca **transitive** (A B'ye trust, B C'ye trust ise A C'yi trust eder) veya **non-transitive** olabilir.
- Bir trust ilişkisi **bidirectional trust** (her iki taraf birbirine güvenir) veya **one-way trust** (sadece tek taraf diğerine güvenir) olarak kurulabilir.

### Attack Path

1. **Trusting ilişkilerini** enumerate edin
2. Hangi **security principal**'in (user/group/computer) **diğer domain**in kaynaklarına **erişimi** olduğunu kontrol edin, belki ACE girdileriyle veya diğer domain gruplarında üyelik yoluyla. **Domainler arası ilişkiler**e bakın (trust mu bu amaçla oluşturulmuş olabilir).
1. Bu durumda kerberoast başka bir seçenek olabilir.
3. Domainler arasında **pivot** yapabilecek **hesapları kompromize edin**.

Bir saldırganın başka bir domaindeki kaynaklara erişimi üç ana mekanizma ile olabilir:

- **Local Group Membership**: Principal'lar makinelerdeki yerel gruplara, örneğin bir server'daki “Administrators” grubuna eklenmiş olabilir ve bu onlara o makine üzerinde önemli kontrol sağlar.
- **Foreign Domain Group Membership**: Principal'lar aynı zamanda yabancı domain içindeki grupların üyeleri olabilir. Ancak bu yöntemin etkinliği, trust'ın doğası ve grubun kapsamına bağlıdır.
- **Access Control Lists (ACLs)**: Principal'lar özellikle bir **DACL** içindeki **ACE** girdileri olarak belirtilmiş olabilir ve belirli kaynaklara erişim sağlar. ACL, DACL ve ACE mekaniklerine daha derin dalmak isteyenler için “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” başlıklı whitepaper çok değerli bir kaynaktır.

### Find external users/groups with permissions

Yabancı security principal'ları bulmak için **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** kontrol edebilirsiniz. Bunlar **harici bir domain/forest**'ten gelen user/group'lar olacaktır.

Bunu **Bloodhound** veya powerview kullanarak kontrol edebilirsiniz:
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
Domain trusts'ı enumerate etmenin diğer yolları:
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
> İki **trusted key** vardır: biri _Child --> Parent_ için, diğeri _Parent_ --> _Child_ için.\
> Mevcut alan tarafından kullanılan anahtarı şu komutlarla görebilirsiniz:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection'ı kullanarak trust'ı kötüye sürerek child/parent domain'e Enterprise admin olarak yükseltin:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC)'nin nasıl istismar edilebileceğini anlamak kritik önemdedir. Configuration NC, Active Directory (AD) ortamlarındaki bir forest boyunca yapılandırma verileri için merkezi bir depo görevi görür. Bu veriler forest içindeki her Domain Controller (DC)'ye replike edilir; yazılabilir DC'ler Configuration NC'nin yazılabilir bir kopyasını tutar. Bunu istismar edebilmek için, tercihen bir child DC olmak üzere, bir DC üzerinde **SYSTEM privileges on a DC** gereklidir.

**Link GPO to root DC site**

Configuration NC'nin Sites konteyneri, AD forest içindeki tüm domain-joined bilgisayarların site bilgilerini içerir. Herhangi bir DC üzerinde SYSTEM ayrıcalıkları ile hareket ederek, saldırganlar GPO'ları root DC sitesine linkleyebilir. Bu işlem, bu sitelere uygulanan politikaları manipüle ederek root domain'i potansiyel olarak tehlikeye atabilir.

Daha derin bilgi için [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) üzerindeki çalışmalara bakılabilir.

**Compromise any gMSA in the forest**

Bir saldırı vektörü, domain içindeki ayrıcalıklı gMSA'ları hedeflemeyi içerir. gMSA'ların parolalarını hesaplamak için gerekli olan KDS Root key, Configuration NC içinde saklanır. Herhangi bir DC üzerinde SYSTEM privileges ile KDS Root key'e erişmek ve forest genelindeki herhangi bir gMSA için parolaları hesaplamak mümkündür.

Detaylı analiz ve adım adım rehberlik şu kayıtta bulunabilir:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Tamamlayıcı delegated MSA saldırısı (BadSuccessor – migration attributes'ın suistimali):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ek dış kaynak: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Bu yöntem, yeni ayrıcalıklı AD nesnelerinin oluşturulmasını beklemeyi gerektirir. SYSTEM privileges ile bir saldırgan AD Schema'yı değiştirerek herhangi bir kullanıcıya tüm sınıflar üzerinde tam kontrol verebilir. Bu, yeni oluşturulan AD nesneleri üzerinde yetkisiz erişim ve kontrol ile sonuçlanabilir.

Daha fazla okumak için [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)'a bakabilirsiniz.

**From DA to EA with ADCS ESC5**

ADCS ESC5 zafiyeti, PKI nesneleri üzerinde kontrol elde etmeye yönelik olup forest içindeki herhangi bir kullanıcı olarak kimlik doğrulaması sağlayan bir certificate template oluşturmayı mümkün kılar. PKI nesneleri Configuration NC'de bulunduğundan, yazılabilir bir child DC'nin ele geçirilmesi ESC5 saldırılarının yürütülmesine olanak tanır.

Bu konuda daha fazla detayı [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) üzerinde okuyabilirsiniz. ADCS olmayan senaryolarda, saldırgan gerekli bileşenleri kurma yeteneğine sahiptir; bu konu [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) içinde tartışılmaktadır.

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
Bu senaryoda **etki alanınız harici bir etki alanı tarafından güveniliyor** ve size onun üzerinde **belirsiz izinler** veriliyor. Hangi etki alanı principal'larının harici etki alanı üzerinde **hangi erişimlere sahip olduğunu** bulmanız ve ardından bunları istismar etmeyi denemeniz gerekecek:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Harici Forest Domain - Tek Yönlü (Outbound)
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
Bu senaryoda **domain'iniz** bazı **izinleri** **farklı bir domain**'den gelen bir principal'e **güveniyor**.

Ancak, bir **domain** güvenilen domain tarafından **trust edildiğinde**, trusted domain **tahmin edilebilir bir isimle bir kullanıcı oluşturur** ve bu kullanıcının **parolası trusted password olarak** ayarlanır. Bu, **trusting domain'den bir kullanıcıya erişip trusted domain'in içine girerek** onu keşfetmenin ve daha fazla ayrıcalık yükseltmeyi denemenin mümkün olduğu anlamına gelir:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Trusted domain'i ele geçirmenin başka bir yolu da domain trust'ın **ters yönünde** oluşturulmuş bir [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) bulmaktır (bu çok yaygın değildir).

Trusted domain'i ele geçirmenin bir diğer yolu da, **trusted domain'den bir kullanıcının** RDP ile oturum açabileceği bir makinede beklemektir. Ardından saldırgan, RDP oturum süreci içine kod enjekte edebilir ve oradan **mağdurun orijin domainine erişebilir**.\
Dahası, eğer **mağdur sabit sürücüsünü mount ettiyse**, saldırgan **RDP oturumu** sürecinden sabit diskin **startup klasörüne** **backdoor'lar** yerleştirebilir. Bu teknik **RDPInception** olarak adlandırılır.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- SID history attribute'ını kullanarak forestlar arası trustlarda gerçekleştirilebilecek saldırıların riski, tüm inter-forest trustlarda varsayılan olarak etkin olan SID Filtering ile azaltılır. Bu, Microsoft'un bakış açısına göre güvenlik sınırı olarak domain yerine forest'un kabul edilmesine dayanan intra-forest trustların güvenli olduğu varsayımına dayanır.
- Ancak bir sorun vardır: SID filtering uygulamaları ve kullanıcı erişimini bozabilir, bu yüzden zaman zaman devre dışı bırakılmasına yol açabilir.

### **Selective Authentication:**

- Inter-forest trustlar için Selective Authentication kullanmak, iki foresttan gelen kullanıcıların otomatik olarak kimlik doğrulanmasını engeller. Bunun yerine, trusting domain veya forest içindeki domainlere ve sunuculara erişim için açıkça izin verilmesi gerekir.
- Bu önlemlerin writable Configuration Naming Context (NC) istismarı veya trust hesabına yönelik saldırılara karşı koruma sağlamadığını not etmek önemlidir.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) bloodyAD-style LDAP primitives'i, tamamen bir on-host implant (ör. Adaptix C2) içinde çalışan x64 Beacon Object File'lar olarak yeniden uygular. Operatörler paketi `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` ile derler, `ldap.axs`'i yükler ve beacon'dan `ldap <subcommand>` çağırır. Tüm trafik mevcut oturum güvenlik bağlamı üzerinden LDAP (389) ile signing/sealing veya LDAPS (636) ile otomatik sertifika güveni üzerinden gider; bu yüzden socks proxy'lere veya disk artifaktlarına ihtiyaç yoktur.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, ve `get-groupmembers` kısa isimleri/OU yollarını tam DN'lere çevirir ve ilgili objeleri döker.
- `get-object`, `get-attribute`, ve `get-domaininfo` rastgele attribute'ları (security descriptors dahil) çeker ve `rootDSE`'den forest/domain metadata'sını alır.
- `get-uac`, `get-spn`, `get-delegation`, ve `get-rbcd` roasting adaylarını, delegation ayarlarını ve mevcut [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) tanımlayıcılarını doğrudan LDAP'tan ortaya çıkarır.
- `get-acl` ve `get-writable --detailed` DACL'i parse ederek trustee'leri, hakları (GenericAll/WriteDACL/WriteOwner/attribute writes) ve inheritance'ı listeler ve ACL ayrıcalık yükseltme için anlık hedefler sağlar.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) operatörün OU haklarının olduğu her yerde yeni principal'ler veya bilgisayar hesapları hazırlamasına izin verir. `add-groupmember`, `set-password`, `add-attribute` ve `set-attribute` ise write-property hakları bulunduğunda hedefleri doğrudan ele geçirir.
- ACL odaklı komutlar (`add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, ve `add-dcsync`) herhangi bir AD nesnesi üzerindeki WriteDACL/WriteOwner'ı parola sıfırlamalara, grup üyeliği kontrolüne veya DCSync çoğaltma ayrıcalıklarına çevirir; bunu PowerShell/ADSI artefaktları bırakmadan yapar. `remove-*` muadilleri enjekte edilmiş ACE'leri temizler.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` ele geçirilmiş bir kullanıcıyı anında Kerberoastable yapar; `add-asreproastable` (UAC toggle) parolaya dokunmadan AS-REP roasting için işaretler.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) beacon üzerinden `msDS-AllowedToDelegateTo`, UAC bayrakları veya `msDS-AllowedToActOnBehalfOfOtherIdentity`'yi yeniden yazar; constrained/unconstrained/RBCD saldırı yollarını etkinleştirir ve uzak PowerShell veya RSAT ihtiyacını ortadan kaldırır.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` ayrıcalıklı SID'leri kontrol edilen bir principal’ın SID history'sine enjekte eder (bkz. [SID-History Injection](sid-history-injection.md)), LDAP/LDAPS üzerinden tamamen gizli erişim mirası sağlar.
- `move-object` bilgisayarların veya kullanıcıların DN/OU'sunu değiştirir; bir saldırganın, delege haklarının zaten bulunduğu OUlere varlıkları çekmesine olanak vererek `set-password`, `add-groupmember` veya `add-spn` gibi işlemleri kötüye kullanmadan önce konumlandırma yapmasını sağlar.
- Dar kapsamlı kaldırma komutları (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, vb.) operatör kimlik bilgilerini veya kalıcılığı topladıktan sonra hızlı geri alma imkanı sunar ve telemetriyi en aza indirir.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Domain Admins'in yalnızca Domain Controller'lara giriş yapmasına izin verilmesi ve diğer hostlarda kullanılmamasına dikkat edilmelidir.
- **Service Account Privileges**: Servisler güvenliği sağlamak için Domain Admin (DA) ayrıcalıklarıyla çalıştırılmamalıdır.
- **Temporal Privilege Limitation**: DA ayrıcalıkları gerektiren görevlerde süre sınırlaması uygulanmalıdır. Bu, şu şekilde yapılabilir: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: LDAP MITM/relay girişimlerini engellemek için Denetim Olay Kimlikleri 2889/3074/3075 incelenmeli ve ardından DC'lerde/istemcilerde LDAP signing ile LDAPS channel binding zorunlu hale getirilmelidir.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Aldatma uygulamak, süresi dolmayan parolalar veya Trusted for Delegation olarak işaretlenmiş özellikler gibi tuzaklar (decoy kullanıcılar veya bilgisayarlar) kurmayı içerir. Ayrıntılı bir yaklaşım, belirli haklara sahip kullanıcılar oluşturmayı veya bunları yüksek ayrıcalıklı gruplara eklemeyi kapsar.
- Pratik bir örnek şu araçların kullanılmasını içerir: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Aldatma tekniklerinin dağıtımı hakkında daha fazla bilgi için bkz.: [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Şüpheli göstergeler arasında alışılmadık ObjectSID, nadir oturum açmalar, oluşturulma tarihleri ve düşük başarısız parola sayıları bulunur.
- **General Indicators**: Potansiyel decoy nesnelerin özniteliklerini gerçek olanlarla karşılaştırmak tutarsızlıkları ortaya çıkarabilir. Bu tür aldatmaları tespit etmek için [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi araçlar yardımcı olabilir.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA tespitini önlemek için Domain Controller'larda oturum sayımlamaktan kaçının.
- **Ticket Impersonation**: Bilet oluşturmak için **aes** anahtarlarının kullanılması, NTLM'e düşürmeyi engellediği için tespitten kaçınmaya yardımcı olur.
- **DCSync Attacks**: ATA tespitinden kaçınmak için non-Domain Controller'dan yürütme yapılması tavsiye edilir; çünkü doğrudan bir Domain Controller'dan yürütme uyarıları tetikler.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
