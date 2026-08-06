# Volatility - Başvuru Sayfası

{{#include ../../../banners/hacktricks-training.md}}

Farklı tarama seviyeleriyle bellek analizini otomatikleştiren ve birden fazla Volatility3 eklentisini paralel olarak çalıştıran bir araca ihtiyacınız varsa autoVolatility3 kullanabilirsiniz:: [https://github.com/H3xKatana/autoVolatility3/](https://github.com/H3xKatana/autoVolatility3/)
```bash
# Full scan (runs all plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s full

# Minimal scan (runs a limited set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s minimal

# Normal scan (runs a balanced set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s normal

```
**hızlı ve çılgın** bir şey istiyorsanız, birkaç Volatility plugin'ini paralel olarak çalıştıracak şu aracı kullanabilirsiniz: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Kurulum

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
### volatility2

{{#tabs}}
{{#tab name="Method1"}}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{{#endtab}}

{{#tab name="Method 2"}}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{{#endtab}}
{{#endtabs}}

## Volatility Komutları

[Volatility command reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan) içindeki resmi dokümana erişin.

### “list” ve “scan” plugin'leri hakkında bir not

Volatility'nin plugin'ler için, bazen adlarına da yansıyan iki ana yaklaşımı vardır. “list” plugin'leri; process'ler gibi bilgileri almak için Windows Kernel yapılarını dolaşmaya çalışır (`_EPROCESS` yapılarının memory'deki bağlı listesini bulup dolaşmak, OS handle'larını bulup listelemek, bulunan pointer'ları dereference etmek vb.). Aşağı yukarı, örneğin process'leri listelemesi istendiğinde Windows API'nin davranacağı şekilde çalışırlar.

Bu nedenle “list” plugin'leri oldukça hızlıdır, ancak malware tarafından yapılan manipulation'lara karşı Windows API kadar savunmasızdır. Örneğin malware, bir process'i `_EPROCESS` bağlı listesinden kaldırmak için DKOM kullanırsa, bu process Task Manager'da da pslist'te de görünmez.

Öte yandan “scan” plugin'leri, belirli yapılar olarak dereference edildiğinde anlamlı olabilecek şeyleri bulmak için memory'yi carving işlemine benzer bir yaklaşımla tarar. Örneğin `psscan`, memory'yi okur ve içinden `_EPROCESS` object'leri oluşturmaya çalışır (pool-tag scanning kullanır; bu, ilgilenilen bir yapının varlığına işaret eden 4-byte string'leri aramaktır). Bunun avantajı, sonlanmış process'leri de ortaya çıkarabilmesidir. Ayrıca malware `_EPROCESS` bağlı listesini manipüle etse bile plugin, memory'de bulunan yapıyı yine de bulur (process'in çalışabilmesi için bu yapının hâlâ var olması gerekir). Dezavantajı ise “scan” plugin'lerinin “list” plugin'lerinden biraz daha yavaş olması ve bazen false positive sonuçlar üretebilmesidir (çok uzun süre önce sonlanmış ve yapısının bazı bölümleri diğer işlemler tarafından üzerine yazılmış bir process).

Kaynak: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)<sup>[[6]](#references)</sup>

## OS Profilleri

### Volatility3

readme içinde açıklandığı üzere, desteklemek istediğiniz OS'nin **symbol table**'ını _volatility3/volatility/symbols_ içine yerleştirmeniz gerekir.\
Çeşitli işletim sistemleri için symbol table paketleri **download** edilebilir:

- [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### External Profile

Aşağıdaki işlemi yaparak desteklenen profillerin listesini alabilirsiniz:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
**indirdiğiniz yeni bir profili** (örneğin bir Linux profili) kullanmak istiyorsanız, bir yerde şu klasör yapısını oluşturmanız gerekir: _plugins/overlays/linux_ ve profil dosyasını içeren zip dosyasını bu klasörün içine koyun. Ardından, profillerin numarasını şu komutla öğrenin:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
[https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles) adresinden **Linux ve Mac profillerini indirebilirsiniz**.

Önceki bölümde profilin `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64` olarak adlandırıldığını görebilirsiniz; bu profili kullanarak şuna benzer bir komut çalıştırabilirsiniz:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Profili Keşfet
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **imageinfo ve kdbgscan arasındaki farklar**

[**Buradan**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): Yalnızca profile önerileri sunan imageinfo'nun aksine, **kdbgscan** doğru profile ve doğru KDBG adresine (birden fazla bulunması durumunda) kesin olarak ulaşmak için tasarlanmıştır. Bu plugin, Volatility profilleriyle ilişkilendirilmiş KDBGHeader signature'larını tarar ve false positive'leri azaltmak için sanity check'ler uygular. Çıktının ayrıntı düzeyi ve gerçekleştirilebilecek sanity check sayısı, Volatility'nin bir DTB bulup bulamamasına bağlıdır. Bu nedenle doğru profile'ı zaten biliyorsanız (veya imageinfo'dan bir profile önerisi aldıysanız), bunu `-f` ile kullandığınızdan emin olun.<sup>[[1]](#references)</sup>

Her zaman **kdbgscan'in bulduğu process sayısına** bakın. Bazen imageinfo ve kdbgscan birden fazla uygun **profile** bulabilir; ancak yalnızca **geçerli olanın process'lerle ilişkili sonuçları olacaktır** (Bunun nedeni, process'leri çıkarmak için doğru KDBG adresinin gerekli olmasıdır.)<sup>[[1]](#references)</sup>
```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```
#### KDBG

Volatility tarafından **KDBG** olarak adlandırılan **kernel debugger block**, Volatility ve çeşitli debugger'lar tarafından gerçekleştirilen adli bilişim görevleri için kritik öneme sahiptir. `KdDebuggerDataBlock` olarak tanımlanan ve `_KDDEBUGGER_DATA64` türünde olan bu yapı, `PsActiveProcessHead` gibi temel referansları içerir. Bu özel referans, süreç listesinin başlangıcını göstererek tüm süreçlerin listelenmesini sağlar; bu da kapsamlı memory analysis için temeldir.<sup>[[2]](#references)</sup>

## İşletim Sistemi Bilgileri
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
`banners.Banners` plugin'i, dump içinde **linux banner'larını bulmayı denemek** için **vol3**'te kullanılabilir.

## Hash'ler/Parolalar

SAM hash'lerini, [domain cached credentials](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) ve [LSA secrets](../../../windows-hardening/authentication-credentials-uac-and-efs/index.html#lsa-secrets) bilgilerini çıkarın.

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
{{#endtab}}
{{#endtabs}}

## Bellek Dökümü

Bir process'in bellek dökümü, process'in mevcut durumundaki **her şeyi çıkarır**. **procdump** modülü yalnızca **code'u çıkarır**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
## İşlemler

### İşlemleri listeleme

**Şüpheli** işlemleri (adlarına göre) veya **beklenmeyen** alt **işlemleri** (örneğin iexplorer.exe'nin alt işlemi olarak cmd.exe) bulmaya çalışın.\
Gizli işlemleri tespit etmek için pslist sonucunu psscan sonucu ile **karşılaştırmak** ilginç olabilir.

{{#tabs}}
{{#tab name="vol3"}}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
{{#endtab}}
{{#endtabs}}

### Proc dökümü

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{{#endtab}}
{{#endtabs}}

### Komut satırı

Şüpheli bir şey çalıştırıldı mı?

{{#tabs}}
{{#tab name="vol3"}}
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{{#endtab}}
{{#endtabs}}

`cmd.exe` içinde yürütülen komutlar **`conhost.exe`** (veya Windows 7 öncesi sistemlerde **`csrss.exe`**) tarafından yönetilir. Bu, bellek dökümü alınmadan önce saldırgan tarafından **`cmd.exe`** sonlandırılsa bile oturumun komut geçmişinin **`conhost.exe`** belleğinden kurtarılmasının hâlâ mümkün olduğu anlamına gelir. Bunu yapmak için konsolun modülleri içinde olağandışı etkinlik algılanırsa, ilişkili **`conhost.exe`** işleminin belleği dökülmelidir. Ardından, bu döküm içinde **strings** aranarak oturumda kullanılan komut satırları potansiyel olarak çıkarılabilir.

### Ortam

Çalışan her işlemin ortam değişkenlerini alın. İlginç değerler olabilir.

{{#tabs}}
{{#tab name="vol3"}}
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
{{#endtab}}
{{#endtabs}}

### Token ayrıcalıkları

Beklenmedik servislerde ayrıcalıklı token'ları kontrol edin.\
Bazı ayrıcalıklı token'ları kullanan işlemleri listelemek ilginç olabilir.

{{#tabs}}
{{#tab name="vol3"}}
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{{#endtab}}
{{#endtabs}}

### SID'ler

Bir işlem tarafından sahip olunan her SSID'yi kontrol edin.\
Ayrıcalıklı bir SID kullanan işlemleri (ve bazı service SID'lerini kullanan işlemleri) listelemek ilginç olabilir.

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
{{#endtab}}
{{#endtabs}}

### Handle'lar

Bir **process**'in hangi diğer dosyalar, anahtarlar, thread'ler, process'ler... için **handle**'a sahip olduğunu (açtığını) bilmek faydalıdır.

{{#tabs}}
{{#tab name="vol3"}}
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
{{#endtab}}
{{#endtabs}}

### DLL'ler

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
{{#endtab}}
{{#endtabs}}

### Process başına string'ler

Volatility, bir string'in hangi process'e ait olduğunu kontrol etmemizi sağlar.

{{#tabs}}
{{#tab name="vol3"}}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{{#endtab}}
{{#endtabs}}

Ayrıca yarascan modülünü kullanarak bir işlem içindeki dizeleri aramaya olanak tanır:

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
{{#endtab}}
{{#endtabs}}

### UserAssist

**Windows**, registry'de **UserAssist keys** adı verilen bir özellik kullanarak çalıştırdığınız programları takip eder. Bu anahtarlar, her programın kaç kez çalıştırıldığını ve en son ne zaman çalıştırıldığını kaydeder.<sup>[[3]](#references)</sup>

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{{#endtab}}

{{#tab name="vol2"}}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{{#endtab}}
{{#endtabs}}

## Hizmetler

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
{{#endtab}}
{{#endtabs}}

## Ağ

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
{{#endtab}}
{{#endtabs}}

## Registry hive

### Kullanılabilir hive'ları listele

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{{#endtab}}
{{#endtabs}}

### Bir değer al

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{{#endtab}}
{{#endtabs}}

### Dump
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## Dosya Sistemi

### Bağlama

{{#tabs}}
{{#tab name="vol3"}}
```bash
#See vol2
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
{{#endtab}}
{{#endtabs}}

### Tarama/döküm

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
{{#endtab}}
{{#endtabs}}

### Ana Dosya Tablosu

{{#tabs}}
{{#tab name="vol3"}}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{{#endtab}}
{{#endtabs}}

**NTFS dosya sistemi**, _master file table_ (MFT) olarak bilinen kritik bir bileşen kullanır. Bu tablo, MFT'nin kendisi de dahil olmak üzere bir volume üzerindeki her dosya için en az bir giriş içerir. Her dosya hakkındaki **boyut, zaman damgaları, izinler ve gerçek veriler** gibi önemli ayrıntılar, MFT girişlerinde veya MFT dışında bulunan ancak bu girişler tarafından referans verilen alanlarda kapsüllenir. Daha fazla ayrıntı [resmi belgelerde](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table) bulunabilir.<sup>[[4]](#references)</sup>

### SSL Anahtarları/Sertifikaları

{{#tabs}}
{{#tab name="vol3"}}
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
{{#endtab}}
{{#endtabs}}

## Zararlı Yazılım

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
{{#endtab}}
{{#endtabs}}

### YARA ile Tarama

Github'dan tüm YARA malware kurallarını indirmek ve birleştirmek için bu scripti kullanın: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
_**rules**_ dizinini oluşturun ve scripti çalıştırın. Bu işlem, malware için tüm YARA kurallarını içeren _**malware_rules.yar**_ adlı bir dosya oluşturur.

{{#tabs}}
{{#tab name="vol3"}}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
{{#endtab}}
{{#endtabs}}

## ÇEŞİTLİ

### Harici eklentiler

Harici eklentileri kullanmak istiyorsanız eklentilerle ilgili klasörlerin kullanılan ilk parametre olduğundan emin olun.

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{{#endtab}}
{{#endtabs}}

#### Autoruns

[https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns) adresinden indirin.
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### Mutex'ler

{{#tabs}}
{{#tab name="vol3"}}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
{{#endtab}}
{{#endtabs}}

### Sembolik bağlantılar

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{{#endtab}}
{{#endtabs}}

### Bash

**Bash geçmişini bellekten okumak** mümkündür. _.bash_history_ dosyasını da dökebilirsiniz, ancak devre dışı bırakılmışsa bu volatility modülünü kullanabildiğiniz için memnun olacaksınız.

{{#tabs}}
{{#tab name="vol3"}}
```
./vol.py -f file.dmp linux.bash.Bash
```
{{#endtab}}

{{#tab name="vol2"}}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
{{#endtab}}
{{#endtabs}}

### Zaman Çizelgesi

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{{#endtab}}

{{#tab name="vol2"}}
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{{#endtab}}
{{#endtabs}}

### Sürücüler

{{#tabs}}
{{#tab name="vol3"}}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{{#endtab}}
{{#endtabs}}

### Clipboard'ı alma
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### IE geçmişini al
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Notepad metnini al
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### Ekran görüntüsü
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Master Boot Record (MBR)
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
**Master Boot Record (MBR)**, farklı [dosya sistemleri](https://en.wikipedia.org/wiki/File_system) ile yapılandırılmış bir depolama ortamının mantıksal bölümlerini yönetmede kritik bir rol oynar. Yalnızca bölüm düzeni bilgilerini barındırmakla kalmaz, aynı zamanda boot loader olarak görev yapan çalıştırılabilir kodu da içerir. Bu boot loader, işletim sisteminin ikinci aşama yükleme sürecini doğrudan başlatır (bkz. [second-stage boot loader](https://en.wikipedia.org/wiki/Second-stage_boot_loader)) veya her bölümün [volume boot record](https://en.wikipedia.org/wiki/Volume_boot_record) (VBR) bileşeniyle birlikte çalışır. Ayrıntılı bilgi için [MBR Wikipedia sayfasına](https://en.wikipedia.org/wiki/Master_boot_record) başvurun.<sup>[[5]](#references)</sup>

## Referanslar

- [1] [Volatility, kendi cheatsheet'im (Bölüm 1): Image Identification](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
- [2] [Kernel Debugger Block'u bulma](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
- [3] [Windows UserAssist Keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
- [4] [Master File Table (Local File Systems) - Win32 apps](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
- [5] [UEFI tabanlı PC, protective MBR: nedir? - Microsoft Community](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)
- [6] [Tutorial: malware analysis için Volatility plugins](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

{{#include ../../../banners/hacktricks-training.md}}
