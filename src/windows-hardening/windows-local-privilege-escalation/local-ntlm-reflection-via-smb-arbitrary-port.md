# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Yeni Windows build'leri **alternatif TCP portları için SMB client desteği** ekledi. Bu özellik, attacker'ın şunları yapabildiği durumlarda **local NTLM authentication** işlemini **SYSTEM local privilege escalation** işlemine dönüştürmek için abuse edilebilir:<sup>[[1]](#references)</sup>

1. **445 olmayan bir portta** attacker-controlled listener'a SMB connection açmak
2. Bu TCP connection'ı canlı tutmak
3. **Privileged local client**'ı **aynı SMB share path**'ine erişmeye zorlamak
4. Ortaya çıkan **local NTLM authentication** işlemini makinenin gerçek SMB service'ine geri relay etmek

Bu, **March 2026**'da patch'lenen **CVE-2026-24294**'ün temelindeki primitive'dir.<sup>[[1]](#references)[[4]](#references)</sup>

## Neden çalışır?

Eski CMTI / serialized-SPN reflection trick burada açıklanmıştır:

{{#ref}}
../ntlm/README.md
{{#endref}}

Bu yeni variant, marshalled hostname gerektirmez. Bunun yerine iki SMB client davranışını abuse eder:<sup>[[1]](#references)</sup>

- **Windows 11 24H2** ve **Windows Server 2025** üzerinde bulunan ve kullanıcıların `net use \\host\share /tcpport:<port>` ile erişebildiği **alternative port support**
- Birden fazla authenticated session'ın aynı TCP connection üzerinden taşınabildiği **SMB connection reuse / multiplexing**

Bu, low-privileged bir kullanıcının önce SMB client'tan high port üzerindeki attacker SMB server'a bir TCP connection oluşturmasına, ardından privileged bir service'i **tam olarak aynı UNC path**'ine erişmeye zorlamasına olanak tanır. Windows mevcut TCP connection'ı yeniden kullanmaya karar verirse privileged NTLM exchange attacker-controlled transport üzerinden gönderilir ve local SMB server'a relay edilebilir.<sup>[[1]](#references)</sup>

## Ön koşullar

- Target, SMB alternative ports özelliğini desteklemelidir:<sup>[[2]](#references)</sup>
- **Windows 11 24H2** veya sonrası
- **Windows Server 2025** veya sonrası
- Attacker, seçtiği high port üzerinde local veya remote SMB server çalıştırabilmelidir
- Attacker, privileged bir service'i UNC path'ine erişmeye zorlayabilmelidir
- Privileged authentication, **NTLM local authentication** olmalıdır
- Target relay edilebilir olmalıdır:<sup>[[1]](#references)</sup>
- Synacktiv, bunun varsayılan olarak **Windows Server 2025** üzerinde çalıştığını bildirdi
- Chain'leri **Windows 11 24H2** üzerinde çalışmadı; çünkü outbound SMB signing burada varsayılan olarak enforced durumdadır

## Userland ve internals

Command line üzerinden bu özellik basit görünür:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programmatically, istemci, belgelenmemiş `lpUseOptions` verileriyle `WNetAddConnection4W` kullanır. İlgili seçenek, sonunda bir FSCTL aracılığıyla kernel SMB client'a ulaşan ve `mrxsmb` tarafından ayrıştırılan `TraP` (transport parameters) seçeneğidir.<sup>[[1]](#references)[[3]](#references)</sup>

Önemli pratik notlar:<sup>[[1]](#references)</sup>

- **UNC syntax'te hâlâ bir port alanı yoktur**
- **`net use` logon session başına çalışır**
- Bypass hâlâ çalışır; çünkü **TCP connection ve SMB session ayrı nesnelerdir**
- Exploit, SMB client'ın daha önce oluşturulmuş TCP connection'ı yeniden kullanmasına bağlıysa **aynı share path'in kullanılması zorunludur**

## Exploitation flow

### 1. Attacker-controlled SMB transport oluşturma

Yüksek bir portta SMB server çalıştırın ve Windows'un bu server'a bağlanmasını sağlayın:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Sunucu, kontrol ettiğiniz herhangi bir kimlik bilgisi çiftini, örneğin `user:user`, kabul edebilir. Bu adımın amacı henüz privilege escalation değildir; yalnızca Windows SMB client'ın listener'ınıza açılan ve yeniden kullanılabilir bir TCP bağlantısı kurup bu bağlantıyı açık tutmasını sağlamaktır.<sup>[[1]](#references)</sup>

### 2. Privileged bir service'i aynı UNC path'e yönlendirin

**PetitPotam** gibi bir coercion primitive kullanarak **aynı** `\\192.168.56.3\share` path'ine karşı işlem yapın. Coerced client privileged ise ve target name local (`localhost` veya local IP/host) olarak belirtilmişse Windows, **NTLM local authentication** gerçekleştirir.

TCP connection yeniden kullanıldığından, privileged NTLM exchange doğrudan gerçek local SMB server'a gitmek yerine attacker SMB service'ine gönderilir.<sup>[[1]](#references)</sup>

### 3. Privileged authentication'ı local SMB'ye geri relay edin

Attacker-controlled SMB service, privileged NTLM exchange'i `ntlmrelayx.py`'ye iletir; bu araç exchange'i makinenin gerçek SMB listener'ına relay eder ve `NT AUTHORITY\SYSTEM` olarak bir session elde eder.<sup>[[1]](#references)</sup>

Public writeup'ta kullanılan tipik tooling:<sup>[[1]](#references)</sup>

- Yeniden kullanılan TCP connection üzerinden privileged auth'ı almak için custom port üzerinde `smbserver.py`
- Yakalanan NTLM'yi local SMB'ye relay etmek için `ntlmrelayx.py`
- Privileged authentication'ı zorlamak için `PetitPotam.exe` veya başka bir coercion primitive

## Operator notları

- Bu, generic remote relay trick değil, bir **local privilege escalation** tekniğidir<sup>[[1]](#references)</sup>
- Attacker-controlled SMB service, share mount için başlangıçta kullanılan **aynı TCP connection** üzerinde privileged authentication'ı işlemelidir<sup>[[1]](#references)</sup>
- Coerced access **farklı bir share path**'ine ulaşırsa Windows farklı bir connection oluşturabilir ve chain bozulur<sup>[[1]](#references)</sup>
- Arbitrary-port adımı çalışsa bile SMB signing gereksinimleri relay'i engelleyebilir<sup>[[1]](#references)</sup>
- Yalnızca Kerberos material'ına sahipseniz veya local NTLM'yi zorlayamıyorsanız bu exact variant yeterli değildir<sup>[[1]](#references)</sup>

## Detection and hardening

- **March 2026 Patch Tuesday** kapsamında yayımlanan **CVE-2026-24294** patch'ini uygulayın<sup>[[4]](#references)</sup>
- **non-default SMB port** kullanan `net use` veya `New-SmbMapping` işlemlerini izleyin<sup>[[1]](#references)</sup>
- Workstation veya server'lardan **high TCP port**'lara yapılan olağandışı outbound SMB trafiği için alert oluşturun<sup>[[1]](#references)</sup>
- **EFSRPC / PetitPotam-style** trigger'lar gibi coercion fırsatlarını inceleyin<sup>[[1]](#references)</sup>
- Mümkün olan yerlerde SMB signing'i zorunlu kılın; Synacktiv, bunun Windows 11 24H2 üzerinde relay işlemlerini engellediğini özellikle belirtiyor<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [2] [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [3] [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [4] [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
