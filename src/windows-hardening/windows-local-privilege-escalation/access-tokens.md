# Erişim Token'ları

{{#include ../../banners/hacktricks-training.md}}

## Erişim Token'ları

Her process'in güvenlik bağlamını tanımlayan bir **primary access token**'ı vardır. Bir thread normalde bu token'ı kullanır, ancak geçici olarak bir **impersonation token**'ı da olabilir. Token'lar kullanıcı SID'sini, grup SID'lerini, ayrıcalıkları, bütünlük bilgilerini ve logon oturumu için bir logon SID'sini içerir. Process'ler genellikle ebeveynlerinin primary token'ına bir başvuru devralır; bu token'ın içeriğinin bağımsız bir kopyasını almazlar.<sup>[[4]](#references)</sup>

Bu bilgileri `whoami /all` komutunu çalıştırarak görebilirsiniz.

```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

veya Sysinternals’tan _Process Explorer_ kullanarak (süreci seçip "Security" sekmesine erişin):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Yerel yönetici

**UAC Admin Approval Mode** bir yönetici için geçerliyse, etkileşimli oturum açma işlemi tam yönetici token’ı ve filtrelenmiş bir token oluşturur. Explorer ve sıradan alt süreçler varsayılan olarak filtrelenmiş token’ı kullanır. **Run as administrator** gibi bir yükseltme isteği, UAC’den programı tam token’la başlatmasını ister. Kesin davranış, yerleşik Administrator hesabına ve Admin Approval Mode’un devre dışı olmasına bağlı olarak değişir.<sup>[[5]](#references)</sup>

Atlatma teknikleri ve ilke ayrıntıları için özel [**UAC sayfasını**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) okuyun.

Uygulamada bu, **yükseltilmemiş bir yönetici kabuğunun genellikle filtrelenmiş bir token’la çalıştığı** anlamına gelir. Bu nedenle süreç yükseltilene kadar `whoami /groups` çıktısında **`BUILTIN\Administrators` genellikle `Deny only` olarak görünür**. Windows, dahili olarak **bağlantılı yükseltilmiş bir token** (`TokenLinkedToken`) tutar ve durumu `TokenElevationType` gibi alanlarla izler.

### Kimlik bilgileriyle kullanıcı taklidi

Başka herhangi bir kullanıcının **geçerli kimlik bilgilerine** sahipseniz, bu kimlik bilgileriyle **yeni bir oturum açma oturumu oluşturabilirsiniz** :

```
runas /user:domain\username cmd.exe
```

**access token**, **LSASS** içindeki oturum açma oturumlarına yönelik bir **reference** da içerir. Bu, süreç ağdaki bazı nesnelere erişmek istediğinde kullanışlıdır.\
Şu komutu kullanarak **ağ hizmetlerine erişmek için farklı kimlik bilgileri kullanan** bir süreç başlatabilirsiniz:

```
runas /user:domain\username /netonly cmd.exe
```

Bu, ağdaki nesnelere erişmek için kullanabileceğiniz kimlik bilgilerine sahipseniz ancak bu kimlik bilgileri yalnızca ağda kullanılacağından mevcut ana bilgisayarda geçerli değilse işe yarar (mevcut ana bilgisayarda mevcut kullanıcı ayrıcalıklarınız kullanılır).

#### `runas /netonly` ayrıntıları

`runas /netonly` (ve `make_token` gibi C2 yardımcıları) bir **`LOGON32_LOGON_NEW_CREDENTIALS`** token'ı oluşturur. Yanal hareket sırasında bunu anlamak çok faydalıdır:<sup>[[3]](#references)</sup>

- **Yerel olarak**, yeni süreç mevcut token ile **aynı yerel kimliği**, grupları, bütünlük düzeyini ve erişim kararlarının çoğunu kullanmaya devam eder.
- **Uzaktan**, giden kimlik doğrulaması SMB / WinRM / LDAP / HTTP / Kerberos / NTLM için **sağlanan kimlik bilgilerini** kullanabilir.
- Bu nedenle ağ erişimi **alternatif hesap** olarak gerçekleşirken `whoami` hâlâ **orijinal yerel kullanıcıyı** gösterebilir.

Bu, kimlik bilgilerinin etki alanında veya başka bir ana bilgisayarda geçerli olduğu ancak kullanıcının mevcut makinede **yerel olarak oturum açamadığı ya da açmaması gerektiği** durumlarda harika bir seçenektir.

### Token türleri

Kullanılabilir iki token türü vardır:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primary token**: Bir sürecin güvenlik bağlamını temsil eder. Bir alt süreç normalde üst sürecin primary token'ını devralır; açık token kullanan süreç oluşturma API'leri ise kendi token erişimi ve çağıran ayrıcalığı gereksinimlerini uygular.
- **Impersonation token**: Bir sunucu iş parçacığının erişim denetimleri için geçici olarak istemcinin güvenlik bağlamını kullanmasını sağlar. Dört düzeyi vardır:
  - **Anonymous**: Sunucuya kimliği belirlenemeyen bir kullanıcınınkine benzer erişim sağlar.
  - **Identification**: Sunucunun istemci kimliğini doğrulamasını sağlar ancak bu kimliğin nesne erişimi için kullanılmasına izin vermez.
  - **Impersonation**: Sunucunun istemcinin kimliği altında çalışmasını sağlar.
  - **Delegation**: Kimlik doğrulama mekanizması ve hesap yapılandırması yetkilendirmeyi desteklediğinde sunucunun istemciyi uzak sistemlerde taklit etmesini sağlar.

#### Kullanımdan önce ele geçirilmiş bir token'ı değerlendirin

Yalnızca kullanıcı adına bakarak token seçmeyin. Aynı hesap; farklı oturum açma oturumları, hizmet SID'leri, ayrıcalıklar, bütünlük düzeyleri, kısıtlamalar ve ağ kimlik bilgileri içeren birden fazla token'a sahip olabilir.<sup>[[9]](#references)</sup> `GetTokenInformation` ile en az **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** ve **`TokenStatistics.AuthenticationId`** değerlerini sorgulayın.<sup>[[7]](#references)</sup>

Kısıtlanmış bir token; yalnızca reddetme amacıyla kullanılan SID'ler, kaldırılmış ayrıcalıklar ve kısıtlayıcı SID'ler içerebilir. Kısıtlayıcı SID'ler varsa Windows bir erişim denetimini etkin SID'lerle, diğerini ise kısıtlayıcı SID'lerle gerçekleştirir; **her iki denetimin de erişime izin vermesi gerekir**. Bu nedenle çıktıda çekici görünen bir kullanıcı SID'si veya etkin bir grup, tek başına token'ın hedef nesneye erişebileceğini kanıtlamaz.<sup>[[8]](#references)</sup>

Belgelenmiş token ve süreç oluşturma gereksinimleri için şu karar akışını kullanın:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Bir **primary token**, `CreateProcessWithTokenW` veya `CreateProcessAsUserW` işlevine verilebilmesi için `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` erişim haklarına sahip bir tanıtıcı gerektirir.
2. Bir **impersonation token**'ı `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)` ile dönüştürün. Identification düzeyindeki token'lar kimlik verilerini açığa çıkarabilir ancak erişim denetimlerini istemci olarak gerçekleştiremez.
3. `CreateProcessWithTokenW`, `SeImpersonatePrivilege` gerektirir ve alt süreci çağıranın oturumunda başlatır. `CreateProcessAsUserW` ise token'ın oturumunu kullanır; ancak normalde `SeIncreaseQuotaPrivilege` gerektirir ve `SeAssignPrimaryTokenPrivilege` de gerekebilir. Kimlik bilgileri mevcutsa ancak bu ayrıcalıklar yoksa belgelenmiş alternatif `CreateProcessWithLogonW`'dir.

#### Yalnızca süreç sahiplerini değil, token tanıtıcılarını da arayın

Her sürecin primary token'ını açmak, hizmetlerin ve aracı süreçlerin içinde sıradan tanıtıcılar olarak tutulan **impersonation token'ları** gözden kaçırabilir. Yeniden kullanılabilir bir tanıtıcı tablosu iş akışı; sistem tanıtıcılarını numaralandırmak, token nesnelerini filtrelemek, her sahibini `PROCESS_DUP_HANDLE` ile açmak, aday tanıtıcıyı mevcut sürece çoğaltmak ve ardından yukarıdaki alanları sorgulamaktır. Çoğaltılan tanıtıcının `TOKEN_QUERY` ve `TOKEN_DUPLICATE` haklarını içerdiğini doğrulayın; bir token tanıtıcısının görülmesi, onun kullanılabilir bir primary token'a çoğaltılabileceği anlamına gelmez. Korunan süreçler ve süreç DACL'leri, sahip süreç tanıtıcısının açılmasını yine de engelleyebilir.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken`, hem süreç primary token'larının hem de tutulan token tanıtıcılarının numaralandırılmasını otomatikleştirir. `list_token` her kullanıcı adı için tercih edilen tek adayı tutarken `list_all_token` tüm adayları yazdırır. Bir PID belirtmek, numaralandırmayı tek bir sahip süreciyle sınırlar.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

For manual inspection ve erişim kontrolleri için **TokenUniverse** process/thread token'larını açabilir, mevcut token handle'larını arayabilir, kısıtlamaları ve logon session'larını inceleyebilir, token'ları çoğaltabilir ve çeşitli process oluşturma yöntemlerini test edebilir.<sup>[[13]](#references)</sup> Temel cross-process handle primitive'i için bkz.:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Impersonate Tokens

Yeterli yetkiniz varsa, metasploit'in _**incognito**_ modülünü kullanarak diğer **token**'ları kolayca **listeleyebilir** ve **impersonate** edebilirsiniz. Bu, **diğer kullanıcıymış gibi işlem yapmak** için yararlı olabilir. Bu teknikle **privilege escalation** da yapabilirsiniz.

İşlem sırasında kolayca gözden kaçabilecek bazı pratik notlar:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`**, çağıran tarafta **`SeImpersonatePrivilege`** gerektirir ve yeni process **çağıranın session'ında** çalışır.
- **`CreateProcessAsUserW`**, `CreateProcessWithTokenW` çağrısı `1314` hatasıyla başarısız olursa, yalnızca çağıran taraf gerekli privilege'lara sahipse yedek seçenek olarak kullanılabilir. Alt process'in **token'ın belirttiği session'da** çalışması gerektiğinde de doğru seçimdir.<sup>[[9]](#references)[[10]](#references)</sup>
- Bir token **`LogonUser(LOGON32_LOGON_NETWORK)`** çağrısından geliyorsa, genellikle bir **impersonation token**'ıdır. Bu nedenle onunla process başlatmayı denemeden önce **`DuplicateTokenEx(..., TokenPrimary, ...)`** kullanmanız gerekir.
- Her impersonation token aynı ölçüde kullanışlı değildir: **`SecurityIdentification`**, kullanıcıyı incelemenize izin verir ancak **onun adına işlem yapmanıza izin vermez**. Bir coercion primitive'i veya pipe/RPC client size yalnızca identification seviyesinde bir token veriyorsa **`TokenImpersonationLevel`** değerini kontrol edin ve **`SecurityImpersonation`** veya daha üst seviyede token sağlayan bir primitive'e geçin.

#### LSASS'a dokunmadan token çalma

Zaten bir **service** veya **SYSTEM** context'ine sahipseniz ve **privileged bir kullanıcı oturum açmışsa**, o kullanıcının token'ını çalmak veya çoğaltmak çoğu zaman **LSASS**'ı dump etmekten daha az dikkat çeker. Gerçek dünyadaki birçok saldırıda bu, şunları yapmak için yeterlidir:<sup>[[2]](#references)</sup>

- yerel işlemleri o kullanıcı olarak yürütmek
- uzak kaynaklara o kullanıcı olarak erişmek
- önce tekrar kullanılabilir kimlik bilgilerini çıkarmadan AD işlemleri gerçekleştirmek

Privileged bir context'ten **session/user token hijacking** örnekleri için [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md) sayfasına bakın. **`WTSQueryUserToken`** gibi API'lerin **yüksek düzeyde güvenilen service'ler** için tasarlandığını ve normalde **`LocalSystem` + `SeTcbPrivilege`** gerektirdiğini unutmayın. Bu nedenle, öncelikle bir service-level context'i zaten kontrol ettiğinizde işe yararlar. Önce **SYSTEM** elde etmenin privilege'a özgü yolları için aşağıdaki sayfalara bakın.

### Token Privileges

**Privilege escalation için kötüye kullanılabilecek token privilege'larını** öğrenin:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**Tüm olası token privilege'larını ve bazı tanımlarını bu harici sayfada**](https://github.com/gtworek/Priv2Admin) inceleyin.

## References

- [1] [Access Token'ları Anlamak ve Kötüye Kullanmak — Bölüm II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [LSASS'a dokunmadan Active Directory'yi ele geçirmek için Windows token'larını kötüye kullanmak](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Cobalt Strike'ın "make_token" Komutunu Açıklığa Kavuşturmak](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Access Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Kullanıcı Hesabı Denetimi nasıl çalışır - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Impersonation Seviyeleri - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [TOKEN_INFORMATION_CLASS enumeration - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Kısıtlı Token'lar - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [CreateProcessWithTokenW function - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [CreateProcessAsUserW function - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [DuplicateHandle function - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
