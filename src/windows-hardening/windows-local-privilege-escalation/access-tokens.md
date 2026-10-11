# Erişim Belirteçleri

{{#include ../../banners/hacktricks-training.md}}

## Erişim Belirteçleri

Her sürecin güvenlik bağlamını tanımlayan bir **birincil erişim belirteci** vardır. Bir iş parçacığı normalde bu belirteci kullanır, ancak geçici olarak bir **kimliğe bürünme belirteci** de kullanabilir. Belirteçler kullanıcı SID'sini, grup SID'lerini, ayrıcalıkları, bütünlük bilgilerini ve oturum açma oturumu için bir oturum açma SID'sini içerir. Süreçler genellikle üst sürecin birincil belirtecine yönelik bir referansı devralır; belirtecin içeriğinin bağımsız bir kopyasını almazlar.<sup>[[4]](#references)</sup>

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

or using _Process Explorer_ from Sysinternals (select process and access"Security" tab):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Yerel yönetici

**UAC Admin Approval Mode** bir yönetici için geçerliyse, etkileşimli oturum açma işlemi tam yetkili bir yönetici token'ı ve filtrelenmiş bir token oluşturur. Explorer ve sıradan alt süreçler varsayılan olarak filtrelenmiş token'ı kullanır. **Run as administrator** gibi bir yükseltme isteği, UAC'den programı tam yetkili token ile başlatmasını ister. Davranış, yerleşik Administrator hesabı için ve Admin Approval Mode devre dışı bırakıldığında farklılık gösterir.<sup>[[5]](#references)</sup>

Atlatma teknikleri ve ilke ayrıntıları için özel [**UAC sayfasını**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) okuyun.

Uygulamada bu, **yükseltilmemiş bir yönetici kabuğunun genellikle filtrelenmiş bir token ile çalıştığı** anlamına gelir. Bu nedenle, süreç yükseltilene kadar `whoami /groups` çıktısında **`BUILTIN\Administrators` genellikle `Deny only` olarak görünür**. Windows, dahili olarak **bağlantılı bir yükseltilmiş token'ı** (`TokenLinkedToken`) tutar ve durumu `TokenElevationType` gibi alanlarla izler.

### Kimlik bilgileriyle kullanıcı taklidi

Başka herhangi bir kullanıcıya ait **geçerli kimlik bilgileriniz varsa**, bu kimlik bilgileriyle **yeni bir oturum açma oturumu oluşturabilirsiniz** :

```
runas /user:domain\username cmd.exe
```

**Erişim belirteci**, **LSASS** içindeki oturum açma oturumlarına yönelik bir **referans** da içerir; bu, sürecin ağdaki bazı nesnelere erişmesi gerektiğinde kullanışlıdır.\
Şu komutla, **ağ hizmetlerine erişmek için farklı kimlik bilgileri kullanan** bir süreç başlatabilirsiniz:

```
runas /user:domain\username /netonly cmd.exe
```

Bu, ağdaki nesnelere erişmek için kullanabileceğiniz kimlik bilgileriniz varsa ancak bu kimlik bilgileri yalnızca ağda kullanılacağından mevcut makinede geçerli değilse yararlıdır (mevcut makinede geçerli kullanıcı ayrıcalıklarınız kullanılır).

#### `runas /netonly` ayrıntıları

`runas /netonly` (ve `make_token` gibi C2 yardımcıları) bir **`LOGON32_LOGON_NEW_CREDENTIALS`** token'ı oluşturur. Lateral movement sırasında bunu anlamak oldukça yararlıdır:<sup>[[3]](#references)</sup>

- **Yerel olarak**, yeni süreç mevcut token ile **aynı yerel kimliği**, grupları, bütünlük düzeyini ve erişim kararlarının çoğunu korur.
- **Uzaktan**, dışarı giden kimlik doğrulama SMB / WinRM / LDAP / HTTP / Kerberos / NTLM için **sağlanan kimlik bilgilerini** kullanabilir.
- Bu nedenle ağ erişimi **alternatif hesap** olarak gerçekleşirken `whoami` hâlâ **orijinal yerel kullanıcıyı** gösterebilir.

Kimlik bilgileri etki alanında veya başka bir makinede geçerliyse ancak kullanıcının mevcut makinede **yerel olarak oturum açamaması ya da açmaması gerekiyorsa** bu harika bir seçenektir.

### Token türleri

İki tür token vardır:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primary token**: Bir sürecin güvenlik bağlamını temsil eder. Bir alt süreç normalde üst sürecin primary token'ını devralır; açık token kullanan süreç oluşturma API'lerinin ise token erişimi ve çağıran ayrıcalıkları için kendi gereksinimleri vardır.
- **Impersonation token**: Bir sunucu iş parçacığının erişim denetimleri için geçici olarak istemcinin güvenlik bağlamını kullanmasını sağlar. Dört düzeyi vardır:
  - **Anonymous**: Sunucuya, kimliği belirlenmemiş bir kullanıcınınkine benzer erişim sağlar.
  - **Identification**: Sunucunun, istemci kimliğini nesne erişimi için kullanmadan doğrulamasına olanak tanır.
  - **Impersonation**: Sunucunun istemci kimliğiyle çalışmasını sağlar.
  - **Delegation**: Kimlik doğrulama mekanizması ve hesap yapılandırması delegation'ı destekliyorsa sunucunun istemciyi uzak sistemlerde taklit etmesine olanak tanır.

#### Kullanmadan önce ele geçirilen token'ı değerlendirin

Token'ı yalnızca kullanıcı adına bakarak seçmeyin. Aynı hesap; farklı oturum açma oturumlarına, hizmet SID'lerine, ayrıcalıklara, bütünlük düzeylerine, kısıtlamalara ve ağ kimlik bilgilerine sahip birden fazla token'a sahip olabilir.<sup>[[9]](#references)</sup> `GetTokenInformation` ile en az **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** ve **`TokenStatistics.AuthenticationId`** alanlarını sorgulayın.<sup>[[7]](#references)</sup>

Kısıtlanmış bir token; yalnızca reddetme amacıyla kullanılan SID'ler, kaldırılmış ayrıcalıklar ve kısıtlayıcı SID'ler içerebilir. Kısıtlayıcı SID'ler varsa Windows, etkin SID'lerle bir erişim denetimi, kısıtlayıcı SID'lerle de ikinci bir erişim denetimi gerçekleştirir; **her iki denetimin de erişime izin vermesi gerekir**. Bu nedenle, çıktıda cazip görünen bir kullanıcı SID'si veya etkin bir grup, token'ın hedef nesneye erişebileceğini tek başına kanıtlamaz.<sup>[[8]](#references)</sup>

Belgelenmiş token ve süreç oluşturma gereksinimleri için şu karar akışını kullanın:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Bir **primary token**, `CreateProcessWithTokenW` veya `CreateProcessAsUserW` işlevine aktarılabilmesi için `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` erişim haklarına sahip bir handle gerektirir.
2. Bir **impersonation token**'ı `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)` ile dönüştürün. Identification düzeyindeki token'lar kimlik bilgilerini açığa çıkarabilir ancak o istemci adına erişim denetimi gerçekleştiremez.
3. `CreateProcessWithTokenW`, `SeImpersonatePrivilege` gerektirir ve alt süreci çağıranın oturumunda başlatır. `CreateProcessAsUserW` ise token'ın oturumunu kullanır; genellikle `SeIncreaseQuotaPrivilege` gerektirir ve `SeAssignPrimaryTokenPrivilege` de gerekebilir. Kimlik bilgileri mevcutsa ancak bu ayrıcalıklar eksikse belgelenmiş alternatif `CreateProcessWithLogonW` işlevidir.

#### Yalnızca süreç sahiplerini değil, token handle'larını da arayın

Her sürecin primary token'ını açmak, hizmetler ve broker süreçleri içinde sıradan handle'lar olarak tutulan **impersonation token'larını** gözden kaçırabilir. Tekrar kullanılabilir bir handle tablosu iş akışı; sistem handle'larını numaralandırıp token nesnelerini filtrelemek, her sahibini `PROCESS_DUP_HANDLE` ile açmak, aday handle'ı mevcut sürece kopyalamak ve ardından yukarıdaki alanları sorgulamaktır. Kopyalanan handle'ın `TOKEN_QUERY` ve `TOKEN_DUPLICATE` haklarını içerdiğini doğrulayın; bir token handle'ı görmek, bunun kullanılabilir bir primary token'a çoğaltılabileceği anlamına gelmez. Korunan süreçler ve süreç DACL'leri, sahibi sürecin handle'ının açılmasını engelleyebilir.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken`, hem süreç primary token'larının hem de tutulan token handle'larının numaralandırılmasını otomatikleştirir. `list_token`, kullanıcı adı başına tercih edilen bir adayı tutarken `list_all_token` tüm adayları yazdırır. PID, numaralandırmayı tek bir sahip süreçle sınırlar.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Manuel inceleme ve erişim denetimi için **TokenUniverse**, process/thread token’larını açabilir, mevcut token handle’larını arayabilir, kısıtlamaları ve logon oturumlarını inceleyebilir, token’ları çoğaltabilir ve çeşitli process oluşturma yöntemlerini test edebilir.<sup>[[13]](#references)</sup> Temelindeki process’ler arası handle primitive’i için bkz.:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Token’ları Impersonate Etme

Yeterli yetkiniz varsa, metasploit’in _**incognito**_ modülünü kullanarak diğer **token**’ları kolayca **listeleyebilir** ve **impersonate edebilirsiniz**. Bu, **diğer kullanıcıymış gibi işlem yapmanızı** sağlayabilir. Bu teknikle **yetki yükseltme** de yapabilirsiniz.

İşlem sırasında kolayca unutulabilecek bazı pratik notlar:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`**, çağıran tarafta **`SeImpersonatePrivilege`** gerektirir ve oluşturulan yeni process **çağıranın oturumunda** çalışır.
- **`CreateProcessAsUserW`**, `CreateProcessWithTokenW` `1314` hatasıyla başarısız olduğunda ancak çağıran taraf gerekli yetkilere sahipse olası bir alternatiftir. Alt process’in **token’ın işaret ettiği oturumda** çalışması gerektiğinde de doğru seçimdir.<sup>[[9]](#references)[[10]](#references)</sup>
- Token **`LogonUser(LOGON32_LOGON_NETWORK)`** çağrısından geliyorsa genellikle bir **impersonation token**’dır; bu nedenle onunla process başlatmayı denemeden önce **`DuplicateTokenEx(..., TokenPrimary, ...)`** kullanmanız gerekir.
- Impersonation token’larının hepsi aynı derecede kullanışlı değildir: **`SecurityIdentification`**, kullanıcıyı incelemenize izin verir ancak **onun gibi davranmanıza izin vermez**. Bir coercion primitive’i veya pipe/RPC istemcisi size yalnızca identification düzeyinde bir token veriyorsa **`TokenImpersonationLevel`** değerini denetleyin ve **`SecurityImpersonation`** veya daha üst düzeyde token sağlayan bir primitive’e geçin.

#### LSASS'e dokunmadan token hırsızlığı

Zaten bir **service** veya **SYSTEM** bağlamınız varsa ve **yetkili bir kullanıcı oturum açmışsa**, o kullanıcının token’ını çalmak ya da çoğaltmak çoğu zaman **LSASS** dökümü almaktan daha az dikkat çeker. Gerçek saldırıların çoğunda bu, şunları yapmak için yeterlidir:<sup>[[2]](#references)</sup>

- yerel işlemleri o kullanıcı olarak yürütmek
- uzak kaynaklara o kullanıcı olarak erişmek
- önce yeniden kullanılabilir kimlik bilgilerini çıkarmadan AD işlemleri gerçekleştirmek

Yetkili bir bağlamdan **oturum/kullanıcı token’ı ele geçirme** örnekleri için [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md) sayfasına bakın. **`WTSQueryUserToken`** gibi API’lerin **yüksek düzeyde güvenilen servisler** için tasarlandığını ve normalde **`LocalSystem` + `SeTcbPrivilege`** gerektirdiğini unutmayın; dolayısıyla bunlar öncelikle servis düzeyinde bir bağlamı zaten kontrol ettiğinizde kullanışlıdır. Önce **SYSTEM** elde etmenin yetkiye özgü yolları için aşağıdaki sayfalara bakın.

### Token Yetkileri

**Yetki yükseltmek için kötüye kullanılabilecek token yetkilerini öğrenin:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**Olası tüm token yetkilerine ve bazı tanımlara bu harici sayfadan göz atın**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Erişim Token’larını Anlama ve Kötüye Kullanma — Bölüm II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [LSASS'e dokunmadan Active Directory'yi ele geçirmek için Windows token’larını kötüye kullanma](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Cobalt Strike'ın "make_token" Komutunu Anlaşılır Kılmak](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Erişim Token’ları - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Kullanıcı Hesabı Denetimi nasıl çalışır - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Impersonation Düzeyleri - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [TOKEN_INFORMATION_CLASS numaralandırması - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Kısıtlanmış Token’lar - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [CreateProcessWithTokenW işlevi - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [CreateProcessAsUserW işlevi - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [DuplicateHandle işlevi - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
