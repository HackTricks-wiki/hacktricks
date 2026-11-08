# Erişim Belirteçleri

{{#include ../../banners/hacktricks-training.md}}

## Erişim Belirteçleri

Her process, güvenlik bağlamını tanımlayan bir **birincil erişim belirtecine** sahiptir. Bir thread normalde bu belirteci kullanır, ancak geçici olarak bir **kimliğe bürünme belirtecine** de sahip olabilir. Belirteçler kullanıcı SID’sini, grup SID’lerini, ayrıcalıkları, bütünlük bilgilerini ve oturum açma oturumuna ait bir oturum açma SID’sini içerir. Process’ler genellikle ebeveynlerinin birincil belirtecine referans devralır; belirtecin içeriğinin bağımsız bir kopyasını almazlar.<sup>[[4]](#references)</sup>

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

veya Sysinternals’tan _Process Explorer_ kullanarak (işlemi seçin ve "Security" sekmesine erişin):

![Access Tokens - Access Tokens: veya Sysinternals’tan Process Explorer kullanarak (işlemi seçin ve "Security" sekmesine erişin)](<../../images/image (772).png>)

### Yerel yönetici

**UAC Admin Approval Mode** bir yönetici için geçerliyse, etkileşimli oturum açma işlemi tam yönetici token’ı ve filtrelenmiş bir token oluşturur. Explorer ve sıradan alt işlemler varsayılan olarak filtrelenmiş token’ı kullanır. **Run as administrator** gibi bir yükseltme isteği, UAC’den programı tam token’la başlatmasını ister. Kesin davranış, yerleşik Administrator hesabına ve Admin Approval Mode’un devre dışı olup olmadığına göre değişir.<sup>[[5]](#references)</sup>

Atlatma teknikleri ve ilke ayrıntıları için özel [**UAC sayfasını**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) okuyun.

Uygulamada bu, **yükseltilmemiş bir yönetici kabuğunun genellikle filtrelenmiş bir token’la çalıştığı** anlamına gelir. Bu nedenle, işlem yükseltilene kadar `whoami /groups` çıktısında **`BUILTIN\Administrators` çoğu zaman `Deny only` olarak görünür**. Windows, dahili olarak bir **bağlantılı yükseltilmiş token’ı** (`TokenLinkedToken`) tutar ve durumu `TokenElevationType` gibi alanlarla takip eder.

### Kimlik bilgileriyle kullanıcı taklidi

Başka herhangi bir kullanıcının **geçerli kimlik bilgilerine** sahipseniz, bu kimlik bilgileriyle **yeni bir oturum açma oturumu oluşturabilirsiniz**:

```
runas /user:domain\username cmd.exe
```

**access token**, **LSASS** içindeki oturum açma oturumlarına bir **referans** da içerir; bu, işlemin ağdaki bazı nesnelere erişmesi gerektiğinde kullanışlıdır.\
Şunu kullanarak **ağ hizmetlerine erişmek için farklı kimlik bilgileri kullanan** bir işlem başlatabilirsiniz:

```
runas /user:domain\username /netonly cmd.exe
```

Bu, ağdaki nesnelere erişmek için kullanabileceğiniz kimlik bilgileri varsa ancak bu kimlik bilgileri yalnızca ağda kullanılacağından geçerli ana bilgisayarda geçerli değilse kullanışlıdır (geçerli ana bilgisayarda mevcut kullanıcı ayrıcalıklarınız kullanılır).

#### `runas /netonly` ayrıntıları

`runas /netonly` (ve `make_token` gibi C2 yardımcıları) **`LOGON32_LOGON_NEW_CREDENTIALS`** token'ı oluşturur. Yanal hareket sırasında bunu anlamak çok faydalıdır:<sup>[[3]](#references)</sup>

- **Yerel olarak**, yeni süreç **aynı yerel kimliği**, grupları, bütünlük düzeyini ve geçerli token ile alınan erişim kararlarının çoğunu korur.
- **Uzaktan**, giden kimlik doğrulama SMB / WinRM / LDAP / HTTP / Kerberos / NTLM için **sağlanan kimlik bilgilerini** kullanabilir.
- Bu nedenle `whoami` hâlâ **orijinal yerel kullanıcıyı** gösterebilirken ağ erişimi **alternatif hesap** olarak gerçekleşebilir.

Bu, kimlik bilgileri etki alanında veya başka bir ana bilgisayarda geçerliyse ancak kullanıcının geçerli makinede yerel olarak oturum **açamaması ya da açmaması gerekiyorsa** harika bir seçenektir.

### Token türleri

İki tür token vardır:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primary token**: Bir sürecin güvenlik bağlamını temsil eder. Alt süreç normalde üst sürecin primary token'ını devralır; açık token kullanan süreç oluşturma API'leri ise kendi token erişimi ve çağıran ayrıcalığı gereksinimlerini uygular.
- **Impersonation token**: Bir sunucu iş parçacığının erişim denetimleri için istemcinin güvenlik bağlamını geçici olarak kullanmasını sağlar. Dört düzeyi vardır:
  - **Anonymous**: Sunucuya kimliği belirlenemeyen bir kullanıcınınkine benzer erişim sağlar.
  - **Identification**: Sunucunun, istemcinin kimliğini nesne erişimi için kullanmadan doğrulamasını sağlar.
  - **Impersonation**: Sunucunun istemcinin kimliğiyle çalışmasını sağlar.
  - **Delegation**: Kimlik doğrulama mekanizması ve hesap yapılandırması delegation'ı desteklediğinde sunucunun istemciyi uzak sistemlerde taklit etmesini sağlar.

#### Kullanımdan önce ele geçirilen token'ı inceleyin

Token'ı yalnızca kullanıcı adına göre seçmeyin. Aynı hesabın farklı oturum açma oturumlarına, hizmet SID'lerine, ayrıcalıklara, bütünlük düzeylerine, kısıtlamalara ve ağ kimlik bilgilerine sahip birden fazla token'ı olabilir.<sup>[[9]](#references)</sup> `GetTokenInformation` ile en az **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** ve **`TokenStatistics.AuthenticationId`** alanlarını sorgulayın.<sup>[[7]](#references)</sup>

Kısıtlanmış bir token deny-only SID'ler, kaldırılmış ayrıcalıklar ve kısıtlayıcı SID'ler içerebilir. Kısıtlayıcı SID'ler varsa Windows, etkin SID'lerle bir erişim denetimi ve kısıtlayıcı SID'lerle başka bir erişim denetimi gerçekleştirir; **her iki denetimin de erişime izin vermesi gerekir**. Bu nedenle, çıktıda çekici görünen bir kullanıcı SID'si veya etkin bir grup tek başına token'ın hedef nesneye erişebileceğini kanıtlamaz.<sup>[[8]](#references)</sup>

Belgelenen token ve süreç oluşturma gereksinimleri için şu karar akışını kullanın:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Bir **primary token**'ın `CreateProcessWithTokenW` veya `CreateProcessAsUserW` işlevine verilebilmesi için `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` erişim haklarına sahip bir tanıtıcı gerekir.
2. Bir **impersonation token**'ını `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)` ile dönüştürün. Identification düzeyindeki token'lar kimlik verilerini açığa çıkarabilir ancak erişim denetimlerini o istemci gibi gerçekleştiremez.
3. `CreateProcessWithTokenW`, `SeImpersonatePrivilege` gerektirir ve alt süreci çağıranın oturumunda başlatır. `CreateProcessAsUserW` ise token'ın oturumunu kullanır; normalde `SeIncreaseQuotaPrivilege` gerektirir ve `SeAssignPrimaryTokenPrivilege` de gerektirebilir. Kimlik bilgileri mevcutsa ancak bu ayrıcalıklar yoksa belgelenmiş alternatif `CreateProcessWithLogonW`'dir.

#### Yalnızca süreç sahiplerini değil, token tanıtıcılarını da arayın

Her sürecin primary token'ını açmak, hizmetler ve broker süreçleri içinde sıradan tanıtıcılar olarak tutulan **impersonation token**'larını gözden kaçırabilir. Yeniden kullanılabilir bir tanıtıcı tablosu iş akışı; sistem tanıtıcılarını listelemek, token nesnelerine göre filtrelemek, her sahibini `PROCESS_DUP_HANDLE` ile açmak, aday tanıtıcıyı geçerli sürece çoğaltmak ve ardından yukarıdaki alanları sorgulamaktır. Çoğaltılan tanıtıcının `TOKEN_QUERY` ve `TOKEN_DUPLICATE` haklarını içerdiğini doğrulayın; bir token tanıtıcısının görülmesi, onun kullanılabilir bir primary token'a çoğaltılabileceği anlamına gelmez. Korumalı süreçler ve süreç DACL'leri, sahip sürecin tanıtıcısının açılmasını yine de engelleyebilir.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken`, hem süreç primary token'larının hem de süreçlerde tutulan token tanıtıcılarının numaralandırılmasını otomatikleştirir. `list_token`, kullanıcı adı başına tercih edilen tek bir adayı tutarken `list_all_token` tüm adayları yazdırır. PID belirtilmesi numaralandırmayı tek bir sahip süreciyle sınırlar.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Manuel inceleme ve erişim denetimi için **TokenUniverse**, süreç/iş parçacığı token’larını açabilir, mevcut token tanıtıcılarını arayabilir, kısıtlamaları ve oturum açma oturumlarını inceleyebilir, token’ları çoğaltabilir ve çeşitli süreç oluşturma yöntemlerini test edebilir.<sup>[[13]](#references)</sup> Temelindeki süreçler arası tanıtıcı primitive’i için bkz.:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

### Etkin iş parçacığı kimliğine bürünme token’larını araştırma

Bir hizmet iş parçacığı, **süreç birincil token’ı** hizmet hesabına ait olsa bile geçici olarak bir istemci adına kimliğe bürünebilir; bu nedenle süreç sahibi taramaları istemci bağlamını gözden kaçırabilir.<sup>[[4]](#references)</sup> TokenUniverse erişilebilir süreç/iş parçacığı token’larını listeleyebilir; System Informer’da aday iş parçacıklarını bulmak için bir sürecin **Threads** sekmesini ve **Impersonation** sütununu inceleyin.<sup>[[13]](#references)[[14]](#references)</sup>

Hedefli bir API denetimi için `TH32CS_SNAPTHREAD` anlık görüntüsü alın, `THREADENTRY32.th32OwnerProcessID` değerini hizmet PID’sine göre filtreleyin, ardından erişilebilir her iş parçacığı için `OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid)` ve `OpenThreadToken(thread, TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &token)` çağrılarını yapın.<sup>[[15]](#references)[[16]](#references)</sup> `TRUE`, token açma erişim denetiminin çağıranın **süreç** bağlamını kullanmasını sağlar; tarayıcının kendisi tanımlama düzeyinde kimliğe bürünüyorsa bu önemlidir.<sup>[[17]](#references)</sup> Yukarıdaki çoğaltma/süreç oluşturma akışını denemeden önce token’ın kullanıcısını, türünü, kimliğe bürünme düzeyini ve oturum açma kimliğini sorgulayın.<sup>[[7]](#references)</sup> Numaralandırma ile açma arasında bir iş parçacığı kimliğe bürünmeyi bırakabilir; token bulunmaması, anonim token’lar, korumalı iş parçacıkları, iş parçacığı DACL’leri ve token DACL’leri token’ın alınmasını engelleyebilir.<sup>[[16]](#references)[[17]](#references)</sup> Bir hizmetin tuttuğu token tanıtıcılarını taramanın aksine, bu yöntem **o anda atanmış iş parçacığı token’ını** sınar.

Mevcut iş parçacıklarını taramak yerine ayrıcalıklı bir istemciyi pipe’ınıza bağlanmaya yönlendirerek iş parçacığı token’ı elde eden bir saldırı yolu için bkz. [named-pipe client impersonation](named-pipe-client-impersonation.md).

#### Token’lara Kimliğe Bürünme

Yeterli ayrıcalığınız varsa, metasploit’in _**incognito**_ modülünü kullanarak diğer **token’ları** kolayca **listeleyebilir** ve **bunlara kimliğe bürünebilirsiniz**. Bu, **diğer kullanıcıymış gibi işlem yapmak** için yararlı olabilir. Bu teknikle **ayrıcalıkları da yükseltebilirsiniz**.

İşlem sırasında unutulması kolay bazı pratik notlar:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`**, çağıranda **`SeImpersonatePrivilege`** gerektirir ve yeni süreç **çağıranın oturumunda** çalışır.
- **`CreateProcessAsUserW`**, `CreateProcessWithTokenW` çağrısı `1314` hatasıyla başarısız olursa, yalnızca çağıran gerekli ayrıcalık koşullarını karşılıyorsa alternatif olabilir. Alt sürecin **token’ın işaret ettiği oturumda** çalışması gerektiğinde de doğru seçimdir.<sup>[[9]](#references)[[10]](#references)</sup>
- **`LogonUser(LOGON32_LOGON_NETWORK)`** bir **kimliğe bürünme token’ı** döndürür. Süreç oluşturmadan önce bunu **`DuplicateTokenEx(..., TokenPrimary, ...)`** ile dönüştürün. Dönüştürüldükten sonra bile ortaya çıkan süreç, kimliği doğrulanmış uzak paylaşımlara veya yazıcılara erişmek için bu ağ oturum açma bilgisini kullanamaz: bu oturum açma türü kimlik bilgilerini önbelleğe almaz. Kimlik bilgileriniz varsa ve sonraki ağ erişimine ihtiyacınız varsa etkileşimli veya ağ-açık metin oturum açma türünü kullanın; bunu yerel kimliği korurken giden kimlik bilgilerini sağlayan `LOGON32_LOGON_NEW_CREDENTIALS` (`runas /netonly`) ile karıştırmayın.<sup>[[18]](#references)</sup>
- Her kimliğe bürünme token’ı aynı ölçüde kullanışlı değildir: **`SecurityIdentification`**, kullanıcıyı incelemenize izin verir ancak **onun adına işlem yapmanıza** izin vermez. Bir zorlama primitive’i veya pipe/RPC istemcisi size yalnızca tanımlama düzeyinde bir token veriyorsa **`TokenImpersonationLevel`** değerini denetleyin ve **`SecurityImpersonation`** veya daha yüksek düzeyde token sağlayan bir primitive’e geçin.

#### LSASS’e dokunmadan token hırsızlığı

Zaten bir **hizmet** veya **SYSTEM** bağlamınız varsa ve **ayrıcalıklı bir kullanıcı oturum açmışsa**, bu kullanıcının token’ını çalmak veya çoğaltmak çoğu zaman **LSASS** dökümü almaktan daha sessizdir. Gerçek saldırıların çoğunda bu, şunlar için yeterlidir:<sup>[[2]](#references)</sup>

- o kullanıcı olarak yerel işlemler gerçekleştirmek
- o kullanıcı olarak uzak kaynaklara erişmek
- yeniden kullanılabilir kimlik bilgilerini önce çıkarmadan AD işlemleri gerçekleştirmek

Ayrıcalıklı bir bağlamdan **oturum/kullanıcı token’ı ele geçirme** örnekleri için [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md) sayfasına bakın. **`WTSQueryUserToken`** gibi API’lerin **yüksek düzeyde güvenilen hizmetler** için tasarlandığını ve normalde **`LocalSystem` + `SeTcbPrivilege`** gerektirdiğini unutmayın; dolayısıyla bunlar öncelikle bir hizmet düzeyindeki bağlamı zaten kontrol ettiğinizde kullanışlıdır. Önce **SYSTEM** elde etmenin ayrıcalığa özgü yolları için aşağıdaki sayfalara bakın.

### Token Ayrıcalıkları

**Ayrıcalıkları yükseltmek için kötüye kullanılabilecek token ayrıcalıklarını öğrenin:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**Olası tüm token ayrıcalıkları ve bazı tanımları için bu harici sayfaya**](https://github.com/gtworek/Priv2Admin) göz atın.



## References

- [1] [Erişim Token’larını Anlamak ve Kötüye Kullanmak — Bölüm II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [LSASS’e dokunmadan Active Directory’yi ele geçirmek için Windows token’larını kötüye kullanma](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Cobalt Strike’ın "make_token" Komutunu Açıklığa Kavuşturma](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Erişim Token’ları - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Kullanıcı Hesabı Denetimi nasıl çalışır - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Kimliğe Bürünme Düzeyleri - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [TOKEN_INFORMATION_CLASS numaralandırması - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Kısıtlanmış Token’lar - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [CreateProcessWithTokenW işlevi - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [CreateProcessAsUserW işlevi - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [DuplicateHandle işlevi - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
- [14] [System Informer iş parçacığı-token özelliği isteği](https://github.com/winsiderss/systeminformer/issues/1275)
- [15] [İş parçacığı listesini dolaşma - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list)
- [16] [NtOpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenthreadtoken)
- [17] [OpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
- [18] [LogonUserA - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera)
{{#include ../../banners/hacktricks-training.md}}
