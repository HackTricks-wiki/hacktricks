# Access Token'ları

{{#include ../../banners/hacktricks-training.md}}

## Access Token'ları

Sisteme **oturum açan her kullanıcı**, o oturum için **güvenlik bilgilerini içeren bir access token'a sahiptir**. Sistem, kullanıcı oturum açtığında bir access token oluşturur. Kullanıcı adına **çalıştırılan her process**, **access token'ın bir kopyasına sahiptir**. Token; kullanıcıyı, kullanıcının gruplarını ve kullanıcının yetkilerini tanımlar. Ayrıca token, mevcut oturum açma oturumunu tanımlayan bir logon SID (Security Identifier) içerir.

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
veya Sysinternals'ın _Process Explorer_ aracını kullanarak (işlemi seçin ve "Security" sekmesine erişin):

![Access Tokens - Access Tokens: veya Sysinternals'ın Process Explorer aracını kullanarak (işlemi seçin ve "Security" sekmesine erişin)](<../../images/image (772).png>)

### Yerel yönetici

Yerel bir yönetici oturum açtığında, **iki access token oluşturulur**: Biri yönetici haklarına, diğeri normal haklara sahip olur. **Varsayılan olarak**, bu kullanıcı bir işlem çalıştırdığında **normal** (yönetici olmayan) **haklara** sahip olan token kullanılır. Bu kullanıcı herhangi bir şeyi **yönetici olarak** ("Run as Administrator" gibi) **çalıştırmayı** denediğinde, izin istemek için **UAC** kullanılır.\
[**UAC hakkında daha fazla bilgi edinmek için bu sayfayı okuyun**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

Pratikte bu, **yükseltilmemiş bir yönetici shell'inin genellikle filtrelenmiş bir token ile çalıştığı** anlamına gelir. Bu nedenle `whoami /groups`, işlem yükseltilene kadar genellikle **`BUILTIN\Administrators` grubunu `Deny only` olarak** gösterir. Dahili olarak Windows, **bağlantılı bir yükseltilmiş token'ı** (`TokenLinkedToken`) tutar ve durumu `TokenElevationType` gibi alanlarla takip eder.

### Kimlik bilgileriyle kullanıcı taklidi

Başka bir kullanıcının **geçerli kimlik bilgilerine** sahipseniz, bu kimlik bilgileriyle **yeni bir logon session** oluşturabilirsiniz:
```
runas /user:domain\username cmd.exe
```
**access token** ayrıca **LSASS** içindeki oturum açma oturumlarına dair bir **reference** içerir; bu, process'in ağdaki bazı nesnelere erişmesi gerekiyorsa kullanışlıdır.\
Şunları kullanarak **network services'e erişmek için farklı kimlik bilgileri kullanan** bir process başlatabilirsiniz:
```
runas /user:domain\username /netonly cmd.exe
```
Bu, network içindeki nesnelere erişmek için kullanabileceğiniz geçerli credentials'a sahip olduğunuzda, ancak bu credentials mevcut host içinde geçerli olmadığında kullanışlıdır; çünkü bu credentials yalnızca network içinde kullanılacaktır (mevcut host üzerinde mevcut user privileges kullanılacaktır).

#### `runas /netonly` ayrıntıları

`runas /netonly` (ve `make_token` gibi C2 yardımcıları), bir **`LOGON32_LOGON_NEW_CREDENTIALS`** token oluşturur. Bu, lateral movement sırasında anlaşılması çok önemlidir, çünkü:<sup>[[3]](#references)</sup>

- **Yerel olarak**, yeni process mevcut token ile **aynı yerel identity**, gruplar, integrity level ve erişim kararlarının çoğunu korur.
- **Uzaktan**, outbound authentication SMB / WinRM / LDAP / HTTP / Kerberos / NTLM için **sağlanan credentials**'ı kullanabilir.
- Bu nedenle `whoami`, network access **alternate account** olarak gerçekleşirken bile **orijinal local user**'ı göstermeye devam edebilir.

Bu seçenek, credentials domain içinde veya başka bir host üzerinde geçerli olduğunda, ancak user'ın mevcut makineye **locally log on** olması mümkün olmadığında veya olmaması gerektiğinde oldukça kullanışlıdır.

### Token türleri

Kullanılabilen iki token türü vardır:

- **Primary Token**: Bir process'in security credentials'ının temsili olarak görev yapar. Primary token'ların oluşturulması ve process'lerle ilişkilendirilmesi, yükseltilmiş privileges gerektiren işlemlerdir ve privilege separation ilkesini vurgular. Genellikle token oluşturulmasından bir authentication service, token'ın user'ın operating system shell'i ile ilişkilendirilmesinden ise bir logon service sorumludur. Process'lerin oluşturulduklarında parent process'lerinin primary token'ını devraldığını belirtmek gerekir.
- **Impersonation Token**: Bir server application'ın secure objects'a erişmek için client identity'sini geçici olarak benimsemesini sağlar. Bu mekanizma dört operation level'a ayrılır:
- **Anonymous**: Server access'i, kimliği belirlenemeyen bir user'ın access'ine benzer şekilde sağlar.
- **Identification**: Server'ın client identity'sini doğrulamasına izin verir, ancak bunu object access için kullanmasına izin vermez.
- **Impersonation**: Server'ın client identity'si altında çalışmasını sağlar.
- **Delegation**: Impersonation'a benzer, ancak server'ın etkileşimde bulunduğu remote systems'a bu identity assumption'ı genişletmesini ve credentials'ın korunmasını sağlar.

#### Impersonate Tokens

Yeterli privileges'a sahipseniz, metasploit'in _**incognito**_ module'ünü kullanarak diğer **tokens**'ları kolayca **list** edebilir ve **impersonate** edebilirsiniz. Bu, **diğer user gibiymişsiniz gibi actions gerçekleştirmek** için kullanışlı olabilir. Bu technique ile **privileges escalate** de edebilirsiniz.

Operasyon sırasında kolayca unutulabilen bazı pratik notlar:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`**, caller'ın **`SeImpersonatePrivilege`** privilege'ına sahip olmasını gerektirir ve yeni process **caller'ın session'ında** çalışır.
- **`CreateProcessAsUserW`**, `CreateProcessWithTokenW` `1314` hatasıyla başarısız olduğunda veya token tarafından referans verilen **session'da** launch etmeniz gerektiğinde kullanılan olağan fallback'tir.
- Bir token **`LogonUser(LOGON32_LOGON_NETWORK)`** üzerinden geliyorsa genellikle bir **impersonation token**'dır; bu nedenle process spawn etmeyi denemeden önce **`DuplicateTokenEx(..., TokenPrimary, ...)`** kullanmanız gerekir.
- Her impersonation token eşit derecede kullanışlı değildir: **`SecurityIdentification`**, user'ı inspect etmenize izin verir, ancak **onun gibi hareket etmenize** izin vermez. Bir coercion primitive veya pipe/RPC client size yalnızca identification-level token veriyorsa **`TokenImpersonationLevel`** değerini kontrol edin ve **`SecurityImpersonation`** veya daha üst bir seviye sağlayan bir primitive'e geçin.

#### LSASS'e dokunmadan token theft

Zaten bir **service** veya **SYSTEM** context'ine sahipseniz ve **privileged bir user log on olmuşsa**, bu user'ın token'ını steal etmek veya duplicate etmek çoğu zaman **LSASS** dump etmekten daha sessizdir. Gerçek intrusion'ların çoğunda bu, aşağıdakiler için yeterlidir:<sup>[[2]](#references)</sup>

- local actions'ı bu user olarak çalıştırmak
- remote resources'lara bu user olarak erişmek
- öncesinde reusable credentials extract etmeden AD operations gerçekleştirmek

Privileged context'ten **session/user token hijacking** örnekleri için [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md) sayfasına bakın. **`WTSQueryUserToken`** gibi API'lerin **highly trusted services** için tasarlandığını ve normalde **`LocalSystem` + `SeTcbPrivilege`** gerektirdiğini unutmayın; bu nedenle bunlar öncelikle service-level bir context'i zaten kontrol ettiğinizde kullanışlıdır. Önce **SYSTEM** elde etmenin privilege-specific yolları için aşağıdaki sayfalara bakın.

### Token Privileges

Privileges escalate etmek için hangi **token privileges'ın abuse edilebileceğini** öğrenin:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**Tüm olası token privileges'larına ve bazı tanımlarına bu external page üzerinden**](https://github.com/gtworek/Priv2Admin) göz atın.

## References

- [1] [Understanding and Abusing Access Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Demystifying Cobalt Strike's "make_token" Command](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
