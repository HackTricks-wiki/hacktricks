# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Sisteme **giriş yapmış** her **kullanıcı**, o logon session için **security information** içeren bir access token taşır. Sistem, kullanıcı giriş yaptığında bir access token oluşturur. Kullanıcı adına yürütülen **her process**, access token’ın bir kopyasına sahiptir. Token, kullanıcıyı, kullanıcının gruplarını ve kullanıcının privileges bilgilerini tanımlar. Bir token ayrıca mevcut logon session’ı tanımlayan bir logon SID (Security Identifier) içerir.

Bu bilgiyi `whoami /all` çalıştırarak görebilirsiniz
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
veya Sysinternals’tan _Process Explorer_ kullanarak (process’i seçin ve "Security" tab’ına erişin):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Local administrator

Bir local administrator login yaptığında, **iki access token oluşturulur**: Biri admin rights ile, diğeri normal rights ile. **Varsayılan olarak**, bu user bir process çalıştırdığında **regular** (non-administrator) **rights** olan kullanılır. Bu user **administrator olarak** bir şey **execute** etmeye çalıştığında ("Run as Administrator" gibi) izin istemek için **UAC** kullanılacaktır.\
Eğer [**UAC hakkında daha fazla bilgi edinmek isterseniz bu sayfayı okuyun**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

Pratikte bu, **non-elevated admin shell**’in genellikle **filtered token** ile çalıştığı anlamına gelir. Bu yüzden `whoami /groups` çoğu zaman process elevated edilene kadar **`BUILTIN\Administrators` için `Deny only`** gösterir. İçeride, Windows bir **linked elevated token** (`TokenLinkedToken`) tutar ve durumu `TokenElevationType` gibi alanlarla izler.

### Credentials user impersonation

Eğer **başka herhangi bir user için geçerli credentials**’ınız varsa, bu credentials ile **yeni** bir **logon session** **create** edebilirsiniz :
```
runas /user:domain\username cmd.exe
```
**access token** ayrıca **LSASS** içindeki logon oturumlarının bir **reference**’ına sahiptir; bu, süreç ağdaki bazı nesnelere erişmesi gerektiğinde faydalıdır.\
Ağ servislerine erişmek için **farklı credentials kullanan** bir süreç başlatabilirsiniz:
```
runas /user:domain\username /netonly cmd.exe
```
Ağdaki nesnelere erişmek için kullanışlı kimlik bilgilerin varsa ama bu kimlik bilgileri yalnızca ağda kullanılacakları için mevcut host içinde geçerli değilse bu faydalıdır (mevcut hostta mevcut kullanıcı ayrıcalıkların kullanılacaktır).

#### `runas /netonly` details

`runas /netonly` (ve `make_token` gibi C2 yardımcıları) bir **`LOGON32_LOGON_NEW_CREDENTIALS`** token oluşturur. Bu, lateral movement sırasında anlamak için çok faydalıdır çünkü:

- **Yerel olarak**, yeni süreç **aynı yerel kimliği**, grupları, integrity level'i ve mevcut token ile aynı erişim kararlarının çoğunu korur.
- **Uzaktan**, outbound authentication SMB / WinRM / LDAP / HTTP / Kerberos / NTLM için **sağlanan kimlik bilgilerini** kullanabilir.
- Bu nedenle `whoami`, ağ erişimi **alternatif hesap** olarak gerçekleşirken hâlâ **orijinal yerel kullanıcıyı** gösterebilir.

Bu, kimlik bilgileri domain içinde veya başka bir hostta geçerliyse ama kullanıcı mevcut makinede **yerel olarak oturum açamıyorsa veya açmamalıysa** harika bir seçenektir.

### Types of tokens

Kullanılabilir iki tür token vardır:

- **Primary Token**: Bir process'in güvenlik kimlik bilgilerinin temsili olarak görev yapar. Primary token'ların process'lerle oluşturulması ve ilişkilendirilmesi elevated privileges gerektiren işlemlerdir; bu da privilege separation ilkesini vurgular. Genellikle bir authentication service token oluşturmasından sorumluyken, bir logon service bunu kullanıcının operating system shell'i ile ilişkilendirir. Process'lerin oluşturulduklarında ebeveyn process'lerinin primary token'ını devraldığını belirtmek gerekir.
- **Impersonation Token**: Bir server application'a, secure object'lere erişmek için client'ın kimliğini geçici olarak benimseme gücü verir. Bu mekanizma dört çalışma seviyesine ayrılır:
- **Anonymous**: Server erişimini kimliği bilinmeyen bir user'a benzer şekilde sağlar.
- **Identification**: Server'ın client'ın kimliğini doğrulamasına izin verir, ancak bunu object access için kullanmaz.
- **Impersonation**: Server'ın client'ın kimliği altında çalışmasını sağlar.
- **Delegation**: Impersonation'a benzer, ancak server'ın etkileşimde bulunduğu remote systems'e de bu kimlik varsayımını genişletme yeteneğini içerir ve credential preservation sağlar.

#### Impersonate Tokens

Metasploit'in _**incognito**_ modülünü kullanarak yeterli ayrıcalığınız varsa diğer **tokens**'ları kolayca **listeleyebilir** ve **impersonate** edebilirsiniz. Bu, **başka kullanıcıymış gibi işlem yapmak** için faydalı olabilir. Bu technique ile **privilege escalation** da yapabilirsiniz.

Çalışırken unutulması kolay bazı pratik notlar:

- **`CreateProcessWithTokenW`**, çağıran tarafta **`SeImpersonatePrivilege`** gerektirir ve yeni process **çağıranın session'ında** çalışır.
- **`CreateProcessAsUserW`**, `CreateProcessWithTokenW` **`1314`** hatasıyla başarısız olduğunda veya token'ın referans verdiği **session** içinde başlatma gerektiğinde kullanılan tipik fallback'tir.
- Bir token **`LogonUser(LOGON32_LOGON_NETWORK)`**'ten geliyorsa, genellikle bir **impersonation token**'dır; bu yüzden onunla process başlatmaya çalışmadan önce **`DuplicateTokenEx(..., TokenPrimary, ...)`** gerekir.
- Her impersonation token eşit derecede faydalı değildir: **`SecurityIdentification`**, user'ı incelemenizi sağlar ama **onlar gibi davranmanızı** sağlamaz. Bir coercion primitive veya pipe/RPC client size yalnızca identification-level token veriyorsa, **`TokenImpersonationLevel`** değerini kontrol edin ve **`SecurityImpersonation`** veya daha iyisini veren bir primitive'e geçin.

#### Token theft without touching LSASS

Eğer zaten bir **service** veya **SYSTEM** bağlamınız varsa ve **privileged user** oturum açmış durumdaysa, o kullanıcının token'ını çalmak veya duplicate etmek çoğu zaman **LSASS** dump etmekten daha sessizdir. Birçok gerçek saldırıda bu, şunlar için yeterlidir:

- o kullanıcı olarak yerel işlemler çalıştırmak
- o kullanıcı olarak remote kaynaklara erişmek
- yeniden kullanılabilir kimlik bilgilerini çıkarmadan AD işlemleri yapmak

Yetkili bir bağlamdan **session/user token hijacking** örnekleri için [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md) sayfasına bakın. **`WTSQueryUserToken`** gibi API'lerin **yüksek derecede güvenilen service'ler** için tasarlandığını ve normalde **`LocalSystem` + `SeTcbPrivilege`** gerektirdiğini unutmayın; bu yüzden esas olarak zaten bir service-level bağlamı kontrol ettiğinizde kullanışlıdır. Önce **SYSTEM** elde etmenin ayrıcalığa özgü yolları için aşağıdaki sayfalara bakın.

### Token Privileges

Hangi **token privileges**'ların privilege escalation için kötüye kullanılabileceğini öğrenin:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**tüm olası token privileges ve bazı tanımlara bu external page üzerinden**](https://github.com/gtworek/Priv2Admin) bakın.

## References

- [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)
- [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
