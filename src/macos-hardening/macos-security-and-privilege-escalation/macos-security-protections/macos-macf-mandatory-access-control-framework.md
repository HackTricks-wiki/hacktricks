# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

**MACF** açılımı **Mandatory Access Control Framework** olan, işletim sistemine entegre edilmiş ve bilgisayarınızı korumaya yardımcı olan bir güvenlik sistemidir. Sistemdeki dosyalar, uygulamalar ve sistem kaynakları gibi belirli bölümlere kimin veya hangi öğenin erişebileceği konusunda **katı kurallar** koyarak çalışır. Bu kuralları otomatik olarak uygulayarak, MACF yalnızca yetkili kullanıcıların ve süreçlerin belirli eylemleri gerçekleştirmesini sağlar ve yetkisiz erişim veya kötü amaçlı etkinlik riskini azaltır.

Dikkat edin ki MACF aslında kararlar almaz; sadece eylemleri **yakalar** ve kararları `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` ve `mcxalr.kext` gibi çağırdığı **policy modules** (kernel extensions) bırakır.

- Bir politika enforcing olabilir (bazı işlemlerde non-zero döndürerek işlemi engelleyebilir)
- Bir politika monitoring olabilir (0 döndürür, itiraz etmez ama hook üzerinden bir şeyler yapabilir)
- Bir MACF static policy önyüklemede kurulur ve ASLA kaldırılmaz
- Bir MACF dynamic policy bir KEXT (kextload) tarafından yüklenir ve teorik olarak kextunloaded olabilir
- iOS'ta yalnızca statik politikalar izinlidir, macOS'ta ise statik + dinamik
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Akış

1. Süreç bir syscall/mach trap gerçekleştirir
2. İlgili fonksiyon kernel içinde çağrılır
3. Fonksiyon MACF'i çağırır
4. MACF, politikasında o fonksiyona hook talep eden policy modules'leri kontrol eder
5. MACF ilgili politikaları çağırır
6. Politikalar eylemi izin verip vermediklerini belirtir

> [!CAUTION]
> MAC Framework KPI'yi kullanabilen tek taraf Apple'dır.

Genellikle MACF ile izinleri kontrol eden fonksiyonlar `MAC_CHECK` makrosunu çağırır. Örneğin socket oluşturmak için yapılan syscall durumunda çağrılan fonksiyon `mac_socket_check_create` olup bu fonksiyon `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` çağrısını yapar. Ayrıca `MAC_CHECK` makrosu security/mac_internal.h içinde şu şekilde tanımlanmıştır:
```c
Resolver tambien MAC_POLICY_ITERATE, MAC_CHECK_CALL, MAC_CHECK_RSLT


#define MAC_CHECK(check, args...) do {                                   \
error = 0;                                                           \
MAC_POLICY_ITERATE({                                                 \
if (mpc->mpc_ops->mpo_ ## check != NULL) {                   \
MAC_CHECK_CALL(check, mpc);                          \
int __step_err = mpc->mpc_ops->mpo_ ## check (args); \
MAC_CHECK_RSLT(check, mpc);                          \
error = mac_error_select(__step_err, error);         \
}                                                            \
});                                                                  \
} while (0)
```
`check`'i `socket_check_create` olarak dönüştürdüğünüzde ve `args...`'ı `(cred, domain, type, protocol)` ile değiştirdiğinizde elde edersiniz:
```c
// Note the "##" just get the param name and append it to the prefix
#define MAC_CHECK(socket_check_create, args...) do {                                   \
error = 0;                                                           \
MAC_POLICY_ITERATE({                                                 \
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {                   \
MAC_CHECK_CALL(socket_check_create, mpc);                          \
int __step_err = mpc->mpc_ops->mpo_socket_check_create (args); \
MAC_CHECK_RSLT(socket_check_create, mpc);                          \
error = mac_error_select(__step_err, error);         \
}                                                            \
});                                                                  \
} while (0)
```
Yardımcı makroların genişletilmesi somut kontrol akışını gösterir:
```c
do {                                                // MAC_CHECK
error = 0;
do {                                            // MAC_POLICY_ITERATE
struct mac_policy_conf *mpc;
u_int i;
for (i = 0; i < mac_policy_list.staticmax; i++) {
mpc = mac_policy_list.entries[i].mpc;
if (mpc == NULL) {
continue;
}
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {
DTRACE_MACF3(mac__call__socket_check_create,
void *, mpc, int, error, int, MAC_ITERATE_CHECK); // MAC_CHECK_CALL
int __step_err = mpc->mpc_ops->mpo_socket_check_create(args);
DTRACE_MACF2(mac__rslt__socket_check_create,
void *, mpc, int, __step_err);                    // MAC_CHECK_RSLT
error = mac_error_select(__step_err, error);
}
}
if (mac_policy_list_conditional_busy() != 0) {
for (; i <= mac_policy_list.maxindex; i++) {
mpc = mac_policy_list.entries[i].mpc;
if (mpc == NULL) {
continue;
}
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {
DTRACE_MACF3(mac__call__socket_check_create,
void *, mpc, int, error, int, MAC_ITERATE_CHECK);
int __step_err = mpc->mpc_ops->mpo_socket_check_create(args);
DTRACE_MACF2(mac__rslt__socket_check_create,
void *, mpc, int, __step_err);
error = mac_error_select(__step_err, error);
}
}
mac_policy_list_unbusy();
}
} while (0);
} while (0);
```
Diğer bir deyişle, `MAC_CHECK(socket_check_create, ...)` önce statik politikaları dolaşır, koşullu olarak kilitler ve dinamik politikalar üzerinde yineleme yapar, her hook etrafında DTrace probe'larını yayınlar ve her hook'un dönüş kodunu `mac_error_select()` ile tek bir `error` sonucunda birleştirir.


### Labels

MACF, erişim verilip verilmeyeceğini kontrol eden policy'lerin kullanacağı **labels** kullanır. Labels struct bildirimine ait kod [burada](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h) bulunabilir; bu yapı daha sonra **`struct ucred`** içinde [**burada**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) **`cr_label`** kısmında kullanılır. Label, flag'ler ve MACF policy'lerinin işaretçi ayırmak için kullanabileceği belli sayıda **slots** içerir. Örneğin Sandbox container profilini işaret eder

## MACF Policies

Bir MACF Policy, belirli kernel işlemlerinde uygulanacak **kurallar ve koşulları** tanımlar.

Bir kernel extension, bir `mac_policy_conf` struct yapılandırıp sonra `mac_policy_register` çağırarak kaydedebilir. Aşağıdakiler [buradan](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
```c
#define mpc_t	struct mac_policy_conf *

/**
@brief Mac policy configuration

This structure specifies the configuration information for a
MAC policy module.  A policy module developer must supply
a short unique policy name, a more descriptive full name, a list of label
namespaces and count, a pointer to the registered enty point operations,
any load time flags, and optionally, a pointer to a label slot identifier.

The Framework will update the runtime flags (mpc_runtime_flags) to
indicate that the module has been registered.

If the label slot identifier (mpc_field_off) is NULL, the Framework
will not provide label storage for the policy.  Otherwise, the
Framework will store the label location (slot) in this field.

The mpc_list field is used by the Framework and should not be
modified by policies.
*/
/* XXX - reorder these for better aligment on 64bit platforms */
struct mac_policy_conf {
const char		*mpc_name;		/** policy name */
const char		*mpc_fullname;		/** full name */
const char		**mpc_labelnames;	/** managed label namespaces */
unsigned int		 mpc_labelname_count;	/** number of managed label namespaces */
struct mac_policy_ops	*mpc_ops;		/** operation vector */
int			 mpc_loadtime_flags;	/** load time flags */
int			*mpc_field_off;		/** label slot */
int			 mpc_runtime_flags;	/** run time flags */
mpc_t			 mpc_list;		/** List reference */
void			*mpc_data;		/** module data */
};
```
Bu politikaları yapılandıran kernel uzantılarını `mac_policy_register` çağrılarını kontrol ederek tespit etmek kolaydır. Ayrıca, uzantının disassemblisini kontrol ederek kullanılan `mac_policy_conf` struct'ını bulmak da mümkündür.

MACF politikalarının ayrıca **dinamik olarak** kaydedilip kaldırılabileceğini unutmayın.

`mac_policy_conf`'un ana alanlarından biri **`mpc_ops`**'dir. Bu alan politikanın ilgilendiği işlemleri belirtir. Yüzlerce işlem olduğunu unutmayın; bu yüzden bunların tümünü sıfırlayıp sadece politikanın ilgi duyduğu işlemleri seçmek mümkündür. From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
```c
struct mac_policy_ops {
mpo_audit_check_postselect_t		*mpo_audit_check_postselect;
mpo_audit_check_preselect_t		*mpo_audit_check_preselect;
mpo_bpfdesc_label_associate_t		*mpo_bpfdesc_label_associate;
mpo_bpfdesc_label_destroy_t		*mpo_bpfdesc_label_destroy;
mpo_bpfdesc_label_init_t		*mpo_bpfdesc_label_init;
mpo_bpfdesc_check_receive_t		*mpo_bpfdesc_check_receive;
mpo_cred_check_label_update_execve_t	*mpo_cred_check_label_update_execve;
mpo_cred_check_label_update_t		*mpo_cred_check_label_update;
[...]
```
Neredeyse tüm hooks, bu işlemlerden biri yakalandığında MACF tarafından geri çağrılır. Ancak, **`mpo_policy_*`** hooks bir istisnadır çünkü `mpo_hook_policy_init()` kayıt sırasında (yani `mac_policy_register()`'dan sonra) çağrılan bir callback'tir ve `mpo_hook_policy_initbsd()` ise BSD subsystem düzgün şekilde başlatıldıktan sonra geç kayıt sırasında çağrılır.

Ayrıca, **`mpo_policy_syscall`** hook herhangi bir kext tarafından private bir **ioctl** style call **interface** açığa çıkarmak için kayıt edilebilir. Böylece, bir user client `mac_syscall` (#381) çağırarak parametre olarak **policy name** ile bir tam sayı **code** ve isteğe bağlı **arguments** belirtebilir.\\
Örneğin, **`Sandbox.kext`** bunu sıkça kullanır.

Kext'in **`__DATA.__const*`**'ını kontrol ederek, policy kaydedilirken kullanılan `mac_policy_ops` yapısını tespit etmek mümkündür. Onu bulmak mümkündür çünkü işaretçisi `mpo_policy_conf` içinde bir offset'te yer alır ve ayrıca o alandaki NULL işaretçi sayısı bunu belli eder.

Ayrıca, her kaydedilen policy ile güncellenen struct **`_mac_policy_list`**'i bellekten dump ederek policy yapılandırmış kext'lerin listesini elde etmek de mümkündür.

Sistemde kayıtlı tüm policy'leri dump etmek için `xnoop` aracını da kullanabilirsiniz:
```bash
xnoop offline .

Xn👀p> macp
mac_policy_list(@0xfffffff0447159b8): 3 Mac Policies@0xfffffff0447153f0
0: 0xfffffff044886f18:
mpc_name: AppleImage4
mpc_fullName: AppleImage4 hooks
mpc_ops: mac_policy_ops@0xfffffff044886f68
1: 0xfffffff0448d7d40:
mpc_name: AMFI
mpc_fullName: Apple Mobile File Integrity
mpc_ops: mac_policy_ops@0xfffffff0448d72c8
2: 0xfffffff044b0b950:
mpc_name: Sandbox
mpc_fullName: Seatbelt sandbox policy
mpc_ops: mac_policy_ops@0xfffffff044b0b9b0
Xn👀p> dump mac_policy_opns@0xfffffff0448d72c8
Type 'struct mac_policy_opns' is unrecognized - dumping as raw 64 bytes
Dumping 64 bytes from 0xfffffff0448d72c8
```
Ve ardından check policy'nin tüm kontrollerini şu komutla dök:
```bash
Xn👀p> dump mac_policy_ops@0xfffffff044b0b9b0
Dumping 2696 bytes from 0xfffffff044b0b9b0 (as struct mac_policy_ops)

mpo_cred_check_label_update_execve(@0x30): 0xfffffff046d7fb54(PACed)
mpo_cred_check_label_update(@0x38): 0xfffffff046d7348c(PACed)
mpo_cred_label_associate(@0x58): 0xfffffff046d733f0(PACed)
mpo_cred_label_destroy(@0x68): 0xfffffff046d733e4(PACed)
mpo_cred_label_update_execve(@0x90): 0xfffffff046d7fb60(PACed)
mpo_cred_label_update(@0x98): 0xfffffff046d73370(PACed)
mpo_file_check_fcntl(@0xe8): 0xfffffff046d73164(PACed)
mpo_file_check_lock(@0x110): 0xfffffff046d7309c(PACed)
mpo_file_check_mmap(@0x120): 0xfffffff046d72fc4(PACed)
mpo_file_check_set(@0x130): 0xfffffff046d72f2c(PACed)
mpo_reserved08(@0x168): 0xfffffff046d72e3c(PACed)
mpo_reserved09(@0x170): 0xfffffff046d72e34(PACed)
mpo_necp_check_open(@0x1f0): 0xfffffff046d72d9c(PACed)
mpo_necp_check_client_action(@0x1f8): 0xfffffff046d72cf8(PACed)
mpo_vnode_notify_setextattr(@0x218): 0xfffffff046d72ca4(PACed)
mpo_vnode_notify_setflags(@0x220): 0xfffffff046d72c84(PACed)
mpo_proc_check_get_task_special_port(@0x250): 0xfffffff046d72b98(PACed)
mpo_proc_check_set_task_special_port(@0x258): 0xfffffff046d72ab4(PACed)
mpo_vnode_notify_unlink(@0x268): 0xfffffff046d72958(PACed)
mpo_vnode_check_copyfile(@0x290): 0xfffffff046d726c0(PACed)
mpo_mount_check_quotactl(@0x298): 0xfffffff046d725c4(PACed)
...
```
## XNU'de MACF başlatılması

### Erken bootstrap ve mac_policy_init()

- MACF çok erken başlatılır. `bootstrap_thread` içinde (XNU başlangıç kodunda), `ipc_bootstrap`'tan sonra XNU `mac_policy_init()`'i (`mac_base.c` içinde) çağırır.
- `mac_policy_init()` global `mac_policy_list`'i (politika yuvalarının bir dizi veya listesi) başlatır ve XNU içinde MAC (Zorunlu Erişim Denetimi) altyapısını kurar.
- Daha sonra `mac_policy_initmach()` çağrılır; bu, gömülü veya paketlenmiş politikalar için çekirdek tarafındaki politika kayıt işlemlerini yönetir.

### `mac_policy_initmach()` ve “security extensions” yüklenmesi

- `mac_policy_initmach()` önceden yüklenmiş (veya bir “policy injection” listesinde olan) kernel uzantılarını (kext) inceler ve Info.plist'lerini `AppleSecurityExtension` anahtarı için kontrol eder.
- Info.plist'lerinde `<key>AppleSecurityExtension</key>` (veya `true`) bildiren kext'ler “security extensions” olarak kabul edilir — yani bir MAC politikası uygulayan veya MACF altyapısına bağlantı yapan uzantılardır.
- Bu anahtara sahip Apple kext örnekleri arasında **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, ve diğerleri bulunur (daha önce listelediğiniz gibi).
- Kernel, bu kext'lerin erken yüklenmesini sağlar, sonra boot sırasında kayıt rutinlerini (`mac_policy_register` aracılığıyla) çağırır ve onları `mac_policy_list` içine ekler.

- Her bir politika modülü (kext) çeşitli MAC işlemleri için kancalar (`mpc_ops`) içeren bir `mac_policy_conf` yapısı sağlar (vnode kontrolleri, exec kontrolleri, etiket güncellemeleri vb.).
- Yükleme zamanı bayrakları `MPC_LOADTIME_FLAG_NOTLATE` içerebilir; bu, “erken yüklenmelidir” anlamına gelir (dolayısıyla geç kayıt denemeleri reddedilir).
- Kayıt olduktan sonra, her modül bir handle alır ve `mac_policy_list` içinde bir yuva işgal eder.
- Daha sonra bir MAC kancası çağrıldığında (örneğin vnode erişimi, exec vb.), MACF toplu kararlar almak için tüm kayıtlı politikalar üzerinde iterasyon yapar.

- Özellikle, **AMFI** (Apple Mobile File Integrity) böyle bir security extension'dır. Info.plist'i `AppleSecurityExtension` içerir ve onu bir güvenlik politikası olarak işaretler.
- Kernel boot'unun bir parçası olarak, kernel yükleme mantığı birçok alt sistemin ona bağlı olmadan önce “security policy”nin (AMFI vb.) zaten aktif olmasını sağlar. Örneğin, kernel “ileri işler için ... güvenlik politikasını, AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine politikası dahil olmak üzere yükleyerek hazırlar.”
```bash
cd /System/Library/Extensions
find . -name Info.plist | xargs grep AppleSecurityExtension 2>/dev/null

./AppleImage4.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./ALF.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./CoreTrust.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./AppleMobileFileIntegrity.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./Quarantine.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./Sandbox.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./AppleSystemPolicy.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
```
## KPI bağımlılığı & com.apple.kpi.dsep MAC policy kext'lerinde

MAC framework'ünü kullanan bir kext yazarken (ör. `mac_policy_register()` gibi çağrılar yapıldığında), kext linker'ının (kxld) bu sembolleri çözebilmesi için KPIs (Kernel Programming Interfaces) üzerinde bağımlılıkları beyan etmeniz gerekir. Bu nedenle bir `kext`'in MACF'ye bağımlı olduğunu belirtmek için `Info.plist` içinde `com.apple.kpi.dsep`'i göstermeniz gerekir (`find . Info.plist | grep AppleSecurityExtension`), böylece kext `mac_policy_register`, `mac_policy_unregister` ve MAC hook fonksiyon işaretçileri gibi sembollere başvurur. Bunları çözebilmek için `com.apple.kpi.dsep`'i bağımlılıklar arasında listelemelisiniz.

Örnek Info.plist parçası (kext'iniz içinde):
```xml
<key>OSBundleLibraries</key>
<dict>
<key>com.apple.kpi.dsep</key>
<string>18.0</string>
<key>com.apple.kpi.libkern</key>
<string>18.0</string>
<key>com.apple.kpi.bsd</key>
<string>18.0</string>
<key>com.apple.kpi.mach</key>
<string>18.0</string>
… (other kpi dependencies as needed)
</dict>
```
## MACF Çağrıları

Koddaki **`#if CONFIG_MAC`** gibi koşullu bloklarda MACF çağrıları bulunması yaygındır. Ayrıca, bu blokların içinde belirli eylemleri gerçekleştirmek için izinleri **kontrol etmek** amacıyla MACF'yi çağıran `mac_proc_check*` çağrılarını bulmak mümkündür. Ayrıca, MACF çağrılarının formatı şudur: **`mac_<object>_<opType>_opName`**.

Nesne aşağıdakilerden biridir: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` genellikle eylemi kabul etmek veya reddetmek için kullanılan check'tir. Ancak, kext'in verilen eyleme tepki vermesine izin veren notify'yu da bulmak mümkündür.

Bir örneğini şurada bulabilirsiniz: [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

<pre class="language-c"><code class="lang-c">int
mmap(proc_t p, struct mmap_args *uap, user_addr_t *retval)
{
[...]
#if CONFIG_MACF
<strong>			error = mac_file_check_mmap(vfs_context_ucred(ctx),
</strong>			    fp->fp_glob, prot, flags, file_pos + pageoff,
&maxprot);
if (error) {
(void)vnode_put(vp);
goto bad;
}
#endif /* MAC */
[...]
</code></pre>

Daha sonra `mac_file_check_mmap`'in kodunu şu adreste bulabilirsiniz: [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
```c
mac_file_check_mmap(struct ucred *cred, struct fileglob *fg, int prot,
int flags, uint64_t offset, int *maxprot)
{
int error;
int maxp;

maxp = *maxprot;
MAC_CHECK(file_check_mmap, cred, fg, NULL, prot, flags, offset, &maxp);
if ((maxp | *maxprot) != *maxprot) {
panic("file_check_mmap increased max protections");
}
*maxprot = maxp;
return error;
}
```
Bu, `MAC_CHECK` makrosunu çağırıyor; kodu şu adreste bulunabilir: [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
```c
/*
* MAC_CHECK performs the designated check by walking the policy
* module list and checking with each as to how it feels about the
* request.  Note that it returns its value via 'error' in the scope
* of the caller.
*/
#define MAC_CHECK(check, args...) do {                              \
error = 0;                                                      \
MAC_POLICY_ITERATE({                                            \
if (mpc->mpc_ops->mpo_ ## check != NULL) {              \
DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_CHECK); \
int __step_err = mpc->mpc_ops->mpo_ ## check (args); \
DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_err); \
error = mac_error_select(__step_err, error);         \
}                                                           \
});                                                             \
} while (0)
```
Bu, kayıtlı tüm mac politikalarını dolaşıp onların fonksiyonlarını çağıracak ve çıktıyı `error` değişkenine depolayacak; bu değişken yalnızca başarı kodlarıyla `mac_error_select` tarafından geçersiz kılınabileceğinden, herhangi bir kontrol başarısız olursa tüm kontrol başarısız olur ve eyleme izin verilmez.

> [!TIP]
> Ancak, tüm MACF callout'larının yalnızca eylemleri reddetmek için kullanılmadığını unutmayın. Örneğin, `mac_priv_grant` makrosu [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) çağırır; eğer herhangi bir policy 0 ile cevap verirse istenen ayrıcalığı verir:
>
> ```c
> /*
> * MAC_GRANT performs the designated check by walking the policy
> * module list and checking with each as to how it feels about the
> * request.  Unlike MAC_CHECK, it grants if any policies return '0',
> * and otherwise returns EPERM.  Note that it returns its value via
> * 'error' in the scope of the caller.
> */
> #define MAC_GRANT(check, args...) do {                              \
>    error = EPERM;                                                  \
>    MAC_POLICY_ITERATE({                                            \
> 	if (mpc->mpc_ops->mpo_ ## check != NULL) {                  \
> 	        DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_GRANT); \
> 	        int __step_res = mpc->mpc_ops->mpo_ ## check (args); \
> 	        if (__step_res == 0) {                              \
> 	                error = 0;                                  \
> 	        }                                                   \
> 	        DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_res); \
> 	    }                                                           \
>    });                                                             \
> } while (0)
> ```

### priv_check & priv_grant

These callas are meant to check and provide (tens of) **privileges** defined in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Bazı kernel kodu, işlemin KAuth kimlik bilgileri ve ayrıcalık kodlarından biri ile [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) içindeki `priv_check_cred()`'i çağırır; bu, `mac_priv_check`'i çağırarak herhangi bir politikanın ayrıcalık vermeyi **reddettiğini** kontrol eder ve sonra herhangi bir politikanın `privilege`'ı verdiğini görmek için `mac_priv_grant`'ı çağırır.

### proc_check_syscall_unix

This hook allows to intercept all system calls. In `bsd/dev/[i386|arm]/systemcalls.c` it's possible to see the declared function [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), which contains this code:
```c
#if CONFIG_MACF
if (__improbable(proc_syscall_filter_mask(proc) != NULL && !bitstr_test(proc_syscall_filter_mask(proc), syscode))) {
error = mac_proc_check_syscall_unix(proc, syscode);
if (error) {
goto skip_syscall;
}
}
#endif /* CONFIG_MACF */
```
Bu, çağıran işlemdeki **bitmask** içinde mevcut syscall'un `mac_proc_check_syscall_unix`'i çağırıp çağırmaması gerektiğini kontrol eder. Bunun nedeni, syscalls'ın o kadar sık çağrılmasıdır ki her seferinde `mac_proc_check_syscall_unix`'i çağırmaktan kaçınmanın mantıklı olmasıdır.

`proc_set_syscall_filter_mask()` fonksiyonunun, bir işlemde syscall bitmask'lerini ayarlayan ve Sandbox tarafından sandboxed process'lara maskeleri ayarlamak için çağrılan bir fonksiyon olduğunu unutmayın.

## Erişime Açık MACF syscalls

MACF ile [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) dosyasında tanımlanmış bazı syscalls aracılığıyla etkileşim kurulabilir:
```c
/*
* Extended non-POSIX.1e interfaces that offer additional services
* available from the userland and kernel MAC frameworks.
*/
#ifdef __APPLE_API_PRIVATE
__BEGIN_DECLS
int      __mac_execve(char *fname, char **argv, char **envv, mac_t _label);
int      __mac_get_fd(int _fd, mac_t _label);
int      __mac_get_file(const char *_path, mac_t _label);
int      __mac_get_link(const char *_path, mac_t _label);
int      __mac_get_pid(pid_t _pid, mac_t _label);
int      __mac_get_proc(mac_t _label);
int      __mac_set_fd(int _fildes, const mac_t _label);
int      __mac_set_file(const char *_path, mac_t _label);
int      __mac_set_link(const char *_path, mac_t _label);
int      __mac_mount(const char *type, const char *path, int flags, void *data,
struct mac *label);
int      __mac_get_mount(const char *path, struct mac *label);
int      __mac_set_proc(const mac_t _label);
int      __mac_syscall(const char *_policyname, int _call, void *_arg);
__END_DECLS
#endif /*__APPLE_API_PRIVATE*/
```
## Referanslar

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}
