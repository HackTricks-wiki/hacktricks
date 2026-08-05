# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

**MACF**, **Mandatory Access Control Framework** (Zorunlu Erişim Kontrolü Framework'ü) anlamına gelir ve bilgisayarınızı korumaya yardımcı olmak için işletim sistemine yerleşik olarak bulunan bir güvenlik sistemidir. Dosyalar, uygulamalar ve sistem kaynakları gibi sistemin belirli bölümlerine kimlerin veya nelerin erişebileceği konusunda **katı kurallar belirleyerek** çalışır. Bu kuralları otomatik olarak uygulayan MACF, yalnızca yetkili kullanıcıların ve süreçlerin belirli işlemleri gerçekleştirebilmesini sağlayarak yetkisiz erişim veya kötü amaçlı etkinlik riskini azaltır.

MACF'nin aslında herhangi bir karar vermediğini unutmayın; yalnızca eylemleri **intercept** eder ve kararları `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` ve `mcxalr.kext` gibi çağırdığı **policy modules**'a (kernel extensions) bırakır.

- Bir policy enforcing olabilir (bazı işlemlerde 0 olmayan bir değer döndürür)
- Bir policy monitoring olabilir (itiraz etmemek, ancak hook'u kullanarak başka bir işlem gerçekleştirmek için 0 döndürür)
- Bir MACF static policy boot sırasında yüklenir ve ASLA kaldırılmaz
- Bir MACF dynamic policy bir KEXT (`kextload`) tarafından yüklenir ve teorik olarak `kextunload` ile kaldırılabilir
- iOS'ta yalnızca static policy'lere izin verilir; macOS'ta ise static + dynamic policy'lere izin verilir.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Akış

1. Process bir syscall/mach trap gerçekleştirir
2. Kernel içinde ilgili function çağrılır
3. Function MACF'yi çağırır
4. MACF, policy'lerinde bu function'a hook eklenmesini isteyen policy module'larını kontrol eder
5. MACF, ilgili policy'leri çağırır
6. Policy'ler eyleme izin verip vermediklerini belirtir

> [!CAUTION]
> MAC Framework KPI'ı yalnızca Apple kullanabilir.

Genellikle MACF ile izinleri kontrol eden function'lar `MAC_CHECK` macro'sunu çağırır. Örneğin socket oluşturmak için kullanılan syscall, `mac_socket_check_create` function'ını çağırır; bu function da `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` çağrısını yapar. Ayrıca `MAC_CHECK` macro'su security/mac_internal.h içinde şu şekilde tanımlanmıştır:<sup>[3]</sup>
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
`check` ifadesini `socket_check_create` ve `args...` ifadesini `(cred, domain, type, protocol)` olarak dönüştürdüğünüzde şunu elde edersiniz:
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
Yardımcı makrolar genişletildiğinde somut kontrol akışı ortaya çıkar:
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
Başka bir deyişle, `MAC_CHECK(socket_check_create, ...)` önce statik policy'leri işler, ardından koşullu olarak kilit alır ve dinamik policy'ler üzerinde yineleme yapar, her hook'un çevresinde DTrace probe'larını oluşturur ve her hook'un dönüş kodunu `mac_error_select()` aracılığıyla tek bir `error` sonucunda birleştirir.


### Etiketler

MACF, policy'lerin belirli bir erişime izin verip vermemeleri gerektiğini kontrol ederken kullanacağı **etiketleri** kullanır. Label struct bildirim kodu [burada](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h) bulunabilir; bu struct daha sonra **`struct ucred`** içinde [burada](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86), **`cr_label`** bölümünde kullanılır. Label, MACF policy'lerinin pointer ayırmak için kullanabileceği flag'leri ve belirli sayıda **slot** içerir. Örneğin Sanbox, container profile'ına işaret eder.

## MACF Policies

Bir MACF Policy, belirli kernel işlemlerinde uygulanacak **kuralları ve koşulları** tanımlar.

Bir kernel extension, bir `mac_policy_conf` struct'ını yapılandırabilir ve ardından `mac_policy_register` çağrısı yaparak kaydedebilir. [Buradan](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[1]</sup>
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
Bu politikaları yapılandıran kernel extension'ları, `mac_policy_register` çağrılarını kontrol ederek kolayca belirlemek mümkündür. Ayrıca extension'ın disassembly'sini inceleyerek kullanılan `mac_policy_conf` struct'ını bulmak da mümkündür.

MACF politikalarının **dinamik olarak** kaydedilip kaldırılabileceğini unutmayın.

`mac_policy_conf`'un ana alanlarından biri **`mpc_ops`**'tur. Bu alan, politikanın ilgilendiği operasyonları belirtir. Bunlardan yüzlercesi olduğunu unutmayın; bu nedenle hepsini sıfırlayıp yalnızca politikanın ilgilendiği operasyonları seçmek mümkündür. [Buradan](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[1]</sup>
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
Neredeyse tüm hook'lar, bu işlemlerden biri intercept edildiğinde MACF tarafından çağrılır. Ancak **`mpo_policy_*`** hook'ları bir istisnadır; çünkü **`mpo_hook_policy_init()`**, registration sırasında (yani `mac_policy_register()` sonrasında) çağrılan bir callback'tir ve **`mpo_hook_policy_initbsd()`**, BSD subsystem'i düzgün şekilde initialize olduktan sonra late registration sırasında çağrılır.

Ayrıca **`mpo_policy_syscall`** hook'ı, herhangi bir kext tarafından private **ioctl** tarzı bir çağrı **arayüzü** sunmak için register edilebilir. Böylece bir user client, parametre olarak **policy name**, integer **code** ve isteğe bağlı **arguments** belirterek `mac_syscall` (#381) çağırabilir.\
Örneğin **`Sandbox.kext`** bunu sıkça kullanır.

Kext'in **`__DATA.__const*`** bölümünü inceleyerek policy register edilirken kullanılan `mac_policy_ops` yapısını belirlemek mümkündür. Bu yapı, pointer'ı `mpo_policy_conf` içinde bir offset'te bulunduğu ve ayrıca bu alanda bulunacak NULL pointer'ların miktarı sayesinde bulunabilir.

Ayrıca, bir policy yapılandırmış kext'lerin listesini, register edilen her policy ile güncellenen **`_mac_policy_list`** struct'ını memory'den dump ederek elde etmek de mümkündür.

Sistemde register edilmiş tüm policy'leri dump etmek için `xnoop` aracını da kullanabilirsiniz:
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
Ardından check policy kapsamındaki tüm kontrolleri şu komutla dökün:
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
## XNU'da MACF başlatılması

### Erken bootstrap ve mac_policy_init()

- MACF çok erken başlatılır. XNU, `bootstrap_thread` içinde (XNU startup kodunda), `ipc_bootstrap` sonrasında `mac_policy_init()` işlevini ( `mac_base.c` içinde) çağırır.
- `mac_policy_init()`, global `mac_policy_list` listesini (policy slot'larının bir array'i veya listesi) başlatır ve XNU içindeki MAC (Mandatory Access Control) altyapısını kurar.
- Daha sonra, yerleşik veya paketlenmiş policy'lerin kernel tarafındaki kayıt işlemlerini yöneten `mac_policy_initmach()` çağrılır.

### `mac_policy_initmach()` ve “security extensions” yüklenmesi

- `mac_policy_initmach()`, önceden yüklenmiş (veya “policy injection” listesinde bulunan) kernel extension'larını (kext) inceler ve bunların Info.plist dosyalarında `AppleSecurityExtension` anahtarını arar.
- Info.plist dosyalarında `<key>AppleSecurityExtension</key>` (veya `true`) tanımlayan kext'ler, MAC policy uygulayan ya da MACF altyapısına hook sağlayan “security extensions” olarak kabul edilir.
- Bu anahtara sahip Apple kext'lerine **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** ve diğerleri örnek olarak verilebilir.
- Kernel, bu kext'lerin erken yüklenmesini sağlar ve ardından boot sırasında kayıt rutinlerini (`mac_policy_register` aracılığıyla) çağırarak kext'leri `mac_policy_list` içine ekler.

- Her policy modülü (kext), çeşitli MAC işlemleri için hook'lar (`mpc_ops`) içeren bir `mac_policy_conf` yapısı sağlar (vnode kontrolleri, exec kontrolleri, label güncellemeleri vb.).
- Yükleme zamanı flag'leri, “erken yüklenmeli” anlamına gelen `MPC_LOADTIME_FLAG_NOTLATE` değerini içerebilir (bu nedenle geç kayıt girişimleri reddedilir).
- Kayıt tamamlandıktan sonra her modül bir handle alır ve `mac_policy_list` içinde bir slot kaplar.
- Daha sonra bir MAC hook çağrıldığında (örneğin vnode erişimi, exec vb.), MACF ortak kararlar almak için kayıtlı tüm policy'leri iterate eder.

- Özellikle **AMFI** (Apple Mobile File Integrity) böyle bir security extension'dır. Info.plist dosyasında, onu bir security policy olarak işaretleyen `AppleSecurityExtension` bulunur.
- Kernel boot sürecinin bir parçası olarak kernel yükleme mantığı, birçok subsystem'in ona ihtiyaç duymasından önce “security policy”nin (AMFI vb.) zaten aktif olmasını sağlar. Örneğin kernel, “AppleMobileFileIntegrity (AMFI), Sandbox ve Quarantine policy dahil olmak üzere … security policy'yi yükleyerek ilerideki task'ler için hazırlık yapar.”
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
## MAC policy kext'lerinde KPI dependency ve com.apple.kpi.dsep

MAC framework kullanan (yani `mac_policy_register()` vb. çağrılar yapan) bir kext yazarken, kext linker'ın (kxld) bu sembolleri çözümleyebilmesi için KPI'lara (Kernel Programming Interfaces) yönelik dependency'leri tanımlamanız gerekir. Dolayısıyla bir `kext`'in MACF'e dependency'si olduğunu belirtmek için bunu `Info.plist` içinde `com.apple.kpi.dsep` ile belirtmeniz gerekir (`find . Info.plist | grep AppleSecurityExtension`). Ardından kext; `mac_policy_register`, `mac_policy_unregister` gibi sembollere ve MAC hook function pointer'larına başvurur. Bunları çözümlemek için `com.apple.kpi.dsep`'i dependency olarak listelemelisiniz.

Example Info.plist snippet (inside your .kext):
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
## Modern macOS sürümlerinde MACF

Modern macOS'ta Apple güvenlik politikalarına genellikle gevşek, bağımsız `.kext` bundle'ları olarak yaklaşmak en iyi yöntem değildir. **macOS 11**'den beri kernel extension'lar **kernel collections** içine bağlanır; **Apple Silicon** üzerinde ayrı bir **SystemKC** bulunmaz ve üçüncü taraf kext'ler yalnızca **Auxiliary Kernel Collection (AuxKC)** içine build edildikten ve yeniden başlatma gerçekleştirildikten sonra yüklenebilir. MACF araştırmaları açısından bu, **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** veya **Quarantine** gibi yerleşik politikaların, `kextstat` gibi kullanımdan kaldırılmış araçlar yerine genellikle `kmutil` ile daha kolay enumerate edilebileceği anlamına gelir.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Apple Silicon üzerinde bir security kext BootKC içinde değilse, önce AuxKC'yi kontrol edin. Bu, `/System/Library/Extensions` altında bağımsız bir bundle aramaktan genellikle daha kullanışlıdır.

## MACF Callouts

Şu tür kodlarda MACF'ye yapılan callout'lara sıkça rastlanır: **`#if CONFIG_MAC`** koşullu blokları. Ayrıca bu blokların içinde, belirli eylemleri gerçekleştirmek için **izinleri kontrol etmek** üzere MACF'yi çağıran `mac_proc_check*` çağrılarını bulmak mümkündür. MACF callout'larının biçimi şöyledir: **`mac_<object>_<opType>_opName`**.

Object aşağıdakilerden biridir: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` genellikle eyleme izin vermek veya eylemi reddetmek için kullanılan `check` değeridir. Ancak kext'in verilen eyleme tepki vermesini sağlayan `notify` değerine de rastlamak mümkündür.

[https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) adresinde bir örnek bulabilirsiniz:

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

Ardından `mac_file_check_mmap` kodunu [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) adresinde bulmak mümkündür.
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
Bu, kodu [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[3]</sup> adresinde bulunabilen `MAC_CHECK` macro'sunu çağırır.
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
Bu işlem, kayıtlı tüm mac policy'leri dolaşarak işlevlerini çağırır ve çıktıyı `error` değişkeninde saklar. Bu değişken yalnızca başarı kodlarıyla `mac_error_select` tarafından geçersiz kılınabilir; dolayısıyla herhangi bir kontrol başarısız olursa tamamı başarısız olur ve işlem gerçekleştirilmez.

> [!TIP]
> Ancak tüm MACF callout'larının yalnızca işlemleri reddetmek için kullanılmadığını unutmayın. Örneğin `mac_priv_grant`, [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) macro'sunu çağırır. Bu macro, herhangi bir policy 0 yanıtı verirse istenen privilege'ı verir:
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

Bu çağrılar, [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) içinde tanımlanan onlarca **privilege**'ı kontrol etmek ve sağlamak için kullanılır.\
Bazı kernel kodları, prosesin KAuth kimlik bilgileriyle ve privilege kodlarından biriyle [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) içindeki `priv_check_cred()` işlevini çağırır. Bu işlev, herhangi bir policy'nin privilege verilmesini **reddedip reddetmediğini** görmek için `mac_priv_check` işlevini çağırır; ardından herhangi bir policy'nin `privilege` verdiğini görmek için `mac_priv_grant` işlevini çağırır.<sup>[4]</sup>

### proc_check_syscall_unix

Bu hook, tüm system call'ların yakalanmasını sağlar. `bsd/dev/[i386|arm]/systemcalls.c` içinde, aşağıdaki kodu içeren [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) işlevinin tanımlandığı görülebilir:
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
Bu, mevcut syscall'in `mac_proc_check_syscall_unix` çağırıp çağırmaması gerektiğini çağrıyı yapan process içindeki **bitmask** üzerinden kontrol eder. Bunun nedeni, syscall'lerin çok sık çağrılması ve her seferinde `mac_proc_check_syscall_unix` çağrılmasından kaçınmanın önemli olmasıdır.

Bir process içindeki syscall bitmask'lerini ayarlayan `proc_set_syscall_filter_mask()` fonksiyonunun, sandbox uygulanmış process'ler üzerinde maskeleri ayarlamak için Sandbox tarafından çağrıldığını unutmayın.

## Exposed MACF syscalls

[security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) içinde tanımlanan bazı syscall'ler aracılığıyla MACF ile etkileşim kurmak mümkündür:
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
Offensive reversing için **`__mac_syscall`** hâlâ en iyi userland chokepoint'lerden biridir. Bir **policy name** (örneğin `"Sandbox"` veya `"AMFI"`), **policy-specific selector/code** ve `mpo_policy_syscall` tarafından işlenecek **opaque argument blob** işaretçisi taşır. Bu, userland'den başlayarak belgelenmemiş işlemleri reverse etmek ve yalnızca daha sonra kernel implementasyonuna geçmek için oldukça kullanışlıdır. Sandbox buna genellikle `__sandbox_ms` üzerinden ulaşır; AMFI ise dyld policy kararları için aynı mekanizmayı kullanır.<sup>[2][5]</sup>

## Pratik offensive research notları

Güncel macOS bug'ları nadiren doğrudan "MACF'i bozar". Bunun yerine genellikle bir MACF / Sandbox / TCC kararı ile daha sonra gerçekleşen privileged action arasındaki **desynchronisation** kötüye kullanılır.

### Broker path checks ve gerçek privileged action

Yaygın bir pattern, privileged bir daemon'ın bir path sürümü üzerinde **userland pre-check** (örneğin `sandbox_check_by_audit_token()`) gerçekleştirmesi ve daha sonra gerçek privileged sink'i **farklı veya canonical olmayan, attacker-controlled bir path** ile çalıştırmasıdır. Güncel `diskarbitrationd` / `storagekitd` research bunun iyi bir örneğidir: **directory traversal** ve **symlink swaps**, attacker'ın daemon'ın sandbox validation'ından geçmesini ve ardından `~/Library/Application Support/com.apple.TCC` gibi hassas konumların üzerine mount etmesini sağlar; böylece bug, seçilen mount point'e bağlı olarak bir **sandbox escape**, **local privilege escalation** veya **TCC bypass**'a dönüşür.<sup>[6]</sup>

Sandbox'dan erişilebilen root broker'ları audit ederken önce şunlar için grep yapın:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helper'ları
- `mount`, `rename`, `copyfile`, helper-tool XPC method'ları gibi privileged sink'ler veya daha sonra attacker-controlled path'lere root olarak dokunan herhangi bir şey

### Private entitlement'lara sahip trusted deputies

Bir diğer pratik pattern, MACF hook'larına doğrudan saldırmak yerine boundary'yi aşmak için gereken haklara zaten sahip olan bir **trusted process**'i kötüye kullanmaktır. Güncel Safari/TCC research bunun iyi bir örneğidir: İlginç primitive "kernel'de TCC'yi disable etmek" değil, **`com.apple.private.tcc.allow`** taşıyan Apple-signed bir process'in hassas action'ı sizin adınıza gerçekleştirmesini sağlayacak şekilde local policy/configuration'ı değiştirmekti. Pratikte yüksek değerli audit hedefleri şunları birleştiren Apple daemon/app'leridir:

- **private entitlements** veya FDA-like reach
- yazılabilir bir config / database / mount point / policy file
- daha sonra **Sandbox**, **AMFI**, **TCC** veya başka bir MACF policy tarafından mediated edilen hassas bir operation

Daha derin product-specific reversing için [macOS Sandbox](macos-sandbox/README.md) ve [macOS TCC](macos-tcc/README.md) üzerindeki özel sayfalara bakın.

## References

- [1] [XNU — `security/mac_policy.h` (tam MACF policy operations vector'ı)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (`MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE` macro'ları)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (`priv_check`/`priv_grant` tarafından kullanılan privilege code'ları)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Apple Vulnerabilities'larını Uncover Etmek: diskarbitrationd ve storagekitd Audit Part 2](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
