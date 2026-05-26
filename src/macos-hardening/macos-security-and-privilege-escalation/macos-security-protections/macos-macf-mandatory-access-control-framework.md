# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF** açılımı **Mandatory Access Control Framework**’dür, işletim sistemine yerleşik, bilgisayarınızı korumaya yardımcı olan bir güvenlik sistemidir. **Sistemin belirli bölümlerine kimlerin veya nelerin erişebileceğine dair katı kurallar** belirleyerek çalışır; örneğin dosyalar, uygulamalar ve sistem kaynakları. Bu kuralları otomatik olarak uygulayarak MACF, yalnızca yetkili kullanıcıların ve süreçlerin belirli eylemleri gerçekleştirebilmesini sağlar ve yetkisiz erişim veya kötü amaçlı faaliyet riskini azaltır.

MACF aslında herhangi bir karar vermez; sadece eylemleri **intercepts** eder, kararları çağırdığı **policy modules** (kernel extensions) olan `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` ve `mcxalr.kext`'e bırakır.

- A policy may be enforcing (return 0 non-zero on some operation)
- A policy may be monitoring (return 0, so as not to object but piggyback on hook to do something)
- A MACF static policy is installed in boot and will NEVER be removed
- A MACF dynamic policy is installed by a KEXT (kextload) and may hypothetically be kextunloaded
- In iOS only static policies are allowed and in macOS static + dynamic.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flow

1. Process performs a syscall/mach trap
2. The relevant function is called inside the kernel
3. Function calls MACF
4. MACF checks policy modules that requested to hook that function in their policy
5. MACF calls the relevant policies
6. Policies indicates if they allow or deny the action

> [!CAUTION]
> Apple is the only one that can use the MAC Framework KPI.

Usually the functions checking permissions with MACF will call the macro `MAC_CHECK`. Like in the case of syscall to create a socket which will call the function which `mac_socket_check_create` which calls `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Moreover, the macro `MAC_CHECK` is defined in security/mac_internal.h as:
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
Note that transforming `check` into `socket_check_create` and `args...` into `(cred, domain, type, protocol)` yields:
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
Yardımcı makroları genişletmek, somut control flow’u gösterir:
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
Başka bir deyişle, `MAC_CHECK(socket_check_create, ...)` önce statik politikaları tarar, ardından dinamik politikaları koşullu olarak kilitleyip üzerinde yineleme yapar, her hook etrafında DTrace probe’larını üretir ve her hook’un dönüş kodunu `mac_error_select()` aracılığıyla tek bir `error` sonucuna indirger.


### Labels

MACF, daha sonra politikaların belirli bir erişimi verip vermemeleri gerektiğini kontrol etmek için kullanacağı **labels** kullanır. Labels struct bildirim kodu [burada](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h) bulunabilir; bu kod daha sonra [burada](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) **`struct ucred`** içinde **`cr_label`** kısmında kullanılır. Label, **MACF policies tarafından pointer allocate etmek için kullanılabilecek** bayraklar ve bir dizi **slot** içerir. Örneğin Sanbox container profile işaret eder

## MACF Policies

Bir MACF Policy, **belirli kernel operations üzerinde uygulanacak rule ve conditions** tanımlar.

Bir kernel extension, bir `mac_policy_conf` struct yapılandırabilir ve ardından `mac_policy_register` çağırarak kaydedebilir. [Buradan](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
`mac_policy_register` çağrılarını kontrol ederek bu politikaları yapılandıran kernel extension’larını kolayca tespit etmek mümkündür. Ayrıca extension’ın disassembly’sini kontrol ederek kullanılan `mac_policy_conf` struct’ını da bulmak mümkündür.

MACF policy’lerinin ayrıca **dinamik** olarak register ve unregister edilebileceğini unutmayın.

`mac_policy_conf`’un ana alanlarından biri **`mpc_ops`**’tur. Bu alan, policy’nin hangi operations ile ilgilendiğini belirtir. Yüzlercesi olduğunu unutmayın; bu yüzden hepsini zero edip ardından policy’nin ilgilendiği yalnızca ilgili olanları seçmek mümkündür. [Buradan](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Almost tüm hooks, bu operasyonlardan biri intercept edildiğinde MACF tarafından geri çağrılacaktır. Ancak, **`mpo_policy_*`** hooks bir istisnadır çünkü **`mpo_hook_policy_init()`** kayıt sırasında çağrılan bir callback’tir (yani `mac_policy_register()` sonrasında) ve **`mpo_hook_policy_initbsd()`** ise BSD subsystem düzgün şekilde initialised olduktan sonra geç kayıt sırasında çağrılır.

Ayrıca, **`mpo_policy_syscall`** hook’u herhangi bir kext tarafından private bir **ioctl** tarzı çağrı **interface**’i expose etmek için register edilebilir. Böylece, bir user client parametre olarak **policy name** ile birlikte integer bir **code** ve opsiyonel **arguments** belirterek `mac_syscall` (#381) çağırabilir.\
Örneğin, **`Sandbox.kext`** bunu sık sık kullanır.

Kext’in **`__DATA.__const*`** bölümünü kontrol etmek, policy kaydı sırasında kullanılan `mac_policy_ops` structure’ını belirlemeyi mümkün kılar. Bunu bulmak mümkündür çünkü pointer’ı `mpo_policy_conf` içinde bir offset’tedir ve ayrıca o alanda bulunacak NULL pointers sayısı da bunu ele verir.

Ayrıca, her register edilen policy ile güncellenen **`_mac_policy_list`** struct’ını memory’den dump ederek policy configure etmiş kext’lerin listesini almak da mümkündür.

Sistemde register edilmiş tüm policy’leri dump etmek için `xnoop` tool’unu da kullanabilirsiniz:
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
Ve ardından tüm check policy kontrollerini şununla dump et:
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

### Erken bootstrap ve `mac_policy_init()`

- MACF çok erken başlatılır. `bootstrap_thread` içinde (XNU startup code'da), `ipc_bootstrap` sonrasında XNU `mac_policy_init()` çağırır (`mac_base.c` içinde).
- `mac_policy_init()`, global `mac_policy_list`'i (policy slot'larının bir dizi ya da listesi) başlatır ve XNU içinde MAC (Mandatory Access Control) için altyapıyı kurar.
- Daha sonra `mac_policy_initmach()` çağrılır; bu, built-in veya bundled policy'ler için policy registration'ın kernel tarafını yönetir.

### `mac_policy_initmach()` ve “security extensions” yüklenmesi

- `mac_policy_initmach()`, önceden yüklenmiş olan kernel extensions (kexts)'ları (veya bir “policy injection” listesi içindekileri) inceler ve Info.plist dosyalarında `AppleSecurityExtension` anahtarını arar.
- Info.plist içinde `<key>AppleSecurityExtension</key>` (veya `true`) tanımlayan kext'ler “security extensions” olarak kabul edilir — yani bir MAC policy uygulayan veya MACF altyapısına hook olanlar.
- Bu anahtara sahip Apple kext örnekleri arasında **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** ve diğerleri bulunur (zaten listelediğin gibi).
- Kernel, bu kext'lerin erken yüklenmesini sağlar, ardından boot sırasında registration rutinlerini (`mac_policy_register` üzerinden) çağırır ve bunları `mac_policy_list` içine ekler.

- Her policy module (kext), çeşitli MAC operasyonları için hook'lar (`mpc_ops`) içeren bir `mac_policy_conf` yapısı sağlar (vnode check'leri, exec check'leri, label update'leri vb.).
- Load time flag'leri `MPC_LOADTIME_FLAG_NOTLATE` içerebilir; bu, “erken yüklenmeli” anlamına gelir (bu yüzden geç registration denemeleri reddedilir).
- Bir kez register edildikten sonra, her module bir handle alır ve `mac_policy_list` içinde bir slot işgal eder.
- Daha sonra bir MAC hook çağrıldığında (örneğin vnode access, exec vb.), MACF tüm kayıtlı policy'ler üzerinde dolaşarak toplu kararlar verir.

- Özellikle, **AMFI** (Apple Mobile File Integrity) böyle bir security extension'dır. Info.plist içinde `AppleSecurityExtension` bulunur ve bu onu bir security policy olarak işaretler.
- Kernel boot sırasında load logic, birçok subsystem buna bağlı hale gelmeden önce “security policy”nin (AMFI vb.) zaten aktif olmasını sağlar. Örneğin, kernel “AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy dahil security policy'yi yükleyerek ilerideki görevler için hazırlanır.”
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
## KPI dependency & com.apple.kpi.dsep in MAC policy kexts

MAC framework’ünü kullanan bir kext yazarken (yani `mac_policy_register()` vb. çağırırken), bu sembolleri kext linker (kxld) çözümleyebilsin diye KPI’lara (Kernel Programming Interfaces) bağımlılıkları belirtmeniz gerekir. Bu yüzden bir `kext`’in MACF’ye bağımlı olduğunu tanımlamak için bunu `Info.plist` içinde `com.apple.kpi.dsep` ile belirtmeniz gerekir (`find . Info.plist | grep AppleSecurityExtension`), ardından kext `mac_policy_register`, `mac_policy_unregister` ve MAC hook function pointers gibi sembollere referans verir. Bunları çözümlemek için `com.apple.kpi.dsep`’i bir dependency olarak listelemeniz gerekir.

Örnek `Info.plist` parçası (sizin `.kext` içinde):
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

Modern macOS'ta, Apple security politikaları genellikle gevşek, bağımsız `.kext` bundle'ları olarak ele alınmamalıdır. **macOS 11**'den beri, kernel extension'lar **kernel collections** içine bağlanır; **Apple Silicon** üzerinde ayrı bir **SystemKC** yoktur ve üçüncü taraf kext'ler ancak **Auxiliary Kernel Collection (AuxKC)** içine build edildikten ve bir reboot sonrası load edilebilir hale gelir. MACF research için bu, **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** veya **Quarantine** gibi built-in politikaların genellikle deprecated tooling olan `kextstat` yerine `kmutil` ile enumerate edilmesinin daha kolay olduğu anlamına gelir.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Apple Silicon’da, bir security kext BootKC içinde değilse, ardından AuxKC’ye bakın. Bu genellikle `/System/Library/Extensions` altında bağımsız bir bundle aramaktan daha faydalıdır.

## MACF Callouts

Code içinde MACF’ye yapılan callout’ları **`#if CONFIG_MAC`** conditional blocks şeklinde bulmak yaygındır. Ayrıca, bu block’ların içinde `mac_proc_check*` çağrılarını bulmak mümkündür; bunlar MACF’yi belirli actions’ları gerçekleştirmek için **permissions** kontrolü yapmak üzere çağırır. Bunun yanında, MACF callout formatı şöyledir: **`mac_<object>_<opType>_opName`**.

Object şu seçeneklerden biridir: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` genellikle action’ı allow veya deny etmek için kullanılacak check’tir. Ancak, kext’in verilen action’a tepki vermesini sağlayan `notify` de bulunabilir.

Bir örneği [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) içinde bulabilirsiniz:

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

Sonrasında, `mac_file_check_mmap` kodunu [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) içinde bulmak mümkündür
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
Hangi `MAC_CHECK` makrosunu çağırır; bunun kodu [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261) adresinde bulunabilir
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
Bu, kayıtlı tüm MAC policy’lerini dolaşıp fonksiyonlarını çağırır ve çıktıyı error değişkeninin içine kaydeder; bu değişken yalnızca `mac_error_select` tarafından başarı kodlarıyla üzerine yazılabilir, bu yüzden herhangi bir kontrol başarısız olursa tüm kontrol başarısız olur ve işlem izin verilmez.

> [!TIP]
> Ancak, tüm MACF callout’larının yalnızca işlemleri engellemek için kullanılmadığını unutmayın. Örneğin, `mac_priv_grant`, macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) çağırır; bu macro, herhangi bir policy 0 döndürürse istenen privilege’ı verecektir:
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
>    }); \
> } while (0)
> ```

### priv_check & priv_grant

Bu çağrılar, [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) içinde tanımlı (onlarca) **privilege**’ı kontrol etmek ve sağlamak için tasarlanmıştır.\
Bazı kernel kodları, sürecin KAuth kimlik bilgileri ve privilege kodlarından biri ile [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) içindeki `priv_check_cred()` fonksiyonunu çağırır; bu fonksiyon, herhangi bir policy’nin privilege vermeyi **reddedip** etmediğini görmek için `mac_priv_check` çağırır ve ardından herhangi bir policy’nin `privilege`’ı verip vermediğini görmek için `mac_priv_grant` çağırır.

### proc_check_syscall_unix

Bu hook tüm system call’ları intercept etmeye izin verir. `bsd/dev/[i386|arm]/systemcalls.c` içinde, şu kodu içeren tanımlı [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) fonksiyonunu görmek mümkündür:
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
Bu, çağıran süreçteki **bitmask** içinde mevcut syscall’ın `mac_proc_check_syscall_unix` çağırıp çağırmaması gerektiğini kontrol eder. Bunun nedeni, syscall’ların çok sık çağrılması ve bu yüzden her seferinde `mac_proc_check_syscall_unix` çağırmaktan kaçınmanın ilginç olmasıdır.

`proc_set_syscall_filter_mask()`, bir süreçte syscall bitmask’ini ayarlayan fonksiyondur; Sandbox tarafından sandboxed süreçlerde maskeleri ayarlamak için çağrılır.

## Exposed MACF syscalls

MACF ile [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) içinde tanımlanan bazı syscalls üzerinden etkileşim kurmak mümkündür:
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
Ofansif reversing için **`__mac_syscall`** hâlâ en iyi userland chokepoint’lerden biridir. Bir **policy name** taşır (örneğin `"Sandbox"` veya `"AMFI"`), bir **policy-specific selector/code** ve `mpo_policy_syscall` tarafından işlenecek **opaque argument blob** için bir pointer içerir. Bu, undocumented işlemleri önce userland’den tersine çevirirken ve daha sonra kernel implementation’a pivot ederken çok faydalıdır. Sandbox genellikle buna `__sandbox_ms` üzerinden ulaşır ve AMFI de dyld policy decisions için aynı mekanizmayı kullanır.

## Practical offensive research notes

Son macOS bug’ları nadiren doğrudan "MACF’i break eder". Bunun yerine, genellikle bir **MACF / Sandbox / TCC decision** ile daha sonra gerçekleşen ayrıcalıklı action arasındaki **desynchronisation**’ı abuse ederler.

### Broker path checks vs real privileged action

Tekrarlayan bir pattern, privileged daemon’ın bir path’in **userland pre-check**’ini (örneğin `sandbox_check_by_audit_token()`) bir sürümü üzerinde yapması ve daha sonra gerçek privileged sink’i **farklı veya non-canonical attacker-controlled path** ile çalıştırmasıdır. Son dönemdeki `diskarbitrationd` / `storagekitd` research bunun iyi bir örneğidir: **directory traversal** + **symlink swaps**, attacker’ın daemon’ın sandbox validation’ını geçmesine ve ardından `~/Library/Application Support/com.apple.TCC` gibi hassas konumların üzerine mount etmesine izin verir; bu da bug’ı seçilen mount point’e bağlı olarak bir **sandbox escape**, **local privilege escalation** veya **TCC bypass** haline getirir.

Sandbox’tan erişilebilen root broker’ları audit ederken önce şunlar için grep yapın:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- `mount`, `rename`, `copyfile`, helper-tool XPC methods gibi privileged sinks veya daha sonra attacker-controlled path’lere root olarak dokunan herhangi bir şey

### Trusted deputies with private entitlements

Bir diğer pratik pattern, MACF hooks’u doğrudan attack etmek yerine, sınırı geçmek için gereken haklara zaten sahip olan **trusted process**’i abuse etmektir. Son Safari/TCC research bunun iyi bir örneğidir: ilginç primitive "kernel’de TCC’yi disable etmek" değil, **`com.apple.private.tcc.allow`** sahibi Apple-signed bir process’in hassas action’ı sizin yerinize gerçekleştirmesi için local policy/configuration’ı değiştirmekti. Pratikte, yüksek değerli auditing hedefleri şu özellikleri birleştiren Apple daemon/app’leridir:

- **private entitlements** veya FDA benzeri erişim
- writable config / database / mount point / policy file
- sonrasında **Sandbox**, **AMFI**, **TCC** veya başka bir MACF policy tarafından aracı edilen hassas bir operation

Daha derin product-specific reversing için [macOS Sandbox](macos-sandbox/README.md) ve [macOS TCC](macos-tcc/README.md) sayfalarına bakın.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
