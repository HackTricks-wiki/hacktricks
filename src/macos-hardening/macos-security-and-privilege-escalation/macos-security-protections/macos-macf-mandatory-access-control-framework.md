# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF**, **Mandatory Access Control Framework** anlamına gelir; işletim sistemine yerleşik, bilgisayarınızı korumaya yardımcı olan bir güvenlik sistemidir. **Sistemin belirli bölümlerine, örneğin dosyalara, uygulamalara ve sistem kaynaklarına kimlerin veya nelerin erişebileceği hakkında katı kurallar** belirleyerek çalışır. Bu kuralları otomatik olarak uygulayarak, MACF yalnızca yetkili kullanıcıların ve süreçlerin belirli eylemleri gerçekleştirebilmesini sağlar ve yetkisiz erişim veya kötü amaçlı faaliyet riskini azaltır.

MACF'nin aslında bir karar vermediğini, sadece eylemleri **araya girip yakaladığını** unutmayın; kararları çağırdığı **policy modules** (kernel extensions) verir; örneğin `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` ve `mcxalr.kext`.

- Bir policy uygulayıcı olabilir (bazı işlemlerde 0 dışı döndürür)
- Bir policy izleyici olabilir (0 döndürür, böylece itiraz etmez ama hook üzerinden bir şey yapmak için faydalanır)
- Bir MACF static policy boot sırasında yüklenir ve ASLA kaldırılmaz
- Bir MACF dynamic policy bir KEXT (kextload) tarafından yüklenir ve teorik olarak kextunloaded yapılabilir
- iOS'ta yalnızca static policies, macOS'ta ise static + dynamic policies izinlidir.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flow

1. Process bir syscall/mach trap gerçekleştirir
2. İlgili function kernel içinde çağrılır
3. Function MACF çağırır
4. MACF, policy'sinde o function'ı hook etmek isteyen policy modules'ları kontrol eder
5. MACF ilgili policies'leri çağırır
6. Policies işlemin izin verilip verilmeyeceğini belirtir

> [!CAUTION]
> Apple, MAC Framework KPI'ını kullanabilen tek taraftır.

Genellikle MACF ile izinleri kontrol eden functions, `MAC_CHECK` macro'sunu çağırır. Bir socket oluşturmak için yapılan syscall örneğinde olduğu gibi; bu, `mac_socket_check_create` function'ını çağırır ve o da `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` çağrısını yapar. Ayrıca, `MAC_CHECK` macro'su security/mac_internal.h içinde şu şekilde tanımlanır:
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
Not edin ki, `check` ifadesini `socket_check_create` ve `(cred, domain, type, protocol)` içindeki `args...` ile dönüştürdüğünüzde şunu elde edersiniz:
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
Yardımcı makroları genişletmek, somut kontrol akışını gösterir:
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
Başka bir deyişle, `MAC_CHECK(socket_check_create, ...)` önce statik policy'leri dolaşır, ardından koşullu olarak dynamic policy'leri kilitleyip üzerinde iterasyon yapar, her hook etrafında DTrace probe'larını çalıştırır ve her hook'un dönüş kodunu `mac_error_select()` aracılığıyla tek bir `error` sonucunda birleştirir.


### Labels

MACF, policy'lerin belirli bir erişim verilip verilmeyeceğini kontrol ederken kullanacağı **labels** kullanır. Labels struct bildirimine ait kod [burada](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h) bulunabilir; bu kod daha sonra **`struct ucred`** içinde, **`cr_label`** kısmında [burada](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) kullanılır. Label, flags ve **slots** sayısını içerir; bu slots, **MACF policies tarafından pointer allocate etmek** için kullanılabilir. Örneğin Sanbox container profile'a işaret eder

## MACF Policies

Bir MACF Policy, belirli kernel operations üzerinde uygulanacak **rule ve conditions**'ı tanımlar.

Bir kernel extension, `mac_policy_conf` struct'ı yapılandırıp ardından `mac_policy_register` çağırarak kaydedebilir. [Buradan](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
`mac_policy_register` çağrılarını kontrol ederek bu politikaları yapılandıran kernel extension’larını kolayca tespit etmek mümkündür. Ayrıca, extension’ın disassemble edilmiş halini inceleyerek kullanılan `mac_policy_conf` struct’ını da bulmak mümkündür.

MACF policy’lerinin ayrıca **dinamik** olarak da register ve unregister edilebileceğini unutmayın.

`mac_policy_conf`’un temel alanlarından biri **`mpc_ops`**’dur. Bu alan, policy’nin hangi operations ile ilgilendiğini belirtir. Yüzlercesi olduğu için, hepsini sıfırlayıp ardından yalnızca policy’nin ilgilendiği olanları seçmek mümkündür. [buradan](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Neredeyse tüm hook’lar, bu işlemlerden biri intercept edildiğinde MACF tarafından geri çağrılacaktır. Ancak, **`mpo_policy_*`** hook’ları bir istisnadır çünkü **`mpo_hook_policy_init()`** kayıt sırasında çağrılan bir callback’tir (yani **`mac_policy_register()`** sonrasında) ve **`mpo_hook_policy_initbsd()`** BSD subsystem düzgün şekilde initialised olduktan sonra geç kayıt sırasında çağrılır.

Ayrıca, **`mpo_policy_syscall`** hook’u herhangi bir kext tarafından özel bir **ioctl** tarzı çağrı **interface**’i expose etmek için register edilebilir. Ardından bir user client, parametre olarak integer bir **code** ve opsiyonel **arguments** ile birlikte **policy name** belirterek `mac_syscall` (#381) çağrısı yapabilir.\
Örneğin, **`Sandbox.kext`** bunu sıkça kullanır.

Kext’in **`__DATA.__const*`** bölümünü kontrol etmek, policy register edilirken kullanılan `mac_policy_ops` yapısını identify etmeyi mümkün kılar. Bunu bulmak mümkündür çünkü pointer’ı `mpo_policy_conf` içinde bir offset’tedir ve ayrıca orada bulunacak NULL pointer’ların sayısı da bunu ele verir.

Ayrıca, her register edilen policy ile güncellenen struct **`_mac_policy_list`**’i memory’den dump ederek policy configure etmiş kext’lerin listesini almak da mümkündür.

Sistemde register edilmiş tüm policy’leri dump etmek için `xnoop` aracını da kullanabilirsiniz:
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
Ve ardından check policy'nin tüm kontrollerini şu şekilde dump et:
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

- MACF çok erken başlatılır. `bootstrap_thread` içinde (XNU startup kodunda), `ipc_bootstrap` sonrasında XNU `mac_policy_init()` çağırır (`mac_base.c` içinde).
- `mac_policy_init()`, global `mac_policy_list`'i (policy slot'larının bir array'i veya listesi) başlatır ve XNU içinde MAC (Mandatory Access Control) altyapısını kurar.
- Daha sonra `mac_policy_initmach()` çağrılır; bu, built-in veya bundled policy'ler için policy registration'ın kernel tarafını yönetir.

### `mac_policy_initmach()` ve “security extensions” yükleme

- `mac_policy_initmach()`, önceden yüklenmiş (veya bir “policy injection” listesi içinde) kernel extension'ları (kexts) inceler ve Info.plist dosyalarında `AppleSecurityExtension` anahtarını arar.
- Info.plist içinde `<key>AppleSecurityExtension</key>` (veya `true`) tanımlayan kexts, “security extension” olarak kabul edilir — yani bir MAC policy uygulayan veya MACF altyapısına hook yapanlar.
- Bu anahtara sahip Apple kexts örnekleri arasında **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** ve diğerleri bulunur (zaten listelediğin gibi).
- Kernel bu kexts'lerin erken yüklenmesini sağlar, ardından boot sırasında registration rutinlerini (`mac_policy_register` üzerinden) çağırır ve bunları `mac_policy_list` içine ekler.

- Her policy module (kext), çeşitli MAC operasyonları için hook'lar (`mpc_ops`) içeren bir `mac_policy_conf` yapısı sağlar (vnode checks, exec checks, label updates, vb.).
- Load time flag'leri arasında, “erken yüklenmeli” anlamına gelen `MPC_LOADTIME_FLAG_NOTLATE` bulunabilir (bu yüzden geç registration denemeleri reddedilir).
- Bir kez register edildikten sonra, her module bir handle alır ve `mac_policy_list` içinde bir slot kaplar.
- Daha sonra bir MAC hook çağrıldığında (örneğin vnode access, exec, vb.), MACF kayıtlı tüm policy'ler üzerinde dolaşarak ortak kararlar verir.

- Özellikle **AMFI** (Apple Mobile File Integrity) böyle bir security extension'dır. Info.plist dosyasında onu bir security policy olarak işaretleyen `AppleSecurityExtension` bulunur.
- Kernel boot'un bir parçası olarak, kernel load logic “security policy”nin (AMFI, vb.) birçok subsystem ona bağımlı hale gelmeden önce zaten aktif olmasını sağlar. Örneğin, kernel “AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy dahil security policy'yi yükleyerek ilerideki görevler için hazırlanır.”
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

MAC framework'ü kullanan bir kext yazarken (yani `mac_policy_register()` vb. çağırırken), bu sembolleri kext linker (kxld) çözebilsin diye KPI'lara (Kernel Programming Interfaces) bağımlılıkları bildirmelisiniz. Dolayısıyla bir `kext`'in MACF'ye bağımlı olduğunu belirtmek için bunu `Info.plist` içinde `com.apple.kpi.dsep` ile belirtmeniz gerekir (`find . Info.plist | grep AppleSecurityExtension`), ardından kext `mac_policy_register`, `mac_policy_unregister` ve MAC hook function pointers gibi sembollere başvuracaktır. Bunları çözmek için `com.apple.kpi.dsep`'i bir bağımlılık olarak listelemelisiniz.

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

Modern macOS’ta, Apple güvenlik politikalarına genellikle gevşek, bağımsız `.kext` bundle’ları olarak yaklaşmak en iyi yöntem değildir. **macOS 11**’den beri kernel extension’lar **kernel collections** içine bağlanır; **Apple Silicon** üzerinde ayrı bir **SystemKC** yoktur ve üçüncü taraf kext’ler ancak **Auxiliary Kernel Collection (AuxKC)** içine derlenip bir reboot sonrası yüklenebilir hale gelir. MACF araştırması açısından bu, **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** veya **Quarantine** gibi yerleşik politikaların genellikle `kextstat` gibi deprecated tooling’lere kıyasla `kmutil` ile enumerate edilmesinin daha kolay olduğu anlamına gelir.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Apple Silicon üzerinde, bir security kext BootKC içinde değilse, sonraki olarak AuxKC’yi kontrol edin. Bu, genellikle `/System/Library/Extensions` altında bağımsız bir bundle aramaktan daha faydalıdır.

## MACF Callouts

Kod içinde MACF’ye yapılan callout’ları, genellikle şu tür **`#if CONFIG_MAC`** koşullu bloklarda bulmak yaygındır. Ayrıca, bu blokların içinde `mac_proc_check*` çağrılarını bulmak mümkündür; bunlar belirli eylemleri gerçekleştirmek için izinleri **check etmek** amacıyla MACF’yi çağırır. Bununla birlikte, MACF callout’larının formatı şöyledir: **`mac_<object>_<opType>_opName`**.

Object, aşağıdakilerden biridir: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\  
`opType` genellikle action’ı allow veya deny etmek için kullanılacak olan check’tir. Ancak `notify` de bulunabilir; bu, kext’in verilen action’a tepki vermesine izin verir.

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

Ardından, `mac_file_check_mmap` kodunu [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) içinde bulmak mümkündür
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
`MAC_CHECK` makrosunu çağırır; bunun kodu [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261) adresinde bulunabilir
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
Which will go over all the registered MAC policy’lerini çağırarak onların fonksiyonlarını çalıştırır ve çıktıyı `error` değişkeni içinde saklar; bu değişken yalnızca `mac_error_select` tarafından success kodlarıyla geçersiz kılınabilir, bu yüzden herhangi bir kontrol başarısız olursa tüm kontrol başarısız olur ve action’a izin verilmez.

> [!TIP]
> Ancak, tüm MACF callout’larının yalnızca action’ları deny etmek için kullanılmadığını unutmayın. Örneğin, `mac_priv_grant` [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) macro’sunu çağırır; bu macro, herhangi bir policy 0 ile cevap verirse istenen privilege’ı grant edecektir:
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

Bu callas’lar [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) içinde tanımlı (onlarca) **privilege**’ı kontrol etmek ve sağlamak için tasarlanmıştır.\
Bazı kernel code’ları, process’in KAuth credential’ları ve privilege code’lardan biriyle [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) içinden `priv_check_cred()` çağırır; bu da herhangi bir policy’nin privilege vermeyi **deny** edip etmediğini görmek için `mac_priv_check`’i çağırır ve ardından herhangi bir policy’nin `privilege`’ı grant edip etmediğini görmek için `mac_priv_grant`’i çağırır.

### proc_check_syscall_unix

Bu hook, tüm system call’ları intercept etmeye izin verir. `bsd/dev/[i386|arm]/systemcalls.c` içinde, şu kodu içeren declared function [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) görülebilir:
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
Çağrıyı yapan süreçte mevcut syscall'ın `mac_proc_check_syscall_unix` çağırıp çağırmaması gerektiğini kontrol edecek olan **bitmask**. Bunun nedeni, syscall'ların o kadar sık çağrılmasıdır ki, her seferinde `mac_proc_check_syscall_unix` çağırmaktan kaçınmak ilginçtir.

`proc_set_syscall_filter_mask()`, bir süreçte bitmask syscall'larını ayarlayan fonksiyonun Sandbox tarafından sandboxed süreçlerde maskeleri ayarlamak için çağrıldığını unutmayın.

## Exposed MACF syscalls

MACF ile [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) içinde tanımlanan bazı syscalls aracılığıyla etkileşim kurmak mümkündür:
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
Tersine mühendislik için, **`__mac_syscall`** hâlâ en iyi userland chokepoint’lerden biridir. Bir **policy name** (örneğin `"Sandbox"` veya `"AMFI"`), bir **policy-specific selector/code** ve `mpo_policy_syscall` tarafından işlenecek **opaque argument blob** için bir pointer taşır. Bu, undocumented operasyonları önce userland’den tersine mühendislik yaparken ve sonra kernel implementation’a pivot ederken çok faydalıdır. Sandbox genelde buna `__sandbox_ms` üzerinden ulaşır, AMFI ise dyld policy kararları için aynı mekanizmayı kullanır.

## Pratik offensive araştırma notları

Son macOS bug’ları nadiren doğrudan "MACF’i kırar". Bunun yerine genellikle bir **MACF / Sandbox / TCC kararı ile daha sonra gerçekleşen privileged action arasındaki desynchronisation**’ı kötüye kullanırlar.

### Broker path checks vs gerçek privileged action

Tekrarlayan bir pattern, privileged daemon’ın bir **userland pre-check** yapmasıdır (örneğin `sandbox_check_by_audit_token()`), bunu bir path’in bir sürümü üzerinde yapar ve sonra gerçek privileged sink’i **farklı veya non-canonical, attacker-controlled bir path** ile çalıştırır. Son dönem `diskarbitrationd` / `storagekitd` araştırmaları iyi bir örnektir: **directory traversal** ile **symlink swaps**, attacker’ın daemon’ın sandbox validation’ından geçmesine ve ardından `~/Library/Application Support/com.apple.TCC` gibi hassas konumların üzerine mount etmesine izin verir; bu da bug’ı seçilen mount point’e bağlı olarak bir **sandbox escape**, **local privilege escalation** veya **TCC bypass** haline getirir.

Sandbox’tan erişilebilen root broker’ları denetlerken önce şunları grep’leyin:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- `mount`, `rename`, `copyfile`, helper-tool XPC methods gibi privileged sink’ler veya daha sonra attacker-controlled path’lere root olarak dokunan her şey

### Özel entitlements ile trusted deputy’ler

Bir başka pratik pattern, MACF hook’larına doğrudan saldırmak yerine sınırı geçmek için gereken yetkileri zaten taşıyan bir **trusted process**’i kötüye kullanmaktır. Son Safari/TCC araştırmaları iyi bir örnektir: ilginç primitive "kernel’de TCC’yi devre dışı bırakmak" değil, yerel policy/configuration’ı değiştirerek **`com.apple.private.tcc.allow`** taşıyan Apple-signed bir process’in hassas işlemi sizin yerinize yapmasını sağlamaktı. Pratikte, yüksek değerli auditing hedefleri şunları birleştiren Apple daemon/app’leridir:

- **private entitlements** veya FDA-benzeri erişim
- yazılabilir bir config / database / mount point / policy file
- **Sandbox**, **AMFI**, **TCC** veya başka bir MACF policy tarafından aracılık edilen daha sonraki hassas bir operasyon

Daha derin product-specific tersine mühendislik için [macOS Sandbox](macos-sandbox/README.md) ve [macOS TCC](macos-tcc/README.md) sayfalarına bakın.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
