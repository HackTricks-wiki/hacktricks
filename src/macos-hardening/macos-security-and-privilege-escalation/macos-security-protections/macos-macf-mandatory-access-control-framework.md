# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

**MACF**, **Zorunlu Erişim Kontrol Çerçevesi** anlamına gelir ve bilgisayarınızı korumaya yardımcı olmak için işletim sistemine entegre edilmiş bir güvenlik sistemidir. Belirli sistem bölümlerine, dosyalara, uygulamalara ve sistem kaynaklarına kimlerin veya nelerin erişebileceği hakkında **katı kurallar belirleyerek** çalışır. Bu kuralları otomatik olarak uygulayarak, MACF yalnızca yetkili kullanıcıların ve süreçlerin belirli eylemleri gerçekleştirmesine izin verir, yetkisiz erişim veya kötü niyetli faaliyetler riskini azaltır.

MACF'nin gerçekten herhangi bir karar vermediğini, yalnızca eylemleri **yakaladığını** unutmayın; kararları çağırdığı **politika modüllerine** (kernel uzantıları) bırakır, bunlar arasında `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` ve `mcxalr.kext` bulunur.

### Akış

1. Süreç bir syscall/mach tuzağı gerçekleştirir
2. İlgili işlev çekirdek içinde çağrılır
3. İşlev MACF'yi çağırır
4. MACF, o işlevi politikalarına bağlamak için talep eden politika modüllerini kontrol eder
5. MACF, ilgili politikaları çağırır
6. Politikalar, eylemi izin verip vermeyeceklerini belirtir

> [!CAUTION]
> Apple, MAC Framework KPI'sini kullanabilen tek şirkettir.

### Etiketler

MACF, ardından politikaların bazı erişim izni verip vermeyeceğini kontrol edeceği **etiketler** kullanır. Etiketlerin yapı tanımının kodu [burada](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h) bulunabilir; bu, **`struct ucred`** içinde [**burada**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) **`cr_label`** kısmında kullanılır. Etiket, **MACF politikalarının işaretçi ayırması** için kullanılabilecek bayraklar ve bir dizi **slot** içerir. Örneğin, Sanbox konteyner profilini işaret edecektir.

## MACF Politikaları

Bir MACF Politikası, belirli çekirdek işlemlerinde uygulanacak **kural ve koşulları** tanımlar.&#x20;

Bir çekirdek uzantısı, `mac_policy_conf` yapısını yapılandırabilir ve ardından `mac_policy_register` çağrısını yaparak kaydedebilir. [Buradan](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Kernel uzantılarını bu politikaları yapılandırırken `mac_policy_register` çağrılarına bakarak kolayca tanımlamak mümkündür. Ayrıca, uzantının ayrıştırmasını kontrol ederek kullanılan `mac_policy_conf` yapısını bulmak da mümkündür.

MACF politikalarının **dinamik** olarak kaydedilebileceğini ve kaydının kaldırılabileceğini unutmayın.

`mac_policy_conf` yapısının ana alanlarından biri **`mpc_ops`**'dir. Bu alan, politikanın ilgilendiği işlemleri belirtir. Bunların yüzlercesi olduğunu unutmayın, bu nedenle hepsini sıfırlamak ve ardından politikanın ilgilendiği sadece belirli olanları seçmek mümkündür. [Buradan](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Neredeyse tüm hook'lar, bu işlemlerden biri engellendiğinde MACF tarafından geri çağrılacaktır. Ancak, **`mpo_policy_*`** hook'ları bir istisnadır çünkü `mpo_hook_policy_init()` kayıt sırasında çağrılan bir geri çağırmadır (yani `mac_policy_register()` sonrasında) ve `mpo_hook_policy_initbsd()` BSD alt sistemi düzgün bir şekilde başlatıldığında geç kayıt sırasında çağrılır.

Ayrıca, **`mpo_policy_syscall`** hook'u, özel bir **ioctl** tarzı çağrı **arayüzü** sunmak için herhangi bir kext tarafından kaydedilebilir. Ardından, bir kullanıcı istemcisi, **politika adı** ile bir tamsayı **kodunu** ve isteğe bağlı **argümanları** belirterek `mac_syscall` (#381) çağrısı yapabilecektir.\
Örneğin, **`Sandbox.kext`** bunu sıkça kullanır.

Kext'in **`__DATA.__const*`** kontrol edilerek, politikanın kaydedilmesi sırasında kullanılan `mac_policy_ops` yapısını tanımlamak mümkündür. Bunu bulmak mümkündür çünkü işaretçisi `mpo_policy_conf` içinde bir ofsettedir ve ayrıca o alanda bulunacak NULL işaretçilerin sayısı nedeniyle.

Ayrıca, her kaydedilen politika ile güncellenen **`_mac_policy_list`** yapısını bellekten dökerek bir politikayı yapılandırmış kext'lerin listesini almak da mümkündür.

## MACF Başlatma

MACF çok kısa bir süre içinde başlatılır. XNU'nun `bootstrap_thread`'inde ayarlanır: `ipc_bootstrap` sonrasında `mac_policy_init()` çağrısı yapılır, bu da `mac_policy_list`'i başlatır ve kısa bir süre sonra `mac_policy_initmach()` çağrılır. Bu işlev, `Info.plist` dosyalarında `AppleSecurityExtension` anahtarına sahip tüm Apple kext'lerini alır; bunlar arasında `ALF.kext`, `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext` ve `TMSafetyNet.kext` bulunur ve bunları yükler.

## MACF Çağrıları

Kodda **`#if CONFIG_MAC`** koşullu blokları gibi MACF'ye yapılan çağrılar bulmak yaygındır. Ayrıca, bu blokların içinde belirli eylemleri gerçekleştirmek için izinleri **kontrol etmek** amacıyla MACF'yi çağıran `mac_proc_check*` çağrılarına rastlamak mümkündür. Ayrıca, MACF çağrılarının formatı: **`mac_<object>_<opType>_opName`** şeklindedir.

Nesne aşağıdakilerden biridir: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` genellikle eylemi onaylamak veya reddetmek için kullanılacak olan kontrol'dür. Ancak, kext'in verilen eyleme tepki vermesine izin verecek `notify`'yi bulmak da mümkündür.

Bir örneği [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) adresinde bulabilirsiniz:

<pre class="language-c"><code class="lang-c">int
mmap(proc_t p, struct mmap_args *uap, user_addr_t *retval)
{
[...]
#if CONFIG_MACF
<strong>			error = mac_file_check_mmap(vfs_context_ucred(ctx),
</strong>			    fp->fp_glob, prot, flags, file_pos + pageoff,
&#x26;maxprot);
if (error) {
(void)vnode_put(vp);
goto bad;
}
#endif /* MAC */
[...]
</code></pre>

Ardından, `mac_file_check_mmap` kodunu [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) adresinde bulmak mümkündür.
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
`MAC_CHECK` makrosunu çağıran, kodu [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261) adresinde bulunabilir.
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
Tüm kayıtlı mac politikalarını çağırarak ve çıktıyı hata değişkeninde saklayarak geçecektir; bu değişken yalnızca başarı kodları ile `mac_error_select` tarafından geçersiz kılınabilir, bu nedenle herhangi bir kontrol başarısız olursa, tüm kontrol başarısız olacak ve işlem izin verilmeyecektir.

> [!TIP]
> Ancak, tüm MACF çağrılarının yalnızca eylemleri reddetmek için kullanılmadığını unutmayın. Örneğin, `mac_priv_grant`, herhangi bir politika 0 ile yanıt verirse istenen ayrıcalığı verecek olan [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) makrosunu çağırır:
>
> ```c
> /*
>  * MAC_GRANT, politika modülü listesini dolaşarak
>  * isteğe ilişkin her biriyle nasıl hissettiğini kontrol ederek
>  * belirlenen kontrolü gerçekleştirir. MAC_CHECK'ten farklı olarak,
>  * herhangi bir politika '0' dönerse verir ve aksi takdirde EPERM döner.
>  * Değerini çağıranın kapsamındaki 'error' aracılığıyla döndürdüğünü unutmayın.
>  */
> #define MAC_GRANT(check, args...) do {                              \
>     error = EPERM;                                                  \
>     MAC_POLICY_ITERATE({                                            \
> 	if (mpc->mpc_ops->mpo_ ## check != NULL) {                  \
> 	        DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_GRANT); \
> 	        int __step_res = mpc->mpc_ops->mpo_ ## check (args); \
> 	        if (__step_res == 0) {                              \
> 	                error = 0;                                  \
> 	        }                                                   \
> 	        DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_res); \
> 	    }                                                           \
>     });                                                             \
> } while (0)
> ```

### priv_check & priv_grant

Bu çağrılar, [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) dosyasında tanımlanan (onlarca) **ayrıcalığı** kontrol etmek ve sağlamak için tasarlanmıştır.\
Bazı çekirdek kodları, `priv_check_cred()`'i [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) dosyasından çağırarak işlemin KAuth kimlik bilgileri ile birlikte bir ayrıcalık kodunu çağıracak ve ardından `mac_priv_check` çağrılarak herhangi bir politikanın ayrıcalığı vermeyi **reddedip** reddetmediği kontrol edilecek ve ardından `mac_priv_grant` çağrılarak herhangi bir politikanın `ayrıcalığı` verip vermediği kontrol edilecektir.

### proc_check_syscall_unix

Bu kanca, tüm sistem çağrılarını kesmeye olanak tanır. `bsd/dev/[i386|arm]/systemcalls.c` dosyasında, bu kodu içeren tanımlı fonksiyonu [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) görebilirsiniz:
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
Hangi çağıran süreçte **bitmask** kontrol edilecektir, böylece mevcut syscall `mac_proc_check_syscall_unix` çağrılmalıdır. Bunun nedeni, syscalls'ın çok sık çağrılmasıdır, bu nedenle her seferinde `mac_proc_check_syscall_unix` çağrısını önlemek ilginçtir.

`proc_set_syscall_filter_mask()` fonksiyonunun, bir süreçte bitmask syscalls'ı ayarlamak için Sandbox tarafından çağrıldığını unutmayın; bu, sandboxed süreçlerde maskeleri ayarlamak içindir.

## Açık MACF syscalls

MACF ile etkileşimde bulunmak, [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) dosyasında tanımlanan bazı syscalls aracılığıyla mümkündür:
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

- [**\*OS İç Yapıları Cilt III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
