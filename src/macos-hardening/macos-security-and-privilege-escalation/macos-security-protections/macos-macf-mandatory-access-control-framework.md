# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

**MACF**, **Mandatory Access Control Framework**'ün (Zorunlu Erişim Kontrol Çerçevesi) kısaltmasıdır; işletim sistemine entegre edilmiş bir güvenlik sistemi olup bilgisayarınızı korumaya yardımcı olur. Sistem dosyalarına, uygulamalara ve sistem kaynaklarına kimlerin veya hangi süreçlerin erişebileceğine dair katı kurallar koyarak çalışır. Bu kuralları otomatik olarak uygulayarak MACF, yalnızca yetkili kullanıcılar ve süreçlerin belirli eylemleri gerçekleştirmesine izin verir ve yetkisiz erişim ya da kötü amaçlı etkinlik riskini azaltır.

MACF'nin aslında doğrudan karar vermediğini, sadece eylemleri **yakaladığını** ve kararları çağırdığı politika modüllerine (kernel extension) bıraktığını unutmayın; örneğin `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` ve `mcxalr.kext`.

- Bir politika enforcing (bazı işlemlerde 0 yerine sıfır olmayan bir değer döndürebilir) olabilir
- Bir politika monitoring (itiraz etmeyip 0 döndürerek kanca üzerinden bir şeyler yapabilir) olabilir
- Bir MACF statik politikası boot sırasında kuruludur ve ASLA kaldırılmaz
- Bir MACF dinamik politikası bir KEXT tarafından kurulur (kextload) ve teorik olarak kextunloaded olabilir
- iOS'ta yalnızca statik politikalar izinlidir, macOS'ta ise statik + dinamik politikalar bulunur.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Akış

1. İşlem bir syscall/mach trap gerçekleştirir
2. İlgili fonksiyon kernel içinde çağrılır
3. Fonksiyon MACF'yi çağırır
4. MACF, politika içinde o fonksiyona hook talep eden politika modüllerini kontrol eder
5. MACF ilgili politikaları çağırır
6. Politikalar eylemi izin verip vermeyeceklerini belirtir

> [!CAUTION]
> MAC Framework KPI'yi kullanabilen tek taraf Apple'dir.

Genellikle MACF ile izinleri kontrol eden fonksiyonlar `MAC_CHECK` makrosunu çağırır. Örneğin bir socket oluşturma syscall'unda çağrılan fonksiyon `mac_socket_check_create`'ü çağırır ve bu da `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`'ı çağırır. Ayrıca, `MAC_CHECK` makrosu security/mac_internal.h içinde şu şekilde tanımlanmıştır:
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
Dikkat: `check`'i `socket_check_create` ve `args...`'ı `(cred, domain, type, protocol)` olarak dönüştürdüğünüzde elde edersiniz:
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
Başka bir deyişle, `MAC_CHECK(socket_check_create, ...)` önce statik politikaları gezer, koşullu olarak dinamik politikaları kilitler ve iterasyon yapar, her kanca etrafında DTrace probe'larını yayınlar ve her kancanın dönüş kodunu `mac_error_select()` ile tek bir `error` sonucunda birleştirir.

### Etiketler

MACF, politikaların belirli bir erişimi verip vermeyeceklerini kontrol etmek için kullandığı **etiketler** kullanır. Etiket struct bildirim kodu [burada](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h) bulunabilir; bu daha sonra **`struct ucred`** içinde [**burada**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) **`cr_label`** bölümünde kullanılır. Etiket, bayraklar ve **MACF politikalarının işaretçi ayırmak için kullanabileceği** bir dizi **slot** içerir. Örneğin Sanbox, container profile'a işaret edecektir.

## MACF Politikaları

Bir MACF politikası, belirli kernel işlemlerinde uygulanacak **kuralları ve koşulları** tanımlar.

Bir kernel uzantısı `mac_policy_conf` struct'ını yapılandırıp ardından `mac_policy_register` çağırarak kaydettirebilir. From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Bu politikaları yapılandıran kernel extensions'leri `mac_policy_register` çağrılarını kontrol ederek kolayca tespit etmek mümkündür. Ayrıca, uzantının disassembly'sini inceleyerek kullanılan `mac_policy_conf` struct'ını bulmak da mümkündür.

MACF politikalarının ayrıca **dinamik olarak** kaydedilip kayıttan kaldırılabileceğini unutmayın.

`mac_policy_conf`'un ana alanlarından biri **`mpc_ops`**'dur. Bu alan politikanın ilgilendiği operasyonları belirtir. Yüzlerce operasyon olduğunu unutmayın; bu yüzden bunların tümünü sıfırlayıp yalnızca politikanın ilgilendiğileri seçmek mümkündür. Buradan [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Neredeyse tüm hook'lar, bu işlemlerden biri yakalandığında MACF tarafından geri çağrılacaktır. Ancak, **`mpo_policy_*`** hook'ları bir istisnadır çünkü `mpo_hook_policy_init()` kayıt sırasında (yani `mac_policy_register()`'den sonra) çağrılan bir callback'tir ve `mpo_hook_policy_initbsd()` BSD alt sistemi düzgün şekilde başlatıldıktan sonra geç kayıt sırasında çağrılır.

Ayrıca, **`mpo_policy_syscall`** hook'ı herhangi bir kext tarafından özel bir **ioctl** tarzı çağrı **interface** sunmak için kaydedilebilir. Daha sonra, bir user client `mac_syscall` (#381) çağırarak parametre olarak **policy name** ile bir tamsayı **code** ve isteğe bağlı **arguments** belirtebilecektir.\
Örneğin, **`Sandbox.kext`** bunu sıkça kullanır.

Kext'in **`__DATA.__const*`**'ını kontrol ederek, politikayı kaydederken kullanılan `mac_policy_ops` yapısını tespit etmek mümkündür. Onu bulmak mümkündür çünkü işaretçisi `mpo_policy_conf` içinde bir offset'tedir ve ayrıca o alandaki NULL işaretçi sayısı nedeniyle de ayırt edilebilir.

Ayrıca, kaydedilen her politika ile güncellenen struct **`_mac_policy_list`**'i bellekten dump'layarak politika yapılandırmış kext'lerin listesini elde etmek de mümkündür.

Sistemde kayıtlı tüm politikaları dump'lamak için `xnoop` aracını da kullanabilirsiniz:
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
Ve sonra check policy'nin tüm check'lerini şu komutla dökün:
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

- MACF çok erken başlatılır. XNU başlangıç kodunda `bootstrap_thread` içinde, `ipc_bootstrap`'ten sonra XNU `mac_policy_init()`'i (`mac_base.c` içinde) çağırır.
- `mac_policy_init()` global `mac_policy_list`'i (politika yuvalarının bir dizi veya listesi) başlatır ve XNU içinde MAC (Zorunlu Erişim Kontrolü) için altyapıyı kurar.
- Daha sonra `mac_policy_initmach()` çağrılır; bu, yerleşik veya paketlenmiş politikaların kernel tarafındaki kayıt işlerini ele alır.

### `mac_policy_initmach()` ve “security extensions” yüklenmesi

- `mac_policy_initmach()` önceden yüklenmiş (veya bir “policy injection” listesinde olan) kernel uzantılarını (kexts) inceler ve Info.plist'lerinde `AppleSecurityExtension` anahtarı için kontrol eder.
- Info.plist'lerinde `<key>AppleSecurityExtension</key>` (veya `true`) belirten kext'ler “security extensions” olarak kabul edilir — yani bir MAC politikası uygulayan veya MACF altyapısına bağlananlar.
- Bu anahtara sahip Apple kext örnekleri arasında **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** ve diğerleri bulunur (zaten listelediğiniz gibi).
- Kernel, bu kext'lerin erken yüklenmesini sağlar, ardından önyükleme sırasında kayıt rutinlerini (`mac_policy_register` aracılığıyla) çağırır ve onları `mac_policy_list`'e ekler.

- Her politika modülü (kext) çeşitli MAC işlemleri (vnode kontrolleri, exec kontrolleri, etiket güncellemeleri, vb.) için hook'lar (`mpc_ops`) içeren bir `mac_policy_conf` yapısı sağlar.
- Yükleme zamanı flag'leri `MPC_LOADTIME_FLAG_NOTLATE` gibi değerleri içerebilir; bu “erken yüklenmeli” anlamına gelir (dolayısıyla geç kayıt denemeleri reddedilir).
- Kayıt olduktan sonra her modül bir handle alır ve `mac_policy_list` içinde bir yuva kaplar.
- Bir MAC hook'u daha sonra çağrıldığında (ör. vnode erişimi, exec, vb.), MACF toplu kararlar almak için kayıtlı tüm politikalar üzerinde iterasyon yapar.

- Özellikle, **AMFI** (Apple Mobile File Integrity) böyle bir security extension'dır. Info.plist'i `AppleSecurityExtension`'i içerir ve onu bir güvenlik politikası olarak işaretler.
- Kernel önyüklemesinin bir parçası olarak, kernel yükleme mantığı birçok alt sistem bununla bağımlı hale gelmeden önce “security policy”nin (AMFI vb.) zaten aktif olmasını sağlar. Örneğin, kernel “ilerideki görevler için … security policy'yi, AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine politikalarını yükleyerek hazırlar.”
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

MAC framework'ünü kullanan bir kext yazarken (ör. `mac_policy_register()` vb. çağrılar), kext bağlayıcısının (kxld) bu sembolleri çözebilmesi için KPI'lara (Kernel Programming Interfaces) bağımlılıkları bildirmeniz gerekir. Bu yüzden bir `kext`'in MACF'e bağımlı olduğunu belirtmek için `Info.plist` içinde `com.apple.kpi.dsep`'i belirtmeniz gerekir (`find . Info.plist | grep AppleSecurityExtension`), böylece kext `mac_policy_register`, `mac_policy_unregister` ve MAC hook fonksiyon işaretçileri gibi sembollere referans verir. Bunları çözebilmek için `com.apple.kpi.dsep`'i bir bağımlılık olarak listelemeniz gerekir.

Örnek Info.plist kesiti (kext'inizin içinde):
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

MACF çağrılarına genelde kod içinde, örneğin **`#if CONFIG_MAC`** koşullu bloklarda rastlanır. Ayrıca bu blokların içinde belli eylemleri gerçekleştirmek için MACF'i çağıran `mac_proc_check*` çağrılarını görmek mümkündür; bunlar belirli eylemler için izinleri **kontrol etmek** amacıyla kullanılır. MACF çağrılarının formatı ise: **`mac_<object>_<opType>_opName`**.

Nesne aşağıdakilerden biridir: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` genellikle `check` olup eylemi onaylamak veya reddetmek için kullanılır. Ancak `notify` gibi, kext'in verilen eyleme tepki vermesine izin veren türler de bulunabilir.

Bir örneğini şu adreste bulabilirsiniz: [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Daha sonra, `mac_file_check_mmap`'in kodunu şurada bulabilirsiniz: [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Bu, kayıtlı tüm mac politikaları üzerinde dolaşacak, onların fonksiyonlarını çağıracak ve çıktıyı error değişkenine kaydedecek; bu değişken yalnızca başarı kodlarıyla `mac_error_select` tarafından geçersiz kılınabilir; dolayısıyla herhangi bir kontrol başarısız olursa tüm kontrol başarısız sayılacak ve işlem izin verilmeyecektir.

> [!TIP]
> Ancak, tüm MACF çağırmalarının yalnızca eylemleri reddetmek için kullanılmadığını unutmayın. Örneğin, `mac_priv_grant` [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) makrosunu çağırır; herhangi bir politika 0 döndürürse istenen yetkiyi verir:
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
Bu çağrılar, [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) içinde tanımlı (onlarca) **yetkiyi** kontrol etmek ve sağlamak içindir. Bazı kernel kodları, sürecin KAuth kimlik bilgileri ve yetki kodlarından biri ile [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) içindeki `priv_check_cred()`'i çağırır; bu `mac_priv_check`'i çağırarak herhangi bir politikanın yetki vermeyi **reddettiğini** kontrol eder ve ardından herhangi bir politikanın `privilege`'ı verip vermediğini görmek için `mac_priv_grant`'ı çağırır.

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
Bu, çağıran süreçteki **bitmask** içinde mevcut syscall'ın `mac_proc_check_syscall_unix`'ı çağırıp çağırmayacağını kontrol eder. Bu, syscalls o kadar sık çağrıldığı için `mac_proc_check_syscall_unix`'ı her seferinde çağırmaktan kaçınmanın mantıklı olmasındandır.

`proc_set_syscall_filter_mask()` fonksiyonunun, bir süreçteki bitmask syscalls'larını ayarlamak için kullanıldığını ve Sandbox tarafından sandboxed processes'lara maskeleri uygulamak için çağrıldığını unutmayın.

## Exposed MACF syscalls

MACF ile [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) dosyasında tanımlı bazı syscalls aracılığıyla etkileşim kurmak mümkündür:
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
## Kaynaklar

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}
