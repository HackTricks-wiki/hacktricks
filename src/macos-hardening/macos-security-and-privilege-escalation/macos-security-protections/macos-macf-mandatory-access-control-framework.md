# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

**MACF**, **Mandatory Access Control Framework**'ün kısaltmasıdır ve bilgisayarınızı korumaya yardımcı olmak için işletim sistemine yerleşik bir güvenlik sistemidir. Dosyalar, uygulamalar ve sistem kaynakları gibi sistemin belirli bölümlerine kimlerin veya nelerin erişebileceğine dair **katı kurallar** belirleyerek çalışır. Bu kuralları otomatik olarak uygulayan MACF, belirli eylemleri yalnızca yetkili kullanıcıların ve süreçlerin gerçekleştirebilmesini sağlar ve yetkisiz erişim ya da kötü amaçlı faaliyet riskini azaltır.

MACF'nin aslında herhangi bir karar vermediğini; yalnızca eylemleri **engellediğini** unutmayın. Kararları, `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` ve `mcxalr.kext` gibi çağırdığı **policy module**'lere (kernel extension) bırakır.

- Bir policy, yaptırım uyguluyor olabilir (bazı işlemlerde 0 olmayan bir değer döndürür)
- Bir policy, izleme yapıyor olabilir (itiraz etmemek, ancak bir şey yapmak için hook'tan yararlanmak üzere 0 döndürür)
- MACF static policy, boot sırasında yüklenir ve ASLA kaldırılmaz
- MACF dynamic policy, bir KEXT tarafından yüklenir (kextload) ve teorik olarak kextunload ile kaldırılabilir
- iOS'ta yalnızca static policy'lere izin verilirken macOS'ta hem static hem de dynamic policy'lere izin verilir.<sup>[[7]](#references)</sup>

### Akış

1. Süreç bir syscall/mach trap gerçekleştirir
2. Kernel içinde ilgili fonksiyon çağrılır
3. Fonksiyon MACF'yi çağırır
4. MACF, kendi policy'lerinde bu fonksiyon için hook talep eden policy module'leri kontrol eder
5. MACF ilgili policy'leri çağırır
6. Policy'ler eyleme izin verip vermediklerini belirtir

> [!CAUTION]
> MAC Framework KPI'yi yalnızca Apple kullanabilir.

Genellikle MACF ile izinleri kontrol eden fonksiyonlar `MAC_CHECK` makrosunu çağırır. Örneğin, socket oluşturmak için yapılan bir syscall, `mac_socket_check_create` fonksiyonunu çağıran fonksiyonu çağırır; bu fonksiyon da `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` çağrısını yapar. Ayrıca `MAC_CHECK` makrosu security/mac_internal.h içinde şöyle tanımlanmıştır:<sup>[[3]](#references)</sup>
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

`check` ifadesini `socket_check_create` ve `(cred, domain, type, protocol)` içindeki `args...` ile değiştirirseniz şunu elde edersiniz:

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

Yardımcı makrolar genişletildiğinde somut kontrol akışı görülür:

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

Başka bir deyişle, `MAC_CHECK(socket_check_create, ...)` önce statik politikaları dolaşır, ardından koşula bağlı olarak kilit alıp dinamik politikalar üzerinde yineleme yapar, her hook çevresinde DTrace probe'ları tetikler ve `mac_error_select()` aracılığıyla her hook'un dönüş kodunu tek bir `error` sonucunda birleştirir.


### Etiketler

MACF, erişim izni verilip verilmeyeceğini denetleyen politikaların kullandığı **etiketleri** kullanır. Etiket struct bildirimine ait kod [burada bulunabilir](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h); bu struct, [burada](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) **`struct ucred`** içinde, **`cr_label`** bölümünde kullanılır. Etiket, MACF politikalarının işaretçi ayırmak için kullanabileceği bayraklar ve belirli sayıda **slot** içerir. Örneğin Sandbox, kapsayıcı profiline işaret eder.

## MACF Politikaları

Bir MACF politikası, belirli kernel işlemlerinde uygulanacak **kuralları ve koşulları tanımlar**.

Bir kernel extension, `mac_policy_conf` struct'ını yapılandırabilir ve ardından `mac_policy_register` çağrısıyla kaydedebilir. [Buradan](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>

```c
 #define mpc_t	struct mac_policy_conf *

/**
  @brief Mac policy configuration

  This structure specifies the configuration information for a
  MAC policy module.  A policy module developer must supply
  a short unique policy name, a more descriptive full name, a list of label
  namespaces and count, a pointer to the registered entry-point operations,
  any load time flags, and optionally, a pointer to a label slot identifier.

  The Framework will update the runtime flags (mpc_runtime_flags) to
  indicate that the module has been registered.

  If the label slot identifier (mpc_field_off) is NULL, the Framework
  will not provide label storage for the policy.  Otherwise, the
  Framework will store the label location (slot) in this field.

  The mpc_list field is used by the Framework and should not be
  modified by policies.
*/
/* XXX - reorder these for better alignment on 64bit platforms */
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

Bu politikaları yapılandıran kernel extension'ları, `mac_policy_register` çağrılarını kontrol ederek kolayca belirleyebilirsiniz. Ayrıca extension'ın disassembly'sini inceleyerek kullanılan `mac_policy_conf` struct'ını bulmak da mümkündür.

MACF policy'lerinin **dinamik olarak** da kaydedilip kaldırılabileceğini unutmayın.

`mac_policy_conf`'un başlıca alanlarından biri **`mpc_ops`**'tur. Bu alan, policy'nin hangi işlemlerle ilgilendiğini belirtir. Yüzlerce işlem olduğundan, tüm girdileri sıfırlayıp ardından yalnızca policy'nin ihtiyaç duyduklarını seçmek mümkündür. [Buradan](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>

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

Bu işlemlerden biri engellendiğinde, hook'ların neredeyse tamamı MACF tarafından çağrılır. Ancak **`mpo_policy_*`** hook'ları bir istisnadır; çünkü `mpo_hook_policy_init()` bir kayıt sırasında çağrılan callback'tir (yani `mac_policy_register()` sonrasında), `mpo_hook_policy_initbsd()` ise BSD alt sistemi düzgün şekilde başlatıldıktan sonra geç kayıt sırasında çağrılır.

Ayrıca, herhangi bir kext özel bir **ioctl** tarzı çağrı **arayüzü** sunmak için **`mpo_policy_syscall`** hook'unu kaydedebilir. Böylece bir kullanıcı istemcisi, parametre olarak **policy adını**, bir tamsayı **kodu** ve isteğe bağlı **argümanları** belirterek `mac_syscall` (#381) çağrısı yapabilir.\
Örneğin, **`Sandbox.kext`** bunu sıkça kullanır.

Policy kaydedilirken kullanılan `mac_policy_ops` yapısını belirlemek için kext'in **`__DATA.__const*`** bölümünü incelemek mümkündür. Bu yapıyı bulmak mümkündür; çünkü işaretçisi `mpo_policy_conf` içinde bir offset'te bulunur ve ayrıca o alanda yer alacak NULL işaretçilerinin sayısı da ipucu verir.

Ayrıca, bellekteki ve kaydedilen her policy ile güncellenen **`_mac_policy_list`** yapısı dökümü alınarak policy yapılandırmış kext'lerin listesi de elde edilebilir.

Sisteme kayıtlı tüm policy'leri dökmek için `xnoop` aracını da kullanabilirsiniz:

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

Ardından, check policy'deki tüm denetimleri şu komutla dökümleyin:

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

## XNU'da MACF başlatması

### Erken önyükleme ve mac_policy_init()

- MACF çok erken başlatılır. XNU, `bootstrap_thread` içinde (XNU başlangıç kodunda), `ipc_bootstrap` işleminden sonra `mac_policy_init()` işlevini (`mac_base.c` içinde) çağırır.  
- `mac_policy_init()`, global `mac_policy_list`'i (policy slot'larından oluşan bir dizi veya liste) başlatır ve XNU içinde MAC (Zorunlu Erişim Denetimi) altyapısını kurar.  
- Daha sonra, yerleşik veya paketlenmiş policy'lerin kernel tarafındaki kaydını yöneten `mac_policy_initmach()` çağrılır.

### `mac_policy_initmach()` ve “güvenlik uzantılarının” yüklenmesi

- `mac_policy_initmach()`, önceden yüklenmiş (veya bir “policy injection” listesinde bulunan) kernel uzantılarını (kext'leri) inceler ve Info.plist dosyalarında `AppleSecurityExtension` anahtarını arar.  
- Info.plist dosyalarında `<key>AppleSecurityExtension</key>` (veya `true`) bildiren kext'ler, “güvenlik uzantıları” olarak kabul edilir; yani bir MAC policy uygulayan veya MACF altyapısına bağlanan uzantılardır.  
- Bu anahtara sahip Apple kext'lerine **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** ve diğerleri örnek verilebilir (daha önce listeledikleriniz gibi).  
- Kernel, bu kext'lerin erken yüklenmesini sağlar, ardından önyükleme sırasında kayıt rutinlerini (`mac_policy_register` aracılığıyla) çağırarak bunları `mac_policy_list`'e ekler.

  - Her policy modülü (kext), çeşitli MAC işlemlerine (vnode kontrolleri, exec kontrolleri, etiket güncellemeleri vb.) yönelik hook'ları (`mpc_ops`) içeren bir `mac_policy_conf` yapısı sağlar.  
  - Yükleme zamanı bayrakları arasında, “erken yüklenmeli” anlamına gelen `MPC_LOADTIME_FLAG_NOTLATE` bulunabilir (bu durumda geç kayıt girişimleri reddedilir).  
  - Kayıt tamamlandığında her modüle bir tanıtıcı atanır ve modül `mac_policy_list` içinde bir slot kaplar.  
  - Daha sonra bir MAC hook'u (örneğin vnode erişimi veya exec sırasında) çağrıldığında MACF, ortak kararlar almak için kayıtlı tüm policy'leri dolaşır.

- Özellikle **AMFI** (Apple Mobile File Integrity) böyle bir güvenlik uzantısıdır. Info.plist dosyasında, bir güvenlik policy'si olduğunu belirten `AppleSecurityExtension` bulunur. 
- Kernel önyüklemesinin bir parçası olarak kernel yükleme mantığı, birçok alt sistem buna bağımlı hâle gelmeden önce “güvenlik policy'sinin” (AMFI vb.) etkin olmasını sağlar. Örneğin kernel, “AppleMobileFileIntegrity (AMFI), Sandbox ve Quarantine policy'si dahil olmak üzere … güvenlik policy'sini yükleyerek ilerideki görevler için hazırlık yapar.” 

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

## KPI bağımlılığı ve MAC policy kext'lerinde com.apple.kpi.dsep

MAC framework'ü kullanan (yani `mac_policy_register()` vb. çağıran) bir kext yazarken, kext linker'ın (kxld) bu sembolleri çözümleyebilmesi için KPI'lara (Kernel Programming Interfaces) bağımlılıkları bildirmeniz gerekir. Dolayısıyla bir `kext`'in MACF'ye bağımlı olduğunu bildirmek için bunu `Info.plist` içinde `com.apple.kpi.dsep` ile belirtmeniz gerekir (`find . Info.plist | grep AppleSecurityExtension`). Ardından kext, `mac_policy_register`, `mac_policy_unregister` gibi sembollere ve MAC hook işlev işaretçilerine başvurur. Bunları çözümlemek için `com.apple.kpi.dsep`'i bağımlılık olarak listelemelisiniz.

Örnek Info.plist parçacığı (.kext'inizin içinde):

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

Modern macOS'te Apple güvenlik politikalarını genellikle bağımsız `.kext` paketleri olarak ele almak doğru yaklaşım değildir. **macOS 11**'den itibaren kernel extension'lar **kernel collection**'lara bağlanır; **Apple Silicon** üzerinde ayrı bir **SystemKC** bulunmaz ve üçüncü taraf kext'ler ancak **Auxiliary Kernel Collection (AuxKC)** içine derlendikten ve sistem yeniden başlatıldıktan sonra yüklenebilir. MACF araştırmalarında bu, **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** veya **Quarantine** gibi yerleşik politikaların, `kextstat` gibi kullanımdan kaldırılmış araçlar yerine `kmutil` ile listelenmesinin genellikle daha kolay olduğu anlamına gelir.

```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```

> [!TIP]
> Apple Silicon'da bir security kext BootKC'de yoksa, sırada AuxKC'yi kontrol edin. Bu, `/System/Library/Extensions` altında bağımsız bir bundle aramaktan genellikle daha faydalıdır.

## MACF Callouts

MACF çağrılarını şu tür kodlarda bulmak yaygındır: **`#if CONFIG_MAC`** koşullu blokları. Ayrıca bu blokların içinde, belirli eylemleri gerçekleştirmek için **izinleri denetlemek** üzere MACF'yi çağıran `mac_proc_check*` çağrıları bulunabilir. MACF çağrılarının biçimi şöyledir: **`mac_<object>_<opType>_opName`**.

Nesne şunlardan biridir: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` genellikle eyleme izin vermek veya eylemi reddetmek için kullanılan `check` değeridir. Ancak, kext'in belirtilen eyleme tepki vermesini sağlayan `notify` değerine de rastlamak mümkündür.

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

Ardından, [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) adresinde `mac_file_check_mmap` kodunu bulabilirsiniz.

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

`MAC_CHECK` makrosunu çağırıyor; makronun kodu [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup> konumunda bulunabilir.

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

Bu, kayıtlı politikaları dolaşır ve sonuçlarını `mac_error_select()` ile birleştirir. Sonraki bir denetimin sıfır döndürmesi, daha önceki bir reddi geçersiz kılamaz; birden fazla politika reddederse işlev, öncelik sırasına göre hatayı seçer (örneğin, `EACCES`, `EPERM`'den önce gelir).<sup>[[2]](#references)</sup>

> [!TIP]
> Ancak, tüm MACF callout'larının yalnızca eylemleri reddetmek için kullanılmadığını unutmayın. Örneğin, `mac_priv_grant`, [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) makrosunu çağırır; herhangi bir politika 0 döndürürse bu makro istenen ayrıcalığı verir:
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

Bu çağrılar, [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) içinde tanımlanan onlarca **ayrıcalığı** denetlemek ve vermek için kullanılır.\
Bazı kernel kodları, sürecin KAuth kimlik bilgileriyle ve ayrıcalık kodlarından biriyle [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) içindeki `priv_check_cred()` işlevini çağırır. Bu işlev, herhangi bir politikanın ayrıcalığın verilmesini **reddedip reddetmediğini** görmek için `mac_priv_check` işlevini çağırır; ardından herhangi bir politikanın `privilege` değerini verip vermediğini görmek için `mac_priv_grant` işlevini çağırır.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Bu hook, tüm sistem çağrılarının yakalanmasını sağlar. `bsd/dev/[i386|arm]/systemcalls.c` dosyasında, şu kodu içeren [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) işlevinin tanımlandığını görebilirsiniz:

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

Çağıran süreçteki **bitmask**'i kontrol ederek geçerli syscall'ın `mac_proc_check_syscall_unix` işlevini çağırıp çağırmaması gerektiğini belirler. Syscall'lar çok sık çağrıldığından, her seferinde `mac_proc_check_syscall_unix` işlevini çağırmaktan kaçınmak yararlıdır.

Bir süreçteki syscall bitmask'lerini ayarlayan `proc_set_syscall_filter_mask()` işlevinin, sandbox uygulanmış süreçlerde maskeleri ayarlamak için Sandbox tarafından çağrıldığını unutmayın.

## MACF syscalls

[security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) içinde tanımlanan bazı syscall'lar aracılığıyla MACF ile etkileşim kurmak mümkündür:

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

Saldırı amaçlı reversing için **`__mac_syscall`**, userland tarafındaki en iyi darboğazlardan biri olmayı sürdürüyor. Bu çağrı, `mpo_policy_syscall` tarafından işlenecek bir **policy name** (örneğin `"Sandbox"` veya `"AMFI"`), **policy-specific selector/code** ve **opaque argument blob** işaretçisi taşır. Userland'den başlayarak belgelenmemiş işlemleri reverse edip daha sonra kernel uygulamasına geçiş yapmak için bu çok kullanışlıdır. Sandbox genellikle bu çağrıya `__sandbox_ms` üzerinden ulaşır; AMFI ise dyld policy kararları için aynı mekanizmayı kullanır.<sup>[[2]](#references)[[5]](#references)</sup>

## Uygulamaya yönelik saldırı araştırması notları

Son macOS bug'ları nadiren doğrudan "MACF'yi bozar". Bunun yerine genellikle bir MACF / Sandbox / TCC kararı ile sonradan gerçekleşen ayrıcalıklı eylem arasındaki **senkronizasyon bozukluğundan** yararlanırlar.

### MACF girdisi olarak policy-specific spawn attributes

`posix_spawnattr_setmacpolicyinfo_np()`, bir `posix_spawn()` isteğine policy name ve opaque bytes ekler. XNU, bu bytes değerlerini kayıtlı her policy'nin `mpc_name` değerine göre arar ve policy'nin exec-label hook'una iletir; launch-constraints hook'u da eşleşen bytes değerlerini okur. Bu, `__mac_syscall`'dan ayrı, saldırganın kontrol edebildiği bir MACF girdi yoludur. Policy'nin bu bytes değerlerini *ek bir kısıtlama* olarak mı ele aldığını, yoksa parent'ın ya da executable'ın mevcut policy'sinin yerine mi kullandığını denetleyin.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Kontrollü bir test için, kısıtlanmış bir parent ile başlayın ve aynı child'ı policy-specific attribute olmadan ve attribute ile spawn edin. Child'ın parent'ın kullanamadığı bir kaynağa erişimini karşılaştırın; spawn işleminin başarılı olması tek başına bir sınırın aşıldığını kanıtlamaz.<sup>[[12]](#references)[[13]](#references)</sup>

Policy'yi reverse ederken `mpo_cred_label_update_execve` ve `mpo_proc_check_launch_constraints` işlevlerini izleyin, ardından çağıranın attribute'u sağlayıp sağlayamayacağını kontrol edin.<sup>[[10]](#references)[[11]](#references)</sup> AMFI geçmişte yerleşik launch constraints yerine sağlananları kabul ediyordu; Sandbox ise parent'ın kısıtlamalarını korumak yerine child'a adı belirtilen yerleşik bir profile uygulayabiliyordu.<sup>[[13]](#references)[[12]](#references)</sup> Her iki davranış da yamalandı; bu nedenle güncel sistemlerde bunlardan herhangi birinin geçerli olduğunu varsaymayın.<sup>[[13]](#references)[[12]](#references)</sup>

AMFI örneği için [launch-constraints analizi](macos-launch-environment-constraints.md) sayfasına, child'ın etkin policy'sini test etmek için [Sandbox debugging](macos-sandbox/macos-sandbox-debug-and-bypass/) sayfasına bakın.

### Broker'ın path kontrolleri ve gerçek ayrıcalıklı eylem

Sık karşılaşılan bir örüntüde, ayrıcalıklı bir daemon bir path'in bir sürümü üzerinde **userland ön kontrolü** (örneğin `sandbox_check_by_audit_token()`) yapar, ardından gerçek ayrıcalıklı sink'i **farklı veya kanonik olmayan, saldırganın kontrol ettiği bir path** ile çalıştırır. Son dönemdeki `diskarbitrationd` / `storagekitd` araştırmaları buna iyi bir örnektir: **directory traversal** ile **symlink swap** kullanarak saldırgan, daemon'ın sandbox doğrulamasını geçebilir ve daha sonra `~/Library/Application Support/com.apple.TCC` gibi hassas konumların üzerine mount işlemi yapabilir. Böylece hata, seçilen mount point'e bağlı olarak **sandbox escape**, **local privilege escalation** veya **TCC bypass** haline gelir.<sup>[[6]](#references)</sup>

Sandbox'tan erişilebilen root broker'larını denetlerken önce şunları arayın:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation yardımcıları
- `mount`, `rename`, `copyfile`, helper-tool XPC metotları gibi ayrıcalıklı sink'ler veya daha sonra root olarak saldırganın kontrol ettiği path'lere dokunan başka işlemler

### Private entitlements sahibi trusted deputy'ler

Bir diğer pratik örüntü, MACF hook'larına doğrudan saldırmak yerine sınırı aşmak için gereken haklara zaten sahip **trusted process**'ten yararlanmaktır. Son dönemdeki Safari/TCC araştırmaları buna iyi bir örnektir: ilginç primitive, "kernel'de TCC'yi devre dışı bırakmak" değil, `com.apple.private.tcc.allow` **private entitlement**'ına sahip, Apple tarafından imzalanmış bir process'in hassas eylemi sizin adınıza gerçekleştirmesini sağlayacak yerel policy/configuration değişikliğiydi.<sup>[[8]](#references)</sup> Uygulamada, yüksek değerli denetim hedefleri şunları bir arada barındıran Apple daemon/app'lerdir:

- **private entitlements** veya FDA benzeri erişim
- yazılabilir bir config / database / mount point / policy file
- **Sandbox**, **AMFI**, **TCC** veya başka bir MACF policy tarafından denetlenen, sonradan gerçekleşen hassas bir işlem

Ürüne özgü daha derin reversing için [macOS Sandbox](macos-sandbox/README.md) ve [macOS TCC](macos-tcc/README.md) konularındaki özel sayfalara bakın.



## References

- [1] [XNU — `security/mac_policy.h` (MACF policy işlemleri vektörünün tamamı)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (`MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE` makroları)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (`priv_check`/`priv_grant` tarafından kullanılan privilege kodları)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Apple Güvenlik Açıklarını Keşfetmek: diskarbitrationd ve storagekitd Denetimi, Bölüm 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — XNU Cross Reference aracı](https://newosxbook.com/xxr/index.php)
- [8] [Yeni macOS güvenlik açığı "HM Surf", yetkisiz veri erişimine yol açabilir (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
- [9] [XNU — posix_spawn policy attribute ayarlayıcısı](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/spawn/posix_spawn.c)
- [10] [XNU — policy-specific exec-label attribute yönlendirmesi](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_vfs.c)
- [11] [XNU — launch-constraints policy yönlendirmesi](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_process.c)
- [12] [Bir Executable Spawn Ederek Apple Sandbox'ından Kaçmak](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [13] [macOS'ta Launch Constraints Bypass Etmek](https://wts.dev/posts/bypassing-launch-constraints/)
{{#include ../../../banners/hacktricks-training.md}}
