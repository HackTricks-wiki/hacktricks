# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

**MACF** ni kifupi cha **Mandatory Access Control Framework**, mfumo wa usalama uliojengwa ndani ya mfumo endeshi ili kusaidia kulinda kompyuta yako. Hufanya kazi kwa kuweka **kanuni kali kuhusu nani au nini kinaweza kufikia sehemu fulani za mfumo**, kama vile faili, programu na rasilimali za mfumo. Kwa kutekeleza kanuni hizi kiotomatiki, MACF huhakikisha kuwa watumiaji na michakato iliyoidhinishwa pekee ndiyo inaweza kutekeleza vitendo maalum, hivyo kupunguza hatari ya ufikiaji usioidhinishwa au shughuli hasidi.

Kumbuka kwamba MACF haifanyi maamuzi yenyewe; **huingilia** tu vitendo, na huacha maamuzi kwa **moduli za sera** (kernel extensions) inazoziita, kama vile `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` na `mcxalr.kext`.

- Sera inaweza kutekeleza vizuizi (kurudisha thamani isiyo 0 kwa operesheni fulani)
- Sera inaweza kufuatilia (kurudisha 0 ili isipingane, lakini itumie hook kufanya jambo fulani)
- Sera tuli ya MACF husakinishwa wakati wa kuwasha mfumo na HAITAONDOLEWA KAMWE
- Sera inayobadilika ya MACF husakinishwa na KEXT (kextload) na kinadharia inaweza kuondolewa kwa kextunload
- Katika iOS, sera tuli pekee ndizo zinazoruhusiwa, ilhali katika macOS, sera tuli na zinazobadilika zinaruhusiwa.<sup>[[7]](#references)</sup>

### Mtiririko

1. Mchakato hutekeleza syscall/mach trap
2. Kazi husika huitwa ndani ya kernel
3. Kazi huita MACF
4. MACF hukagua moduli za sera zilizoomba kuweka hook kwenye kazi hiyo katika sera zao
5. MACF huita sera husika
6. Sera huonyesha ikiwa zinaruhusu au zinakataa kitendo hicho

> [!CAUTION]
> Apple pekee ndiyo inayoweza kutumia MAC Framework KPI.

Kwa kawaida, kazi zinazokagua ruhusa kwa kutumia MACF huita macro `MAC_CHECK`. Kwa mfano, syscall ya kuunda socket huita kazi `mac_socket_check_create`, ambayo nayo huita `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Zaidi ya hayo, macro `MAC_CHECK` hufafanuliwa katika security/mac_internal.h kama ifuatavyo:<sup>[[3]](#references)</sup>
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

Kumbuka kwamba ukibadilisha `check` kuwa `socket_check_create` na `args...` kuwa `(cred, domain, type, protocol)`, utapata:

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

Kupanua macro saidizi kunaonyesha mtiririko halisi wa udhibiti:

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

Kwa maneno mengine, `MAC_CHECK(socket_check_create, ...)` hupitia sera tuli kwanza, kisha hufunga kwa masharti na kupitia sera zinazobadilika, hutoa DTrace probes kabla na baada ya kila hook, na kujumlisha misimbo ya matokeo ya kila hook kuwa matokeo moja ya `error` kupitia `mac_error_select()`.


### Lebo

MACF hutumia **lebo** ambazo sera hutumia kuamua kama zinapaswa kuruhusu ufikiaji fulani au la. Msimbo wa tamko la struct ya lebo [unapatikana hapa](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), na struct hiyo hutumika ndani ya **`struct ucred`** [hapa](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86), katika sehemu ya **`cr_label`**. Lebo ina flags na idadi ya **slots** zinazoweza kutumiwa na **sera za MACF kuhifadhi pointers**. Kwa mfano, Sandbox huelekeza kwenye wasifu wa container.

## Sera za MACF

Sera ya MACF hufafanua **sheria na masharti yatakayotumika katika shughuli fulani za kernel**.

Kernel extension inaweza kusanidi struct ya `mac_policy_conf` kisha kuisajili kwa kuita `mac_policy_register`. Kutoka [hapa](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>

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

Ni rahisi kutambua kernel extensions zinazosanidi sera hizi kwa kuangalia miito ya `mac_policy_register`. Zaidi ya hayo, kwa kuchunguza disassembly ya extension, inawezekana pia kupata struct ya `mac_policy_conf` inayotumika.

Kumbuka kuwa sera za MACF zinaweza kusajiliwa na kufutwa usajili pia **kwa njia ya dynamically**.

Mojawapo ya sehemu kuu za `mac_policy_conf` ni **`mpc_ops`**. Sehemu hii hubainisha ni operesheni zipi zinazohusu sera hiyo. Kuna mamia ya operesheni hizo, kwa hivyo inawezekana kuweka maingizo yote kuwa sifuri kisha kuchagua tu yale ambayo sera inahitaji. Kutoka [hapa](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>

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

Takriban hooks zote zitaitwa tena na MACF mojawapo ya operesheni hizo zinaponaswa. Hata hivyo, hooks za **`mpo_policy_*`** ni tofauti kwa sababu `mpo_hook_policy_init()` ni callback inayoitwa wakati wa usajili (kwa hiyo baada ya `mac_policy_register()`), na `mpo_hook_policy_initbsd()` inaitwa wakati wa usajili wa baadaye, baada ya subsystem ya BSD kuanzishwa ipasavyo.

Zaidi ya hayo, hook ya **`mpo_policy_syscall** inaweza kusajiliwa na kext yoyote ili kufichua **interface** ya aina ya **ioctl** ya wito binafsi. Kisha, client ya user itaweza kuita `mac_syscall` (#381), ikibainisha kama vigezo **jina la policy** pamoja na **code** ya nambari kamili na **arguments** za hiari.\
Kwa mfano, **`Sandbox.kext`** hutumia hii mara nyingi.

Inawezekana kuchunguza **`__DATA.__const*`** ya kext ili kutambua muundo wa `mac_policy_ops` unaotumiwa wakati wa kusajili policy. Muundo huu unaweza kupatikana kwa sababu pointer yake iko kwenye offset ndani ya `mpo_policy_conf`, na pia kutokana na idadi ya pointers za NULL katika eneo hilo.

Zaidi ya hayo, inawezekana pia kupata orodha ya kexts ambazo zimesanidi policy kwa kutoa kutoka kwenye memory struct **`_mac_policy_list`**, ambayo husasishwa kila policy inaposajiliwa.

Unaweza pia kutumia zana `xnoop` kutoa policies zote zilizosajiliwa kwenye mfumo:

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

Kisha dump ukaguzi wote wa check policy kwa kutumia:

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

## Uanzishaji wa MACF katika XNU

### Uanzishaji wa awali na mac_policy_init()

- MACF huanzishwa mapema sana. Katika `bootstrap_thread` (kwenye msimbo wa uanzishaji wa XNU), baada ya `ipc_bootstrap`, XNU huita `mac_policy_init()` (katika `mac_base.c`).  
- `mac_policy_init()` huanzisha `mac_policy_list` ya kimataifa (array au orodha ya nafasi za sera) na kuweka miundombinu ya MAC (Mandatory Access Control) ndani ya XNU.  
- Baadaye, `mac_policy_initmach()` huitwa, na hushughulikia usajili wa sera upande wa kernel kwa sera zilizojengewa ndani au zilizounganishwa.

### `mac_policy_initmach()` na kupakia “security extensions”

- `mac_policy_initmach()` hukagua kernel extensions (kexts) zilizopakiwa awali (au zilizo katika orodha ya “policy injection”) na kukagua Info.plist zao ili kupata ufunguo `AppleSecurityExtension`.  
- Kexts zinazotangaza `<key>AppleSecurityExtension</key>` (au `true`) katika Info.plist zao huchukuliwa kuwa “security extensions” — yaani, zinazotekeleza sera ya MAC au kuunganishwa na miundombinu ya MACF.  
- Mifano ya Apple kexts zilizo na ufunguo huo ni pamoja na **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, na nyinginezo (kama ulivyoorodhesha awali).  
- Kernel huhakikisha kexts hizo zinapakiwa mapema, kisha huita taratibu zake za usajili (kupitia `mac_policy_register`) wakati wa boot na kuziingiza kwenye `mac_policy_list`.

  - Kila moduli ya sera (kext) hutoa muundo wa `mac_policy_conf`, wenye hooks (`mpc_ops`) za shughuli mbalimbali za MAC (ukaguzi wa vnode, ukaguzi wa exec, masasisho ya lebo, n.k.).  
  - Alama za wakati wa kupakia zinaweza kujumuisha `MPC_LOADTIME_FLAG_NOTLATE`, ikimaanisha “lazima ipakiwe mapema” (hivyo majaribio ya usajili wa baadaye hukataliwa).  
  - Baada ya kusajiliwa, kila moduli hupata handle na kuchukua nafasi katika `mac_policy_list`.  
  - Hook ya MAC inapoitiwa baadaye (kwa mfano, ufikiaji wa vnode, exec, n.k.), MACF huzunguka sera zote zilizosajiliwa ili kufanya maamuzi ya pamoja.

- Hasa, **AMFI** (Apple Mobile File Integrity) ni mojawapo ya security extensions hizo. Info.plist yake ina `AppleSecurityExtension` inayoitambulisha kama sera ya usalama. 
- Wakati wa boot ya kernel, mantiki ya upakiaji wa kernel huhakikisha kwamba “security policy” (AMFI, n.k.) tayari inatumika kabla mifumo mingi haijaitegemea. Kwa mfano, kernel “hujiandaa kwa kazi zinazofuata kwa kupakia … security policy, ikijumuisha AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.” 

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

## Utegemezi wa KPI na com.apple.kpi.dsep katika MAC policy kexts

Unapoandika kext inayotumia MAC framework (yaani, inapopiga simu `mac_policy_register()` n.k.), lazima utangaze utegemezi wa KPIs (Kernel Programming Interfaces) ili kext linker (kxld) iweze kutatua alama hizo. Kwa hiyo, ili kutangaza kuwa `kext` inategemea MACF, unahitaji kubainisha hilo kwenye `Info.plist` kwa kutumia `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`). Kisha kext itarejelea alama kama `mac_policy_register`, `mac_policy_unregister`, na MAC hook function pointers. Ili kuzitatua, lazima uorodheshe `com.apple.kpi.dsep` kama utegemezi.

Mfano wa kipande cha Info.plist (ndani ya .kext yako):

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



## MACF kwenye matoleo ya kisasa ya macOS

Kwenye macOS ya kisasa, sera za usalama za Apple kwa kawaida hazichunguzwi vyema kwa kuzichukulia kama vifurushi huru vya `.kext`. Tangu **macOS 11**, kernel extensions huunganishwa katika **kernel collections**; kwenye **Apple Silicon** hakuna **SystemKC** tofauti, na kexts za wahusika wengine zinaweza kupakiwa tu baada ya kujengwa ndani ya **Auxiliary Kernel Collection (AuxKC)** na kompyuta kuwashwa upya. Kwa utafiti wa MACF, hii inamaanisha kuwa sera zilizojengewa ndani, kama **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** au **Quarantine**, kwa kawaida ni rahisi kuziorodhesha kwa kutumia `kmutil` kuliko zana zilizopitwa na wakati kama `kextstat`.

```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```

> [!TIP]
> Kwenye Apple Silicon, ikiwa security kext haipo kwenye BootKC, kagua AuxKC inayofuata. Kwa kawaida, hii ni njia yenye manufaa zaidi kuliko kutafuta bundle inayojitegemea chini ya `/System/Library/Extensions`.

## Miito ya MACF

Ni jambo la kawaida kupata miito ya MACF iliyofafanuliwa kwenye msimbo, kama vile katika vizuizi vya masharti vya **`#if CONFIG_MAC`**. Zaidi ya hayo, ndani ya vizuizi hivi inawezekana kupata miito ya `mac_proc_check*` ambayo huiita MACF **kukagua ruhusa** za kutekeleza vitendo fulani. Pia, muundo wa miito ya MACF ni: **`mac_<object>_<opType>_opName`**.

Object ni mojawapo ya hizi: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` kwa kawaida ni check, ambayo hutumika kuruhusu au kukataa kitendo. Hata hivyo, inawezekana pia kupata `notify`, ambayo huruhusu kext kuitikia kitendo husika.

Unaweza kupata mfano katika [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Kisha, inawezekana kupata msimbo wa `mac_file_check_mmap` katika [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)

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

Ambayo inaita macro ya `MAC_CHECK`, ambayo msimbo wake unaweza kupatikana katika [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>

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

Hii hupitia sera zilizosajiliwa na kuunganisha matokeo yake kwa kutumia `mac_error_select()`. Thamani ya kurudishwa ya sifuri kutoka kwa ukaguzi wa baadaye haiwezi kubatilisha kukataliwa kwa awali; sera kadhaa zikikataa, function huchagua hitilafu kulingana na kipaumbele (kwa mfano, `EACCES` kabla ya `EPERM`).<sup>[[2]](#references)</sup>

> [!TIP]
> Hata hivyo, kumbuka kwamba si callout zote za MACF hutumiwa kukataa vitendo pekee. Kwa mfano, `mac_priv_grant` huita macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), ambayo itatoa privilege iliyoombwa ikiwa sera yoyote itajibu kwa 0:
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

Wito huu umeundwa kukagua na kutoa (makumi ya) **privileges** zilizofafanuliwa katika [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Baadhi ya code ya kernel inaweza kuita `priv_check_cred()` kutoka [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) kwa kutumia credentials za KAuth za process na code ya mojawapo ya privileges. Code hiyo itaita `mac_priv_check` ili kuona kama policy yoyote **inazuia** kutoa privilege hiyo, kisha itaaita `mac_priv_grant` ili kuona kama policy yoyote inatoa `privilege` hiyo.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Hook hii huruhusu kunasa system calls zote. Katika `bsd/dev/[i386|arm]/systemcalls.c` unaweza kuona function iliyotangazwa [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), ambayo ina code hii:

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

Ambayo itaangalia **bitmask** katika process inayoita ili kubaini kama syscall ya sasa inapaswa kuita `mac_proc_check_syscall_unix`. Hii ni kwa sababu syscalls huitwa mara nyingi sana, hivyo ni vyema kuepuka kuita `mac_proc_check_syscall_unix` kila mara.

Kumbuka kuwa function `proc_set_syscall_filter_mask()`, ambayo huweka bitmask ya syscalls katika process, huitwa na Sandbox ili kuweka masks kwenye processes zilizo kwenye sandbox.

## Exposed MACF syscalls

Inawezekana kuingiliana na MACF kupitia baadhi ya syscalls zilizofafanuliwa katika [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):

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

Kwa offensive reversing, **`__mac_syscall`** bado ni mojawapo ya sehemu bora zaidi za kukatiza userland. Hubeba **jina la policy** (kwa mfano `"Sandbox"` au `"AMFI"`), **selector/code mahususi kwa policy**, na pointer ya **opaque argument blob** ambayo itashughulikiwa na `mpo_policy_syscall`. Hii ni muhimu sana unapochunguza operations zisizoandikwa nyaraka, kwanza kutoka userland na baadaye tu kuhamia kwenye utekelezaji wa kernel. Sandbox kwa kawaida huifikia kupitia `__sandbox_ms`, na AMFI hutumia utaratibu huo huo kwa maamuzi ya policy ya dyld.<sup>[[2]](#references)[[5]](#references)</sup>

## Vidokezo vya vitendo vya utafiti wa offensive

Bugs za hivi karibuni za macOS mara chache "hupasua MACF" moja kwa moja. Badala yake, kwa kawaida hutumia **kutolingana kati ya uamuzi wa MACF / Sandbox / TCC na kitendo cha privileged kinachotekelezwa baadaye**.

### Sifa za spawn mahususi kwa policy kama ingizo la MACF

`posix_spawnattr_setmacpolicyinfo_np()` huambatisha jina la policy na bytes zisizo wazi kwenye ombi la `posix_spawn()`. XNU hutafuta bytes hizo kwa kutumia `mpc_name` ya kila policy iliyosajiliwa na kuzipitisha kwenye hook ya exec-label ya policy hiyo; hook ya launch-constraints pia husoma bytes zinazolingana. Hii ni njia tofauti ya ingizo la MACF, linalodhibitiwa na mshambuliaji, na `__mac_syscall`. Kagua kama policy inachukulia bytes hizo kama *kizuizi cha ziada* au inaziruhusu kuchukua nafasi ya policy iliyopo ya parent au executable.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Kwa jaribio linalodhibitiwa, anza na parent yenye vizuizi kisha spawn child yuleyule **bila** na **kwa** sifa mahususi ya policy. Linganisha ufikiaji halisi wa child kwa resource ambayo parent haiwezi kutumia; kufanikiwa kwa spawn pekee hakuthibitishi kuwa mpaka wa usalama umevukwa.<sup>[[12]](#references)[[13]](#references)</sup>

Unapochunguza policy, fuatilia `mpo_cred_label_update_execve` na `mpo_proc_check_launch_constraints`, kisha hakikisha kama caller anaweza kutoa sifa hiyo.<sup>[[10]](#references)[[11]](#references)</sup> Kihistoria, AMFI ilikubali launch constraints zilizotolewa badala ya zilizojengewa ndani; Sandbox ingeweza kutumia profile iliyojengewa ndani yenye jina maalum kwa child badala ya kuhifadhi vizuizi vya parent.<sup>[[13]](#references)[[12]](#references)</sup> Tabia zote mbili zilirekebishwa, kwa hiyo usidhani mojawapo bado ipo kwenye mifumo ya sasa.<sup>[[13]](#references)[[12]](#references)</sup>

Tazama [uchambuzi wa launch-constraints](macos-launch-environment-constraints.md) kwa kisa cha AMFI na [utatuzi wa matatizo ya Sandbox](macos-sandbox/macos-sandbox-debug-and-bypass/) kwa kujaribu policy halisi ya child.

### Ukaguzi wa njia wa broker dhidi ya kitendo halisi cha privileged

Mwenendo unaojirudia ni daemon ya privileged kufanya **ukaguzi wa awali wa userland** (kwa mfano `sandbox_check_by_audit_token()`) kwenye toleo moja la path, kisha baadaye kutekeleza sink halisi ya privileged kwa kutumia **path tofauti au isiyo canonical inayodhibitiwa na mshambuliaji**. Utafiti wa hivi karibuni wa `diskarbitrationd` / `storagekitd` ni mfano mzuri: **directory traversal** pamoja na **symlink swaps** humwezesha mshambuliaji kupita uthibitishaji wa sandbox wa daemon, kisha mount juu ya maeneo nyeti kama `~/Library/Application Support/com.apple.TCC`, na kugeuza bug hiyo kuwa **sandbox escape**, **local privilege escalation** au **TCC bypass**, kutegemea mount point iliyochaguliwa.<sup>[[6]](#references)</sup>

Unapokagua root brokers zinazoweza kufikiwa kutoka sandbox, tafuta kwanza:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, helpers za path canonicalisation
- sink za privileged kama `mount`, `rename`, `copyfile`, methods za helper-tool XPC, au chochote kinachogusa baadaye paths zinazodhibitiwa na mshambuliaji kikiwa root

### Trusted deputies zenye private entitlements

Mwenendo mwingine wa vitendo ni kuepuka kushambulia MACF hooks moja kwa moja na badala yake kutumia vibaya **trusted process** ambayo tayari ina haki zinazohitajika kuvuka mpaka. Utafiti wa hivi karibuni wa Safari/TCC ni mfano mzuri: primitive muhimu haikuwa "kuzima TCC kwenye kernel", bali kurekebisha policy/configuration ya ndani ili process iliyosainiwa na Apple yenye **`com.apple.private.tcc.allow`** itekeleze kitendo nyeti kwa niaba yako.<sup>[[8]](#references)</sup> Kwa vitendo, maeneo yenye thamani kubwa ya kukaguliwa ni Apple daemons/apps zinazochanganya:

- **private entitlements** au ufikiaji wa aina ya FDA
- config / database / mount point / policy file inayoweza kuandikwa
- operesheni nyeti inayofuata, inayodhibitiwa na **Sandbox**, **AMFI**, **TCC** au policy nyingine ya MACF

Kwa uchunguzi wa kina zaidi wa reversing unaohusu bidhaa mahususi, angalia kurasa maalum za [macOS Sandbox](macos-sandbox/README.md) na [macOS TCC](macos-tcc/README.md).



## References

- [1] [XNU — `security/mac_policy.h` (vektori kamili ya operations za policy za MACF)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (macros za `MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (misimbo ya privilege inayotumiwa na `priv_check`/`priv_grant`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Usalama wa Offensive)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Kugundua Udhaifu wa Apple: Ukaguzi wa diskarbitrationd na storagekitd, Sehemu ya 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — Zana ya marejeleo ya XNU](https://newosxbook.com/xxr/index.php)
- [8] [Udhaifu mpya wa macOS, "HM Surf", unaweza kusababisha ufikiaji wa data bila idhini (Blogu ya Usalama ya Microsoft)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
- [9] [XNU — setter ya sifa ya policy ya posix_spawn](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/spawn/posix_spawn.c)
- [10] [XNU — uelekezaji wa sifa ya exec-label mahususi kwa policy](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_vfs.c)
- [11] [XNU — uelekezaji wa policy ya launch-constraints](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_process.c)
- [12] [Kutoroka Apple Sandbox kwa Kuspawn Executable](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [13] [Kukwepa Launch Constraints kwenye macOS](https://wts.dev/posts/bypassing-launch-constraints/)
{{#include ../../../banners/hacktricks-training.md}}
