# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

**MACF** staan vir **Mandatory Access Control Framework**, wat ’n sekuriteitstelsel is wat in die bedryfstelsel ingebou is om jou rekenaar te help beskerm. Dit werk deur **streng reëls te stel oor wie of wat toegang kan kry tot sekere dele van die stelsel**, soos lêers, toepassings en stelselhulpbronne. Deur hierdie reëls outomaties af te dwing, verseker MACF dat slegs gemagtigde gebruikers en prosesse spesifieke aksies kan uitvoer, wat die risiko van ongemagtigde toegang of kwaadwillige aktiwiteite verminder.

Let daarop dat MACF nie regtig enige besluite neem nie, aangesien dit net aksies **onderskep**; dit laat die besluite oor aan die **policy modules** (kernel extensions) wat dit aanroep, soos `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` en `mcxalr.kext`.

- ’n policy kan enforcing wees (gee 0 nie-nul terug op een of ander operasie)
- ’n policy kan monitor wees (gee 0 terug, sodat dit nie beswaar maak nie maar op die hook “piggyback” om iets te doen)
- ’n MACF static policy word tydens boot geïnstalleer en sal NOOIT verwyder word nie
- ’n MACF dynamic policy word deur ’n KEXT (kextload) geïnstalleer en kan hipoteties kextunloaded word
- In iOS word slegs static policies toegelaat en in macOS static + dynamic.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flow

1. Process voer ’n syscall/mach trap uit
2. Die relevante funksie word binne die kernel geroep
3. Funksie roep MACF
4. MACF kyk na policy modules wat versoek het om daardie funksie in hul policy te hook
5. MACF roep die relevante policies
6. Policies dui aan of hulle die aksie toelaat of weier

> [!CAUTION]
> Apple is die enigste een wat die MAC Framework KPI kan gebruik.

Gewoonlik sal die funksies wat permissions met MACF nagaan die makro `MAC_CHECK` roep. Soos in die geval van ’n syscall om ’n socket te skep wat die funksie `mac_socket_check_create` sal roep, wat `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` roep. Verder is die makro `MAC_CHECK` gedefinieer in security/mac_internal.h as:
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
Let daarop dat as jy `check` na `socket_check_create` en `args...` na `(cred, domain, type, protocol)` omskakel, kry jy:
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
Die uitbreiding van die helper-makro's toon die konkrete beheervloei:
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
Met ander woorde, `MAC_CHECK(socket_check_create, ...)` loop eers deur die statiese beleide, sluit en iterer dan voorwaardelik oor dinamiese beleide, emit die DTrace probes rondom elke hook, en vou elke hook se return code saam in die enkele `error` resultaat via `mac_error_select()`.


### Labels

MACF gebruik **labels** wat dan deur die policies wat nagaan of hulle toegang moet toestaan of nie, gebruik sal word. Die kode van die labels struct declaration kan [hier gevind word](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), en dit word dan binne die **`struct ucred`** in [**hier**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) in die **`cr_label`** deel gebruik. Die label bevat flags en ’n aantal **slots** wat deur **MACF policies to allocate pointers** gebruik kan word. Byvoorbeeld, Sanbox sal na die container profile wys

## MACF Policies

'n MACF Policy definieer **reëls en voorwaardes wat op sekere kernel operations toegepas moet word**.

’n kernel extension kan ’n `mac_policy_conf` struct konfigureer en dit dan registreer deur `mac_policy_register` te roep. Van [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Dit is maklik om die kernel-uitbreidings te identifiseer wat hierdie beleid konfigureer deur calls na `mac_policy_register` na te gaan. Verder, deur die disassemble van die uitbreiding na te gaan, is dit ook moontlik om die gebruikte `mac_policy_conf` struct te vind.

Let daarop dat MACF-beleid ook **dinamies** geregistreer en gederegistreer kan word.

Een van die hoofvelde van die `mac_policy_conf` is die **`mpc_ops`**. Hierdie veld spesifiseer watter operasies die beleid in belang stel. Let daarop dat daar honderde van hulle is, so dit is moontlik om hulle almal op nul te stel en dan net dié te kies waarin die beleid belang stel. Van [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Amper al die hooks sal deur MACF teruggeroep word wanneer een van daardie operations onderskep word. Die **`mpo_policy_*`** hooks is egter ’n uitsondering omdat **`mpo_hook_policy_init()`** ’n callback is wat by registrasie geroep word (dus ná **`mac_policy_register()`**) en **`mpo_hook_policy_initbsd()`** tydens laat registrasie geroep word sodra die BSD-substelsel korrek geïnitialiseer het.

Verder kan die **`mpo_policy_syscall`** hook deur enige kext geregistreer word om ’n private **ioctl**-styl call **interface** bloot te stel. Dan sal ’n user client in staat wees om **`mac_syscall`** (#381) te roep en as parameters die **policy name** met ’n heelgetal **code** en opsionele **arguments** te spesifiseer.\
Byvoorbeeld, die **`Sandbox.kext`** gebruik dit baie.

Deur die kext se **`__DATA.__const*`** te ondersoek, is dit moontlik om die `mac_policy_ops`-struktuur te identifiseer wat gebruik is toe die policy geregistreer is. Dit is moontlik om dit te vind omdat sy pointer op ’n offset binne **`mpo_policy_conf`** is en ook weens die hoeveelheid NULL-pointers wat in daardie area sal wees.

Verder is dit ook moontlik om die lys van kexts wat ’n policy gekonfigureer het te kry deur uit memory die struct **`_mac_policy_list`** te dump, wat met elke policy wat geregistreer word opgedateer word.

Jy kan ook die tool `xnoop` gebruik om al die policies wat in die stelsel geregistreer is te dump:
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
En dan gooi al die kontroles van die check policy met:
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
## MACF initialisation in XNU

### Early bootstrap and mac_policy_init()

- MACF word baie vroeg geïnitialiseer. In `bootstrap_thread` (in XNU startup code), na `ipc_bootstrap`, roep XNU `mac_policy_init()` aan (in `mac_base.c`).
- `mac_policy_init()` initialiseer die globale `mac_policy_list` (’n array of list van policy slots) en stel die infrastruktuur vir MAC (Mandatory Access Control) binne XNU op.
- Later word `mac_policy_initmach()` geroep, wat die kernel-kant van policy registration vir ingeboude of gebundelde policies hanteer.

### `mac_policy_initmach()` and loading “security extensions”

- `mac_policy_initmach()` ondersoek kernel extensions (kexts) wat vooraf gelaai is (or in ’n “policy injection” list) en inspekteer hul Info.plist vir die sleutel `AppleSecurityExtension`.
- Kexts wat `<key>AppleSecurityExtension</key>` (or `true`) in hul Info.plist verklaar, word as “security extensions” beskou — m.a.w. dié wat ’n MAC policy implementeer or in die MACF-infrastruktuur hook.
- Voorbeelde van Apple kexts met daardie sleutel sluit in **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, onder andere (soos jy reeds gelys het).
- Die kernel verseker dat daardie kexts vroeg gelaai word, en roep dan hul registration routines aan (via `mac_policy_register`) tydens boot, en voeg hulle in die `mac_policy_list` in.

- Elke policy module (kext) verskaf ’n `mac_policy_conf` structure, met hooks (`mpc_ops`) vir verskeie MAC operations (vnode checks, exec checks, label updates, ens.).
- Die load time flags kan `MPC_LOADTIME_FLAG_NOTLATE` insluit wat beteken “must be loaded early” (dus word laat registration attempts geweier).
- Sodra geregistreer, kry elke module ’n handle en neem ’n slot in `mac_policy_list` op.
- Wanneer ’n MAC hook later aangeroep word (byvoorbeeld, vnode access, exec, ens.), iterer MACF oor al die geregistreerde policies om kollektiewe besluite te neem.

- In die besonder is **AMFI** (Apple Mobile File Integrity) so ’n security extension. Sy Info.plist sluit `AppleSecurityExtension` in wat dit as ’n security policy merk.
- As deel van kernel boot verseker die kernel load logic dat die “security policy” (AMFI, ens.) reeds aktief is voordat baie subsystems daarvan afhanklik word. Byvoorbeeld, die kernel “prepares for tasks ahead by loading … security policy, including AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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

Wanneer jy 'n kext skryf wat die MAC framework gebruik (d.w.s. `mac_policy_register()` ens. aanroep), moet jy afhanklikhede op KPI's (Kernel Programming Interfaces) verklaar sodat die kext linker (kxld) daardie symbols kan oplos. SO om te verklaar dat 'n `kext` van MACF afhanklik is, moet jy dit in die `Info.plist` met `com.apple.kpi.dsep` aandui (`find . Info.plist | grep AppleSecurityExtension`), dan sal die kext na symbols soos `mac_policy_register`, `mac_policy_unregister`, en MAC hook function pointers verwys. Om dié op te los, moet jy `com.apple.kpi.dsep` as 'n dependency lys.

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
## MACF op moderne macOS-vrystellings

Op moderne macOS word Apple-sekuriteitsbeleid gewoonlik nie die beste benader as losstaande `.kext` bundels nie. Sedert **macOS 11** word kernel extensions in **kernel collections** gekoppel; op **Apple Silicon** is daar geen aparte **SystemKC** nie, en derdeparty-kexts word eers laaibaar nadat hulle in die **Auxiliary Kernel Collection (AuxKC)** gebou is en ’n herlaai plaasgevind het. Vir MACF-navorsing beteken dit dat ingeboude beleid soos **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** of **Quarantine** gewoonlik makliker met `kmutil` as met verouderde gereedskap soos `kextstat` gelys kan word.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Op Apple Silicon, as 'n security kext nie in die BootKC is nie, kyk volgende in die AuxKC. Dit is gewoonlik meer nuttig as om te soek vir 'n standalone bundle onder `/System/Library/Extensions`.

## MACF Callouts

Dit is algemeen om callouts na MACF te vind wat in kode gedefinieer is soos: **`#if CONFIG_MAC`** voorwaardelike blokke. Verder is dit binne hierdie blokke moontlik om aanroepe na `mac_proc_check*` te vind, wat MACF roep om **permissions te check** om sekere actions uit te voer. Verder is die formaat van die MACF callouts: **`mac_<object>_<opType>_opName`**.

Die object is een van die volgende: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
Die `opType` is gewoonlik check wat gebruik sal word om die action toe te laat of te weier. Dit is egter ook moontlik om `notify` te vind, wat die kext sal toelaat om op die gegewe action te reageer.

Jy kan 'n voorbeeld vind in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Dan is dit moontlik om die kode van `mac_file_check_mmap` te vind in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Which is calling the `MAC_CHECK` macro, whose code can be found in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Which will oor al die geregistreerde MAC-beleide gaan, hul funksies aanroep en die uitvoer binne die error-variabele stoor, wat slegs deur `mac_error_select` met sukses-kodes oorskryf sal kan word, so as enige check faal sal die volledige check faal en die action nie toegelaat word nie.

> [!TIP]
> Onthou egter dat nie alle MACF callouts net gebruik word om actions te weier nie. Byvoorbeeld, `mac_priv_grant` roep die macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) aan, wat die versoekte privilege sal grant as enige policy met `0` antwoord:
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

These callas is bedoel om **privileges** wat in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) gedefinieer is, te check en te provide.\
Sommige kernel code sal `priv_check_cred()` vanaf [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) met die KAuth credentials van die process en een van die privileges code aanroep, wat `mac_priv_check` sal aanroep om te sien of enige policy die gee van die privilege **denies**, en dan roep dit `mac_priv_grant` aan om te sien of enige policy die `privilege` grant.

### proc_check_syscall_unix

Hierdie hook laat toe om alle system calls te intercept. In `bsd/dev/[i386|arm]/systemcalls.c` is dit moontlik om die verklaarde function [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) te sien, wat hierdie code bevat:
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
Wat sal in die aanroepende proses se **bitmask** nagaan of die huidige syscall `mac_proc_check_syscall_unix` moet aanroep. Dit is omdat syscalls so gereeld geroep word dat dit interessant is om te vermy om `mac_proc_check_syscall_unix` elke keer aan te roep.

Let daarop dat die funksie `proc_set_syscall_filter_mask()`, wat die bitmask syscalls in ’n proses stel, deur Sandbox geroep word om masks op sandboxed prosesse te stel.

## Blootgestelde MACF syscalls

Dit is moontlik om met MACF te interaksie deur sommige syscalls wat in [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) gedefinieer is:
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
Vir aanstootlike reversing is **`__mac_syscall`** steeds een van die beste userland chokepoints. Dit dra ’n **policy name** by, byvoorbeeld `"Sandbox"` of `"AMFI"`, ’n **policy-specific selector/code**, en ’n wyser na die **opaque argument blob** wat deur `mpo_policy_syscall` hanteer sal word. Dit is baie nuttig wanneer jy undocumented operations eers vanaf userland reverse en eers later in die kernel implementation pivot. Sandbox bereik dit gewoonlik via `__sandbox_ms`, en AMFI gebruik dieselfde meganisme vir dyld policy decisions.

## Praktiese offensiewe navorsingsnotas

Onlangse macOS-bugs “breek” selde MACF direk. In plaas daarvan misbruik hulle gewoonlik ’n **desynchronisation tussen ’n MACF / Sandbox / TCC decision en die privileged action wat later gebeur**.

### Broker path checks vs real privileged action

’n Herhalende patroon is ’n privileged daemon wat ’n **userland pre-check** uitvoer, byvoorbeeld `sandbox_check_by_audit_token()`, op een weergawe van ’n path, en later die werklike privileged sink uitvoer met ’n **ander of nie-kanonieke aanvaller-beheerde path**. Onlangse `diskarbitrationd` / `storagekitd` navorsing is ’n goeie voorbeeld: **directory traversal** plus **symlink swaps** laat die aanvaller toe om die daemon se sandbox validation te slaag en dan oor sensitiewe liggings soos `~/Library/Application Support/com.apple.TCC` te mount, wat die bug in ’n **sandbox escape**, **local privilege escalation** of **TCC bypass** omskep, afhangend van die gekose mount point.

Wanneer jy root brokers oudit wat vanaf die sandbox bereik kan word, grep eers vir:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- privileged sinks soos `mount`, `rename`, `copyfile`, helper-tool XPC methods, of enigiets wat later attacker-controlled paths as root raak

### Trusted deputies met private entitlements

Nog ’n praktiese patroon is om nie MACF hooks direk aan te val nie, maar eerder ’n **trusted process** te misbruik wat reeds die regte dra wat nodig is om die grens oor te steek. Onlangse Safari/TCC-navorsing is ’n goeie voorbeeld: die interessante primitive was nie “disable TCC in the kernel” nie, maar om local policy/configuration te verander sodat ’n Apple-gesigneerde proses met **`com.apple.private.tcc.allow`** die sensitiewe aksie namens jou uitvoer. In die praktyk is hoë-waarde ouditdoelwitte Apple daemons/apps wat kombineer:

- **private entitlements** of FDA-like reach
- ’n skryfbare config / database / mount point / policy file
- ’n latere sensitiewe operasie wat deur **Sandbox**, **AMFI**, **TCC** of ’n ander MACF policy gemedieer word

Vir dieper product-specific reversing, kyk na die toegewyde bladsye oor [macOS Sandbox](macos-sandbox/README.md) en [macOS TCC](macos-tcc/README.md).

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
