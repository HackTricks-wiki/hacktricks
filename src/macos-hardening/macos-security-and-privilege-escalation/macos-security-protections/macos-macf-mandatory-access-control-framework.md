# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

**MACF** staan vir **Mandatory Access Control Framework**, wat 'n sekuriteitstelsel is ingebou in die bedryfstelsel om jou rekenaar te help beskerm. Dit werk deur **streng reëls te stel oor wie of wat sekere dele van die stelsel kan benader**, soos lêers, toepassings en stelselhulpbronne. Deur hierdie reëls outomaties af te dwing, verseker MACF dat slegs gemagtigde gebruikers en prosesse sekere aksies kan uitvoer, wat die risiko van ongemagtigde toegang of kwaadwillige aktiwiteite verminder.

Let daarop dat MACF nie regtig besluite neem nie aangesien dit net aksies **intercepts**, dit laat die besluite oor aan die **policy modules** (kernel extensions) wat dit aanroep soos `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` en `mcxalr.kext`.

- 'n Beleid kan afdwingend wees (return 0 non-zero op sekere operasie)
- 'n Beleid kan moniterend wees (return 0, sodat dit nie beswaar maak nie maar op die hook kan meelif om iets te doen)
- 'n MACF statiese beleid word by boot geïnstalleer en sal NOOIT verwyder word nie
- 'n MACF dinamiese beleid word deur 'n KEXT geïnstalleer (kextload) en mag hipoteties kextunloaded word
- In iOS word slegs statiese beleide toegelaat en in macOS staties + dinamies.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flow

1. Proses voer 'n syscall/mach trap uit
2. Die relevante funksie word binne die kernel aangeroep
3. Die funksie roep MACF aan
4. MACF kontroleer beleidsmodules wat versoek het om daardie funksie in hul beleid te hook
5. MACF roep die relevante beleide aan
6. Beleide dui aan of hulle die aksie toelaat of weier

> [!CAUTION]
> Apple is die enigste een wat die MAC Framework KPI kan gebruik.

Gewoonlik sal die funksies wat permissies met MACF nagaan die macro `MAC_CHECK` aanroep. Soos in die geval van 'n syscall om 'n socket te skep wat die funksie `mac_socket_check_create` aanroep wat op sy beurt `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` aanroep. Verder is die macro `MAC_CHECK` gedefinieer in security/mac_internal.h as:
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
Let op dat deur `check` te transformeer na `socket_check_create` en `args...` in `(cred, domain, type, protocol)` kry jy:
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
Deur die hulp-makros uit te brei, word die konkrete beheerstroom getoon:
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
Met ander woorde, `MAC_CHECK(socket_check_create, ...)` deurloop eers die statiese beleide, vergrendel voorwaardelik en iterate oor die dinamiese beleide, stuur die DTrace probes rondom elke hook uit, en vou elke hook se terugkeerkode saam tot die enkele `error` resultaat via `mac_error_select()`.


### Etikette

MACF gebruik **etikette** wat dan deur die beleide gebruik word om te bepaal of toegang toegestaan moet word of nie. Die kode van die label-struktuurdeklaring kan [hier gevind word](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), wat dan binne die **`struct ucred`** gebruik word in [**hier**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) in die **`cr_label`** gedeelte. Die label bevat vlae en 'n aantal **slots** wat deur **MACF-beleide gebruik kan word om pointers toe te ken**. Byvoorbeeld Sal Sanbox na die container profile wys

## MACF-beleide

'n MACF-beleid definieer **reëls en voorwaardes wat in sekere kernel-operasies toegepas word**.

'n kernel-uitbreiding kan 'n `mac_policy_conf` struct konfigureer en dit dan registreer deur `mac_policy_register` aan te roep. Vanaf [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Dit is maklik om die kernel-uitbreidings wat hierdie beleide konfigureer te identifiseer deur die oproepe na `mac_policy_register` na te gaan. Verder, deur die uitbreiding se ontleding na te gaan, is dit ook moontlik om die gebruikte `mac_policy_conf` struct te vind.

Let wel dat MACF-beleide ook **dinamies** geregistreer en gederegistreer kan word.

Een van die hoofvelde van die `mac_policy_conf` is die **`mpc_ops`**. Hierdie veld spesifiseer aan watter operasies die beleid belangstel. Let daarop dat daar honderde daarvan is, so dit is moontlik om almal na nul te stel en dan slegs dié te kies waarin die beleid belangstel. Van [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Byna al die hooks sal deur MACF teruggeroep word wanneer een van daardie operasies onderskep word. Nietemin is die **`mpo_policy_*`** hooks ’n uitsondering omdat `mpo_hook_policy_init()` ’n callback is wat by registrasie aangeroep word (dus na `mac_policy_register()`) en `mpo_hook_policy_initbsd()` tydens latere registrasie aangeroep word wanneer die BSD-substelsel behoorlik geïnitialiseer is.

Verder kan die **`mpo_policy_syscall`** hook deur enige kext geregistreer word om ’n private **ioctl** style call **interface** bloot te lê. Dan sal ’n user client `mac_syscall` (#381) kan aanroep en as parameters die **naam van die beleid** met ’n heelgetal **kode** en opsionele **argumente** spesifiseer.\
Byvoorbeeld, die **`Sandbox.kext`** gebruik dit gereeld.

Deur die kext se **`__DATA.__const*`** na te gaan, is dit moontlik om die `mac_policy_ops` struktuur te identifiseer wat gebruik is toe die beleid geregistreer is. Dit is moontlik om dit te vind omdat sy pointer op ’n offset binne `mpo_policy_conf` is en ook as gevolg van die aantal NULL pointers wat in daardie area sal wees.

Verder is dit ook moontlik om die lys kexts wat ’n beleid gekonfigureer het te kry deur die struktuur **`_mac_policy_list`** uit geheue te dump, wat bygewerk word met elke beleid wat geregistreer word.

Jy kan ook die hulpmiddel `xnoop` gebruik om al die beleide wat in die stelsel geregistreer is uit te dump:
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
En dan dump alle kontroles van check policy met:
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
## MACF-initialisering in XNU

### Vroeë opstart en mac_policy_init()

- MACF word baie vroeg geïnitialiseer. In `bootstrap_thread` (in XNU-opstartkode), na `ipc_bootstrap`, roep XNU `mac_policy_init()` (in `mac_base.c`).
- `mac_policy_init()` initialiseer die globale `mac_policy_list` (an array or list of policy slots) en stel die infrastruktuur vir MAC (Mandatory Access Control) binne XNU op.
- Later word `mac_policy_initmach()` aangeroep, wat die kernelkant van beleidregistrasie vir ingeboude of gebundelde beleide hanteer.

### `mac_policy_initmach()` and loading “security extensions”

- `mac_policy_initmach()` ondersoek kernel extensions (kexts) wat vooraf gelaai is (of in ’n “policy injection” list) en inspekteer hul Info.plist vir die sleutel `AppleSecurityExtension`.
- Kexts wat `<key>AppleSecurityExtension</key>` (of `true`) in hul Info.plist verklaar, word beskou as “security extensions” — d.w.s. dié wat ’n MAC-beleid implementeer of aan die MACF-infrastruktuur koppel.
- Voorbeelde van Apple kexts met daardie sleutel sluit in **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, onder andere (soos jy reeds gelys het).
- Die kernel sorg dat daardie kexts vroeg gelaai word, en roep dan hul registrasie-roetines (via `mac_policy_register`) tydens boot aan, en voeg hulle in die `mac_policy_list` in.

- Elke beleidsmodule (kext) verskaf ’n `mac_policy_conf` struktuur, met hooks (`mpc_ops`) vir verskeie MAC-operasies (vnode checks, exec checks, label updates, ens.).
- Die laaityd-vlae mag `MPC_LOADTIME_FLAG_NOTLATE` insluit wat beteken “moet vroeg gelaai word” (sodat laat registrasiepogings afgekeur word).
- Sodra geregistreer, kry elke module ’n handle en beset ’n slot in `mac_policy_list`.
- Wanneer ’n MAC-hook later aangeroep word (byvoorbeeld vnode access, exec, ens.), iterereer MACF oor alle geregistreerde beleide om kollektiewe besluite te neem.

- In die besonder is **AMFI** (Apple Mobile File Integrity) so ’n security extension. Sy Info.plist sluit `AppleSecurityExtension` in wat dit as ’n security policy merk.
- As deel van kernel-boot sorg die kernel se laaislogika dat die “security policy” (AMFI, ens.) reeds aktief is voordat baie subsisteme daarvan afhanklik raak. Byvoorbeeld, die kernel “prepares for tasks ahead by loading … security policy, including AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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
## KPI afhanklikheid & com.apple.kpi.dsep in MAC policy kexts

Wanneer jy 'n kext skryf wat die MAC framework gebruik (bv. deur `mac_policy_register()` te noem, ens.), moet jy afhanklikhede op KPIs (Kernel Programming Interfaces) verklaar sodat die kext linker (kxld) daardie simbole kan oplos. Dus, om te verklaar dat 'n `kext` van MACF afhanklik is, moet jy dit in die `Info.plist` aandui met `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`); dan sal die kext verwys na simbole soos `mac_policy_register`, `mac_policy_unregister`, en MAC hook-funksie-aanwysers. Om daardie simbole op te los, moet jy `com.apple.kpi.dsep` as 'n afhanklikheid lys.

Voorbeeld Info.plist-stukkie (binne jou .kext):
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
## MACF-oproepe

Dit is algemeen om oproepe na MACF in kode te vind, soos in kondisionele blokke **`#if CONFIG_MAC`**. Verder is dit binne hierdie blokke moontlik om oproepe na `mac_proc_check*` te vind, wat MACF aanroep om **toestemmings te kontroleer** om sekere aksies uit te voer. Die formaat van die MACF-oproepe is: **`mac_<object>_<opType>_opName`**.

Die object is een van die volgende: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
Die `opType` is gewoonlik check wat gebruik sal word om die aksie toe te laat of te weier. Dit is egter ook moontlik om `notify` te vind, wat die kext in staat sal stel om op die gegewe aksie te reageer.

You can find an example in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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
Wat die `MAC_CHECK`-makro aanroep, waarvan die kode gevind kan word by [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Wat oor al die geregistreerde mac-beleide sal loop, hul funksies sal aanroep en die uitset in die error-variabele sal stoor, wat slegs deur `mac_error_select` met sukses-kodes oorskryfbaar is; as enige kontrole misluk sal die hele kontrole misluk en sal die aksie nie toegelaat word nie.

> [!TIP]
> Onthou egter dat nie alle MACF-callouts net gebruik word om aksies te weier nie. Byvoorbeeld, `mac_priv_grant` roep die macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) aan, wat die aangevraagde voorreg sal toeken indien enige beleid met '0' reageer:
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

Hierdie callas is bedoel om (tientalle) **privileges** te kontroleer en te voorsien wat gedefinieer is in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Sommige kernel-kode sal `priv_check_cred()` uit [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) met die KAuth credentials van die proses en een van die privileges-kodes aanroep; dit sal `mac_priv_check` aanroep om te sien of enige beleid die toekenning van die voorreg **weier**, en daarna `mac_priv_grant` om te sien of enige beleid daardie `privilege` toeken.

### proc_check_syscall_unix

Hierdie hook maak dit moontlik om alle system calls te onderskep. In `bsd/dev/[i386|arm]/systemcalls.c` is dit moontlik om die gedeclareerde funksie [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) te sien, wat die volgende kode bevat:
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
Wat sal in die oproepende proses se **bitmask** nagaan of die huidige syscall `mac_proc_check_syscall_unix` moet aanroep. Dit is omdat syscalls so gereeld aangeroep word dat dit sinvol is om te vermy om `mac_proc_check_syscall_unix` elke keer aan te roep.

Neem kennis dat die funksie `proc_set_syscall_filter_mask()`, wat die bitmask vir syscalls in 'n proses stel, deur Sandbox aangeroep word om maskers op gesandboxeerde prosesse te stel.

## Blootgestelde MACF syscalls

Dit is moontlik om met MACF te kommunikeer via sommige syscalls wat in [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) gedefinieer is:
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
## Verwysings

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}
