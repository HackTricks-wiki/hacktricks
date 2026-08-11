# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

**MACF** staan vir **Mandatory Access Control Framework**, ’n sekuriteitstelsel wat in die bedryfstelsel ingebou is om jou rekenaar te help beskerm. Dit werk deur **streng reëls te stel oor wie of wat toegang tot sekere dele van die stelsel kan verkry**, soos lêers, toepassings en stelselhulpbronne. Deur hierdie reëls outomaties af te dwing, verseker MACF dat slegs gemagtigde gebruikers en prosesse spesifieke handelinge kan uitvoer, wat die risiko van ongemagtigde toegang of kwaadwillige aktiwiteite verminder.

Let daarop dat MACF nie werklik enige besluite neem nie, aangesien dit slegs handelinge **onderskep**. Dit laat die besluite aan die **beleidsmodules** (kernel-uitbreidings) wat dit aanroep, soos `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` en `mcxalr.kext`.

- ’n Beleid kan afdwingend wees (return 0 non-zero on some operation)
- ’n Beleid kan moniterend wees (return 0, so as not to object but piggyback on hook to do something)
- ’n MACF-statiese beleid word tydens boot geïnstalleer en sal NOOIT verwyder word nie
- ’n MACF-dinamiese beleid word deur ’n KEXT (kextload) geïnstalleer en kan hipoteties kextunloaded word
- In iOS word slegs statiese beleide toegelaat, en in macOS statiese + dinamiese beleide.<sup>[[7]](#references)</sup>

### Vloei

1. Proses voer ’n syscall/mach trap uit
2. Die relevante funksie word binne die kernel aangeroep
3. Funksie roep MACF aan
4. MACF kontroleer die beleidsmodules wat versoek het om daardie funksie in hul beleid te hook
5. MACF roep die relevante beleide aan
6. Beleide dui aan of hulle die handeling toelaat of weier

> [!CAUTION]
> Apple is die enigste een wat die MAC Framework KPI kan gebruik.

Gewoonlik sal die funksies wat toestemmings met MACF kontroleer, die makro `MAC_CHECK` aanroep. Soos in die geval van ’n syscall om ’n socket te skep, wat die funksie `mac_socket_check_create` sal aanroep, wat op sy beurt `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` aanroep. Daarbenewens word die makro `MAC_CHECK` in security/mac_internal.h gedefinieer as:<sup>[[3]](#references)</sup>
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
Let daarop dat wanneer jy `check` na `socket_check_create` en `args...` na `(cred, domain, type, protocol)` transformeer, jy kry:
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
Deur die helper-makro's uit te brei, word die konkrete beheervloei sigbaar:
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
Met ander woorde, `MAC_CHECK(socket_check_create, ...)` loop eers deur die statiese beleide, sluit voorwaardelik en itereer deur die dinamiese beleide, stuur die DTrace probes rondom elke hook uit, en voeg elke hook se terugkeerkode saam tot die enkele `error`-resultaat via `mac_error_select()`.


### Etikette

MACF gebruik **etikette** wat die beleide dan sal gebruik om te bepaal of hulle toegang moet toestaan of nie. Die kode van die etikette-struktuur se deklarasie kan [hier gevind word](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), wat dan binne die **`struct ucred`** in [**hierdie deel**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) in die **`cr_label`**-deel gebruik word. Die etiket bevat vlae en ’n aantal **gleuwe** wat deur **MACF-beleide gebruik kan word om pointers toe te ken**. Sandbox sal byvoorbeeld na die container-profiel wys.

## MACF-beleide

’n MACF-beleid definieer **reëls en voorwaardes wat in sekere kernel-bewerkings toegepas moet word**.

’n Kernel-uitbreiding kan ’n `mac_policy_conf`-struktuur opstel en dit dan registreer deur `mac_policy_register` aan te roep. Vanaf [hierdie bron](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
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
Dit is maklik om die kernel extensions wat hierdie beleide konfigureer, te identifiseer deur oproepe na `mac_policy_register` na te gaan. Deur die disassemble van die extension na te gaan, is dit boonop ook moontlik om die gebruikte `mac_policy_conf`-struktuur te vind.

Let daarop dat MACF-beleide ook **dinamies** geregistreer en gederegistreer kan word.

Een van die belangrikste velde van `mac_policy_conf` is **`mpc_ops`**. Hierdie veld spesifiseer in watter bewerkings die beleid belangstel. Daar is honderde daarvan, dus is dit moontlik om alle inskrywings na nul te stel en dan slegs dié te kies wat die beleid benodig. Van [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
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
Byna al die hooks sal deur MACF teruggeroep word wanneer een van daardie operasies onderskep word. Die **`mpo_policy_*`**-hooks is egter ’n uitsondering, omdat `mpo_hook_policy_init()` ’n callback is wat tydens registrasie geroep word (dus ná `mac_policy_register()`), en `mpo_hook_policy_initbsd()` tydens laat registrasie geroep word sodra die BSD-substelsel behoorlik geïnisialiseer is.

Verder kan die **`mpo_policy_syscall`**-hook deur enige kext geregistreer word om ’n private **ioctl**-styl oproep-**interface** bloot te stel. ’n User client sal dan `mac_syscall` (#381) kan roep deur die **policy name** met ’n heelgetal-**code** en opsionele **arguments** as parameters te spesifiseer.\
Byvoorbeeld, die **`Sandbox.kext`** gebruik dit baie.

Deur die kext se **`__DATA.__const*`** na te gaan, is dit moontlik om die `mac_policy_ops`-struktuur te identifiseer wat gebruik word wanneer die policy geregistreer word. Dit is moontlik om dit te vind omdat sy pointer op ’n offset binne `mpo_policy_conf` is, asook weens die hoeveelheid NULL-pointers wat in daardie area sal wees.

Verder is dit ook moontlik om die lys kexts te kry wat ’n policy gekonfigureer het deur die **`_mac_policy_list`**-struktuur, wat met elke geregistreerde policy opgedateer word, uit die geheue te dump.

Jy kan ook die `xnoop`-tool gebruik om al die policies wat in die stelsel geregistreer is te dump:
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
En dump dan al die checks van check policy met:
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
## MACF-inisialisering in XNU

### Vroeë bootstrap en mac_policy_init()

- MACF word baie vroeg geïnisialiseer. In `bootstrap_thread` (in XNU se opstartkode) roep XNU, ná `ipc_bootstrap`, `mac_policy_init()` (in `mac_base.c`) aan.
- `mac_policy_init()` inisialiseer die globale `mac_policy_list` ('n skikking of lys van beleidsplekke) en stel die infrastruktuur vir MAC (Mandatory Access Control) binne XNU op.
- Later word `mac_policy_initmach()` aangeroep, wat die kerne l se kant van beleidsregistrasie vir ingeboude of gebundelde beleide hanteer.

### `mac_policy_initmach()` en die laai van “sekuriteitsuitbreidings”

- `mac_policy_initmach()` ondersoek kerne l-uitbreidings (kexts) wat vooraf gelaai is (of in 'n “policy injection”-lys is) en inspekteer hul Info.plist vir die sleutel `AppleSecurityExtension`.
- Kexts wat `<key>AppleSecurityExtension</key>` (of `true`) in hul Info.plist verklaar, word as “sekuriteitsuitbreidings” beskou — dit wil sê dié wat 'n MAC-beleid implementeer of by die MACF-infrastruktuur inskakel.
- Voorbeelde van Apple-kexts met daardie sleutel sluit **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, en ander in (soos jy reeds gelys het).
- Die kern verseker dat daardie kexts vroeg gelaai word, en roep dan hul registrasieroetines (via `mac_policy_register`) tydens boot aan, waardeur hulle in die `mac_policy_list` ingevoeg word.

- Elke beleidsmodule (kext) verskaf 'n `mac_policy_conf`-struktuur met hooks (`mpc_ops`) vir verskeie MAC-bewerkings (vnode-kontroles, exec-kontroles, etiketopdaterings, ens.).
- Die laaitydvlae kan `MPC_LOADTIME_FLAG_NOTLATE` insluit, wat beteken “moet vroeg gelaai word” (sodat laat registrasiepogings afgekeur word).
- Nadat dit geregistreer is, kry elke module 'n handvatsel en beslaan dit 'n plek in `mac_policy_list`.
- Wanneer 'n MAC-hook later aangeroep word (byvoorbeeld vir vnode-toegang, exec, ens.), itereer MACF deur alle geregistreerde beleide om gesamentlike besluite te neem.

- Veral **AMFI** (Apple Mobile File Integrity) is so 'n sekuriteitsuitbreiding. Sy Info.plist sluit `AppleSecurityExtension` in, wat dit as 'n sekuriteitsbeleid merk.
- As deel van die kernel boot verseker die kernel-laailogika dat die “sekuriteitsbeleid” (AMFI, ens.) reeds aktief is voordat baie subsisteme daarvan afhanklik raak. Die kernel “berei byvoorbeeld voor vir take wat voorlê deur … sekuriteitsbeleid, insluitend AppleMobileFileIntegrity (AMFI), Sandbox en Quarantine-beleid, te laai.”
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
## KPI-afhanklikheid & com.apple.kpi.dsep in MAC-policy-kexts

Wanneer jy ’n kext skryf wat die MAC-framework gebruik (d.w.s. `mac_policy_register()` ens.), moet jy afhanklikhede op KPI’s (Kernel Programming Interfaces) verklaar sodat die kext-linker (kxld) daardie simbole kan oplos. Dus, om te verklaar dat ’n `kext` van MACF afhanklik is, moet jy dit in die `Info.plist` aandui met `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`); daarna sal die kext na simbole soos `mac_policy_register`, `mac_policy_unregister` en MAC-hook-funksiewysers verwys. Om dit op te los, moet jy `com.apple.kpi.dsep` as ’n afhanklikheid lys.

Voorbeeld van ’n `Info.plist`-brokkie (binne jou .kext):
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

Op moderne macOS word Apple-sekuriteitsbeleide gewoonlik nie die beste benader as losstaande `.kext`-bundels nie. Sedert **macOS 11** word kernel extensions in **kernel collections** gekoppel; op **Apple Silicon** is daar geen aparte **SystemKC** nie, en third-party kexts kan slegs gelaai word nadat hulle in die **Auxiliary Kernel Collection (AuxKC)** ingebou is en die stelsel herbegin is. Vir MACF-navorsing beteken dit dat ingeboude beleide soos **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** of **Quarantine** gewoonlik makliker met `kmutil` opgespoor kan word as met verouderde nutsprogramme soos `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Op Apple Silicon, indien ’n security kext nie in die BootKC is nie, gaan volgende die AuxKC na. Dit is gewoonlik nuttiger as om na ’n standalone bundle onder `/System/Library/Extensions` te soek.

## MACF Callouts

Dit is algemeen om callouts na MACF te vind wat in kode soos **`#if CONFIG_MAC`**-conditional blocks gedefinieer is. Daarbenewens is dit binne hierdie blocks moontlik om calls na `mac_proc_check*` te vind, wat MACF aanroep om **toestemmings te kontroleer** om sekere aksies uit te voer. Die formaat van die MACF-callouts is verder: **`mac_<object>_<opType>_opName`**.

Die object is een van die volgende: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
Die `opType` is gewoonlik check, wat gebruik sal word om die aksie toe te laat of te weier. Dit is egter ook moontlik om `notify` te vind, wat die kext sal toelaat om op die gegewe aksie te reageer.

Jy kan ’n voorbeeld vind by [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Daarna is dit moontlik om die kode van `mac_file_check_mmap` te vind by [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174).
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
Wat die `MAC_CHECK`-makro aanroep, waarvan die kode gevind kan word by [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>.
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
Wat al die geregistreerde mac policies sal deurloop, hul funksies sal aanroep en die uitvoer binne die `error`-veranderlike sal stoor. Hierdie veranderlike kan slegs deur `mac_error_select` met sukses-kodes oorskryf word; dus, indien enige kontrole misluk, sal die volledige kontrole misluk en sal die aksie nie toegelaat word nie.

> [!TIP]
> Onthou egter dat nie alle MACF callouts slegs gebruik word om aksies te weier nie. Byvoorbeeld, `mac_priv_grant` roep die makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) aan, wat die aangevraagde privilege sal toestaan indien enige policy met ’n 0 antwoord:
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

Hierdie callouts is bedoel om die (tientalle) **privileges** wat in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) gedefinieer word, te kontroleer en toe te ken.\
Sekere kernel-kode roep `priv_check_cred()` uit [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) aan met die KAuth credentials van die proses en een van die privilege-kodes. Dit sal `mac_priv_check` aanroep om te bepaal of enige policy die toekenning van die privilege **weier**, en roep daarna `mac_priv_grant` aan om te bepaal of enige policy die `privilege` toestaan.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Hierdie hook laat toe dat alle system calls onderskep word. In `bsd/dev/[i386|arm]/systemcalls.c` kan ’n mens die gedeclareerde funksie [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) sien, wat hierdie kode bevat:
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
Wat in die **bitmask** van die calling process sal kontroleer of die huidige syscall `mac_proc_check_syscall_unix` moet aanroep. Dit is omdat syscalls so gereeld aangeroep word dat dit interessant is om te vermy om `mac_proc_check_syscall_unix` elke keer aan te roep.

Let daarop dat die funksie `proc_set_syscall_filter_mask()`, wat die bitmask-syscalls in 'n process stel, deur Sandbox aangeroep word om masks op sandboxed processes te stel.

## Blootgestelde MACF-syscalls

Dit is moontlik om met MACF te kommunikeer deur sommige syscalls wat in [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) gedefinieer is:
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
Vir offensive reversing bly **`__mac_syscall`** steeds een van die beste userland-knelpunte. Dit dra ’n **policy name** (byvoorbeeld `"Sandbox"` of `"AMFI"`), ’n **policy-specific selector/code**, en ’n pointer na die **opaque argument blob** wat deur `mpo_policy_syscall` hanteer sal word. Dit is baie nuttig wanneer ongedokumenteerde operasies eers vanuit userland gereverse word en later na die kernel-implementering geskuif word. Sandbox bereik dit algemeen via `__sandbox_ms`, en AMFI gebruik dieselfde meganisme vir dyld-policy-besluite.<sup>[[2]](#references)[[5]](#references)</sup>

## Praktiese offensive research-notas

Onlangse macOS-bugs "breek MACF" selde direk. In plaas daarvan misbruik hulle gewoonlik ’n **desynchronisation tussen ’n MACF / Sandbox / TCC-besluit en die bevoorregte aksie wat later plaasvind**.

### Broker path checks teenoor die werklike bevoorregte aksie

’n Herhalende patroon is ’n bevoorregte daemon wat ’n **userland pre-check** (byvoorbeeld `sandbox_check_by_audit_token()`) op een weergawe van ’n path uitvoer, en later die werklike bevoorregte sink met ’n **ander of nie-kanonieke attacker-controlled path** uitvoer. Onlangse `diskarbitrationd` / `storagekitd`-research is ’n goeie voorbeeld: **directory traversal** plus **symlink swaps** laat die attacker toe om die daemon se sandbox-validasie te slaag en dan oor sensitiewe liggings soos `~/Library/Application Support/com.apple.TCC` te mount, wat die bug in ’n **sandbox escape**, **local privilege escalation** of **TCC bypass** verander, afhangend van die gekose mount point.<sup>[[6]](#references)</sup>

Wanneer jy root brokers wat vanaf die sandbox bereikbaar is, audit, grep eers vir:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path-canonicalisation helpers
- bevoorregte sinks soos `mount`, `rename`, `copyfile`, helper-tool XPC methods, of enigiets wat later attacker-controlled paths as root raak

### Trusted deputies met private entitlements

Nog ’n praktiese patroon is om te vermy om MACF hooks direk aan te val en eerder ’n **trusted process** te misbruik wat reeds die regte het wat nodig is om die grens oor te steek. Onlangse Safari/TCC-research is ’n goeie voorbeeld: die interessante primitive was nie "disable TCC in the kernel" nie, maar om plaaslike policy/configuration te wysig sodat ’n Apple-signed process met **`com.apple.private.tcc.allow`** die sensitiewe aksie namens jou uitvoer.<sup>[[8]](#references)</sup> In die praktyk is Apple-daemons/apps wat die volgende kombineer, belangrike audit-teikens:

- **private entitlements** of FDA-like reach
- ’n writable config / database / mount point / policy file
- ’n latere sensitiewe operasie wat deur **Sandbox**, **AMFI**, **TCC** of ’n ander MACF-policy bemiddel word

Vir dieper product-specific reversing, raadpleeg die toegewyde bladsye oor [macOS Sandbox](macos-sandbox/README.md) en [macOS TCC](macos-tcc/README.md).

## References

- [1] [XNU — `security/mac_policy.h` (die volledige MACF-policy operations vector)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (`MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE` macros)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (privilege codes wat deur `priv_check`/`priv_grant` gebruik word)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Ontbloot Apple-kwesbaarhede: diskarbitrationd- en storagekitd-audit, Deel 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — XNU Cross Reference tool](https://newosxbook.com/xxr/index.php)
- [8] [Nuwe macOS-kwesbaarheid, "HM Surf", kan tot ongemagtigde datatoegang lei (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
{{#include ../../../banners/hacktricks-training.md}}
