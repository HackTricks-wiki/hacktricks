# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

**MACF** znači **Mandatory Access Control Framework**, što je bezbednosni sistem ugrađen u operativni sistem da pomogne u zaštiti vašeg računara. Radi tako što postavlja **stroga pravila o tome ko ili šta može da pristupi određenim delovima sistema**, kao što su fajlovi, aplikacije i sistemski resursi. Primenom ovih pravila automatski, MACF obezbeđuje da samo autorizovani korisnici i procesi mogu da izvršavaju određene akcije, smanjujući rizik od neovlašćenog pristupa ili zlonamernih aktivnosti.

Imajte na umu da MACF zapravo ne donosi nikakve odluke, već samo **presreće** akcije; odluke prepušta **policy modules** (kernel extensions) koje poziva, kao što su `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` i `mcxalr.kext`.

- Policy može biti enforcing (vratiti 0 non-zero na nekoj operaciji)
- Policy može biti monitoring (vratiti 0, kako se ne bi protivio, ali da iskoristi hook da uradi nešto)
- MACF static policy se instalira pri boot-u i NIKADA neće biti uklonjen
- MACF dynamic policy instalira KEXT (kextload) i hipotetički može biti kextunloaded
- U iOS su dozvoljeni samo static policies, a u macOS static + dynamic.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Tok

1. Process izvršava syscall/mach trap
2. Relevantna funkcija se poziva unutar kernela
3. Funkcija poziva MACF
4. MACF proverava policy modules koji su zatražili da hook-uju tu funkciju u svom policy-ju
5. MACF poziva relevantne policies
6. Policies pokazuju da li dozvoljavaju ili odbijaju akciju

> [!CAUTION]
> Apple is the only one that can use the MAC Framework KPI.

Obično će funkcije koje proveravaju dozvole pomoću MACF pozivati makro `MAC_CHECK`. Kao u slučaju syscall-a za kreiranje socket-a koji će pozvati funkciju koja `mac_socket_check_create` koja poziva `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Štaviše, makro `MAC_CHECK` je definisan u security/mac_internal.h kao:
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
Imajte na umu da transformisanjem `check` u `socket_check_create` i `args...` u `(cred, domain, type, protocol)` dobijate:
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
Širenje pomoćnih makroa prikazuje konkretan tok kontrole:
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
Drugim rečima, `MAC_CHECK(socket_check_create, ...)` prvo prolazi kroz statičke politike, uslovno zaključava i iterira kroz dinamičke politike, emituje DTrace probe oko svakog hook-a i sabija svaki povratni kod hook-a u jedan `error` rezultat preko `mac_error_select()`.


### Labels

MACF koristi **labels** koje zatim politike, dok proveravaju da li treba da odobre neki pristup ili ne, koriste. Kod deklaracije strukture labels može se [naći ovde](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), a zatim se koristi unutar **`struct ucred`** [**ovde**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) u delu **`cr_label`**. Label sadrži flagove i broj **slots** koji mogu da se koriste da bi **MACF policies alocirale pointere**. Na primer Sanbox će pokazivati na container profile

## MACF Policies

MACF Policy definiše **pravila i uslove koji se primenjuju na određene kernel operacije**.

Kernel ekstenzija može da konfiguriše `mac_policy_conf` struct i zatim da je registruje pozivanjem `mac_policy_register`. From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Lako je identifikovati kernel ekstenzije koje konfigurišu ove politike proverom poziva ka `mac_policy_register`. Takođe, pregledom disasembliranog koda ekstenzije moguće je pronaći i korišćenu `mac_policy_conf` strukturu.

Imajte na umu da se MACF politike mogu registrovati i odjaviti i **dinamički**.

Jedno od glavnih polja `mac_policy_conf` je **`mpc_ops`**. Ovo polje određuje na koje je operacije politika zainteresovana. Imajte na umu da ih ima na stotine, pa je moguće postaviti sve na nulu, a zatim izabrati samo one za koje je politika zainteresovana. Iz [ovde](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Skoro svi hooks će biti pozvani nazad od strane MACF kada se jedna od tih operacija presretne. Međutim, **`mpo_policy_*`** hooks su izuzetak jer je **`mpo_hook_policy_init()`** callback koji se poziva pri registraciji (dakle posle `mac_policy_register()`) a **`mpo_hook_policy_initbsd()`** se poziva tokom kasne registracije, nakon što je BSD subsystem pravilno inicijalizovan.

Takođe, **`mpo_policy_syscall`** hook može da registruje bilo koji kext da bi izložio privatni **ioctl** stil **interface**. Zatim će user client moći da pozove `mac_syscall` (#381) navodeći kao parametre **policy name** sa celobrojnim **code** i opcionim **arguments**.\
Na primer, **`Sandbox.kext`** ovo mnogo koristi.

Provera kext-ovog **`__DATA.__const*`** je moguća da bi se identifikovala struktura `mac_policy_ops` koja se koristi pri registraciji policy-ja. Moguće ju je pronaći zato što se njen pointer nalazi na offsetu unutar `mpo_policy_conf` i takođe zbog količine NULL pointera koji će se nalaziti u toj oblasti.

Takođe, moguće je dobiti listu kext-ova koji su konfigurisali policy tako što se iz memorije dump-uje struktura **`_mac_policy_list`** koja se ažurira sa svakim policy-jem koji se registruje.

Možeš takođe da koristiš alat `xnoop` da dump-uje sve policy-je registrovane u sistemu:
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
A zatim izbaci sve provere iz check policy sa:
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
## MACF inicijalizacija u XNU

### Rani bootstrap i `mac_policy_init()`

- MACF se inicijalizuje veoma rano. U `bootstrap_thread` (u XNU startup code), nakon `ipc_bootstrap`, XNU poziva `mac_policy_init()` (u `mac_base.c`).
- `mac_policy_init()` inicijalizuje globalni `mac_policy_list` (niz ili listu slotova za policy) i postavlja infrastrukturu za MAC (Mandatory Access Control) unutar XNU.
- Kasnije se poziva `mac_policy_initmach()`, koja obrađuje kernel stranu registracije policy-ja za ugrađene ili bundled policy-je.

### `mac_policy_initmach()` i učitavanje “security extensions”

- `mac_policy_initmach()` ispituje kernel extensions (kexts) koji su unapred učitani (ili se nalaze u listi “policy injection”) i proverava njihov Info.plist za ključ `AppleSecurityExtension`.
- Kexts koji u svom Info.plist imaju `<key>AppleSecurityExtension</key>` (ili `true`) smatraju se “security extensions” — tj. onima koje implementiraju MAC policy ili se kače na MACF infrastrukturu.
- Primeri Apple kexts sa tim ključem uključuju **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, između ostalih (kao što si već naveo).
- Kernel obezbeđuje da se ti kexts učitaju rano, zatim poziva njihove registration routine (preko `mac_policy_register`) tokom boot-a, ubacujući ih u `mac_policy_list`.

- Svaki policy modul (kext) obezbeđuje `mac_policy_conf` strukturu, sa hook-ovima (`mpc_ops`) za različite MAC operacije (vnode checks, exec checks, label updates, itd.).
- Flags pri učitavanju mogu uključivati `MPC_LOADTIME_FLAG_NOTLATE`, što znači “mora biti učitan rano” (pa se kasniji pokušaji registracije odbijaju).
- Nakon registracije, svaki modul dobija handle i zauzima slot u `mac_policy_list`.
- Kada se MAC hook kasnije pozove (na primer, vnode access, exec, itd.), MACF iterira kroz sve registrovane policy-je da bi doneo zajedničke odluke.

- Posebno, **AMFI** (Apple Mobile File Integrity) je takva security extension. Njegov Info.plist sadrži `AppleSecurityExtension`, čime je označen kao security policy.
- Kao deo kernel boot-a, kernel load logic obezbeđuje da je “security policy” (AMFI, itd.) već aktivan pre nego što se mnogi subsystem-i oslone na njega. Na primer, kernel “prepares for tasks ahead by loading … security policy, including AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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

Kada pišete kext koji koristi MAC framework (tj. poziva `mac_policy_register()` itd.), morate deklarisati zavisnosti od KPI-ja (Kernel Programming Interfaces) kako bi kext linker (kxld) mogao da razreši te simbole. Dakle, da biste deklarisali da `kext` zavisi od MACF, morate to naznačiti u `Info.plist` sa `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), tada će se kext referisati na simbole poput `mac_policy_register`, `mac_policy_unregister`, i MAC hook function pointers. Da biste ih razrešili, morate navesti `com.apple.kpi.dsep` kao zavisnost.

Primer Info.plist isečka (unutar vašeg .kext):
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
## MACF na modernim macOS verzijama

Na modernom macOS-u, Apple security policies se obično ne posmatraju najbolje kao labavi samostalni `.kext` bundle-ovi. Od **macOS 11**, kernel extensions se povezuju u **kernel collections**; na **Apple Silicon** ne postoji zaseban **SystemKC**, a third-party kext-ovi postaju loadable tek nakon što budu izgrađeni u **Auxiliary Kernel Collection (AuxKC)** i posle reboot-a. Za MACF research ovo znači da su built-in policies kao što su **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** ili **Quarantine** obično lakše za enumerate sa `kmutil` nego sa deprecated tooling-om kao što je `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Na Apple Silicon, ako security kext nije u BootKC, proveri sledeći AuxKC. Ovo je obično korisnije nego tražiti zaseban bundle u `/System/Library/Extensions`.

## MACF Callouts

Uobičajeno je pronaći callouts ka MACF definisane u kodu poput: **`#if CONFIG_MAC`** uslovnih blokova. Takođe, unutar ovih blokova moguće je pronaći pozive ka `mac_proc_check*`, koji poziva MACF da **proveri dozvole** za izvršavanje određenih akcija. Takođe, format MACF callout-a je: **`mac_<object>_<opType>_opName`**.

Object je jedan od sledećih: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` je obično `check`, koji će se koristiti da dozvoli ili zabrani akciju. Međutim, moguće je pronaći i `notify`, što će omogućiti kext-u da reaguje na datu akciju.

Možeš pronaći primer u [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Zatim, moguće je pronaći kod za `mac_file_check_mmap` u [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Koji poziva `MAC_CHECK` makro, čiji se kod može pronaći u [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Koji će proći kroz sve registrovane MAC politike, pozivati njihove funkcije i čuvati izlaz unutar promenljive error, koja će biti zamenljiva samo preko `mac_error_select` sa success kodovima, tako da ako bilo koja provera padne, kompletna provera će pasti i akcija neće biti dozvoljena.

> [!TIP]
> Međutim, imajte na umu da se ne koriste svi MACF callouts samo za zabranu akcija. Na primer, `mac_priv_grant` poziva makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), koji će dodeliti traženu privilegiju ako bilo koja politika odgovori sa 0:
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
>    });                                                           \
> } while (0)
> ```

### priv_check & priv_grant

Ovi callas-i su namenjeni za proveru i dodelu (desetina) **privilege** definisanih u [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Neki kernel kod bi pozivao `priv_check_cred()` iz [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) sa KAuth kredencijalima procesa i jednim od kodova privilege, što će pozvati `mac_priv_check` da vidi da li neka politika **odbijа** dodelu privilege, a zatim poziva `mac_priv_grant` da vidi da li neka politika dodeljuje `privilege`.

### proc_check_syscall_unix

Ovaj hook omogućava presretanje svih system call-ova. U `bsd/dev/[i386|arm]/systemcalls.c` moguće je videti deklarisanu funkciju [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), koja sadrži ovaj kod:
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
Koja će u pozivajućem procesu proveriti **bitmask** da li trenutni syscall treba da pozove `mac_proc_check_syscall_unix`. Ovo je zato što se syscalls pozivaju toliko često da je korisno izbegavati pozivanje `mac_proc_check_syscall_unix` svaki put.

Imajte na umu da funkciju `proc_set_syscall_filter_mask()`, koja postavlja bitmask syscalls u procesu, poziva Sandbox da bi postavio maske na sandboxed procese.

## Exposed MACF syscalls

Moguće je interagovati sa MACF kroz neke syscalls definisane u [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
Za offensive reversing, **`__mac_syscall`** je i dalje jedan od najboljih userland chokepoint-ova. Nosi **policy name** (na primer `"Sandbox"` ili `"AMFI"`), **policy-specific selector/code**, i pointer ka **opaque argument blob-u** koji će obraditi `mpo_policy_syscall`. Ovo je veoma korisno kada se reverzuje nedokumentovane operacije najpre iz userland-a, a tek kasnije se pivotuje u kernel implementaciju. Sandbox mu obično pristupa preko `__sandbox_ms`, a AMFI koristi isti mehanizam za dyld policy odluke.

## Practical offensive research notes

Nedavni macOS bugovi retko direktno "break MACF". Umesto toga, obično zloupotrebljavaju **desynchronisation između MACF / Sandbox / TCC odluke i privilegovane akcije koja se dešava kasnije**.

### Broker path checks vs real privileged action

Ponavljajući obrazac je da privilegovani daemon izvršava **userland pre-check** (na primer `sandbox_check_by_audit_token()`) nad jednom verzijom putanje, a zatim izvršava stvarni privileged sink sa **drugačijom ili non-canonical path kojom upravlja napadač**. Nedavna istraživanja nad `diskarbitrationd` / `storagekitd` su dobar primer: **directory traversal** plus **symlink swaps** omogućavaju napadaču da prođe daemon-ovu sandbox validaciju, a zatim da mount-uje preko osetljivih lokacija kao što su `~/Library/Application Support/com.apple.TCC`, pretvarajući bug u **sandbox escape**, **local privilege escalation** ili **TCC bypass** u zavisnosti od izabrane mount tačke.

Prilikom audita root broker-a dostupnih iz sandbox-a, prvo grep-uj za:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, helper-e za canonicalisation putanje
- privileged sinks kao što su `mount`, `rename`, `copyfile`, helper-tool XPC metode, ili bilo šta što kasnije dodiruje path-eve kojima upravlja napadač kao root

### Trusted deputies with private entitlements

Drugi praktičan obrazac je da se ne napadaju MACF hook-ovi direktno, već da se zloupotrebi **trusted process** koji već ima prava potrebna da pređe granicu. Nedavna Safari/TCC istraživanja su dobar primer: zanimljiv primitive nije bio "disable TCC in the kernel", već modifikovanje lokalne policy/configuration tako da Apple-signed process sa **`com.apple.private.tcc.allow`** izvrši osetljivu akciju u tvoje ime. U praksi, high-value auditing target-i su Apple daemoni/aplikacije koje kombinuju:

- **private entitlements** ili FDA-like reach
- writable config / database / mount point / policy file
- kasniju osetljivu operaciju posredovanu od strane **Sandbox**, **AMFI**, **TCC** ili neke druge MACF policy

Za dublji product-specific reversing, proveri posvećene stranice na [macOS Sandbox](macos-sandbox/README.md) i [macOS TCC](macos-tcc/README.md).

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
