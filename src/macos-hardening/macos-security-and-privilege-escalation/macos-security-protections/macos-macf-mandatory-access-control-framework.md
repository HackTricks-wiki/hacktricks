# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF** znači **Mandatory Access Control Framework**, što je sigurnosni sistem ugrađen u operativni sistem da pomogne u zaštiti vašeg računara. Radi tako što postavlja **stroga pravila o tome ko ili šta može da pristupi određenim delovima sistema**, kao što su fajlovi, aplikacije i sistemski resursi. Primenom ovih pravila automatski, MACF obezbeđuje da samo autorizovani korisnici i procesi mogu da izvode određene akcije, smanjujući rizik od neovlašćenog pristupa ili zlonamernih aktivnosti.

Imajte na umu da MACF zapravo ne donosi nikakve odluke, već samo **presreće** akcije; odluke prepušta **policy modules** (kernel extensions) koje poziva, kao što su `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` i `mcxalr.kext`.

- A policy may be enforcing (return 0 non-zero on some operation)
- A policy may be monitoring (return 0, so as not to object but piggyback on hook to do something)
- A MACF static policy is installed in boot and will NEVER be removed
- A MACF dynamic policy is installed by a KEXT (kextload) and may hypothetically be kextunloaded
- In iOS only static policies are allowed and in macOS static + dynamic.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flow

1. Process performs a syscall/mach trap
2. Relevant function is called inside the kernel
3. Function calls MACF
4. MACF checks policy modules that requested to hook that function in their policy
5. MACF calls the relevant policies
6. Policies indicates if they allow or deny the action

> [!CAUTION]
> Apple is the only one that can use the MAC Framework KPI.

Obično će funkcije koje proveravaju dozvole pomoću MACF pozivati makro `MAC_CHECK`. Kao u slučaju syscall za kreiranje socket-a, koji će pozvati funkciju `mac_socket_check_create`, a ona poziva `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Štaviše, makro `MAC_CHECK` je definisan u security/mac_internal.h kao:
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
Drugim rečima, `MAC_CHECK(socket_check_create, ...)` prvo prolazi kroz statičke politike, uslovno zaključava i iteriše kroz dinamičke politike, emitуje DTrace probe oko svakog hook-a, i svodi svaki return code hook-a u jedinstveni `error` rezultat preko `mac_error_select()`.


### Labels

MACF koristi **labels** koje će zatim politike koje proveravaju da li treba da odobre neki access ili ne koristiti. Kod deklaracije `struct` za labels može se [naći ovde](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), a zatim se koristi unutar **`struct ucred`** [**ovde**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) u delu **`cr_label`**. Label sadrži flags i broj **slots** koji MACF policies mogu da koriste za alociranje pointera. Na primer, Sanbox će pokazivati na container profile

## MACF Policies

MACF Policy definisan **rule i conditions** koje treba primeniti u određenim kernel operacijama.

Kernel extension može da konfiguriše `mac_policy_conf` struct i zatim da ga registruje pozivanjem `mac_policy_register`. Iz [ovde](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Lako je identifikovati kernel extensions koje konfigurišu ove politike proverom poziva ka `mac_policy_register`. Štaviše, analizom disassemble-a extensiona takođe je moguće pronaći korišćeni `mac_policy_conf` struct.

Imajte na umu da MACF politike mogu biti registrovane i unregistered takođe **dynamically**.

Jedno od glavnih polja `mac_policy_conf` je **`mpc_ops`**. Ovo polje specificira koje opreations su od interesa za politiku. Imajte na umu da ih ima stotine, pa je moguće postaviti sve na nulu i zatim selektovati samo one koje su od interesa za policy. Iz [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Gotovo svi hook-ovi će biti pozvani nazad od strane MACF kada se jedna od tih operacija presretne. Međutim, hook-ovi **`mpo_policy_*`** su izuzetak jer je **`mpo_hook_policy_init()`** callback koji se poziva prilikom registracije (dakle nakon `mac_policy_register()`), a **`mpo_hook_policy_initbsd()`** se poziva tokom kasne registracije, jednom kada se BSD pod-sistem ispravno inicijalizuje.

Pored toga, hook **`mpo_policy_syscall`** može biti registrovan od strane bilo kog kext-a kako bi se izložio privatni **ioctl**-stil pozivni **interface**. Zatim će user client moći da pozove `mac_syscall` (#381), navodeći kao parametre **policy name** sa celobrojnom **code** i opcionim **arguments**.\
Na primer, **`Sandbox.kext`** ovo često koristi.

Provera kext-ovog **`__DATA.__const*`** je moguća kako bi se identifikovala `mac_policy_ops` struktura koja se koristi prilikom registracije policy-ja. Moguće ju je pronaći jer se njen pointer nalazi na offset-u unutar `mpo_policy_conf`, a i zbog broja NULL pokazivača koji će biti u tom području.

Pored toga, moguće je dobiti listu kext-ova koji su konfigurisali policy dumpovanjem iz memorije strukture **`_mac_policy_list`** koja se ažurira sa svakim policy-jem koji se registruje.

Takođe možeš koristiti alat `xnoop` da dump-uješ sve policy-je registrovane u sistemu:
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
I onda izbaci sve provere iz check policy sa:
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

- MACF se inicijalizuje veoma rano. U `bootstrap_thread` (u XNU startup kodu), posle `ipc_bootstrap`, XNU poziva `mac_policy_init()` (u `mac_base.c`).
- `mac_policy_init()` inicijalizuje globalni `mac_policy_list` (niz ili listu slotova za policy) i postavlja infrastrukturu za MAC (Mandatory Access Control) unutar XNU.
- Kasnije se poziva `mac_policy_initmach()`, koja obrađuje kernel stranu registracije policy-ja za ugrađene ili bundled policy-je.

### `mac_policy_initmach()` i učitavanje „security extensions”

- `mac_policy_initmach()` ispituje kernel ekstenzije (kexts) koje su unapred učitane (ili su u listi za „policy injection“) i proverava njihov Info.plist za ključ `AppleSecurityExtension`.
- Kexts koji deklarisu `<key>AppleSecurityExtension</key>` (ili `true`) u svom Info.plist smatraju se „security extensions“ — tj. onima koji implementiraju MAC policy ili se povezuju sa MACF infrastrukturom.
- Primeri Apple kexts sa tim ključem uključuju **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, između ostalih (kao što si već naveo).
- Kernel obezbeđuje da se ti kexts učitaju rano, zatim poziva njihove registration rutine (preko `mac_policy_register`) tokom boot-a, ubacujući ih u `mac_policy_list`.

- Svaki policy modul (kext) obezbeđuje `mac_policy_conf` strukturu, sa hook-ovima (`mpc_ops`) za razne MAC operacije (vnode provere, exec provere, ažuriranje label-a, itd.).
- Load time flags mogu uključivati `MPC_LOADTIME_FLAG_NOTLATE`, što znači „mora biti učitan rano” (pa se kasniji pokušaji registracije odbijaju).
- Nakon registracije, svaki modul dobija handle i zauzima slot u `mac_policy_list`.
- Kada se MAC hook kasnije pozove (na primer, vnode access, exec, itd.), MACF iterira kroz sve registrovane policy-je da bi doneo zajedničke odluke.

- Posebno, **AMFI** (Apple Mobile File Integrity) je takva security extension. Njegov Info.plist uključuje `AppleSecurityExtension`, što ga označava kao security policy.
- Kao deo kernel boot-a, logika učitavanja kernela obezbeđuje da je „security policy” (AMFI, itd.) već aktivan pre nego što se mnogi podsistemi oslone na njega. Na primer, kernel „priprema se za zadatke koji slede tako što učitava … security policy, uključujući AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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

Kada pišete kext koji koristi MAC framework (tj. poziva `mac_policy_register()` itd.), morate deklarisati zavisnosti od KPI-ja (Kernel Programming Interfaces) kako bi kext linker (kxld) mogao da razreši te simbole. Dakle, da biste deklarisali da `kext` zavisi od MACF-a, treba to da navedete u `Info.plist` sa `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), tada će se kext pozivati na simbole kao što su `mac_policy_register`, `mac_policy_unregister` i MAC hook function pointers. Da biste ih razrešili, morate navesti `com.apple.kpi.dsep` kao zavisnost.

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
## MACF na modernim macOS izdanjima

Na modernom macOS-u, Apple security policies se obično ne posmatraju najbolje kao labavi samostalni `.kext` bundle-ovi. Od **macOS 11**, kernel extensions se povezuju u **kernel collections**; na **Apple Silicon** ne postoji poseban **SystemKC**, a third-party kexts postaju učitljivi tek nakon što budu izgrađeni u **Auxiliary Kernel Collection (AuxKC)** i nakon reboot-a. Za MACF research ovo znači da su ugrađene policies kao što su **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** ili **Quarantine** obično lakše za enumeraciju pomoću `kmutil` nego pomoću deprecated tooling-a kao što je `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> On Apple Silicon, if a security kext is not in the BootKC, check the AuxKC next. This is usually more useful than hunting for a standalone bundle under `/System/Library/Extensions`.

## MACF Callouts

Uobičajeno je pronaći callouts ka MACF definisane u kodu kao: **`#if CONFIG_MAC`** uslovni blokovi. Pored toga, unutar ovih blokova je moguće pronaći pozive `mac_proc_check*` koji poziva MACF da **proveri dozvole** za izvršavanje određenih radnji. Takođe, format MACF callouts je: **`mac_<object>_<opType>_opName`**.

Object je jedan od sledećih: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` je obično `check`, što će se koristiti da se dozvoli ili odbije akcija. Međutim, moguće je pronaći i `notify`, što će omogućiti kext-u da reaguje na дату akciju.

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

Zatim je moguće pronaći kod za `mac_file_check_mmap` u [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Koji poziva `MAC_CHECK` makro, čiji se kod može naći u [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Koji će proći kroz sve registrovane MAC politike, pozivati njihove funkcije i čuvati izlaz unutar promenljive `error`, koju će moći da prepiše samo `mac_error_select` kodovima uspeha, tako da ako bilo koja provera padne, kompletna provera će pasti i akcija neće biti dozvoljena.

> [!TIP]
> Međutim, imajte na umu da se ne koriste svi MACF callouts samo za odbijanje akcija. Na primer, `mac_priv_grant` poziva makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), koji će dodeliti traženu privilegiju ako bilo koja politika odgovori sa 0:
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

Ove pozivnice su namenjene za proveru i dodelu (desetina) **privileges** definisanih u [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Neki kernel kod bi pozvao `priv_check_cred()` iz [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) sa KAuth credentials procesa i jednim od code privilege, što će pozvati `mac_priv_check` da vidi da li neka politika **odbijа** davanje privilegije, a zatim poziva `mac_priv_grant` da vidi da li neka politika dodeljuje `privilege`.

### proc_check_syscall_unix

Ovaj hook omogućava presretanje svih system calls. U `bsd/dev/[i386|arm]/systemcalls.c` moguće je videti deklarisanu funkciju [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), koja sadrži ovaj kod:
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
Koji će proveriti u pozivajućem procesu **bitmask** da li trenutni syscall treba da pozove `mac_proc_check_syscall_unix`. Ovo je zato što se syscalls pozivaju tako često da je zanimljivo izbeći pozivanje `mac_proc_check_syscall_unix` svaki put.

Napomena da funkcija `proc_set_syscall_filter_mask()`, koja postavlja bitmask syscalls u procesu, poziva Sandbox da bi postavila maske na sandboxed procese.

## Izloženi MACF syscalls

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
Za offensive reversing, **`__mac_syscall`** je i dalje jedan od najboljih userland chokepoint-a. Nosи **ime politike** (na primer `"Sandbox"` ili `"AMFI"`), **selector/kod specifičan za politiku**, i pokazivač na **opaque argument blob** kojim će upravljati `mpo_policy_syscall`. Ovo je veoma korisno kada se undocumented operacije prvo analiziraju iz userland-a, a tek kasnije prelazi na kernel implementaciju. Sandbox mu obično pristupa preko `__sandbox_ms`, a AMFI koristi isti mehanizam za dyld policy odluke.

## Practical offensive research notes

Recent macOS bug-ovi retko direktno "break MACF". Umesto toga, obično abuse-ju **desynchronisation između MACF / Sandbox / TCC odluke i privilegovane akcije koja se dešava kasnije**.

### Broker path checks vs real privileged action

Ponavljajući obrazac je da privileged daemon radi **userland pre-check** (na primer `sandbox_check_by_audit_token()`) nad jednom verzijom path-a, a kasnije izvršava pravi privileged sink sa **drugačijim ili non-canonical attacker-controlled path-om**. Nedavno istraživanje nad `diskarbitrationd` / `storagekitd` je dobar primer: **directory traversal** plus **symlink swaps** omogućavaju attacker-u da prođe daemon-ovu sandbox validaciju, a zatim da mount-uje preko osetljivih lokacija poput `~/Library/Application Support/com.apple.TCC`, pretvarajući bug u **sandbox escape**, **local privilege escalation** ili **TCC bypass** u zavisnosti od izabrane mount tačke.

Kada audituješ root broker-e dostupne iz sandbox-a, prvo grep-uj za:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- privileged sink-ove kao što su `mount`, `rename`, `copyfile`, helper-tool XPC metode, ili bilo šta što kasnije dotakne attacker-controlled path-ove kao root

### Trusted deputies with private entitlements

Još jedan praktičan obrazac je da se ne napadaju MACF hook-ovi direktno, već da se abuse-uje **trusted process** koji već nosi prava potrebna za prelazak granice. Nedavno Safari/TCC istraživanje je dobar primer: zanimljiva primitive nije bila "disable TCC in the kernel", već modifikovanje lokalne policy/configuration tako da Apple-signed proces sa **`com.apple.private.tcc.allow`** izvrši osetljivu akciju umesto tebe. U praksi, targets visokog prioriteta za auditing su Apple daemons/apps koji kombinuju:

- **private entitlements** ili FDA-like reach
- writable config / database / mount point / policy file
- kasniju osetljivu operaciju posredovanu preko **Sandbox**, **AMFI**, **TCC** ili druge MACF politike

Za dublji product-specific reversing, pogledaj posebne strane na [macOS Sandbox](macos-sandbox/README.md) i [macOS TCC](macos-tcc/README.md).

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
