# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

**MACF** označava **Mandatory Access Control Framework**, što je sigurnosni sistem ugrađen u operativni sistem koji pomaže u zaštiti vašeg računara. Radi tako što postavlja **stroga pravila o tome ko ili šta može pristupiti određenim delovima sistema**, kao što su fajlovi, aplikacije i sistemski resursi. Automatskim sprovođenjem ovih pravila, MACF osigurava da samo ovlašćeni korisnici i procesi mogu izvršavati određene radnje, smanjujući rizik od neovlašćenog pristupa ili zlonamernih aktivnosti.

Imajte na umu da MACF zapravo ne donosi odluke, već samo **presreće** radnje i prepušta odluke **policy module-ima** (kernel extensions) koje poziva, kao što su `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` i `mcxalr.kext`.

- Policy može biti enforcing (vraća nenulti kod za neku operaciju)
- Policy može biti monitoring (vraća 0, kako ne bi prigovarao, ali koristi hook da izvrši neku radnju)
- MACF statička politika se instalira pri boot-u i NIKADA se neće ukloniti
- MACF dinamička politika se instalira putem KEXT-a (kextload) i hipotetički može biti kextunloaded
- U iOS-u su dozvoljene samo statičke politike, a u macOS-u statičke + dinamičke.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Tok

1. Process izvršava syscall/mach trap
2. Relevantna funkcija se poziva unutar kernela
3. Funkcija poziva MACF
4. MACF proverava policy module koji su tražili da hook-uju tu funkciju u svojoj politici
5. MACF poziva relevantne politike
6. Politike označavaju da li dozvoljavaju ili odbijaju akciju

> [!CAUTION]
> Apple je jedini koji može koristiti MAC Framework KPI.

Obično funkcije koje proveravaju permisije kroz MACF pozivaju makro `MAC_CHECK`. Kao u slučaju syscall-a za kreiranje socketa koji će pozvati funkciju `mac_socket_check_create` koja poziva `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Štaviše, makro `MAC_CHECK` je definisan u security/mac_internal.h kao:
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
Primetite da transformacijom `check` u `socket_check_create` i `args...` u `(cred, domain, type, protocol)` dobijate:
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
Proširenjem pomoćnih makroa prikazuje se konkretan kontrolni tok:
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
In other words, `MAC_CHECK(socket_check_create, ...)` walks the static policies first, conditionally locks and iterates over dynamic policies, emits the DTrace probes around each hook, and collapses every hook’s return code into the single `error` result via `mac_error_select()`.


### Labels

MACF koristi **labels** koje politike koriste pri proveri da li treba odobriti pristup ili ne. Kod deklaracije labels struct-a može se naći [found here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), koja se potom koristi unutar **`struct ucred`** u [**here**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) u delu **`cr_label`**. Label sadrži flagove i određeni broj **slots** koji mogu biti korišćeni od strane **MACF policies** za alokaciju pokazivača. Na primer Sanbox će pokazivati na profil kontejnera

## MACF Policies

MACF Policy definiše **pravila i uslove koji se primenjuju u određenim kernel operacijama**.

Kernel ekstenzija može konfigurisati `mac_policy_conf` struct i zatim ga registrovati pozivom `mac_policy_register`. From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Lako je identifikovati kernel ekstenzije koje konfigurišu ove politike proverom poziva `mac_policy_register`. Pored toga, analizom disasembliranog koda ekstenzije moguće je pronaći korišćenu strukturu `mac_policy_conf`.

Napomena: MACF politike se takođe mogu registrovati i odregistrovati **dinamički**.

Jedno od glavnih polja u `mac_policy_conf` je **`mpc_ops`**. Ovo polje određuje za koje operacije je politika zainteresovana. Imajte na umu da ih ima stotine, pa je moguće postaviti sva na nulu i zatim izabrati samo ona koja politika zahteva. From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Gotovo svi hooks biće pozvani od strane MACF-a kada se jedna od tih operacija presretne. Međutim, **`mpo_policy_*`** hooks predstavljaju izuzetak: `mpo_hook_policy_init()` je callback koji se poziva prilikom registracije (tj. nakon `mac_policy_register()`), a `mpo_hook_policy_initbsd()` se poziva tokom kasne registracije, kada se BSD subsistem pravilno inicijalizuje.

Pored toga, **`mpo_policy_syscall`** hook može biti registrovan od strane bilo kog kext-a da izloži privatni **ioctl** style call **interface**. Tada će user client moći da pozove `mac_syscall` (#381), navodeći kao parametre **policy name** sa celobrojnim **code** i opcionim **arguments**.\
Na primer, **`Sandbox.kext`** ovo često koristi.

Proverom **`__DATA.__const*`** kext-a moguće je identifikovati `mac_policy_ops` strukturu koja se koristi pri registraciji politike. Može se pronaći zato što je njen pokazivač na offsetu unutar `mpo_policy_conf` i zbog broja NULL pokazivača koji će se nalaziti u tom području.

Takođe je moguće dobiti listu kext-ova koji su konfigurisali politiku tako što se iz memorije iskopa struct **`_mac_policy_list`**, koja se ažurira za svaku registrovanu politiku.

Takođe možete koristiti alat `xnoop` da iskopate sve politike registrovane u sistemu:
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
A zatim ispišite sve provere check policy pomoću:
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
## Inicijalizacija MACF-a u XNU

### Early bootstrap and mac_policy_init()

- MACF se inicijalizuje veoma rano. U `bootstrap_thread` (u XNU startup kodu), nakon `ipc_bootstrap`, XNU poziva `mac_policy_init()` (u `mac_base.c`).
- `mac_policy_init()` inicijalizuje globalnu `mac_policy_list` (niz ili listu slotova za politike) i uspostavlja infrastrukturu za MAC (Mandatory Access Control) unutar XNU.
- Kasnije se poziva `mac_policy_initmach()`, koji obrađuje kernel stranu registracije politika za ugrađene ili priložene politike.

### `mac_policy_initmach()` and loading “security extensions”

- `mac_policy_initmach()` pregledava kernel extensions (kexts) koji su pre učitani (ili u “policy injection” listi) i proverava njihov Info.plist za ključ `AppleSecurityExtension`.
- Kexts koji deklarišu `<key>AppleSecurityExtension</key>` (ili `true`) u svom Info.plist smatraju se “security extensions” — tj. oni koji implementiraju MAC policy ili se uključe u MACF infrastrukturu.
- Primeri Apple kexts sa tim ključem uključuju **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, između ostalih (kao što ste već naveli).
- Kernel obezbeđuje da ti kexts budu učitani rano, zatim poziva njihove rutine za registraciju (preko `mac_policy_register`) tokom boot-a, ubacujući ih u `mac_policy_list`.

- Svaki policy modul (kext) obezbeđuje `mac_policy_conf` strukturu, sa hook-ovima (`mpc_ops`) za razne MAC operacije (vnode provere, exec provere, ažuriranja labela, itd.).
- Load time flags mogu uključivati `MPC_LOADTIME_FLAG_NOTLATE` što znači „mora biti učitano rano“ (tako da kasni pokušaji registracije bivaju odbijeni).
- Kada su registrovani, svaki modul dobija handle i zauzima slot u `mac_policy_list`.
- Kada se MAC hook pozove kasnije (na primer, pristup vnode, exec, itd.), MACF iterira kroz sve registrovane politike da donese kolektivne odluke.

- Konkretno, **AMFI** (Apple Mobile File Integrity) je takva security extension. Njegov Info.plist uključuje `AppleSecurityExtension` označavajući ga kao security policy.
- Kao deo kernel boot-a, logika učitavanja kernela osigurava da je “security policy” (AMFI, itd.) već aktivna pre nego što se mnogi podsistemi oslone na nju. Na primer, kernel „sprema se za naredne zadatke učitavanjem … security policy, uključujući AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.“
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
## Zavisnost od KPI i com.apple.kpi.dsep u MAC policy kext-ovima

Kada pišete kext koji koristi MAC framework (npr. pozivanjem `mac_policy_register()` itd.), morate deklarisati zavisnosti od KPI (Kernel Programming Interfaces) kako bi kext linker (kxld) mogao da razreši te simbole. Dakle, da biste deklarisali da `kext` zavisi od MACF, morate to navesti u `Info.plist` pomoću `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), tada će kext koristiti simbole poput `mac_policy_register`, `mac_policy_unregister` i pokazivače na MAC hook funkcije. Da bi se ti simboli razrešili, morate navesti `com.apple.kpi.dsep` kao zavisnost.

Primer isječka Info.plist (u okviru vašeg .kext):
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
## MACF pozivi

Uobičajeno je pronaći pozive na MACF definisane u kodu, kao u uslovnim blokovima **`#if CONFIG_MAC`**. Štaviše, unutar ovih blokova moguće je naći pozive `mac_proc_check*` koji pozivaju MACF da **proveri dozvole** za izvođenje određenih akcija. Format MACF poziva je: **`mac_<object>_<opType>_opName`**.

Objekat je jedan od sledećih: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` je obično check, koji se koristi da dozvoli ili odbije akciju. Međutim, moguće je naći i `notify`, koji omogućava kext-u da reaguje na zadatu akciju.

Primer možete naći na [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Zatim, moguće je pronaći kod `mac_file_check_mmap` u [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Koji poziva makro `MAC_CHECK`, čiji se kod može naći na [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Koji će proći kroz sve registrovane mac politike pozivajući njihove funkcije i smeštajući izlaz u promenljivu error, koju može nadjačati samo `mac_error_select` pomoću kodova uspeha, tako da ako bilo koja provera zakaže, cela provera će propasti i akcija neće biti dozvoljena.

> [!TIP]
> Ipak, imajte na umu da ne koriste svi MACF callouts samo za odbijanje akcija. Na primer, `mac_priv_grant` poziva makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), koji će dodeliti traženu privilegiju ako bilo koja politika odgovori sa 0:
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
Neki kernel kod pozivaće `priv_check_cred()` iz [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) са KAuth акредитивима procesa и једним од кодова привилегија, који ће позвати `mac_priv_check` да види да ли нека политика **odbija** dodelu привилегије и затим позива `mac_priv_grant` да провери да ли нека политика dodeljuje ту `privilege`.

### proc_check_syscall_unix

Ovaj hook omogućava presretanje svih sistemskih poziva. U `bsd/dev/[i386|arm]/systemcalls.c` može се vidети деклараisana функција [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), која садржи следећи код:
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
Koji će proveriti u pozivajućem procesu **bitmask** da li trenutni syscall treba da pozove `mac_proc_check_syscall_unix`. To je zato što se syscalls pozivaju toliko često da je korisno izbegavati pozivanje `mac_proc_check_syscall_unix` svaki put.

Napomena da se funkcija `proc_set_syscall_filter_mask()`, koja postavlja bitmasku syscalls u procesu, poziva od strane Sandbox-a da postavi maske na sandboxed processes.

## Izloženi MACF syscalls

Moguće je komunicirati sa MACF kroz neke syscalls definisane u [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
## Literatura

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}
