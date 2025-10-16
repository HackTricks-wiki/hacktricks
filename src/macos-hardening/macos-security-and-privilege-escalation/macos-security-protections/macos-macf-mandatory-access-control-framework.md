# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

**MACF** označava **Okvir obaveznog kontrole pristupa (Mandatory Access Control Framework)**, koji je sigurnosni sistem ugrađen u operativni sistem kako bi zaštitio vaš računar. On funkcioniše tako što postavlja **stroga pravila o tome ko ili šta može da pristupi određenim delovima sistema**, kao što su fajlovi, aplikacije i sistemski resursi. Automatskim sprovođenjem ovih pravila, MACF osigurava da samo ovlašćeni korisnici i procesi mogu da izvršavaju određene radnje, smanjujući rizik od neovlašćenog pristupa ili malicioznih aktivnosti.

Imajte na umu da MACF zapravo ne donosi odluke — on samo **presreće** radnje i prepušta odluke **policy modules** (kernel extensions) koje poziva, kao što su `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` and `mcxalr.kext`.

- Polisa može biti enforcing (vraća 0 ili nenulti kod u nekim operacijama)
- Polisa može biti monitoring (vraća 0, dakle ne prigovara, ali iskoristi hook da obavi nešto)
- MACF statička politika se instalira pri boot-u i NIKADA neće biti uklonjena
- MACF dinamička politika se instalira pomoću KEXT-a (kextload) i hipotetički može biti kextunloaded
- Na iOS-u su dozvoljene samo statičke politike, a na macOS-u statičke + dinamičke.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Tok

1. Proces izvršava syscall/mach trap
2. Relevantna funkcija se poziva unutar kernela
3. Funkcija poziva MACF
4. MACF proverava module politike koji su zatražili da hookuju tu funkciju u svojoj politici
5. MACF poziva odgovarajuće politike
6. Politike označavaju da li dozvoljavaju ili odbijaju akciju

> [!CAUTION]
> Apple je jedini koji može koristiti MAC Framework KPI.

Obično funkcije koje proveravaju dozvole preko MACF pozivaće makro `MAC_CHECK`. Kao u slučaju syscall-a za kreiranje socketa koji će pozvati funkciju `mac_socket_check_create` koja poziva `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Štaviše, makro `MAC_CHECK` je definisan u security/mac_internal.h kao:
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
Obratite pažnju da, transformišući `check` u `socket_check_create` i `args...` u `(cred, domain, type, protocol)`, dobijate:
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
Proširenje pomoćnih makroa pokazuje konkretan tok kontrole:
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

### Oznake

MACF koristi **labels** koje politike zatim koriste da provere da li treba da odobre neki pristup ili ne. Kod deklaracije strukture label može se [pronaći ovde](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), koja se potom koristi unutar **`struct ucred`** u [**ovde**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) u delu **`cr_label`**. Oznaka sadrži zastavice i broj **slotova** koje mogu koristiti **MACF politike za alociranje pokazivača**. Na primer Sandbox će pokazivati na profil kontejnera

## MACF politike

MACF politika definiše **pravila i uslove koji se primenjuju u određenim kernel operacijama**.

Kernel ekstenzija može konfigurisati `mac_policy_conf` struct i potom ga registrovati pozivom `mac_policy_register`. Iz [ovde](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Lako je identifikovati kernel extensions koje konfigurišu ove politike proverom poziva ka `mac_policy_register`. Pored toga, pregledom disasembliranog koda ekstenzije moguće je pronaći korišćenu `mac_policy_conf` strukturu.

Imajte na umu da se MACF politike mogu registrovati i odregistrovati i **dinamički**.

Jedno od glavnih polja u `mac_policy_conf` je **`mpc_ops`**. Ovo polje određuje u kojim operacijama je politika zainteresovana. Imajte na umu da ih ima na stotine, pa je moguće postaviti sva na nulu i zatim uključiti samo ona koja su relevantna za datu politiku. Više informacija na [ovde](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Gotovo svi hook-ovi će biti pozvani od strane MACF-a kada se jedna od tih operacija presretne. Međutim, **`mpo_policy_*`** hook-ovi su izuzetak zato što se `mpo_hook_policy_init()` poziva kao callback pri registraciji (dakle nakon `mac_policy_register()`) i `mpo_hook_policy_initbsd()` se poziva tokom kasne registracije kada se BSD subsistem pravilno inicijalizuje.

Štaviše, **`mpo_policy_syscall`** hook može da registruje bilo koji kext kako bi izložio privatni **ioctl** stil interfejs za pozive. Tada će user client moći da pozove `mac_syscall` (#381) navodeći kao parametre **policy name** sa celobrojnom vrednošću **code** i opcionim **arguments**.\
Na primer, **`Sandbox.kext`** ovo često koristi.

Provera kext-ovog **`__DATA.__const*`** omogućava identifikovanje strukture `mac_policy_ops` koja se koristi prilikom registracije policy-ja. Može se naći zato što je njen pokazivač na offsetu unutar `mpo_policy_conf` i takođe zbog broja NULL pokazivača koji će biti u tom području.

Takođe je moguće dobiti listu kext-ova koji su konfigurisali policy tako što ćete izdumpovati iz memorije strukturu **`_mac_policy_list`** koja se ažurira za svaki registrovani policy.

Takođe možete koristiti alat `xnoop` da izdumpujete sve policy-je registrovane u sistemu:
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
A zatim ispiši sve provere check policy pomoću:
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
## MACF initialization in XNU

### Early bootstrap and mac_policy_init()

- MACF je inicijalizovan veoma rano. U `bootstrap_thread` (u XNU startup kodu), nakon `ipc_bootstrap`, XNU poziva `mac_policy_init()` (u `mac_base.c`).
- `mac_policy_init()` inicijalizuje globalni `mac_policy_list` (niz ili lista slotova za politike) i postavlja infrastrukturu za MAC (Mandatory Access Control) unutar XNU.
- Kasnije se poziva `mac_policy_initmach()`, koji rukovodi kernel stranom registracije politika za ugrađene ili paketirane politike.

### `mac_policy_initmach()` and loading “security extensions”

- `mac_policy_initmach()` pregleda kernel extensions (kexts) koji su prethodno učitani (ili se nalaze na listi za „policy injection”) i ispituje njihov Info.plist za ključ `AppleSecurityExtension`.
- Kexts koji u svom Info.plist deklariraju `<key>AppleSecurityExtension</key>` (ili `true`) smatraju se „security extensions” — tj. onima koji implementiraju MAC politiku ili se kače na MACF infrastrukturu.
- Primeri Apple kexts sa tim ključem uključuju **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, između ostalih (kao što ste već naveli).
- Kernel osigurava da su ti kexts učitani rano, a zatim poziva njihove rutine za registraciju (putem `mac_policy_register`) tokom boota, ubacujući ih u `mac_policy_list`.

- Svaki modul politike (kext) obezbeđuje `mac_policy_conf` strukturu, sa hook-ovima (`mpc_ops`) za razne MAC operacije (vnode provere, exec provere, ažuriranja labela, itd.).
- Load time flags mogu uključivati `MPC_LOADTIME_FLAG_NOTLATE` što znači „mora biti učitano rano” (tako da su pokušaji kasne registracije odbijeni).
- Kada se registruje, svaki modul dobija handle i zauzima slot u `mac_policy_list`.
- Kada se kasnije pozove MAC hook (na primer, pristup vnode-u, exec, itd.), MACF iterira kroz sve registrovane politike da bi doneo zajedničke odluke.

- Konkretno, **AMFI** (Apple Mobile File Integrity) je takva security extension. Njegov Info.plist uključuje `AppleSecurityExtension` što ga označava kao sigurnosnu politiku.
- Kao deo boot procesa kernela, logika učitavanja kernela osigurava da je „security policy” (AMFI, itd.) već aktivna pre nego što se mnogi subsistemi na nju oslone. Na primer, kernel „priprema za zadatke učitavajući … security policy, uključujući AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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
## Zavisnost KPI & com.apple.kpi.dsep u MAC policy kexts

Kada pišete kext koji koristi MAC framework (npr. pozivajući `mac_policy_register()` itd.), morate deklarisati zavisnosti od KPI (Kernel Programming Interfaces) kako bi linker za kext (kxld) mogao da razreši te simbole. Dakle, da biste deklarisali da se `kext` oslanja na MACF, potrebno je to navesti u `Info.plist` koristeći `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), nakon čega će kext referencirati simbole kao što su `mac_policy_register`, `mac_policy_unregister` i pokazivače na MAC hook funkcije. Da bi se oni razrešili, morate navesti `com.apple.kpi.dsep` kao zavisnost.

Primer isečka Info.plist (unutar vašeg .kext):
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

Uobičajeno je pronaći MACF pozive definisane u kodu u okviru uslovnih blokova kao što je: **`#if CONFIG_MAC`**. Takođe, unutar ovih blokova moguće je pronaći pozive `mac_proc_check*` koji pozivaju MACF da proveri dozvole za izvršavanje određenih radnji. Format MACF poziva je: **`mac_<object>_<opType>_opName`**.

Objekat je jedan od sledećih: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` je obično check, koji se koristi za dozvoljavanje ili odbijanje akcije. Međutim, moguće je naći i `notify`, koji omogućava kext-u da reaguje na datu akciju.

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

Kod `mac_file_check_mmap` možete pronaći u [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Koji poziva makro `MAC_CHECK`, čiji se kod može pronaći na [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Koja će proći kroz sve registrovane mac politike pozivajući njihove funkcije i sačuvati izlaz u promenljivu error, koju će `mac_error_select` moći da prepiše samo za uspešne kodove; dakle, ako neka provera zakaže, cela provera će propasti i akcija neće biti dozvoljena.

> [!TIP]
> Međutim, imajte na umu da se svi MACF pozivi ne koriste samo za odbijanje akcija. Na primer, `mac_priv_grant` poziva makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), koji će dodeliti traženu privilegiju ako bilo koja politika odgovori sa 0:
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

Ovi pozivi služe za proveru i dodelu (desetina) **privilegija** definisanih u [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Neki kernel kod pozivaće `priv_check_cred()` iz [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) sa KAuth akreditivima procesa i jednim od kodova privilegija; on će pozvati `mac_priv_check` da proveri da li neka politika **odbija** dodelu privilegije, a zatim poziva `mac_priv_grant` da vidi da li neka politika dodeljuje tu `privilege`.

### proc_check_syscall_unix

Ovaj hook omogućava presretanje svih sistemskih poziva. U `bsd/dev/[i386|arm]/systemcalls.c` može se videti deklarisana funkcija [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), koja sadrži ovaj kod:
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
Koji će proveriti u pozivajućem procesu **bitmask** da li trenutni syscall treba da pozove `mac_proc_check_syscall_unix`. Razlog je što se syscalls pozivaju tako često da je korisno izbeći pozivanje `mac_proc_check_syscall_unix` svaki put.

Napomena: funkcija `proc_set_syscall_filter_mask()`, koja postavlja bitmasku syscalls u procesu, poziva se iz Sandbox-a da postavi maske na sandboxed processes.

## Izloženi MACF syscalls

Moguće je interagovati sa MACF preko nekih syscalls definisanih u [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
## Izvori

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}
