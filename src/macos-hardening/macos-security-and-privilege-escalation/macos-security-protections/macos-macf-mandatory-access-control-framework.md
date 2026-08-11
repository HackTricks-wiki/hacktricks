# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

**MACF** je skraćenica za **Mandatory Access Control Framework**, bezbednosni sistem ugrađen u operativni sistem koji pomaže u zaštiti računara. Funkcioniše tako što postavlja **stroga pravila o tome ko ili šta može da pristupi određenim delovima sistema**, kao što su datoteke, aplikacije i sistemski resursi. Automatskim sprovođenjem ovih pravila, MACF obezbeđuje da samo ovlašćeni korisnici i procesi mogu da izvršavaju određene radnje, čime se smanjuje rizik od neovlašćenog pristupa ili zlonamernih aktivnosti.

Imajte na umu da MACF zapravo ne donosi odluke, već samo **presreće** radnje, dok donošenje odluka prepušta **policy modules** (kernel extensions) koje poziva, kao što su `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` i `mcxalr.kext`.

- Policy može da sprovodi pravila (vraća 0 ili vrednost različitu od nule za određenu operaciju)
- Policy može da vrši nadzor (vraća 0 kako se ne bi protivila, ali koristi hook da bi izvršila određenu radnju)
- MACF static policy se instalira tokom pokretanja sistema i NIKADA se ne uklanja
- MACF dynamic policy se instalira pomoću KEXT-a (`kextload`) i hipotetički može da se ukloni pomoću `kextunload`
- U iOS-u su dozvoljene samo static policies, dok su u macOS-u dozvoljene static + dynamic policies.<sup>[[7]](#references)</sup>

### Tok

1. Proces izvršava syscall/mach trap
2. Relevantna funkcija se poziva unutar kernela
3. Funkcija poziva MACF
4. MACF proverava policy modules koji su u okviru svoje policy zatražili hook te funkcije
5. MACF poziva relevantne policies
6. Policies označavaju da li dozvoljavaju ili odbijaju radnju

> [!CAUTION]
> Apple je jedini koji može da koristi MAC Framework KPI.

Funkcije koje proveravaju dozvole pomoću MACF-a obično pozivaju makro `MAC_CHECK`. Na primer, syscall za kreiranje socketa pozvaće funkciju `mac_socket_check_create`, koja poziva `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Pored toga, makro `MAC_CHECK` je definisan u datoteci security/mac_internal.h kao:<sup>[[3]](#references)</sup>
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
Imajte na umu da transformacijom `check` u `socket_check_create` i `args...` u `(cred, domain, type, protocol)` dobijate:
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
Proširivanje pomoćnih makroa otkriva konkretan tok kontrole:
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
Drugim rečima, `MAC_CHECK(socket_check_create, ...)` prvo prolazi kroz statičke policies, uslovno zaključava i iterira kroz dinamičke policies, emituje DTrace probe oko svakog hook-a i objedinjuje povratni kod svakog hook-a u jedan `error` rezultat putem funkcije `mac_error_select()`.


### Oznake

MACF koristi **oznake** koje će policies zatim koristiti prilikom provere da li treba da odobre određeni pristup ili ne. Kod deklaracije strukture oznake možete [pronaći ovde](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), a ona se zatim koristi unutar **`struct ucred`**, [ovde](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86), u delu **`cr_label`**. Oznaka sadrži flags i određeni broj **slotova** koje **MACF policies mogu koristiti za alociranje pokazivača**. Na primer, Sanbox će pokazivati na container profile.

## MACF Policies

MACF Policy definiše **pravila i uslove koji se primenjuju tokom određenih kernel operacija**.

Kernel extension može konfigurisati strukturu `mac_policy_conf`, a zatim je registrovati pozivanjem funkcije `mac_policy_register`. Sa [ove stranice](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
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
Lako je identifikovati kernel ekstenzije koje konfigurišu ove policies proverom poziva ka `mac_policy_register`. Pored toga, proverom disassembly-ja ekstenzije moguće je pronaći i korišćenu strukturu `mac_policy_conf`.

Imajte na umu da se MACF policies mogu registrovati i odregistrirati takođe **dinamički**.

Jedno od glavnih polja strukture `mac_policy_conf` jeste **`mpc_ops`**. Ovo polje određuje koje operacije interesuju policy. Ima ih na stotine, pa je moguće postaviti sve unose na nulu, a zatim izabrati samo one koje policy zahteva. Od [ovde](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
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
Gotovo svi hook-ovi će biti pozvani od strane MACF-a kada jedna od tih operacija bude presretnuta. Međutim, hook-ovi **`mpo_policy_*`** predstavljaju izuzetak, jer je `mpo_hook_policy_init()` callback koji se poziva prilikom registracije (dakle, nakon `mac_policy_register()`), dok se `mpo_hook_policy_initbsd()` poziva tokom kasne registracije, nakon što se BSD subsystem pravilno inicijalizuje.

Pored toga, hook **`mpo_policy_syscall`** može da registruje bilo koji kext kako bi izložio privatni **ioctl** stil pozivnog **interfejsa**. Tada će user client moći da pozove `mac_syscall` (#381), navodeći kao parametre **naziv policy-ja**, celobrojni **code** i opcione **arguments**.\
Na primer, **`Sandbox.kext`** ovo često koristi.

Pregledom kext-ovog **`__DATA.__const*`** moguće je identifikovati strukturu `mac_policy_ops` koja se koristi prilikom registracije policy-ja. Moguće ju je pronaći zato što se njen pointer nalazi na offset-u unutar `mpo_policy_conf`, kao i zbog količine NULL pointer-a koji će se nalaziti u toj oblasti.

Pored toga, moguće je dobiti listu kext-ova koji su konfigurisali policy tako što se iz memorije dump-uje struktura **`_mac_policy_list`**, koja se ažurira sa svakim registrovanim policy-jem.

Možete koristiti i alat `xnoop` za dump svih policy-ja registrovanih u sistemu:
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
A zatim izlistajte sve provere check policy-ja pomoću:
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

### Rani bootstrap i mac_policy_init()

- MACF se inicijalizuje veoma rano. U `bootstrap_thread` (u XNU startup kodu), nakon `ipc_bootstrap`, XNU poziva `mac_policy_init()` (u `mac_base.c`).
- `mac_policy_init()` inicijalizuje globalni `mac_policy_list` (niz ili listu slotova za policies) i postavlja infrastrukturu za MAC (Mandatory Access Control) unutar XNU-a.
- Kasnije se poziva `mac_policy_initmach()`, koji obrađuje registraciju policies na nivou kernela za ugrađene ili bundlovane policies.

### `mac_policy_initmach()` i učitavanje „security extensions“

- `mac_policy_initmach()` ispituje kernel extensions (kexts) koji su unapred učitani (ili se nalaze na listi „policy injection“) i analizira njihov Info.plist u potrazi za ključem `AppleSecurityExtension`.
- Kexts koji u svom Info.plist-u deklarišu `<key>AppleSecurityExtension</key>` (ili `true`) smatraju se „security extensions“ — odnosno onima koji implementiraju MAC policy ili se povezuju sa MACF infrastrukturom.
- Primeri Apple kexts sa tim ključem uključuju **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** i druge, kao što je već navedeno.
- Kernel obezbeđuje da se ti kexts učitaju rano, a zatim tokom boot-a poziva njihove rutine za registraciju (putem `mac_policy_register`), pri čemu ih ubacuje u `mac_policy_list`.

- Svaki policy modul (kext) obezbeđuje strukturu `mac_policy_conf`, sa hooks (`mpc_ops`) za različite MAC operacije (provere vnode-a, provere exec-a, ažuriranja labela itd.).
- Zastavice vremena učitavanja mogu uključivati `MPC_LOADTIME_FLAG_NOTLATE`, što znači „mora biti učitano rano“ (zbog čega se pokušaji kasne registracije odbijaju).
- Nakon registracije, svaki modul dobija handle i zauzima slot u `mac_policy_list`.
- Kada se MAC hook kasnije pozove (na primer, za pristup vnode-u, exec itd.), MACF iterira kroz sve registrovane policies kako bi doneo kolektivne odluke.

- Konkretno, **AMFI** (Apple Mobile File Integrity) predstavlja takvu security extension. Njegov Info.plist sadrži `AppleSecurityExtension`, čime se označava kao security policy.
- U sklopu boot-a kernela, logika učitavanja kernela obezbeđuje da „security policy“ (AMFI itd.) već bude aktivna pre nego što mnogi subsystems počnu da zavise od nje. Na primer, kernel se „priprema za predstojeće tasks učitavanjem … security policy, uključujući AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.“
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
## KPI dependency i com.apple.kpi.dsep u MAC policy kext-ovima

Prilikom pisanja kext-a koji koristi MAC framework (tj. poziva `mac_policy_register()` itd.), morate deklarisati dependencies on KPIs (Kernel Programming Interfaces) kako bi kext linker (kxld) mogao da razreši te simbole. Dakle, da biste deklarisali da `kext` zavisi od MACF-a, morate to navesti u `Info.plist` datoteci pomoću `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), nakon čega će se kext pozivati na simbole kao što su `mac_policy_register`, `mac_policy_unregister` i pokazivači na MAC hook funkcije. Da biste ih razrešili, morate navesti `com.apple.kpi.dsep` kao dependency.

Primer isečka `Info.plist` datoteke (unutar vašeg `.kext`-a):
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

Na modernom macOS-u, Apple bezbednosnim politikama obično nije najbolje pristupati kao labavo povezanim samostalnim `.kext` paketima. Od verzije **macOS 11**, ekstenzije kernela povezane su u **kernel collections**; na **Apple Silicon** ne postoji zaseban **SystemKC**, a kext-ovi trećih strana mogu da se učitaju tek nakon što budu ugrađeni u **Auxiliary Kernel Collection (AuxKC)** i nakon ponovnog pokretanja sistema. Za MACF istraživanje to znači da je ugrađene politike, kao što su **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** ili **Quarantine**, obično lakše enumerisati pomoću `kmutil` nego zastarelim alatima kao što je `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Na Apple Silicon-u, ako se security kext ne nalazi u BootKC-u, sledeće proverite AuxKC. Ovo je obično korisnije nego tražiti standalone bundle u direktorijumu `/System/Library/Extensions`.

## MACF pozivi

Uobičajeno je pronaći pozive ka MACF-u definisane u kodu, u uslovnim blokovima poput: **`#if CONFIG_MAC`**. Štaviše, unutar ovih blokova moguće je pronaći pozive ka `mac_proc_check*`, koji pozivaju MACF da **provere dozvole** za izvršavanje određenih radnji. Format MACF poziva je: **`mac_<object>_<opType>_opName`**.

Objekat je jedan od sledećih: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` je obično check, koji se koristi za dozvoljavanje ili odbijanje radnje. Međutim, moguće je pronaći i `notify`, koji omogućava kext-u da reaguje na datu radnju.

Primer možete pronaći na [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Zatim je moguće pronaći kod funkcije `mac_file_check_mmap` na [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Koji poziva makro `MAC_CHECK`, čiji kod se može pronaći na [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>.
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
Koja će proći kroz sve registrovane mac politike, pozvati njihove funkcije i sačuvati izlaz unutar promenljive `error`, koju će `mac_error_select` moći da promeni samo kodovima uspeha, tako da će, ako bilo koja provera ne uspe, kompletna provera biti neuspešna i radnja neće biti dozvoljena.

> [!TIP]
> Međutim, imajte na umu da se svi MACF callouts ne koriste samo za uskraćivanje radnji. Na primer, `mac_priv_grant` poziva makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), koji će dodeliti traženu privilegiju ako bilo koja policy vrati 0:
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

Ovi pozivi služe za proveru i dodelu desetina **privilegija** definisanih u [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Deo kernel koda poziva `priv_check_cred()` iz [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) sa KAuth kredencijalima procesa i jednim od kodova privilegija, što će pozvati `mac_priv_check` kako bi proverilo da li neka policy **uskraćuje** dodelu privilegije, a zatim poziva `mac_priv_grant` da proveri da li neka policy dodeljuje `privilege`.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Ovaj hook omogućava presretanje svih sistemskih poziva. U `bsd/dev/[i386|arm]/systemcalls.c` moguće je videti deklarisanu funkciju [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), koja sadrži ovaj kod:
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
Koji će u procesu koji ga poziva proveriti **bitmask** da li trenutni syscall treba da pozove `mac_proc_check_syscall_unix`. Razlog je to što se syscalls pozivaju veoma često, pa je korisno izbeći pozivanje `mac_proc_check_syscall_unix` svaki put.

Imajte na umu da funkciju `proc_set_syscall_filter_mask()`, koja postavlja bitmask syscalls u procesu, poziva Sandbox kako bi postavio maske na sandboxed procese.

## Izloženi MACF syscalls

Moguće je komunicirati sa MACF-om preko nekih syscalls definisanih u [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
Za ofanzivni reverse engineering, **`__mac_syscall`** je i dalje jedna od najboljih userland tačaka presretanja. On prenosi **naziv policy-ja** (na primer `"Sandbox"` ili `"AMFI"`), **selector/code specifičan za policy**, kao i pokazivač na **opaque argument blob** kojim će rukovati `mpo_policy_syscall`. Ovo je veoma korisno pri reverse engineering-u nedokumentovanih operacija, najpre iz userland-a, a tek kasnije prelaskom na implementaciju u kernelu. Sandbox do njega često dolazi preko `__sandbox_ms`, a AMFI koristi isti mehanizam za dyld policy odluke.<sup>[[2]](#references)[[5]](#references)</sup>

## Praktične beleške za ofanzivno istraživanje

Noviji macOS bug-ovi retko direktno „lome MACF“. Umesto toga, obično zloupotrebljavaju **desinhronizaciju između odluke MACF / Sandbox / TCC i privilegovane radnje koja se izvršava kasnije**.

### Provere putanja u brokeru naspram stvarne privilegovane radnje

Čest obrazac je da privilegovani daemon izvrši **userland pre-proveru** (na primer `sandbox_check_by_audit_token()`) nad jednom verzijom putanje, a zatim izvrši pravi privilegovani sink sa **drugom ili nekonvencionalnom putanjom pod kontrolom napadača**. Nedavna istraživanja `diskarbitrationd` / `storagekitd` dobar su primer: **directory traversal** zajedno sa **zamenama symlink-ova** omogućava napadaču da prođe sandbox validaciju daemon-a, a zatim mount-uje preko osetljivih lokacija kao što je `~/Library/Application Support/com.apple.TCC`, pretvarajući bug u **sandbox escape**, **local privilege escalation** ili **TCC bypass**, u zavisnosti od izabrane mount tačke.<sup>[[6]](#references)</sup>

Kada auditujete root brokere dostupne iz sandbox-a, prvo pretražite:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, pomoćne funkcije za kanonikalizaciju putanja
- privilegovane sink-ove kao što su `mount`, `rename`, `copyfile`, XPC metode helper-tool-ova ili bilo šta što kasnije pristupa putanjama pod kontrolom napadača kao root

### Trusted deputies sa privatnim entitlement-ima

Drugi praktičan obrazac jeste izbegavanje direktnog napada na MACF hook-ove i umesto toga zloupotreba **trusted process-a** koji već poseduje prava potrebna za prelazak granice. Nedavna istraživanja Safari/TCC predstavljaju dobar primer: zanimljivi primitive nije bio „isključivanje TCC-a u kernelu“, već menjanje lokalne policy/configuration tako da Apple-signed process sa **`com.apple.private.tcc.allow`** izvrši osetljivu radnju u vaše ime.<sup>[[8]](#references)</sup> U praksi, ciljevi za high-value auditing su Apple daemon-i/aplikacije koje kombinuju:

- **private entitlement-e** ili reach sličan FDA-u
- konfiguraciju / bazu podataka / mount tačku / policy fajl sa mogućnošću upisa
- kasniju osetljivu operaciju posredovanu putem **Sandbox**, **AMFI**, **TCC** ili drugog MACF policy-ja

Za dublji, proizvodno specifičan reverse engineering, pogledajte posvećene stranice o [macOS Sandbox](macos-sandbox/README.md) i [macOS TCC](macos-tcc/README.md).

## References

- [1] [XNU — `security/mac_policy.h` (ceo vektor MACF policy operacija)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (makroi `MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (kodovi privilegija koje koriste `priv_check`/`priv_grant`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Ofanzivna bezbednost)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Otkrivanje Apple ranjivosti: diskarbitrationd i storagekitd audit, 2. deo](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — alat za unakrsno referenciranje XNU-a](https://newosxbook.com/xxr/index.php)
- [8] [Nova macOS ranjivost, „HM Surf“, može dovesti do neovlašćenog pristupa podacima (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
{{#include ../../../banners/hacktricks-training.md}}
