# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

**MACF** je skraćenica za **Mandatory Access Control Framework** (okvir obavezne kontrole pristupa), bezbednosni sistem ugrađen u operativni sistem koji pomaže u zaštiti računara. Funkcioniše tako što postavlja **stroga pravila o tome ko ili šta može da pristupi određenim delovima sistema**, kao što su datoteke, aplikacije i sistemski resursi. Automatskim sprovođenjem ovih pravila, MACF obezbeđuje da samo ovlašćeni korisnici i procesi mogu da obavljaju određene radnje, čime se smanjuje rizik od neovlašćenog pristupa ili zlonamernih aktivnosti.

Imajte na umu da MACF zapravo ne donosi odluke, već samo **presreće** radnje. Odluke prepušta **policy modulima** (kernel ekstenzijama) koje poziva, kao što su `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` i `mcxalr.kext`.

- Policy može da sprovodi pravila (vraća vrednost različitu od 0 za neke operacije)
- Policy može da nadgleda (vraća 0 kako se ne bi protivio, ali koristi hook da bi obavio neku radnju)
- MACF statički policy instalira se pri pokretanju i NIKADA se ne uklanja
- MACF dinamički policy instalira KEXT (`kextload`) i teoretski se može ukloniti komandom `kextunload`
- U iOS-u su dozvoljeni samo statički policy-ji, a u macOS-u i statički i dinamički.<sup>[[7]](#references)</sup>

### Tok

1. Proces izvršava syscall/mach trap
2. Relevantna funkcija se poziva unutar kernela
3. Funkcija poziva MACF
4. MACF proverava policy module koji su u svom policy-ju zatražili hook za tu funkciju
5. MACF poziva relevantne policy-je
6. Policy-ji određuju da li dozvoljavaju ili odbijaju radnju

> [!CAUTION]
> Samo Apple može da koristi MAC Framework KPI.

Funkcije koje proveravaju dozvole pomoću MACF-a obično pozivaju makro `MAC_CHECK`. Na primer, syscall za kreiranje socket-a poziva funkciju `mac_socket_check_create`, koja poziva `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Pored toga, makro `MAC_CHECK` definisan je u `security/mac_internal.h` kao:<sup>[[3]](#references)</sup>
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

Proširivanje pomoćnih makroa prikazuje konkretan tok kontrole:

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

Drugim rečima, `MAC_CHECK(socket_check_create, ...)` prvo prolazi kroz statičke politike, uslovno zaključava i iterira kroz dinamičke politike, emituje DTrace probe oko svakog hook-a i objedinjuje povratne kodove svih hook-ova u jedan rezultat `error` pomoću `mac_error_select()`.


### Oznake

MACF koristi **oznake**, koje zatim koriste politike prilikom odlučivanja da li treba da odobre pristup. Deklaracija strukture oznaka može se [pronaći ovde](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), a koristi se unutar **`struct ucred`**, [ovde](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86), u delu **`cr_label`**. Oznaka sadrži zastavice i određeni broj **slotova** koje **MACF politike mogu da koriste za alociranje pokazivača**. Na primer, Sandbox pokazuje na profil kontejnera.

## MACF politike

MACF politika definiše **pravila i uslove koji se primenjuju pri određenim operacijama kernela**.

Kernel ekstenzija može da konfiguriše strukturu `mac_policy_conf`, a zatim da je registruje pozivanjem funkcije `mac_policy_register`. Iz [ovog izvora](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>

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

Lako je identifikovati kernel ekstenzije koje konfigurišu ove politike proverom poziva `mac_policy_register`. Štaviše, pregledom disasembliranog koda ekstenzije moguće je pronaći i korišćenu strukturu `mac_policy_conf`.

Imajte na umu da se MACF politike mogu registrovati i odregistrirati **dinamički**.

Jedno od glavnih polja strukture `mac_policy_conf` jeste **`mpc_ops`**. Ovo polje određuje koje operacije su od interesa za politiku. Ima ih na stotine, pa je moguće postaviti sve unose na nulu, a zatim izabrati samo one koji su potrebni politici. Iz [ovog izvora](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>

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

Skoro sve hook-ove će MACF pozvati kada se presretne neka od tih operacija. Međutim, hook-ovi **`mpo_policy_*`** su izuzetak, jer je **`mpo_hook_policy_init()`** callback koji se poziva prilikom registracije (dakle, nakon `mac_policy_register()`), dok se **`mpo_hook_policy_initbsd()`** poziva tokom kasne registracije, kada se BSD podsistem pravilno inicijalizuje.

Pored toga, bilo koji kext može da registruje hook **`mpo_policy_syscall`** kako bi izložio privatni **ioctl**-stil **interfejsa** za pozive. Zatim, user client može da pozove `mac_syscall` (#381) i kao parametre navede **naziv polise**, celobrojni **kôd** i opcione **argumente**.\
Na primer, **`Sandbox.kext`** ovo često koristi.

Pregledom **`__DATA.__const*`** kext-a moguće je identifikovati strukturu `mac_policy_ops` koja se koristi prilikom registracije polise. Može se pronaći jer se njen pokazivač nalazi na određenom pomeraju unutar `mpo_policy_conf`, kao i po broju NULL pokazivača u toj oblasti.

Pored toga, moguće je dobiti listu kext-ova koji su konfigurisali polisu tako što se iz memorije izvuče struktura **`_mac_policy_list`**, koja se ažurira pri svakoj registraciji polise.

Možete koristiti i alat `xnoop` za izlistavanje svih polisa registrovanih u sistemu:

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

## Inicijalizacija MACF-a u XNU-u

### Rano pokretanje i mac_policy_init()

- MACF se inicijalizuje veoma rano. U `bootstrap_thread` (u XNU kodu za pokretanje), nakon `ipc_bootstrap`, XNU poziva `mac_policy_init()` (u `mac_base.c`).
- `mac_policy_init()` inicijalizuje globalni `mac_policy_list` (niz ili listu mesta za politike) i postavlja infrastrukturu za MAC (Mandatory Access Control) unutar XNU-a.
- Kasnije se poziva `mac_policy_initmach()`, koja obrađuje registraciju politika na strani kernela za ugrađene ili objedinjene politike.

### `mac_policy_initmach()` и учитавање „security extensions“

- `mac_policy_initmach()` прегледа kernel extensions (kexts) који су унапред учитани (или се налазе на листи за „policy injection“) и проверава њихов Info.plist тражећи кључ `AppleSecurityExtension`.
- Kexts који у свом Info.plist-у имају `<key>AppleSecurityExtension</key>` (или `true`) сматрају се „security extensions“ — односно онима који имплементирају MAC policy или се повезују са MACF инфраструктуром.
- Примери Apple kexts-а са тим кључем су **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** и други (као што сте већ навели).
- Kernel обезбеђује да се ти kexts учитају рано, а затим током покретања позива њихове рутине за регистрацију (преко `mac_policy_register`), чиме их убацује у `mac_policy_list`.

  - Сваки policy модул (kext) обезбеђује структуру `mac_policy_conf`, са hooks (`mpc_ops`) за различите MAC операције (провере vnode-а, провере exec-а, ажурирање ознака итд.).
  - Заставице за време учитавања могу да садрже `MPC_LOADTIME_FLAG_NOTLATE`, што значи „мора да се учита рано“ (па се каснији покушаји регистрације одбијају).
  - Након регистрације, сваки модул добија handle и заузима место у `mac_policy_list`.
  - Када се касније позове MAC hook (на пример, за приступ vnode-у, exec итд.), MACF пролази кроз све регистроване политике да би донео заједничку одлуку.

- Конкретно, **AMFI** (Apple Mobile File Integrity) је такво security extension проширење. Његов Info.plist садржи `AppleSecurityExtension`, који га означава као security policy.
- Као део покретања kernela, логика учитавања обезбеђује да „security policy“ (AMFI итд.) буде активна пре него што многи подсистеми почну да зависе од ње. На пример, kernel се „припрема за предстојеће задатке учитавањем … security policy-ја, укључујући AppleMobileFileIntegrity (AMFI), Sandbox и Quarantine policy.“ 

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

## KPI zavisnost i com.apple.kpi.dsep u MAC policy kext-ovima

Kada pišete kext koji koristi MAC framework (tj. poziva `mac_policy_register()` itd.), morate da navedete zavisnosti od KPI-jeva (Kernel Programming Interfaces) kako bi kext linker (kxld) mogao da razreši te simbole. Dakle, da biste naveli da `kext` zavisi od MACF-a, to morate da naznačite u `Info.plist` pomoću `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`). Zatim će kext koristiti simbole kao što su `mac_policy_register`, `mac_policy_unregister` i pokazivači na MAC hook funkcije. Da bi se oni razrešili, morate da navedete `com.apple.kpi.dsep` kao zavisnost.

Primer isečka iz Info.plist-a (unutar vašeg .kext):

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



## MACF na modernim izdanjima macOS-a

Na modernom macOS-u, Apple-ove bezbednosne politike obično nije najbolje posmatrati kao labave, samostalne `.kext` pakete. Od **macOS 11**, kernel extensions se povezuju u **kernel collections**; na **Apple Silicon** uređajima ne postoji zaseban **SystemKC**, a kexts trećih strana mogu da se učitaju tek kada se ugrade u **Auxiliary Kernel Collection (AuxKC)** i nakon ponovnog pokretanja. Za MACF istraživanje to znači da je ugrađene politike kao što su **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** ili **Quarantine** obično lakše izlistati pomoću `kmutil` nego zastarelim alatima kao što je `kextstat`.

```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```

> [!TIP]
> Na Apple Silicon-u, ako se security kext ne nalazi u BootKC-u, sledeće proverite AuxKC. To je obično korisnije nego tražiti zaseban bundle u `/System/Library/Extensions`.

## MACF pozivi

Uobičajeno je naići na pozive MACF-a definisane u kodu, na primer u uslovnim blokovima **`#if CONFIG_MAC`**. Pored toga, unutar ovih blokova moguće je pronaći pozive `mac_proc_check*`, koji pozivaju MACF da **proveri dozvole** za izvršavanje određenih radnji. Takođe, format poziva MACF-a je: **`mac_<object>_<opType>_opName`**.

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

Zatim, kod funkcije `mac_file_check_mmap` možete pronaći na [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)

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

Koji poziva makro `MAC_CHECK`, čiji se kod može pronaći na [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>

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

Ova funkcija prolazi kroz registrovane politike i objedinjuje njihove rezultate pomoću `mac_error_select()`. Nulta vrednost koju vrati kasnija provera ne može da poništi ranije odbijanje; ako više politika odbije zahtev, funkcija bira grešku prema prioritetu (na primer, `EACCES` ima prednost nad `EPERM`).<sup>[[2]](#references)</sup>

> [!TIP]
> Ipak, imajte na umu da se svi MACF callback-ovi ne koriste samo za odbijanje radnji. Na primer, `mac_priv_grant` poziva makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), koji će dodeliti traženu privilegiju ako bilo koja politika vrati 0:
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
Neki kernel kod poziva `priv_check_cred()` iz [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c), prosleđujući KAuth kredencijale procesa i jednu od privilegija. Ta funkcija poziva `mac_priv_check` da proveri da li neka policy **uskraćuje** dodelu privilegije, a zatim poziva `mac_priv_grant` da proveri da li neka policy dodeljuje `privilege`.<sup>[[4]](#references)</sup>

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

Što će proveriti u **bitmask**-u procesa koji poziva da li trenutni syscall treba da pozove `mac_proc_check_syscall_unix`. To je zato što se syscall-ovi pozivaju veoma često, pa je korisno izbeći pozivanje funkcije `mac_proc_check_syscall_unix` svaki put.

Imajte na umu da funkciju `proc_set_syscall_filter_mask()`, koja postavlja bitmask syscall-ova u procesu, poziva Sandbox da bi postavio maske na sandbox-ovane procese.

## MACF syscall-ovi koji su izloženi

Moguće je komunicirati sa MACF-om preko nekih syscall-ova definisanih u [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):

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

Za ofanzivni reverse engineering, **`__mac_syscall`** je i dalje jedna od najboljih tačaka presretanja u userland-u. Prenosi **ime politike** (na primer `"Sandbox"` ili `"AMFI"`), **selektor/kod specifičan za politiku** i pokazivač na **neprozirni blok argumenata** koji će obraditi `mpo_policy_syscall`. Ovo je veoma korisno kada se prvo iz userland-a reverzno analizira nedokumentovana operacija, a tek kasnije prelazi na implementaciju u kernelu. Sandbox do njega često dolazi preko `__sandbox_ms`, a AMFI koristi isti mehanizam za odluke o dyld politici.<sup>[[2]](#references)[[5]](#references)</sup>

## Praktične beleške za ofanzivno istraživanje

Nedavne macOS ranjivosti retko direktno „zaobilaze MACF“. Umesto toga, obično zloupotrebljavaju **desinhronizaciju između odluke MACF / Sandbox / TCC i privilegovane radnje koja se izvršava kasnije**.

### Atributi pokretanja specifični za politiku kao MACF ulaz

`posix_spawnattr_setmacpolicyinfo_np()` dodaje ime politike i neprozirne bajtove zahtevu za `posix_spawn()`. XNU traži te bajtove prema `mpc_name` svake registrovane politike i prosleđuje ih exec-label hook-u te politike; hook za launch-constraints takođe čita odgovarajuće bajtove. Ovo je zaseban, napadaču dostupan ulazni put za MACF, različit od `__mac_syscall`. Proverite da li politika te bajtove tretira kao *dodatno ograničenje* ili im dozvoljava da zamene postojeću politiku roditelja ili izvršne datoteke.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Za kontrolisani test, počnite sa ograničenim roditeljskim procesom i pokrenite isti child **bez atributa specifičnog za politiku i sa njim**. Uporedite efektivni pristup child procesa resursu koji roditelj ne može da koristi; samo uspešno pokretanje ne dokazuje da je granica probijena.<sup>[[12]](#references)[[13]](#references)</sup>

Pri reverznom analiziranju politike pratite `mpo_cred_label_update_execve` i `mpo_proc_check_launch_constraints`, a zatim proverite da li pozivalac može da prosledi atribut.<sup>[[10]](#references)[[11]](#references)</sup> AMFI je istorijski prihvatao prosleđene launch constraints umesto ugrađenih; Sandbox je mogao da primeni imenovani ugrađeni profil na child proces umesto da sačuva ograničenja roditelja.<sup>[[13]](#references)[[12]](#references)</sup> Oba ponašanja su ispravljena, zato nemojte pretpostaviti da se bilo koje od njih javlja na aktuelnim sistemima.<sup>[[13]](#references)[[12]](#references)</sup>

Pogledajte [analizu launch-constraints](macos-launch-environment-constraints.md) za AMFI slučaj i [Sandbox debugging](macos-sandbox/macos-sandbox-debug-and-bypass/) za testiranje efektivne politike child procesa.

### Provere putanje u brokeru naspram stvarne privilegovane radnje

Čest obrazac je privilegovani daemon koji izvršava **proveru pre izvršavanja u userland-u** (na primer, `sandbox_check_by_audit_token()`) nad jednom verzijom putanje, a kasnije izvršava stvarni privilegovani cilj koristeći **drugačiju ili nekannoničnu putanju koju kontroliše napadač**. Nedavna istraživanja `diskarbitrationd` / `storagekitd` dobar su primer: **directory traversal** i **zamene symlink-a** omogućavaju napadaču da prođe proveru sandbox-a u daemon-u, a zatim montira preko osetljivih lokacija kao što je `~/Library/Application Support/com.apple.TCC`, pretvarajući ranjivost u **sandbox escape**, **lokalnu eskalaciju privilegija** ili **TCC bypass**, u zavisnosti od izabrane tačke montiranja.<sup>[[6]](#references)</sup>

Pri proveri root broker-a dostupnih iz sandbox-a, prvo pretražite:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, pomoćne funkcije za kanonikalizaciju putanja
- privilegovane ciljeve kao što su `mount`, `rename`, `copyfile`, XPC metode helper alata ili bilo šta što kasnije kao root pristupa putanjama koje kontroliše napadač

### Pouzdani posrednici sa privatnim entitlement-ima

Još jedan praktičan obrazac je izbeći direktan napad na MACF hook-ove i umesto toga zloupotrebiti **pouzdan proces** koji već poseduje prava potrebna za prelazak granice. Nedavna istraživanja Safari/TCC dobar su primer: zanimljiv primitiv nije bio „isključiti TCC u kernelu“, već izmeniti lokalnu politiku/konfiguraciju tako da Apple-ovim potpisan proces sa **`com.apple.private.tcc.allow`** izvrši osetljivu radnju u vaše ime.<sup>[[8]](#references)</sup> U praksi, ciljevi visokog prioriteta za proveru su Apple daemon-i/aplikacije koji kombinuju:

- **privatne entitlement-e** ili pristup nalik FDA-u
- konfiguraciju / bazu podataka / tačku montiranja / datoteku politike u koju je moguće pisati
- naknadnu osetljivu operaciju koju posreduje **Sandbox**, **AMFI**, **TCC** ili druga MACF politika

Za dublji reverse engineering specifičnih proizvoda, pogledajte posebne stranice o [macOS Sandbox](macos-sandbox/README.md) i [macOS TCC](macos-tcc/README.md).



## References

- [1] [XNU — `security/mac_policy.h` (kompletny vektor operacija MACF politike)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (makroi `MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (kodovi privilegija koje koriste `priv_check`/`priv_grant`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (ofanzivna bezbednost)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Otkrivanje Apple ranjivosti: revizija `diskarbitrationd` i `storagekitd`, 2. deo](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — alat za unakrsno referenciranje XNU-a](https://newosxbook.com/xxr/index.php)
- [8] [Nova ranjivost u macOS-u, „HM Surf“, mogla bi da omogući neovlašćeni pristup podacima (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
- [9] [XNU — setter atributa politike za `posix_spawn`](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/spawn/posix_spawn.c)
- [10] [XNU — prosleđivanje exec-label atributa specifičnog za politiku](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_vfs.c)
- [11] [XNU — prosleđivanje launch-constraints politike](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_process.c)
- [12] [Izlazak iz Apple Sandbox-a pokretanjem izvršne datoteke](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [13] [Zaobilaženje Launch Constraints-a u macOS-u](https://wts.dev/posts/bypassing-launch-constraints/)
{{#include ../../../banners/hacktricks-training.md}}
