# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF** steht für **Mandatory Access Control Framework**. Es ist ein in das Betriebssystem integriertes Sicherheitssystem, das deinen Computer schützt. Dazu legt es **strenge Regeln dafür fest, wer oder was auf bestimmte Teile des Systems zugreifen darf**, etwa auf Dateien, Anwendungen und Systemressourcen. Durch die automatische Durchsetzung dieser Regeln stellt MACF sicher, dass nur autorisierte Benutzer und Prozesse bestimmte Aktionen ausführen können. Dadurch wird das Risiko unbefugten Zugriffs oder böswilliger Aktivitäten verringert.

Beachte, dass MACF selbst keine Entscheidungen trifft, sondern Aktionen lediglich **abfängt**. Die Entscheidungen überlässt es den **policy modules** (Kernel-Erweiterungen), die es aufruft, etwa `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` und `mcxalr.kext`.

- Eine policy kann Aktionen durchsetzen (bei bestimmten Operationen 0 oder einen Wert ungleich null zurückgeben)
- Eine policy kann Aktionen überwachen (0 zurückgeben, um keinen Einwand zu erheben, aber den Hook zu nutzen, um etwas auszuführen)
- Eine statische MACF policy wird beim Booten installiert und wird NIEMALS entfernt
- Eine dynamische MACF policy wird von einem KEXT installiert (kextload) und könnte theoretisch mit kextunload entladen werden
- In iOS sind nur statische policies erlaubt, in macOS hingegen statische und dynamische.<sup>[[7]](#references)</sup>

### Flow

1. Ein Prozess führt einen syscall/mach trap aus
2. Die entsprechende Funktion wird im Kernel aufgerufen
3. Die Funktion ruft MACF auf
4. MACF prüft die policy modules, die in ihrer policy einen Hook für diese Funktion angefordert haben
5. MACF ruft die entsprechenden policies auf
6. Die policies geben an, ob sie die Aktion zulassen oder verweigern

> [!CAUTION]
> Nur Apple kann das MAC Framework KPI verwenden.

Üblicherweise rufen die Funktionen, die Berechtigungen mit MACF prüfen, das Makro `MAC_CHECK` auf. Beim syscall zum Erstellen eines Sockets wird beispielsweise die Funktion `mac_socket_check_create` aufgerufen, die `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` aufruft. Außerdem ist das Makro `MAC_CHECK` in security/mac_internal.h wie folgt definiert:<sup>[[3]](#references)</sup>
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

Beachte, dass du durch Umwandeln von `check` in `socket_check_create` und von `args...` in `(cred, domain, type, protocol)` Folgendes erhältst:

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

Durch Expansion der Helper-Makros wird der konkrete Kontrollfluss sichtbar:

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

In anderen Worten: `MAC_CHECK(socket_check_create, ...)` durchläuft zuerst die statischen Policies, sperrt bei Bedarf und iteriert über die dynamischen Policies, gibt DTrace-Probes um jeden Hook herum aus und fasst den Rückgabecode jedes Hooks mithilfe von `mac_error_select()` zu einem einzigen Ergebnis `error` zusammen.


### Labels

MACF verwendet **Labels**, die die Policies anschließend heranziehen, um zu entscheiden, ob sie einen Zugriff gewähren sollen. Der Code für die Deklaration der Label-Struktur ist [hier zu finden](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h). Sie wird anschließend im **`struct ucred`** unter [**hier**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) im Teil **`cr_label`** verwendet. Das Label enthält Flags und eine bestimmte Anzahl von **Slots**, die von **MACF-Policies zum Speichern von Pointern** verwendet werden können. Beispielsweise verweist Sandbox auf das Container-Profil.

## MACF Policies

Eine MACF Policy definiert **Regeln und Bedingungen, die bei bestimmten Kernel-Operationen angewendet werden**.

Eine Kernel-Erweiterung kann eine `mac_policy_conf`-Struktur konfigurieren und sie anschließend durch Aufruf von `mac_policy_register` registrieren. Von [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>

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

Es ist einfach, die Kernel-Erweiterungen zu identifizieren, die diese Richtlinien konfigurieren, indem man Aufrufe von `mac_policy_register` überprüft. Außerdem ist es möglich, durch Überprüfung der Disassemblierung der Erweiterung die verwendete `mac_policy_conf`-Struktur zu finden.

Beachte, dass MACF-Richtlinien auch **dynamisch** registriert und deregistriert werden können.

Eines der Hauptfelder von `mac_policy_conf` ist **`mpc_ops`**. Dieses Feld gibt an, für welche Operationen sich die Richtlinie interessiert. Es gibt Hunderte davon, daher können alle Einträge auf null gesetzt und anschließend nur die von der Richtlinie benötigten ausgewählt werden. Von [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>

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

Fast alle Hooks werden von MACF aufgerufen, wenn eine dieser Operationen abgefangen wird. Die **`mpo_policy_*`**-Hooks sind jedoch eine Ausnahme, da `mpo_hook_policy_init()` ein Callback ist, der bei der Registrierung (also nach `mac_policy_register()`) aufgerufen wird, während `mpo_hook_policy_initbsd()` während der späten Registrierung aufgerufen wird, sobald das BSD-Subsystem ordnungsgemäß initialisiert wurde.

Außerdem kann jeder Kext den **`mpo_policy_syscall`**-Hook registrieren, um ein privates **ioctl**-artiges Aufruf-**Interface** bereitzustellen. Ein User Client kann dann `mac_syscall` (#381) aufrufen und dabei als Parameter den **Policy-Namen**, einen Integer-**Code** sowie optionale **Argumente** angeben.\
Zum Beispiel nutzt **`Sandbox.kext`** dies häufig.

Anhand von **`__DATA.__const*`** des Kexts lässt sich die beim Registrieren der Policy verwendete Struktur `mac_policy_ops` identifizieren. Sie ist auffindbar, weil sich ihr Zeiger an einem Offset innerhalb von `mpo_policy_conf` befindet und weil sich in diesem Bereich zahlreiche NULL-Zeiger befinden.

Außerdem lässt sich die Liste der Kexts, die eine Policy konfiguriert haben, ermitteln, indem die Struktur **`_mac_policy_list`** aus dem Arbeitsspeicher ausgelesen wird. Sie wird bei jeder registrierten Policy aktualisiert.

Mit dem Tool `xnoop` können Sie auch alle im System registrierten Policies ausgeben:

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

Und anschließend alle Prüfungen der Check-Policy mit folgendem Befehl ausgeben:

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

## MACF-Initialisierung in XNU

### Früher Bootstrap und mac_policy_init()

- MACF wird sehr früh initialisiert. In `bootstrap_thread` (im XNU-Startcode) ruft XNU nach `ipc_bootstrap` `mac_policy_init()` (in `mac_base.c`) auf.
- `mac_policy_init()` initialisiert die globale `mac_policy_list` (ein Array oder eine Liste von Policy-Slots) und richtet die Infrastruktur für MAC (Mandatory Access Control) innerhalb von XNU ein.
- Später wird `mac_policy_initmach()` aufgerufen. Diese Funktion übernimmt die Registrierung von Policies auf der Kernel-Seite für integrierte oder gebündelte Policies.

### `mac_policy_initmach()` und das Laden von „Sicherheitserweiterungen“

- `mac_policy_initmach()` untersucht vorab geladene Kernel-Erweiterungen (kexts) (oder solche in einer „Policy-Injection“-Liste) und prüft deren Info.plist auf den Schlüssel `AppleSecurityExtension`.
- Kexts, die `<key>AppleSecurityExtension</key>` (oder `true`) in ihrer Info.plist deklarieren, gelten als „Sicherheitserweiterungen“ – das heißt, sie implementieren eine MAC-Policy oder binden sich in die MACF-Infrastruktur ein.
- Beispiele für Apple-kexts mit diesem Schlüssel sind unter anderem **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext** und **AppleSystemPolicy.kext** (wie bereits aufgeführt).
- Der Kernel stellt sicher, dass diese kexts früh geladen werden, und ruft dann während des Bootvorgangs ihre Registrierungsroutinen (über `mac_policy_register`) auf, um sie in die `mac_policy_list` aufzunehmen.

  - Jedes Policy-Modul (kext) stellt eine `mac_policy_conf`-Struktur mit Hooks (`mpc_ops`) für verschiedene MAC-Operationen bereit (vnode-Prüfungen, exec-Prüfungen, Label-Aktualisierungen usw.).
  - Die Flags für den Ladezeitpunkt können `MPC_LOADTIME_FLAG_NOTLATE` enthalten. Das bedeutet, dass das Modul „früh geladen werden muss“ (spätere Registrierungsversuche werden abgelehnt).
  - Nach der Registrierung erhält jedes Modul ein Handle und belegt einen Slot in `mac_policy_list`.
  - Wenn später ein MAC-Hook aufgerufen wird (zum Beispiel bei vnode-Zugriff, exec usw.), durchläuft MACF alle registrierten Policies, um gemeinsam eine Entscheidung zu treffen.

- Insbesondere ist **AMFI** (Apple Mobile File Integrity) eine solche Sicherheitserweiterung. Die Info.plist enthält `AppleSecurityExtension`, wodurch AMFI als Sicherheits-Policy gekennzeichnet wird.
- Beim Kernel-Bootvorgang stellt die Kernel-Ladelogik sicher, dass die „Security-Policy“ (AMFI usw.) bereits aktiv ist, bevor viele Subsysteme von ihr abhängen. Zum Beispiel „bereitet sich der Kernel auf die anstehenden Aufgaben vor, indem er … die Security-Policy lädt, einschließlich AppleMobileFileIntegrity (AMFI), Sandbox und der Quarantine-Policy“. 

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

## KPI-Abhängigkeit & com.apple.kpi.dsep in MAC-Policy-Kexts

Wenn du ein Kext schreibst, das das MAC-Framework verwendet (d. h. `mac_policy_register()` usw. aufruft), musst du Abhängigkeiten von KPIs (Kernel Programming Interfaces) deklarieren, damit der Kext-Linker (kxld) diese Symbole auflösen kann. Daher musst du, damit ein `kext` von MACF abhängt, dies in der `Info.plist` mit `com.apple.kpi.dsep` angeben (`find . Info.plist | grep AppleSecurityExtension`). Anschließend verweist das Kext auf Symbole wie `mac_policy_register`, `mac_policy_unregister` und Funktionszeiger für MAC-Hooks. Damit diese aufgelöst werden können, musst du `com.apple.kpi.dsep` als Abhängigkeit aufführen.

Beispiel für einen `Info.plist`-Ausschnitt (innerhalb deines .kext):

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



## MACF unter modernen macOS-Versionen

Unter modernen macOS-Versionen lassen sich Apples Sicherheitsrichtlinien in der Regel nicht am besten als lose, eigenständige `.kext`-Bundles betrachten. Seit **macOS 11** werden Kernel-Erweiterungen in **Kernel-Collections** eingebunden; auf **Apple Silicon** gibt es kein separates **SystemKC**, und Kexts von Drittanbietern können erst geladen werden, nachdem sie in die **Auxiliary Kernel Collection (AuxKC)** eingebunden wurde und ein Neustart erfolgt ist. Für die MACF-Forschung bedeutet das, dass integrierte Richtlinien wie **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** oder **Quarantine** meist einfacher mit `kmutil` als mit veralteten Tools wie `kextstat` aufzulisten sind.

```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```

> [!TIP]
> Wenn sich auf Apple Silicon ein Security-Kext nicht im BootKC befindet, prüfe als Nächstes das AuxKC. Das ist meist sinnvoller, als nach einem eigenständigen Bundle unter `/System/Library/Extensions` zu suchen.

## MACF Callouts

Callouts zu MACF sind häufig in Code innerhalb bedingter Blöcke wie **`#if CONFIG_MAC`** definiert. Außerdem finden sich in diesen Blöcken Aufrufe von `mac_proc_check*`, die MACF aufrufen, um **Berechtigungen für bestimmte Aktionen zu prüfen**. Das Format der MACF-Callouts lautet: **`mac_<object>_<opType>_opName`**.

`object` ist einer der folgenden Werte: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` ist normalerweise `check` und wird verwendet, um die Aktion zuzulassen oder zu verweigern. Es kann aber auch `notify` vorkommen, wodurch der Kext auf die jeweilige Aktion reagieren kann.

Ein Beispiel findest du unter [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Den Code von `mac_file_check_mmap` findest du unter [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)

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

Dabei wird das Makro `MAC_CHECK` aufgerufen, dessen Code unter [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup> zu finden ist.

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

This durchläuft die registrierten Policies und kombiniert ihre Ergebnisse mit `mac_error_select()`. Ein Rückgabewert von null bei einer späteren Prüfung kann eine frühere Verweigerung nicht aufheben. Wenn mehrere Policies den Zugriff verweigern, wählt die Funktion den Fehler anhand seiner Priorität aus (zum Beispiel `EACCES` vor `EPERM`).<sup>[[2]](#references)</sup>

> [!TIP]
> Beachten Sie jedoch, dass nicht alle MACF-Callouts ausschließlich dazu dienen, Aktionen zu verweigern. Beispielsweise ruft `mac_priv_grant` das Makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) auf, das die angeforderte Berechtigung erteilt, wenn eine Policy mit 0 antwortet:
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

Diese Aufrufe dienen dazu, die in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) definierten **Privilegien** zu prüfen und zu gewähren.\
Ein Teil des Kernel-Codes ruft `priv_check_cred()` aus [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) mit den KAuth-Anmeldedaten des Prozesses und einem der Privilegiencodes auf. Dieser ruft `mac_priv_check` auf, um zu prüfen, ob eine Richtlinie die Gewährung des Privilegs **verweigert**. Anschließend ruft er `mac_priv_grant` auf, um zu prüfen, ob eine Richtlinie das `privilege` gewährt.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Dieser Hook ermöglicht es, alle Systemaufrufe abzufangen. In `bsd/dev/[i386|arm]/systemcalls.c` ist die deklarierte Funktion [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) zu sehen, die folgenden Code enthält:

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

Die Funktion überprüft in der **Bitmaske** des aufrufenden Prozesses, ob für den aktuellen syscall `mac_proc_check_syscall_unix` aufgerufen werden soll. Da syscalls sehr häufig aufgerufen werden, ist es sinnvoll, `mac_proc_check_syscall_unix` nicht jedes Mal aufzurufen.

Beachte, dass die Funktion `proc_set_syscall_filter_mask()`, die die syscalls-Bitmaske in einem Prozess setzt, von Sandbox aufgerufen wird, um Masken für sandboxed Prozesse festzulegen.

## MACF-syscalls

Es ist möglich, über einige in [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) definierte syscalls mit MACF zu interagieren:

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

Für offensives Reverse Engineering ist **`__mac_syscall`** nach wie vor einer der besten Userland-Engpässe. Der Aufruf übermittelt einen **Policy-Namen** (zum Beispiel `"Sandbox"` oder `"AMFI"`), einen **Policy-spezifischen Selector/Code** und einen Zeiger auf den **undurchsichtigen Argument-Blob**, der von `mpo_policy_syscall` verarbeitet wird. Das ist sehr nützlich, wenn man undokumentierte Operationen zunächst aus dem Userland heraus untersucht und erst später zur Kernel-Implementierung übergeht. Sandbox erreicht den Aufruf häufig über `__sandbox_ms`, und AMFI verwendet denselben Mechanismus für dyld-Policy-Entscheidungen.<sup>[[2]](#references)[[5]](#references)</sup>

## Praktische Hinweise für offensive Forschung

Aktuelle macOS-Bugs „brechen MACF“ selten direkt. Stattdessen nutzen sie meist eine **Desynchronisierung zwischen einer MACF- / Sandbox- / TCC-Entscheidung und der privilegierten Aktion, die später ausgeführt wird**.

### Policy-spezifische Spawn-Attribute als MACF-Eingabe

`posix_spawnattr_setmacpolicyinfo_np()` fügt einer `posix_spawn()`-Anfrage einen Policy-Namen und undurchsichtige Bytes hinzu. XNU sucht diese Bytes anhand von `mpc_name` für jede registrierte Policy und übergibt sie an den Exec-Label-Hook dieser Policy; auch der Launch-Constraints-Hook liest die passenden Bytes. Dies ist ein separater, vom Angreifer kontrollierter MACF-Eingabepfad, unabhängig von `__mac_syscall`. Prüfe, ob die Policy diese Bytes als *zusätzliche Einschränkung* behandelt oder damit die bestehende Policy des Elternprozesses oder der ausführbaren Datei ersetzt.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Beginne für einen kontrollierten Test mit einem eingeschränkten Elternprozess und starte denselben Kindprozess **ohne** und **mit** einem policy-spezifischen Attribut. Vergleiche den effektiven Zugriff des Kindprozesses auf eine Ressource, die der Elternprozess nicht verwenden kann; ein erfolgreicher Spawn allein beweist nicht, dass eine Sicherheitsgrenze überschritten wurde.<sup>[[12]](#references)[[13]](#references)</sup>

Verfolge beim Reverse Engineering der Policy `mpo_cred_label_update_execve` und `mpo_proc_check_launch_constraints` und prüfe dann, ob der Aufrufer das Attribut übergeben darf.<sup>[[10]](#references)[[11]](#references)</sup> AMFI akzeptierte früher übergebene Launch Constraints anstelle der integrierten; Sandbox konnte einem Kindprozess ein benanntes integriertes Profil zuweisen, statt die Einschränkungen des Elternprozesses beizubehalten.<sup>[[13]](#references)[[12]](#references)</sup> Beide Verhaltensweisen wurden behoben. Gehe daher nicht davon aus, dass eines davon auf aktuellen Systemen noch möglich ist.<sup>[[13]](#references)[[12]](#references)</sup>

Weitere Informationen zum AMFI-Fall findest du in der [Analyse der Launch Constraints](macos-launch-environment-constraints.md) und zum Testen der effektiven Policy des Kindprozesses unter [Sandbox-Debugging](macos-sandbox/macos-sandbox-debug-and-bypass/).

### Prüfungen von Broker-Pfaden vs. tatsächliche privilegierte Aktionen

Ein wiederkehrendes Muster ist ein privilegierter Daemon, der eine **Userland-Vorprüfung** (zum Beispiel `sandbox_check_by_audit_token()`) für eine Version eines Pfads durchführt und später den eigentlichen privilegierten Sink mit einem **anderen oder nicht kanonischen, vom Angreifer kontrollierten Pfad** ausführt. Aktuelle Forschung zu `diskarbitrationd` / `storagekitd` ist ein gutes Beispiel: **Directory Traversal** zusammen mit **Symlink-Swaps** ermöglicht es dem Angreifer, die Sandbox-Prüfung des Daemons zu bestehen und anschließend sensible Speicherorte wie `~/Library/Application Support/com.apple.TCC` zu übermounten. Je nach gewähltem Mount-Punkt wird der Bug dadurch zu einem **Sandbox Escape**, einer **lokalen Rechteausweitung** oder einem **TCC-Bypass**.<sup>[[6]](#references)</sup>

Wenn du Root-Broker untersuchst, die aus der Sandbox erreichbar sind, suche zuerst nach:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, Hilfsfunktionen zur Pfadkanonisierung
- privilegierten Senken wie `mount`, `rename`, `copyfile`, XPC-Methoden von Hilfsprogrammen oder allem, was später als Root auf vom Angreifer kontrollierte Pfade zugreift

### Vertrauenswürdige Deputies mit privaten Entitlements

Ein weiteres praktisches Muster besteht darin, MACF-Hooks nicht direkt anzugreifen, sondern stattdessen einen **vertrauenswürdigen Prozess** auszunutzen, der bereits über die nötigen Rechte verfügt, um die Sicherheitsgrenze zu überschreiten. Aktuelle Safari-/TCC-Forschung ist ein gutes Beispiel: Die interessante Primitive war nicht „TCC im Kernel deaktivieren“, sondern die lokale Policy/Konfiguration so zu ändern, dass ein von Apple signierter Prozess mit **`com.apple.private.tcc.allow`** die sensible Aktion in deinem Auftrag ausführt.<sup>[[8]](#references)</sup> Besonders lohnende Ziele für die Untersuchung sind Apple-Daemons/-Apps, die Folgendes kombinieren:

- **private Entitlements** oder einen ähnlichen Zugriff wie FDA
- eine beschreibbare Konfiguration / Datenbank / einen Mount-Punkt / eine Policy-Datei
- eine spätere sensible Operation, die von **Sandbox**, **AMFI**, **TCC** oder einer anderen MACF-Policy vermittelt wird

Für tiefergehendes, produktspezifisches Reverse Engineering findest du weitere Informationen auf den speziellen Seiten zu [macOS Sandbox](macos-sandbox/README.md) und [macOS TCC](macos-tcc/README.md).



## References

- [1] [XNU — `security/mac_policy.h` (der vollständige Vektor der MACF-Policy-Operationen)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (Makros `MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (von `priv_check`/`priv_grant` verwendete Privilegiencodes)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI-Systemaufruf (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Apple-Schwachstellen aufgedeckt: Audit von diskarbitrationd und storagekitd, Teil 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — XNU-Cross-Reference-Tool](https://newosxbook.com/xxr/index.php)
- [8] [Neue macOS-Schwachstelle „HM Surf“ könnte zu unbefugtem Datenzugriff führen (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
- [9] [XNU — Setter für posix_spawn-Policy-Attribute](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/spawn/posix_spawn.c)
- [10] [XNU — Dispatch von policy-spezifischen Exec-Label-Attributen](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_vfs.c)
- [11] [XNU — Dispatch von Launch-Constraints-Policies](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_process.c)
- [12] [Die Apple Sandbox durch das Starten einer ausführbaren Datei umgehen](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [13] [Launch Constraints unter macOS umgehen](https://wts.dev/posts/bypassing-launch-constraints/)
{{#include ../../../banners/hacktricks-training.md}}
