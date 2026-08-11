# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

**MACF** steht für **Mandatory Access Control Framework** und ist ein in das Betriebssystem integriertes Sicherheitssystem, das zum Schutz des Computers beiträgt. Es funktioniert, indem es **strenge Regeln dafür festlegt, wer oder was auf bestimmte Teile des Systems zugreifen kann**, etwa auf Dateien, Anwendungen und Systemressourcen. Durch die automatische Durchsetzung dieser Regeln stellt MACF sicher, dass nur autorisierte Benutzer und Prozesse bestimmte Aktionen ausführen können, wodurch das Risiko unbefugten Zugriffs oder bösartiger Aktivitäten reduziert wird.

Beachte, dass MACF eigentlich keine Entscheidungen trifft, da es Aktionen lediglich **abfängt**. Die Entscheidungen werden den **policy modules** (Kernel-Erweiterungen) überlassen, die es aufruft, etwa `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` und `mcxalr.kext`.

- Eine Policy kann durchsetzen (bei einer Operation 0 oder einen Nicht-Null-Wert zurückgeben)
- Eine Policy kann überwachen (0 zurückgeben, um keinen Einwand zu erheben, sich aber in den Hook einzuklinken und etwas auszuführen)
- Eine statische MACF-Policy wird beim Booten installiert und wird NIEMALS entfernt
- Eine dynamische MACF-Policy wird durch ein KEXT (`kextload`) installiert und kann theoretisch per `kextunload` entladen werden
- In iOS sind nur statische Policies erlaubt, in macOS hingegen statische und dynamische.<sup>[[7]](#references)</sup>

### Ablauf

1. Der Prozess führt einen Syscall/Mach-Trap aus
2. Die relevante Funktion wird innerhalb des Kernels aufgerufen
3. Die Funktion ruft MACF auf
4. MACF prüft die policy modules, die in ihrer Policy einen Hook für diese Funktion angefordert haben
5. MACF ruft die relevanten Policies auf
6. Die Policies geben an, ob sie die Aktion erlauben oder verweigern

> [!CAUTION]
> Apple ist die einzige Instanz, die das MAC Framework KPI verwenden kann.

Üblicherweise rufen die Funktionen, die Berechtigungen mit MACF prüfen, das Makro `MAC_CHECK` auf. Im Fall eines Syscalls zum Erstellen eines Sockets wird beispielsweise die Funktion `mac_socket_check_create` aufgerufen, die `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` aufruft. Außerdem ist das Makro `MAC_CHECK` in `security/mac_internal.h` wie folgt definiert:<sup>[[3]](#references)</sup>
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
Beachte, dass du durch die Umwandlung von `check` in `socket_check_create` und von `args...` in `(cred, domain, type, protocol)` Folgendes erhältst:
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
Das Erweitern der Helper-Makros zeigt den konkreten Kontrollfluss:
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
Mit anderen Worten: `MAC_CHECK(socket_check_create, ...)` durchläuft zuerst die statischen Policies, sperrt und iteriert bedingt über die dynamischen Policies, gibt die DTrace-Probes rund um jeden Hook aus und fasst den Rückgabecode jedes Hooks über `mac_error_select()` im einzelnen Ergebnis `error` zusammen.


### Labels

MACF verwendet **Labels**, die anschließend von den Policies verwendet werden, um zu prüfen, ob sie einen bestimmten Zugriff gewähren sollen oder nicht. Der Code für die Deklaration der Label-Struktur ist [hier zu finden](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h). Sie wird anschließend innerhalb von **`struct ucred`** [hier](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) im Teil **`cr_label`** verwendet. Das Label enthält Flags und eine Anzahl von **Slots**, die von **MACF policies zur Allokation von Pointern** verwendet werden können. Beispielsweise zeigt Sandbox auf das Container-Profil.

## MACF Policies

Eine MACF Policy definiert **Regeln und Bedingungen, die auf bestimmte Kernel-Operationen angewendet werden**.

Eine Kernel Extension könnte eine `mac_policy_conf`-Struktur konfigurieren und sie anschließend durch den Aufruf von `mac_policy_register` registrieren. Von [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
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
Die Kernel Extensions, die diese Policies konfigurieren, lassen sich leicht identifizieren, indem man nach Aufrufen von `mac_policy_register` sucht. Außerdem ist es durch die Disassemblierung der Extension möglich, die verwendete `mac_policy_conf`-Struktur zu finden.

Beachte, dass MACF-Policies auch **dynamisch** registriert und deregistriert werden können.

Eines der wichtigsten Felder von `mac_policy_conf` ist **`mpc_ops`**. Dieses Feld legt fest, für welche Operationen sich die Policy interessiert. Es gibt Hunderte davon, daher ist es möglich, zunächst alle Einträge auf null zu setzen und anschließend nur diejenigen auszuwählen, die die Policy benötigt. Von [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
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
Fast alle Hooks werden von MACF zurückgerufen, wenn eine dieser Operationen abgefangen wird. Die **`mpo_policy_*`**-Hooks bilden jedoch eine Ausnahme, da `mpo_hook_policy_init()` ein Callback ist, der bei der Registrierung (also nach `mac_policy_register()`) aufgerufen wird, während `mpo_hook_policy_initbsd()` während der späten Registrierung aufgerufen wird, sobald das BSD-Subsystem ordnungsgemäß initialisiert wurde.

Außerdem kann der **`mpo_policy_syscall`**-Hook von jedem Kext registriert werden, um ein privates **ioctl**-ähnliches Aufruf-**Interface** bereitzustellen. Ein User Client kann dann `mac_syscall` (#381) aufrufen und dabei als Parameter den **Policy-Namen** mit einem Integer-**Code** und optionalen **Argumenten** angeben.\
Zum Beispiel verwendet **`Sandbox.kext`** dies häufig.

Durch die Untersuchung von **`__DATA.__const*`** des Kexts kann die beim Registrieren der Policy verwendete `mac_policy_ops`-Struktur identifiziert werden. Sie kann gefunden werden, weil sich ihr Pointer an einem Offset innerhalb von `mpo_policy_conf` befindet und außerdem aufgrund der Anzahl der NULL-Pointer, die sich in diesem Bereich befinden werden.

Außerdem ist es möglich, die Liste der Kexts abzurufen, die eine Policy konfiguriert haben, indem die Struktur **`_mac_policy_list`**, die mit jeder registrierten Policy aktualisiert wird, aus dem Speicher ausgelesen wird.

Du kannst auch das Tool `xnoop` verwenden, um alle im System registrierten Policies auszugeben:
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
Und dann alle Prüfungen der check policy mit folgendem Befehl ausgeben:
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

- MACF wird sehr früh initialisiert. In `bootstrap_thread` (im XNU-Startup-Code) ruft XNU nach `ipc_bootstrap` `mac_policy_init()` (in `mac_base.c`) auf.
- `mac_policy_init()` initialisiert die globale `mac_policy_list` (ein Array oder eine Liste von Policy-Slots) und richtet die Infrastruktur für MAC (Mandatory Access Control) innerhalb von XNU ein.
- Später wird `mac_policy_initmach()` aufgerufen, das die kernel-seitige Registrierung von Policies für integrierte oder gebündelte Policies übernimmt.

### `mac_policy_initmach()` und das Laden von „security extensions“

- `mac_policy_initmach()` untersucht vorausgeladene Kernel Extensions (kexts) (oder solche in einer „policy injection“-Liste) und prüft deren Info.plist auf den Schlüssel `AppleSecurityExtension`.
- Kexts, die `<key>AppleSecurityExtension</key>` (oder `true`) in ihrer Info.plist deklarieren, gelten als „security extensions“ – also als solche, die eine MAC-Policy implementieren oder sich in die MACF-Infrastruktur einklinken.
- Beispiele für Apple-kexts mit diesem Schlüssel sind unter anderem **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext** und **AppleSystemPolicy.kext** (wie bereits aufgelistet).
- Der Kernel stellt sicher, dass diese kexts früh geladen werden, und ruft dann während des Bootvorgangs deren Registrierungsroutinen (über `mac_policy_register`) auf, wobei sie in die `mac_policy_list` eingefügt werden.

- Jedes Policy-Modul (kext) stellt eine `mac_policy_conf`-Struktur mit Hooks (`mpc_ops`) für verschiedene MAC-Operationen bereit (vnode-Prüfungen, exec-Prüfungen, Label-Aktualisierungen usw.).
- Die Load-Time-Flags können `MPC_LOADTIME_FLAG_NOTLATE` enthalten, was bedeutet: „muss früh geladen werden“ (daher werden späte Registrierungsversuche abgelehnt).
- Nach der Registrierung erhält jedes Modul ein Handle und belegt einen Slot in der `mac_policy_list`.
- Wenn später ein MAC-Hook aufgerufen wird (beispielsweise für vnode-Zugriff, exec usw.), iteriert MACF über alle registrierten Policies, um gemeinsame Entscheidungen zu treffen.

- Insbesondere ist **AMFI** (Apple Mobile File Integrity) eine solche security extension. Seine Info.plist enthält `AppleSecurityExtension`, wodurch es als Security-Policy gekennzeichnet wird.
- Als Teil des Kernel-Bootvorgangs stellt die Kernel-Load-Logik sicher, dass die „Security-Policy“ (AMFI usw.) bereits aktiv ist, bevor viele Subsysteme von ihr abhängen. Beispielsweise „bereitet“ der Kernel „Tasks vor, indem er … die Security-Policy lädt, einschließlich AppleMobileFileIntegrity (AMFI), Sandbox und der Quarantine-Policy.“
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
## KPI-Abhängigkeit & com.apple.kpi.dsep in MAC policy kexts

Wenn du ein kext schreibst, das das MAC framework verwendet (d. h. `mac_policy_register()` usw. aufruft), musst du Abhängigkeiten von KPIs (Kernel Programming Interfaces) deklarieren, damit der kext-Linker (kxld) diese Symbole auflösen kann. Daher musst du, um zu deklarieren, dass ein `kext` von MACF abhängt, dies in der `Info.plist` mit `com.apple.kpi.dsep` angeben (`find . Info.plist | grep AppleSecurityExtension`). Anschließend wird das kext auf Symbole wie `mac_policy_register`, `mac_policy_unregister` und Funktionszeiger für MAC hooks verweisen. Um diese aufzulösen, musst du `com.apple.kpi.dsep` als Abhängigkeit auflisten.

Beispiel für einen Info.plist-Ausschnitt (innerhalb deines .kext):
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
## MACF in modernen macOS-Versionen

Unter modernen macOS-Versionen lassen sich die Sicherheitsrichtlinien von Apple in der Regel nicht am besten als lose, eigenständige `.kext`-Bundles betrachten. Seit **macOS 11** werden Kernel-Erweiterungen in **Kernel collections** eingebunden; auf **Apple Silicon** gibt es keine separate **SystemKC**, und Drittanbieter-kexts können erst geladen werden, nachdem sie in die **Auxiliary Kernel Collection (AuxKC)** eingebunden wurden und ein Neustart erfolgt ist. Für die MACF-Forschung bedeutet dies, dass sich integrierte Richtlinien wie **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** oder **Quarantine** meist leichter mit `kmutil` als mit veralteten Tools wie `kextstat` auflisten lassen.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Auf Apple Silicon solltest du als Nächstes die AuxKC prüfen, wenn sich ein Security kext nicht in der BootKC befindet. Das ist normalerweise nützlicher, als nach einem eigenständigen Bundle unter `/System/Library/Extensions` zu suchen.

## MACF Callouts

Es ist üblich, Callouts zu MACF in Code wie bedingten Blöcken mit **`#if CONFIG_MAC`** zu finden. Außerdem können innerhalb dieser Blöcke Aufrufe von `mac_proc_check*` gefunden werden, die MACF aufrufen, um **Berechtigungen zu prüfen**, bevor bestimmte Aktionen ausgeführt werden. Das Format der MACF-Callouts lautet außerdem: **`mac_<object>_<opType>_opName`**.

Das Objekt ist eines der folgenden: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
Der `opType` ist normalerweise check und wird verwendet, um die Aktion zu erlauben oder zu verweigern. Es ist jedoch auch möglich, `notify` zu finden, wodurch der kext auf die angegebene Aktion reagieren kann.

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

Anschließend ist es möglich, den Code von `mac_file_check_mmap` unter [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) zu finden.
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
Das das `MAC_CHECK`-Makro aufruft, dessen Code unter [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup> zu finden ist.
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
Dabei werden alle registrierten mac policies durchlaufen, ihre Funktionen aufgerufen und die Ausgabe in der Variable `error` gespeichert. Diese kann nur durch `mac_error_select` anhand von Erfolgscodes überschrieben werden. Wenn also eine Prüfung fehlschlägt, schlägt die gesamte Prüfung fehl und die Aktion wird nicht erlaubt.

> [!TIP]
> Denke jedoch daran, dass nicht alle MACF callouts ausschließlich zum Verweigern von Aktionen verwendet werden. Beispielsweise ruft `mac_priv_grant` das Makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) auf, das die angeforderte Berechtigung gewährt, wenn eine beliebige policy mit 0 antwortet:
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

Diese Aufrufe dienen dazu, die in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) definierten **Berechtigungen** zu prüfen und bereitzustellen.\
Ein Teil des Kernel-Codes ruft `priv_check_cred()` aus [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) mit den KAuth-Anmeldedaten des Prozesses und einem der Berechtigungscodes auf. Dieser ruft `mac_priv_check` auf, um zu prüfen, ob eine policy die Vergabe der Berechtigung **verweigert**, und anschließend `mac_priv_grant`, um zu prüfen, ob eine policy die `privilege` gewährt.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Dieser Hook ermöglicht das Abfangen aller Systemaufrufe. In `bsd/dev/[i386|arm]/systemcalls.c` ist die deklarierte Funktion [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) zu finden, die folgenden Code enthält:
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
Das prüft in der **bitmask** des aufrufenden Prozesses, ob der aktuelle syscall `mac_proc_check_syscall_unix` aufrufen sollte. Da syscalls so häufig aufgerufen werden, ist es sinnvoll, den Aufruf von `mac_proc_check_syscall_unix` jedes Mal zu vermeiden.

Beachte, dass die Funktion `proc_set_syscall_filter_mask()`, die die syscall-Bitmask in einem Prozess festlegt, von Sandbox aufgerufen wird, um Masken für sandboxed processes zu setzen.

## Exposed MACF syscalls

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
Für offensives Reversing ist **`__mac_syscall`** nach wie vor einer der besten Userland-Chokepoints. Es überträgt einen **policy name** (zum Beispiel `"Sandbox"` oder `"AMFI"`), einen **policy-specific selector/code** sowie einen Zeiger auf den **opaque argument blob**, der von `mpo_policy_syscall` verarbeitet wird. Das ist sehr nützlich, wenn undokumentierte Operationen zunächst aus dem Userland heraus analysiert werden und erst später zur Kernel-Implementierung gewechselt wird. Sandbox erreicht diese Funktion häufig über `__sandbox_ms`, und AMFI verwendet denselben Mechanismus für dyld-Policy-Entscheidungen.<sup>[[2]](#references)[[5]](#references)</sup>

## Praktische Hinweise für offensive Forschung

Aktuelle macOS-Bugs "brechen MACF" nur selten direkt. Stattdessen missbrauchen sie normalerweise eine **Desynchronisation zwischen einer MACF- / Sandbox- / TCC-Entscheidung und der privilegierten Aktion, die später ausgeführt wird**.

### Broker-Pfadprüfungen vs. tatsächliche privilegierte Aktion

Ein wiederkehrendes Muster ist ein privilegierter Daemon, der einen **Userland pre-check** (zum Beispiel `sandbox_check_by_audit_token()`) für eine Version eines Pfads ausführt und später den tatsächlichen privilegierten Sink mit einem **anderen oder nicht kanonischen, vom Angreifer kontrollierten Pfad** ausführt. Die aktuelle Forschung zu `diskarbitrationd` / `storagekitd` ist ein gutes Beispiel: **directory traversal** plus **symlink swaps** ermöglichen es dem Angreifer, die Sandbox-Validierung des Daemons zu passieren und anschließend sensible Orte wie `~/Library/Application Support/com.apple.TCC` zu überschreiben, wodurch der Bug je nach gewähltem Mountpoint zu einem **sandbox escape**, einer **local privilege escalation** oder einem **TCC bypass** wird.<sup>[[6]](#references)</sup>

Beim Audit von Root-Brokern, die aus der Sandbox erreichbar sind, sollte zuerst nach Folgendem gesucht werden:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, Hilfsfunktionen zur Pfadkanonisierung
- privilegierte Sinks wie `mount`, `rename`, `copyfile`, XPC-Methoden von Helper-Tools oder alles, was später als Root auf vom Angreifer kontrollierte Pfade zugreift

### Vertrauenswürdige Stellvertreter mit privaten Entitlements

Ein weiteres praktisches Muster besteht darin, MACF-Hooks nicht direkt anzugreifen, sondern stattdessen einen **vertrauenswürdigen Prozess** zu missbrauchen, der bereits die erforderlichen Rechte besitzt, um die Grenze zu überschreiten. Die aktuelle Safari-/TCC-Forschung ist ein gutes Beispiel: Das interessante Primitive bestand nicht darin, "TCC im Kernel zu deaktivieren", sondern die lokale Policy-/Konfiguration so zu verändern, dass ein von Apple signierter Prozess mit **`com.apple.private.tcc.allow`** die sensible Aktion stellvertretend für den Angreifer ausführt.<sup>[[8]](#references)</sup> In der Praxis sind Apple-Daemons/-Apps mit folgenden Eigenschaften besonders wertvolle Audit-Ziele:

- **private Entitlements** oder ein Zugriff ähnlich wie FDA
- eine beschreibbare Konfiguration / Datenbank / ein beschreibbarer Mountpoint / eine beschreibbare Policy-Datei
- eine spätere sensible Operation, die durch **Sandbox**, **AMFI**, **TCC** oder eine andere MACF-Policy vermittelt wird

Für ein tiefergehendes produktspezifisches Reversing sollten die speziellen Seiten zu [macOS Sandbox](macos-sandbox/README.md) und [macOS TCC](macos-tcc/README.md) konsultiert werden.

## References

- [1] [XNU — `security/mac_policy.h` (der vollständige Vektor der MACF-Policy-Operationen)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (`MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`-Makros)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (von `priv_check`/`priv_grant` verwendete Privilege-Codes)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Aufdeckung von Apple-Schwachstellen: Audit von diskarbitrationd und storagekitd, Teil 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — XNU Cross Reference tool](https://newosxbook.com/xxr/index.php)
- [8] [Neue macOS-Schwachstelle "HM Surf" könnte zu unbefugtem Datenzugriff führen (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
{{#include ../../../banners/hacktricks-training.md}}
