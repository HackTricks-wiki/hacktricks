# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

**MACF** steht für **Mandatory Access Control Framework** und ist ein in das Betriebssystem integriertes Sicherheitssystem, das zum Schutz deines Computers beiträgt. Es legt **strenge Regeln darüber fest, wer oder was auf bestimmte Teile des Systems zugreifen darf**, etwa auf Dateien, Anwendungen und Systemressourcen. Durch die automatische Durchsetzung dieser Regeln stellt MACF sicher, dass nur autorisierte Benutzer und Prozesse bestimmte Aktionen ausführen können, wodurch das Risiko unbefugter Zugriffe oder schädlicher Aktivitäten reduziert wird.

Beachte, dass MACF eigentlich keine Entscheidungen trifft, da es Aktionen lediglich **abfängt**. Die Entscheidungen überlässt es den **policy modules** (Kernel-Erweiterungen), die es aufruft, etwa `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` und `mcxalr.kext`.

- Eine Policy kann erzwingend sein (bei einer bestimmten Operation 0 oder einen Nicht-null-Wert zurückgeben)
- Eine Policy kann überwachen (0 zurückgeben, um keinen Einwand zu erheben, aber den Hook zu nutzen, um etwas auszuführen)
- Eine statische MACF-Policy wird beim Booten installiert und wird NIEMALS entfernt
- Eine dynamische MACF-Policy wird durch ein KEXT (`kextload`) installiert und könnte theoretisch per `kextunload` entladen werden
- Unter iOS sind nur statische Policies erlaubt, unter macOS dagegen statische und dynamische.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Ablauf

1. Der Prozess führt einen syscall/Mach-Trap aus
2. Die entsprechende Funktion wird innerhalb des Kernels aufgerufen
3. Die Funktion ruft MACF auf
4. MACF überprüft die policy modules, die in ihrer Policy einen Hook für diese Funktion angefordert haben
5. MACF ruft die entsprechenden Policies auf
6. Die Policies geben an, ob sie die Aktion erlauben oder verweigern

> [!CAUTION]
> Apple ist das einzige Unternehmen, das das MAC Framework KPI verwenden kann.

Üblicherweise rufen die Funktionen, die Berechtigungen mit MACF überprüfen, das Makro `MAC_CHECK` auf. Beispielsweise wird beim syscall zum Erstellen eines Sockets die Funktion `mac_socket_check_create` aufgerufen, die wiederum `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` aufruft. Außerdem ist das Makro `MAC_CHECK` in security/mac_internal.h wie folgt definiert:<sup>[3]</sup>
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
Die Erweiterung der Helper-Makros zeigt den konkreten Kontrollfluss:
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
Mit anderen Worten: `MAC_CHECK(socket_check_create, ...)` durchläuft zuerst die statischen Policies, sperrt und iteriert bedingt über dynamische Policies, gibt die DTrace-Probes rund um jeden Hook aus und fasst den Rückgabecode jedes Hooks über `mac_error_select()` zu einem einzigen `error`-Ergebnis zusammen.


### Labels

MACF verwendet **Labels**, die anschließend von den Policies genutzt werden, um zu prüfen, ob sie einen Zugriff gewähren sollen oder nicht. Der Code für die Deklaration der Label-Struktur ist [hier zu finden](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h). Diese Struktur wird anschließend innerhalb von **`struct ucred`** [hier](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) im Teil **`cr_label`** verwendet. Das Label enthält Flags und eine Reihe von **Slots**, die von **MACF policies zur Speicherung von Pointern** verwendet werden können. Beispielsweise verweist Sandbox auf das Container-Profil.

## MACF Policies

Eine MACF Policy definiert **Regeln und Bedingungen, die bei bestimmten Kernel-Operationen angewendet werden**.

Eine Kernel-Erweiterung kann eine `mac_policy_conf`-Struktur konfigurieren und diese anschließend durch Aufruf von `mac_policy_register` registrieren. Von [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[1]</sup>
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
Die Kernel Extensions, die diese Policies konfigurieren, lassen sich leicht identifizieren, indem die Aufrufe von `mac_policy_register` überprüft werden. Darüber hinaus ist es durch die Überprüfung des Disassemblats der Extension ebenfalls möglich, die verwendete `mac_policy_conf`-Struktur zu finden.

Beachte, dass MACF-Policies auch **dynamisch** registriert und deregistriert werden können.

Eines der wichtigsten Felder von `mac_policy_conf` ist **`mpc_ops`**. Dieses Feld legt fest, für welche Operationen sich die Policy interessiert. Beachte, dass es Hunderte davon gibt. Daher ist es möglich, zunächst alle auf null zu setzen und anschließend nur diejenigen auszuwählen, für die sich die Policy interessiert. Von [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[1]</sup>
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
Fast alle Hooks werden von MACF zurückgerufen, wenn eine dieser Operationen abgefangen wird. Die **`mpo_policy_*`**-Hooks bilden jedoch eine Ausnahme, da `mpo_hook_policy_init()` ein Callback ist, der bei der Registrierung aufgerufen wird (also nach `mac_policy_register()`), während `mpo_hook_policy_initbsd()` während der späten Registrierung aufgerufen wird, sobald das BSD-Subsystem ordnungsgemäß initialisiert wurde.

Außerdem kann der **`mpo_policy_syscall`**-Hook von jedem Kext registriert werden, um eine private **ioctl**-ähnliche Aufrufschnittstelle bereitzustellen. Anschließend kann ein User Client `mac_syscall` (#381) aufrufen und dabei als Parameter den **policy name**, einen Integer-**code** sowie optionale **arguments** angeben.\
Beispielsweise verwendet die **`Sandbox.kext`** dies häufig.

Durch die Überprüfung von **`__DATA.__const*`** des Kexts lässt sich die beim Registrieren der Policy verwendete Struktur `mac_policy_ops` identifizieren. Sie kann gefunden werden, weil sich ihr Pointer an einem Offset innerhalb von `mpo_policy_conf` befindet und außerdem anhand der Anzahl der NULL-Pointer, die in diesem Bereich vorkommen.

Außerdem ist es möglich, die Liste der Kexts abzurufen, die eine Policy konfiguriert haben, indem die Struktur **`_mac_policy_list`** aus dem Speicher ausgelesen wird. Diese wird mit jeder registrierten Policy aktualisiert.

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
Und anschließend alle Prüfungen der Check-Policy mit:
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

- `mac_policy_initmach()` untersucht vorab geladene Kernel-Erweiterungen (kexts) oder solche in einer „policy injection“-Liste und prüft deren Info.plist auf den Schlüssel `AppleSecurityExtension`.
- Kexts, die `<key>AppleSecurityExtension</key>` (oder `true`) in ihrer Info.plist deklarieren, gelten als „security extensions“ – also als Erweiterungen, die eine MAC policy implementieren oder sich in die MACF-Infrastruktur einklinken.
- Beispiele für Apple-kexts mit diesem Schlüssel sind **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** und weitere (wie bereits aufgelistet).
- Der Kernel stellt sicher, dass diese kexts früh geladen werden, und ruft anschließend während des Bootvorgangs deren Registrierungsroutinen (über `mac_policy_register`) auf, wodurch sie in die `mac_policy_list` eingefügt werden.

- Jedes Policy-Modul (kext) stellt eine `mac_policy_conf`-Struktur mit Hooks (`mpc_ops`) für verschiedene MAC-Operationen bereit (vnode-Prüfungen, exec-Prüfungen, Label-Aktualisierungen usw.).
- Die Load-Time-Flags können `MPC_LOADTIME_FLAG_NOTLATE` enthalten, was bedeutet: „muss früh geladen werden“ (spätere Registrierungsversuche werden abgelehnt).
- Nach der Registrierung erhält jedes Modul ein Handle und belegt einen Slot in der `mac_policy_list`.
- Wenn später ein MAC-Hook aufgerufen wird (beispielsweise für vnode-Zugriff, exec usw.), iteriert MACF über alle registrierten Policies, um gemeinsame Entscheidungen zu treffen.

- Insbesondere ist **AMFI** (Apple Mobile File Integrity) eine solche security extension. Seine Info.plist enthält `AppleSecurityExtension`, wodurch es als security policy gekennzeichnet wird.
- Im Rahmen des Kernel-Bootvorgangs stellt die Kernel-Ladelogik sicher, dass die „security policy“ (AMFI usw.) bereits aktiv ist, bevor viele Subsysteme von ihr abhängen. Beispielsweise „bereitet der Kernel sich auf anstehende Aufgaben vor, indem er … security policy einschließlich AppleMobileFileIntegrity (AMFI), Sandbox und Quarantine policy lädt.“
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
## KPI-Abhängigkeit und com.apple.kpi.dsep in MAC policy kexts

Wenn du ein kext schreibst, das das MAC framework verwendet (z. B. durch Aufruf von `mac_policy_register()` usw.), musst du Abhängigkeiten von KPIs (Kernel Programming Interfaces) deklarieren, damit der kext-Linker (kxld) diese Symbole auflösen kann. UM eine `kext`-Abhängigkeit von MACF zu deklarieren, musst du dies in der `Info.plist` mit `com.apple.kpi.dsep` angeben (`find . Info.plist | grep AppleSecurityExtension`). Anschließend verweist das kext auf Symbole wie `mac_policy_register`, `mac_policy_unregister` und MAC hook function pointers. Um diese aufzulösen, musst du `com.apple.kpi.dsep` als Abhängigkeit aufführen.

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
## MACF auf modernen macOS-Versionen

Auf modernen macOS-Versionen lassen sich die Sicherheitsrichtlinien von Apple gewöhnlich nicht am besten als lose, eigenständige `.kext`-Bundles betrachten. Seit **macOS 11** werden Kernel-Erweiterungen in **Kernel Collections** eingebunden; auf **Apple Silicon** gibt es keine separate **SystemKC**, und Kexts von Drittanbietern können erst geladen werden, nachdem sie in die **Auxiliary Kernel Collection (AuxKC)** integriert wurden und ein Neustart erfolgt ist. Für die MACF-Forschung bedeutet dies, dass integrierte Richtlinien wie **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** oder **Quarantine** gewöhnlich einfacher mit `kmutil` als mit veralteten Tools wie `kextstat` aufgelistet werden können.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Auf Apple Silicon: Wenn sich ein Security-kext nicht in der BootKC befindet, prüfe als Nächstes die AuxKC. Das ist normalerweise nützlicher, als nach einem eigenständigen Bundle unter `/System/Library/Extensions` zu suchen.

## MACF Callouts

Es ist üblich, Verweise auf MACF in Code wie in bedingten Blöcken mit **`#if CONFIG_MAC`** zu finden. Außerdem können innerhalb dieser Blöcke Aufrufe von `mac_proc_check*` gefunden werden, die MACF aufrufen, um **Berechtigungen zu prüfen**, bestimmte Aktionen auszuführen. Das Format der MACF-Callouts lautet außerdem: **`mac_<object>_<opType>_opName`**.

Das object ist eines der folgenden: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
Der `opType` ist normalerweise check und wird verwendet, um die Aktion zu erlauben oder zu verweigern. Es ist jedoch auch möglich, `notify` zu finden, wodurch das kext auf die jeweilige Aktion reagieren kann.

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

Anschließend kann der Code von `mac_file_check_mmap` unter [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) gefunden werden.
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
die das `MAC_CHECK`-Makro aufruft, dessen Code in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[3]</sup> zu finden ist.
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
Dabei werden alle registrierten mac-Richtlinien durchlaufen, ihre Funktionen aufgerufen und die Ausgabe in der Variable `error` gespeichert. Diese kann nur durch `mac_error_select` mit Erfolgs-Codes überschrieben werden. Wenn also eine Prüfung fehlschlägt, schlägt die gesamte Prüfung fehl und die Aktion wird nicht erlaubt.

> [!TIP]
> Beachten Sie jedoch, dass nicht alle MACF-Callouts ausschließlich zum Verweigern von Aktionen verwendet werden. Beispielsweise ruft `mac_priv_grant` das Makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) auf, das das angeforderte Privileg gewährt, wenn eine Richtlinie mit 0 antwortet:
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

Diese Callouts dienen dazu, die in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) definierten **Privilegien** zu prüfen und bereitzustellen.\
Bestimmter Kernel-Code ruft `priv_check_cred()` aus [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) mit den KAuth-Anmeldedaten des Prozesses und einem der Privileg-Codes auf. Dieser ruft `mac_priv_check` auf, um zu prüfen, ob eine Richtlinie die Vergabe des Privilegs **verweigert**. Anschließend wird `mac_priv_grant` aufgerufen, um zu prüfen, ob eine Richtlinie das `privilege` gewährt.<sup>[4]</sup>

### proc_check_syscall_unix

Dieser Hook ermöglicht das Abfangen aller Systemaufrufe. In `bsd/dev/[i386|arm]/systemcalls.c` ist die deklarierte Funktion [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) zu sehen, die folgenden Code enthält:
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
Dabei wird in der **bitmask** des aufrufenden Prozesses geprüft, ob der aktuelle syscall `mac_proc_check_syscall_unix` aufrufen soll. Dies liegt daran, dass syscalls so häufig aufgerufen werden, dass es sinnvoll ist, nicht jedes Mal `mac_proc_check_syscall_unix` aufzurufen.

Beachte, dass die Funktion `proc_set_syscall_filter_mask()`, die die bitmask-syscalls in einem Prozess setzt, von Sandbox aufgerufen wird, um Masken für sandboxed processes zu setzen.

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
Für Offensive Reversing ist **`__mac_syscall`** weiterhin einer der besten Userland-Chokepoints. Es überträgt einen **Policy-Namen** (zum Beispiel `"Sandbox"` oder `"AMFI"`), einen **Policy-spezifischen Selector/Code** und einen Pointer auf den **opaquen Argument-Blob**, der von `mpo_policy_syscall` verarbeitet wird. Das ist sehr nützlich, wenn undokumentierte Operationen zunächst aus dem Userland heraus analysiert werden und erst später in die Kernel-Implementierung gewechselt wird. Sandbox erreicht es häufig über `__sandbox_ms`, und AMFI verwendet denselben Mechanismus für dyld-Policy-Entscheidungen.<sup>[2][5]</sup>

## Praktische Hinweise für offensive Forschung

Aktuelle macOS-Bugs **brechen MACF** nur selten direkt. Stattdessen wird meist eine **Desynchronisation zwischen einer MACF- / Sandbox- / TCC-Entscheidung und der privilegierten Aktion, die später erfolgt**, ausgenutzt.

### Broker-Pfadprüfungen vs. tatsächliche privilegierte Aktion

Ein wiederkehrendes Muster besteht darin, dass ein privilegierter Daemon eine **Userland-Vorprüfung** (zum Beispiel `sandbox_check_by_audit_token()`) für eine Version eines Pfads durchführt und später den tatsächlichen privilegierten Sink mit einem **anderen oder nicht kanonischen, vom Angreifer kontrollierten Pfad** ausführt. Die aktuelle Forschung zu `diskarbitrationd` / `storagekitd` ist ein gutes Beispiel: **Directory Traversal** plus **Symlink Swaps** ermöglichen es dem Angreifer, die Sandbox-Validierung des Daemons zu passieren und anschließend sensible Verzeichnisse wie `~/Library/Application Support/com.apple.TCC` zu mounten. Dadurch wird der Bug je nach gewähltem Mountpoint zu einem **Sandbox Escape**, einer **Local Privilege Escalation** oder einem **TCC Bypass**.<sup>[6]</sup>

Beim Audit von Root-Brokern, die aus der Sandbox erreichbar sind, sollte zuerst nach Folgendem gesucht werden:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, Hilfsfunktionen zur Pfadkanonisierung
- privilegierte Sinks wie `mount`, `rename`, `copyfile`, XPC-Methoden von Helper-Tools oder alles, was später als Root auf vom Angreifer kontrollierte Pfade zugreift

### Vertrauenswürdige Deputies mit privaten Entitlements

Ein weiteres praktisches Muster besteht darin, MACF-Hooks nicht direkt anzugreifen, sondern stattdessen einen **vertrauenswürdigen Prozess** auszunutzen, der bereits die erforderlichen Rechte besitzt, um die Grenze zu überschreiten. Die aktuelle Safari-/TCC-Forschung ist ein gutes Beispiel: Das interessante Primitive bestand nicht darin, „TCC im Kernel zu deaktivieren“, sondern darin, die lokale Policy-/Konfiguration so zu verändern, dass ein von Apple signierter Prozess mit **`com.apple.private.tcc.allow`** die sensible Aktion stellvertretend für den Angreifer ausführt. In der Praxis sind Apple-Daemons/-Apps mit folgenden Eigenschaften besonders wertvolle Audit-Ziele:

- **private Entitlements** oder FDA-ähnliche Reichweite
- eine beschreibbare Konfiguration / Datenbank / ein Mountpoint / eine Policy-Datei
- eine spätere sensible Operation, die durch **Sandbox**, **AMFI**, **TCC** oder eine andere MACF-Policy vermittelt wird

Für tiefergehendes produktspezifisches Reversing siehe die dedizierten Seiten zu [macOS Sandbox](macos-sandbox/README.md) und [macOS TCC](macos-tcc/README.md).

## Referenzen

- [1] [XNU — `security/mac_policy.h` (der vollständige Vektor der MACF-Policy-Operationen)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (`MAC_CHECK`- / `MAC_GRANT`- / `MAC_POLICY_ITERATE`-Makros)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (von `priv_check`/`priv_grant` verwendete Privileg-Codes)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Aufdeckung von Apple-Schwachstellen: diskarbitrationd- und storagekitd-Audit, Teil 2](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
