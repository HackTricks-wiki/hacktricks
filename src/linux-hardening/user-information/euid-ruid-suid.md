# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Vigezo vya Utambulisho wa Mtumiaji

- **`ruid`**: **Kitambulisho halisi cha mtumiaji** huonyesha mtumiaji aliyeanzisha mchakato.<sup>[[1]](#references)</sup>
- **`euid`**: Kinachojulikana kama **kitambulisho cha mtumiaji kinachotumika**, huwakilisha utambulisho wa mtumiaji unaotumiwa na mfumo kubaini privileges za mchakato. Kwa kawaida, `euid` huwa sawa na `ruid`, isipokuwa katika hali kama utekelezaji wa binary ya SetUID (wakati mpito wa set-user-ID unazingatiwa), ambapo `euid` huchukua utambulisho wa mmiliki wa file, hivyo kutoa ruhusa mahususi za uendeshaji.<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**: **Kitambulisho hiki cha mtumiaji kilichohifadhiwa** ni muhimu wakati mchakato wenye privileges za juu (kwa kawaida unaoendeshwa kama root) unahitaji kuachilia privileges zake kwa muda ili kutekeleza kazi fulani, kisha baadaye kurejesha hali yake ya awali yenye privileges za juu.<sup>[[1]](#references)</sup>

#### Dokezo Muhimu

Mchakato usio na privileges unaweza kubadilisha `euid` yake tu ili ilingane na `ruid`, `euid`, au `suid` ya sasa.<sup>[[3]](#references)</sup>

### Kuelewa set\*uid Functions

- **`setuid`**: Kinyume na dhana za awali, `setuid` huweka `euid` ya mchakato unaoiita. Kwa mchakato wenye privileges, pia huweka `ruid` na `suid` kuwa mtumiaji aliyeainishwa; baada ya IDs zote kuwekwa kuwa root, mchakato hauwezi kurejesha utambulisho wa awali kwa kutumia `setuid`. Maelezo ya kina yanapatikana kwenye [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** na **`setresuid`**: `setreuid` hubadilisha `ruid` na `euid`, huku `setresuid` ikibadilisha IDs zote tatu. Kwa mchakato usio na privileges, `setresuid` huwekea kila lengo kikomo cha `ruid`, `euid`, au `suid` ya sasa; `setreuid` huwekea `euid` kikomo cha thamani hizo na `ruid` kikomo cha `ruid` au `euid` ya sasa. Mchakato wenye `CAP_SETUID` unaweza kuweka thamani zozote kwenye IDs zinazoungwa mkono na kila call. Maelezo zaidi yanaweza kupatikana kwenye [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) na [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Utendaji huu haukuundwa kama mechanism ya usalama, bali kuwezesha mtiririko wa uendeshaji uliokusudiwa, kama wakati program inachukua utambulisho wa mtumiaji mwingine kwa kubadilisha effective user ID yake.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Muhimu kutambua kwamba call yenye privileges ya `setuid` inaweza kuweka IDs zote tatu, huku `setreuid` na `setresuid` zikitoa controls tofauti; kutofautisha functions hizi ni muhimu kwa kuelewa mipito ya user-ID.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Mechanisms za Utekelezaji wa Programu katika Linux

#### **`execve` System Call**

- **Utendaji**: `execve` huanzisha program, iliyoainishwa na argument ya kwanza. Hupokea arguments mbili za array, `argv` kwa arguments na `envp` kwa environment.<sup>[[5]](#references)</sup>
- **Tabia**: Huhifadhi memory space ya caller lakini hu-refresh stack, heap, na data segments. Code ya program hubadilishwa na program mpya.<sup>[[5]](#references)</sup>
- **Uhifadhi wa User ID**:
- `ruid` na supplementary group IDs hubaki bila kubadilishwa.<sup>[[5]](#references)</sup>
- `euid` kwa kawaida haibadilishwi, lakini inaweza kubadilika ikiwa program mpya ina SetUID bit iliyowekwa.<sup>[[5]](#references)</sup>
- `suid` husasishwa kutoka kwa `euid` baada ya utekelezaji.<sup>[[5]](#references)</sup>
- **Documentation**: Maelezo ya kina yanaweza kupatikana kwenye [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **`system` Function**

- **Utendaji**: Tofauti na `execve`, `system` hufanya kazi kana kwamba inaunda child process kwa kutumia `fork` na kutekeleza command ndani ya child process hiyo kwa kutumia `execl`.<sup>[[6]](#references)</sup>
- **Utekelezaji wa Command**: Hutekeleza command kupitia `sh` kwa kutumia `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.<sup>[[6]](#references)</sup>
- **Tabia**: Kwa kuwa `execl` ni call ya familia ya `exec`, hufanya kazi kwa njia inayofanana na `execve`, lakini katika context ya child process mpya.<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **Documentation**: Maelezo zaidi yanaweza kupatikana kwenye [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).<sup>[[6]](#references)</sup>

#### **Tabia ya `bash` na `sh` zikiwa na SUID**

- **`bash`**:
- Ina option ya `-p` inayoathiri jinsi `euid` na `ruid` zinavyoshughulikiwa.<sup>[[7]](#references)</sup>
- Bila `-p`, `bash` huweka `euid` kuwa `ruid` ikiwa mwanzoni zinatofautiana.<sup>[[7]](#references)</sup>
- Ikiwa na `-p`, `euid` ya awali huhifadhiwa.<sup>[[7]](#references)</sup>
- Maelezo zaidi yanaweza kupatikana kwenye [`bash` man page](https://linux.die.net/man/1/bash).<sup>[[7]](#references)</sup>
- **`sh`**:
- POSIX `sh` haifafanui option ya kuhifadhi privileges ya mtindo wa Bash ya `-p`.<sup>[[8]](#references)</sup>
- Orodha yake ya POSIX options inajumuisha `-i`, inayochagua interactive mode na inaweza kukataliwa wakati IDs halisi na zinazotumika zinatofautiana.<sup>[[8]](#references)</sup>
- Maelezo ya ziada yanapatikana kwenye [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).<sup>[[8]](#references)</sup>

Mechanisms hizi, ambazo hutofautiana katika uendeshaji wake, hutoa chaguo mbalimbali za kutekeleza na kubadilisha kati ya programs, zikiwa na nuances mahususi kuhusu jinsi user IDs zinavyosimamiwa na kuhifadhiwa.

### Kujaribu Tabia za User ID wakati wa Utekelezaji

Mifano imechukuliwa kutoka https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, iangalie kwa maelezo zaidi.<sup>[[1]](#references)</sup>

#### Case 1: Kutumia `setuid` pamoja na `system`

**Lengo**: Kuelewa athari ya `setuid` inapounganishwa na `system` na `bash` kama `sh`.

**C Code**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Uundaji na Ruhusa:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Uchambuzi:**

- `ruid` na `euid` huanza zikiwa 99 (nobody) na 1000 (frank), mtawalia.
- Katika muktadha huu usio na privileges, `setuid(1000)` huacha `ruid` ikiwa 99 na `euid` ikiwa 1000.<sup>[[1]](#references)</sup>
- `system` hutekeleza `/bin/bash -c id` kutokana na symlink kutoka sh hadi bash.
- `bash`, bila `-p`, hurekebisha `euid` ilingane na `ruid`, hivyo zote zinakuwa 99 (nobody).<sup>[[1]](#references)</sup>

#### Kesi ya 2: Kutumia setreuid na system

**Msimbo wa C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Ukompilishaji na Ruhusa:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Utekelezaji na Matokeo:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Uchambuzi:**

- `setreuid` huweka ruid na euid zote kuwa 1000.
- `system` huendesha bash, ambayo hudumisha user IDs kwa sababu ziko sawa, hivyo kufanya kazi kama frank.<sup>[[1]](#references)</sup>

#### Kisa cha 3: Kutumia setuid na execve

Lengo: Kuchunguza mwingiliano kati ya setuid na execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Utekelezaji na Matokeo:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Uchambuzi:**

- `ruid` inabaki kuwa 99, lakini euid inawekwa kuwa 1000, kulingana na athari ya setuid.<sup>[[1]](#references)</sup>

**Mfano wa Code ya C 2 (Calling Bash):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Utekelezaji na Matokeo:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Uchambuzi:**

- Ingawa `euid` imewekwa kuwa 1000 na `setuid`, `bash` inaweka upya euid kuwa `ruid` (99) kwa sababu ya kutokuwepo kwa `-p`.<sup>[[1]](#references)</sup>

**Mfano wa Msimbo wa C 3 (Kwa kutumia bash -p):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Utekelezaji na Matokeo:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```
## References

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - ukurasa wa man wa setuid](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - ukurasa wa man wa setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - ukurasa wa man wa setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - ukurasa wa man wa execve](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - ukurasa wa man wa system](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - ukurasa wa man wa bash](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - ukurasa wa man wa POSIX sh](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}
