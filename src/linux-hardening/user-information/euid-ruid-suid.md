# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### Vigezo vya Utambulisho wa Mtumiaji

- **`ruid`**: **Kitambulisho halisi cha mtumiaji** huwakilisha mtumiaji aliyeanzisha process.
- **`euid`**: Kinachojulikana kama **kitambulisho halisi cha mtumiaji kinachotumika**, huwakilisha utambulisho wa mtumiaji unaotumiwa na mfumo kubainisha privileges za process. Kwa kawaida, `euid` huwa sawa na `ruid`, isipokuwa katika hali kama execution ya SetUID binary, ambapo `euid` huchukua utambulisho wa mmiliki wa file, hivyo kutoa permissions maalum za uendeshaji.
- **`suid`**: **Kitambulisho cha mtumiaji kilichohifadhiwa** ni muhimu wakati process yenye privileges za juu (kwa kawaida inayoendesha kama root) inahitaji kuachilia privileges zake kwa muda ili kutekeleza kazi fulani, kisha baadaye kurejesha hali yake ya awali yenye privileges zilizoinuliwa.

#### Dokezo Muhimu

Process isiyoendesha kama root inaweza kubadilisha `euid` yake tu ili ilingane na `ruid`, `euid`, au `suid` ya sasa.

### Kuelewa Functions za set\*uid

- **`setuid`**: Kinyume na dhana za awali, `setuid` hubadilisha hasa `euid` badala ya `ruid`. Hasa, kwa processes zenye privileges, huweka `ruid`, `euid`, na `suid` kuwa user aliyeainishwa, mara nyingi root, na hivyo kuzifanya IDs hizi ziwe thabiti kwa sababu ya `suid` inayozifunika. Maelezo zaidi yanapatikana kwenye [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** na **`setresuid`**: Functions hizi huruhusu marekebisho ya kina ya `ruid`, `euid`, na `suid`. Hata hivyo, uwezo wake hutegemea kiwango cha privileges cha process. Kwa processes zisizo root, mabadiliko yanawekewa mipaka ya values za sasa za `ruid`, `euid`, na `suid`. Kinyume chake, processes za root au zilizo na capability ya `CAP_SETUID` zinaweza kuweka values zozote kwenye IDs hizi. Maelezo zaidi yanapatikana kwenye [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) na [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Functionalities hizi zilibuniwa si kama security mechanism, bali kuwezesha mtiririko wa uendeshaji uliokusudiwa, kama vile wakati program inachukua utambulisho wa user mwingine kwa kubadilisha effective user ID yake.

Inafaa kutambua kwamba, ingawa `setuid` inaweza kuwa chaguo la kawaida la kuongeza privileges hadi root (kwa kuwa inaweka IDs zote kuwa root), kutofautisha kati ya functions hizi ni muhimu kwa kuelewa na kudhibiti tabia za user ID katika hali mbalimbali.

### Mechanisms za Kuendesha Program katika Linux

#### **`execve` System Call**

- **Functionality**: `execve` huanzisha program, inayobainishwa na argument ya kwanza. Hupokea array arguments mbili, `argv` kwa arguments na `envp` kwa environment.
- **Behavior**: Huhifadhi memory space ya caller lakini hu-refresh stack, heap, na data segments. Code ya program hubadilishwa na program mpya.
- **User ID Preservation**:
- `ruid`, `euid`, na supplementary group IDs hubaki bila kubadilishwa.
- `euid` inaweza kubadilika kwa namna maalum ikiwa program mpya ina SetUID bit iliyowekwa.
- `suid` husasishwa kutoka kwa `euid` baada ya execution.
- **Documentation**: Maelezo zaidi yanapatikana kwenye [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **`system` Function**

- **Functionality**: Tofauti na `execve`, `system` huunda child process kwa kutumia `fork` na hu-execute command ndani ya child process hiyo kwa kutumia `execl`.
- **Command Execution**: Hu-execute command kupitia `sh` kwa kutumia `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Behavior**: Kwa kuwa `execl` ni aina ya `execve`, hufanya kazi kwa namna inayofanana lakini katika muktadha wa child process mpya.
- **Documentation**: Maelezo zaidi yanaweza kupatikana kwenye [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Behavior ya `bash` na `sh` ikiwa na SUID**

- **`bash`**:
- Ina option ya `-p` inayoathiri namna `euid` na `ruid` zinavyoshughulikiwa.
- Bila `-p`, `bash` huweka `euid` kuwa `ruid` ikiwa mwanzoni zilikuwa tofauti.
- Ikiwa na `-p`, `euid` ya awali huhifadhiwa.
- Maelezo zaidi yanaweza kupatikana kwenye [`bash` man page](https://linux.die.net/man/1/bash).
- **`sh`**:
- Haina mechanism inayofanana na `-p` ya `bash`.
- Behavior inayohusu user IDs haijaelezwa wazi, isipokuwa chini ya option ya `-i`, inayosisitiza kuhifadhi usawa wa `euid` na `ruid`.
- Maelezo ya ziada yanapatikana kwenye [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).

Mechanisms hizi, ambazo hutofautiana katika uendeshaji wake, hutoa options mbalimbali za ku-execute na kubadilisha kati ya programs, zikiwa na nuances maalum kuhusu namna user IDs zinavyodhibitiwa na kuhifadhiwa.

### Kujaribu Tabia za User ID Wakati wa Execution

Mifano imechukuliwa kutoka https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, iangalie kwa maelezo zaidi

#### Case 1: Kutumia `setuid` na `system`

**Objective**: Kuelewa athari ya `setuid` kwa kushirikiana na `system` na `bash` kama `sh`.

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
**Kompilishaji na Ruhusa:**
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
- `setuid` huzilinganisha zote kuwa 1000.
- `system` hutekeleza `/bin/bash -c id` kutokana na symlink kutoka sh kwenda bash.
- `bash`, bila `-p`, hurekebisha `euid` ilingane na `ruid`, na hivyo zote kuwa 99 (nobody).

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
- `system` huanzisha bash, ambayo hudumisha user IDs kwa sababu ni sawa, hivyo kufanya kazi kama frank.

#### Case 3: Kutumia setuid na execve

Objective: Kuchunguza mwingiliano kati ya setuid na execve.
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

- `ruid` inabaki 99, lakini `euid` imewekwa kuwa 1000, kulingana na athari ya `setuid`.

**Mfano wa Msimbo wa C 2 (Kuita Bash):**
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

- Ingawa `euid` imewekwa kuwa 1000 na `setuid`, `bash` inaweka tena euid kuwa `ruid` (99) kwa sababu ya kutokuwepo kwa `-p`.

**Mfano wa 3 wa C Code (Kwa kutumia bash -p):**
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
uid=99(nobody) gid=99(nobody) euid=100
```
## Marejeo

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}
