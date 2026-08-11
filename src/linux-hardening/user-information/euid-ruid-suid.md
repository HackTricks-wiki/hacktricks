# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Змінні ідентифікації користувача

- **`ruid`**: **реальний ідентифікатор користувача** позначає користувача, який ініціював процес.<sup>[[1]](#references)</sup>
- **`euid`**: Відомий як **ефективний ідентифікатор користувача**, він представляє ідентичність користувача, яку система використовує для визначення привілеїв процесу. Зазвичай `euid` збігається з `ruid`, за винятком випадків на кшталт виконання SetUID binary (коли перехід set-user-ID дозволено), де `euid` набуває ідентичності власника файлу, надаючи відповідні операційні дозволи.<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**: Цей **збережений ідентифікатор користувача** має ключове значення, коли процес із високими привілеями (зазвичай запущений від імені root) має тимчасово відмовитися від своїх привілеїв для виконання певних завдань, а потім відновити свій початковий підвищений статус.<sup>[[1]](#references)</sup>

#### Важливе зауваження

Непривілейований процес може змінити свій `euid` лише так, щоб він відповідав поточному `ruid`, `euid` або `suid`.<sup>[[3]](#references)</sup>

### Розуміння функцій set\*uid

- **`setuid`**: Всупереч початковим припущенням, `setuid` встановлює `euid` процесу, що викликає функцію. Для привілейованого процесу вона також встановлює `ruid` і `suid` у вказаного користувача; після встановлення всіх ідентифікаторів у root процес не може відновити попередню ідентичність за допомогою `setuid`. Докладні відомості наведено на [сторінці man setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** і **`setresuid`**: `setreuid` змінює `ruid` і `euid`, тоді як `setresuid` змінює всі три ідентифікатори. Для непривілейованого процесу `setresuid` обмежує кожне цільове значення поточним `ruid`, `euid` або `suid`; `setreuid` обмежує `euid` цими значеннями, а `ruid` — поточним `ruid` або `euid`. Процес із `CAP_SETUID` може призначати довільні значення ідентифікаторам, які підтримує кожен виклик. Додаткову інформацію можна знайти на [сторінці man setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) і [сторінці man setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Ці функціональні можливості призначені не як механізм безпеки, а для забезпечення передбаченого операційного процесу, наприклад коли програма приймає ідентичність іншого користувача, змінюючи свій ефективний ідентифікатор користувача.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Варто зазначити, що привілейований виклик `setuid` може призначити всі три ідентифікатори, тоді як `setreuid` і `setresuid` надають різні елементи керування; розрізнення цих функцій має вирішальне значення для розуміння переходів між ідентифікаторами користувача.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Механізми виконання програм у Linux

#### **Системний виклик `execve`**

- **Функціональність**: `execve` запускає програму, визначену першим аргументом. Він приймає два масиви аргументів: `argv` для аргументів і `envp` для середовища.<sup>[[5]](#references)</sup>
- **Поведінка**: Він зберігає адресний простір виклику, але оновлює стек, купу та сегменти даних. Код програми замінюється новою програмою.<sup>[[5]](#references)</sup>
- **Збереження ідентифікаторів користувача**:
- `ruid` і додаткові ідентифікатори груп залишаються незмінними.<sup>[[5]](#references)</sup>
- `euid` зазвичай не змінюється, але може змінитися, якщо нова програма має встановлений біт SetUID.<sup>[[5]](#references)</sup>
- `suid` після виконання оновлюється зі значення `euid`.<sup>[[5]](#references)</sup>
- **Документація**: Докладну інформацію наведено на [сторінці man [`execve`](https://man7.org/linux/man-pages/man2/execve.2.html)].<sup>[[5]](#references)</sup>

#### **Функція `system`**

- **Функціональність**: На відміну від `execve`, `system` поводиться так, ніби створює дочірній процес за допомогою `fork` і виконує команду в цьому дочірньому процесі за допомогою `execl`.<sup>[[6]](#references)</sup>
- **Виконання команди**: Виконує команду через `sh` за допомогою `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.<sup>[[6]](#references)</sup>
- **Поведінка**: Оскільки `execl` є викликом із сімейства `exec`, він працює подібно до `execve`, але в контексті нового дочірнього процесу.<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **Документація**: Додаткову інформацію можна отримати на [сторінці man [`system`](https://man7.org/linux/man-pages/man3/system.3.html)].<sup>[[6]](#references)</sup>

#### **Поведінка `bash` і `sh` із SUID**

- **`bash`**:
- Має параметр `-p`, який впливає на обробку `euid` і `ruid`.<sup>[[7]](#references)</sup>
- Без `-p` `bash` встановлює `euid` рівним `ruid`, якщо спочатку вони відрізнялися.<sup>[[7]](#references)</sup>
- Із `-p` початковий `euid` зберігається.<sup>[[7]](#references)</sup>
- Докладніші відомості наведено на [сторінці man [`bash`](https://linux.die.net/man/1/bash)].<sup>[[7]](#references)</sup>
- **`sh`**:
- POSIX `sh` не визначає опцію збереження привілеїв у стилі Bash `-p`.<sup>[[8]](#references)</sup>
- Його список опцій POSIX містить `-i`, яка вмикає інтерактивний режим і може бути відхилена, коли реальний та ефективний ідентифікатори відрізняються.<sup>[[8]](#references)</sup>
- Додаткову інформацію наведено на [сторінці man [`sh`](https://man7.org/linux/man-pages/man1/sh.1p.html)].<sup>[[8]](#references)</sup>

Ці механізми, різні за принципом роботи, надають широкий набір можливостей для виконання програм і переходу між ними з певними нюансами щодо керування ідентифікаторами користувача та їх збереження.

### Тестування поведінки ідентифікаторів користувача під час виконання

Приклади взято з https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, додаткову інформацію див. у цьому матеріалі.<sup>[[1]](#references)</sup>

#### Випадок 1: Використання `setuid` із `system`

**Мета**: Зрозуміти вплив `setuid` у поєднанні з `system` і `bash` як `sh`.

**Код C**:
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
**Компіляція та права доступу:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Аналіз:**

- `ruid` і `euid` починаються зі значень 99 (nobody) і 1000 (frank) відповідно.
- У цьому непривілейованому контексті `setuid(1000)` залишає `ruid` рівним 99, а `euid` — 1000.<sup>[[1]](#references)</sup>
- `system` виконує `/bin/bash -c id` через symlink від sh до bash.
- `bash` без `-p` змінює `euid`, щоб він відповідав `ruid`, унаслідок чого обидва стають рівними 99 (nobody).<sup>[[1]](#references)</sup>

#### Випадок 2: Використання setreuid із system

**Код C:**
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
**Компіляція та права доступу:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Виконання та результат:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Аналіз:**

- `setreuid` встановлює і ruid, і euid у значення 1000.
- `system` викликає bash, який зберігає ідентифікатори користувача завдяки їхній рівності, фактично працюючи як frank.<sup>[[1]](#references)</sup>

#### Випадок 3: Використання setuid з execve

Мета: дослідження взаємодії між setuid і execve.
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
**Виконання та результат:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Аналіз:**

- `ruid` залишається рівним 99, але `euid` встановлюється рівним 1000 відповідно до ефекту setuid.<sup>[[1]](#references)</sup>

**Приклад коду C 2 (Виклик Bash):**
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
**Виконання та результат:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Аналіз:**

- Although `euid` is set to 1000 by `setuid`, `bash` resets euid to `ruid` (99) due to the absence of `-p`.<sup>[[1]](#references)</sup>

**Приклад коду 3 (Використання bash -p):**
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
**Виконання та результат:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```
## References

- [1] [Пастка SetUID - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - сторінка man для setuid](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - сторінка man для setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - сторінка man для setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - сторінка man для execve](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - сторінка man для system](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - сторінка man для bash](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - сторінка man для POSIX sh](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}
