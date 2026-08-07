# Простір імен cgroup

{{#include ../../../../../banners/hacktricks-training.md}}

## Огляд

Простір імен cgroup не замінює cgroups і сам по собі не застосовує обмеження ресурсів. Натомість він змінює **те, як ієрархія cgroup виглядає** для процесу. Іншими словами, він віртуалізує видиму інформацію про шляхи cgroup, щоб workload бачив область, обмежену контейнером, а не всю ієрархію хоста.

Це переважно функція видимості та зменшення обсягу інформації. Вона допомагає зробити середовище самодостатнім на вигляд і розкриває менше відомостей про структуру cgroup хоста. Це може здаватися незначним, але все одно має значення, оскільки зайва видимість структури хоста може допомогти під час розвідки та спростити exploit chains, що залежать від середовища.

## Робота

Без приватного простору імен cgroup процес може бачити шляхи cgroup, відносні до хоста, які розкривають більшу частину ієрархії машини, ніж потрібно. У приватному просторі імен cgroup `/proc/self/cgroup` та пов'язані спостереження стають більш локалізованими відповідно до власного представлення контейнера. Це особливо корисно для сучасних runtime stacks, які прагнуть надати workload чистіше середовище, що розкриває менше інформації про хост.

Віртуалізація також впливає на `/proc/<pid>/mountinfo`, а не лише на `/proc/<pid>/cgroup`. Коли ви читаєте інформацію про інший процес з іншої перспективи простору імен cgroup, шляхи за межами кореня вашого простору імен відображаються з компонентами `../` на початку. Це зручна підказка, що ви переглядаєте рівень вище свого делегованого піддерева. Важливий нюанс для labs і post-exploitation полягає в тому, що щойно створеному простору імен cgroup часто потрібен **повторний mount cgroupfs зсередини цього простору імен**, перш ніж `mountinfo` коректно відобразить новий корінь. Інакше ви все ще можете бачити корінь монтування, наприклад `/..`, що означає: успадковане монтування все ще відкриває представлення з коренем у предку, хоча сам простір імен уже змінився.<sup>[[1]](#references)</sup>

## Лабораторія

Ви можете перевірити простір імен cgroup за допомогою:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Якщо ви хочете, щоб `mountinfo` чіткіше показував новий root cgroup namespace, виконайте remount файлової системи cgroup зсередини нового namespace і порівняйте ще раз:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
І порівняйте поведінку під час виконання з:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Зміна здебільшого стосується того, що може бачити процес, а не того, чи існує enforcement cgroup.

## Вплив на безпеку

cgroup namespace найкраще розглядати як **рівень hardening видимості**. Сам по собі він не зупинить breakout, якщо контейнер має доступні для запису cgroup mounts, широкі capabilities або небезпечне середовище cgroup v1. Однак якщо namespace cgroup хоста спільний, процес отримує більше інформації про організацію системи, і йому може бути простіше зіставити шляхи cgroup відносно хоста з іншими спостереженнями.

У **cgroup v2** namespace стає дещо важливішим, оскільки правила delegation є суворішими. Якщо ієрархію змонтовано з `nsdelegate`, kernel розглядає cgroup namespaces як межі delegation: файли керування предків мають залишатися поза досяжністю delegatee, а запис у корені namespace обмежується файлами, безпечними для delegation, такими як `cgroup.procs`, `cgroup.threads` і `cgroup.subtree_control`.<sup>[[2]](#references)</sup> Це все одно не перетворює namespace на примітив для escape, але змінює те, що compromised workload може перевіряти, і місця, де він може безпечно створювати sub-cgroups.

Тож хоча цей namespace зазвичай не є головною темою у writeups про container breakout, він усе одно сприяє ширшій меті — мінімізації витоку інформації про хост і обмеженню cgroup delegation.

## Зловживання

Безпосередня цінність для зловживання здебільшого полягає в reconnaissance. Якщо namespace cgroup хоста спільний, порівняйте видимі шляхи та шукайте деталі ієрархії, які можуть розкрити інформацію про хост:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Якщо також доступні для запису шляхи cgroup, поєднайте цю видимість із пошуком небезпечних застарілих інтерфейсів:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Сам namespace рідко одразу забезпечує escape, але часто допомагає легше скласти карту середовища перед перевіркою примітивів зловживання, пов’язаних із cgroup.

Швидка перевірка реального стану runtime також допомагає визначити пріоритетність attack path. Docker надає `--cgroupns=host|private`, тоді як Podman підтримує `host`, `private`, `container:<id>` і `ns:<path>`. У Podman, зокрема, типовим значенням зазвичай є **`host` для cgroup v1** і **`private` для cgroup v2`, тому просте визначення версії cgroup уже підказує, який namespace posture імовірніший, ще до перевірки повної OCI config.

### Сучасна розвідка v2: Чи є це делегованим subtree?

На сучасних хостах цікавою часто є не `release_agent`, а те, чи перебуває поточний процес усередині делегованого subtree **cgroup v2** із достатньою видимістю або правами на запис для створення вкладених груп:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Корисна інтерпретація:

- `cgroup2fs` означає, що ви перебуваєте в уніфікованій ієрархії v2, тому класичні ланцюжки `release_agent`, притаманні лише v1, не варто розглядати як першу гіпотезу.
- `cgroup.controllers` показує, які контролери доступні від батьківського cgroup, а отже, до яких контролерів поточне піддерево потенційно може розгалужуватися для дочірніх cgroup.
- `cgroup.subtree_control` показує, які контролери фактично ввімкнені для нащадків.
- `cgroup.events` надає `populated=0/1`, що зручно для відстеження того, чи стало піддерево порожнім, але це **не примітив виконання коду на хості**, як `release_agent` у v1.

Якщо у вас уже достатньо привілеїв, щоб безпосередньо перевірити namespace іншого процесу, порівняйте представлення за допомогою:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Повний приклад: спільний cgroup namespace + доступний для запису cgroup v1

Самого cgroup namespace зазвичай недостатньо для escape. Практичне підвищення привілеїв відбувається, коли шляхи cgroup, що розкривають інформацію про хост, поєднуються з доступними для запису інтерфейсами cgroup v1:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Якщо ці файли доступні та доступні для запису, негайно переходьте до повного `release_agent` exploitation flow з [cgroups.md](../cgroups.md). Наслідком є виконання коду на host зсередини container.

Без інтерфейсів cgroup, доступних для запису, наслідки зазвичай обмежуються reconnaissance.

## Перевірки

Мета цих команд — з’ясувати, чи має процес приватне представлення cgroup namespace, чи він дізнається більше про ієрархію host, ніж це справді потрібно.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Що тут є цікавого:

- Якщо ідентифікатор namespace відповідає процесу хоста, який вас цікавить, cgroup namespace може бути спільним.
- Шляхи, що розкривають інформацію про хост, у `/proc/self/cgroup` або записи в `mountinfo`, коренем яких є ancestor, корисні для розвідки, навіть якщо їх неможливо безпосередньо експлуатувати.
- Якщо використовується `cgroup2fs`, зосередьтеся на delegation, видимих контролерах і доступних для запису піддеревьях, а не припускайте, що старі примітиви v1 все ще існують.
- Якщо монтування cgroup також доступні для запису, питання видимості стає набагато важливішим.

cgroup namespace слід розглядати як рівень hardening видимості, а не як основний механізм запобігання escape. Непотрібне розкриття структури cgroup хоста додає атакувальнику цінну інформацію для розвідки.

## References

- [1] [cgroup_namespaces(7) — сторінка посібника Linux](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [2] [Control Group v2 — документація Linux Kernel](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
