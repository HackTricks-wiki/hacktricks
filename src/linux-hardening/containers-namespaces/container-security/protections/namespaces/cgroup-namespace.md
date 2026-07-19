# Простір імен cgroup

{{#include ../../../../../banners/hacktricks-training.md}}

## Огляд

Простір імен cgroup не замінює cgroups і сам по собі не встановлює обмеження ресурсів. Натомість він змінює **спосіб відображення ієрархії cgroup** для процесу. Іншими словами, він віртуалізує видиму інформацію про шляхи cgroup, щоб workload бачив область контейнера, а не всю ієрархію хоста.

Це насамперед функція видимості та зменшення обсягу інформації. Вона допомагає зробити середовище самодостатнім на вигляд і розкриває менше інформації про структуру cgroup хоста. Це може здаватися незначним, але все одно має значення, оскільки зайва видимість структури хоста може допомагати під час розвідки та спрощувати exploit chains, залежні від середовища.

## Робота

Без приватного простору імен cgroup процес може бачити шляхи cgroup, що визначаються відносно хоста та розкривають більшу частину ієрархії машини, ніж це потрібно. Із приватним простором імен cgroup `/proc/self/cgroup` та пов'язані спостереження стають більш локалізованими до власного представлення контейнера. Це особливо корисно в сучасних runtime stacks, які хочуть, щоб workload бачив чистіше середовище, що розкриває менше інформації про хост.

Віртуалізація також впливає на `/proc/<pid>/mountinfo`, а не лише на `/proc/<pid>/cgroup`. Коли ви читаєте інформацію про інший процес із perspective іншого простору імен cgroup, шляхи за межами кореня вашого простору імен відображаються з початковими компонентами `../`. Це зручна ознака того, що ви переглядаєте ієрархію вище свого делегованого піддерева. Важливий нюанс для labs і post-exploitation полягає в тому, що щойно створений простір імен cgroup часто потребує **повторного монтування cgroupfs зсередини цього простору імен**, перш ніж `mountinfo` коректно відобразить новий корінь. Інакше ви все ще можете бачити корінь монтування на кшталт `/..`, що означає: успадковане монтування все ще показує представлення з коренем у батьківському вузлі, хоча сам простір імен уже змінився.

## Лабораторна робота

Перевірити простір імен cgroup можна за допомогою:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Якщо ви хочете, щоб `mountinfo` чіткіше показував новий root cgroup-namespace, перемонтуйте файлову систему cgroup зсередини нового namespace і порівняйте ще раз:
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
Зміна здебільшого стосується того, що може бачити процес, а не того, чи існує enforcement для cgroup.

## Вплив на безпеку

cgroup namespace найкраще розуміти як **рівень hardening видимості**. Сам по собі він не зупинить breakout, якщо контейнер має доступні для запису монтування cgroup, широкі capabilities або небезпечне середовище cgroup v1. Однак якщо namespace cgroup хоста є спільним, процес отримує більше інформації про організацію системи, і йому може бути простіше зіставити шляхи cgroup, відносні до хоста, з іншими спостереженнями.

У **cgroup v2** namespace стає дещо важливішим, оскільки правила delegation є суворішими. Якщо ієрархію змонтовано з `nsdelegate`, kernel розглядає cgroup namespaces як межі delegation: файли керування ancestor мають залишатися поза межами доступу delegatee, а записи в root namespace обмежуються файлами, безпечними для delegation, такими як `cgroup.procs`, `cgroup.threads` і `cgroup.subtree_control`. Це все одно не робить namespace примітивом для escape, але змінює те, що compromised workload може перевіряти, і місця, де він може безпечно створювати sub-cgroups.

Тож, хоча цей namespace зазвичай не є головним елементом writeup'ів про container breakout, він усе одно сприяє ширшій меті — мінімізації витоку інформації про хост і обмеженню delegation cgroup.

## Abuse

Безпосередня цінність abuse здебільшого полягає в reconnaissance. Якщо namespace cgroup хоста є спільним, порівняйте видимі шляхи та шукайте деталі ієрархії, які розкривають інформацію про хост:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Якщо також відкриті для запису шляхи cgroup, поєднайте це з пошуком небезпечних застарілих інтерфейсів:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Сам namespace рідко одразу дає змогу виконати escape, але часто спрощує аналіз середовища перед тестуванням примітивів зловживання на основі cgroup.

Швидка перевірка фактичної конфігурації runtime також допомагає визначити пріоритетність attack path. Docker підтримує `--cgroupns=host|private`, тоді як Podman підтримує `host`, `private`, `container:<id>` і `ns:<path>`. Зокрема в Podman типовим значенням зазвичай є **`host` для cgroup v1** і **`private` для cgroup v2`, тож саме визначення версії cgroup уже підказує, який стан namespace є більш імовірним, ще до перевірки повної конфігурації OCI.

### Сучасний Recon у v2: Чи є це делегованим піддеревом?

На сучасних хостах важливим питанням часто є не `release_agent`, а те, чи перебуває поточний процес усередині делегованого піддерева **cgroup v2** із достатньою видимістю або правами на запис для створення вкладених груп:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Корисна інтерпретація:

- `cgroup2fs` означає, що ви перебуваєте в уніфікованій ієрархії v2, тож класичні ланцюжки `release_agent`, що працюють лише у v1, не повинні бути вашою першою здогадкою.
- `cgroup.controllers` показує, які контролери доступні від батьківського вузла, а отже, які контролери поточне піддерево потенційно може передати дочірнім вузлам.
- `cgroup.subtree_control` показує, які контролери фактично увімкнені для нащадків.
- `cgroup.events` надає значення `populated=0/1`, що зручно для відстеження того, чи стало піддерево порожнім, але це **не примітив виконання коду на хості**, подібний до `release_agent` у v1.

Якщо ви вже маєте достатні привілеї для безпосередньої перевірки namespace іншого процесу, порівняйте представлення за допомогою:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Повний приклад: спільний cgroup namespace + доступний для запису cgroup v1

Самого cgroup namespace зазвичай недостатньо для escape. Практична ескалація відбувається, коли cgroup paths, що розкривають інформацію про host, поєднуються з доступними для запису інтерфейсами cgroup v1:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Якщо ці файли доступні та доступні для запису, негайно переходьте до повного ланцюжка експлуатації `release_agent` з [cgroups.md](../cgroups.md). Впливом є виконання коду на host із контейнера.

Без інтерфейсів cgroup, доступних для запису, вплив зазвичай обмежується розвідкою.

## Перевірки

Мета цих команд — з’ясувати, чи має процес приватне представлення простору імен cgroup, чи отримує він більше інформації про ієрархію host, ніж це справді потрібно.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Що тут є цікавого:

- Якщо ідентифікатор namespace збігається з ідентифікатором потрібного вам процесу на host, cgroup namespace може бути спільним.
- Шляхи, що розкривають host, у `/proc/self/cgroup` або записи в `mountinfo`, прив'язані до кореня ancestor, корисні для розвідки, навіть якщо безпосередньо не можуть бути використані для exploitation.
- Якщо використовується `cgroup2fs`, зосередьтеся на delegation, видимих controllers і writable subtrees, а не припускайте, що старі примітиви v1 усе ще існують.
- Якщо cgroup mounts також доступні для запису, питання видимості стає набагато важливішим.

cgroup namespace слід розглядати як рівень hardening видимості, а не як основний механізм запобігання escape. Непотрібне розкриття структури cgroup host додає attacker додаткові можливості для розвідки.

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Документація Linux kernel щодо cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
