# cgroup простір імен

{{#include ../../../../../banners/hacktricks-training.md}}

## Огляд

cgroup namespace не замінює cgroups і сам по собі не застосовує обмеження ресурсів. Натомість він змінює **те, як ієрархія cgroup виглядає** для процесу. Іншими словами, він віртуалізує видиму інформацію про шлях cgroup так, щоб робоче навантаження бачило огляд, обмежений контейнером, замість повної ієрархії хоста.

Це в основному функція для обмеження видимості й скорочення інформації. Вона допомагає зробити середовище більш автономним і розкривати менше про розкладку cgroup хоста. Це може звучати незначно, але має значення, оскільки зайва видимість структури хоста може полегшити розвідку і спростити залежні від середовища ланцюжки експлойтів.

## Як це працює

Без приватного cgroup namespace процес може бачити шляхи cgroup відносно хоста, які розкривають більше ієрархії машини, ніж потрібно. З приватним cgroup namespace `/proc/self/cgroup` та пов'язані спостереження стають більш локалізованими у межах огляду контейнера. Це особливо корисно в сучасних runtime-стеках, які прагнуть, щоб робоче навантаження бачило чистіше, менш розкриваюче інформацію про хост середовище.

## Лаб

Ви можете перевірити cgroup namespace за допомогою:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
І порівняйте поведінку під час виконання з:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Зміна здебільшого стосується того, що процес може бачити, а не того, чи існує cgroup enforcement.

## Вплив на безпеку

cgroup namespace найкраще розуміти як **шар обмеження видимості**. Сам по собі він не зупинить breakout, якщо контейнер має writable cgroup mounts, широкі capabilities або небезпечне cgroup v1 середовище. Однак якщо host cgroup namespace спільний, процес дізнається більше про організацію системи й може легше зіставляти host-relative cgroup paths з іншими спостереженнями.

Тому хоча цей namespace зазвичай не є головним у container breakout writeups, він все ж сприяє ширшій меті — мінімізації host information leakage.

## Зловживання

Негайна цінність для зловживань здебільшого в reconnaissance. Якщо host cgroup namespace спільний, порівняйте видимі шляхи й шукайте деталі ієрархії, що видають інформацію про хоста:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Якщо доступні для запису cgroup paths, поєднайте цю видимість з пошуком небезпечних застарілих інтерфейсів:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Сам namespace рідко дає миттєвий escape, але часто полегшує картографування середовища перед тестуванням cgroup-based abuse primitives.

### Повний приклад: Shared cgroup Namespace + Writable cgroup v1

Сама cgroup namespace зазвичай недостатня для escape. Практична ескалація відбувається, коли host-revealing cgroup paths поєднуються з writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Якщо ті файли доступні й дозволяють запис, негайно переходьте до повного потоку експлуатації `release_agent` з [cgroups.md](../cgroups.md). Наслідок — виконання коду на хості зсередини контейнера.

Якщо cgroup interfaces не доступні для запису, вплив зазвичай обмежується reconnaissance.

## Перевірки

Суть цих команд — визначити, чи має процес приватний вигляд cgroup namespace або дізнається більше про ієрархію хоста, ніж йому насправді потрібно.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
Цікаве тут:

- Якщо ідентифікатор namespace збігається з процесом хоста, який вас цікавить, cgroup namespace може бути спільним.
- Шляхи, що розкривають інформацію про хост у `/proc/self/cgroup`, корисні для reconnaissance, навіть коли вони не є безпосередньо експлуатованими.
- Якщо cgroup mounts також доступні для запису, питання видимості стає значно важливішим.

cgroup namespace слід розглядати як шар посилення захисту видимості, а не як основний escape-prevention mechanism. Непотрібне розкриття структури cgroup хоста підвищує reconnaissance-цінність для атакувальника.
{{#include ../../../../../banners/hacktricks-training.md}}
