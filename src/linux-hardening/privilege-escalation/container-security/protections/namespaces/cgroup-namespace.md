# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Огляд

cgroup namespace не замінює cgroups і сам по собі не примушує застосовувати обмеження ресурсів. Замість цього він змінює **як виглядає ієрархія cgroup** для процесу. Іншими словами, він віртуалізує видиму інформацію про шляхи cgroup, тож робоче навантаження бачить вигляд, обмежений контейнером, а не повну ієрархію хоста.

Це переважно функція видимості та скорочення інформації. Вона допомагає зробити середовище більш ізольованим і відкриває менше відомостей про структуру cgroup хоста. Це може здатися скромним, але важливо, оскільки непотрібна видимість структури хоста може сприяти розвідці й спрощувати environment-dependent exploit chains.

## Принцип роботи

Без приватного cgroup namespace процес може бачити шляхи cgroup відносно хоста, які розкривають більше ієрархії машини, ніж корисно. З приватним cgroup namespace `/proc/self/cgroup` та пов'язані спостереження стають більш локалізованими до власного погляду контейнера. Це особливо корисно в сучасних runtime-стеках, які прагнуть, щоб робоче навантаження бачило більш чисте, менш таке, що видає хост, середовище.

## Лабораторія

Ви можете інспектувати cgroup namespace за допомогою:
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

## Security Impact

The cgroup namespace is best understood as a **шар, що ускладнює видимість**. Сам по собі він не зупинить breakout, якщо контейнер має writable cgroup mounts, широкі capabilities або небезпечне cgroup v1 environment. Однак, якщо host cgroup namespace спільний, процес дізнається більше про те, як організована система, і може легше зіставляти host-relative cgroup paths з іншими спостереженнями.

Тому, хоча цей namespace зазвичай не є зіркою у container breakout writeups, він все одно сприяє ширшій меті мінімізації витоку інформації про хост.

## Abuse

Негайна цінність для зловживань здебільшого полягає в reconnaissance. Якщо host cgroup namespace спільний, порівняйте видимі шляхи та шукайте деталі ієрархії, що видають інформацію про host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Якщо також відкриті для запису cgroup paths, поєднайте цю видимість з пошуком небезпечних legacy interfaces:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Сам по собі namespace рідко дає миттєвий escape, але часто полегшує картографування середовища перед тестуванням cgroup-based abuse primitives.

### Повний приклад: Shared cgroup Namespace + Writable cgroup v1

Сама cgroup namespace зазвичай недостатня для escape. Практична ескалація відбувається, коли host-revealing cgroup paths поєднуються з writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Якщо до цих файлів можна дістатися й у них можна записувати, негайно переходьте до повного експлуатаційного ланцюжка `release_agent` з [cgroups.md](../cgroups.md). Наслідком є виконання коду на хості зсередини контейнера.

Якщо інтерфейси cgroup не дозволяють запис, вплив зазвичай обмежується розвідкою.

## Checks

Мета цих команд — перевірити, чи має процес приватний cgroup namespace або чи дізнається він про ієрархію хоста більше, ніж насправді потрібно.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
What is interesting here:

- Якщо ідентифікатор namespace збігається з процесом хоста, який вас цікавить, cgroup namespace може бути спільним.
- Шляхи в `/proc/self/cgroup`, що розкривають інформацію про хост, корисні для розвідки навіть коли їх неможливо безпосередньо експлуатувати.
- Якщо cgroup mounts також доступні для запису, питання видимості стає набагато важливішим.

The cgroup namespace should be treated as a visibility-hardening layer rather than as a primary escape-prevention mechanism. Exposing host cgroup structure unnecessarily adds reconnaissance value for the attacker.
