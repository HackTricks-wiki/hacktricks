# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

cgroup namespace не замінює cgroups і сам по собі не застосовує обмеження ресурсів. Натомість він змінює **те, як ієрархія cgroup виглядає** для процесу. Іншими словами, він віртуалізує видиму інформацію про шлях cgroup так, щоб workload бачив представлення в межах container, а не повну ієрархію host.

Це переважно функція видимості та зменшення інформації. Вона допомагає зробити середовище більш самодостатнім і розкриває менше про cgroup-структуру host. Це може здаватися незначним, але все ж важливо, бо зайва видимість структури host може допомогти в reconnaissance і спростити exploit chains, що залежать від середовища.

## Operation

Без приватного cgroup namespace процес може бачити host-relative cgroup paths, які розкривають більше ієрархії машини, ніж потрібно. З приватним cgroup namespace `/proc/self/cgroup` та пов’язані спостереження стають більш локальними до власного подання container. Це особливо корисно в сучасних runtime stacks, які хочуть, щоб workload бачив чистіше середовище, яке менше розкриває host.

Віртуалізація також впливає на `/proc/<pid>/mountinfo`, а не лише на `/proc/<pid>/cgroup`. Коли ви читаєте інший процес з іншої cgroup-namespace perspective, шляхи поза коренем вашого namespace відображаються з початковими компонентами `../`, що є зручною підказкою про те, що ви дивитеся вище за свій delegated subtree. Корисний нюанс для labs і post-exploitation полягає в тому, що щойно створений cgroup namespace часто потребує **cgroupfs remount зсередини цього namespace** перед тим, як `mountinfo` почне чисто відображати новий root. Інакше ви все ще можете бачити mount root на кшталт `/..`, що означає, що успадкований mount і далі показує подання з root предка, хоча сам namespace вже змінився.

## Lab

You can inspect a cgroup namespace with:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Якщо ви хочете, щоб `mountinfo` показував новий root cgroup-namespace більш чітко, перемонтуйте cgroup filesystem зсередини нового namespace і порівняйте ще раз:
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
Зміна здебільшого стосується того, що process може бачити, а не того, чи існує cgroup enforcement.

## Security Impact

cgroup namespace найкраще розуміти як **visibility-hardening layer**. Сам по собі він не зупинить breakout, якщо container має writable cgroup mounts, broad capabilities або небезпечне cgroup v1 середовище. Однак, якщо host cgroup namespace shared, process дізнається більше про те, як організована system, і може легше зіставити host-relative cgroup paths з іншими спостереженнями.

На **cgroup v2** namespace стає трохи важливішим, тому що delegation rules суворіші. Якщо hierarchy змонтовано з `nsdelegate`, kernel розглядає cgroup namespaces як delegation boundaries: ancestor control files мають залишатися поза досяжністю delegatee, а writes у namespace root обмежуються delegation-safe files, такими як `cgroup.procs`, `cgroup.threads` і `cgroup.subtree_control`. Це все ще не робить namespace escape primitive сам по собі, але змінює те, що compromised workload може inspect і де він може safely створювати sub-cgroups.

Тож хоча цей namespace зазвичай не є зіркою writeups про container breakout, він усе одно сприяє ширшій меті мінімізації host information leakage і обмеження cgroup delegation.

## Abuse

Найближча практична цінність abuse — це здебільшого reconnaissance. Якщо host cgroup namespace shared, порівняйте visible paths і шукайте details ієрархії, що видають host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Якщо також exposed writable cgroup paths, поєднайте цю visibility з пошуком dangerous legacy interfaces:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Сам namespace рідко дає миттєву втечу, але часто полегшує картографування середовища перед тестуванням primitives зловживання на основі cgroup.

Швидка перевірка runtime-реальності також допомагає пріоритизувати шлях атаки. Docker надає `--cgroupns=host|private`, тоді як Podman підтримує `host`, `private`, `container:<id>`, і `ns:<path>`. Саме в Podman типовим значенням зазвичай є **`host` на cgroup v1** і **`private` на cgroup v2**, тож просте визначення версії cgroup уже підказує, який posture namespace є більш імовірним, ще до перегляду повної OCI config.

### Modern v2 Recon: Is This A Delegated Subtree?

На сучасних hosts цікаве питання часто полягає не в `release_agent`, а в тому, чи перебуває поточний process всередині делегованого піддерева **cgroup v2** з достатньою видимістю або доступом на запис, щоб створювати вкладені groups:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Корисна інтерпретація:

- `cgroup2fs` означає, що ви перебуваєте в unified v2 ієрархії, тож класичні v1-only `release_agent` ланцюжки більше не мають бути вашим першим припущенням.
- `cgroup.controllers` показує, які controllers доступні з батьківського рівня, а отже на що поточне піддерево потенційно може розгалужуватися до дочірніх.
- `cgroup.subtree_control` показує, які controllers фактично увімкнені для нащадків.
- `cgroup.events` розкриває `populated=0/1`, що зручно для спостереження, чи стало піддерево порожнім, але це **не** primitive для host-code-execution, як v1 `release_agent`.

Якщо у вас уже достатньо privilege, щоб напряму перевірити namespace іншого процесу, порівняйте views за допомогою:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Повний приклад: Shared cgroup Namespace + Writable cgroup v1

cgroup namespace сам по собі зазвичай недостатній для escape. Практичне підвищення привілеїв відбувається, коли шляхи cgroup, що розкривають host, поєднуються з writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Якщо ті файли reachable і writable, негайно pivot into full `release_agent` exploitation flow з [cgroups.md](../cgroups.md). Impact — host code execution зсередини container.

Без writable cgroup interfaces impact зазвичай обмежується reconnaissance.

## Checks

Мета цих команд — перевірити, чи має process private cgroup namespace view, або чи дізнається більше про host hierarchy, ніж йому справді потрібно.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Що тут цікаво:

- Якщо ідентифікатор namespace збігається з host process, який вас цікавить, cgroup namespace може бути спільним.
- Шляхи, що reveal host у `/proc/self/cgroup`, або записи в `mountinfo`, rooted від ancestor, корисні для reconnaissance, навіть якщо вони не є directly exploitable.
- Якщо використовується `cgroup2fs`, зосередьтеся на delegation, visible controllers і writable subtrees, а не на припущенні, що старі primitives v1 усе ще існують.
- Якщо cgroup mounts також writable, питання visibility стає ще важливішим.

cgroup namespace слід розглядати як visibility-hardening layer, а не як primary escape-prevention mechanism. Неналежне exposure host cgroup structure додає attacker reconnaissance value.

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
