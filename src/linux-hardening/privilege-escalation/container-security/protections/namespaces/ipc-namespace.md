# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Огляд

The IPC namespace isolates **System V IPC objects** and **POSIX message queues**. That includes shared memory segments, semaphores, and message queues that would otherwise be visible across unrelated processes on the host. In practical terms, this prevents a container from casually attaching to IPC objects belonging to other workloads or the host.

Compared with mount, PID, or user namespaces, the IPC namespace is often discussed less often, but that should not be confused with irrelevance. Shared memory and related IPC mechanisms can contain highly useful state. If the host IPC namespace is exposed, the workload may gain visibility into inter-process coordination objects or data that was never intended to cross the container boundary.

## Принцип роботи

When the runtime creates a fresh IPC namespace, the process gets its own isolated set of IPC identifiers. This means commands such as `ipcs` show only the objects available in that namespace. If the container instead joins the host IPC namespace, those objects become part of a shared global view.

This matters especially in environments where applications or services use shared memory heavily. Even when the container cannot directly break out through IPC alone, the namespace may leak information or enable cross-process interference that materially helps a later attack.

## Лабораторна

You can create a private IPC namespace with:
```bash
sudo unshare --ipc --fork bash
ipcs
```
І порівняйте поведінку під час виконання з:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Використання під час виконання

Docker і Podman за замовчуванням ізолюють IPC. Kubernetes зазвичай надає Pod власний IPC namespace, спільний для контейнерів у тому самому Pod, але за замовчуванням не з host. Спільний доступ до host IPC можливий, але його слід розглядати як суттєве зниження ізоляції, а не як незначну runtime-опцію.

## Неправильні налаштування

Очевидна помилка — `--ipc=host` або `hostIPC: true`. Це може робитись для сумісності зі застарілим ПО або зручності, але суттєво змінює модель довіри. Інша повторювана проблема — просто нехтування IPC, оскільки це здається менш драматичним, ніж host PID або host networking. Насправді, якщо робоче навантаження оперує браузерами, базами даних, науковими задачами або іншим ПО, яке інтенсивно використовує спільну пам'ять, поверхня IPC може бути дуже релевантною.

## Зловживання

Коли host IPC спільний, атакувальник може переглядати або втручатися у shared memory objects, отримати додаткове уявлення про поведінку host або сусідніх робочих навантажень, або поєднати отриману інформацію з видимістю процесів та можливостями ptrace-style. Спільний доступ до IPC часто є допоміжною слабкістю, а не повним шляхом ескалації, але допоміжні слабкості важливі, бо скорочують і стабілізують реальні ланцюги атак.

Перший корисний крок — перелічити, які IPC об'єкти взагалі видимі:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Якщо спільно використовується простір імен IPC хоста, великі сегменти спільної пам'яті або цікаві власники об'єктів можуть негайно розкрити поведінку додатка:
```bash
ipcs -m -p
ipcs -q -p
```
У деяких середовищах, вміст `/dev/shm` сам по собі leak filenames, artifacts або tokens, які варто перевірити:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC sharing рідко саме по собі дає миттєвий host root, але може відкривати канали даних і координації, які значно полегшують подальші атаки на процеси.

### Повний приклад: `/dev/shm` відновлення секретів

Найреалістичніший повний випадок зловживання — це крадіжка даних, а не direct escape. Якщо host IPC або широка схема спільної пам’яті відкриті, чутливі артефакти іноді можна відновити безпосередньо:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Вплив:

- вилучення секретів або матеріалів сесії, що залишилися у shared memory
- інформація про додатки, які наразі активні на хості
- краще націлювання для подальших атак на основі PID-namespace або ptrace

Отже, IPC sharing радше слід розглядати як **підсилювач атаки**, ніж як автономний host-escape primitive.

## Перевірки

Ці команди мають відповісти, чи має workload приватний IPC view, чи видимі значущі shared-memory або message objects, та чи сам `/dev/shm` містить корисні артефакти.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
- Якщо `ipcs -a` виявляє об'єкти, що належать неочікуваним користувачам або сервісам, простір імен може бути не таким ізольованим, як очікували.
- Великі або незвичні сегменти розділеної пам'яті часто варто перевірити.
- Широке монтування `/dev/shm` не є автоматично помилкою, але в деяких середовищах воно leaks імена файлів, артефакти та тимчасові секрети.

IPC рідко отримує стільки уваги, як більші типи просторів імен, але в середовищах, де його інтенсивно використовують, його спільне використання з хостом — це радше рішення з безпеки.
{{#include ../../../../../banners/hacktricks-training.md}}
