# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

The cgroup namespace does not replace cgroups and does not itself enforce resource limits. Instead, it changes **як відображається ієрархія cgroup** для процесу. Іншими словами, він віртуалізує видиму інформацію про cgroup-шлях так, щоб робоче навантаження бачило подання, обмежене контейнером, а не повну ієрархію хоста.

Це насамперед функція обмеження видимості та зменшення обсягу інформації. Вона допомагає зробити середовище більш самодостатнім і розкривати менше про розмітку cgroup хоста. Це може здаватися незначним, але має значення, оскільки зайва видимість структури хоста може допомогти при розвідці та спростити environment-dependent exploit chains.

## Operation

Без приватного cgroup namespace процес може бачити cgroup-шляхи відносно хоста, які розкривають більше ієрархії машини, ніж потрібно. З приватним cgroup namespace `/proc/self/cgroup` та суміжні спостереження стають більш локалізованими до власного подання контейнера. Це особливо корисно в сучасних runtime-стеках, які прагнуть, щоб робоче навантаження бачило більш чисте, менше видаюче інформацію про хост середовище.

## Lab

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

The cgroup namespace is best understood as a **visibility-hardening layer**. By itself it will not stop a breakout if the container has writable cgroup mounts, broad capabilities, or a dangerous cgroup v1 environment. However, if the host cgroup namespace is shared, the process learns more about how the system is organized and may find it easier to line up host-relative cgroup paths with other observations.

Отже, хоча цей namespace зазвичай не є центральним у writeups про container breakout, він все одно сприяє загальній меті мінімізації host information leakage.

## Зловживання

The immediate abuse value is mostly reconnaissance. If the host cgroup namespace is shared, compare the visible paths and look for host-revealing hierarchy details:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Якщо також відкриті для запису шляхи cgroup, поєднайте цю видимість із пошуком небезпечних застарілих інтерфейсів:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
The namespace itself rarely gives instant escape, but it often makes the environment easier to map before testing cgroup-based abuse primitives.

### Повний приклад: Спільний cgroup Namespace + Доступний для запису cgroup v1

Одна тільки cgroup namespace зазвичай недостатня для escape. Практична ескалація відбувається, коли шляхи cgroup, що видають інформацію про хост, поєднуються з інтерфейсами cgroup v1, доступними для запису:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Якщо ці файли доступні та записувані, негайно переходьте до повного експлуатаційного сценарію `release_agent` з [cgroups.md](../cgroups.md). Наслідком є виконання коду на хості зсередини контейнера.

За відсутності записуваних інтерфейсів cgroup, наслідки зазвичай обмежуються розвідкою.

## Перевірки

Мета цих команд — визначити, чи має процес приватний перегляд cgroup namespace або чи дізнається він більше про ієрархію хоста, ніж йому справді потрібно.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
Цікаве тут:

- Якщо ідентифікатор простору імен збігається з процесом хоста, який вас цікавить, the cgroup namespace може бути спільним.
- Шляхи, що розкривають інформацію про хост у `/proc/self/cgroup`, корисні для розвідки навіть коли вони прямо не експлуатуються.
- Якщо cgroup mounts також доступні для запису, питання видимості стає набагато важливішим.

The cgroup namespace слід розглядати як шар загартування видимості, а не як основний механізм запобігання escape. Непотрібне розкриття структури cgroup хоста надає нападнику додаткову інформацію для розвідки.
{{#include ../../../../../banners/hacktricks-training.md}}
