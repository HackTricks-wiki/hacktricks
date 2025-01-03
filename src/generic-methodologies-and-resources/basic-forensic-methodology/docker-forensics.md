# Docker Forensics

{{#include ../../banners/hacktricks-training.md}}

## Container modification

Є підозри, що деякий docker контейнер був скомпрометований:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Ви можете легко **знайти зміни, внесені до цього контейнера щодо зображення** за допомогою:
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
У попередній команді **C** означає **Змінено**, а **A** - **Додано**.\
Якщо ви виявите, що якийсь цікавий файл, наприклад, `/etc/shadow`, був змінений, ви можете завантажити його з контейнера, щоб перевірити на наявність шкідливої активності за допомогою:
```bash
docker cp wordpress:/etc/shadow.
```
Ви також можете **порівняти його з оригіналом**, запустивши новий контейнер і витягнувши файл з нього:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Якщо ви виявите, що **був доданий якийсь підозрілий файл**, ви можете отримати доступ до контейнера і перевірити його:
```bash
docker exec -it wordpress bash
```
## Зміни зображень

Коли вам надається експортоване зображення docker (ймовірно, у форматі `.tar`), ви можете використовувати [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) для **витягнення підсумку змін**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Тоді ви можете **розпакувати** образ і **отримати доступ до блобів**, щоб шукати підозрілі файли, які ви могли знайти в історії змін:
```bash
tar -xf image.tar
```
### Основний аналіз

Ви можете отримати **основну інформацію** з образу, запустивши:
```bash
docker inspect <image>
```
Ви також можете отримати підсумок **історії змін** за допомогою:
```bash
docker history --no-trunc <image>
```
Ви також можете згенерувати **dockerfile з образу** за допомогою:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Щоб знайти додані/змінені файли в образах docker, ви також можете використовувати [**dive**](https://github.com/wagoodman/dive) (завантажте його з [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) утиліту:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Це дозволяє вам **переміщатися між різними об'єктами образів docker** і перевіряти, які файли були змінені/додані. **Червоний** означає додано, а **жовтий** означає змінено. Використовуйте **tab** для переходу до іншого виду та **space** для згортання/розгортання папок.

З die ви не зможете отримати доступ до вмісту різних етапів образу. Щоб це зробити, вам потрібно **розпакувати кожен шар і отримати до нього доступ**.\
Ви можете розпакувати всі шари з образу з каталогу, де образ був розпакований, виконавши:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Облікові дані з пам'яті

Зверніть увагу, що коли ви запускаєте контейнер docker на хості, **ви можете бачити процеси, що виконуються в контейнері з хоста**, просто запустивши `ps -ef`.

Отже, (як root) ви можете **вивантажити пам'ять процесів** з хоста і шукати **облікові дані** просто [**як у наступному прикладі**](../../linux-hardening/privilege-escalation/#process-memory).

{{#include ../../banners/hacktricks-training.md}}
