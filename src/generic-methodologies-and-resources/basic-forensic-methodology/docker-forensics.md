# Форензика Docker

{{#include ../../banners/hacktricks-training.md}}


## Модифікація контейнера

Є підозри, що деякий docker-контейнер було скомпрометовано:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Ви можете легко **знайти зміни, внесені до цього контейнера порівняно з образом**, за допомогою:
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
У попередній команді **C** означає **Змінено**, а **A** — **Додано**.\
Якщо ви виявите, що такий цікавий файл, як `/etc/shadow`, було змінено, ви можете завантажити його з контейнера, щоб перевірити наявність шкідливої активності за допомогою:
```bash
docker cp wordpress:/etc/shadow.
```
Ви також можете **порівняти його з оригінальним**, запустивши новий контейнер і витягнувши з нього файл:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Якщо ви виявите, що було додано **якийсь підозрілий файл**, ви можете отримати доступ до контейнера та перевірити його:
```bash
docker exec -it wordpress bash
```
## Модифікації образу

Коли ви отримуєте експортований docker-образ (імовірно у форматі `.tar`), ви можете використати [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases), щоб **отримати зведення модифікацій**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Потім ви можете **розпакувати** образ і **отримати доступ до blobs**, щоб шукати підозрілі файли, які, можливо, ви знайшли в історії змін:
```bash
tar -xf image.tar
```
### Базовий аналіз

Ви можете отримати **базову інформацію** з образу, виконавши:
```bash
docker inspect <image>
```
Також можна отримати короткий огляд **історії змін** за допомогою:
```bash
docker history --no-trunc <image>
```
Також можна згенерувати **dockerfile з image** за допомогою:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Щоб знайти додані/змінені файли в Docker images, також можна використовувати утиліту [**dive**](https://github.com/wagoodman/dive) (завантажте її зі сторінки [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Це дозволяє **переміщатися між різними blob-об’єктами Docker images** і перевіряти, які файли було змінено/додано. **Червоний** означає доданий, а **жовтий** — змінений. Використовуйте **tab**, щоб перейти до іншого подання, і **space**, щоб згортати/розгортати папки.

За допомогою die ви не зможете отримати доступ до вмісту різних stages image. Для цього потрібно **розпакувати кожен layer і отримати до нього доступ**.\
Ви можете розпакувати всі layers image з каталогу, де image було розпаковано, виконавши:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Облікові дані з пам’яті

Зверніть увагу, що коли ви запускаєте docker container всередині host, **ви можете бачити процеси, запущені в container, із host**, просто виконавши `ps -ef`

Тому (як root) ви можете **дампити пам’ять процесів** із host і шукати **облікові дані** просто [**як у наведеному прикладі**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).


{{#include ../../banners/hacktricks-training.md}}
