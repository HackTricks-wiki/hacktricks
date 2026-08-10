# Форензика Docker

## Модифікація контейнера

Є підозри, що певний docker-контейнер було скомпрометовано:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Ви можете легко **знайти зміни, внесені до файлової системи цього контейнера з моменту його створення**:<sup>[[1]](#references)</sup>
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
У попередній команді **C** означає **Changed**, а **A** — **Added**.<sup>[[1]](#references)</sup>\
Якщо ви виявите, що якийсь цікавий файл, наприклад `/etc/shadow`, було змінено, ви можете завантажити його з контейнера, щоб перевірити на наявність шкідливої активності за допомогою:<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
Ви також можете **порівняти його з оригінальним**, запустивши новий контейнер і видобувши з нього файл:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Якщо ви виявите, що було додано **підозрілий файл**, ви можете отримати доступ до контейнера та перевірити його:<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## Зміни образу Docker

Якщо вам надано експортований образ Docker (імовірно у форматі `.tar`), ви можете використати [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases), щоб **отримати зведення змін**:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Потім ви можете **розпакувати** образ і **отримати доступ до blob-об’єктів**, щоб шукати підозрілі файли, які ви могли знайти в історії змін:<sup>[[7]](#references)</sup>
```bash
tar -xf image.tar
```
### Базовий аналіз

Ви можете отримати **базову інформацію** з образу, виконавши:<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
Ви також можете отримати короткий огляд **історії змін** за допомогою:<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
Ви також можете створити **dockerfile з image** за допомогою:<sup>[[10]](#references)</sup>
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

Щоб знайти додані/змінені файли в docker images, ви також можете використати утиліту [**dive**](https://github.com/wagoodman/dive) (завантажте її зі сторінки [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0):<sup>[[11]](#references)[[12]](#references)</sup>

Перед відкриттям image tag за допомогою dive завантажте збережений archive у Docker:<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Це дозволяє **переміщатися між різними blobs Docker-образів** і перевіряти, які файли було змінено/додано/видалено. Використовуйте **tab**, щоб перейти до іншого представлення, і **пробіл**, щоб згорнути/розгорнути папки.<sup>[[11]](#references)</sup>

За допомогою dive ви не зможете отримати доступ до вмісту різних етапів образу. Для цього потрібно **розпакувати кожен layer і отримати до нього доступ**.\
Ви можете розпакувати всі layer з образу з каталогу, де було розпаковано образ, виконавши:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Облікові дані з пам'яті

У Linux простір імен PID предка хоста може бачити процеси в дочірньому просторі імен PID контейнера, тому список процесів хоста, наприклад `ps -ef`, може показувати їх.<sup>[[14]](#references)</sup>

Якщо облікові дані хоста, capabilities і політика LSM/ptrace це дозволяють, належним чином привілейований дослідник хоста може **зняти дамп пам'яті процесу** та шукати **облікові дані** [**так само, як у наступному прикладі**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).<sup>[[15]](#references)</sup>

## References

- [1] [Порівняння контейнера Docker](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [Копіювання контейнера Docker](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [Запуск контейнера Docker](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [Виконання команди в контейнері Docker](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [Визначення аналізаторів container-diff](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [Збереження образу Docker](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [Перевірка образу Docker](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [Історія образу Docker](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [README Dive v0.10.0](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [Реліз Dive v0.10.0](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [Завантаження образу Docker](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{{#include ../../banners/hacktricks-training.md}}
