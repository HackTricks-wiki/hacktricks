# Безпека образів, підписування та Secrets

{{#include ../../../banners/hacktricks-training.md}}

## Реєстри образів і довіра

Безпека контейнера починається ще до запуску workload. Образ визначає, які бінарні файли, інтерпретатори, бібліотеки, startup-скрипти та вбудована конфігурація потраплять у production. Якщо образ містить backdoor, застарілий або зібраний із вбудованими secrets, подальше hardening runtime вже працює зі скомпрометованим артефактом.

Саме тому provenance образу, vulnerability scanning, перевірка підписів і робота із secrets мають розглядатися разом із namespaces та seccomp. Вони захищають іншу фазу життєвого циклу, але помилки на цьому етапі часто визначають attack surface, який runtime згодом має обмежити.

## Реєстри образів і довіра

Образи можуть надходити з public registries, таких як Docker Hub, або з private registries, якими керує організація. Питання безпеки полягає не лише в тому, де зберігається образ, а й у тому, чи може команда підтвердити його provenance та integrity. Завантаження unsigned або недостатньо відстежуваних образів із public sources підвищує ризик потрапляння malicious або tampered content у production. Навіть internally hosted registries потребують чіткого власника, перевірки та trust policy.

Docker Content Trust історично використовував концепції Notary і TUF для вимоги підписаних образів. Екосистема з часом змінилася, але основний урок залишається актуальним: ідентичність та integrity образу мають бути verifiable, а не прийматися на віру.

Приклад історичного workflow Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Суть прикладу не в тому, що кожна команда й надалі повинна використовувати той самий набір інструментів, а в тому, що підписування та керування ключами — це операційні завдання, а не абстрактна теорія.

## Сканування вразливостей

Сканування image допомагає відповісти на два різні запитання. По-перше, чи містить image відомі вразливі пакети або бібліотеки? По-друге, чи містить image непотрібне програмне забезпечення, яке розширює attack surface? Image, переповнений інструментами для налагодження, shell-ами, інтерпретаторами та застарілими пакетами, легше експлуатувати й складніше аналізувати.

Приклади поширених сканерів:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Результати роботи цих tools слід інтерпретувати обережно. Вразливість у невикористовуваному package не має такого самого ризику, як exposed RCE path, але обидва випадки все одно важливі для рішень щодо hardening.

## Секрети під час build

Однією з найстаріших помилок у container build pipelines є безпосереднє вбудовування secrets в image або передавання їх через environment variables, які згодом стають видимими через `docker inspect`, build logs або відновлені layers. Build-time secrets слід тимчасово монтувати під час build, а не копіювати у файлову систему image.

BuildKit покращив цю модель, додавши спеціалізовану обробку build-time secrets. Замість запису secret у layer, build step може тимчасово його використати:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Це важливо, оскільки шари image є довговічними артефактами. Щойно секрет потрапляє до зафіксованого шару, подальше видалення файлу в іншому шарі не вилучає початкове розкриття з історії image.

## Секрети під час виконання

Секрети, необхідні для workload, що виконується, також мають по можливості не передаватися через ad hoc підходи, як-от звичайні змінні середовища. Поширеними механізмами є volumes, спеціалізовані інтеграції для керування секретами, Docker secrets і Kubernetes Secrets. Жоден із них не усуває всіх ризиків, особливо якщо attacker уже має виконання коду в workload, але вони все одно кращі за постійне зберігання облікових даних в image або їхнє недбале розкриття через інструменти інспекції.

Проста декларація секрету у стилі Docker Compose має такий вигляд:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
У Kubernetes об’єкти Secret, projected volumes, service-account tokens і cloud workload identities створюють ширшу та потужнішу модель, але також збільшують кількість можливостей для випадкового розкриття через монтування хостових ресурсів, надто широкі правила RBAC або слабкий дизайн Pod.

## Зловживання

Під час перевірки target мета полягає в тому, щоб з’ясувати, чи були secrets вбудовані в image, leaked у його шарах або змонтовані в передбачувані runtime-локації:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Ці команди допомагають розрізнити три різні проблеми: application configuration leaks, image-layer leaks і runtime-injected secret files. Якщо secret з’являється в `/run/secrets`, projected volume або шляху cloud identity token, наступним кроком є з’ясування, чи надає він доступ лише до поточного workload, чи до значно ширшої control plane.

### Повний приклад: Embedded Secret In Image Filesystem

Якщо build pipeline скопіював `.env` файли або credentials до фінального image, post-exploitation стає простим:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Вплив залежить від application, але вбудовані ключі підпису, JWT-секрети або cloud credentials можуть легко перетворити компрометацію контейнера на компрометацію API, lateral movement або підробку довірених токенів application.

### Повна перевірка leak секретів під час build

Якщо проблема полягає в тому, що history image зафіксувала шар із секретом:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Такий аналіз корисний, оскільки secret міг бути видалений із кінцевого представлення файлової системи, але водночас залишитися в попередньому layer або метаданих збірки.

## Перевірки

Ці перевірки призначені для визначення того, чи могли image та pipeline обробки secret збільшити поверхню атаки до runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Що тут є цікавого:

- Підозріла історія збірки може розкрити скопійовані облікові дані, SSH-матеріали або небезпечні кроки збірки.
- Secrets у шляхах projected volume можуть надати доступ до кластера або cloud, а не лише до локального застосунку.
- Велика кількість конфігураційних файлів із обліковими даними у відкритому тексті зазвичай свідчить, що image або модель розгортання містить більше матеріалів довіри, ніж необхідно.

## Runtime Defaults

| Runtime / platform | Стан за замовчуванням | Поведінка за замовчуванням | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Docker / BuildKit | Підтримує безпечні монтування секретів під час збірки, але не вмикає їх автоматично | Secrets можна тимчасово монтувати під час `build`; підписування та сканування image потребують явного вибору workflow | копіювання secrets до image, передавання secrets через `ARG` або `ENV`, вимкнення перевірок provenance |
| Podman / Buildah | Підтримує OCI-native builds і workflows із підтримкою secrets | Доступні безпечні workflows збірки, але оператори все одно мають свідомо їх обрати | вбудовування secrets у Containerfiles, широкі build contexts, надто permissive bind mounts під час збірки |
| Kubernetes | Нативні Secret objects і projected volumes | Доставка secrets під час виконання є first-class, але рівень exposure залежить від RBAC, дизайну pod і монтувань хоста | надто широкі Secret mounts, неналежне використання service-account token, доступ через `hostPath` до томів, якими керує kubelet |
| Registries | Цілісність є необов'язковою, якщо її не забезпечено примусово | Public і private registries залежать від policy, signing та admission-рішень | вільне завантаження unsigned images, слабкий admission control, неналежне керування ключами |

{{#include ../../../banners/hacktricks-training.md}}
