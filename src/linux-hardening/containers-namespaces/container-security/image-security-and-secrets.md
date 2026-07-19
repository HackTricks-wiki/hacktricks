# Безпека образів, підписування та secrets

{{#include ../../../banners/hacktricks-training.md}}

## Реєстри образів і довіра

Безпека контейнерів починається ще до запуску workload. Образ визначає, які бінарні файли, інтерпретатори, бібліотеки, startup-скрипти та вбудована конфігурація потраплять у production. Якщо в образі є backdoor, він застарілий або secrets були вбудовані в нього під час створення, подальше hardening runtime вже працює зі скомпрометованим артефактом.

Саме тому provenance образу, сканування вразливостей, перевірка підписів і робота із secrets мають розглядатися разом із namespaces і seccomp. Вони захищають іншу фазу життєвого циклу, але помилки на цьому етапі часто визначають attack surface, який runtime згодом має обмежити.

## Реєстри образів і довіра

Образи можуть надходити з public registry, таких як Docker Hub, або з private registry, якими керує організація. Питання безпеки полягає не лише в тому, де зберігається образ, а й у тому, чи може команда підтвердити його provenance та integrity. Завантаження unsigned або неналежно відстежуваних образів із public sources підвищує ризик потрапляння malicious або tampered content у production. Навіть внутрішньо розміщені registry потребують чіткої відповідальності, перевірки та trust policy.

Docker Content Trust історично використовував концепції Notary і TUF, щоб вимагати signed images. Екосистема з часом змінилася, але основний висновок залишається актуальним: identity та integrity образу мають бути verifiable, а не прийматися на віру.

Приклад історичного workflow Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Суть прикладу не в тому, що кожна команда й надалі має використовувати ті самі інструменти, а в тому, що підписування та керування ключами є операційними завданнями, а не абстрактною теорією.

## Сканування вразливостей

Сканування image допомагає відповісти на два різні запитання. По-перше, чи містить image відомі вразливі пакети або бібліотеки? По-друге, чи містить image непотрібне програмне забезпечення, яке розширює поверхню атаки? Image, переповнений інструментами налагодження, shell, інтерпретаторами та застарілими пакетами, легше експлуатувати й складніше аналізувати.

Приклади поширених сканерів:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Результати роботи цих інструментів слід інтерпретувати обережно. Вразливість у невикористовуваному пакеті не становить такого самого ризику, як відкритий шлях до RCE, але обидва випадки все одно мають значення для рішень щодо hardening.

## Secrets під час збірки

Однією з найстаріших помилок у pipeline збірки контейнерів є безпосереднє вбудовування secrets в image або передавання їх через environment variables, які згодом стають видимими через `docker inspect`, логи збірки або відновлені layers. Secrets під час збірки слід тимчасово монтувати під час збірки, а не копіювати у файлову систему image.

BuildKit удосконалив цю модель, додавши спеціальну обробку secrets під час збірки. Замість запису secret у layer крок збірки може тимчасово його використовувати:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Це важливо, оскільки шари image є довговічними артефактами. Якщо secret потрапляє до зафіксованого шару, подальше видалення файлу в іншому шарі насправді не усуває початкове розкриття з історії image.

## Runtime Secrets

Secrets, потрібні для workload, що працює, також мають, за можливості, не передаватися через ad hoc механізми, як-от звичайні змінні середовища. Поширеними механізмами є volumes, спеціалізовані інтеграції для керування secrets, Docker secrets і Kubernetes Secrets. Жоден із них не усуває всі ризики, особливо якщо attacker уже отримав code execution у workload, але вони все одно кращі за постійне зберігання credentials в image або їхнє недбале розкриття через інструменти інспекції.

Просте оголошення secret у стилі Docker Compose має такий вигляд:
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
У Kubernetes об’єкти Secret, projected volumes, service-account tokens і cloud workload identities створюють ширшу та потужнішу модель, але водночас збільшують кількість можливостей для випадкового розкриття через монтування хостових ресурсів, надмірно широкі правила RBAC або неналежний дизайн Pod.

## Зловживання

Під час перевірки цілі потрібно з’ясувати, чи були secrets вбудовані в image, витекли в його шари або змонтовані в передбачувані runtime-розташування:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Ці команди допомагають розрізнити три різні проблеми: витоки конфігурації application, витоки на рівні image та файли секретів, інжектовані під час runtime. Якщо секрет з’являється у `/run/secrets`, projected volume або за шляхом до cloud identity token, наступним кроком буде з’ясувати, чи надає він доступ лише до поточного workload, чи до значно ширшої control plane.

### Повний приклад: вбудований секрет у файловій системі image

Якщо build pipeline скопіював `.env`-файли або credentials у фінальний image, post-exploitation стає простим:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Вплив залежить від застосунку, але вбудовані ключі підпису, JWT secrets або cloud credentials можуть легко перетворити компрометацію контейнера на компрометацію API, lateral movement або підробку довірених токенів застосунку.

### Повна інструкція: Build-Time Secret Leakage Check

Якщо проблема полягає в тому, що історія image містить layer із секретом:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Такий огляд корисний, оскільки секрет могли видалити з фінального вигляду файлової системи, але він усе ще може залишатися в попередньому шарі або в метаданих збірки.

## Перевірки

Ці перевірки призначені для визначення того, чи могли image та pipeline обробки секретів збільшити поверхню атаки до запуску.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Що тут цікавого:

- Підозріла історія build може виявити скопійовані облікові дані, SSH-матеріали або небезпечні кроки build.
- Secrets у шляхах projected volume можуть надати доступ до cluster або cloud, а не лише до локального застосунку.
- Велика кількість конфігураційних файлів із обліковими даними у відкритому тексті зазвичай вказує, що image або модель розгортання містить більше матеріалів довіри, ніж необхідно.

## Типові налаштування середовища виконання

| Середовище виконання / платформа | Типовий стан | Типова поведінка | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Docker / BuildKit | Підтримує безпечні монтування secret під час build, але не вмикає їх автоматично | Secrets можна тимчасово монтувати під час `build`; підписування та сканування image потребують явного вибору workflow | копіювання secrets в image, передавання secrets через `ARG` або `ENV`, вимкнення перевірок provenance |
| Podman / Buildah | Підтримує OCI-native builds і workflow з урахуванням secrets | Доступні безпечні workflow для build, але оператори мають навмисно їх обрати | вбудовування secrets у Containerfiles, широкі build contexts, дозвільні bind mounts під час build |
| Kubernetes | Нативні об’єкти Secret і projected volumes | Доставка secrets під час виконання є штатною можливістю, але рівень exposure залежить від RBAC, структури pod і монтувань хоста | надто широкі монтування Secret, зловживання service-account token, доступ через `hostPath` до томів, якими керує kubelet |
| Registries | Цілісність є необов’язковою, якщо її не забезпечено примусово | Публічні та приватні registries залежать від policy, підписування та рішень admission | вільне завантаження непідписаних images, слабкий admission control, неналежне керування ключами |
{{#include ../../../banners/hacktricks-training.md}}
