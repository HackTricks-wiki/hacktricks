# Широкий пошук вихідного коду

Мета цієї сторінки — перелічити **платформи, які дають змогу шукати код** (буквально, за regex, з урахуванням символів або в межах певних шляхів) у **тисячах/мільйонах репозиторіїв**.

Це корисно для:

- **Пошуку leaked information**
- **Пошуку вразливих шаблонів**
- **Картографування технологій, внутрішніх хостів, CI/CD та infrastructure-as-code**
- **Переходу від назви компанії/org до репозиторіїв, гілок і файлів із високою сигнальністю**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted пошук коду з підтримкою regex, символів і фільтрованого пошуку в репозиторіях. Налаштуйте додаткові гілки/теги та запитуйте їх за допомогою `rev:`, коли важливе охоплення гілок.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search): Пошук коду з підтримкою regex, boolean, символів, репозиторіїв/файлів/мов, гілок/комітів, diff і запитів за повідомленнями комітів.<sup>[[8]](#references)[[10]](#references)</sup> Structural search є необов'язковим, оскільки поточна документація описує його як вимкнений за замовчуванням і обмежений за продуктивністю.<sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search): Підтримує regex, boolean logic та qualifiers, як-от `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` і `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Пошук коду на основі Zoekt із режимами exact і regex та фільтрами, як-от `file:`, `lang:`, `repo:` і `sym:`.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) є ширшим fallback, оскільки дає змогу шукати код, коментарі, коміти, merge requests і wikis.<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/): Сервіс code-intelligence із boolean/regex/structural пошуком коду, а також отриманням файлів і символів.<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/): Public code search у мільйоні GitHub-репозиторіїв із пошуком за вмістом, файлами та шляхами.<sup>[[13]](#references)</sup>

## Корисні можливості пошуку

Під час аудиту org у контексті bug bounty/red team найкориснішими зазвичай є такі можливості:

- Підтримка **Regex** для пошуку форматів токенів, схем URL, назв небезпечних функцій або багаторядкових фрагментів.
- **Фільтри шляхів**, щоб одразу переходити до файлів із високою цінністю, таких як `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` або `nginx.conf`.
- **Фільтри мов**, щоб відокремити код застосунку від IaC і pipelines.
- **Пошук з урахуванням символів**, щоб перелічити handlers, auth middleware, webhook consumers, небезпечні helper functions або певні класи/методи.
- **Boolean operators** для зменшення шуму: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Пошук за revision/diff**, якщо він доступний, щоб відновлювати **видалені рядки**, відстежувати **зміни, пов'язані з безпекою**, або перевіряти **не-default гілки/теги** без попереднього клонування всього репозиторію.

## Практична методологія

1. **Почніть з indexed platforms**, щоб швидко визначити репозиторії, власників, шляхи та сімейства коду.
2. **Переходьте до locations із високою сигнальністю**, а не шукайте лише загальні рядки `password`/`secret`.
3. **Шукайте attack surface, а не лише credentials**:
- CI/CD workflows, reusable workflows, composite actions і deployment scripts
- Файли bootstrap для Dev Containers / Codespaces та custom features
- Маніфести Terraform/Helm/Kubernetes
- Інтеграції SSO/OIDC/SAML
- Внутрішні URL, staging hosts, admin panels, message brokers і callback endpoints
- Небезпечні code paths (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders тощо)
4. **Клонуйте та шукайте локально**, коли потрібні не-default гілки, повна history, краща підтримка regex або bulk automation.
5. **Переходьте до спеціалізованих scanners**, коли метою є secrets triage або verification (наприклад, див. спеціальну сторінку нижче).

### Ідеї запитів із високою сигнальністю

Вони навмисно сформульовані широко, щоб ви могли адаптувати їх до синтаксису GitHub, GitLab, Sourcegraph або Sourcebot:
```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "workflow_call" OR "secrets: inherit" OR "id-token: write" OR "self-hosted")
org:target path:.github/workflows ("uses:" AND NOT /@[0-9a-f]{40}/)
org:target (path:.devcontainer OR path:devcontainer.json) ("remoteEnv" OR "containerEnv" OR "initializeCommand" OR "postCreateCommand" OR "mounts")
org:target ("devcontainer-feature.json" OR "install.sh") ("curl " OR "wget " OR "docker.sock" OR "sudo ")
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```
### Нові файли з високою цінністю сигналу, яким варто надати пріоритет

- **`.github/workflows/*.yml`**: Перевірте привілейовані тригери `pull_request_target` і `workflow_run`, а також рядки сторонніх `uses:`, зафіксовані лише на тегах/гілках, а не на повних commit SHA.<sup>[[3]](#references)</sup> Також виконайте пошук `workflow_call`, `secrets: inherit`, `id-token: write` і `runs-on: self-hosted`.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** і **`.devcontainer.json`**: Виконайте пошук `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts`, а також пов’язаних Dockerfiles/скриптів, щоб виявити значення середовища, bootstrap-команди, монтування та пов’язані файли.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Перевірте обидва файли, оскільки мінімальна структура Feature містить метадані та entrypoint-скрипт `install.sh`.<sup>[[14]](#references)</sup>
- **Інші файли CI/control-plane**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Масовий локальний пошук, коли пошуку за індексом недостатньо
```bash
gh repo list TARGET_ORG --limit 1000 --json nameWithOwner,sshUrl \
| jq -r '.[].sshUrl' \
| while read -r repo; do
dst="repos/$(basename "$repo" .git)"
git clone --depth 1 "$repo" "$dst" 2>/dev/null || true
done

rg -n --pcre2 \
-g '!{.git,node_modules,vendor,dist,build,coverage}' \
'(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|AIza[0-9A-Za-z\-_]{35}|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY)' \
repos/
```
Використовуйте локальний пошук, коли потрібно:

- Шукати **не стандартні гілки** або **теги**
- Шукати **історію git**
- Агресивніше виконувати запити **PCRE2/multiline**
- Виконувати пакетний triage багатьох репозиторіїв без обмежень UI

### Явно шукайте історію, гілки та diff-и
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Це особливо корисно, коли цікавий рядок існував лише у **release branch**, **tag** або **deleted commit**. Якщо ваше розгортання Sourcegraph це підтримує, пошукові запити `type:diff` і `type:commit` є чудовим способом виконати no-clone pivot для тієї самої проблеми.<sup>[[8]](#references)[[10]](#references)</sup>

## Поширені сліпі зони

- **Індексація лише default branch** є поширеною. Не припускайте, що code search охоплює всі branch/tag/history.
- **Великі файли, vendored code, generated code або archives** можуть пропускатися або створювати багато шуму.
- **Коментарі, issues, PRs, gists і wikis** часто не входять до області generic code search і можуть вимагати platform-specific tooling.
- **Конфігурації Codespaces / devcontainer можуть бути специфічними для branch**. Вони можуть знаходитися в кількох шляхах `.devcontainer/<variant>/devcontainer.json`, тому чистий default branch не означає, що dev environment всюди чисте.<sup>[[4]](#references)</sup>
- **Reusable workflows/actions і devcontainer features можуть знаходитися не в очевидному файлі**. Шукайте `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` і `install.sh`, а не лише workflow file у корені.
- **Синтаксис пошуку відрізняється на різних платформах**. Dork, який працює в GitHub Code Search, може потребувати незначних змін для GitLab, Sourcegraph або Sourcebot.

### Особливості окремих платформ

- **GitHub Code Search** корисний для швидкого recon, але шукає лише **default branch**. Якщо вам потрібні feature branches, deleted secrets або historical code, клонуйте repo і шукайте в ньому локально.<sup>[[15]](#references)</sup>
- **GitLab Exact Code Search** має обмеження **default branch** і індексує лише файли розміром до 1 MB, що містять менше ніж 20 000 trigrams.<sup>[[2]](#references)</sup> **Advanced Search** все ще може охоплювати comments, commits і wikis.<sup>[[11]](#references)</sup>
- **Sourcebot** за замовчуванням індексує **default branch**, але його можна налаштувати для індексації додаткових branches/tags, після чого виконувати пошук із фільтрами `rev:`, якщо ви контролюєте index.<sup>[[7]](#references)</sup>
- **Sourcegraph** підтримує regex, symbol, diff і commit queries; використовуйте structural search лише там, де його увімкнено, і враховуйте задокументовані обмеження продуктивності.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> Коли ви шукаєте leaks у repo і запускаєте щось на кшталт `git log -p`, не забувайте, що можуть існувати **інші branches з іншими commits**, які містять secrets!

Для спеціалізованого secret hunting, GitHub dorks на рівні всієї org і таких інструментів, як TruffleHog/Gitleaks, перегляньте [сторінку GitHub leaked secrets](github-leaked-secrets.md).

## References

- [1] [Синтаксис GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [Довідник безпечного використання GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Довідник метаданих Dev Container](https://containers.dev/implementors/json_reference/)
- [5] [Sourcebot](https://www.sourcebot.dev/)
- [6] [API пошуку Sourcebot](https://docs.sourcebot.dev/api-reference/search-%26-navigation/search-code)
- [7] [Багатогілкова індексація Sourcebot](https://docs.sourcebot.dev/docs/features/search/multi-branch-indexing)
- [8] [Sourcegraph Code Search](https://sourcegraph.com/docs/code-search)
- [9] [Sourcegraph Structural Search](https://sourcegraph.com/docs/code-search/types/structural)
- [10] [Синтаксис пошукових запитів Sourcegraph](https://sourcegraph.com/docs/code-search/queries)
- [11] [GitLab Advanced Search](https://docs.gitlab.com/user/search/advanced_search/)
- [12] [SearchCode](https://searchcode.com/)
- [13] [Grep.app](https://grep.app/)
- [14] [Створення Dev Container Feature](https://containers.dev/guide/author-a-feature)
- [15] [Інструменти розслідування інцидентів безпеки](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-tools)
{{#include ../../banners/hacktricks-training.md}}
