# Широкий пошук вихідного коду

{{#include ../../banners/hacktricks-training.md}}

Мета цієї сторінки — перелічити **платформи, які дають змогу шукати код** (літерально, за regex, з урахуванням символів або в межах шляхів) у **тисячах/мільйонах repo**.

Це корисно для:

- **Пошуку витоку інформації**
- **Пошуку вразливих шаблонів**
- **Картографування технологій, внутрішніх хостів, CI/CD та infrastructure-as-code**
- **Переходу від назви компанії/org до repo, гілок і файлів із високою сигнальністю**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted пошук коду. Дуже корисний, коли потрібно індексувати **багато repo** і, за умови налаштування, додаткові гілки/теги, зберігаючи regex-фільтри, такі як `repo:`, `file:`, `lang:`, `rev:` і `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): Пошук у мільйонах repo. Regex зазвичай є найбезпечнішим варіантом; structural search доступний у деяких deployment, але має обмеження продуктивності й не завжди ввімкнений.
- [**GitHub Code Search**](https://github.com/search): Підтримує regex, булеву логіку та qualifiers, такі як `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` і `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Сучасний пошук коду в GitLab на базі Zoekt. Підтримує режими exact і regex з фільтрами, такими як `file:`, `lang:`, `repo:` і `sym:`.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) усе ще корисний як ширший fallback, оскільки дає змогу шукати код, коментарі, commit, merge request і wiki.
- [**SearchCode**](https://searchcode.com/): Пошук коду в мільйонах проєктів.
- [**Grep**](https://grep.app/): Швидкий public search у дуже великому GitHub corpus. Корисний, коли потрібен альтернативний погляд на індексацію/ranking для переходів за **content**, **file** і **path**.

## Корисні можливості пошуку

Під час аудиту org у контексті bug bounty/red team найкориснішими можливостями зазвичай є:

- Підтримка **Regex** для пошуку форматів token, схем URL, назв небезпечних функцій або багаторядкових фрагментів.
- **Path filters** для безпосереднього переходу до цінних файлів, таких як `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` або `nginx.conf`.
- **Language filters** для відокремлення app code від IaC і pipeline.
- **Symbol-aware search** для переліку handler, auth middleware, webhook consumer, небезпечних helper-функцій або конкретних class/method.
- **Boolean operators** для зменшення шуму: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Revision/diff search**, якщо доступний, щоб відновлювати **видалені рядки**, відстежувати **зміни, пов’язані з безпекою**, або перевіряти **неосновні гілки/теги** без попереднього клонування всього.

## Практична методологія

1. **Почніть з індексованих платформ**, щоб швидко визначити repo, власників, шляхи та сімейства коду.
2. **Переходьте до місць із високою сигнальністю**, замість пошуку лише за загальними рядками `password`/`secret`.
3. **Шукайте attack surface, а не лише credentials**:
- CI/CD workflow, reusable workflow, composite action і deployment script
- Bootstrap-файли Dev Containers / Codespaces і custom features
- Маніфести Terraform/Helm/Kubernetes
- Інтеграції SSO/OIDC/SAML
- Внутрішні URL, staging host, admin panel, message broker і callback endpoint
- Небезпечні code path (`exec`, template rendering, SSRF fetcher, deserializer, ZIP extraction, YAML loader тощо)
4. **Клонуйте та шукайте локально**, коли потрібні неосновні гілки, повна history, краща підтримка regex або bulk automation.
5. **Переходьте до спеціалізованих scanner**, коли метою є triage або verification секретів (наприклад, див. спеціальну сторінку нижче).

### Ідеї запитів із високою сигнальністю

Вони навмисно є широкими, щоб ви могли адаптувати їх до синтаксису GitHub, GitLab, Sourcegraph або Sourcebot:
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
### Нові файли з високою цінністю сигналів, яким варто надати пріоритет

- **`.github/workflows/*.yml`**: Шукайте `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted` і рядки сторонніх `uses:`, закріплені лише на тегах/гілках, а не на повних commit SHA.<sup>[[3]](#references)</sup>
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** і **`.devcontainer.json`**: Шукайте `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts`, а також згадані Dockerfiles/scripts. Вони часто розкривають внутрішні package registries, bootstrap URLs, host mounts і endpoints, призначені лише для розробників.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Чудове джерело для пошуку специфічної для організації installer logic, яка виконується під час створення середовища.
- **Інші CI/control-plane файли**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Масовий локальний пошук, коли indexed search недостатньо
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

- Шукати в **не стандартних гілках** або **тегах**
- Шукати в **історії git**
- Агресивніше виконувати запити **PCRE2/multiline**
- Виконувати пакетний первинний аналіз багатьох репозиторіїв без обмежень UI

### Явно шукайте в історії, гілках і diff'ах
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Це особливо корисно, коли цікавий рядок існував лише у **release branch**, **tag** або **deleted commit**. Якщо ваше розгортання Sourcegraph це підтримує, пошукові запити `type:diff` і `type:commit` є чудовим способом виконати pivot без клонування для тієї самої проблеми.

## Поширені сліпі зони

- Часто індексується **лише default branch**. Не припускайте, що пошук коду охоплює всі branches/tags/history.
- **Великі файли, vendored code, generated code або archives** можуть пропускатися або створювати багато шуму.
- **Comments, issues, PRs, gists і wikis** часто перебувають поза межами generic code search і можуть потребувати platform-specific tooling.
- Конфігурації **Codespaces / devcontainer** можуть бути специфічними для branch і міститися в кількох шляхах `.devcontainer/<variant>/devcontainer.json`, тому чистий default branch не означає, що dev environment всюди чисте.
- **Reusable workflows/actions і devcontainer features** можуть міститися не в очевидному файлі. Шукайте `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` та `install.sh`, а не лише workflow file у корені.
- **Search syntax відрізняється залежно від platform**. Dork, який працює в GitHub Code Search, може потребувати невеликих змін для GitLab, Sourcegraph або Sourcebot.

### Platform-specific gotchas

- **GitHub Code Search** чудово підходить для швидкого recon, але шукає лише **default branch**. Якщо вам потрібні feature branches, deleted secrets або historical code, клонуйте repo і шукайте локально.
- **GitLab Exact Code Search** також має обмеження **default-branch** і індексує лише менші файли, але **Advanced Search** усе ще може бути корисним для пошуку comments, commits і wikis.<sup>[[2]](#references)</sup>
- **Sourcebot** за замовчуванням індексує **default branch**, але його можна налаштувати для індексації додаткових branches/tags, після чого виконувати пошук за допомогою фільтрів `rev:`. Це дуже зручно для внутрішніх аудитів, зосереджених на branch/tag, коли ви контролюєте index.
- Regex search у **Sourcegraph** загалом є найбільш передбачуваним варіантом для offensive work; сприймайте structural search як додаткову можливість, а не як гарантовану функцію. Якщо deployment це підтримує, запити `type:diff` і `type:commit` дуже добре підходять для відновлення deleted strings або нещодавніх security-relevant changes.

> [!WARNING]
> Коли ви шукаєте leaks у repo і виконуєте щось на кшталт `git log -p`, не забувайте, що можуть існувати **інші branches з іншими commits**, які містять secrets!

Щоб виконувати спеціалізований пошук секретів, використовувати org-wide GitHub dorks та інструменти на кшталт TruffleHog/Gitleaks, перегляньте:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

## References

- [1] [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)

{{#include ../../banners/hacktricks-training.md}}
