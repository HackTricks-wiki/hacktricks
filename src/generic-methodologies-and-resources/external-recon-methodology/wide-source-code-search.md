# Широкий пошук вихідного коду

{{#include ../../banners/hacktricks-training.md}}

Мета цієї сторінки — перелічити **платформи, які дають змогу шукати код** (за літеральним збігом, regex, символами або шляхами) у **тисячах/мільйонах репозиторіїв**.

Це корисно для:

- **Пошуку leaked information**
- **Пошуку вразливих шаблонів**
- **Мапування технологій, внутрішніх хостів, CI/CD та infrastructure-as-code**
- **Переходу від назви компанії/організації до репозиторіїв, гілок і файлів із високим рівнем сигналу**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted пошук коду. Дуже корисний, коли потрібно індексувати **багато репозиторіїв** і, за додаткового налаштування, інші гілки/теги, зберігаючи regex-фільтри, як-от `repo:`, `file:`, `lang:`, `rev:` і `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): Пошук у мільйонах репозиторіїв. Regex зазвичай є найбезпечнішим варіантом; structural search доступний у деяких розгортаннях, але має обмеження продуктивності й не завжди увімкнений.
- [**GitHub Code Search**](https://github.com/search): Підтримує regex, boolean logic і qualifiers, як-от `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` та `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Сучасний пошук коду GitLab на основі Zoekt. Підтримує режими exact і regex з фільтрами, як-от `file:`, `lang:`, `repo:` та `sym:`.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) досі корисний як ширший fallback, оскільки дає змогу шукати в коді, коментарях, комітах, merge requests і wikis.
- [**SearchCode**](https://searchcode.com/): Пошук коду в мільйонах проєктів.
- [**Grep**](https://grep.app/): Швидкий публічний пошук у дуже великому корпусі GitHub. Корисний, коли потрібне додаткове представлення індексації/ранжування для переходів за **content**, **file** і **path**.

## Корисні можливості пошуку

Під час аудиту організації в контексті bug bounty/red team зазвичай найкориснішими є такі можливості:

- Підтримка **Regex** для пошуку форматів токенів, схем URL, назв небезпечних функцій або багаторядкових фрагментів.
- **Фільтри шляхів** для безпосереднього переходу до цінних файлів, як-от `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` або `nginx.conf`.
- **Фільтри мов** для відокремлення коду застосунків від IaC і pipeline.
- **Пошук із підтримкою символів** для переліку handlers, auth middleware, webhook consumers, небезпечних helper-функцій або конкретних класів/методів.
- **Boolean operators** для зменшення шуму: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Пошук за revision/diff**, якщо він доступний, щоб відновлювати **видалені рядки**, відстежувати **зміни, пов’язані з безпекою**, або перевіряти **нестандатрні гілки/теги**, не клонуючи все заздалегідь.

## Практична методологія

1. **Почніть з індексованих платформ**, щоб швидко визначити репозиторії, власників, шляхи та групи коду.
2. **Переходьте до місць із високим рівнем сигналу**, а не шукайте лише загальні рядки `password`/`secret`.
3. **Шукайте attack surface, а не лише credentials**:
- CI/CD workflows, reusable workflows, composite actions і deployment scripts
- Файли початкового налаштування Dev Containers / Codespaces і custom features
- Маніфести Terraform/Helm/Kubernetes
- Інтеграції SSO/OIDC/SAML
- Внутрішні URL, staging-хости, admin panels, message brokers і callback endpoints
- Небезпечні ділянки коду (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders тощо)
4. **Клонуйте та шукайте локально**, коли потрібні не стандартні гілки, повна історія, краща підтримка regex або bulk automation.
5. **Переходьте до спеціалізованих сканерів**, коли метою є triage або verification secrets (наприклад, див. спеціальну сторінку нижче).

### Ідеї запитів із високим рівнем сигналу

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

- **`.github/workflows/*.yml`**: Шукайте `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted` і рядки сторонніх `uses:`, закріплені лише за тегами/гілками, а не за повними commit SHA.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** і **`.devcontainer.json`**: Шукайте `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts`, а також Dockerfiles/скрипти, на які є посилання. Вони часто розкривають внутрішні package registries, bootstrap URLs, host mounts і endpoints, призначені лише для розробників.
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Чудове джерело для пошуку специфічної для організації installer logic, яка виконується під час створення середовища.
- **Інші файли CI/control-plane**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

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

- Шукати в **гілках** або **тегах, відмінних від стандартних**
- Шукати в **історії git**
- Агресивніше виконувати запити **PCRE2/multiline**
- Виконувати пакетне сортування багатьох репозиторіїв без обмежень UI

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
Це особливо корисно, коли цікавий рядок існував лише у **release branch**, **tag** або **deleted commit**. Якщо ваше розгортання Sourcegraph це підтримує, пошукові запити `type:diff` і `type:commit` є чудовим способом виконати pivot без клонування для тієї самої задачі.

## Поширені сліпі зони

- Часто індексується лише **default branch**. Не припускайте, що пошук коду охоплює всі branches/tags/history.
- **Великі файли, vendored code, generated code або archives** можуть пропускатися або створювати багато шуму.
- **Коментарі, issues, PRs, gists і wikis** часто перебувають поза межами generic code search і можуть вимагати platform-specific tooling.
- Конфігурації **Codespaces / devcontainer** можуть бути специфічними для branch і зберігатися в кількох шляхах `.devcontainer/<variant>/devcontainer.json`, тому чистий default branch не означає, що dev environment всюди чисте.
- **Reusable workflows/actions і devcontainer features** можуть знаходитися не в очевидному файлі. Шукайте `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` та `install.sh`, а не лише у workflow file верхнього рівня.
- **Синтаксис пошуку відрізняється залежно від платформи**. Dork, який працює в GitHub Code Search, може потребувати незначних змін для GitLab, Sourcegraph або Sourcebot.

### Platform-specific gotchas

- **GitHub Code Search** чудово підходить для швидкого recon, але шукає лише **default branch**. Якщо потрібні feature branches, deleted secrets або historical code, клонуйте repo і виконуйте пошук локально.
- **GitLab Exact Code Search** також має обмеження **default-branch** і індексує лише менші файли, але **Advanced Search** все одно може бути корисним для пошуку в comments, commits і wikis.
- **Sourcebot** за замовчуванням індексує **default branch**, але його можна налаштувати для індексації додаткових branches/tags, після чого виконувати пошук із фільтрами `rev:`. Це дуже зручно для branch/tag-focused internal audits, коли ви контролюєте index.
- Regex search у **Sourcegraph** загалом є найбільш передбачуваним варіантом для offensive work; сприймайте structural search як необов'язковий bonus, а не гарантовану можливість. Якщо розгортання це підтримує, запити `type:diff` і `type:commit` дуже добре підходять для відновлення deleted strings або нещодавніх security-relevant changes.

> [!WARNING]
> Коли ви шукаєте leaks у repo і виконуєте щось на кшталт `git log -p`, не забувайте, що можуть існувати **інші branches з іншими commits**, які містять secrets!

Щодо dedicated secret hunting, org-wide GitHub dorks і таких інструментів, як TruffleHog/Gitleaks, дивіться:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [Синтаксис GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [Довідник із безпечного використання GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [Довідник із метаданих Dev Container](https://containers.dev/implementors/json_reference/)
{{#include ../../banners/hacktricks-training.md}}
