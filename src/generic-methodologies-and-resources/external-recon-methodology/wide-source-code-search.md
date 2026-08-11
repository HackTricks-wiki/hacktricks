# Recherche étendue de code source

{{#include ../../banners/hacktricks-training.md}}

L’objectif de cette page est d’énumérer les **plateformes qui permettent de rechercher du code** (littéral, regex, sensible aux symboles ou limité à certains chemins) dans **des milliers ou des millions de repos**.

C’est utile pour :

- **Rechercher des informations leakées**
- **Rechercher des patterns vulnérables**
- **Cartographier les technologies, les hôtes internes, le CI/CD et l’infrastructure-as-code**
- **Pivoter depuis le nom d’une entreprise ou d’une organisation vers les repos, les branches et les fichiers à forte valeur**

- [**Sourcebot**](https://www.sourcebot.dev/) : service de recherche de code open source/self-hosted avec recherche regex, par symboles et filtrée dans les repos. Configurez des branches/tags supplémentaires et interrogez-les avec `rev:` lorsque la couverture des branches est importante.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search) : recherche de code avec des requêtes regex, booléennes, par symbole, repo/fichier/langage, branche/commit, diff et message de commit.<sup>[[8]](#references)[[10]](#references)</sup> La recherche structurelle est optionnelle, car la documentation actuelle indique qu’elle est désactivée par défaut et limitée en termes de performances.<sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search) : prend en charge les regex, la logique booléenne et des qualifiers tels que `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` et `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/) : recherche de code basée sur Zoekt, avec des modes exact et regex, ainsi que des filtres tels que `file:`, `lang:`, `repo:` et `sym:`.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) constitue une solution de repli plus large, car elle peut rechercher dans le code, les commentaires, les commits, les merge requests et les wikis.<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/) : service de code-intelligence avec recherche de code booléenne/regex/structurelle, ainsi que récupération de fichiers et de symboles.<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/) : recherche publique de code dans un million de repos GitHub, avec recherche dans le contenu, les fichiers et les chemins.<sup>[[13]](#references)</sup>

## Fonctionnalités de recherche utiles

Lors de l’audit d’une organisation dans un contexte de bug bounty/red team, les fonctionnalités les plus utiles sont généralement :

- La prise en charge des **regex** pour rechercher des formats de tokens, des schémas d’URL, des noms de fonctions dangereuses ou des fragments multilignes.
- Les **filtres de chemin** pour accéder directement aux fichiers à forte valeur tels que `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` ou `nginx.conf`.
- Les **filtres de langage** pour séparer le code applicatif de l’IaC et des pipelines.
- La **recherche sensible aux symboles** pour énumérer les handlers, les middleware d’authentification, les consommateurs de webhooks, les fonctions utilitaires dangereuses ou des classes/méthodes spécifiques.
- Les **opérateurs booléens** pour réduire le bruit : `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- La **recherche dans les révisions/diffs** lorsqu’elle est disponible, afin de retrouver des **chaînes supprimées**, de suivre des **modifications pertinentes pour la sécurité** ou d’inspecter des **branches/tags non par défaut** sans tout cloner au préalable.

## Méthodologie pratique

1. **Commencez par les plateformes indexées** afin d’identifier rapidement les repos, propriétaires, chemins et familles de code.
2. **Pivotez vers les emplacements à forte valeur** au lieu de rechercher uniquement des chaînes génériques `password`/`secret`.
3. **Recherchez la surface d’attaque, pas uniquement les credentials** :
- Workflows CI/CD, workflows réutilisables, composite actions et scripts de déploiement
- Fichiers d’amorçage des Dev Containers / Codespaces et custom features
- Manifests Terraform/Helm/Kubernetes
- Intégrations SSO/OIDC/SAML
- URL internes, hôtes de staging, panneaux d’administration, brokers de messages et endpoints de callback
- Chemins de code dangereux (`exec`, rendu de templates, fetchers SSRF, désérialiseurs, extraction ZIP, chargeurs YAML, etc.)
4. **Clonez et recherchez localement** lorsque vous avez besoin de branches non par défaut, de l’historique complet, d’une meilleure prise en charge des regex ou d’une automatisation en masse.
5. **Passez à des scanners dédiés** lorsque l’objectif est le triage ou la vérification de secrets (voir, par exemple, la page dédiée ci-dessous).

### Idées de requêtes à forte valeur

Elles sont volontairement générales afin que vous puissiez les adapter à la syntaxe de GitHub, GitLab, Sourcegraph ou Sourcebot :
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
### Nouveaux fichiers à forte valeur à prioriser

- **`.github/workflows/*.yml`** : Examinez les déclencheurs privilégiés `pull_request_target` et `workflow_run`, ainsi que les lignes tierces `uses:` épinglées uniquement à des tags/branches plutôt qu'à des commit SHAs complets.<sup>[[3]](#references)</sup> Recherchez également `workflow_call`, `secrets: inherit`, `id-token: write` et `runs-on: self-hosted`.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** et **`.devcontainer.json`** : Recherchez `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts`, ainsi que les Dockerfiles/scripts référencés, afin de découvrir les valeurs d'environnement, les commandes d'initialisation, les montages et les fichiers associés.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`) : Examinez les deux fichiers, car la structure minimale d'une Feature inclut des métadonnées et un script d'entrée `install.sh`.<sup>[[14]](#references)</sup>
- **Autres fichiers CI/control-plane** : `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Recherche locale massive lorsque la recherche indexée ne suffit pas
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
Utilisez la recherche locale lorsque vous devez :

- Rechercher dans les **non-default branches** ou les **tags**
- Rechercher dans l'historique de **git**
- Exécuter des requêtes **PCRE2/multiline** de manière plus intensive
- Effectuer le triage par lots de nombreux repositories sans les limites de l'UI

### Rechercher explicitement dans l'historique, les branches et les diffs
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Cela est particulièrement utile lorsque la chaîne intéressante n'existait que dans une **release branch**, un **tag** ou un **commit supprimé**. Si votre déploiement Sourcegraph le prend en charge, les recherches `type:diff` et `type:commit` constituent une excellente alternative sans clone pour le même problème.<sup>[[8]](#references)[[10]](#references)</sup>

## Angles morts courants

- **L'indexation limitée à la branche par défaut** est courante. Ne supposez pas que la recherche de code couvre toutes les branches/tags et tout l'historique.
- **Les fichiers volumineux, le code vendored, le code généré ou les archives** peuvent être ignorés ou produire trop de bruit.
- **Les commentaires, issues, PRs, gists et wikis** sont souvent hors du périmètre de la recherche de code générique et peuvent nécessiter des outils spécifiques à la plateforme.
- **Les configurations Codespaces / devcontainer peuvent être spécifiques à une branche**. Elles peuvent se trouver dans plusieurs chemins `.devcontainer/<variant>/devcontainer.json`, donc une branche par défaut propre ne signifie pas que l'environnement de développement est propre partout.<sup>[[4]](#references)</sup>
- **Les reusable workflows/actions et les devcontainer features peuvent se trouver ailleurs que dans le fichier évident**. Recherchez `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` et `install.sh`, et pas seulement le fichier workflow de niveau supérieur.
- **La syntaxe de recherche diffère selon la plateforme**. Un dork qui fonctionne dans GitHub Code Search peut nécessiter de petites modifications pour GitLab, Sourcegraph ou Sourcebot.

### Pièges spécifiques aux plateformes

- **GitHub Code Search** est utile pour une recon rapide, mais il recherche uniquement la **branche par défaut**. Si vous avez besoin des feature branches, des secrets supprimés ou du code historique, clonez le repo et recherchez-y localement.<sup>[[15]](#references)</sup>
- **GitLab Exact Code Search** est limité à la **branche par défaut** et n'indexe que les fichiers de moins de 1 Mo contenant moins de 20 000 trigrammes.<sup>[[2]](#references)</sup> **Advanced Search** peut tout de même couvrir les commentaires, commits et wikis.<sup>[[11]](#references)</sup>
- **Sourcebot** indexe par défaut la **branche par défaut**, mais peut être configuré pour indexer des branches/tags supplémentaires, puis effectuer des recherches avec des filtres `rev:` lorsque vous contrôlez l'index.<sup>[[7]](#references)</sup>
- **Sourcegraph** prend en charge les requêtes regex, symbol, diff et commit ; utilisez la recherche structurelle uniquement lorsqu'elle est activée et tenez compte de ses limites de performances documentées.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> Lorsque vous recherchez des leaks dans un repo et exécutez quelque chose comme `git log -p`, n'oubliez pas qu'il peut y avoir **d'autres branches avec d'autres commits** contenant des secrets !

Pour la recherche dédiée de secrets, les dorks GitHub à l'échelle d'une organisation et les outils tels que TruffleHog/Gitleaks, consultez [la page GitHub sur les secrets leaked](github-leaked-secrets.md).

## References

- [1] [Syntaxe de GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [Référence sur l'utilisation sécurisée de GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Référence des métadonnées Dev Container](https://containers.dev/implementors/json_reference/)
- [5] [Sourcebot](https://www.sourcebot.dev/)
- [6] [API de recherche Sourcebot](https://docs.sourcebot.dev/api-reference/search-%26-navigation/search-code)
- [7] [Indexation multi-branches de Sourcebot](https://docs.sourcebot.dev/docs/features/search/multi-branch-indexing)
- [8] [Sourcegraph Code Search](https://sourcegraph.com/docs/code-search)
- [9] [Sourcegraph Structural Search](https://sourcegraph.com/docs/code-search/types/structural)
- [10] [Syntaxe des requêtes de recherche Sourcegraph](https://sourcegraph.com/docs/code-search/queries)
- [11] [GitLab Advanced Search](https://docs.gitlab.com/user/search/advanced_search/)
- [12] [SearchCode](https://searchcode.com/)
- [13] [Grep.app](https://grep.app/)
- [14] [Création d'une Dev Container Feature](https://containers.dev/guide/author-a-feature)
- [15] [Outils d'investigation pour les incidents de sécurité](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-tools)
{{#include ../../banners/hacktricks-training.md}}
