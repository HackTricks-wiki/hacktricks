# Recherche étendue de code source

{{#include ../../banners/hacktricks-training.md}}

L’objectif de cette page est d’énumérer les **plateformes permettant de rechercher du code** (littéral, regex, sensible aux symboles ou limité par chemin) à travers **des milliers/millions de repos**.

Cela est utile pour :

- **Rechercher des informations leak**
- **Rechercher des patterns vulnérables**
- **Cartographier les technologies, les hôtes internes, le CI/CD et l’infrastructure as code**
- **Effectuer un pivot depuis le nom d’une entreprise/organisation vers les repos, branches et fichiers à forte valeur**

- [**Sourcebot**](https://www.sourcebot.dev/) : moteur de recherche de code open source/self-hosted. Très utile lorsque vous souhaitez indexer **de nombreux repos** et, si configuré, des branches/tags supplémentaires, tout en conservant des filtres regex tels que `repo:`, `file:`, `lang:`, `rev:` et `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search) : recherche dans des millions de repos. La regex est généralement l’option la plus sûre ; la recherche structurelle existe dans certains déploiements, mais elle présente des limitations de performance et n’est pas toujours activée.
- [**GitHub Code Search**](https://github.com/search) : prend en charge la regex, la logique booléenne et des qualifiers tels que `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` et `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/) : recherche de code GitLab moderne basée sur Zoekt. Prend en charge les modes exact et regex avec des filtres tels que `file:`, `lang:`, `repo:` et `sym:`.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) reste utile comme solution de repli plus large, car il peut rechercher dans le code, les commentaires, les commits, les merge requests et les wikis.
- [**SearchCode**](https://searchcode.com/) : recherche du code dans des millions de projets.
- [**Grep**](https://grep.app/) : recherche publique rapide dans un très vaste corpus GitHub. Utile lorsque vous souhaitez disposer d’une seconde vue d’indexation/classement pour effectuer des pivots sur le **contenu**, les **fichiers** et les **chemins**.

## Fonctionnalités de recherche utiles

Lors de l’audit d’une organisation dans un contexte de bug bounty/red team, les fonctionnalités les plus utiles sont généralement :

- La prise en charge de la **regex** pour rechercher des formats de tokens, des schémas d’URL, des noms de fonctions dangereuses ou des fragments multilignes.
- Les **filtres de chemin** pour accéder directement à des fichiers à forte valeur tels que `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` ou `nginx.conf`.
- Les **filtres de langage** pour séparer le code applicatif de l’IaC et des pipelines.
- La **recherche sensible aux symboles** pour énumérer les handlers, les middlewares d’authentification, les consommateurs de webhooks, les fonctions helper dangereuses ou des classes/méthodes spécifiques.
- Les **opérateurs booléens** pour réduire le bruit : `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- La **recherche par révision/diff** lorsqu’elle est disponible, afin de récupérer des **chaînes supprimées**, de suivre les **modifications pertinentes pour la sécurité** ou d’inspecter des **branches/tags non par défaut** sans tout cloner au préalable.

## Méthodologie pratique

1. **Commencez par les plateformes indexées** afin d’identifier rapidement les repos, propriétaires, chemins et familles de code.
2. **Effectuez un pivot vers les emplacements à forte valeur** au lieu de rechercher uniquement des chaînes génériques telles que `password`/`secret`.
3. **Recherchez la surface d’attaque, pas uniquement les credentials** :
- Workflows CI/CD, workflows réutilisables, composite actions et scripts de déploiement
- Fichiers d’amorçage des Dev Containers / Codespaces et custom features
- Manifestes Terraform/Helm/Kubernetes
- Intégrations SSO/OIDC/SAML
- URLs internes, hôtes de staging, panneaux d’administration, message brokers et endpoints de callback
- Chemins de code dangereux (`exec`, rendu de templates, fetchers SSRF, désérialiseurs, extraction ZIP, chargeurs YAML, etc.)
4. **Clonez et recherchez localement** lorsque vous avez besoin de branches non par défaut, de l’historique complet, d’une meilleure prise en charge de la regex ou d’une automatisation en masse.
5. **Passez à des scanners dédiés** lorsque l’objectif est le triage ou la vérification de secrets (par exemple, consultez la page dédiée ci-dessous).

### Idées de requêtes à forte valeur

Elles sont volontairement larges afin que vous puissiez les adapter à la syntaxe de GitHub, GitLab, Sourcegraph ou Sourcebot :
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
### Fichiers plus récents à fort signal à prioriser

- **`.github/workflows/*.yml`** : Recherchez `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted` et les lignes `uses:` tierces qui sont épinglées uniquement sur des tags/branches plutôt que sur des SHA de commit complets.<sup>[[3]](#references)</sup>
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** et **`.devcontainer.json`** : Recherchez `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` ainsi que les Dockerfiles/scripts référencés. Ceux-ci exposent souvent des registres de packages internes, des URLs de bootstrap, des montages de l’hôte et des endpoints réservés aux développeurs.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`) : Très utiles pour trouver la logique d’installation spécifique à l’organisation qui s’exécute lors de la création de l’environnement.
- **Autres fichiers CI/control plane** : `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

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
Utilisez la recherche locale lorsque vous avez besoin de :

- Rechercher dans des **branches non par défaut** ou des **tags**
- Rechercher dans l’**historique git**
- Exécuter des requêtes **PCRE2/multiline** de manière plus intensive
- Effectuer le triage par lots de nombreux repositories sans les limites de l’UI

### Rechercher explicitement dans l’historique, les branches et les diffs
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
C'est particulièrement utile lorsque la chaîne intéressante n'existait que dans une **release branch**, un **tag** ou un **commit supprimé**. Si votre déploiement Sourcegraph le prend en charge, les recherches `type:diff` et `type:commit` constituent également un excellent pivot sans clone pour le même problème.

## Angles morts courants

- L'**indexation limitée à la default branch** est fréquente. Ne supposez pas que la recherche de code couvre toutes les branches/tags/l'historique.
- Les **fichiers volumineux, le code vendored, le code généré ou les archives** peuvent être ignorés ou produire trop de bruit.
- Les **commentaires, issues, PRs, gists et wikis** sont souvent hors du périmètre de la recherche de code générique et peuvent nécessiter des outils spécifiques à la plateforme.
- Les configurations **Codespaces / devcontainer peuvent être spécifiques à une branche** et se trouver dans plusieurs chemins `.devcontainer/<variant>/devcontainer.json` ; une default branch propre ne signifie donc pas que l'environnement de développement est propre partout.
- Les **workflows/actions réutilisables et les devcontainer features peuvent se trouver en dehors du fichier évident**. Recherchez dans `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` et `install.sh`, et pas uniquement dans le fichier workflow à la racine.
- La **syntaxe de recherche diffère selon la plateforme**. Un dork qui fonctionne dans GitHub Code Search peut nécessiter de petites modifications pour GitLab, Sourcegraph ou Sourcebot.

### Pièges spécifiques aux plateformes

- **GitHub Code Search** est excellent pour une recon rapide, mais il ne recherche que dans la **default branch**. Si vous avez besoin des feature branches, des secrets supprimés ou du code historique, clonez le repo et recherchez localement.
- **GitLab Exact Code Search** est également limité à la **default branch** et n'indexe que les fichiers plus petits, mais **Advanced Search** peut tout de même être utile pour rechercher dans les commentaires, les commits et les wikis.<sup>[[2]](#references)</sup>
- **Sourcebot** indexe la **default branch** par défaut, mais peut être configuré pour indexer des branches/tags supplémentaires, puis effectuer des recherches avec des filtres `rev:` ; c'est très pratique pour les audits internes ciblant une branche ou un tag lorsque vous contrôlez l'index.
- La recherche regex de **Sourcegraph** est généralement l'option la plus prévisible pour le travail offensif ; considérez la recherche structurelle comme un bonus facultatif, et non comme une fonctionnalité garantie. Si le déploiement la prend en charge, les requêtes `type:diff` et `type:commit` sont très efficaces pour récupérer des chaînes supprimées ou des modifications récentes liées à la sécurité.

> [!WARNING]
> Lorsque vous recherchez des leaks dans un repo et exécutez une commande comme `git log -p`, n'oubliez pas qu'il peut exister **d'autres branches contenant d'autres commits** avec des secrets !

Pour la recherche dédiée de secrets, les dorks GitHub à l'échelle d'une organisation et les outils tels que TruffleHog/Gitleaks, consultez :

{{#ref}}
github-leaked-secrets.md
{{#endref}}

## Références

- [1] [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)

{{#include ../../banners/hacktricks-training.md}}
