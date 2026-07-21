# Recherche étendue de code source

{{#include ../../banners/hacktricks-training.md}}

L’objectif de cette page est d’énumérer les **plateformes qui permettent de rechercher du code** (littéral, par regex, sensible aux symboles ou limité à des chemins) dans **des milliers ou des millions de repos**.

Cela est utile pour :

- **Rechercher des informations leakées**
- **Rechercher des patterns vulnérables**
- **Cartographier les technologies, les hosts internes, le CI/CD et l’infrastructure-as-code**
- **Effectuer un pivot depuis le nom d’une entreprise/organisation vers les repos, les branches et les fichiers à fort signal**

- [**Sourcebot**](https://www.sourcebot.dev/) : outil open source/self-hosted de recherche de code. Très utile lorsque vous souhaitez indexer **de nombreux repos** et, s’il est configuré ainsi, des branches/tags supplémentaires, tout en conservant des filtres regex tels que `repo:`, `file:`, `lang:`, `rev:` et `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search) : recherche dans des millions de repos. Les regex constituent généralement l’option la plus sûre ; la recherche structurelle existe dans certains déploiements, mais elle présente des limitations de performance et n’est pas toujours activée.
- [**GitHub Code Search**](https://github.com/search) : prend en charge les regex, la logique booléenne et des qualifiers tels que `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` et `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/) : recherche de code moderne de GitLab, basée sur Zoekt. Prend en charge les modes exact et regex avec des filtres tels que `file:`, `lang:`, `repo:` et `sym:`.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) reste utile comme solution de repli plus large, car elle permet de rechercher dans le code, les commentaires, les commits, les merge requests et les wikis.
- [**SearchCode**](https://searchcode.com/) : recherche de code dans des millions de projets.
- [**Grep**](https://grep.app/) : recherche publique rapide dans un très vaste corpus GitHub. Utile lorsque vous souhaitez disposer d’une seconde vue d’indexation/classement pour effectuer des pivots sur le **contenu**, les **fichiers** et les **chemins**.

## Fonctionnalités de recherche utiles

Lors de l’audit d’une organisation dans un contexte de bug bounty/red team, les fonctionnalités les plus utiles sont généralement :

- La prise en charge des **regex** pour rechercher des formats de tokens, des schémas d’URL, des noms de fonctions dangereuses ou des fragments multilignes.
- Les **filtres de chemin** pour accéder directement aux fichiers à forte valeur tels que `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` ou `nginx.conf`.
- Les **filtres de langage** pour séparer le code applicatif de l’IaC et des pipelines.
- La recherche **sensible aux symboles** pour énumérer les handlers, les middleware d’authentification, les consommateurs de webhooks, les fonctions helper dangereuses ou des classes/méthodes spécifiques.
- Les **opérateurs booléens** pour réduire le bruit : `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- La recherche par **révision/diff** lorsqu’elle est disponible, afin de récupérer des **chaînes supprimées**, de suivre les **modifications liées à la sécurité** ou d’inspecter des **branches/tags non par défaut** sans tout cloner au préalable.

## Méthodologie pratique

1. **Commencez par les plateformes indexées** afin d’identifier rapidement les repos, les propriétaires, les chemins et les familles de code.
2. **Effectuez un pivot vers les emplacements à fort signal** au lieu de rechercher uniquement des chaînes génériques telles que `password`/`secret`.
3. **Recherchez la surface d’attaque, et pas uniquement les credentials** :
- Workflows CI/CD, reusable workflows, composite actions et scripts de déploiement
- Fichiers d’amorçage des Dev Containers / Codespaces et custom features
- Manifestes Terraform/Helm/Kubernetes
- Intégrations SSO/OIDC/SAML
- URLs internes, hosts de staging, panneaux d’administration, brokers de messages et endpoints de callback
- Chemins de code dangereux (`exec`, rendu de templates, fetchers SSRF, désérialiseurs, extraction ZIP, chargeurs YAML, etc.)
4. **Clonez et recherchez localement** lorsque vous avez besoin de branches non par défaut, de l’historique complet, d’une meilleure prise en charge des regex ou d’une automatisation en masse.
5. **Passez à des scanners dédiés** lorsque l’objectif est le triage ou la vérification de secrets (voir, par exemple, la page dédiée ci-dessous).

### Idées de requêtes à fort signal

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
### Fichiers plus récents à forte valeur de signal à prioriser

- **`.github/workflows/*.yml`** : Recherchez `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted` ainsi que les lignes `uses:` de fournisseurs tiers qui sont uniquement épinglées sur des tags/branches au lieu de l'être sur des commit SHAs complets.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** et **`.devcontainer.json`** : Recherchez `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` ainsi que les Dockerfiles/scripts référencés. Ceux-ci exposent souvent des registres de packages internes, des URLs de bootstrap, des mounts de l'hôte et des endpoints réservés aux développeurs.
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`) : Très utiles pour trouver la logique d'installation spécifique à l'organisation qui s'exécute lors de la création de l'environnement.
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

- Rechercher dans des **branches non par défaut** ou des **tags**
- Rechercher dans l’**historique Git**
- Exécuter plus intensivement des requêtes **PCRE2/multiline**
- Effectuer le triage par lots de nombreux dépôts sans les limites de l’interface

### Rechercher explicitement dans l’historique, les branches et les différences
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Ceci est particulièrement utile lorsque la chaîne intéressante n'existait que dans une **release branch**, un **tag** ou un **commit supprimé**. Si votre déploiement Sourcegraph le permet, les recherches `type:diff` et `type:commit` constituent un excellent pivot sans clone pour le même problème.

## Angles morts courants

- L'**indexation limitée à la default branch** est courante. Ne supposez pas que la recherche de code couvre toutes les branches/tags/l'historique.
- Les **fichiers volumineux, le code vendored, le code généré ou les archives** peuvent être ignorés ou produire trop de bruit.
- Les **commentaires, issues, PRs, gists et wikis** sont souvent hors du périmètre de la recherche de code générique et peuvent nécessiter des outils spécifiques à la plateforme.
- Les configurations **Codespaces / devcontainer peuvent être spécifiques à une branche** et se trouver dans plusieurs chemins `.devcontainer/<variant>/devcontainer.json`. Une default branch propre ne signifie donc pas que l'environnement de développement est propre partout.
- Les **workflows/actions réutilisables et les features devcontainer peuvent se trouver ailleurs que dans le fichier évident**. Recherchez dans `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` et `install.sh`, et pas seulement dans le fichier workflow de niveau supérieur.
- La **syntaxe de recherche diffère selon la plateforme**. Un dork qui fonctionne dans GitHub Code Search peut nécessiter de petites modifications pour GitLab, Sourcegraph ou Sourcebot.

### Pièges spécifiques aux plateformes

- **GitHub Code Search** est excellent pour une recon rapide, mais il ne recherche que la **default branch**. Si vous avez besoin des feature branches, de secrets supprimés ou de code historique, clonez le repo et effectuez la recherche localement.
- **GitLab Exact Code Search** est également limité à la **default branch** et n'indexe que les fichiers de petite taille, mais **Advanced Search** peut tout de même être utile pour rechercher dans les commentaires, les commits et les wikis.
- **Sourcebot** indexe la **default branch** par défaut, mais peut être configuré pour indexer des branches/tags supplémentaires, puis effectuer des recherches avec des filtres `rev:`. C'est très pratique pour les audits internes ciblant des branches/tags lorsque vous contrôlez l'index.
- La recherche regex de **Sourcegraph** est généralement l'option la plus prévisible pour les opérations offensives ; considérez la recherche structurelle comme un bonus facultatif, et non comme une fonctionnalité garantie. Si le déploiement la prend en charge, les requêtes `type:diff` et `type:commit` sont très efficaces pour récupérer des chaînes supprimées ou des changements récents liés à la sécurité.

> [!WARNING]
> Lorsque vous recherchez des leaks dans un repo et exécutez une commande telle que `git log -p`, n'oubliez pas qu'il peut y avoir **d'autres branches avec d'autres commits** contenant des secrets !

Pour la recherche dédiée de secrets, les dorks GitHub à l'échelle de l'organisation et les outils tels que TruffleHog/Gitleaks, consultez :

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## Références

- [Syntaxe de GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [Référence sur l'utilisation sécurisée de GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [Référence des métadonnées Dev Container](https://containers.dev/implementors/json_reference/)
{{#include ../../banners/hacktricks-training.md}}
