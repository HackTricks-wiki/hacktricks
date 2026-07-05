# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

Le but de cette page est d'énumérer les **platforms qui permettent de rechercher du code** (littéral, regex, sensible aux symboles, ou limité par chemin) à travers **des milliers/des millions de repos**.

C'est utile pour :

- **Rechercher des informations leak**
- **Rechercher des patterns vulnérables**
- **Cartographier les technologies, hôtes internes, CI/CD, et infrastructure-as-code**
- **Pivoter depuis un nom d'entreprise/d'organisation vers des repos, branches, et fichiers à fort signal**

- [**Sourcebot**](https://www.sourcebot.dev/) : recherche de code open-source/self-hosted. Très utile lorsque vous voulez indexer **de nombreux repos** et, si configuré, des branches/tags supplémentaires tout en conservant des filtres regex tels que `repo:`, `file:`, `lang:`, `rev:` et `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search) : recherche dans des millions de repos. La regex est généralement l'option la plus sûre ; la recherche structurelle existe dans certaines déploiements, mais elle a des limitations de performance et n'est pas toujours activée.
- [**GitHub Code Search**](https://github.com/search) : prend en charge la regex, la logique booléenne et des qualifiers tels que `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` et `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/) : recherche de code GitLab moderne propulsée par Zoekt. Prend en charge les modes exact et regex avec des filtres tels que `file:`, `lang:`, `repo:` et `sym:`.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) reste utile comme solution de repli plus large car il peut rechercher dans le code, les commentaires, les commits, les merge requests et les wikis.
- [**SearchCode**](https://searchcode.com/) : recherche du code dans des millions de projets.

## Useful search capabilities

Lors de l'audit d'une org dans un contexte bug bounty/red team, les capacités les plus utiles sont généralement :

- Prise en charge de la **regex** pour rechercher des formats de tokens, des schémas d'URL, des noms de fonctions dangereux, ou des fragments multilignes.
- **Filtres de chemin** pour aller directement vers des fichiers à forte valeur comme `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile`, ou `nginx.conf`.
- **Filtres de langage** pour séparer le code applicatif de l'IaC et des pipelines.
- **Recherche sensible aux symboles** pour énumérer des handlers, des middleware d'auth, des consommateurs de webhooks, des fonctions helper dangereuses, ou des classes/méthodes spécifiques.
- **Opérateurs booléens** pour réduire le bruit : `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.

## Practical methodology

1. **Commencez par les platforms indexées** pour identifier rapidement les repos, owners, chemins et familles de code.
2. **Pivotez vers des emplacements à fort signal** au lieu de rechercher uniquement des chaînes génériques `password`/`secret`.
3. **Recherchez la surface d'attaque, pas seulement les credentials** :
- workflows CI/CD et scripts de déploiement
- manifests Terraform/Helm/Kubernetes
- intégrations SSO/OIDC/SAML
- URLs internes, hôtes de staging, panneaux d'admin, brokers de messages, et endpoints de callback
- chemins de code dangereux (`exec`, rendu de templates, fetchers SSRF, deserializers, extraction ZIP, loaders YAML, etc.)
4. **Clonez et recherchez localement** lorsque vous avez besoin de branches non par défaut, de l'historique complet, d'une meilleure prise en charge de la regex, ou d'une automatisation en masse.
5. **Passez à des scanners dédiés** lorsque l'objectif est le triage ou la vérification de secrets (par exemple, voir la page dédiée ci-dessous).

### High-signal query ideas

Elles sont volontairement larges afin que vous puissiez les adapter à la syntaxe GitHub, GitLab, Sourcegraph ou Sourcebot :
```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```
### Recherche locale de masse lorsque la recherche indexée ne suffit pas
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
Utilisez la recherche locale quand vous en avez besoin pour :

- Rechercher des **branches non par défaut** ou des **tags**
- Rechercher dans l’**historique git**
- Exécuter des requêtes **PCRE2/multiline** de manière plus agressive
- Faire du triage en lot sur de nombreux dépôts sans limites d’interface

## Points aveugles courants

- L’**indexation limitée à la branche par défaut** est fréquente. Ne supposez pas que la recherche de code couvre toutes les branches/tags/l’historique.
- Les **gros fichiers, le code vendored, le code généré ou les archives** peuvent être ignorés ou produire du bruit.
- Les **comments, issues, PRs, gists et wikis** sont souvent hors du périmètre de la recherche de code générique et peuvent nécessiter des outils spécifiques à la plateforme.
- La **syntaxe de recherche diffère selon la plateforme**. Un dork qui fonctionne dans GitHub Code Search peut nécessiter de petits ajustements pour GitLab, Sourcegraph ou Sourcebot.

### Pièges spécifiques aux plateformes

- **GitHub Code Search** est excellent pour une reconnaissance rapide, mais il recherche uniquement la **branche par défaut**. Si vous avez besoin des branches de fonctionnalité, des secrets supprimés ou du code historique, clonez le repo et recherchez localement.
- **GitLab Exact Code Search** a aussi une limitation sur la **branche par défaut** et n’indexe que les fichiers plus petits, mais **Advanced Search** peut quand même être utile pour rechercher dans les comments, commits et wikis.
- **Sourcebot** indexe par défaut la **branche par défaut**, mais il peut être configuré pour indexer des branches/tags supplémentaires puis être recherché avec des filtres `rev:`, ce qui est très pratique pour des audits internes centrés sur des branches/tags quand vous contrôlez l’index.
- La recherche regex de **Sourcegraph** est généralement l’option la plus prévisible pour les travaux offensifs ; considérez la structural search comme un bonus optionnel, pas comme une capacité garantie.

> [!WARNING]
> Quand vous cherchez des leak dans un repo et que vous lancez quelque chose comme `git log -p`, n’oubliez pas qu’il peut y avoir **d’autres branches avec d’autres commits** contenant des secrets !

Pour la chasse dédiée aux secrets, les dorks GitHub à l’échelle de l’org, et des outils comme TruffleHog/Gitleaks, consultez :

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## Références

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
{{#include ../../banners/hacktricks-training.md}}
