# Ευρεία αναζήτηση Source Code

Ο στόχος αυτής της σελίδας είναι να καταγράψει **platforms που σας επιτρέπουν να αναζητάτε code** (literal, regex, symbol-aware ή με περιορισμό βάσει path) σε **χιλιάδες/εκατομμύρια repos**.

Αυτό είναι χρήσιμο για:

- **Αναζήτηση leaked πληροφοριών**
- **Αναζήτηση ευάλωτων patterns**
- **Χαρτογράφηση technologies, internal hosts, CI/CD και infrastructure-as-code**
- **Pivot από το όνομα μιας εταιρείας/org σε repos, branches και αρχεία υψηλού σήματος**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search με regex, symbol και filtered search σε repositories. Ρυθμίστε επιπλέον branches/tags και αναζητήστε τα με `rev:` όταν η κάλυψη branches είναι σημαντική.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search): Code search με queries για regex, boolean, symbol, repository/file/language, branch/commit, diff και commit-message.<sup>[[8]](#references)[[10]](#references)</sup> Το Structural search είναι προαιρετικό, επειδή η τρέχουσα τεκμηρίωση το περιγράφει ως απενεργοποιημένο από προεπιλογή και περιορισμένο ως προς την απόδοση.<sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search): Υποστηρίζει regex, boolean logic και qualifiers όπως `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` και `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Code search με υποστήριξη από το Zoekt, με exact και regex modes και filters όπως `file:`, `lang:`, `repo:` και `sym:`.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) είναι ένα ευρύτερο fallback, επειδή μπορεί να αναζητήσει code, comments, commits, merge requests και wikis.<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/): Υπηρεσία code-intelligence με boolean/regex/structural code search, καθώς και ανάκτηση αρχείων και symbols.<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/): Public code search σε ένα εκατομμύριο GitHub repositories, με αναζήτηση σε content, files και paths.<sup>[[13]](#references)</sup>

## Χρήσιμες δυνατότητες αναζήτησης

Κατά τον έλεγχο ενός org σε πλαίσιο bug bounty/red team, οι πιο χρήσιμες δυνατότητες είναι συνήθως:

- Υποστήριξη **Regex** για αναζήτηση formats token, URL schemes, ονομάτων επικίνδυνων functions ή multiline fragments.
- **Path filters** για άμεση μετάβαση σε αρχεία υψηλής αξίας, όπως `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` ή `nginx.conf`.
- **Language filters** για διαχωρισμό του app code από IaC και pipelines.
- **Symbol-aware search** για καταγραφή handlers, auth middleware, webhook consumers, επικίνδυνων helper functions ή συγκεκριμένων classes/methods.
- **Boolean operators** για μείωση του noise: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Revision/diff search** όταν είναι διαθέσιμο, ώστε να μπορείτε να ανακτήσετε **διαγραμμένα strings**, να παρακολουθήσετε **αλλαγές σχετικές με την ασφάλεια** ή να επιθεωρήσετε **non-default branches/tags** χωρίς να κάνετε πρώτα clone τα πάντα.

## Πρακτική μεθοδολογία

1. **Ξεκινήστε με τα indexed platforms** για να εντοπίσετε γρήγορα repos, owners, paths και code families.
2. **Κάντε pivot σε locations υψηλού σήματος**, αντί να αναζητάτε μόνο generic strings όπως `password`/`secret`.
3. **Αναζητήστε attack surface και όχι μόνο credentials**:
- CI/CD workflows, reusable workflows, composite actions και deployment scripts
- Αρχεία bootstrap και custom features για Dev Containers / Codespaces
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML integrations
- Internal URLs, staging hosts, admin panels, message brokers και callback endpoints
- Επικίνδυνα code paths (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders κ.λπ.)
4. **Κάντε clone και αναζητήστε locally** όταν χρειάζεστε non-default branches, πλήρες history, καλύτερη υποστήριξη regex ή bulk automation.
5. **Προχωρήστε σε dedicated scanners** όταν ο στόχος είναι secrets triage ή verification (για παράδειγμα, δείτε την dedicated σελίδα παρακάτω).

### Ιδέες για queries υψηλού σήματος

Αυτές είναι σκόπιμα ευρείες, ώστε να μπορείτε να τις προσαρμόσετε στο syntax των GitHub, GitLab, Sourcegraph ή Sourcebot:
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
### Νεότερα αρχεία υψηλού σήματος που αξίζει να δοθεί προτεραιότητα

- **`.github/workflows/*.yml`**: Ελέγξτε τα privileged triggers `pull_request_target` και `workflow_run`, καθώς και τις γραμμές τρίτων `uses:` που είναι pinned μόνο σε tags/branches αντί για πλήρη commit SHAs.<sup>[[3]](#references)</sup> Αναζητήστε επίσης `workflow_call`, `secrets: inherit`, `id-token: write` και `runs-on: self-hosted`.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** και **`.devcontainer.json`**: Αναζητήστε `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` και τα referenced Dockerfiles/scripts για να εντοπίσετε environment values, bootstrap commands, mounts και σχετικά αρχεία.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Ελέγξτε και τα δύο αρχεία, επειδή το ελάχιστο layout ενός Feature περιλαμβάνει metadata και ένα `install.sh` entrypoint script.<sup>[[14]](#references)</sup>
- **Άλλα αρχεία CI/control-plane**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Μαζική local search όταν η indexed search δεν επαρκεί
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
Χρησιμοποιήστε local searching όταν χρειάζεται να:

- Αναζητήσετε **non-default branches** ή **tags**
- Αναζητήσετε το **git history**
- Εκτελέσετε πιο επιθετικά queries **PCRE2/multiline**
- Κάνετε batch triage σε πολλά repositories χωρίς περιορισμούς του UI

### Αναζητήστε ρητά στο history, στα branches και στα diffs
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Αυτό είναι ιδιαίτερα χρήσιμο όταν το ενδιαφέρον string υπήρχε μόνο σε ένα **release branch**, **tag** ή **deleted commit**. Αν το Sourcegraph deployment σας το υποστηρίζει, οι αναζητήσεις `type:diff` και `type:commit` είναι εξαιρετικό pivot χωρίς clone για το ίδιο πρόβλημα.<sup>[[8]](#references)[[10]](#references)</sup>

## Συνηθισμένα τυφλά σημεία

- Η **ευρετηρίαση μόνο του default branch** είναι συνηθισμένη. Μην υποθέτετε ότι το code search καλύπτει όλα τα branches/tags/history.
- **Μεγάλα αρχεία, vendored code, generated code ή archives** μπορεί να παραλείπονται ή να παράγουν θόρυβο.
- Τα **comments, issues, PRs, gists και wikis** συχνά βρίσκονται εκτός του πεδίου εφαρμογής του generic code search και μπορεί να απαιτούν platform-specific tooling.
- Τα **Codespaces / devcontainer configs μπορεί να είναι branch-specific**. Μπορεί να βρίσκονται σε πολλές διαδρομές `.devcontainer/<variant>/devcontainer.json`, επομένως ένα καθαρό default branch δεν σημαίνει ότι το dev environment είναι καθαρό παντού.<sup>[[4]](#references)</sup>
- Τα **reusable workflows/actions και devcontainer features μπορεί να βρίσκονται εκτός του προφανούς αρχείου**. Κάντε search στα `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` και `install.sh`, όχι μόνο στο workflow file ανώτερου επιπέδου.
- Η **σύνταξη search διαφέρει ανά platform**. Ένα dork που λειτουργεί στο GitHub Code Search μπορεί να χρειάζεται μικρές αλλαγές για GitLab, Sourcegraph ή Sourcebot.

### Ιδιαίτερες παγίδες ανά platform

- Το **GitHub Code Search** είναι χρήσιμο για γρήγορο recon, αλλά κάνει search μόνο στο **default branch**. Αν χρειάζεστε feature branches, deleted secrets ή historical code, κάντε clone το repo και κάντε search τοπικά.<sup>[[15]](#references)</sup>
- Το **GitLab Exact Code Search** έχει περιορισμό στο **default branch** και κάνει index μόνο σε αρχεία μικρότερα από 1 MB με λιγότερα από 20.000 trigrams.<sup>[[2]](#references)</sup> Το **Advanced Search** μπορεί να καλύψει επίσης comments, commits και wikis.<sup>[[11]](#references)</sup>
- Το **Sourcebot** κάνει index από προεπιλογή στο **default branch**, αλλά μπορεί να ρυθμιστεί ώστε να κάνει index σε επιπλέον branches/tags και στη συνέχεια να πραγματοποιεί search με φίλτρα `rev:` όταν ελέγχετε το index.<sup>[[7]](#references)</sup>
- Το **Sourcegraph** υποστηρίζει regex, symbol, diff και commit queries. Χρησιμοποιήστε structural search μόνο όπου είναι ενεργοποιημένο και λάβετε υπόψη τους τεκμηριωμένους περιορισμούς απόδοσής του.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> Όταν ψάχνετε για leaks σε ένα repo και εκτελείτε κάτι όπως `git log -p`, μην ξεχνάτε ότι μπορεί να υπάρχουν **άλλα branches με άλλα commits** που περιέχουν secrets!

Για dedicated secret hunting, org-wide GitHub dorks και εργαλεία όπως τα TruffleHog/Gitleaks, δείτε [τη σελίδα GitHub leaked secrets](github-leaked-secrets.md).

## References

- [1] [Σύνταξη GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [Αναφορά ασφαλούς χρήσης του GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Αναφορά metadata Dev Container](https://containers.dev/implementors/json_reference/)
- [5] [Sourcebot](https://www.sourcebot.dev/)
- [6] [Search API του Sourcebot](https://docs.sourcebot.dev/api-reference/search-%26-navigation/search-code)
- [7] [Indexing πολλαπλών branches του Sourcebot](https://docs.sourcebot.dev/docs/features/search/multi-branch-indexing)
- [8] [Sourcegraph Code Search](https://sourcegraph.com/docs/code-search)
- [9] [Sourcegraph Structural Search](https://sourcegraph.com/docs/code-search/types/structural)
- [10] [Σύνταξη Search Query του Sourcegraph](https://sourcegraph.com/docs/code-search/queries)
- [11] [GitLab Advanced Search](https://docs.gitlab.com/user/search/advanced_search/)
- [12] [SearchCode](https://searchcode.com/)
- [13] [Grep.app](https://grep.app/)
- [14] [Συγγραφή Dev Container Feature](https://containers.dev/guide/author-a-feature)
- [15] [Εργαλεία διερεύνησης για περιστατικά ασφαλείας](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-tools)
{{#include ../../banners/hacktricks-training.md}}
