# Ευρεία αναζήτηση πηγαίου κώδικα

{{#include ../../banners/hacktricks-training.md}}

Ο στόχος αυτής της σελίδας είναι να καταγράψει **platforms που σας επιτρέπουν να αναζητάτε κώδικα** (literal, regex, symbol-aware ή με περιορισμό βάσει path) σε **χιλιάδες/εκατομμύρια repos**.

Αυτό είναι χρήσιμο για:

- **Αναζήτηση leaked information**
- **Αναζήτηση ευάλωτων patterns**
- **Χαρτογράφηση τεχνολογιών, internal hosts, CI/CD και infrastructure-as-code**
- **Pivot από το όνομα μιας εταιρείας/org σε repos, branches και αρχεία με υψηλό signal**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search. Πολύ χρήσιμο όταν θέλετε να κάνετε index **πολλά repos** και, αν ρυθμιστεί κατάλληλα, επιπλέον branches/tags, διατηρώντας regex filters όπως `repo:`, `file:`, `lang:`, `rev:` και `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): Αναζήτηση σε εκατομμύρια repos. Το regex είναι συνήθως η ασφαλέστερη επιλογή· structural search υπάρχει σε ορισμένα deployments, αλλά έχει περιορισμούς απόδοσης και δεν είναι πάντα ενεργοποιημένο.
- [**GitHub Code Search**](https://github.com/search): Υποστηρίζει regex, boolean logic και qualifiers όπως `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` και `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Σύγχρονο GitLab code search που υποστηρίζεται από το Zoekt. Υποστηρίζει exact και regex modes με filters όπως `file:`, `lang:`, `repo:` και `sym:`.
- Το [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) παραμένει χρήσιμο ως ευρύτερο fallback, επειδή μπορεί να αναζητήσει σε code, comments, commits, merge requests και wikis.
- [**SearchCode**](https://searchcode.com/): Αναζήτηση κώδικα σε εκατομμύρια projects.
- [**Grep**](https://grep.app/): Γρήγορη public search σε ένα πολύ μεγάλο GitHub corpus. Χρήσιμο όταν θέλετε μια δεύτερη οπτική indexing/ranking για pivots σε **content**, **file** και **path**.

## Χρήσιμες δυνατότητες αναζήτησης

Κατά τον έλεγχο ενός org σε πλαίσιο bug bounty/red team, οι πιο χρήσιμες δυνατότητες είναι συνήθως:

- Υποστήριξη **Regex** για αναζήτηση formats token, URL schemes, ονομάτων επικίνδυνων functions ή multiline fragments.
- **Path filters** για άμεση μετάβαση σε αρχεία υψηλής αξίας, όπως `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` ή `nginx.conf`.
- **Language filters** για διαχωρισμό app code από IaC και pipelines.
- **Symbol-aware search** για καταγραφή handlers, auth middleware, webhook consumers, επικίνδυνων helper functions ή συγκεκριμένων classes/methods.
- **Boolean operators** για μείωση του noise: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Revision/diff search**, όπου είναι διαθέσιμο, ώστε να μπορείτε να ανακτήσετε **deleted strings**, να παρακολουθήσετε **security-relevant changes** ή να ελέγξετε **non-default branches/tags** χωρίς να κάνετε πρώτα clone τα πάντα.

## Practical methodology

1. **Ξεκινήστε με τα indexed platforms** για να εντοπίσετε γρήγορα repos, owners, paths και code families.
2. **Κάντε pivot σε locations υψηλού signal** αντί να αναζητάτε μόνο generic strings όπως `password`/`secret`.
3. **Αναζητήστε attack surface, όχι μόνο credentials**:
- CI/CD workflows, reusable workflows, composite actions και deployment scripts
- Dev Containers / Codespaces bootstrap files και custom features
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML integrations
- Internal URLs, staging hosts, admin panels, message brokers και callback endpoints
- Επικίνδυνα code paths (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders κ.λπ.)
4. **Κάντε clone και local search** όταν χρειάζεστε non-default branches, full history, καλύτερη υποστήριξη regex ή bulk automation.
5. **Κλιμακώστε σε dedicated scanners** όταν ο στόχος είναι secrets triage ή verification (για παράδειγμα, δείτε την dedicated σελίδα παρακάτω).

### Ιδέες για queries υψηλού signal

Αυτές είναι σκόπιμα ευρείες, ώστε να μπορείτε να τις προσαρμόσετε στη syntax των GitHub, GitLab, Sourcegraph ή Sourcebot:
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
### Νεότερα αρχεία υψηλής αξίας που αξίζει να ιεραρχήσετε

- **`.github/workflows/*.yml`**: Αναζητήστε `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted` και γραμμές τρίτων `uses:` που είναι pinned μόνο σε tags/branches αντί για πλήρη commit SHAs.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** και **`.devcontainer.json`**: Αναζητήστε `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` και τα αναφερόμενα Dockerfiles/scripts. Αυτά συχνά εκθέτουν internal package registries, bootstrap URLs, host mounts και endpoints που προορίζονται μόνο για developers.
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Ιδιαίτερα χρήσιμα για τον εντοπισμό org-specific installer logic που εκτελείται κατά τη δημιουργία του environment.
- **Άλλα CI/control-plane αρχεία**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Μαζική τοπική αναζήτηση όταν η indexed αναζήτηση δεν επαρκεί
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
Χρησιμοποίησε local αναζήτηση όταν χρειάζεται να:

- Αναζητήσεις σε **non-default branches** ή **tags**
- Αναζητήσεις στο **git history**
- Εκτελέσεις ερωτήματα **PCRE2/multiline** πιο επιθετικά
- Κάνεις μαζική αρχική αξιολόγηση πολλών repositories χωρίς όρια UI

### Αναζήτησε ρητά σε history, branches και diffs
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Αυτό είναι ιδιαίτερα χρήσιμο όταν το ενδιαφέρον string υπήρχε μόνο σε ένα **release branch**, **tag** ή **deleted commit**. Αν το Sourcegraph deployment σας το υποστηρίζει, τα searches `type:diff` και `type:commit` αποτελούν εξαιρετικό no-clone pivot για το ίδιο πρόβλημα.

## Συνήθεις blind spots

- Το indexing μόνο του **default branch** είναι συνηθισμένο. Μην υποθέτετε ότι το code search καλύπτει όλα τα branches/tags/history.
- Τα **large files**, ο vendored code, ο generated code ή τα archives μπορεί να παραλείπονται ή να δημιουργούν θόρυβο.
- Τα comments, issues, PRs, gists και wikis βρίσκονται συχνά εκτός του scope του generic code search και μπορεί να απαιτούν platform-specific tooling.
- Τα configs των **Codespaces / devcontainer** μπορεί να είναι branch-specific και να βρίσκονται σε πολλές διαδρομές `.devcontainer/<variant>/devcontainer.json`, επομένως ένα καθαρό default branch δεν σημαίνει ότι το dev environment είναι καθαρό παντού.
- Τα reusable workflows/actions και τα devcontainer features μπορεί να βρίσκονται εκτός του προφανούς file. Κάντε search στα `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` και `install.sh`, όχι μόνο στο workflow file του top-level.
- Η σύνταξη search διαφέρει ανά platform. Ένα dork που λειτουργεί στο GitHub Code Search μπορεί να χρειάζεται μικρές αλλαγές για GitLab, Sourcegraph ή Sourcebot.

### Platform-specific gotchas

- Το **GitHub Code Search** είναι εξαιρετικό για γρήγορο recon, αλλά κάνει search μόνο στο **default branch**. Αν χρειάζεστε feature branches, deleted secrets ή historical code, κάντε clone το repo και κάντε search τοπικά.
- Το **GitLab Exact Code Search** έχει επίσης περιορισμό στο **default branch** και κάνει indexing μόνο σε μικρότερα files, όμως το **Advanced Search** μπορεί να παραμένει χρήσιμο για search σε comments, commits και wikis.
- Το **Sourcebot** κάνει indexing στο **default branch** από προεπιλογή, αλλά μπορεί να ρυθμιστεί ώστε να κάνει indexing σε επιπλέον branches/tags και στη συνέχεια να γίνεται search με `rev:` filters, κάτι ιδιαίτερα βολικό για branch/tag-focused internal audits όταν ελέγχετε εσείς το index.
- Το regex search του **Sourcegraph** είναι γενικά η πιο προβλέψιμη επιλογή για offensive work. Αντιμετωπίστε το structural search ως προαιρετικό bonus και όχι ως εγγυημένη δυνατότητα. Αν το deployment το υποστηρίζει, τα queries `type:diff` και `type:commit` είναι πολύ καλά για την ανάκτηση deleted strings ή πρόσφατων security-relevant αλλαγών.

> [!WARNING]
> Όταν αναζητάτε leaks σε ένα repo και εκτελείτε κάτι όπως `git log -p`, μην ξεχνάτε ότι μπορεί να υπάρχουν **άλλα branches με άλλα commits** που περιέχουν secrets!

Για dedicated secret hunting, org-wide GitHub dorks και εργαλεία όπως τα TruffleHog/Gitleaks, δείτε:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)
{{#include ../../banners/hacktricks-training.md}}
