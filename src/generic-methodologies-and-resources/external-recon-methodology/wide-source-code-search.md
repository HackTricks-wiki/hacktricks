# Ευρεία αναζήτηση source code

{{#include ../../banners/hacktricks-training.md}}

Ο στόχος αυτής της σελίδας είναι να καταγράψει **platforms που σας επιτρέπουν να κάνετε αναζήτηση σε code** (literal, regex, symbol-aware ή path-scoped) σε **χιλιάδες/εκατομμύρια repos**.

Αυτό είναι χρήσιμο για:

- **Αναζήτηση για leaked πληροφορίες**
- **Αναζήτηση για ευάλωτα patterns**
- **Χαρτογράφηση τεχνολογιών, εσωτερικών hosts, CI/CD και infrastructure-as-code**
- **Pivot από το όνομα μιας εταιρείας/org σε repos, branches και αρχεία υψηλού σήματος**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search. Πολύ χρήσιμο όταν θέλετε να κάνετε index **πολλών repos** και, αν έχει ρυθμιστεί κατάλληλα, επιπλέον branches/tags, διατηρώντας regex filters όπως `repo:`, `file:`, `lang:`, `rev:` και `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): Αναζήτηση σε εκατομμύρια repos. Το Regex είναι συνήθως η ασφαλέστερη επιλογή· structural search υπάρχει σε ορισμένα deployments, αλλά έχει περιορισμούς απόδοσης και δεν είναι πάντα ενεργοποιημένο.
- [**GitHub Code Search**](https://github.com/search): Υποστηρίζει regex, boolean logic και qualifiers όπως `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` και `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Modern GitLab code search που βασίζεται στο Zoekt. Υποστηρίζει exact και regex modes με filters όπως `file:`, `lang:`, `repo:` και `sym:`.<sup>[[2]](#references)</sup>
- Το [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) παραμένει χρήσιμο ως ευρύτερο fallback, επειδή μπορεί να κάνει αναζήτηση σε code, comments, commits, merge requests και wikis.
- [**SearchCode**](https://searchcode.com/): Αναζήτηση σε code εκατομμυρίων projects.
- [**Grep**](https://grep.app/): Γρήγορη public αναζήτηση σε ένα πολύ μεγάλο GitHub corpus. Χρήσιμο όταν θέλετε μια δεύτερη οπτική indexing/ranking για pivots σε **content**, **file** και **path**.

## Χρήσιμες δυνατότητες αναζήτησης

Κατά τον έλεγχο ενός org σε πλαίσιο bug bounty/red team, οι πιο χρήσιμες δυνατότητες είναι συνήθως:

- Υποστήριξη **Regex** για αναζήτηση token formats, URL schemes, ονομάτων επικίνδυνων functions ή multiline fragments.
- **Path filters** για άμεση μετάβαση σε αρχεία υψηλής αξίας, όπως `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` ή `nginx.conf`.
- **Language filters** για διαχωρισμό του app code από IaC και pipelines.
- **Symbol-aware search** για καταγραφή handlers, auth middleware, webhook consumers, επικίνδυνων helper functions ή συγκεκριμένων classes/methods.
- **Boolean operators** για μείωση του θορύβου: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Revision/diff search**, όταν είναι διαθέσιμο, ώστε να μπορείτε να ανακτήσετε **διαγραμμένα strings**, να παρακολουθήσετε **αλλαγές σχετικές με την ασφάλεια** ή να εξετάσετε **non-default branches/tags** χωρίς να κάνετε πρώτα clone τα πάντα.

## Πρακτική μεθοδολογία

1. **Ξεκινήστε με τα indexed platforms** για να εντοπίσετε γρήγορα repos, owners, paths και code families.
2. **Κάντε pivot σε τοποθεσίες υψηλού σήματος** αντί να αναζητάτε μόνο generic strings όπως `password`/`secret`.
3. **Αναζητήστε attack surface, όχι μόνο credentials**:
- CI/CD workflows, reusable workflows, composite actions και deployment scripts
- Dev Containers / Codespaces bootstrap files και custom features
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML integrations
- Internal URLs, staging hosts, admin panels, message brokers και callback endpoints
- Επικίνδυνα code paths (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders κ.λπ.)
4. **Κάντε clone και αναζήτηση locally** όταν χρειάζεστε non-default branches, πλήρες history, καλύτερη υποστήριξη regex ή bulk automation.
5. **Κλιμακώστε σε dedicated scanners** όταν ο στόχος είναι secrets triage ή verification (για παράδειγμα, δείτε την ειδική σελίδα παρακάτω).

### Ιδέες για queries υψηλού σήματος

Αυτά είναι σκόπιμα ευρεία, ώστε να μπορείτε να τα προσαρμόσετε στο GitHub, GitLab, Sourcegraph ή Sourcebot syntax:
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
### Νεότερα αρχεία υψηλής αξίας που αξίζει να τεθούν σε προτεραιότητα

- **`.github/workflows/*.yml`**: Αναζητήστε `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted` και γραμμές `uses:` τρίτων που είναι pinned μόνο σε tags/branches αντί για πλήρη commit SHAs.<sup>[[3]](#references)</sup>
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** και **`.devcontainer.json`**: Αναζητήστε `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` και τα Dockerfiles/scripts που αναφέρονται. Αυτά συχνά αποκαλύπτουν internal package registries, bootstrap URLs, host mounts και endpoints που προορίζονται μόνο για developers.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Ιδιαίτερα χρήσιμα για την εύρεση installer logic συγκεκριμένης από τον οργανισμό, η οποία εκτελείται κατά τη δημιουργία του environment.
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
Χρησιμοποίησε local searching όταν χρειάζεται να:

- Κάνεις search σε **non-default branches** ή **tags**
- Κάνεις search στο **git history**
- Εκτελείς πιο επιθετικά queries **PCRE2/multiline**
- Κάνεις batch triage σε πολλά repositories χωρίς UI limits

### Κάνε explicit search στα history, branches και diffs
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Αυτό είναι ιδιαίτερα χρήσιμο όταν το ενδιαφέρον string υπήρχε μόνο σε ένα **release branch**, **tag** ή **deleted commit**. Αν το Sourcegraph deployment σας το υποστηρίζει, οι αναζητήσεις `type:diff` και `type:commit` είναι εξαιρετικό no-clone pivot για το ίδιο πρόβλημα.

## Common blind spots

- Το indexing μόνο του **default branch** είναι συνηθισμένο. Μην θεωρείτε ότι το code search καλύπτει όλα τα branches/tags/history.
- **Μεγάλα αρχεία, vendored code, generated code ή archives** ενδέχεται να παραλείπονται ή να παράγουν θόρυβο.
- Τα **comments, issues, PRs, gists και wikis** συχνά βρίσκονται εκτός του scope του generic code search και ενδέχεται να απαιτούν platform-specific tooling.
- Τα **Codespaces / devcontainer configs** μπορεί να είναι branch-specific και να βρίσκονται σε πολλά paths όπως `.devcontainer/<variant>/devcontainer.json`, επομένως ένα καθαρό default branch δεν σημαίνει ότι το dev environment είναι καθαρό παντού.
- Τα **reusable workflows/actions και devcontainer features** μπορεί να βρίσκονται εκτός του προφανούς αρχείου. Αναζητήστε τα `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` και `install.sh`, όχι μόνο το workflow file στο top level.
- Το **search syntax** διαφέρει ανά platform. Ένα dork που λειτουργεί στο GitHub Code Search μπορεί να χρειάζεται μικρές αλλαγές για GitLab, Sourcegraph ή Sourcebot.

### Platform-specific gotchas

- Το **GitHub Code Search** είναι εξαιρετικό για γρήγορο recon, αλλά αναζητά μόνο στο **default branch**. Αν χρειάζεστε feature branches, deleted secrets ή historical code, κάντε clone το repo και αναζητήστε τοπικά.
- Το **GitLab Exact Code Search** επίσης έχει περιορισμό στο **default branch** και κάνει indexing μόνο σε μικρότερα αρχεία, αλλά το **Advanced Search** μπορεί να είναι χρήσιμο για αναζήτηση σε comments, commits και wikis.<sup>[[2]](#references)</sup>
- Το **Sourcebot** κάνει indexing στο **default branch** από προεπιλογή, αλλά μπορεί να ρυθμιστεί ώστε να κάνει indexing σε επιπλέον branches/tags και, στη συνέχεια, να πραγματοποιεί αναζητήσεις με `rev:` filters. Αυτό είναι ιδιαίτερα πρακτικό για internal audits που επικεντρώνονται σε branches/tags, όταν ελέγχετε το index.
- Το **Sourcegraph** regex search είναι γενικά η πιο προβλέψιμη επιλογή για offensive work. Αντιμετωπίστε το structural search ως προαιρετικό bonus και όχι ως εγγυημένη δυνατότητα. Αν το deployment το υποστηρίζει, τα `type:diff` και `type:commit` queries είναι πολύ καλά για την ανάκτηση deleted strings ή πρόσφατων security-relevant αλλαγών.

> [!WARNING]
> Όταν αναζητάτε leaks σε ένα repo και εκτελείτε κάτι όπως `git log -p`, μην ξεχνάτε ότι μπορεί να υπάρχουν **άλλα branches με άλλα commits** που περιέχουν secrets!

Για dedicated secret hunting, org-wide GitHub dorks και εργαλεία όπως τα TruffleHog/Gitleaks, δείτε:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

## References

- [1] [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)

{{#include ../../banners/hacktricks-training.md}}
