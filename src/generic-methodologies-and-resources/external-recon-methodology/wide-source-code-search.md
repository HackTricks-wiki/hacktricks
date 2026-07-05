# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

Ο στόχος αυτής της σελίδας είναι να καταγράψει **platforms that allow you to search code** (literal, regex, symbol-aware, or path-scoped) σε **thousands/millions of repos**.

Αυτό είναι χρήσιμο για:

- **Search for leaked information**
- **Search for vulnerable patterns**
- **Map technologies, internal hosts, CI/CD, and infrastructure-as-code**
- **Pivot from a company/org name into repos, branches, and high-signal files**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search. Πολύ χρήσιμο όταν θέλεις να κάνεις index **many repos** και, αν έχει ρυθμιστεί, επιπλέον branches/tags ενώ κρατάς regex filters όπως `repo:`, `file:`, `lang:`, `rev:` και `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): Search in millions of repos. Το Regex είναι συνήθως η ασφαλέστερη επιλογή· το structural search υπάρχει σε ορισμένα deployments, αλλά έχει περιορισμούς απόδοσης και δεν είναι πάντα ενεργό.
- [**GitHub Code Search**](https://github.com/search): Υποστηρίζει regex, boolean logic, και qualifiers όπως `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` και `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Σύγχρονο GitLab code search με Zoekt. Υποστηρίζει exact και regex modes με filters όπως `file:`, `lang:`, `repo:` και `sym:`.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) παραμένει χρήσιμο ως ευρύτερη εναλλακτική, επειδή μπορεί να κάνει search σε code, comments, commits, merge requests, και wikis.
- [**SearchCode**](https://searchcode.com/): Search code σε εκατομμύρια projects.

## Useful search capabilities

Όταν κάνεις auditing σε ένα org σε bug bounty/red team context, οι πιο χρήσιμες δυνατότητες συνήθως είναι:

- **Regex** υποστήριξη για search σε token formats, URL schemes, dangerous function names, ή multiline fragments.
- **Path filters** για να πας απευθείας σε high-value files όπως `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile`, ή `nginx.conf`.
- **Language filters** για να ξεχωρίζεις app code από IaC και pipelines.
- **Symbol-aware search** για να καταγράφεις handlers, auth middleware, webhook consumers, dangerous helper functions, ή συγκεκριμένες classes/methods.
- **Boolean operators** για να μειώσεις τον θόρυβο: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.

## Practical methodology

1. **Start with the indexed platforms** για να εντοπίσεις γρήγορα repos, owners, paths, και code families.
2. **Pivot into high-signal locations** αντί να ψάχνεις μόνο για γενικά `password`/`secret` strings.
3. **Search for attack surface, not only credentials**:
- CI/CD workflows and deployment scripts
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML integrations
- Internal URLs, staging hosts, admin panels, message brokers, and callback endpoints
- Dangerous code paths (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders, etc.)
4. **Clone and search locally** όταν χρειάζεσαι non-default branches, full history, καλύτερη regex υποστήριξη, ή bulk automation.
5. **Escalate to dedicated scanners** όταν ο στόχος είναι secrets triage ή verification (για παράδειγμα, δες την dedicated page παρακάτω).

### High-signal query ideas

Αυτά είναι σκόπιμα ευρεία, ώστε να μπορείς να τα προσαρμόσεις στη σύνταξη των GitHub, GitLab, Sourcegraph, ή Sourcebot:
```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```
### Μαζική τοπική αναζήτηση όταν η ευρετηριασμένη αναζήτηση δεν είναι αρκετή
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

- Search **non-default branches** ή **tags**
- Search **git history**
- Run **PCRE2/multiline** queries πιο επιθετικά
- Batch triage πολλά repositories χωρίς UI limits

## Common blind spots

- **Default-branch-only indexing** είναι συνηθισμένο. Μην υποθέτεις ότι το code search καλύπτει όλα τα branches/tags/history.
- **Large files, vendored code, generated code, ή archives** μπορεί να παραλείπονται ή να προκαλούν θόρυβο.
- **Comments, issues, PRs, gists, and wikis** συχνά είναι εκτός scope του generic code search και μπορεί να απαιτούν platform-specific tooling.
- **Search syntax differs per platform**. Ένα dork που δουλεύει στο GitHub Code Search μπορεί να χρειάζεται μικρές αλλαγές για GitLab, Sourcegraph, ή Sourcebot.

### Platform-specific gotchas

- **GitHub Code Search** είναι εξαιρετικό για fast recon, αλλά κάνει search μόνο στο **default branch**. Αν χρειάζεσαι feature branches, deleted secrets, ή historical code, κάνε clone το repo και search το τοπικά.
- **GitLab Exact Code Search** έχει επίσης limitation στο **default-branch** και κάνει index μόνο smaller files, αλλά το **Advanced Search** μπορεί να είναι χρήσιμο για search σε comments, commits, και wikis.
- **Sourcebot** κάνει index το **default branch** by default, αλλά μπορεί να ρυθμιστεί ώστε να κάνει index additional branches/tags και μετά να γίνει search με `rev:` filters, κάτι πολύ βολικό για branch/tag-focused internal audits όταν ελέγχεις το index.
- **Sourcegraph** regex search είναι γενικά η πιο προβλέψιμη επιλογή για offensive work; αντιμετώπισε το structural search ως προαιρετικό bonus, όχι ως εγγυημένη δυνατότητα.

> [!WARNING]
> Όταν ψάχνεις για leaks σε ένα repo και τρέχεις κάτι σαν `git log -p` μην ξεχνάς ότι μπορεί να υπάρχουν **other branches with other commits** που περιέχουν secrets!

Για dedicated secret hunting, org-wide GitHub dorks, και tooling όπως TruffleHog/Gitleaks, δες:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
{{#include ../../banners/hacktricks-training.md}}
