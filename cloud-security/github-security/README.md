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

### With User SSH Key

#### GPG Keys

### With User Token

### With Oauth Application

### With Github Application

### With Malicious Github Action

### Bypassing Branch Protection
