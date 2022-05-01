

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>


# Gitea Security

## What is Gitea

**Gitea** is a **self-hosted community managed lightweight code hosting** solution written in Go.

![](<../../.gitbook/assets/image (655).png>)

### Basic Information

{% content-ref url="basic-gitea-information.md" %}
[basic-gitea-information.md](basic-gitea-information.md)
{% endcontent-ref %}

## Lab

To run a Gitea instance locally you can just run a docker container:

```bash
docker run -p 3000:3000 gitea/gitea
```

Connect to port 3000 to access the web page.

You could also run it with kubernetes:

```
helm repo add gitea-charts https://dl.gitea.io/charts/
helm install gitea gitea-charts/gitea
```

## Unauthenticated Enumeration

* Public repos: [http://localhost:3000/explore/repos](http://localhost:3000/explore/repos)
* Registered users: [http://localhost:3000/explore/users](http://localhost:3000/explore/users)
* Registered Organizations: [http://localhost:3000/explore/organizations](http://localhost:3000/explore/organizations)

Note that by **default Gitea allows new users to register**. This won't give specially interesting access to the new users over other organizations/users repos, but a **logged in user** might be able to **visualize more repos or organizations**.

## Internal Exploitation

For this scenario we are going to suppose that you have obtained some access to a github account.

### With User Credentials/Web Cookie

If you somehow already have credentials for a user inside an organization (or you stole a session cookie) you can **just login** and check which which **permissions you have** over which **repos,** in **which teams** you are, **list other users**, and **how are the repos protected.**

Note that **2FA may be used** so you will only be able to access this information if you can also **pass that check**.

{% hint style="info" %}
Note that if you **manage to steal the `i_like_gitea` cookie** (currently configured with SameSite: Lax) you can **completely impersonate the user** without needing credentials or 2FA.
{% endhint %}

### With User SSH Key

Gitea allows **users** to set **SSH keys** that will be used as **authentication method to deploy code** on their behalf (no 2FA is applied).

With this key you can perform **changes in repositories where the user has some privileges**, however you can not use it to access gitea api to enumerate the environment. However, you can **enumerate local settings** to get information about the repos and user you have access to:

```bash
# Go to the the repository folder
# Get repo config and current user name and email
git config --list
```

If the user has configured its username as his gitea username you can access the **public keys he has set** in his account in _https://github.com/\<gitea\_username>.keys_, you could check this to confirm the private key you found can be used.

**SSH keys** can also be set in repositories as **deploy keys**. Anyone with access to this key will be able to **launch projects from a repository**. Usually in a server with different deploy keys the local file **`~/.ssh/config`** will give you info about key is related.

#### GPG Keys

As explained [**here**](../github-security/basic-github-information.md#ssh-keys) sometimes it's needed to sign the commits or you might get discovered.

Check locally if the current user has any key with:

```shell
gpg --list-secret-keys --keyid-format=long
```

### With User Token

For an introduction about [**User Tokens check the basic information**](basic-gitea-information.md#personal-access-tokens).

A user token can be used **instead of a password** to **authenticate** against Gitea server [**via API**](https://try.gitea.io/api/swagger#/). it will has **complete access** over the user.

### With Oauth Application

For an introduction about [**Gitea Oauth Applications check the basic information**](basic-gitea-information.md#oauth-applications).

An attacker might create a **malicious Oauth Application** to access privileged data/actions of the users that accepts them probably as part of a phishing campaign.

As explained in the basic information, the application will have **full access over the user account**.

### Branch Protection Bypass

In Github we have **github actions** which by default get a **token with write access** over the repo that can be used to **bypass branch protections**. In this case that **doesn't exist**, so the bypasses are more limited. But lets take a look to what can be done:

* **Enable Push**: If anyone with write access can push to the branch, just push to it.
* **Whitelist Restricted Pus**h: The same way, if you are part of this list push to the branch.
* **Enable Merge Whitelist**: If there is a merge whitelist, you need to be inside of it
* **Require approvals is bigger than 0**: Then... you need to compromise another user
* **Restrict approvals to whitelisted**: If only whitelisted users can approve... you need to compromise another user that is inside that list
* **Dismiss stale approvals**: If approvals are not removed with new commits, you could hijack an already approved PR to inject your code and merge the PR.

Note that **if you are an org/repo admin** you can bypass the protections.

### Enumerate Webhooks

**Webhooks** are able to **send specific gitea information to some places**. You might be able to **exploit that communication**.\
However, usually a **secret** you can **not retrieve** is set in the **webhook** that will **prevent** external users that know the URL of the webhook but not the secret to **exploit that webhook**.\
But in some occasions, people instead of setting the **secret** in its place, they **set it in the URL** as a parameter, so **checking the URLs** could allow you to **find secrets** and other places you could exploit further.

Webhooks can be set at **repo and at org level**.

## Post Exploitation

### Inside the server

If somehow you managed to get inside the server where gitea is running you should search for the gitea configuration file. By default it's located in `/data/gitea/conf/app.ini`

In this file you can find **keys** and **passwords**.

In the gitea path (by default: /data/gitea) you can find also interesting information like:

* The **sqlite** DB: If gitea is not using an external db it will use a sqlite db
* The **sessions** inside the sessions folder: Running `cat sessions/*/*/*` you can see the usernames of the logged users (gitea could also save the sessions inside the DB).
* The **jwt private key** inside the jwt folder
* More **sensitive information** could be found in this folder

If you are inside the server you can also **use the `gitea` binary** to access/modify information:

* `gitea dump` will dump gitea and generate a .zip file
* `gitea generate secret INTERNAL_TOKEN/JWT_SECRET/SECRET_KEY/LFS_JWT_SECRET` will generate a token of the indicated type (persistence)
* `gitea admin user change-password --username admin --password newpassword` Change the password
* `gitea admin user create --username newuser --password superpassword --email user@user.user --admin --access-token` Create new admin user and get an access token


<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>


