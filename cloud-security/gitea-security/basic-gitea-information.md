

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>


# Basic Structure

The basic gitea environment structure is to group repos by **organization(s),** each of them may contain **several repositories** and **several teams.** However, note that just like in github users can have repos outside of the organization.

Moreover, a **user** can be a **member** of **different organizations**. Within the organization the user may have **different permissions over each repository**.

A user may also be **part of different teams** with different permissions over different repos.

And finally **repositories may have special protection mechanisms**.

# Permissions

## Organizations

When an **organization is created** a team called **Owners** is **created** and the user is put inside of it. This team will give **admin access** over the **organization**, those **permissions** and the **name** of the team **cannot be modified**.

**Org admins** (owners) can select the **visibility** of the organization:

* Public
* Limited (logged in users only)
* Private (members only)

**Org admins** can also indicate if the **repo admins** can **add and or remove access** for teams. They can also indicate the max number of repos.

When creating a new team, several important settings are selected:

* It's indicated the **repos of the org the members of the team will be able to access**: specific repos (repos where the team is added) or all.
* It's also indicated **if members can create new repos** (creator will get admin access to it)
* The **permissions** the **members** of the repo will **have**:
  * **Administrator** access
  * **Specific** access:

![](<../../.gitbook/assets/image (648) (1).png>)

## Teams & Users

In a repo, the **org admin** and the **repo admins** (if allowed by the org) can **manage the roles** given to collaborators (other users) and teams. There are **3** possible **roles**:

* Administrator
* Write
* Read

# Gitea Authentication

## Web Access

Using **username + password** and potentially (and recommended) a 2FA.

## **SSH Keys**

You can configure your account with one or several public keys allowing the related **private key to perform actions on your behalf.** [http://localhost:3000/user/settings/keys](http://localhost:3000/user/settings/keys)

### **GPG Keys**

You **cannot impersonate the user with these keys** but if you don't use it it might be possible that you **get discover for sending commits without a signature**.

## **Personal Access Tokens**

You can generate personal access token to **give an application access to your account**. A personal access token gives full access over your account: [http://localhost:3000/user/settings/applications](http://localhost:3000/user/settings/applications)

## Oauth Applications

Just like personal access tokens **Oauth applications** will have **complete access** over your account and the places your account has access because, as indicated in the [docs](https://docs.gitea.io/en-us/oauth2-provider/#scopes), scopes aren't supported yet:

![](<../../.gitbook/assets/image (662).png>)

## Deploy keys

Deploy keys might have read-only or write access to the repo, so they might be interesting to compromise specific repos.

# Branch Protections

Branch protections are designed to **not give complete control of a repository** to the users. The goal is to **put several protection methods before being able to write code inside some branch**.

The **branch protections of a repository** can be found in _https://localhost:3000/\<orgname>/\<reponame>/settings/branches_

{% hint style="info" %}
It's **not possible to set a branch protection at organization level**. So all of them must be declared on each repo.
{% endhint %}

Different protections can be applied to a branch (like to master):

* **Disable Push**: No-one can push to this branch
* **Enable Push**: Anyone with access can push, but not force push.
* **Whitelist Restricted Push**: Only selected users/teams can push to this branch (but no force push)
* **Enable Merge Whitelist**: Only whitelisted users/teams can merge PRs.
* **Enable Status checks:** Require status checks to pass before merging.
* **Require approvals**: Indicate the number of approvals required before a PR can be merged.
* **Restrict approvals to whitelisted**: Indicate users/teams that can approve PRs.
* **Block merge on rejected reviews**: If changes are requested, it cannot be merged (even if the other checks pass)
* **Block merge on official review requests**: If there official review requests it cannot be merged
* **Dismiss stale approvals**: When new commits, old approvals will be dismissed.
* **Require Signed Commits**: Commits must be signed.
* **Block merge if pull request is outdated**
* **Protected/Unprotected file patterns**: Indicate patterns of files to protect/unprotect against changes

{% hint style="info" %}
As you can see, even if you managed to obtain some credentials of a user, **repos might be protected avoiding you to pushing code to master** for example to compromise the CI/CD pipeline.
{% endhint %}



<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>


