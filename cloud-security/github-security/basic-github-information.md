# Basic Github Information

## Basic Structure

The basic github environment structure of a big **company** is to own an **enterprise** which owns **several organizations** and each of them may contain **several repositories** and **several teams.**. Smaller companies may just **own one organization and no enterprises**.

From a user point of view a **user** can be a **member** of **different enterprises and organizations**. Within them the user may have **different enterprise, organization and repository roles**.

Moreover, a user may be **part of different teams** with different enterprise, organization or repository roles.

And finally **repositories may have special protection mechanisms**.

## Privileges

### Enterprise Roles

* **Enterprise owner**: People with this role can **manage administrators, manage organizations within the enterprise, manage enterprise settings, enforce policy across organizations**. However, they **cannot access organization settings or content** unless they are made an organization owner or given direct access to an organization-owned repository
* **Enterprise members**: Members of organizations owned by your enterprise are also **automatically members of the enterprise**.

### Organization Roles

In an organisation users can have different roles:

* **Organization owners**: Organization owners have **complete administrative access to your organization**. This role should be limited, but to no less than two people, in your organization.
* **Organization members**: The **default**, non-administrative role for **people in an organization** is the organization member. By default, organization members **have a number of permissions**.
* **Billing managers**: Billing managers are users who can **manage the billing settings for your organization**, such as payment information.
* **Security Managers**: It's a role that organization owners can assign to any team in an organization. When applied, it gives every member of the team permissions to **manage security alerts and settings across your organization, as well as read permissions for all repositories** in the organization.
  * If your organization has a security team, you can use the security manager role to give members of the team the least access they need to the organization.&#x20;
* **Github App managers**: To allow additional users to **manage GitHub Apps owned by an organization**, an owner can grant them GitHub App manager permissions.
* **Outside collaborators**: An outside collaborator is a person who has **access to one or more organization repositories but is not explicitly a member** of the organization.

You can **compare the permissions** of these roles in this table: [https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/roles-in-an-organization#permissions-for-organization-roles](https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/roles-in-an-organization#permissions-for-organization-roles)

### Members Privileges

In _https://github.com/organizations/\<org\_name>/settings/member\_privileges_ you can see the **permissions users will have just for being part of the organisation**.

The settings here configured will indicate the following permissions of members of the organisation:

* Be admin, writer, reader or no permission over all the organisation repos.
* If members can create private, internal or public repositories.
* If forking of repositories is possible
* If it's possible to invite outside collaborators
* If public or private sites can be published
* The permissions admins has over the repositories
* If members can create new teams

### Repository Roles

By default repository roles are created:

* **Read**: Recommended for **non-code contributors** who want to view or discuss your project
* **Triage**: Recommended for **contributors who need to proactively manage issues and pull requests** without write access
* **Write**: Recommended for contributors who **actively push to your project**
* **Maintain**: Recommended for **project managers who need to manage the repository** without access to sensitive or destructive actions
* **Admin**: Recommended for people who need **full access to the project**, including sensitive and destructive actions like managing security or deleting a repository

You can **compare the permissions** of each role in this table [https://docs.github.com/en/organizations/managing-access-to-your-organizations-repositories/repository-roles-for-an-organization#permissions-for-each-role](https://docs.github.com/en/organizations/managing-access-to-your-organizations-repositories/repository-roles-for-an-organization#permissions-for-each-role)

You can also **create your own roles** in _https://github.com/organizations/\<org\_name>/settings/roles_

### Teams

You can **list the teams created in an organization** in _https://github.com/orgs/\<org\_name>/teams_. Note that to see the teams which are children of other teams you need to access each parent team.

![](<../../.gitbook/assets/image (630).png>)

### Users

The users of an organization can be **listed** in _https://github.com/orgs/\<org\_name>/people._

In the information of each user you can see the **teams the user is member of**, and the **repos the user has access to**.

## Github Authentication

Github offers different ways to authenticate to your account and perform actions on your behalf.

### Web Access

Accessing **github.com** you can login using your **username and password** (and a **2FA potentially**).

### **SSH Keys**

You can configure your account with one or several public keys allowing the related **private key to perform actions on your behalf.** [https://github.com/settings/keys](https://github.com/settings/keys)

#### **GPG Keys**

You **cannot impersonate the user with these keys** but if you don't use it it might be possible that you **get discover for sending commits without a signature**. Learn more about [vigilant mode here](https://docs.github.com/en/authentication/managing-commit-signature-verification/displaying-verification-statuses-for-all-of-your-commits#about-vigilant-mode).

### **Personal Access Tokens**

You can generate personal access token to **give an application access to your account**. When creating a personal access token the **user** needs to **specify** the **permissions** to **token** will have. [https://github.com/settings/tokens](https://github.com/settings/tokens)

### Oauth Applications

Oauth applications may ask you for permissions **to access part of your github information or to impersonate you** to perform some actions. A common example of this functionality is the **login with github button** you might find in some platforms.

* You can **create** your own **Oauth applications** in [https://github.com/settings/developers](https://github.com/settings/developers)
* You can see all the **Oauth applications that has access to your account**  in [https://github.com/settings/applications](https://github.com/settings/applications)
* You can see the **scopes that Oauth Apps can ask for** in [https://docs.github.com/en/developers/apps/building-oauth-apps/scopes-for-oauth-apps](https://docs.github.com/en/developers/apps/building-oauth-apps/scopes-for-oauth-apps)
* You can see third party access of applications in an **organization** in _https://github.com/organizations/\<org\_name>/settings/oauth\_application\_policy_

Some **security recommendations**:

* An **OAuth App** should always **act as the authenticated GitHub user across all of GitHub** (for example, when providing user notifications) and with access only to the specified scopes..
* An OAuth App can be used as an identity provider by enabling a "Login with GitHub" for the authenticated user.
* **Don't** build an **OAuth App** if you want your application to act on a **single repository**. With the `repo` OAuth scope, OAuth Apps can **act on **_**all**_** of the authenticated user's repositorie**s.
* **Don't** build an OAuth App to act as an application for your **team or company**. OAuth Apps authenticate as a **single user**, so if one person creates an OAuth App for a company to use, and then they leave the company, no one else will have access to it.
* **More** in [here](https://docs.github.com/en/developers/apps/getting-started-with-apps/about-apps#about-oauth-apps).

### Github Applications

Github applications can ask for permissions to **access your github information or impersonate you** to perform specific actions over specific resources. In Github Apps you need to specify the repositories the app will have access to.

* To install a GitHub App, you must be an **organisation owner or have admin permissions** in a repository.
* The GitHub App should **connect to a personal account or an organisation**.
* You can create your own Github application in [https://github.com/settings/apps](https://github.com/settings/apps)
* You can see all the **Github applications that has access to your account**  in [https://github.com/settings/apps/authorizations](https://github.com/settings/apps/authorizations)
* These are the **API Endpoints for Github Applications** [https://docs.github.com/en/rest/overview/endpoints-available-for-github-app](https://docs.github.com/en/rest/overview/endpoints-available-for-github-apps). Depending on the permissions of the App it will be able to access some of them
* You can see installed apps in an **organization** in _https://github.com/organizations/\<org\_name>/settings/installations_

Some security recommendations:

* A GitHub App should **take actions independent of a user** (unless the app is using a [user-to-server](https://docs.github.com/en/apps/building-github-apps/identifying-and-authorizing-users-for-github-apps#user-to-server-requests) token). To keep user-to-server access tokens more secure, you can use access tokens that will expire after 8 hours, and a refresh token that can be exchanged for a new access token. For more information, see "[Refreshing user-to-server access tokens](https://docs.github.com/en/apps/building-github-apps/refreshing-user-to-server-access-tokens)."
* Make sure the GitHub App integrates with **specific repositories**.
* The GitHub App should **connect to a personal account or an organisation**.
* Don't expect the GitHub App to know and do everything a user can.
* **Don't use a GitHub App if you just need a "Login with GitHub" service**. But a GitHub App can use a [user identification flow](https://docs.github.com/en/apps/building-github-apps/identifying-and-authorizing-users-for-github-apps) to log users in _and_ do other things.
* Don't build a GitHub App if you _only_ want to act as a GitHub user and do everything that user can do.
* If you are using your app with GitHub Actions and want to modify workflow files, you must authenticate on behalf of the user with an OAuth token that includes the `workflow` scope. The user must have admin or write permission to the repository that contains the workflow file. For more information, see "[Understanding scopes for OAuth apps](https://docs.github.com/en/apps/building-oauth-apps/understanding-scopes-for-oauth-apps/#available-scopes)."
* **More** in [here](https://docs.github.com/en/developers/apps/getting-started-with-apps/about-apps#about-github-apps).

### Github Actions

This **isn't a way to authenticate in github**, but a **malicious** Github Action could get **unauthorised access to github** and **depending** on the **privileges** given to the Action several **different attacks** could be done. See below for more information.

## Git Actions

Git actions allows to automate the **execution of code when an event happen**. Usually the code executed is **somehow related to the code of the repository** (maybe build a docker container or check that the PR doesn't contain secrets).

### Configuration

In _https://github.com/organizations/\<org\_name>/settings/actions_ it's possible to check the **configuration of the github actions** for the organization.

It's possible to disallow the use of github actions completely, **allow all github actions**, or just allow certain actions.

It's also possible to configure **who needs approval to run a Github Action** and the **permissions of the  **_**GITHUB\_TOKEN**_** of a Github Action when it's run**.

### Git Secrets

Github Action usually need some kind of secrets to interact with github or third party applications. To **avoid putting them in clear-text** in the repo, github allow to put them as **Secrets**.

These secrets can be configured **for the repo or for all the organization**. Then, in order for the **Action to be able to access the secret** you need to declare it like:

```yaml
steps:
  - name: Hello world action
    with: # Set the secret as an input
      super_secret: ${{ secrets.SuperSecret }}
    env: # Or as an environment variable
      super_secret: ${{ secrets.SuperSecret }}
```

#### Example using Bash <a href="#example-using-bash" id="example-using-bash"></a>

```yaml
steps:
  - shell: bash
    env:
      SUPER_SECRET: ${{ secrets.SuperSecret }}
    run: |
      example-command "$SUPER_SECRET"
```

{% hint style="warning" %}
Secrets **can only be accessed from the Github Actions** that have them declared.

Once configured in the repo or the organizations **users of github won't be able to access them again**, they just will be able to **change them**.
{% endhint %}

Therefore, the **only way to steal github secrets is to be able to access the machine that is executing the Github Action** (in that scenario you will be able to access only the secrets declared for the Action).

### Git Environments

Github allows to create **environments** where you can save **secrets**. Then, you can give the github action access to the secrets inside the environment with something like:

```yaml
jobs:
  deployment:
    runs-on: ubuntu-latest
    environment: env_name
```

You can configure an environment to be **accessed** by **all branches** (default), **only protected** branches or **specify** which branches can access it.

### Git Action Box

A Github Action can be **executed inside the github environment** or can be executed in a **third party infrastructure** configured by the user.

Several organizations will allow to run Github Actions in a **third party infrastructure** as it use to be **cheaper**.

You can **list the self-hosted runners** of an organization in _https://github.com/organizations/\<org\_name>/settings/actions/runners_

The way to find which **Github Actions are being executed in non-github infrastructure** is to search for `runs-on: self-hosted` in the Github Action configuration yaml.

It's **not possible to run a Github Action of an organization inside a self hosted box** of a different organization because **a unique token is generated for the Runner** when configuring it to know where the runner belongs.

If the custom **Github Runner is configured in a machine inside AWS or GCP** for example, the Action **could have access to the metadata endpoint** and **steal the token of the service account** the machine is running with.

### Git Action Compromise

If all actions (or a malicious action) are allowed a user could use a **Github action** that is **malicious** and will **compromise** the **container** where it's being executed.

{% hint style="danger" %}
A **malicious Github Action** run could be **abused** by the attacker to:

* **Steal all the secrets** the Action has access to
* **Move laterally** if the Action is executed inside a **third party infrastructure** where the SA token used to run the machine can be accessed (probably via the metadata service)
* **Abuse the token** used by the **workflow** to **steal the code of the repo** where the Action is executed or **even modify it**.
{% endhint %}

## Branch Protections

Branch protections are designed to **not give complete control of a repository** to the users. The goal is to **put several protection methods before being able to write code inside some branch**.

The **branch protections of a repository** can be found in _https://github.com/\<orgname>/\<reponame>/settings/branches_

{% hint style="info" %}
It's **not possible to set a branch protection at organization level**. So all of them must be declared on each repo.
{% endhint %}

Different protections can be applied to a branch (like to master):

* You can **require a PR before merging** (so you cannot directly merge code over the branch). If this is select different other protections can be in place:
  * **Require a number of approvals**. It's very common to require 1 or 2 more people to approve your PR so a single user isn't capable of merge code directly.
  * **Dismiss approvals when new commits are pushed**. If not, a user may approve legit code and then the user could add malicious code and merge it.
  * **Require reviews from Code Owners**. At least 1 code owner of the repo needs to approve the PR (so "random" users cannot approve it)
  * **Restrict who can dismiss pull request reviews.** You can specify people or teams allowed to dismiss pull request reviews.
  * **Allow specified actors to bypass pull request requirements**. These users will be able to bypass previous restrictions.
* **Require status checks to pass before merging.** Some checks needs to pass before being able to merge the commit (like a github action checking there isn't any cleartext secret).
* **Require conversation resolution before merging**. All comments on the code needs to be resolved before the PR can be merged.
* **Require signed commits**. The commits need to be signed.
* **Require linear history.** Prevent merge commits from being pushed to matching branches.
* **Include administrators**. If this isn't set, admins can bypass the restrictions.
* **Restrict who can push to matching branches**. Restrict who can send a PR.

{% hint style="info" %}
As you can see, even if you managed to obtain some credentials of a user, **repos might be protected avoiding you to pushing code to master** for example to compromise the CI/CD pipeline.
{% endhint %}

## References

* [https://docs.github.com/en/organizations/managing-access-to-your-organizations-repositories/repository-roles-for-an-organization](https://docs.github.com/en/organizations/managing-access-to-your-organizations-repositories/repository-roles-for-an-organization)
* [https://docs.github.com/en/enterprise-server@3.3/admin/user-management/managing-users-in-your-enterprise/roles-in-an-enterprise](https://docs.github.com/en/enterprise-server@3.3/admin/user-management/managing-users-in-your-enterprise/roles-in-an-enterprise)[https://docs.github.com/en/enterprise-server](https://docs.github.com/en/enterprise-server@3.3/admin/user-management/managing-users-in-your-enterprise/roles-in-an-enterprise)
* [https://docs.github.com/en/get-started/learning-about-github/access-permissions-on-github](https://docs.github.com/en/get-started/learning-about-github/access-permissions-on-github)
* [https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-github-user-account/managing-user-account-settings/permission-levels-for-user-owned-project-boards](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-github-user-account/managing-user-account-settings/permission-levels-for-user-owned-project-boards)
* [https://docs.github.com/en/actions/security-guides/encrypted-secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)

