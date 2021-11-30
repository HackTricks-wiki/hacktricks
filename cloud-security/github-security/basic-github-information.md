# Basic Github Information

## Basic Structure

The basic github environment structure of a big **company** is to own an **enterprise** which owns **several organizations** and each of them may contain **several repositories** and **several groups.**. Smaller companies may just **own one organization and no enterprises**.

From a user point of view a **user** can be a **member** of **different enterprises and organizations**. Within them the user may have **different enterprise, organization and repository roles**.

Moreover, a user may be **part of different groups** with different enterprise, organization or repository roles.

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

* **Read**: Recommended for non-code contributors who want to view or discuss your project
* **Triage**: Recommended for contributors who need to proactively manage issues and pull requests without write access
* **Write**: Recommended for contributors who actively push to your project
* **Maintain**: Recommended for project managers who need to manage the repository without access to sensitive or destructive actions
* **Admin**: Recommended for people who need full access to the project, including sensitive and destructive actions like managing security or deleting a repository

You can compaIt's possIt re the permissions of each role in this table [https://docs.github.com/en/organizations/managing-access-to-your-organizations-repositories/repository-roles-for-an-organization#permissions-for-each-role](https://docs.github.com/en/organizations/managing-access-to-your-organizations-repositories/repository-roles-for-an-organization#permissions-for-each-role)



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

Some security recommendations:

* A GitHub App should **take actions independent of a user** (unless the app is using a [user-to-server](https://docs.github.com/en/apps/building-github-apps/identifying-and-authorizing-users-for-github-apps#user-to-server-requests) token). To keep user-to-server access tokens more secure, you can use access tokens that will expire after 8 hours, and a refresh token that can be exchanged for a new access token. For more information, see "[Refreshing user-to-server access tokens](https://docs.github.com/en/apps/building-github-apps/refreshing-user-to-server-access-tokens)."
* Make sure the GitHub App integrates with **specific repositories**.
* The GitHub App should **connect to a personal account or an organisation**.
* Don't expect the GitHub App to know and do everything a user can.
* **Don't use a GitHub App if you just need a "Login with GitHub" service**. But a GitHub App can use a [user identification flow](https://docs.github.com/en/apps/building-github-apps/identifying-and-authorizing-users-for-github-apps) to log users in _and_ do other things.
* Don't build a GitHub App if you _only_ want to act as a GitHub user and do everything that user can do.
* If you are using your app with GitHub Actions and want to modify workflow files, you must authenticate on behalf of the user with an OAuth token that includes the `workflow` scope. The user must have admin or write permission to the repository that contains the workflow file. For more information, see "[Understanding scopes for OAuth apps](https://docs.github.com/en/apps/building-oauth-apps/understanding-scopes-for-oauth-apps/#available-scopes)."
* **More** in [here](https://docs.github.com/en/developers/apps/getting-started-with-apps/about-apps#about-github-apps).

## References

* [https://docs.github.com/en/organizations/managing-access-to-your-organizations-repositories/repository-roles-for-an-organization](https://docs.github.com/en/organizations/managing-access-to-your-organizations-repositories/repository-roles-for-an-organization)
* [https://docs.github.com/en/enterprise-server@3.3/admin/user-management/managing-users-in-your-enterprise/roles-in-an-enterprise](https://docs.github.com/en/enterprise-server@3.3/admin/user-management/managing-users-in-your-enterprise/roles-in-an-enterprise)[https://docs.github.com/en/enterprise-server](https://docs.github.com/en/enterprise-server@3.3/admin/user-management/managing-users-in-your-enterprise/roles-in-an-enterprise)
* [https://docs.github.com/en/get-started/learning-about-github/access-permissions-on-github](https://docs.github.com/en/get-started/learning-about-github/access-permissions-on-github)
* [https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-github-user-account/managing-user-account-settings/permission-levels-for-user-owned-project-boards](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-github-user-account/managing-user-account-settings/permission-levels-for-user-owned-project-boards)

