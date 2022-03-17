# Concourse

**Concourse allows you to build pipelines to automatically run tests, actions and build images whenever you need it (time based, when something happens...)**

## User Roles & Permissions

Concourse comes with five roles:

* _Concourse_ **Admin**: This role is only given to owners of the **main team** (default initial concourse team). Admins can **configure other teams** (e.g.: `fly set-team`, `fly destroy-team`...). The permissions of this role cannot be affected by RBAC.
* **owner**: Team owners can **modify everything within the team**.
* **member**: Team members can **read and write** within the **teams assets** but cannot modify the team settings.
* **pipeline-operator**: Pipeline operators can perform **pipeline operations** such as triggering builds and pinning resources, however they cannot update pipeline configurations.
* **viewer**: Team viewers have **"read-only" access to a team** and its pipelines.

{% hint style="info" %}
Moreover, the **permissions of the roles owner, member, pipeline-operator and viewer can be modified** configuring RBAC (configuring more specifically it's actions). Read more about it in: [https://concourse-ci.org/user-roles.html](https://concourse-ci.org/user-roles.html)
{% endhint %}

Note that Concourse **groups pipelines inside Teams**. Therefore users belonging to a Team will be able to manage those pipelines and **several Teams** might exist. A user can belong to several Teams and have different permissions inside each of them.

##

## References

* [https://concourse-ci.org/internals.html#architecture-worker](https://concourse-ci.org/internals.html#architecture-worker)
