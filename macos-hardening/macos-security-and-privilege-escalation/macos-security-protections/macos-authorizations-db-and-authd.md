# macOS Authorizations DB & Authd



{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## **Athorizarions DB**

The database located in `/var/db/auth.db` is database used to store permissions to perform sensitive operations. These operations are performed completely in **user space** and are usually used by **XPC services** which need to check **if the calling client is authorized** to perform certain action checking this database.

Initially this database is created from the content of `/System/Library/Security/authorization.plist`. Then, some services might add or modify this dataabse to add other permissions to it.

The rules are stored in the `rules` table inside the database and contains the folliwing colmns:

* **id**: A unique identifier for each rule, automatically incremented and serving as the primary key.
* **name**: The unique name of the rule used to identify and reference it within the authorization system.
* **type**: Specifies the type of the rule, restricted to values 1 or 2 to define its authorization logic.
* **class**: Categorizes the rule into a specific class, ensuring it is a positive integer.
  * "allow" for allow, "deny" for deny, "user" if the group property indicated a group which membership allows the access, "rule" indicates in an array a rule to be fulfilled, "evaluate-mechanisms" followed by a `mechanisms` array which are either builtins or a name of a bundle inside `/System/Library/CoreServices/SecurityAgentPlugins/` or /Library/Security//SecurityAgentPlugins
* **group**: Indicates the user group associated with the rule for group-based authorization.
* **kofn**: Represents the "k-of-n" parameter, determining how many subrules must be satisfied out of a total number.
* **timeout**: Defines the duration in seconds before the authorization granted by the rule expires.
* **flags**: Contains various flags that modify the behavior and characteristics of the rule.
* **tries**: Limits the number of allowed authorization attempts to enhance security.
* **version**: Tracks the version of the rule for version control and updates.
* **created**: Records the timestamp when the rule was created for auditing purposes.
* **modified**: Stores the timestamp of the last modification made to the rule.
* **hash**: Holds a hash value of the rule to ensure its integrity and detect tampering.
* **identifier**: Provides a unique string identifier, such as a UUID, for external references to the rule.
* **requirement**: Contains serialized data defining the rule's specific authorization requirements and mechanisms.
* **comment**: Offers a human-readable description or comment about the rule for documentation and clarity.

### Example

```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>class</key>
	<string>rule</string>
	<key>comment</key>
	<string>For modification of TCC settings.</string>
	<key>created</key>
	<real>701369782.01043606</real>
	<key>modified</key>
	<real>701369782.01043606</real>
	<key>rule</key>
	<array>
		<string>authenticate-admin-nonshared</string>
	</array>
	<key>version</key>
	<integer>0</integer>
</dict>
</plist>
```

Moreover in [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) it's possible to see the meaning of `authenticate-admin-nonshared`:

```json
{
  'allow-root' : 'false',
  'authenticate-user' : 'true',
  'class' : 'user',
  'comment' : 'Authenticate as an administrator.',
  'group' : 'admin',
  'session-owner' : 'false',
  'shared' : 'false',
  'timeout' : '30',
  'tries' : '10000',
  'version' : '1'
}
```

## Authd

It's a deamon that will receive requests to authorize clients to perform sensitive actions. It works as a XPC service defined inside the `XPCServices/` folder and use to write its logs in `/var/log/authd.log`.

Moreover using the security tool it's possible to test many `Security.framework` APIs. For example the `AuthorizationExecuteWithPrivileges` running: `security execute-with-privileges /bin/ls`

That will fork and exec `/usr/libexec/security_authtrampoline /bin/ls` as root, which will ask for permissions in a prompt to execute ls as root:

<figure><img src="../../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
