# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## Authorization Database

The Security framework's Authorization Services let privileged helpers and other components evaluate named authorization rights. On current macOS versions, many of those rules are persisted in `/var/db/auth.db` and evaluated by `authd`; this file and its SQLite schema are implementation details and can change between releases.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

System defaults have historically been seeded from `/System/Library/Security/authorization.plist`, and installers or privileged services may add named rights. Prefer the supported `security authorizationdb read|write|remove` interface over editing the database directly.<sup>[[3]](#references)</sup>

The `rules` table observed on the documented build contains the following columns. Treat this as a forensic map, not a stable public schema:

- **id**: A unique identifier for each rule, automatically incremented and serving as the primary key.
- **name**: The unique name of the rule used to identify and reference it within the authorization system.
- **type**: Specifies the type of the rule, restricted to values 1 or 2 to define its authorization logic.
- **class**: Categorizes the rule into a specific class, ensuring it is a positive integer.
  - Common rule classes include `allow`, `deny`, `user`, `rule`, and `evaluate-mechanisms`. Mechanisms can be built-ins or Security Agent plug-ins under `/System/Library/CoreServices/SecurityAgentPlugins/` or `/Library/Security/SecurityAgentPlugins/`.<sup>[[2]](#references)</sup>
- **group**: Indicates the user group associated with the rule for group-based authorization.
- **kofn**: Represents the "k-of-n" parameter, determining how many subrules must be satisfied out of a total number.
- **timeout**: Defines the duration in seconds before the authorization granted by the rule expires.
- **flags**: Contains various flags that modify the behavior and characteristics of the rule.
- **tries**: Limits the number of allowed authorization attempts to enhance security.
- **version**: Tracks the version of the rule for version control and updates.
- **created**: Records the timestamp when the rule was created for auditing purposes.
- **modified**: Stores the timestamp of the last modification made to the rule.
- **hash**: Holds a hash value of the rule to ensure its integrity and detect tampering.
- **identifier**: Provides a unique string identifier, such as a UUID, for external references to the rule.
- **requirement**: Contains serialized data defining the rule's specific authorization requirements and mechanisms.
- **comment**: Offers a human-readable description or comment about the rule for documentation and clarity.

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

The following decoded rule illustrates `authenticate-admin-nonshared` on a documented macOS version:<sup>[[1]](#references)</sup>

```json
{
  "allow-root": "false",
  "authenticate-user": "true",
  "class": "user",
  "comment": "Authenticate as an administrator.",
  "group": "admin",
  "session-owner": "false",
  "shared": "false",
  "timeout": "30",
  "tries": "10000",
  "version": "1"
}
```

## Authd

`authd` is the XPC service that evaluates Authorization Services requests. On current macOS builds its bundle can be inspected at `/System/Library/Frameworks/Security.framework/XPCServices/authd.xpc`; the path is an implementation detail and may differ across releases. Older releases wrote `/var/log/authd.log`; current releases primarily use the unified logging system, which can be queried with `log show`/`log stream` using an `authd` process predicate.<sup>[[2]](#references)</sup><sup>[[5]](#references)</sup>

The `security` tool exposes several Authorization Services operations. A historical example invokes `AuthorizationExecuteWithPrivileges` with `security execute-with-privileges /bin/ls`. Apple deprecated that API in macOS 10.7; modern privileged helpers should use a launchd-managed helper and XPC authorization instead.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>

On releases that still support it, this uses `/usr/libexec/security_authtrampoline` and displays an authorization prompt before running the command as root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Overview of the macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)
- [2] [Apple Authorization Services Programming Guide (archive)](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/)
- [3] [`security(1)` macOS manual page](https://keith.github.io/xcode-man-pages/security.1.html)
- [4] [Apple - Daemons and Services Programming Guide: Creating launchd jobs](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [5] [Apple open-source Security project - `authd`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/authd)


{{#include ../../../banners/hacktricks-training.md}}
