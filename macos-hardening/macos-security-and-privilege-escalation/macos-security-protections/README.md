# macOS Security Protections

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

## Gatekeeper

Gatekeeper is usually used to refer to the combination of **Quarantine + Gatekeeper + XProtect**, 3 macOS security modules that will try to **prevent users from executing potentially malicious software downloaded**.

More information in:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Processes Limitants

### MACF



### SIP - System Integrity Protection

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

MacOS Sandbox **limits applications** running inside the sandbox to the **allowed actions specified in the Sandbox profile** the app is running with. This helps to ensure that **the application will be accessing only expected resources**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** is a security framework. It's designed to **manage the permissions** of applications, specifically by regulating their access to sensitive features. This includes elements like **location services, contacts, photos, microphone, camera, accessibility, and full disk access**. TCC ensures that apps can only access these features after obtaining explicit user consent, thereby bolstering privacy and control over personal data.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Launch/Environment Constraints & Trust Cache

Launch constraints in macOS are a security feature to **regulate process initiation** by defining **who can launch** a process, **how**, and **from where**. Introduced in macOS Ventura, they categorize system binaries into constraint categories within a **trust cache**. Every executable binary has set **rules** for its **launch**, including **self**, **parent**, and **responsible** constraints. Extended to third-party apps as **Environment** Constraints in macOS Sonoma, these features help mitigate potential system exploitations by governing process launching conditions.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Malware Removal Tool

The Malware Removal Tool (MRT) is another part of macOS's security infrastructure. As the name suggests, MRT's main function is to **remove known malware from infected systems**.

Once malware is detected on a Mac (either by XProtect or by some other means), MRT can be used to automatically **remove the malware**. MRT operates silently in the background and typically runs whenever the system is updated or when a new malware definition is downloaded (it looks like the rules MRT has to detect malware are inside the binary).

While both XProtect and MRT are part of macOS's security measures, they perform different functions:

* **XProtect** is a preventative tool. It **checks files as they're downloaded** (via certain applications), and if it detects any known types of malware, it **prevents the file from opening**, thereby preventing the malware from infecting your system in the first place.
* **MRT**, on the other hand, is a **reactive tool**. It operates after malware has been detected on a system, with the goal of removing the offending software to clean up the system.

The MRT application is located in **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Background Tasks Management

**macOS** now **alerts** every time a tool uses a well known **technique to persist code execution** (such as Login Items, Daemons...), so the user knows better **which software is persisting**.

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

This runs with a **daemon** located in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` and the **agent** in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

The way **`backgroundtaskmanagementd`** knows something is installed in a persistent folder is by **getting the FSEvents** and creating some **handlers** for those.

Moreover, there is a plist file that contains **well known applications** that frequently persists maintained by apple located in: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`

```json
[...]
"us.zoom.ZoomDaemon" => {
    "AssociatedBundleIdentifiers" => [
      0 => "us.zoom.xos"
    ]
    "Attribution" => "Zoom"
    "Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
    "ProgramArguments" => [
      0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
    ]
    "TeamIdentifier" => "BJ4HAAB9B3"
  }
[...]
```

### Enumeration

It's possible to **enumerate all** the configured background items running the Apple cli tool:

```bash
# The tool will always ask for the users password
sfltool dumpbtm
```

Moreover, it's also possible to list this information with [**DumpBTM**](https://github.com/objective-see/DumpBTM).

```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```

This information is being stored in **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** and the Terminal needs FDA.

### Messing with BTM

When a new persistence is found an event of type **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. So, any way to **prevent** this **event** from being sent or the **agent from alerting** the user will help an attacker to _**bypass**_ BTM.

* **Reseting the database**: Running the following command will reset the database (should rebuild it from the ground), however, for some reason, after running this, **no new persistence will be alerted until the system is rebooted**.
  * **root** is required.

```bash
# Reset the database
sfltool resettbtm
```

* **Stop the Agent**: It's possible to send a stop signal to the agent so it **won't be alerting the user** when new detections are found.

```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```

* **Bug**: If the **process that created the persistence exists fast right after it**, the daemon will try to **get information** about it, **fail**, and **won't be able to send the event** indicating that a new thing is persisting.

References and **more information about BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

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
