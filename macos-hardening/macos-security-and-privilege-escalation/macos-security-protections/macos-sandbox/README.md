# macOS Sandbox

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

MacOS Sandbox (initially called Seatbelt) **limits applications** running inside the sandbox to the **allowed actions specified in the Sandbox profile** the app is running with. This helps to ensure that **the application will be accessing only expected resources**.

Any app with the **entitlement** **`com.apple.security.app-sandbox`** will be executed inside the sandbox. **Apple binaries** are usually executed inside a Sandbox, and all applications from the **App Store have that entitlement**. So several applications will be executed inside the sandbox.

In order to control what a process can or cannot do the **Sandbox has hooks** in almost any operation a process might try (including most syscalls) using **MACF**. However, d**epending** on the **entitlements** of the app the Sandbox might be more permissive with the process.

Some important components of the Sandbox are:

* The **kernel extension** `/System/Library/Extensions/Sandbox.kext`
* The **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* A **daemon** running in userland `/usr/libexec/sandboxd`
* The **containers** `~/Library/Containers`

### Containers

Every sandboxed application will have its own container in `~/Library/Containers/{CFBundleIdentifier}` :

```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```

Inside each bundle id folder you can find the **plist** and the **Data directory** of the App with a structure that mimics the Home folder:

```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```

{% hint style="danger" %}
Note that even if the symlinks are there to "escape" from the Sandbox and access other folders, the App still needs to **have permissions** to access them. These permissions are inside the **`.plist`** in the `RedirectablePaths`.
{% endhint %}

The **`SandboxProfileData`** is the compiled sandbox profile CFData escaped to B64.

```bash
# Get container config
## You need FDA to access the file, not even just root can read it
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...
		
# In this file you can find the entitlements:
<key>Entitlements</key>
	<dict>
		<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
		<true/>
		<key>com.apple.accounts.appleaccount.fullaccess</key>
		<true/>
		<key>com.apple.appattest.spi</key>
		<true/>
		<key>keychain-access-groups</key>
		<array>
			<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
			<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
		</array>
[...]

# Some parameters
<key>Parameters</key>
	<dict>
		<key>_HOME</key>
		<string>/Users/username</string>
		<key>_UID</key>
		<string>501</string>
		<key>_USER</key>
		<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
	<array>
		<string>/Users/username/Downloads</string>
		<string>/Users/username/Documents</string>
		<string>/Users/username/Library/Calendars</string>
		<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
	<array/>
[...]
```

{% hint style="warning" %}
Everything created/modified by a Sandboxed application will get the **quarantine attribut**e. This will prevent a sandbox space by triggering Gatekeeper if the sandbox app tries to execute something with **`open`**.
{% endhint %}

## Sandbox Profiles

The Sandbox profiles are configuration files that indicate what is going to be **allowed/forbidden** in that **Sandbox**. It uses the **Sandbox Profile Language (SBPL)**, which uses the [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)) programming language.

Here you can find an example:

```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
    (subpath "/Users/username/")
    (literal "/tmp/afile")
    (regex #"^/private/etc/.*")
)

(allow mach-lookup
    (global-name "com.apple.analyticsd")
)
```

{% hint style="success" %}
Check this [**research**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **to check more actions that could be allowed or denied.**

Note that in the compiled version of a profile the name of the operations are substituded by their entries in an array known by the dylib and the kext, making the compiled version shorter and more difficult to read.
{% endhint %}

Important **system services** also run inside their own custom **sandbox** such as the `mdnsresponder` service. You can view these custom **sandbox profiles** inside:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**
* Other sandbox profiles can be checked in [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

**App Store** apps use the **profile** **`/System/Library/Sandbox/Profiles/application.sb`**. You can check in this profile how entitlements such as **`com.apple.security.network.server`** allows a process to use the network.

SIP is a Sandbox profile called platform\_profile in /System/Library/Sandbox/rootless.conf

### Sandbox Profile Examples

To start an application with an **specific sandbox profile** you can use:

```bash
sandbox-exec -f example.sb /Path/To/The/Application
```

{% tabs %}
{% tab title="touch" %}
{% code title="touch.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}

```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```

{% code title="touch2.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
{% endcode %}

{% code title="touch3.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
Note that the **Apple-authored** **software** that runs on **Windows** **doesn’t have additional security precautions**, such as application sandboxing.
{% endhint %}

Bypasses examples:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (they are able to write files outside the sandbox whose name starts with `~$`).

### Sandbox Tracing

#### Via profile

It's possible to trace all the checks sandbox performs every time an action is checked. For it just create the following profile:

{% code title="trace.sb" %}
```scheme
(version 1)
(trace /tmp/trace.out)
```
{% endcode %}

Ans then just execute something using that profile:

```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```

In `/tmp/trace.out` you will be able to see each sandbox check performed every-time it was called (so, lots of duplicates).

It's also possible to trace the sandbox using the **`-t`** parameter: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Via API

The function `sandbox_set_trace_path` exported by `libsystem_sandbox.dylib` allows to specify a trace filename where sandbox checks will be written to.\
It's also possible to do something similar calling `sandbox_vtrace_enable()` and getting then the logs error from the buffer calling `sandbox_vtrace_report()`.

### Sandbox Inspection

`libsandbox.dylib` exports a function called sandbox\_inspect\_pid which gives a list of the sandbox state of a process (including extensions). However, only platform binaries can use this function.

### MacOS & iOS Sandbox Profiles

MacOS stores system sandbox profiles in two locations: **/usr/share/sandbox/** and **/System/Library/Sandbox/Profiles**.

And if a third-party application carry the _**com.apple.security.app-sandbox**_ entitlement, the system applies the **/System/Library/Sandbox/Profiles/application.sb** profile to that process.

In iOS, the default profile is called **container** and we don't have the SBPL text representation. In memory, this sandbox is represented as Allow/Deny binary tree for each permissions from the sandbox.

### Custom SBPL in App Store apps

It could be possible for companies to make their apps run **with custom Sandbox profiles** (instead of with the default one). They need to use the entitlement **`com.apple.security.temporary-exception.sbpl`** which needs to be authorized by Apple.

It's possible to check the definition of this entitlement in **`/System/Library/Sandbox/Profiles/application.sb:`**

```scheme
(sandbox-array-entitlement
  "com.apple.security.temporary-exception.sbpl"
  (lambda (string)
    (let* ((port (open-input-string string)) (sbpl (read port)))
      (with-transparent-redirection (eval sbpl)))))
```

This will **eval the string after this entitlement** as an Sandbox profile.

### Compiling & decompiling a Sandbox Profile

The **`sandbox-exec`** tool uses the functions `sandbox_compile_*` from `libsandbox.dylib`. The main functions exported are: `sandbox_compile_file` (expects a file path, param `-f`), `sandbox_compile_string` (expects a string, param `-p`), `sandbox_compile_name` (expects a name of a container, param `-n`), `sandbox_compile_entitlements` (expects entitlements plist).

This reversed and [**open sourced version of the tool sandbox-exec**](https://newosxbook.com/src.jl?tree=listings\&file=/sandbox\_exec.c) allows to make **`sandbox-exec`** write into a file the compiled sandbox profile.

Moreover, to confine a process inside a container it might call `sandbox_spawnattrs_set[container/profilename]` and pass a container or pre-existing profile.

## Debug & Bypass Sandbox

On macOS, unlike iOS where processes are sandboxed from the start by the kernel, **processes must opt-in to the sandbox themselves**. This means on macOS, a process is not restricted by the sandbox until it actively decides to enter it, although App Store apps are always sandboxed.

Processes are automatically Sandboxed from userland when they start if they have the entitlement: `com.apple.security.app-sandbox`. For a detailed explanation of this process check:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

## **Sandbox Extensions**

Extensions allow to give further privileges to an object and are giving calling one of the functions:

* `sandbox_issue_extension`
* `sandbox_extension_issue_file[_with_new_type]`
* `sandbox_extension_issue_mach`
* `sandbox_extension_issue_iokit_user_client_class`
* `sandbox_extension_issue_iokit_registry_rentry_class`
* `sandbox_extension_issue_generic`
* `sandbox_extension_issue_posix_ipc`

The extensions are stored in the second MACF label slot accessible from the process credentials. The following **`sbtool`** can access this information.

Note that extensions are usually granted by allowed processes, for example, `tccd` will grant the extension token of `com.apple.tcc.kTCCServicePhotos` when a process tried to access the photos and was allowed in a XPC message. Then, the process will need to consume the extension token so it gets added to it.\
Note that the extension tokens are long hexadecimals that encode the granted permissions. However they don't have the allowed PID hardcoded which means that any process with access to the token might be **consumed by multiple processes**.

Note that extensions are very related to entitlements also, so having certain entitlements might automatically grant certain extensions.

### **Check PID Privileges**

[**According to this**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), the **`sandbox_check`** functions (it's a `__mac_syscall`), can check **if an operation is allowed or not** by the sandbox in a certain PID, audit token or unique ID.

The [**tool sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) (find it [compiled here](https://newosxbook.com/articles/hitsb.html)) can check if a PID can perform a certain actions:

```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```

### \[un]suspend

It's also possible to suspend and unsuspend the sandbox using the functions `sandbox_suspend` and `sandbox_unsuspend` from `libsystem_sandbox.dylib`.

Note that to call the suspend function some entitlements are checked in order to authorize the caller to call it like:

* com.apple.private.security.sandbox-manager
* com.apple.security.print
* com.apple.security.temporary-exception.audio-unit-host

## mac\_syscall

This system call (#381) expects one string first argument which will indicate the module to run, and then a code in the second argument which will indicate the function to run. Then the third argument will depend on the function executed.

The function `___sandbox_ms` call wraps `mac_syscall` indicating in the first argument `"Sandbox"` just like `___sandbox_msp` is a wrapper of `mac_set_proc` (#387). Then, the some of supported codes by `___sandbox_ms` can be found in this table:

* **set\_profile (#0)**: Apply a compiled or named profile to a process.
* **platform\_policy (#1)**: Enforce platform-specific policy checks (varies between macOS and iOS).
* **check\_sandbox (#2)**: Perform a manual check of a specific sandbox operation.
* **note (#3)**: Adds ana nontation to a Sandbox
* **container (#4)**: Attach an annotation to a sandbox, typically for debugging or identification.
* **extension\_issue (#5)**: Generate a new extension for a process.
* **extension\_consume (#6)**: Consume a given extension.
* **extension\_release (#7)**: Release the memory tied to a consumed extension.
* **extension\_update\_file (#8)**: Modify parameters of an existing file extension within the sandbox.
* **extension\_twiddle (#9)**: Adjust or modify an existing file extension (e.g., TextEdit, rtf, rtfd).
* **suspend (#10)**: Temporarily suspend all sandbox checks (requires appropriate entitlements).
* **unsuspend (#11)**: Resume all previously suspended sandbox checks.
* **passthrough\_access (#12)**: Allow direct passthrough access to a resource, bypassing sandbox checks.
* **set\_container\_path (#13)**: (iOS only) Set a container path for an app group or signing ID.
* **container\_map (#14)**: (iOS only) Retrieve a container path from `containermanagerd`.
* **sandbox\_user\_state\_item\_buffer\_send (#15)**: (iOS 10+) Set user mode metadata in the sandbox.
* **inspect (#16)**: Provide debug information about a sandboxed process.
* **dump (#18)**: (macOS 11) Dump the current profile of a sandbox for analysis.
* **vtrace (#19)**: Trace sandbox operations for monitoring or debugging.
* **builtin\_profile\_deactivate (#20)**: (macOS < 11) Deactivate named profiles (e.g., `pe_i_can_has_debugger`).
* **check\_bulk (#21)**: Perform multiple `sandbox_check` operations in a single call.
* **reference\_retain\_by\_audit\_token (#28)**: Create a reference for an audit token for use in sandbox checks.
* **reference\_release (#29)**: Release a previously retained audit token reference.
* **rootless\_allows\_task\_for\_pid (#30)**: Verify whether `task_for_pid` is allowed (similar to `csr` checks).
* **rootless\_whitelist\_push (#31)**: (macOS) Apply a System Integrity Protection (SIP) manifest file.
* **rootless\_whitelist\_check (preflight) (#32)**: Check the SIP manifest file before execution.
* **rootless\_protected\_volume (#33)**: (macOS) Apply SIP protections to a disk or partition.
* **rootless\_mkdir\_protected (#34)**: Apply SIP/DataVault protection to a directory creation process.

## Sandbox.kext

Note that in iOS the kernel extension contains **hardcoded all the profiles** inside the `__TEXT.__const` segment to avoid them being modified. The following are some interesting functions from the kernel extension:

* **`hook_policy_init`**: It hooks `mpo_policy_init` and it's called after `mac_policy_register`. It performs most of the initializations of the Sandbox. It also initializes SIP.
* **`hook_policy_initbsd`**: It sets up the sysctl interface registering `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` and `security.mac.sandbox.debug_mode` (if booed with `PE_i_can_has_debugger`).
* **`hook_policy_syscall`**: It's called by `mac_syscall` with "Sandbox" as first argument and code indicating the operation in the second one. A switch is used to find the code to run according to the requested code.

### MACF Hooks

**`Sandbox.kext`** uses more than a hundred of hooks via MACF. Most of the hooks will just check some trivial cases that allows to perform the action if it not, they will call **`cred_sb_evalutate`** with the **credentials** from MACF and a number corresponding to the **operation** to perform and a **buffer** for the output.

A good example of that is the function  **`_mpo_file_check_mmap`** which hooked **`mmap`** and which will start checking if the new memory is going to be writable (and if not allow the execution), then it'll check if its used for the dyld shared cache and if so allow the execution, and finally it'll call **`sb_evaluate_internal`** (or one of its wrappers) to perform further allowance checks.

Moreover, out of the hundred(s) hooks Sandbox uses, there are 3 in particular that are very interesting:

* `mpo_proc_check_for`: It applies the profile if needed and if it wasn't previously applied
* `mpo_vnode_check_exec`: Called when a process loads the associated binary, then a profile check is perfomed and also a check forbidding SUID/SGID executions.
* `mpo_cred_label_update_execve`: This is called when the label is assigned. This is the longest one as it's called when the binary is fully loaded but it hasn't been executed yet. It'll perform actions such as creating the sandbox object, attach sandbox struct to the kauth credentials, remove access to mach ports...

Note that **`_cred_sb_evalutate`** is a wrapper over **`sb_evaluate_internal`** and this function gets the credentials passed and then performs the evaluation using the **`eval`** function which usually evaluates the **platform profile** which is by default applied to all processes and then the **specific process profile**. Note that the platform profile is one of the main components of **SIP** in macOS.

## Sandboxd

Sandbox also has a user daemon running exposing the XPC Mach service `com.apple.sandboxd` and binding the special port 14 (`HOST_SEATBELT_PORT`) which the kernel extension uses to communicate with it. It exposes some functions using MIG.

## References

* [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

