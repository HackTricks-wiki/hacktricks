# macOS - AMFI - AppleMobileFileIntegrity

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



## AppleMobileFileIntegrity.kext and amfid

It focuses on enforcing the integrity of the code running on the system providing the logic behind XNU's code signature verification. It's also able to check entitlements and handle other sensitive tasks such as allowing debugging or obtaining task ports.

Moreover, for some operations, the kext prefers to contact the user space running daemon `/usr/libexec/amfid`. This trust relationship has been abused in several jailbreaks.

AMFI uses **MACF** policies and it registers its hooks the moment it's started. Also, preventing its loading or unloading it could trigger a kernel panic. However, there are some boot arguments that allow to debilitate AMFI:

* `amfi_unrestricted_task_for_pid`: Allow task\_for\_pid to be allowed without required entitlements
* `amfi_allow_any_signature`: Allow any code signature
* `cs_enforcement_disable`: System-wide argument used to disable code signing enforcement
* `amfi_prevent_old_entitled_platform_binaries`: Void platform binaries with entitlements
* `amfi_get_out_of_my_way`: Disables amfi completely

These are some of the MACF policies it registers:

* **`cred_check_label_update_execve:`** Label update will be performed and return 1
* **`cred_label_associate`**: Update AMFI's mac label slot with label
* **`cred_label_destroy`**: Remove AMFI’s mac label slot
* **`cred_label_init`**: Move 0 in AMFI's mac label slot
* **`cred_label_update_execve`:** It checks the entitlements of the process to see it should be allowed to modify the labels.
* **`file_check_mmap`:** It checks if mmap is acquiring memory and setting it as executable. In that case it check if library validation is needed and if so, it calls the library validation function.
* **`file_check_library_validation`**: Calls the library validation function which checks among other things if a platform binary is loading another platform binary or if the process and the new loaded file have the same TeamID. Certain entitlements will also allow to load any library.
* **`policy_initbsd`**: Sets up trusted NVRAM Keys
* **`policy_syscall`**: It checks DYLD policies like if the binary has unrestricted segments, if it should allow env vars... this is also called when a process is started via `amfi_check_dyld_policy_self()`.
* **`proc_check_inherit_ipc_ports`**: It checks if when a processes executes a new binary other processes with SEND rights over the task port of the process should keep them or not. Platform binaries are allowed, `get-task-allow` entitled allows it, `task_for_pid-allow` entitles are allowed and binaries with the same TeamID.
* **`proc_check_expose_task`**: enforce entitlements
* **`amfi_exc_action_check_exception_send`**: An exception message is sent to debugger
* **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Label lifecycle during exception handling (debugging)
* **`proc_check_get_task`**: Checks entitlements like `get-task-allow` which allows other processes to get the tasks port and `task_for_pid-allow`, which allow the process to get other processes tasks ports. If neither of those, it calls up to `amfid permitunrestricteddebugging` to check if it's allowed.
* **`proc_check_mprotect`**: Deny if `mprotect` is called with the flag `VM_PROT_TRUSTED` which indicates that the region must be treated as if it has a valid code signature.
* **`vnode_check_exec`**: Gets called when a executable files are loaded in memory and sets `cs_hard | cs_kill` which will kill the process if any of the pages becomes invalid
* **`vnode_check_getextattr`**: MacOS: Check `com.apple.root.installed` and `isVnodeQuarantined()`
* **`vnode_check_setextattr`**: As get + com.apple.private.allow-bless and internal-installer-equivalent entitlement
* &#x20;**`vnode_check_signature`**: Code that calls XNU to check the code signature using entitlements, trust cache and `amfid`
* &#x20;**`proc_check_run_cs_invalid`**: It intercepts `ptrace()` calls (`PT_ATTACH` and `PT_TRACE_ME`). It checks for any of the entitlements `get-task-allow`, `run-invalid-allow` and `run-unsigned-code` and if none, it checks if debugging is permitted.
* **`proc_check_map_anon`**: If mmap is called with the **`MAP_JIT`** flag, AMFI will checks for the `dynamic-codesigning` entitlement.

`AMFI.kext` also exposes an API for other kernel extensions, and it's possible to find its dependencies with:

```bash
kextstat | grep " 19 " | cut -c2-5,50- | cut -d '(' -f1
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
   8   com.apple.kec.corecrypto
  19   com.apple.driver.AppleMobileFileIntegrity
  22   com.apple.security.sandbox
  24   com.apple.AppleSystemPolicy
  67   com.apple.iokit.IOUSBHostFamily
  70   com.apple.driver.AppleUSBTDM
  71   com.apple.driver.AppleSEPKeyStore
  74   com.apple.iokit.EndpointSecurity
  81   com.apple.iokit.IOUserEthernet
 101   com.apple.iokit.IO80211Family
 102   com.apple.driver.AppleBCMWLANCore
 118   com.apple.driver.AppleEmbeddedUSBHost
 134   com.apple.iokit.IOGPUFamily
 135   com.apple.AGXG13X
 137   com.apple.iokit.IOMobileGraphicsFamily
 138   com.apple.iokit.IOMobileGraphicsFamily-DCP
 162   com.apple.iokit.IONVMeFamily
```

## amfid

This is the user mode running daemon that `AMFI.kext` will use to check for code signatures in user mode.\
For `AMFI.kext` to communicate with the daemon it uses mach messages over the port `HOST_AMFID_PORT` which is the special port `18`.

Note that in macOS it's no longer possible for root processes to hijack special ports as they are protected by `SIP` and only launchd can get them. In iOS it's checked that the process sending the response back has the CDHash hardcoded of `amfid`.

It's possible to see when `amfid` is requested to check a binary and the response of it by debugging it and setting a breakpoint in `mach_msg`.

Once a message is received via the special port **MIG** is used to send each function to the function it's calling. The main functions were reversed and explained inside the book.

## Provisioning Profiles

A provisioning profile can be used to sign code. There are **Developer** profiles that can be used to sign code and test it, and **Enterprise** profiles which can be used in all devices.

After an App is submitted to the Apple Store, if approved, it's signed by Apple and the provisioning profile is no longer needed.

A profile usually use the extension `.mobileprovision` or `.provisionprofile` and can be dumped with:

```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```

Although sometimes referred as certificated, these provisioning profiles have more than a certificate:

* **AppIDName:** The Application Identifier
* **AppleInternalProfile**: Designates this as an Apple Internal profile
* **ApplicationIdentifierPrefix**: Prepended to AppIDName (same as TeamIdentifier)
* **CreationDate**: Date in `YYYY-MM-DDTHH:mm:ssZ` format
* **DeveloperCertificates**: An array of (usually one) certificate(s), encoded as Base64 data
* **Entitlements**: The entitlements allowed with entitlements for this profile
* **ExpirationDate**: Expiration date in `YYYY-MM-DDTHH:mm:ssZ` format
* **Name**: The Application Name, the same as AppIDName
* **ProvisionedDevices**: An array (for developer certificates) of UDIDs this profile is valid for
* **ProvisionsAllDevices**: A boolean (true for enterprise certificates)
* **TeamIdentifier**: An array of (usually one) alphanumeric string(s) used to identify the developer for inter-app interaction purposes
* **TeamName**: A human-readable name used to identify the developer
* **TimeToLive**: Validity (in days) of the certificate
* **UUID**: A Universally Unique Identifier for this profile
* **Version**: Currently set to 1

Note that the entitlements entry will contain a restricted set of entitlements and the provisioning profile will only be able to give those specific entitlements to prevent giving Apple private entitlements.

Note that profiles are usually located in `/var/MobileDeviceProvisioningProfiles` and it's possible to check them with **`security cms -D -i /path/to/profile`**

## **libmis.dyld**

This is the external library that `amfid` calls i order to ask if it should allow something or not. This has been historically abused in jailbreaking by running a backdoored version of it that would allow everything.

In macOS this is inside `MobileDevice.framework`.

## AMFI Trust Caches

iOS AMFI maintains a lost of known hashes which are signed ad-hoc, called the **Trust Cache** and found in the kext's `__TEXT.__const` section. Note that in very specific and sensitive operations It's possible to extend this Trust Cache with an external file.

## References

* [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

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

