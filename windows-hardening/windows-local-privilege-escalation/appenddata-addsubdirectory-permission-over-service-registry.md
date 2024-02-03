

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


**The original post is** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Summary
The script's output indicates that the current user possesses write permissions on two registry keys:

- `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`
- `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`

To further investigate the permissions of the RpcEptMapper service, the user mentions the use of the regedit GUI and highlights the usefulness of the Advanced Security Settings window's Effective Permissions tab. This tab allows users to check the effective permissions granted to a specific user or group without inspecting individual ACEs.

The screenshot provided displays the permissions for the low-privileged lab-user account. Most permissions are standard, such as Query Value, but one permission stands out: Create Subkey. The generic name for this permission is AppendData/AddSubdirectory, which aligns with what was reported by the script.

The user proceeds to explain that this means they cannot modify certain values directly but can only create new subkeys. They show an example where attempting to modify the ImagePath value results in an access denied error.

However, they clarify that this is not a false positive and that there is an interesting opportunity here. They investigate the Windows registry structure and discover a potential way to leverage the Performance subkey, which doesn't exist by default for the RpcEptMapper service. This subkey could potentially allow for DLL registration and performance monitoring, offering an opportunity for privilege escalation.

They mention that they found documentation related to the Performance subkey and how to use it for performance monitoring. This leads them to create a proof-of-concept DLL and show the code for implementing the required functions: OpenPerfData, CollectPerfData, and ClosePerfData. They also export these functions for external use.

The user demonstrates testing the DLL using rundll32 to ensure it functions as expected, successfully logging information.

Next, they explain that the challenge is to trick the RPC Endpoint Mapper service into loading their Performance DLL. They mention that they observed their log file being created when querying WMI classes related to Performance Data in PowerShell. This allows them to execute arbitrary code in the context of the WMI service, which runs as LOCAL SYSTEM. This provides them with unexpected and elevated access.

In conclusion, the user highlights the unexplained persistence of this vulnerability and its potential impact, which could extend to post-exploitation, lateral movement, and antivirus/EDR evasion.

They also mention that while they initially made the vulnerability public unintentionally through their script, its impact is limited to unsupported versions of Windows (e.g., Windows 7 / Server 2008 R2) with local access.


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


