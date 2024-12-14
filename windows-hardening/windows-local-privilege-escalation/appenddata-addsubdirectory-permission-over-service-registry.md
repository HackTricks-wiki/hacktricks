

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


**The original post is** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Summary

Two registry keys were found to be writable by the current user:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

It was suggested to check the permissions of the **RpcEptMapper** service using the **regedit GUI**, specifically the **Advanced Security Settings** window's **Effective Permissions** tab. This approach enables the assessment of granted permissions to specific users or groups without the need to examine each Access Control Entry (ACE) individually.

A screenshot showed the permissions assigned to a low-privileged user, among which the **Create Subkey** permission was notable. This permission, also referred to as **AppendData/AddSubdirectory**, corresponds with the script's findings.

The inability to modify certain values directly, yet the capability to create new subkeys, was noted. An example highlighted was an attempt to alter the **ImagePath** value, which resulted in an access denied message.

Despite these limitations, a potential for privilege escalation was identified through the possibility of leveraging the **Performance** subkey within the **RpcEptMapper** service's registry structure, a subkey not present by default. This could enable DLL registration and performance monitoring.

Documentation on the **Performance** subkey and its utilization for performance monitoring was consulted, leading to the development of a proof-of-concept DLL. This DLL, demonstrating the implementation of **OpenPerfData**, **CollectPerfData**, and **ClosePerfData** functions, was tested via **rundll32**, confirming its operational success.

The goal was to coerce the **RPC Endpoint Mapper service** into loading the crafted Performance DLL. Observations revealed that executing WMI class queries related to Performance Data via PowerShell resulted in the creation of a log file, enabling the execution of arbitrary code under the **LOCAL SYSTEM** context, thus granting elevated privileges.

The persistence and potential implications of this vulnerability were underscored, highlighting its relevance for post-exploitation strategies, lateral movement, and evasion of antivirus/EDR systems.

Although the vulnerability was initially disclosed unintentionally through the script, it was emphasized that its exploitation is constrained to outdated Windows versions (e.g., **Windows 7 / Server 2008 R2**) and requires local access.

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}



