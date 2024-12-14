# macOS Launch/Environment Constraints & Trust Cache

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

## Basic Information

Launch constraints in macOS were introduced to enhance security by **regulating how, who, and from where a process can be initiated**. Initiated in macOS Ventura, they provide a framework that categorizes **each system binary into distinct constraint categories**, which are defined within the **trust cache**, a list containing system binaries and their respective hashes​. These constraints extend to every executable binary within the system, entailing a set of **rules** delineating the requirements for **launching a particular binary**. The rules encompass self constraints that a binary must satisfy, parent constraints required to be met by its parent process, and responsible constraints to be adhered to by other relevant entities​.

The mechanism extends to third-party apps through **Environment Constraints**, beginning from macOS Sonoma, allowing developers to protect their apps by specifying a **set of keys and values for environment constraints.**

You define **launch environment and library constraints** in constraint dictionaries that you either save in **`launchd` property list files**, or in **separate property list** files that you use in code signing.

There are 4 types of constraints:

* **Self Constraints**: Constrains applied to the **running** binary.
* **Parent Process**: Constraints applied to the **parent of the process** (for example **`launchd`** running a XP service)
* **Responsible Constraints**: Constraints applied to the **process calling the service** in a XPC communication
* **Library load constraints**: Use library load constraints to selectively describe code that can be loaded

So when a process tries to launch another process — by calling `execve(_:_:_:)` or `posix_spawn(_:_:_:_:_:_:)` — the operating system checks that the **executable** file **satisfies** its **own self constraint**. It also checks that the **parent** **process’s** executable **satisfies** the executable’s **parent constraint**, and that the **responsible** **process’s** executable **satisfies the executable’s responsible process constrain**t. If any of these launch constraints aren’t satisfied, the operating system doesn’t run the program.

If when loading a library any part of the **library constraint isn’t true**, your process **doesn’t load** the library.

## LC Categories

A LC as composed by **facts** and **logical operations** (and, or..) that combines facts.

The[ **facts that a LC can use are documented**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints). For example:

* is-init-proc: A Boolean value that indicates whether the executable must be the operating system’s initialization process (`launchd`).
* is-sip-protected: A Boolean value that indicates whether the executable must be a file protected by System Integrity Protection (SIP).
* `on-authorized-authapfs-volume:` A Boolean value that indicates whether the operating system loaded the executable from an authorized, authenticated APFS volume.
* `on-authorized-authapfs-volume`: A Boolean value that indicates whether the operating system loaded the executable from an authorized, authenticated APFS volume.
  * Cryptexes volume
* `on-system-volume:`A Boolean value that indicates whether the operating system loaded the executable from the currently-booted system volume.
  * Inside /System...
* ...

When an Apple binary is signed it **assigns it to a LC category** inside the **trust cache**.

* **iOS 16 LC categories** were [**reversed and documented in here**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
* Current **LC categories (macOS 14** - Somona) have been reversed and their [**descriptions can be found here**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

For example Category 1 is:

```
Category 1:
        Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
        Parent Constraint: is-init-proc
```

* `(on-authorized-authapfs-volume || on-system-volume)`: Must be in System or Cryptexes volume.
* `launch-type == 1`: Must be a system service (plist in LaunchDaemons).
* `validation-category == 1`: An operating system executable.
* `is-init-proc`: Launchd

### Reversing LC Categories

You have more information [**about it in here**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints), but basically, They are defined in **AMFI (AppleMobileFileIntegrity)**, so you need to download the Kernel Development Kit to get the **KEXT**. The symbols starting with **`kConstraintCategory`** are the **interesting** ones. Extracting them you will get a DER (ASN.1) encoded stream that you will need to decode with [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) or the python-asn1 library and its `dump.py` script, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) which will give you a more understandable string.

## Environment Constraints

These are the Launch Constraints set configured in **third party applications**. The developer can select the **facts** and **logical operands to use** in his application to restrict the access to itself.

It's possible to enumerate the Environment Constraints of an application with:

```bash
codesign -d -vvvv app.app
```

## Trust Caches

In **macOS** there are a few trust caches:

* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
* **`/System/Library/Security/OSLaunchPolicyData`**

And in iOS it looks like it's in **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

{% hint style="warning" %}
On macOS running on Apple Silicon devices, if an Apple signed binary is not in the trust cache, AMFI will refuse to load it.
{% endhint %}

### Enumerating Trust Caches

The previous trust cache files are in format **IMG4** and **IM4P**, being IM4P the payload section of a IMG4 format.

You can use [**pyimg4**](https://github.com/m1stadev/PyIMG4) to extract the payload of databases:

{% code overflow="wrap" %}
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
{% endcode %}

(Another option could be to use the tool [**img4tool**](https://github.com/tihmstar/img4tool), which will run even in M1 even if the release is old and for x86\_64 if you install it in the proper locations).

Now you can use the tool [**trustcache**](https://github.com/CRKatri/trustcache) to get the information in a readable format:

```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```

The trust cache follows the following structure, so The **LC category is the 4th column**

```c
struct trust_cache_entry2 {
	uint8_t cdhash[CS_CDHASH_LEN];
	uint8_t hash_type;
	uint8_t flags;
	uint8_t constraintCategory;
	uint8_t reserved0;
} __attribute__((__packed__));
```

Then, you could use a script such as [**this one**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) to extract data.

From that data you can check the Apps with a **launch constraints value of `0`** , which are the ones that aren't constrained ([**check here**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) for what each value is).

## Attack Mitigations

Launch Constrains would have mitigated several old attacks by **making sure that the process won't be executed in unexpected conditions:** For example from unexpected locations or being invoked by an unexpected parent process (if only launchd should be launching it)

Moreover, Launch Constraints also **mitigates downgrade attacks.**

However, they **don't mitigate common XPC** abuses, **Electron** code injections or **dylib injections** without library validation (unless the team IDs that can load libraries are known).

### XPC Daemon Protection

In the Sonoma release, a notable point is the daemon XPC service's **responsibility configuration**. The XPC service is accountable for itself, as opposed to the connecting client being responsible. This is documented in the feedback report FB13206884. This setup might seem flawed, as it allows certain interactions with the XPC service:

- **Launching the XPC Service**: If assumed to be a bug, this setup does not permit initiating the XPC service through attacker code.
- **Connecting to an Active Service**: If the XPC service is already running (possibly activated by its original application), there are no barriers to connecting to it.

While implementing constraints on the XPC service might be beneficial by **narrowing the window for potential attacks**, it doesn't address the primary concern. Ensuring the security of the XPC service fundamentally requires **validating the connecting client effectively**. This remains the sole method to fortify the service's security. Also, it's worth noting that the mentioned responsibility configuration is currently operational, which might not align with the intended design.


### Electron Protection

Even if it's required that the application has to be **opened by LaunchService** (in the parents constraints). This can be achieved using **`open`** (which can set env variables) or using the **Launch Services API** (where env variables can be indicated).

## References

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

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

