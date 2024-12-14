# macOS Bundles

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

Bundles in macOS serve as containers for a variety of resources including applications, libraries, and other necessary files, making them appear as single objects in Finder, such as the familiar `*.app` files. The most commonly encountered bundle is the `.app` bundle, though other types like `.framework`, `.systemextension`, and `.kext` are also prevalent.

### Essential Components of a Bundle

Within a bundle, particularly within the `<application>.app/Contents/` directory, a variety of important resources are housed:

* **\_CodeSignature**: This directory stores code-signing details vital for verifying the integrity of the application. You can inspect the code-signing information using commands like: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
* **MacOS**: Contains the executable binary of the application that runs upon user interaction.
* **Resources**: A repository for the application's user interface components including images, documents, and interface descriptions (nib/xib files).
* **Info.plist**: Acts as the application's main configuration file, crucial for the system to recognize and interact with the application appropriately.

#### Important Keys in Info.plist

The `Info.plist` file is a cornerstone for application configuration, containing keys such as:

* **CFBundleExecutable**: Specifies the name of the main executable file located in the `Contents/MacOS` directory.
* **CFBundleIdentifier**: Provides a global identifier for the application, used extensively by macOS for application management.
* **LSMinimumSystemVersion**: Indicates the minimum version of macOS required for the application to run.

### Exploring Bundles

To explore the contents of a bundle, such as `Safari.app`, the following command can be used: `bash ls -lR /Applications/Safari.app/Contents`

This exploration reveals directories like `_CodeSignature`, `MacOS`, `Resources`, and files like `Info.plist`, each serving a unique purpose from securing the application to defining its user interface and operational parameters.

#### Additional Bundle Directories

Beyond the common directories, bundles may also include:

* **Frameworks**: Contains bundled frameworks used by the application. Frameworks are like dylibs with extra resources.
* **PlugIns**: A directory for plug-ins and extensions that enhance the application's capabilities.
* **XPCServices**: Holds XPC services used by the application for out-of-process communication.

This structure ensures that all necessary components are encapsulated within the bundle, facilitating a modular and secure application environment.

For more detailed information on `Info.plist` keys and their meanings, the Apple developer documentation provides extensive resources: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

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

