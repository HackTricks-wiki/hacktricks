# macOS Bundles

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Basic Information

Basically, a bundle is a **directory structure** within the file system. Interestingly, by default this directory **looks like a single object in Finder**.&#x20;

The **common** frequent bundle we will encounter is the **`.app` bundle**, but many other executables are also packaged as bundles, such as **`.framework`** and **`.systemextension`** or **`.kext`**.

The types of resources contained within a bundle may consist of applications, libraries, images, documentation, header files, etc. All these files are inside `<application>.app/Contents/`

```bash
ls -lR /Applications/Safari.app/Contents
```

* `Contents/_CodeSignature` -> Contains **code-signing information** about the application (i.e., hashes, etc.).
  * `openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64`
* `Contents/MacOS` -> Contains the **application’s binary** (which is executed when the user double-clicks the application icon in the UI).
* `Contents/Resources` -> Contains **UI elements of the application**, such as images, documents, and nib/xib files (that describe various user interfaces).
* `Contents/Info.plist` -> The application’s main “**configuration file.**” Apple notes that “the system relies on the presence of this file to identify relevant information about \[the] application and any related files”.
  * **Plist** **files** contains configuration information. You can find find information about the meaning of they plist keys in [https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)
  *   Pairs that may be of interest when analyzing an application include:\\

      * **CFBundleExecutable**

      Contains the **name of the application’s binary** (found in Contents/MacOS).

      * **CFBundleIdentifier**

      Contains the application’s bundle identifier (often used by the system to **globally** **identify** the application).

      * **LSMinimumSystemVersion**

      Contains the **oldest** **version** of **macOS** that the application is compatible with.

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
