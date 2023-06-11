# macOS Office Sandbox Bypasses

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### Word Sandbox bypass via Launch Agents

The application uses a **custom Sandbox** using the entitlement **`com.apple.security.temporary-exception.sbpl`** and this custom sandbox allows to write files anywhere as long as the filename started with `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Therefore, escaping was as easy as **writing a `plist`** LaunchAgent in `~/Library/LaunchAgents/~$escape.plist`.

Check the [**original report here**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Word Sandbox bypass via Login Items and zip

(Remember that from the first escape, Word can write arbitrary files whose name start with `~$`).

It was discovered that from within the sandbox it's possible to create a **Login Item** (apps that will be executed when the user logs in). However, these apps **won't execute unless** they are **notarized** and it's **not possible to add args** (so you cannot just run a reverse shell using **`bash`**).

From the previous Sandbox bypass, Microsoft disabled the option to write files in `~/Library/LaunchAgents`. However, it was discovered that if you put a **zip file as a Login Item** the `Archive Utility` will just **unzip** it on its current location. So, because by default the folder `LaunchAgents` from `~/Library` is not created, it was possible to **zip a plist in `LaunchAgents/~$escape.plist`** and **place** the zip file in **`~/Library`** so when decompress it will reach the persitence destination.

Check the [**original report here**](https://objective-see.org/blog/blog\_0x4B.html).

### Word Sandbox bypass via Login Items and .zshenv

(Remember that from the first escape, Word can write arbitrary files whose name start with `~$`).

However, the previous technique had a limitation, if the folder **`~/Library/LaunchAgents`** exists because some other software created it, it would fail. So a different Login Items chain was discovered for this.

An attacker could crate the the files **`.bash_profile`** and **`.zshenv`** with the payload to execute and then zip them and **write the zip in the victims** user folder: \~/\~$escape.zip.

Then, add the zip file to the **Login Items** and then the **`Terminal`** app. When the user relogins, the zip file would be uncompressed in the users file, overwriting **`.bash_profile`** and **`.zshenv`** and therefore, the terminal will execute one of these files (depending if bash or zsh is used).

Check the [**original report here**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Word Sandbox Bypass with Open and env variables

From sandboxed processes it's still possible to invoke other processes using the **`open`** utility. Moreover, these processes will run **within their own sandbox**.

It was discovered that the open utility has the **`--env`** option to run an app with **specific env** variables. Therefore, it was possible to create the **`.zshenv` file** within a folder **inside** the **sandbox** and the use `open` with `--env` setting the **`HOME` variable** to that folder opening that `Terminal` app, which will execute the `.zshenv` file (for some reason it was also needed to set the variable `__OSINSTALL_ENVIROMENT`).

Check the [**original report here**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Word Sandbox Bypass with Open and stdin

The **`open`** utility also supported the **`--stdin`** param (and after the previous bypass it was no longer possible to use `--env`).

The thing is that even if **`python`** was signed by Apple, it **won't execute** a script with the **`quarantine`** attribute. However, it was possible to pass it a script from stdin so it won't check if it was quarantined or not:&#x20;

1. Drop a **`~$exploit.py`** file with arbitrary Python commands.
2. Run _open_ **`–stdin='~$exploit.py' -a Python`**, which runs the Python app with our dropped file serving as its standard input. Python happily runs our code, and since it’s a child process of _launchd_, it isn’t bound to Word’s sandbox rules.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
