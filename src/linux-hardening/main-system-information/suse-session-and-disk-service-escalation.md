# SUSE 会话与磁盘服务提权指标

{{#include ../../banners/hacktricks-training.md}}

## 通过 PAM 进行 SSH 会话授权

CVE-2025-6018 影响了 SUSE 15 的 PAM 配置：SSH 身份验证栈先加载 `pam_env`，随后会话栈才加载 `pam_systemd`。当 `pam_env` 读取用户的 `.pam_environment` 时，用户可以提供 `XDG_SEAT` 和 `XDG_VTNR` 值，使 Polkit 将 SSH 会话视为物理活动会话。这样，远程用户就可能获得 `allow_active=yes` 操作的权限。这会改变会话授权，但本身并不能保证获得 root 权限。SUSE 修复了 `pam` 中默认的用户环境行为，以及 `pam-config` 生成的模块位置。<sup>[[1]](#references)[[2]](#references)</sup>

检查有效的 `/etc/pam.d/sshd` include 链、`pam_env.so` 和 `pam_systemd.so` 的顺序，以及任何显式的 `user_readenv=1` 选项。已修补的 `pam` 软件包会更改默认行为，但显式选项仍可请求读取用户环境。较新的 `pam-config` 软件包并不能证明本地修改过或过时的 PAM 栈已重新生成。请同时检查供应商软件包版本和实际配置。<sup>[[1]](#references)[[2]](#references)</sup>

## 活动用户磁盘服务路径

CVE-2025-6019 是 `libblockdev` 中的一条提权路径，可通过 `udisks2` 使用：在调整 XFS 大小期间，攻击者提供的文件系统可能会暂时以未启用预期 `nosuid` 限制的方式挂载。此路径需要可用的 UDisks D-Bus 服务、XFS 大小调整支持、调用者可用的相关 Polkit 操作，以及受影响版本的库软件包。CVE-2025-6018 是获取活动用户会话的一种方式，但已有活动会话的用户也可以独立利用磁盘服务路径。<sup>[[3]](#references)</sup>

进行被动检查时，请检查 UDisks 服务元数据、`org.freedesktop.udisks2.modify-device` 策略、`xfs_growfs` 和已安装的 `libbd_fs2` 软件包。SUSE 列出的 openSUSE Leap 15.6 修复版本为 `libbd_fs2` `2.26-150400.3.5.1`；具体修复版本取决于产品。仅发现策略和软件包并不能证明调用者能够挂载或调整设备大小。枚举过程中请避免更改挂载或调用 D-Bus 方法。<sup>[[3]](#references)</sup>

## References

- [1] [SUSE CVE-2025-6018 安全公告](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [SUSE pam-config 安全更新](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [SUSE CVE-2025-6019 安全公告](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
