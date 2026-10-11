# 用户信息

{{#include ../../banners/hacktricks-training.md}}

用户身份、组成员身份和委托凭据决定进程可以访问哪些资源。在调查下方的访问路径之前，请先检查有效身份和补充组。

- [用户、会话和凭据痕迹](user-and-session-triage.md)介绍账户枚举、活动登录、SSH 和 shell 痕迹以及凭据存储。
- [真实、有效和已保存的用户 ID](euid-ruid-suid.md)解释 SUID 程序和进程执行期间的身份变更。
- [Linux 权限提升相关的有趣组](interesting-groups-linux-pe/README.md)介绍由组授予的访问权限，包括 LXD/LXC。
- [SSH 转发代理利用](ssh-forward-agent-exploitation.md)分析转发的 SSH 凭据带来的风险。
- [Linux Active Directory](linux-active-directory.md)介绍加入 AD 环境的主机。
{{#include ../../banners/hacktricks-training.md}}
