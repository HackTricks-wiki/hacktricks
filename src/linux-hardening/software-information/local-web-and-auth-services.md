# 本地 Web 和身份验证服务

{{#include ../../banners/hacktricks-training.md}}

Linux shell 提供了从主机侧查看 Web 和身份验证服务的视角：进程参数、监听端口、unit 文件、配置、日志以及仅本地可访问的接口。利用这些信息，将可访问的服务与其实际使用的账户和文件关联起来。

## 映射本地 Web 技术栈

```bash
ss -lntup
ps -eo user,pid,args | grep -E '[a]pache|[n]ginx|[p]hp-fpm|[j]enkins'
systemctl list-units --type=service --state=running 2>/dev/null
find /etc/apache2 /etc/httpd /etc/nginx -maxdepth 3 -type f 2>/dev/null | head -80
```

检查 virtual-host 名称、document root、proxy 路由、upload 目录、PHP 执行设置，以及包含凭据的配置文件。loopback listener 可能可通过 proxy 或 SSH tunnel 访问。要针对本地 listener 测试指定的 virtual host，请发送预期的 `Host` header，或使用 `curl --resolve` 并指定正确的地址和端口。virtual-host 枚举还可能发现默认响应中未出现的名称。将可写的 upload 目录视为代码执行路径之前，请检查 Apache 是否允许 `.htaccess` 覆盖，以及 upload 路径能否执行 PHP。已部署的 JavaScript source map 可能暴露源代码路径或客户端机密；将找回的值视为线索，并验证其实际权限。有关 Web 专项检查，请参阅 [Apache](../../network-services-pentesting/pentesting-web/apache.md) 和 [Nginx](../../network-services-pentesting/pentesting-web/nginx.md)。

对于使用 [mpm-itk](https://mpm-itk.sesse.net/) 的 Apache，启用的 `AssignUserID` 可以让 virtual host 以不同的用户和组运行。如果低权限账户能够在该主机的 `DocumentRoot` 中写入脚本，请检查是否存在可访问的路由，能以指定身份实际执行该脚本。确认模块已加载、virtual host 的有效配置（包括基于表达式的身份覆盖）、目录的写入和搜索权限、脚本 handler，以及 listener 的可访问性。仅凭醒目的指令或可写目录，无法证明存在跨用户执行。

通过 Web server 发布的 home directory，即使实时的 `.ssh` 目录是私有的，也可能暴露包含 SSH identity 文件的备份归档。例如，[Nostromo 的 `homedirs_public` 设置](https://www.nazgul.ch/dev/nostromo_man.html)用于选择从用户 home 目录提供服务的子目录。仅发现归档路径只是线索：请验证 server 的有效映射、本地可读性或 HTTP 授权、归档内容、私钥口令，以及对应账户是否确实接受该密钥。例行主机枚举时不要解压归档或打印密钥材料。

高权限本地 Web app 的可读备份，即使其实时源代码无法访问，也可能暴露身份验证和文件读取逻辑。依赖备份内容之前，请将其与已部署的服务进行比对。尤其是，当 app 使用确定性的 ECB block、会为指定文本返回新 cookie，并在之后按未转义的分隔符拆分解密值时，应审查这样一种 cookie：它通过加密调用者可控文本，后接 secret 和 role flag 构造。[NIST 说明了 ECB 独立且可重复的 block 映射特性](https://csrc.nist.gov/news/2022/proposal-to-revise-sp-800-38a)；这一特性可能支持基于指定输入的比较，但本身并不会授予更高权限。请确认实时路由、session 前置条件、具体 parser/data flow、服务身份，以及独立的特权操作或文件读取路径。被动盘点应报告备份元数据和 listener 所有权，不要读取归档内容或发送身份验证探测。

同样的源代码审查方法也适用于特权的**非 HTTP** loopback 服务，例如基于自定义 SSH 的接口。如果可访问的源代码备份显示某个命令接受调用者指定的文件路径，请检查其身份验证门槛、路径解析方式，以及打开文件前是否确认解析后的文件仍位于预期目录下。在 Go 中，[`filepath.Join`](https://pkg.go.dev/path/filepath#Join) 会清理路径，但不会强制执行该目录边界。请确认备份与运行中的 build 相符、listener 可访问、低权限账户可以使用该命令，并且进程能够读取目标文件；持有可读 SSH key 与能否登录是两个独立的策略问题。报告源代码归档路径和服务所有权，不要将归档内容或密钥解压到自动化输出中。

监听 TCP loopback 的 PHP-FPM pool，即使其网站需要身份验证，仍可能被其他本地账户访问。[PHP 警告，能够连接 FastCGI 的客户端可以控制请求设置，包括 `auto_prepend_file`](https://www.php.net/manual/en/install.fpm.php)。请结合实时 listener、worker UID、现有脚本路径，以及任何 `security.limit_extensions` 或 `php_admin_value` 限制，检查 pool 的 `listen` 和 `listen.allowed_clients` 设置。Pool 配置文件的 `env[...]` 指令中可能包含凭据，因此自动化盘点应报告文件路径，而不是文件内容。配置文件或端口本身无法证明存在跨用户执行路径；协议详情请参阅 [FastCGI 指南](../../network-services-pentesting/9000-pentesting-fastcgi.md)。

对于特权本地 API，除了代码执行，也要追踪授权逻辑。低权限账户可以修改的 database role 可能会解锁某个 API 路由，但下一道边界取决于该路由的实现。例如，将请求 JSON 合并到 JavaScript 对象后调用 [`child_process.exec`](https://nodejs.org/api/child_process.html)，就需要检查是否存在[从 prototype pollution 到执行的数据流](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)。请验证实际使用的 merge library/version、输入验证、可访问路由、进程身份和 child-process 选项；仅发现 root-owned Node listener 或易受攻击的依赖名称，只能算线索。

基于文件的 CMS 存储可能会在常规 `.php` 配置文件之外保存管理员密码验证器。例如，站点的 `data/database.js` 或 `data/settings/pass.php`。手动审查前请检查文件所有权和可读性，并避免将 hash 输出到自动化共享结果中。可恢复的应用密码与 Unix 账户是不同的权限边界：请针对具体账户和允许的身份验证方式，验证密码是否确实被复用。

应用的 authentication controller 也可能在源代码中直接包含明文登录密码，而非将其存放在配置文件中。如果低权限用户能够读取已部署的 controller，请在本地审查其身份验证比对逻辑，并避免将任何密码值写入共享的枚举输出。声称存在本地提权之前，请确认该代码路径处于启用状态、密码对应用有效，并且另一个具体的高权限 Unix 账户确实接受同一密码。仅凭 controller 文件名只能作为审查线索。

Dolibarr 将数据库连接设置（包括 `dolibarr_main_db_pass`）存储在 `htdocs/conf/conf.php` 中（[配置参考](https://wiki.dolibarr.org/index.php/Configuration_file)）。可读文件只是凭据线索；只有经过验证的账户密码复用或其他数据库权限，才可能构成本地提权。请先检查权限，并避免在自动化输出中打印该值。

GitLab Linux package 的配置文件通常是 `/etc/gitlab/gitlab.rb`，但部署中也可能在其他位置保留可读副本。[GitLab 文档](https://docs.gitlab.com/omnibus/settings/smtp/)指出，该文件可能包含 `gitlab_rails['smtp_password']`，不过加密的 SMTP 设置可能会将密码保存在明文文件之外。将可读配置视为凭据线索：在声称存在密码复用之前，请验证该配置处于启用状态、凭据仍然有效，并且特定的高权限账户确实接受该凭据。另外，[GitLab 在 `gitlab-ctl reconfigure` 期间会以 root 身份将 `gitlab.rb` 作为 Ruby 代码运行](https://docs.gitlab.com/omnibus/settings/configuration/)；要将可写的活动配置文件或被包含的 `from_file` 判定为执行问题，必须确认存在实际的特权 reconfigure 路径。配置预览可能暴露凭据值，因此应将其输出视为敏感信息，并仅共享路径和权限。

自托管的 Mattermost 安装可能会将 `SqlSettings.DataSource` 保存在 `/opt/mattermost/config/config.json` 中；[Mattermost 文档](https://docs.mattermost.com/deployment-guide/server/troubleshooting)介绍了该常见路径，以及将活动配置存储在数据库中的部署方式。可读文件可能暴露应用数据库凭据，但这并不能证明可以访问数据库或取得 Unix root 权限。请验证活动配置来源、数据库角色的实际权限、任何单独找回的应用密码，以及该密码是否能用于某个具体的高权限 Unix 账户。Mattermost 的密码 hash 格式可能随版本而变化；枚举时请记录配置路径和访问元数据，不要打印连接字符串或查询数据库。

```bash
curl -i -H 'Host: admin.example.local' http://127.0.0.1:8080/
ffuf -w wordlist.txt -u http://127.0.0.1:8080/ -H 'Host: FUZZ.example.local' -fs 1234 # replace 1234 with the default response size
grep -R 'sourceMappingURL' /var/www /opt 2>/dev/null | head
```

根据默认响应大小或其他稳定基线筛选虚拟主机结果，避免每个猜测的名称看起来都有效。只有在 source map 确实已部署或可通过其他方式读取时，它才有用。

反向代理可能会改变应用信任哪些客户端标头。先比较直接请求和经代理转发的请求，再判断 `X-Forwarded-For`、`X-Forwarded-Host` 或类似标头是否能确定调用者身份。结合检查代理和应用配置。

如果 PHP 将 `$_SERVER['HTTP_X_FORWARDED_FOR']` 复制到传给 [`system()`](https://www.php.net/manual/en/function.system.php) 的字符串中，请检查可达的请求路径是否允许调用者提供标头，以及 shell 元字符是否原样进入该字符串。开头嵌入的 `sudo iptables` 命令**不会**让后续以 shell 分隔的命令以 root 身份运行；除非另有生效的 sudo 规则允许提权，否则这些命令会以 Web worker 的身份运行。在声称存在 root 路径之前，请确认 worker 身份、确切的 `sudo -l` 授权及其认证要求，以及命令的参数边界。日常主机枚举时，应检查源码和策略，不要发送注入探测请求。

## 访问日志中的登录凭据

如果应用通过 `GET` 提交登录表单，用户名和密码可能会成为请求 URI 中的查询参数。`POST` 请求也可以包含查询字符串；使用 `POST` 并不能隐藏意外放入 URI 的秘密，包括填写在无关表单字段中的密码。当配置格式使用 `%r` 时，[Apache 的常见访问日志请求行](https://httpd.apache.org/docs/2.4/logs.html)会记录方法和 URI，包括查询字符串。因此，获准读取这些日志的账户（例如某些 Linux 系统上的 `adm` 组成员）可能会发现凭据线索。检查实际日志格式和权限，然后确认该值确实是秘密、账户接受该值，并且它能跨越权限边界。不要假定请求正文也被记录，也不要将候选值复制到共享输出中。

仅检查可读取的访问日志，并确保凭据值不会出现在共享命令输出中。较长的请求行还可能包含 referrer 和 user agent，因此短行过滤器可能会隐藏真正需要关注的请求。Apache、httpd 和 Nginx 常见的访问日志位置分别为 `/var/log/apache2/access.log`、`/var/log/httpd/access_log` 和 `/var/log/nginx/access.log`。轮转日志中可能包含较早的凭据。[通过 LFI 访问日志](../../pentesting-web/file-inclusion/README.md#read-access-logs-to-harvest-get-based-auth-tokens-token-replay)是获取同一数据的相关途径。

应用认证日志也可能暴露意外填入失败登录**用户名**字段的密码。首先确认日志可读取，且其格式会记录提交的用户名；仅在本地检查少量相关内容，不要将候选凭据复制到共享输出中。看起来像密码的用户名只是线索，并不能证明它是有效密码或拥有更高权限。声称发生了权限转换之前，请先验证目标账户，并确认该密码是否在特定服务或 Unix 账户中复用。

如果另一个身份下运行的定时客户端会向某个端点提交凭据，则应单独审查可写的 Web 登录处理程序。确认对**当前生效**处理程序的写入权限、客户端实际的计划任务和请求路径、它发送的是谁的凭据，以及该应用密码是否也能独立用于更高权限的操作系统账户。仅有可写页面或定期运行的进程，并不能证明发生了权限转换。被动盘点时，应报告路径权限和任务元数据，不要修改处理程序或收集密码。

启用 FTP 事件日志记录时，Suricata 的 EVE JSON 日志也可能记录 FTP `USER` 和 `PASS` 命令及其 `command_data`。在查看少量相关内容之前，先检查 `/var/log/suricata/eve*.json*` 是否可读，包括轮转或压缩文件。可读取的 EVE 文件只是线索：请确认确实记录了 FTP 事件、数据包含可用凭据，并且该凭据能跨越权限边界。避免在共享枚举输出中打印 `command_data`。Suricata 文档介绍了 [FTP 事件字段](https://docs.suricata.io/en/suricata-8.0.2/output/eve/eve-json-format.html)和 [EVE 轮转及文件名变体](https://docs.suricata.io/en/suricata-7.0.15/output/eve/eve-json-output.html)。

## 生成的 Apache 配置和管道日志

[remco](https://github.com/HeavyHorst/remco) 可以监视键值后端，将模板渲染到 Apache 配置文件中，并运行重新加载命令。检查正在运行的 remco 进程身份、其配置的模板来源和目标、监视的键前缀，以及后端值是否会直接插入 `ServerName` 等 Apache 指令中。仅有本地后端监听器，并不能证明当前用户可以写入被监视的键；声称存在提权之前，请先验证后端认证和权限。

可写后端值中未转义的换行符，可能会将一个预期的指令值变成多个 Apache 指令。[Apache 管道日志](https://httpd.apache.org/docs/2.4/logs.html#piped)尤其敏感：带有 `|` 命令的 `CustomLog` 或 `ErrorLog` 会以父 httpd 进程的身份启动辅助进程，通常为 root；`|$` 则要求 Apache 使用 shell。枚举期间，应检查生成的配置及其重新加载路径，不要更改后端数据或重启服务。请妥善保管完整的管道命令，因为其参数可能包含秘密。

## 认证与服务身份

Monit 的控制文件通常是 `~/.monitrc` 或 `/etc/monitrc`，但 `monit -c` 可以指定其他路径。可读取的文件可能包含 Web 界面的 `set httpd` 和 `allow user:password` 条目，该界面通常监听本地端口 2812。查看文件前请检查其所有者和权限，并确保密码值不会出现在共享枚举输出中。Web 凭据只能授予配置的 Monit 角色；只读用户不能执行控制操作。要通过 Unix 账户单独提权，必须确认密码复用，或确认已认证角色确实能够触发特权 Monit 操作。参见 [Monit 控制文件和认证文档](https://www.mmonit.com/monit/documentation/monit.html)。

对于 Webmin，`/etc/webmin/miniserv.conf` 用于确定服务器设置，`/etc/webmin/webmin.acl` 记录用户可以访问哪些模块；[Webmin 文档说明了模块授权边界](https://webmin.com/docs/development/creating-modules/)。Unix 密码或可读取的 ACL 文件本身并不能授予 Webmin 会话。请确认实际的认证映射、可达的监听器、已认证账户、生效的 Package Updates 模块权限、已安装代码或厂商修复，以及 Webmin 进程身份。在受影响的 1.910 及更早版本中，[CVE-2019-12840](https://nvd.nist.gov/vuln/detail/CVE-2019-12840)允许拥有该模块权限的账户通过更新处理程序执行命令。被动枚举时，应报告配置路径和权限，不要打印凭据或尝试更新。

```bash
find /etc/pam.d /etc/sssd /etc/postfix -maxdepth 2 -type f -ls 2>/dev/null
systemctl cat sssd postfix jenkins 2>/dev/null
getent passwd
```

- [PAM](pam-pluggable-authentication-modules.md) 管理特定服务的身份验证；可写的策略文件或模块路径可能改变登录行为。
- LDAP/SSSD 配置可能暴露目录端点、绑定身份和访问规则。恢复出的绑定密码可能允许查询超出当前 OS 账户权限范围的 LDAP 内容；请使用确切的绑定身份测试，并检查目录 ACL。检查文件权限后再查看机密信息；[Linux Active Directory](../user-information/linux-active-directory.md) 和 [FreeIPA](freeipa-pentesting.md) 介绍了票据和目录的使用。
- Postfix 别名可以将收到的邮件通过管道传给本地命令。如果权限较低的用户能够修改被引用的脚本，邮件投递就可能以投递身份触发其代码。在认定这条路径可行之前，请检查别名映射和脚本所有权；参见 [SMTP and mail service testing](../../network-services-pentesting/pentesting-smtp/README.md)。
- Jenkins 和其他 CI 服务可能以高权限本地账户运行作业。在测试 Pipeline 或插件之前，请检查服务用户、可写的作业/工作区路径以及本地管理界面。还要检查**作业可用的凭据**以及凭据可用于认证的账户：[SSH Agent step](https://www.jenkins.io/doc/pipeline/steps/ssh-agent/) 可使 Pipeline 以 SSH 凭据对应的用户身份访问主机，即使 Jenkins 本身以权限较低的 Unix 账户运行。认定存在主机权限提升之前，请确认当前 Jenkins 身份具有 `Job/Create`、`Job/Configure` 或其他有效途径来修改 Pipeline，该作业可使用该凭据，并且目标 SSH 账户接受该密钥。凭据的显示名称或 ID 本身无法证明这些条件中的任何一项。Jenkins 警告，作业创建者以及通常的作业配置者，可以任意使用其权限范围内可用的凭据；因此，[credential scope](https://www.jenkins.io/doc/book/security/credentials/) 和 [Pipeline trust](https://www.jenkins.io/doc/book/security/securing-org-folders-and-multibranch-pipelines/) 与服务 UID 同样重要。不要将凭据值和私钥写入共享的枚举输出。

## Gogs 仓库文件写入

对于本地 Gogs 服务，请结合 `gogs web` 进程所有者、可执行文件版本和 `custom/conf/app.ini` 进行判断。配置可能暴露服务身份、仓库根目录、监听地址，以及是否禁用了注册。仅监听 loopback 地址的服务，本地用户仍可访问。最高至 0.13.3 的 Gogs 版本存在经过身份验证的 `PutContents` symlink 文件写入问题（[CVE-2025-8110](https://github.com/advisories/GHSA-mq8m-42gh-wq7r)）：仓库写入者可以提交一个 symlink，然后通过它引导 API 写入。由此产生的文件访问权限与 Gogs 进程相同，因此以 root 运行的实例需要立即处理。在认定存在可用路径之前，请验证已部署的修复和身份验证要求；API 错误并不能证明文件写入失败。

## Gitea 仓库描述 XSS 和高权限查看者

Gitea 1.22.0 允许在仓库描述中存储 JavaScript（[CVE-2024-6886](https://github.com/advisories/GHSA-4h4p-553m-46qh)）；1.22.1 已修复此问题。能够编辑描述的用户，如果其恶意链接被权限更高的用户查看并激活，就能影响该用户的浏览器会话。该浏览器身份随后可能泄露私有仓库内容或其他应用数据。要实现单独的本地提权，还需要通过这些内容获得可用的凭据或权限，例如重复使用的管理员密码；仅凭 Gitea 进程所有者身份，无法证明会造成 root 级影响。在认定这条攻击链成立之前，请检查已部署的版本、描述编辑权限、查看者的操作流程以及实际的浏览器交互。

## Cobbler 配置 API

Cobbler 的管理服务会公开 XML-RPC API，通常使用端口 `25151`。评估其影响之前，请检查监听地址和 `cobblerd` 进程所有者；仅监听 loopback 地址的 API 仍可被主机上的用户访问。请检查 `/etc/cobbler/modules.conf` 中的身份验证和授权模块、`/etc/cobbler/settings` 或 `/etc/cobbler/settings.yaml` 中的服务设置，以及 `/etc/cobbler/users.conf`、`/etc/cobbler/users.digest` 和 `/var/lib/cobbler/web.ss` 的权限。摘要文件和共享密钥文件包含凭据材料，因此默认情况下应记录其可读性，但不要打印其内容。

```bash
ps -eo user,pid,args | grep '[c]obblerd'
ss -ltn 2>/dev/null | grep ':25151'
for file in /etc/cobbler/modules.conf /etc/cobbler/settings /etc/cobbler/settings.yaml \
            /etc/cobbler/users.conf /etc/cobbler/users.digest /var/lib/cobbler/web.ss; do
    [ -e "$file" ] && ls -l "$file"
done
```

**CVE-2024-47533** 是 Cobbler 3.0.0 至 3.2.2，以及 3.3.0 至 3.3.6 中的 XML-RPC authentication bypass。读取共享密钥时出错会返回可预测的值 `-1`，而 API 会将其接受为密码。对应的修复版本是 3.2.3 和 3.3.7。软件包版本只能作为线索；在报告存在风险之前，应验证已部署的代码以及是否已回移修复。

如果 `cobblerd` 以 root 身份运行，经过身份验证的 API session 可能成为特权执行路径。在受影响的实现中，`background_import` 会将用户控制的 `rsync_flags` 传入 shell 命令，而渲染用户控制的 Cheetah autoinstall template 时可能会执行 Python。测试任一路径之前，应检查 API 权限和已安装版本。限制对管理 API 的访问，修补 authentication bypass，并确保配置文件和凭据文件只有服务管理员可读取。

## Motion 和 motionEye 配置

检查 `/etc/motioneye/motioneye.conf` 中的 `conf_path`，然后检查该目录下的 `motion.conf` 和少量 `camera-*.conf` 文件。报告其中是否存在可读取的 `# @admin_password` 哈希，但不要打印哈希。[较旧的 motionEye 版本会以过于宽松的读取权限写入这些文件](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-rhgp-6wq6-9j67)；此问题在 0.44.0 中修复。应同时检查 Motion 的 `webcontrol_port`、`webcontrol_parms`、`webcontrol_auth_method` 和 `webcontrol_localhost` 设置：如果启用了高级控制（`2` 或 `3`）且禁用了身份验证，本地用户可能执行包括强大操作在内的功能，即使监听器绑定在 loopback 地址上也一样。[Motion 文档说明了这些值和默认值](https://motion-project.github.io/motion_config.html)。

在 0.43.1b5 之前，motionEye 的 admin session 可以将 camera 文件名设置转化为命令执行，触发条件是 Motion 处理该设置时（[CVE-2025-60787](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-j945-qm58-4gjx)）。在声称存在权限提升之前，应确认正在运行的版本、服务身份、可用的身份验证路径，以及是否配置了 camera。仅凭配置无法证明服务正在运行或具有特权。

服务名称或已安装的软件包只能作为线索。权限边界取决于可触达的输入、进程身份、可写配置，以及最终受其控制的命令或文件。

## 本地 AWS emulator 和存储的凭据

主机用户可能会通过已发布的 loopback 端点访问运行在容器中的 AWS 兼容 emulator。在评估对 [Secrets Manager](https://docs.localstack.cloud/aws/services/secretsmanager/) 或 [KMS](https://docs.localstack.cloud/aws/services/kms/) 的访问权限之前，应结合检查活动中的监听器、客户端选择的端点和账户，以及 emulator 已安装的授权设置。在 LocalStack 中，[IAM policy enforcement 是单独的设置](https://docs.localstack.cloud/aws/developer-tools/security-testing/iam-policy-enforcement/)；不要仅凭凭据文件、IAM policy 或监听器推断实际生效的 API 权限。应确认已安装版本和配置的实际行为。

只有当当前 API 身份能够检索某个存储的 secret，且另一个权限更高的账户接受取回的凭据时，该 secret 才能用于本地权限提升。加密的本地数据块还需要文件读取权限、匹配且可用的 KMS key 和算法，以及实际生效的解密权限。对于[非对称 KMS key](https://docs.aws.amazon.com/cli/latest/reference/kms/decrypt.html)，解密请求必须指定加密该数据块时使用的算法。常规枚举时，主机自动化清单应仅收集进程、监听器、配置路径和文件权限方面的证据；不要请求或打印 secret 值或解密后的明文。
{{#include ../../banners/hacktricks-training.md}}
