# 本地 Web 和认证服务

{{#include ../../banners/hacktricks-training.md}}

Linux shell 提供了 Web 和认证服务的主机侧视图：进程参数、监听端口、unit 文件、配置、日志以及仅限本地访问的接口。利用这些信息，将可访问的服务与其实际使用的账户和文件关联起来。

## 映射本地 Web 栈

```bash
ss -lntup
ps -eo user,pid,args | grep -E '[a]pache|[n]ginx|[p]hp-fpm|[j]enkins'
systemctl list-units --type=service --state=running 2>/dev/null
find /etc/apache2 /etc/httpd /etc/nginx -maxdepth 3 -type f 2>/dev/null | head -80
```

检查虚拟主机名称、文档根目录、代理路由、上传目录、PHP 执行设置，以及包含凭据的配置文件。通过代理或 SSH tunnel 可能可以访问 loopback 监听器。要针对本地监听器测试指定的虚拟主机，请发送预期的 `Host` header，或使用 `curl --resolve` 指定正确的地址和端口。虚拟主机枚举还可能发现默认响应中没有的名称。在将可写上传目录视为代码执行入口之前，请检查 Apache 是否允许 `.htaccess` 覆盖设置，以及上传路径是否能执行 PHP。已部署的 JavaScript source map 可能暴露源代码路径或客户端密钥；将恢复出的值视为线索，并验证其实际权限。有关 Web 专项检查，请参阅 [Apache](../../network-services-pentesting/pentesting-web/apache.md) 和 [Nginx](../../network-services-pentesting/pentesting-web/nginx.md)。

对于使用 [mpm-itk](https://mpm-itk.sesse.net/) 的 Apache，启用的 `AssignUserID` 可让虚拟主机以不同的用户和组运行。如果低权限账户可以在该主机的 `DocumentRoot` 中写入脚本，请检查是否存在可访问的路由，确实会以指定身份执行该脚本。确认模块已加载、有效的虚拟主机配置（包括基于表达式的身份覆盖）、目录的写入和搜索权限、脚本处理器以及监听器访问权限。仅凭醒目的指令或可写目录，不能证明存在跨用户执行。

通过 Web 服务器发布的 home 目录，即使实时的 `.ssh` 目录是私有的，也可能暴露 SSH 身份文件的备份归档。例如，[Nostromo 的 `homedirs_public` 设置](https://www.nazgul.ch/dev/nostromo_man.html)会指定从用户 home 目录中提供服务的子目录。仅发现归档路径只是线索：请验证服务器的有效映射、本地可读性或 HTTP 授权、归档内容、私钥口令，以及对应账户是否实际接受该密钥。常规主机枚举时不要解压归档或打印密钥材料。

可读取的高权限本地 Web 应用备份，即使其实时源代码无法访问，也可能暴露身份验证和文件读取逻辑。依赖备份前，请先将其与已部署的服务进行比较。尤其要审查这样一种 cookie：它通过加密调用方可控的文本再加上密钥和角色标志来构造，而应用使用确定性的 ECB 分组、会针对选定文本返回新 cookie，并在之后按未转义的分隔符拆分解密值。[NIST 说明了 ECB 独立且可重复的分组映射特性](https://csrc.nist.gov/news/2022/proposal-to-revise-sp-800-38a)；这一特性可用于基于选定输入进行比较，但本身并不能授予更高权限。请确认实时路由、会话前置条件、确切的解析器和数据流、服务身份，以及独立的特权操作或文件读取路径。被动清点应报告备份元数据和监听器归属，但不要读取归档内容或发送身份验证探测。

相同的源代码审查方法也适用于高权限的**非 HTTP** loopback 服务，例如由 SSH 支持的自定义接口。如果可访问的源代码备份显示某条命令接受调用方指定的文件路径，请检查其身份验证门槛、路径解析方式，以及它是否确保解析后的文件仍位于预期目录之下再打开。在 Go 中，[`filepath.Join`](https://pkg.go.dev/path/filepath#Join) 会规范化路径，但不会强制路径位于指定目录之内。请确认备份与运行中的构建相符、监听器可访问、低权限账户可以使用该命令，且进程可以读取目标文件；持有可读 SSH 密钥是另一个独立的登录策略问题。报告源代码归档路径和服务归属，不要将归档内容或密钥解压到自动化输出中。

监听在 TCP loopback 上的 PHP-FPM pool，即使其网站启用了身份验证，也可能被其他本地账户访问。[PHP 警告称，能够连接 FastCGI 的客户端可以控制请求设置，包括 `auto_prepend_file`](https://www.php.net/manual/en/install.fpm.php)。请结合实时监听器、worker UID、已有脚本路径，以及任何 `security.limit_extensions` 或 `php_admin_value` 限制，检查 pool 的 `listen` 和 `listen.allowed_clients` 设置。pool 配置文件可能会在 `env[...]` 指令中包含凭据，因此自动化清点应报告文件路径而非文件内容。仅凭配置文件或端口，不能证明存在跨用户执行路径；协议详情请参阅 [FastCGI guide](../../network-services-pentesting/9000-pentesting-fastcgi.md)。

对于高权限本地 API，除了代码执行也要追踪授权流程。低权限账户可以修改的数据库角色可能解锁某个 API 路由，但之后的权限边界取决于该路由的实现。例如，将请求 JSON 合并到 JavaScript 对象后调用 [`child_process.exec`](https://nodejs.org/api/child_process.html)，就值得检查是否存在[从 prototype pollution 到执行的数据流](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)。请验证实际使用的合并库及其版本、输入验证、可访问路由、进程身份和子进程选项；仅发现一个由 root 拥有的 Node 监听器或一个名称上有漏洞的依赖项，都只是线索。

基于文件的 CMS 存储可能会在常规 `.php` 配置文件之外保存管理员密码验证值。例如站点的 `data/database.js` 或 `data/settings/pass.php`。手动审查前请检查文件的所有权和可读性，并避免将哈希写入自动化共享输出。可恢复的应用密码与 Unix 账户是两个独立的权限边界：如果声称存在密码复用，请针对具体账户和允许的身份验证方式进行验证。

应用的身份验证控制器也可能在源代码中直接包含明文登录密码，而非将其存入配置文件。如果低权限用户可以读取已部署的控制器，请在本地检查其中的身份验证比较逻辑，并避免将任何值写入共享枚举输出。声称存在本地权限提升前，请确认该代码路径处于活动状态、密码对该应用有效，而且另一个独立的高权限 Unix 账户确实接受同一密码。仅发现控制器文件名只是审查线索。

Dolibarr 在 `htdocs/conf/conf.php` 中存储数据库连接设置，包括 `dolibarr_main_db_pass`（[配置参考](https://wiki.dolibarr.org/index.php/Configuration_file)）。可读取该文件只是凭据线索；只有经过单独验证的账户密码复用或其他数据库权限，才能构成本地权限提升。请先检查权限，并避免在自动化输出中打印该值。

GitLab 的 Linux package 配置文件通常是 `/etc/gitlab/gitlab.rb`，但部署也可能在其他位置保留可读取的副本。[GitLab 文档说明](https://docs.gitlab.com/omnibus/settings/smtp/)该文件可能包含 `gitlab_rails['smtp_password']`，不过加密的 SMTP 设置可能会将密码保存在明文文件之外。将可读取的配置视为凭据线索：在声称存在密码复用前，请验证配置处于活动状态、凭据仍有效，并且某个特定的高权限账户确实接受该凭据。此外，[GitLab 会在 `gitlab-ctl reconfigure` 期间以 root 身份将 `gitlab.rb` 作为 Ruby 代码运行](https://docs.gitlab.com/omnibus/settings/configuration/)；要将可写的活动配置文件或被 `from_file` 引入的文件判定为执行问题，必须确认存在实际的特权 reconfigure 路径。配置预览可能暴露凭据值，因此应将其输出视为敏感信息，并改为共享路径和权限信息。

自托管 Mattermost 安装可能会将 `SqlSettings.DataSource` 保存在 `/opt/mattermost/config/config.json` 中；[Mattermost 文档](https://docs.mattermost.com/deployment-guide/server/troubleshooting)说明了这一常见路径，以及将活动配置存储在数据库中的部署方式。可读取该文件可能会暴露应用数据库凭据，但这并不能证明可以访问数据库或获得 Unix root 权限。请验证活动配置源、数据库角色的实际权限、任何单独恢复的应用密码，以及该密码是否对某个特定的高权限 Unix 账户有效。密码哈希格式可能会随 Mattermost 版本变化；枚举时记录配置路径和访问元数据，不要打印连接字符串或查询数据库。

```bash
curl -i -H 'Host: admin.example.local' http://127.0.0.1:8080/
ffuf -w wordlist.txt -u http://127.0.0.1:8080/ -H 'Host: FUZZ.example.local' -fs 1234 # replace 1234 with the default response size
grep -R 'sourceMappingURL' /var/www /opt 2>/dev/null | head
```

根据默认响应大小或其他稳定基线过滤虚拟主机结果，避免每个猜测的名称看起来都有效。只有在 source map 确实已部署或可通过其他方式读取时，它才有用。

反向代理可能会改变应用信任哪些客户端请求头。在假设 `X-Forwarded-For`、`X-Forwarded-Host` 或类似请求头能确立调用者身份之前，请比较直接请求和经代理转发的请求。应同时检查代理和应用配置。

如果 PHP 将 `$_SERVER['HTTP_X_FORWARDED_FOR']` 复制到传递给 [`system()`](https://www.php.net/manual/en/function.system.php) 的字符串中，请检查可访问的请求路径是否允许调用者提供请求头，以及 shell 元字符是否原样进入该字符串。开头嵌入的 `sudo iptables` 命令**不会**让后续由 shell 分隔的命令以 root 身份运行；除非另有有效的 sudo 规则允许提权，否则这些命令会以 Web worker 的身份运行。在声称存在 root 路径之前，应确认 worker 身份、确切的 `sudo -l` 授权及其身份验证要求，以及命令的参数边界。在常规主机枚举期间，应检查源码和策略，不要发送注入探测。

## 获得 Web foothold 后的特权 loopback API

即使本地 HTTP 服务的监听器绑定到 `127.0.0.1`，Web 进程 shell 仍可调用这些服务。在报告中提到的易受攻击的 Control Web Panel 版本中，账户控制面板以托管用户身份运行，但 `https://127.0.0.1:2302` 上的 user API 以 root 身份运行。其 `/v1/restoredatabase/` POST 路由未检查访问令牌，并将 `file` 字段传入 `shell_exec('mysql ... < ' . $file)`。因此，从托管用户的 foothold 出发，`file` 中的 shell 分隔符会以 root 身份执行。请确认该路由的访问限制以及 API 进程的有效身份；绑定到 loopback 本身并不等同于身份验证。参见 [PHP execution after redirect](../../pentesting-web/login-bypass/#php-execution-after-redirect)，了解一种获取该 foothold 的方式。报告中的漏洞已在 CWP 1.29 中完全修复。<sup>[[1]](#references)</sup>

```bash
curl -sk 'https://127.0.0.1:2302/v1/restoredatabase/' \
  --data-urlencode 'file=/dev/null ; id > /tmp/root-proof ; echo'
```

同一 API 还存在一个独立的认证门缺陷：`access_token()` 会将提供的 token 插入 `WHERE authorization_code='$access_token' AND client_id='$user'`。包含预期列且过期时间在未来的 `UNION` 行可以通过 token 检查，同时注释掉原有的 client-ID 条件。这样便能解锁受保护的路由，例如 `/v1/newpass/`，该路由会将原始 `user` 追加到由 root 拥有的 `passwd` shell 命令中。token 注入可以绕过认证门；但命令执行仍取决于第二个 sink。参见 [SQL injection authentication bypass](../../pentesting-web/login-bypass/#sql-injection-authentication-bypass)。<sup>[[1]](#references)</sup>

对于披露的六列认证门，注入的 token 可以提供一个未来的过期时间，并抑制剩余的谓词；列结构仅适用于该构建版本。<sup>[[1]](#references)</sup>

```sql
' UNION SELECT 'a','x','c','d','2099-01-01 00:00:00','f' -- -
```

单独的 tokenless `/v1/user_panel_dashboard/` 路由会将 `user` 插入 `oauth_clients` 查询中。这是使用 API 的 MySQL-root 连接进行的 blind database read，**不是** root OS execution：MySQL server 以 `mysql` OS user 运行。当查询的表为空时，[constant derived-table timing probe](../../pentesting-web/sql-injection/#exploiting-time-based-sqli) 可以避免因缺少行而无法观察到延迟。<sup>[[1]](#references)</sup>

## 访问日志中的登录凭据

如果应用使用 `GET` 提交登录表单，用户名和密码可能成为请求 URI 中的查询参数。`POST` 请求也可以包含查询字符串；使用 `POST` 并不能隐藏意外放入 URI 的机密信息，包括填入无关表单字段的密码。[Apache 常见访问日志的请求行](https://httpd.apache.org/docs/2.4/logs.html)会在配置格式使用 `%r` 时记录请求方法和 URI（包括查询字符串）。因此，有权读取这些日志的账户（例如某些 Linux 系统上的 `adm` 组成员）可能会发现凭据线索。检查实际的日志格式和权限，然后确认该值确实是机密信息、账户接受该值，并且它能跨越权限边界。不要假设请求正文也被记录，或将候选值复制到共享输出中。

只检查有权读取的访问日志，并避免在共享命令输出中暴露凭据值。较长的请求行也可能包含 referrer 和 user agent，因此短行过滤器可能会隐藏真正相关的请求。Apache、httpd 和 Nginx 常见的访问日志位置分别是 `/var/log/apache2/access.log`、`/var/log/httpd/access_log` 和 `/var/log/nginx/access.log`。轮转日志中可能包含较早的凭据。[通过 LFI 访问日志文件](../../pentesting-web/file-inclusion/README.md#read-access-logs-to-harvest-get-based-auth-tokens-token-replay)是获取相同数据的相关途径。

应用认证日志也可能意外暴露失败登录时填入**用户名**字段的密码。首先确认日志可读，且其格式会记录提交的用户名；只在本地查看少量相关内容，不要将候选凭据复制到共享输出中。看起来像密码的用户名只是线索，并不能证明它是有效密码或具有更高权限。确认目标账户，并核实该密码是否在特定服务或 Unix 账户中复用，然后再声称发生了权限转换。

如果另一个身份下的定时客户端会向可写的 Web 登录处理程序提交凭据，则应单独审查该处理程序。确认当前生效的处理程序是否可写、客户端的实际计划和请求路径、它发送的是谁的凭据，以及该应用密码是否也能用于权限更高的操作系统账户。仅有可写页面或周期性进程，并不能证明发生了权限转换。被动清点应报告路径权限和作业元数据，不要修改处理程序或收集密码。

启用 FTP 事件日志记录时，Suricata 的 EVE JSON 日志也可能记录 FTP `USER` 和 `PASS` 命令及其 `command_data`。在查看少量相关内容前，先检查 `/var/log/suricata/eve*.json*` 是否可读，包括轮转或压缩文件。可读的 EVE 文件只是线索：确认日志记录了 FTP 事件、数据中包含可用凭据，并且该凭据能跨越权限边界。避免在共享枚举输出中打印 `command_data`。Suricata 文档介绍了 [FTP 事件字段](https://docs.suricata.io/en/suricata-8.0.2/output/eve/eve-json-format.html)以及 [EVE 轮转和文件名变体](https://docs.suricata.io/en/suricata-7.0.15/output/eve/eve-json-output.html)。

## 生成的 Apache 配置和管道日志

[remco](https://github.com/HeavyHorst/remco) 可以监视键/值后端，将模板渲染到 Apache 配置文件中，并运行重载命令。检查正在运行的 remco 进程身份、配置的模板源和目标、所监视的键前缀，以及后端值是否被直接插入 `ServerName` 等 Apache 指令中。仅有本地后端监听器，并不能证明当前用户可以写入受监视的键；在声称存在权限提升之前，应先验证后端的认证和权限。

可写后端值中的未转义换行符可能会将原本单个指令值变成多个 Apache 指令。[Apache 管道日志](https://httpd.apache.org/docs/2.4/logs.html#piped)尤其敏感：带有 `|` 命令的 `CustomLog` 或 `ErrorLog` 会以父 httpd 的身份（通常是 root）启动辅助进程；`|$` 则要求 Apache 使用 shell。枚举期间应审查生成的配置及其重载路径，不要修改后端数据或重启服务。请妥善保管完整的管道命令，因为其参数可能包含机密信息。

## 认证与服务身份

Monit 的控制文件通常是 `~/.monitrc` 或 `/etc/monitrc`，但 `monit -c` 可以指定其他路径。可读文件中可能包含 Web 界面的 `set httpd` 和 `allow user:password` 条目，该界面通常监听本地端口 2812。查看文件前先检查其所有者和权限，并避免在共享枚举输出中暴露密码值。Web 凭据只授予配置的 Monit 角色；只读用户无法调用控制操作。若要确认另一个 Unix 账户的权限提升，必须证实密码复用，或确认已认证角色确实能够触发特权 Monit 操作。请参阅 [Monit 控制文件和认证文档](https://www.mmonit.com/monit/documentation/monit.html)。

对于 Webmin，`/etc/webmin/miniserv.conf` 包含服务器设置，`/etc/webmin/webmin.acl` 记录用户可访问的模块；[Webmin 文档说明了模块授权边界](https://webmin.com/docs/development/creating-modules/)。Unix 密码或可读的 ACL 文件本身并不能授予 Webmin 会话。请确认实际的认证映射、可访问的监听器、已认证账户、Package Updates 模块的有效权限、已安装代码或供应商修复，以及 Webmin 进程身份。在受影响的 1.910 及更早版本中，[CVE-2019-12840](https://nvd.nist.gov/vuln/detail/CVE-2019-12840) 允许拥有该模块权限的账户通过其更新处理程序执行命令。被动枚举时应报告配置路径和权限，不要打印凭据或尝试执行更新。

```bash
find /etc/pam.d /etc/sssd /etc/postfix -maxdepth 2 -type f -ls 2>/dev/null
systemctl cat sssd postfix jenkins 2>/dev/null
getent passwd
```

- [PAM](pam-pluggable-authentication-modules.md) 管理特定服务的身份验证；可写的策略或模块路径可能改变登录行为。
- LDAP/SSSD 配置可能会泄露目录端点、绑定身份和访问规则。恢复的绑定密码可能允许查询超出当前 OS 账户权限范围的 LDAP 内容；应使用确切的绑定身份测试，并检查目录 ACL。检查文件权限后再查看机密信息；[Linux Active Directory](../user-information/linux-active-directory.md) 和 [FreeIPA](freeipa-pentesting.md) 介绍了票据和目录的使用。
- Postfix 别名可以将收到的邮件通过管道传递给本地命令。如果低权限用户可以修改所引用的脚本，邮件投递可能会以投递身份触发其代码。提出这一路径前，应检查别名映射和脚本所有权；参见 [SMTP and mail service testing](../../network-services-pentesting/pentesting-smtp/README.md)。
- Jenkins 和其他 CI 服务可能会以强大的本地账户运行作业。测试 Pipeline 或插件前，应检查服务用户、可写的作业/工作区路径以及本地管理界面。还应检查**作业可用的凭据**以及这些凭据可认证为哪个账户：[SSH Agent step](https://www.jenkins.io/doc/pipeline/steps/ssh-agent/) 中使用的 Pipeline 可以 SSH 凭据对应的用户身份访问主机，即使 Jenkins 本身以权限较低的 Unix 账户运行。声称存在主机权限提升前，应确认当前 Jenkins 身份拥有 `Job/Create`、`Job/Configure` 或其他能有效修改 Pipeline 的途径，凭据在该作业的作用域内，并且目标 SSH 账户接受该密钥。仅凭凭据的显示名称或 ID，无法确认上述任何条件。Jenkins 警告称，作业创建者以及通常的作业配置者可以任意使用其作用域内可用的凭据；因此，[credential scope](https://www.jenkins.io/doc/book/security/credentials/) 和 [Pipeline trust](https://www.jenkins.io/doc/book/security/securing-org-folders-and-multibranch-pipelines/) 与服务 UID 同样重要。不要将凭据值和私钥输出到共享的枚举结果中。

## Gogs 仓库文件写入

对于本地 Gogs 服务，应将 `gogs web` 进程所有者与可执行文件版本及 `custom/conf/app.ini` 关联起来。配置可能会泄露服务身份、仓库根目录、监听地址，以及是否禁用了注册。仅监听回环地址的服务仍可由本地用户访问。0.13.3 及更早版本的 Gogs 存在一个需要身份验证的 `PutContents` 符号链接文件写入问题（[CVE-2025-8110](https://github.com/advisories/GHSA-mq8m-42gh-wq7r)）：仓库写入者可以提交符号链接，然后引导 API 通过该链接写入文件。由此产生的文件访问权限与 Gogs 进程相同，因此以 root 身份运行的实例需要尽快处理。声称存在可用路径前，应验证已部署的修复和身份验证要求；API 错误并不能证明文件写入失败。

## Gitea 仓库描述 XSS 和特权查看者

Gitea 1.22.0 允许在仓库描述中存储 JavaScript（[CVE-2024-6886](https://github.com/advisories/GHSA-4h4p-553m-46qh)）；1.22.1 修复了此问题。能够编辑描述的用户，如果某个权限更高的用户查看仓库并激活恶意链接，就能影响该用户的浏览器会话。该浏览器身份随后可能泄露私有仓库内容或其他应用程序数据。若要进一步实现本地权限提升，则需要通过这些内容获取可用的凭据或权限，例如重复使用的管理员密码；仅凭 Gitea 进程所有者身份，无法证明会造成 root 级影响。声称存在这条攻击链前，应检查已部署的版本、描述编辑权限、查看者的操作流程以及实际浏览器交互。

## Cobbler 配置服务 API

Cobbler 的管理服务会公开 XML-RPC API，通常使用端口 `25151`。评估其影响前，应检查监听器和 `cobblerd` 进程所有者；仅监听回环地址的 API 仍可由主机上的用户访问。检查 `/etc/cobbler/modules.conf` 中的身份验证和授权模块、`/etc/cobbler/settings` 或 `/etc/cobbler/settings.yaml` 中的服务设置，以及 `/etc/cobbler/users.conf`、`/etc/cobbler/users.digest` 和 `/var/lib/cobbler/web.ss` 的权限。摘要文件和共享密钥文件包含凭据材料，因此默认情况下只记录其可读性，不要打印其内容。

```bash
ps -eo user,pid,args | grep '[c]obblerd'
ss -ltn 2>/dev/null | grep ':25151'
for file in /etc/cobbler/modules.conf /etc/cobbler/settings /etc/cobbler/settings.yaml \
            /etc/cobbler/users.conf /etc/cobbler/users.digest /var/lib/cobbler/web.ss; do
    [ -e "$file" ] && ls -l "$file"
done
```

**CVE-2024-47533** 是 Cobbler 3.0.0 至 3.2.2 以及 3.3.0 至 3.3.6 中的 XML-RPC authentication bypass。共享密钥读取错误会返回可预测的值 `-1`，而 API 会将其接受为密码。对应的修复版本为 3.2.3 和 3.3.7。软件包版本只能作为线索；报告存在风险前，请核实已部署的代码以及是否已 backport 修复。

当 `cobblerd` 以 root 身份运行时，经过身份验证的 API session 可能成为特权执行路径。在受影响的实现中，`background_import` 会将用户可控的 `rsync_flags` 传入 shell command，而渲染用户可控的 Cheetah autoinstall template 时可能会执行 Python。测试任一路径前，请检查 API 权限和已安装版本。限制对管理 API 的访问，修补 authentication bypass，并确保只有服务管理员可以读取配置和凭据文件。

## Motion 和 motionEye 配置

检查 `/etc/motioneye/motioneye.conf` 中的 `conf_path`，然后检查该目录中的 `motion.conf` 和少量 `camera-*.conf` 文件。报告是否存在可读取的 `# @admin_password` hash，但不要打印该 hash。[较旧的 motionEye 版本会以过于宽松的读取权限写入这些文件](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-rhgp-6wq6-9j67)；此问题已在 0.44.0 中修复。请结合检查 Motion 的 `webcontrol_port`、`webcontrol_parms`、`webcontrol_auth_method` 和 `webcontrol_localhost` 设置：如果启用了高级控制（`2` 或 `3`）但禁用了身份验证，本地用户可能会执行强大的操作，即使监听器仅绑定到 loopback 也不例外。[Motion 文档说明了这些值和默认设置](https://motion-project.github.io/motion_config.html)。

在低于 0.43.1b5 的 motionEye 中，针对 admin session 的攻击者可以将摄像头文件名设置转换为命令执行，条件是 Motion 会处理该设置（[CVE-2025-60787](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-j945-qm58-4gjx)）。在声称存在权限提升之前，请确认运行版本、服务身份、可用的身份验证路径，以及是否已配置摄像头。仅凭配置无法证明服务正在运行或具有特权。

服务名称或已安装的软件包只能作为线索。权限边界取决于可触达的输入、进程身份、可写配置，以及该输入最终控制的命令或文件。

## 本地 AWS emulator 和存储的凭据

主机用户可能可以通过已发布的 loopback endpoint，访问在容器中运行的 AWS-compatible emulator。评估对 [Secrets Manager](https://docs.localstack.cloud/aws/services/secretsmanager/) 或 [KMS](https://docs.localstack.cloud/aws/services/kms/) 的访问权限前，请核实实际监听器、客户端选择的 endpoint 和 account，以及 emulator 已安装的授权设置。在 LocalStack 中，[IAM policy enforcement 是一项独立设置](https://docs.localstack.cloud/aws/developer-tools/security-testing/iam-policy-enforcement/)；不要仅凭凭据文件、IAM policy 或监听器推断实际 API 权限。请确认已安装版本和配置的实际行为。

只有当当前 API identity 可以检索某个存储的 secret，且另一个独立的高权限账户接受取回的凭据时，该 secret 才能用于本地权限提升。解密本地 blob 还需要文件读取权限、匹配且可用的 KMS key 和 algorithm，以及有效的 decrypt 权限。对于 [asymmetric KMS key](https://docs.aws.amazon.com/cli/latest/reference/kms/decrypt.html)，decrypt request 必须指定用于加密该 blob 的 algorithm。常规枚举时，主机自动化 inventory 应仅收集进程、监听器、配置路径和文件权限相关证据；不要请求或打印 secret 值或解密后的明文。

## References

- [1] [VulnCheck - 永远不会拒绝登录的页面：CWP2Shell](https://www.vulncheck.com/blog/control-web-panel-pre-auth-module-dispatch-rce)
