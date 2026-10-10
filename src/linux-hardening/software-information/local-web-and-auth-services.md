# 本地 Web 和身份验证服务

{{#include ../../banners/hacktricks-training.md}}

Linux shell 提供了从主机侧查看 Web 和身份验证服务的视角：进程参数、监听端口、单元文件、配置、日志和仅限本地访问的接口。利用这些信息，将可访问的服务与其实际使用的账户和文件关联起来。

## 梳理本地 Web 栈

```bash
ss -lntup
ps -eo user,pid,args | grep -E '[a]pache|[n]ginx|[p]hp-fpm|[j]enkins'
systemctl list-units --type=service --state=running 2>/dev/null
find /etc/apache2 /etc/httpd /etc/nginx -maxdepth 3 -type f 2>/dev/null | head -80
```

检查虚拟主机名称、文档根目录、代理路由、上传目录、PHP 执行设置，以及包含凭据的配置文件。代理或 SSH 隧道可能使 loopback 监听器可被访问。要针对本地监听器测试指定的虚拟主机，请发送预期的 `Host` header，或使用 `curl --resolve` 并指定正确的地址和端口。虚拟主机枚举还可能发现默认响应中未出现的名称。在将可写上传目录视为代码执行途径之前，请检查 Apache 是否允许 `.htaccess` 覆盖设置，以及上传路径是否可以执行 PHP。已部署的 JavaScript source map 可能会暴露源文件路径或客户端机密；将找回的值视为线索，并验证其实际权限。有关 Web 专项检查，请参阅 [Apache](../../network-services-pentesting/pentesting-web/apache.md) 和 [Nginx](../../network-services-pentesting/pentesting-web/nginx.md)。

对于使用 [mpm-itk](https://mpm-itk.sesse.net/) 的 Apache，启用的 `AssignUserID` 可让虚拟主机以不同用户和组的身份运行。如果低权限账户可以在该主机的 `DocumentRoot` 中写入脚本，请检查是否存在可访问的路由，确实会以指定身份执行该脚本。确认模块已加载、虚拟主机的有效配置（包括基于表达式的身份覆盖）、目录的写入和搜索权限、脚本处理程序，以及监听器的可访问性。仅凭醒目的指令或可写目录，并不能证明存在跨用户执行。

通过 Web 服务器公开的 home 目录，即使实时 `.ssh` 目录是私有的，也可能暴露包含 SSH identity 文件的备份归档。例如，[Nostromo 的 `homedirs_public` 设置](https://www.nazgul.ch/dev/nostromo_man.html)会选择从用户 home 目录中提供服务的子目录。仅发现归档路径只是线索：请验证服务器的有效映射、本地可读性或 HTTP 授权、归档内容、私钥口令，以及相应账户是否确实接受该密钥。在常规主机枚举期间，不要提取归档或打印密钥材料。

高权限本地 Web 应用的可读备份，即使其实时源代码无法访问，也可能暴露身份验证和文件读取逻辑。依赖备份前，请将其与已部署的服务进行比较。特别是，如果应用使用确定性的 ECB 分块、会针对指定文本返回新 cookie，并在之后按未转义的分隔符拆分解密后的值，那么对由调用者控制的文本追加 secret 和角色标志后再加密所生成的 cookie，就值得审查。[NIST 说明了 ECB 独立且可重复的分块映射特性](https://csrc.nist.gov/news/2022/proposal-to-revise-sp-800-38a)；这一特性可能支持对指定输入进行比较，但本身并不会授予更高角色。请确认实时路由、会话前置条件、确切的解析器/数据流、服务身份，以及独立的特权操作或文件读取路径。被动盘点应报告备份元数据和监听器所有权，而不读取归档内容或发送身份验证探测。

相同的源代码审查方法也适用于高权限的**非 HTTP** loopback 服务，例如由 SSH 支持的自定义接口。如果可访问的源代码备份显示某个命令接受调用者指定的文件路径，请检查其身份验证门槛、路径解析方式，以及在打开文件前是否会验证解析后的文件仍位于预期目录之下。在 Go 中，[`filepath.Join`](https://pkg.go.dev/path/filepath#Join) 会清理路径，但不会强制路径位于指定目录之内。请确认备份与运行中的构建相符、监听器可访问、低权限账户可以使用该命令，并且进程有权读取目标文件；拥有可读 SSH 密钥与是否允许登录是两个独立问题。报告源代码归档路径和服务所有权，不要将归档内容或密钥提取到自动化输出中。

监听在 TCP loopback 上的 PHP-FPM pool，即使其网站要求身份验证，其他本地账户仍可能访问。[PHP 警告称，能够连接到 FastCGI 的客户端可以控制请求设置，包括 `auto_prepend_file`](https://www.php.net/manual/en/install.fpm.php)。请结合实时监听器、worker UID、现有脚本路径，以及任何 `security.limit_extensions` 或 `php_admin_value` 限制，检查 pool 的 `listen` 和 `listen.allowed_clients` 设置。Pool 配置文件可能在 `env[...]` 指令中包含凭据，因此自动化盘点应报告文件路径，而非文件内容。仅凭配置文件或端口并不能证明存在跨用户执行途径；协议详情请参阅 [FastCGI guide](../../network-services-pentesting/9000-pentesting-fastcgi.md)。

对于高权限本地 API，除了代码执行，还要追踪授权流程。低权限账户可以更改的数据库角色可能会解锁某个 API 路由，但下一道边界取决于该路由的实现。例如，将请求 JSON 合并到 JavaScript 对象后调用 [`child_process.exec`](https://nodejs.org/api/child_process.html)，就值得检查是否存在[从 prototype pollution 到执行的数据流](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)。请验证实际使用的合并库及版本、输入验证、可访问路由、进程身份和子进程选项；仅凭 root 所有的 Node 监听器或易受攻击的依赖名称都只是线索。

基于文件的 CMS 存储可能会在常规 `.php` 配置文件之外保存管理员密码验证信息。例如，站点的 `data/database.js` 或 `data/settings/pass.php`。手动审查前请检查文件所有权和可读性，并避免将哈希写入自动化共享输出。可恢复的应用密码与 Unix 账户是不同的权限边界：如声称密码被重复使用，请针对具体账户和允许的身份验证方式进行验证。

应用的身份验证控制器也可能在源代码中直接包含明文登录密码，而非将密码保存在配置文件中。如果低权限用户可以读取已部署的控制器，请在本地审查其身份验证比较逻辑，并避免将任何值写入共享枚举输出。声称可实现本地提权前，请确认该代码路径处于启用状态、密码在应用中有效，并且另一个独立的高权限 Unix 账户确实接受相同密码。控制器文件名本身仅是审查线索。

Dolibarr 会将数据库连接设置（包括 `dolibarr_main_db_pass`）存储在 `htdocs/conf/conf.php` 中（[configuration reference](https://wiki.dolibarr.org/index.php/Configuration_file)）。可读文件只是凭据线索；只有经过单独验证的账户密码重复使用或其他数据库权限，才可能使其成为本地提权途径。请先检查权限，并避免在自动化输出中打印该值。

GitLab 的 Linux package 配置文件通常是 `/etc/gitlab/gitlab.rb`，但部署环境也可能在其他位置保留可读副本。[GitLab 文档](https://docs.gitlab.com/omnibus/settings/smtp/)指出，该文件可能包含 `gitlab_rails['smtp_password']`，但加密的 SMTP 设置可能会将密码保存在明文文件之外。将可读配置视为凭据线索：在声称密码被重复使用之前，请验证配置是否生效、凭据是否仍有效，以及特定的高权限账户是否接受该凭据。另外，[GitLab 在执行 `gitlab-ctl reconfigure` 时会以 root 身份将 `gitlab.rb` 作为 Ruby 代码运行](https://docs.gitlab.com/omnibus/settings/configuration/)；要将可写的生效配置文件或包含的 `from_file` 认定为代码执行问题，必须确认存在实际的特权 reconfigure 路径。配置预览可能会暴露凭据值，因此应将其输出视为敏感信息，并改为共享路径和权限信息。

自托管的 Mattermost 安装可能会将 `SqlSettings.DataSource` 保存在 `/opt/mattermost/config/config.json` 中；[Mattermost 文档](https://docs.mattermost.com/deployment-guide/server/troubleshooting)介绍了该常见路径，也说明某些部署会将生效配置存储在数据库中。可读文件可能会暴露应用数据库凭据，但这并不能证明具备数据库访问权限或 Unix root 访问权限。请验证实际生效的配置来源、数据库角色的实际权限、单独找回的任何应用密码，以及该密码是否可用于特定的高权限 Unix 账户。密码哈希格式可能会随 Mattermost 版本变化；枚举时请记录配置文件路径和访问元数据，不要打印连接字符串或查询数据库。

```bash
curl -i -H 'Host: admin.example.local' http://127.0.0.1:8080/
ffuf -w wordlist.txt -u http://127.0.0.1:8080/ -H 'Host: FUZZ.example.local' -fs 1234 # replace 1234 with the default response size
grep -R 'sourceMappingURL' /var/www /opt 2>/dev/null | head
```

对虚拟主机枚举结果使用默认响应大小或其他稳定基准进行筛选，避免每个猜测的名称看起来都有效。只有在 source map 实际部署或以其他方式可读取时，它才有用。

反向代理可能会改变应用信任哪些客户端标头。在假设 `X-Forwarded-For`、`X-Forwarded-Host` 或类似标头能够确立调用者身份之前，应比较直连请求与经代理转发的请求。结合检查代理和应用配置。

如果 PHP 将 `$_SERVER['HTTP_X_FORWARDED_FOR']` 复制到传给 [`system()`](https://www.php.net/manual/en/function.system.php) 的字符串中，应检查可访问的请求路径是否允许调用者提供该标头，以及 shell 元字符是否会原样进入该字符串。开头嵌入了 `sudo iptables` 之类的命令，**并不**意味着后续由 shell 分隔的命令也会以 root 身份运行；除非另有允许提权的有效 sudo 规则，否则这些命令会以 Web worker 的身份运行。在声称存在 root 提权路径之前，应确认 worker 身份、确切的 `sudo -l` 授权及其认证要求，以及命令的参数边界。日常主机枚举时，应检查源代码和策略，不要发送注入探测。

## 访问日志中的登录凭据

如果应用使用 `GET` 提交登录表单，用户名和密码可能成为请求 URI 中的查询参数。`POST` 请求也可以包含查询字符串；使用 `POST` 并不能隐藏意外放入 URI 的机密信息，包括输入到无关表单字段中的密码。当配置格式使用 `%r` 时，[Apache 的常见访问日志请求行](https://httpd.apache.org/docs/2.4/logs.html)会记录方法和 URI，包括其查询字符串。因此，有权读取这些日志的账户（例如某些 Linux 系统上的 `adm` 组成员）可能会发现凭据线索。检查实际日志格式和权限，然后验证该值是否为机密信息、该账户是否接受它，以及它是否跨越了权限边界。不要假设请求正文也被记录，也不要将候选值复制到共享输出中。

只检查可读取的访问日志，并避免在共享命令输出中暴露凭据值。较长的请求行还可能包含 referrer 和 user agent，因此短行筛选可能会隐藏真正相关的请求。Apache、httpd 和 Nginx 常见的访问日志路径分别为 `/var/log/apache2/access.log`、`/var/log/httpd/access_log` 和 `/var/log/nginx/access.log`。轮转后的日志可能包含较早的凭据。[通过 LFI 读取日志文件](../../pentesting-web/file-inclusion/README.md#read-access-logs-to-harvest-get-based-auth-tokens-token-replay)是获取相同数据的相关路径。

应用认证日志也可能暴露误填入失败登录**用户名**字段的密码。首先确认日志可读取，且其格式会记录提交的用户名；只在本地检查少量相关内容，不要将候选凭据复制到共享输出中。看起来像密码的用户名只是线索，并不能证明它是有效密码或具有更高权限。声称存在权限转换之前，应先验证预期账户，并确认该凭据是否在特定服务或 Unix 账户中复用。

如果另一个身份下的定时客户端会向某个端点提交凭据，那么可写的 Web 登录处理程序值得单独检查。确认当前**生效**的处理程序是否可写、客户端实际的计划任务和请求路径、它发送的是谁的凭据，以及该应用密码是否也能用于更高权限的操作系统账户。仅有可写页面或周期性进程，并不能证明存在权限转换。被动盘点应报告路径权限和作业元数据，不要修改处理程序或收集密码。

启用 FTP 事件日志记录时，Suricata 的 EVE JSON 日志也可能记录 FTP `USER` 和 `PASS` 命令及其 `command_data`。在检查本地少量相关内容之前，应确认 `/var/log/suricata/eve*.json*` 是否可读，包括轮转或压缩文件。可读取的 EVE 文件仅是线索：应确认其中记录了 FTP 事件、数据包含可用凭据，以及凭据跨越了权限边界。避免在共享枚举输出中打印 `command_data`。Suricata 文档介绍了 [FTP 事件字段](https://docs.suricata.io/en/suricata-8.0.2/output/eve/eve-json-format.html)以及 [EVE 轮转和文件名变体](https://docs.suricata.io/en/suricata-7.0.15/output/eve/eve-json-output.html)。

## 生成的 Apache 配置和管道日志

[remco](https://github.com/HeavyHorst/remco) 可以监视键值后端，将模板渲染到 Apache 配置文件中，并运行 reload 命令。检查正在运行的 remco 进程身份、配置的模板源和目标、受监视的键前缀，以及后端值是否会直接插入 `ServerName` 等 Apache 指令中。仅有本地后端监听器，并不能证明当前用户可以写入受监视的键；在声称存在提权路径之前，应先验证后端认证和权限。

可写后端值中的未转义换行符可能会将原本预期的单个指令值变成额外的 Apache 指令。[Apache 管道日志](https://httpd.apache.org/docs/2.4/logs.html#piped)尤其敏感：包含 `|` 命令的 `CustomLog` 或 `ErrorLog` 会以父级 httpd 的身份（通常是 root）启动辅助进程；`|$` 则要求 Apache 使用 shell。枚举期间，应检查生成的配置及其 reload 路径，不要修改后端数据或重启服务。请勿公开完整的管道命令，因为其参数可能包含机密信息。

## 认证和服务身份

Monit 的控制文件通常是 `~/.monitrc` 或 `/etc/monitrc`，但 `monit -c` 可以指定其他路径。可读取的文件可能包含 Web 界面的 `set httpd` 和 `allow user:password` 条目，该界面通常监听本地端口 2812。检查文件所有者和权限后再查看内容，并避免在共享枚举输出中暴露密码值。Web 凭据只能授予配置的 Monit 角色；只读用户无法调用控制操作。若要确认存在单独的 Unix 账户提权路径，必须确认密码复用，或证明已认证角色确实可以触发某项特权 Monit 操作。参见 [Monit 控制文件和认证文档](https://www.mmonit.com/monit/documentation/monit.html)。

对于 Webmin，`/etc/webmin/miniserv.conf` 标识服务器设置，`/etc/webmin/webmin.acl` 则记录用户可访问的模块；[Webmin 文档说明了模块授权边界](https://webmin.com/docs/development/creating-modules/)。Unix 密码或可读取的 ACL 文件本身并不会授予 Webmin 会话。应确认实际的认证映射、可访问的监听器、已认证账户、有效的 Package Updates 模块权限、已安装的代码或供应商修复，以及 Webmin 进程身份。在受影响的 1.910 及更早版本中，[CVE-2019-12840](https://nvd.nist.gov/vuln/detail/CVE-2019-12840) 允许拥有该模块权限的账户通过更新处理程序执行命令。被动枚举期间应报告配置路径和权限，但不要打印凭据或尝试执行更新。

```bash
find /etc/pam.d /etc/sssd /etc/postfix -maxdepth 2 -type f -ls 2>/dev/null
systemctl cat sssd postfix jenkins 2>/dev/null
getent passwd
```

- [PAM](pam-pluggable-authentication-modules.md) 管理特定服务的身份验证；可写的策略或模块路径可能改变登录行为。
- LDAP/SSSD 配置可能会泄露目录端点、绑定身份和访问规则。找回的绑定密码可能允许查询超出当前 OS 账户权限范围的 LDAP 内容；请使用确切的绑定身份测试，并检查目录 ACL。检查文件权限后再查看机密信息；[Linux Active Directory](../user-information/linux-active-directory.md) 和 [FreeIPA](freeipa-pentesting.md) 介绍了票据和目录的使用。
- Postfix 别名可以将收到的邮件通过管道传递给本地命令。如果低权限用户可以更改别名所引用的脚本，邮件投递可能会以投递身份触发其代码。确认这条路径前，请检查别名映射和脚本所有权；参见 [SMTP and mail service testing](../../network-services-pentesting/pentesting-smtp/README.md)。
- Jenkins 和其他 CI 服务可能会以权限较高的本地账户运行作业。测试 Pipeline 或插件前，请检查服务用户、可写的作业/工作区路径，以及本地管理界面。同时检查**作业可用的凭据**及其可用于身份验证的账户：[SSH Agent step](https://www.jenkins.io/doc/pipeline/steps/ssh-agent/) 中的 Pipeline 可以使用 SSH 凭据对应的用户身份访问主机，即使 Jenkins 本身以权限较低的 Unix 账户运行。声称存在主机权限提升前，请确认当前 Jenkins 身份拥有 `Job/Create`、`Job/Configure` 或其他可有效修改 Pipeline 的途径，该凭据在此作业的作用范围内，且目标 SSH 账户接受该密钥。凭据的显示名称或 ID 本身无法证明上述任何条件。Jenkins 警告称，作业创建者以及通常的作业配置者，可以任意使用其作用范围内可用的凭据；因此，[credential scope](https://www.jenkins.io/doc/book/security/credentials/) 和 [Pipeline trust](https://www.jenkins.io/doc/book/security/securing-org-folders-and-multibranch-pipelines/) 与服务 UID 同样重要。请勿将凭据值和私钥写入共享的枚举输出。

## Gogs 仓库文件写入

对于本地 Gogs 服务，请结合 `gogs web` 进程所有者、可执行文件版本和 `custom/conf/app.ini` 进行判断。配置可能会暴露服务身份、仓库根目录、监听地址，以及是否禁用了注册。仅监听 loopback 的服务仍可由本地用户访问。最高至 0.13.3 的 Gogs 版本存在经过身份验证的 `PutContents` 符号链接文件写入问题（[CVE-2025-8110](https://github.com/advisories/GHSA-mq8m-42gh-wq7r)）：仓库写入者可以提交符号链接，然后通过 API 将写入操作定向到该链接。由此产生的文件访问权限与 Gogs 进程相同，因此以 root 运行的实例需要及时处理。声称存在可用路径前，请验证已部署的修复情况和身份验证要求；API 错误并不能证明文件写入失败。

## Gitea 仓库描述 XSS 和高权限浏览者

Gitea 1.22.0 允许在仓库描述中存储 JavaScript（[CVE-2024-6886](https://github.com/advisories/GHSA-4h4p-553m-46qh)）；1.22.1 已修复此问题。能够编辑描述的用户可以影响权限更高的浏览器会话，前提是该用户查看仓库并激活恶意链接。随后，该浏览器身份可能暴露私有仓库内容或其他应用数据。若要进一步实现本地权限提升，还需要该内容可获取的凭据或权限，例如重复使用的管理员密码；仅凭 Gitea 进程所有者身份不足以证明会影响 root。声称存在攻击链前，请检查已部署的版本、描述编辑权限、浏览者的操作流程，以及实际的浏览器交互。

## Cobbler 配置 API

Cobbler 的管理服务会开放 XML-RPC API，通常使用端口 `25151`。评估其影响前，请检查监听器和 `cobblerd` 进程所有者；仅监听 loopback 的 API 仍可由主机上的用户访问。检查 `/etc/cobbler/modules.conf` 中的身份验证和授权模块、`/etc/cobbler/settings` 或 `/etc/cobbler/settings.yaml` 中的服务设置，以及 `/etc/cobbler/users.conf`、`/etc/cobbler/users.digest` 和 `/var/lib/cobbler/web.ss` 的权限。摘要和共享密钥文件包含凭据材料，因此默认情况下只记录其是否可读，不要打印其内容。

```bash
ps -eo user,pid,args | grep '[c]obblerd'
ss -ltn 2>/dev/null | grep ':25151'
for file in /etc/cobbler/modules.conf /etc/cobbler/settings /etc/cobbler/settings.yaml \
            /etc/cobbler/users.conf /etc/cobbler/users.digest /var/lib/cobbler/web.ss; do
    [ -e "$file" ] && ls -l "$file"
done
```

**CVE-2024-47533** 是 Cobbler 3.0.0 至 3.2.2 以及 3.3.0 至 3.3.6 中的 XML-RPC 身份验证绕过漏洞。读取共享密钥时出错会返回可预测的值 `-1`，而 API 会将其接受为密码。对应的修复版本为 3.2.3 和 3.3.7。软件包版本只能作为线索；在报告漏洞风险前，请先核实已部署的代码以及是否已回移修复。

如果 `cobblerd` 以 root 身份运行，经过身份验证的 API 会话可能成为特权执行路径。在受影响的实现中，`background_import` 会将用户控制的 `rsync_flags` 传入 shell 命令，而渲染用户控制的 Cheetah autoinstall 模板时可能会执行 Python。测试这两条路径之前，请先检查 API 权限和已安装的版本。限制对管理 API 的访问，修补身份验证绕过漏洞，并确保只有服务管理员可以读取配置文件和凭据文件。

## Motion 和 motionEye 配置

检查 `/etc/motioneye/motioneye.conf` 中的 `conf_path`，然后查看该目录中的 `motion.conf` 和少量 `camera-*.conf` 文件。报告是否存在可读取的 `# @admin_password` 哈希，但不要打印哈希。[较旧版本的 motionEye 会以过于宽松的读取权限写入这些文件](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-rhgp-6wq6-9j67)；该问题已在 0.44.0 中修复。请结合检查 Motion 的 `webcontrol_port`、`webcontrol_parms`、`webcontrol_auth_method` 和 `webcontrol_localhost` 设置：启用高级控制（`2` 或 `3`）且禁用身份验证时，本地用户可能执行高权限操作，即使监听器绑定在 loopback 地址上也不例外。[Motion 文档说明了这些设置的取值和默认值](https://motion-project.github.io/motion_config.html)。

在 0.43.1b5 之前的 motionEye 中，管理员会话可将摄像头文件名设置转化为命令执行，前提是 Motion 处理了该设置（[CVE-2025-60787](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-j945-qm58-4gjx)）。在声称存在权限提升之前，请确认运行版本、服务身份、可用的身份验证路径，以及是否配置了摄像头。仅凭配置无法证明服务正在运行或具有特权。

服务名称或已安装的软件包只能作为线索。权限边界取决于可触达的输入、进程身份、可写配置，以及这些输入最终控制的命令或文件。

## 本地 AWS 模拟器和存储的凭据

主机用户可能通过已发布的 loopback 端点访问运行在容器中的 AWS 兼容模拟器。在评估对 [Secrets Manager](https://docs.localstack.cloud/aws/services/secretsmanager/) 或 [KMS](https://docs.localstack.cloud/aws/services/kms/) 的访问权限之前，请交叉核实当前监听器、客户端选用的端点和账户，以及模拟器已安装的授权设置。在 LocalStack 中，[IAM 策略强制执行是单独的设置](https://docs.localstack.cloud/aws/developer-tools/security-testing/iam-policy-enforcement/)；不要仅凭凭据文件、IAM 策略或监听器推断实际生效的 API 权限。请确认已安装版本和配置的实际行为。

只有当当前 API 身份能够检索存储的 secret，且另一个权限更高的账户接受取回的凭据时，该 secret 才能用于本地权限提升。读取本地加密 blob 还需要文件读取权限、匹配且可用的 KMS 密钥和算法，以及有效的解密权限。对于[非对称 KMS 密钥](https://docs.aws.amazon.com/cli/latest/reference/kms/decrypt.html)，解密请求必须指定加密该 blob 时使用的算法。常规枚举中的自动主机清点应仅收集进程、监听器、配置路径和文件权限证据；不要在其中请求或打印 secret 值或解密后的明文。
{{#include ../../banners/hacktricks-training.md}}
