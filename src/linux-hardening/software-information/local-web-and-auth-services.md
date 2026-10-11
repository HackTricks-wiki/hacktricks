# 本地 Web 和身份验证服务

{{#include ../../banners/hacktricks-training.md}}

Linux shell 提供了 Web 和身份验证服务的主机侧视图：进程参数、监听端口、unit 文件、配置、日志以及仅限本地访问的接口。利用这些信息，将可访问的服务与其实际使用的账户和文件关联起来。

## 绘制本地 Web 栈的映射

```bash
ss -lntup
ps -eo user,pid,args | grep -E '[a]pache|[n]ginx|[p]hp-fpm|[j]enkins'
systemctl list-units --type=service --state=running 2>/dev/null
find /etc/apache2 /etc/httpd /etc/nginx -maxdepth 3 -type f 2>/dev/null | head -80
```

检查虚拟主机名称、文档根目录、代理路由、上传目录、PHP 执行设置，以及包含凭据的配置文件。回环监听器可能可通过代理或 SSH 隧道访问。要针对本地监听器测试指定的虚拟主机，请发送预期的 `Host` header，或使用 `curl --resolve` 指定正确的地址和端口。虚拟主机枚举还可能发现默认响应中未出现的名称。确认 Apache 是否允许 `.htaccess` 覆盖设置，以及上传路径能否执行 PHP，再将可写上传目录视为代码执行入口。已部署的 JavaScript source map 可能暴露源代码路径或客户端机密；将恢复出的值视为线索，并验证其实际权限。有关 Web 专项检查，请参阅 [Apache](../../network-services-pentesting/pentesting-web/apache.md) 和 [Nginx](../../network-services-pentesting/pentesting-web/nginx.md)。

对于使用 [mpm-itk](https://mpm-itk.sesse.net/) 的 Apache，启用的 `AssignUserID` 可以让虚拟主机以不同的用户和组运行。如果权限较低的账户能在该主机的 `DocumentRoot` 中写入脚本，请检查是否存在可访问的路由，能以指定身份实际执行该脚本。确认模块已加载、虚拟主机的生效配置（包括基于表达式的身份覆盖）、目录的写入和搜索权限、脚本处理器以及监听器的可访问性。仅凭醒目的指令或可写目录，不能证明存在跨用户执行。

通过 Web 服务器公开的主目录可能会泄露 SSH 身份文件的备份归档，即使实时的 `.ssh` 目录是私有的。例如，[Nostromo 的 `homedirs_public` 设置](https://www.nazgul.ch/dev/nostromo_man.html)会选择从用户主目录提供服务的子目录。仅发现归档路径只是线索：请验证服务器的生效映射、本地可读性或 HTTP 授权、归档内容、私钥口令，以及对应账户是否确实接受该密钥。常规主机枚举期间不要解压归档或输出密钥内容。

即使无法访问实时源代码，高权限本地 Web 应用的可读备份也可能暴露身份验证和文件读取逻辑。在依赖备份前，请先将其与已部署的服务进行比对。特别是，如果应用使用确定性的 ECB 分块、会针对所选文本返回新 cookie，并在之后按未转义的分隔符拆分解密值，那么对“加密调用者可控文本，后接密钥和角色标志”构造的 cookie 应进行审查。[NIST 解释了 ECB 独立且可重复的分块映射特性](https://csrc.nist.gov/news/2022/proposal-to-revise-sp-800-38a)；此特性可能支持对所选输入进行比较，但本身不会授予更高角色。请确认实时路由、会话前置条件、准确的解析器和数据流、服务身份，以及独立的特权操作或文件读取路径。被动清点应报告备份元数据和监听器所有者，不要读取归档内容或发送身份验证探测。

同样的源码审查方法也适用于特权**非 HTTP**回环服务，例如由自定义 SSH 支持的接口。如果可访问的源码备份显示某个命令接受调用者指定的文件路径，请检查其身份验证门槛、路径解析方式，以及它是否确保解析后的文件仍位于预期目录之下再打开。在 Go 中，[`filepath.Join`](https://pkg.go.dev/path/filepath#Join)会清理路径，但不会强制执行路径包含关系。请确认备份与正在运行的构建相符、监听器可访问、低权限账户能够使用该命令，并且进程能够读取目标文件；拥有可读 SSH 密钥与登录策略是两个不同的问题。报告源代码归档路径和服务所有者，不要将归档内容或密钥解压到自动化输出中。

监听在 TCP 回环接口上的 PHP-FPM pool，即使其网站要求身份验证，其他本地账户仍可能访问。[PHP 警告，能够连接 FastCGI 的客户端可以控制请求设置，包括 `auto_prepend_file`](https://www.php.net/manual/en/install.fpm.php)。请结合实时监听器、worker UID、现有脚本路径，以及任何 `security.limit_extensions` 或 `php_admin_value` 限制，审查 pool 的 `listen` 和 `listen.allowed_clients` 设置。pool 配置文件的 `env[...]` 指令中可能包含凭据，因此自动化清点应报告其路径，而不是文件内容。仅凭配置文件或端口，不能证明存在跨用户执行路径；协议详情请参阅 [FastCGI guide](../../network-services-pentesting/9000-pentesting-fastcgi.md)。

对于特权本地 API，除了代码执行之外，也要追踪授权逻辑。低权限账户能够更改的数据库角色可能解锁某个 API 路由，但后续的安全边界取决于该路由的实现。例如，将请求 JSON 合并到 JavaScript 对象，再调用 [`child_process.exec`](https://nodejs.org/api/child_process.html)，就值得检查是否存在[从 prototype pollution 到执行的数据流](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)。请验证实际使用的合并库及其版本、输入验证、可访问路由、进程身份和子进程选项；仅凭 root 拥有的 Node 监听器或易受攻击的依赖名称，都只能算线索。

基于文件存储的 CMS 可能会将管理员密码验证值保存在常规 `.php` 配置文件之外。例如，站点的 `data/database.js` 或 `data/settings/pass.php`。手动检查前先确认文件所有者和可读性，并避免将哈希写入自动化共享输出。可恢复的应用密码与 Unix 账户是不同的权限边界：任何关于密码复用的结论，都应针对具体账户和允许的身份验证方式进行验证。

应用的身份验证控制器也可能在源码中直接包含明文登录密码，而不是将其保存在配置文件中。如果低权限用户能够读取已部署的控制器，请在本地检查其身份验证比较逻辑，并避免将任何值写入共享枚举输出。请确认该代码路径正在使用、密码对该应用有效，并且另一个独立的高权限 Unix 账户确实接受相同密码，然后再声称实现了本地提权。仅凭控制器文件名只能作为审查线索。

Dolibarr 将数据库连接设置（包括 `dolibarr_main_db_pass`）保存在 `htdocs/conf/conf.php` 中（[配置参考](https://wiki.dolibarr.org/index.php/Configuration_file)）。可读文件只是凭据线索；只有经过验证的独立账户密码复用或其他数据库权限，才能将其转化为本地提权。请先检查权限，避免在自动化输出中打印该值。

GitLab Linux package 的配置文件通常为 `/etc/gitlab/gitlab.rb`，但部署中可能会在其他位置留有可读副本。[GitLab 文档](https://docs.gitlab.com/omnibus/settings/smtp/)指出，该文件可能包含 `gitlab_rails['smtp_password']`，不过加密的 SMTP 设置可能会将密码保存在明文文件之外。将可读配置视为凭据线索：在声称密码复用前，请验证配置是否生效、凭据是否仍有效，以及某个特定的高权限账户是否接受该凭据。另外，[GitLab 会在 `gitlab-ctl reconfigure` 期间以 root 身份将 `gitlab.rb` 作为 Ruby 代码运行](https://docs.gitlab.com/omnibus/settings/configuration/)；要将可写的生效文件或被包含的 `from_file` 判定为执行问题，必须确认存在实际的特权 reconfigure 路径。配置预览可能会暴露凭据值，因此请将其输出视为敏感信息，只共享路径和权限。

自托管的 Mattermost 安装可能会将 `SqlSettings.DataSource` 保存在 `/opt/mattermost/config/config.json` 中；[Mattermost 文档](https://docs.mattermost.com/deployment-guide/server/troubleshooting)介绍了这一常见路径，也说明有些部署会将生效配置存储在数据库中。可读文件可能暴露应用数据库凭据，但这不能证明可以访问数据库或获得 Unix root 权限。请验证生效的配置来源、数据库角色的实际权限、任何单独恢复的应用密码，以及该密码是否适用于某个特定的高权限 Unix 账户。Mattermost 的密码哈希格式可能随版本变化；清点期间请记录配置路径和访问元数据，不要打印连接字符串或查询数据库。

```bash
curl -i -H 'Host: admin.example.local' http://127.0.0.1:8080/
ffuf -w wordlist.txt -u http://127.0.0.1:8080/ -H 'Host: FUZZ.example.local' -fs 1234 # replace 1234 with the default response size
grep -R 'sourceMappingURL' /var/www /opt 2>/dev/null | head
```

对 virtual-host 扫描结果使用默认响应大小或其他稳定基准进行筛选，避免每个猜测的名称看起来都有效。只有在 source map 确实已部署或可通过其他方式读取时，它才有用。

Reverse proxy 可能会改变应用信任哪些客户端 header。在假定 `X-Forwarded-For`、`X-Forwarded-Host` 或类似 header 能确立调用方身份之前，应比较直接请求与经 proxy 转发的请求。应一并检查 proxy 和应用配置。

如果 PHP 将 `$_SERVER['HTTP_X_FORWARDED_FOR']` 复制到传给 [`system()`](https://www.php.net/manual/en/function.system.php) 的字符串中，应检查可访问的请求路径是否允许调用方提供 header，以及 shell 元字符是否会原样进入该字符串。在命令开头嵌入类似 `sudo iptables` 的命令，**并不会**让之后由 shell 分隔的命令以 root 身份运行；除非另有有效的 sudo 规则允许权限提升，否则这些命令会以 web worker 的身份运行。在声称存在 root 路径之前，应确认 worker 身份、准确的 `sudo -l` 授权及其认证要求，以及命令的参数边界。常规主机枚举时，应检查源代码和策略，不要发送注入探测。

## 登录凭据记录在访问日志中

如果应用使用 `GET` 提交登录表单，用户名和密码可能成为请求 URI 中的 query parameter。`POST` 请求也可以包含 query string；使用 `POST` 并不能隐藏意外放入 URI 的秘密，包括填入无关表单字段的密码。[Apache 常见访问日志中的请求行](https://httpd.apache.org/docs/2.4/logs.html)会在配置格式使用 `%r` 时记录 method 和 URI，包括 query string。因此，有权读取这些日志的账户（例如某些 Linux 系统上的 `adm` 组成员）可能会发现可供追查的凭据线索。检查实际日志格式和权限，然后确认该值确实是秘密、该账户接受此凭据，并且它跨越了权限边界。不要假定请求 body 被记录，也不要将候选值复制到共享输出中。

只检查可读取的访问日志，并确保凭据值不会出现在共享命令输出中。较长的请求行还可能包含 referrer 和 user agent，因此短行筛选可能会隐藏真正需要查看的请求。Apache、httpd 和 Nginx 常见的访问日志位置分别为 `/var/log/apache2/access.log`、`/var/log/httpd/access_log` 和 `/var/log/nginx/access.log`。轮转后的日志可能包含较早的凭据。[通过 LFI 读取日志](../../pentesting-web/file-inclusion/README.md#read-access-logs-to-harvest-get-based-auth-tokens-token-replay)是获取相同数据的相关途径。

应用认证日志也可能意外暴露填入失败登录的**用户名**字段中的密码。首先确认日志可读，且其格式会记录提交的用户名；仅在本地查看少量相关内容，不要将候选凭据复制到共享输出中。看起来像密码的用户名只是线索，并不能证明它是有效密码或拥有更高权限。声称发生权限转换之前，应确认目标账户，并验证该凭据是否在特定服务或 Unix 账户上复用。

如果另一个身份下的计划任务客户端会向某个 web endpoint 提交凭据，则应单独审查可写的 web 登录处理程序。确认对**当前生效**处理程序的写入权限、客户端的实际计划任务和请求路径、它发送的是谁的凭据，以及该应用密码能否独立用于更高权限的操作系统账户。仅有可写页面或周期性进程，并不能证明发生了权限转换。被动枚举应报告路径权限和任务元数据，不要修改处理程序或收集密码。

启用 FTP 事件日志记录时，Suricata 的 EVE JSON 日志也可能记录 FTP `USER` 和 `PASS` 命令及其 `command_data`。在本地查看少量相关内容之前，应先检查 `/var/log/suricata/eve*.json*` 是否可读，包括轮转或压缩文件。可读取 EVE 文件仅是线索：应确认已记录 FTP 事件、数据中包含可用凭据，并且该凭据跨越了权限边界。避免在共享枚举输出中打印 `command_data`。Suricata 文档介绍了 [FTP 事件字段](https://docs.suricata.io/en/suricata-8.0.2/output/eve/eve-json-format.html)以及 [EVE 轮转和文件名变体](https://docs.suricata.io/en/suricata-7.0.15/output/eve/eve-json-output.html)。

## 生成的 Apache 配置和管道日志

[remco](https://github.com/HeavyHorst/remco) 可以监视 key/value backend，将 template 渲染为 Apache 配置文件，并运行 reload 命令。检查运行中的 remco 进程身份、配置的 template 源和目标、受监视的 key 前缀，以及 backend 值是否会直接插入 `ServerName` 等 Apache 指令。在本地监听的 backend 本身并不能证明当前用户可以写入受监视的 key；声称存在权限提升之前，应先验证 backend 的认证和权限。

可写 backend 值中的未转义换行符可能会将一个预期的指令值变成多个 Apache 指令。[Apache 管道日志](https://httpd.apache.org/docs/2.4/logs.html#piped)尤其敏感：包含 `|` 命令的 `CustomLog` 或 `ErrorLog` 会以父 httpd 进程的身份（通常是 root）启动辅助进程；`|$` 则要求 Apache 使用 shell。枚举期间应审查生成的配置及其 reload 路径，不要修改 backend 数据或重启服务。完整的管道命令可能包含秘密，因此应予以保密。

## 认证与服务身份

Monit 的控制文件通常是 `~/.monitrc` 或 `/etc/monitrc`，但 `monit -c` 可以指定其他路径。可读取的文件可能包含其 web interface 的 `set httpd` 和 `allow user:password` 条目，通常使用本地 2812 端口。查看前应检查文件的所有者和权限，并确保密码值不会出现在共享枚举输出中。Web 凭据仅授予配置的 Monit 角色；只读用户不能执行控制操作。要提升为另一个 Unix 账户，需要确认密码复用，或确认已认证角色确实能够触发特权 Monit 操作。请参阅 [Monit 控制文件和认证文档](https://www.mmonit.com/monit/documentation/monit.html)。

对于 Webmin，`/etc/webmin/miniserv.conf` 标明服务器设置，`/etc/webmin/webmin.acl` 记录用户可以访问哪些模块；[Webmin 文档说明了模块授权边界](https://webmin.com/docs/development/creating-modules/)。Unix 密码或可读取的 ACL 文件本身并不会授予 Webmin 会话。应确认实际的认证映射、可访问的 listener、已认证账户、有效的 Package Updates 模块权限、已安装代码或供应商修复，以及 Webmin 进程身份。在受影响的 1.910 及更早版本中，[CVE-2019-12840](https://nvd.nist.gov/vuln/detail/CVE-2019-12840) 允许拥有该模块权限的账户通过其更新处理程序执行命令。被动枚举时应报告配置路径和权限，不要打印凭据或尝试更新。

```bash
find /etc/pam.d /etc/sssd /etc/postfix -maxdepth 2 -type f -ls 2>/dev/null
systemctl cat sssd postfix jenkins 2>/dev/null
getent passwd
```

- [PAM](pam-pluggable-authentication-modules.md) 管理特定服务的身份验证；可写的策略或模块路径可能改变登录行为。
- LDAP/SSSD 配置可能暴露目录端点、绑定身份和访问规则。恢复出的绑定密码可能允许查询当前 OS 账户之外的 LDAP 内容；请使用确切的绑定身份测试，并检查目录 ACL。检查文件权限后再查看机密信息；[Linux Active Directory](../user-information/linux-active-directory.md) 和 [FreeIPA](freeipa-pentesting.md) 介绍了票据和目录的使用。
- Postfix 别名可以将收到的邮件通过管道传递给本地命令。如果权限较低的用户可以修改被引用的脚本，邮件投递可能会以投递身份触发其代码。在断言存在该利用路径之前，请检查别名映射和脚本所有权；参见 [SMTP and mail service testing](../../network-services-pentesting/pentesting-smtp/README.md)。
- Jenkins 和其他 CI 服务可能会以高权限本地账户运行作业。测试 Pipeline 或插件之前，请检查服务用户、可写的作业/工作区路径和本地管理界面。还要检查**作业可用的凭据**以及它们可用于身份验证的账户：[Pipeline 使用](https://www.jenkins.io/doc/pipeline/steps/ssh-agent/)中的 [SSH Agent step](https://www.jenkins.io/doc/pipeline/steps/ssh-agent/) 时，即使 Jenkins 本身以权限较低的 Unix 账户运行，也可以使用 SSH 凭据对应的用户身份访问主机。断言存在主机权限提升之前，请确认当前 Jenkins 身份具有 `Job/Create`、`Job/Configure` 或其他能修改 Pipeline 的有效途径，该凭据对该作业可用，并且目标 SSH 账户接受此密钥。凭据的显示名称或 ID 本身无法证明其中任何条件。Jenkins 提醒，作业创建者以及通常的作业配置者，可以任意使用其权限范围内可用的凭据；因此，[credential scope](https://www.jenkins.io/doc/book/security/credentials/) 和 [Pipeline trust](https://www.jenkins.io/doc/book/security/securing-org-folders-and-multibranch-pipelines/) 与服务 UID 同样重要。不要将凭据值和私钥输出到共享的枚举结果中。

## Gogs 仓库文件写入

对于本地 Gogs 服务，请结合 `gogs web` 进程所有者、可执行文件版本和 `custom/conf/app.ini` 进行分析。配置可能会暴露服务身份、仓库根目录、监听地址，以及是否禁用了注册。仅监听 loopback 的服务仍可由本地用户访问。Gogs 0.13.3 及更早版本存在一个经过身份验证的 `PutContents` 符号链接文件写入问题（[CVE-2025-8110](https://github.com/advisories/GHSA-mq8m-42gh-wq7r)）：仓库写入者可以提交符号链接，然后通过它定向 API 写入。由此产生的文件访问权限与 Gogs 进程相同，因此以 root 运行的实例需要及时处理。在断言存在可用路径之前，请验证已部署的修复和身份验证要求；API 错误并不能证明文件写入失败。

## Gitea 仓库描述 XSS 与高权限查看者

Gitea 1.22.0 允许在仓库描述中存储 JavaScript（[CVE-2024-6886](https://github.com/advisories/GHSA-4h4p-553m-46qh)）；1.22.1 已修复此问题。能够编辑描述的用户可以影响权限更高的浏览器会话，前提是该用户查看仓库并激活恶意链接。随后，该浏览器身份可能暴露私有仓库内容或其他应用数据。要实现单独的本地权限提升，还需要通过该内容获取凭据或权限，例如重复使用的管理员密码；仅凭 Gitea 进程所有者无法证明会造成 root 级影响。在断言存在利用链之前，请检查已部署的版本、描述编辑权限、查看者的操作流程以及实际的浏览器交互。

## Cobbler 配置 API

Cobbler 的管理服务会提供 XML-RPC API，通常使用端口 `25151`。评估其影响之前，请检查监听器和 `cobblerd` 进程所有者；即使 API 仅监听 loopback，主机上的用户仍然可以访问。检查 `/etc/cobbler/modules.conf` 中的身份验证和授权模块、`/etc/cobbler/settings` 或 `/etc/cobbler/settings.yaml` 中的服务设置，以及 `/etc/cobbler/users.conf`、`/etc/cobbler/users.digest` 和 `/var/lib/cobbler/web.ss` 的权限。摘要文件和共享密钥文件包含凭据材料，因此默认情况下只记录这些文件是否可读，不要打印其内容。

```bash
ps -eo user,pid,args | grep '[c]obblerd'
ss -ltn 2>/dev/null | grep ':25151'
for file in /etc/cobbler/modules.conf /etc/cobbler/settings /etc/cobbler/settings.yaml \
            /etc/cobbler/users.conf /etc/cobbler/users.digest /var/lib/cobbler/web.ss; do
    [ -e "$file" ] && ls -l "$file"
done
```

**CVE-2024-47533** 是 Cobbler 3.0.0 至 3.2.2 以及 3.3.0 至 3.3.6 中的 XML-RPC authentication bypass。读取共享密钥时发生错误会返回可预测的值 `-1`，而 API 会将其接受为密码。对应的修复版本为 3.2.3 和 3.3.7。软件包版本只是一个线索；报告存在风险前，请先核实部署的代码以及是否有 backported fix。

当 `cobblerd` 以 root 身份运行时，经过身份验证的 API session 可能成为特权执行路径。在受影响的实现中，`background_import` 会将用户控制的 `rsync_flags` 传入 shell command，而渲染用户控制的 Cheetah autoinstall template 时可能执行 Python。测试任一路径前，请检查 API 权限和已安装版本。限制对管理 API 的访问，修补 authentication bypass，并确保只有服务管理员能够读取配置和凭据文件。

## Motion 和 motionEye 配置

检查 `/etc/motioneye/motioneye.conf` 中的 `conf_path`，然后检查该目录中的 `motion.conf` 和少量 `camera-*.conf` 文件。报告是否存在可读取的 `# @admin_password` hash，但不要打印该 hash。[较旧的 motionEye 版本会以宽松的读取权限写入这些文件](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-rhgp-6wq6-9j67)；该问题已在 0.44.0 中修复。结合检查 Motion 的 `webcontrol_port`、`webcontrol_parms`、`webcontrol_auth_method` 和 `webcontrol_localhost` 设置：如果启用了高级控制（`2` 或 `3`）但禁用了身份验证，本地用户可能执行强大的操作，即使监听器绑定在 loopback 上也不例外。[Motion 文档说明了这些值和默认值](https://motion-project.github.io/motion_config.html)。

在 0.43.1b5 之前，对 motionEye 的 admin session 可以将摄像头文件名设置转化为命令执行，前提是 Motion 对其进行处理（[CVE-2025-60787](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-j945-qm58-4gjx)）。在声称存在提权之前，请确认运行版本、服务身份、可用的身份验证路径，以及是否配置了摄像头。仅凭配置无法证明服务正在运行或具有特权。

服务名称或已安装的软件包只是线索。权限边界取决于可触达的输入、进程身份、可写配置，以及该输入最终控制的命令或文件。

## 本地 AWS emulator 和存储的凭据

主机用户可能通过已发布的 loopback endpoint 访问运行在容器中的 AWS 兼容 emulator。在评估对 [Secrets Manager](https://docs.localstack.cloud/aws/services/secretsmanager/) 或 [KMS](https://docs.localstack.cloud/aws/services/kms/) 的访问权限前，请结合检查当前监听器、客户端选择的 endpoint 和 account，以及 emulator 已安装的授权设置。在 LocalStack 中，[IAM policy enforcement 是一项独立设置](https://docs.localstack.cloud/aws/developer-tools/security-testing/iam-policy-enforcement/)；不要仅凭凭据文件、IAM policy 或监听器推断有效的 API 权限。请确认已安装版本和配置的实际行为。

存储的 secret 只有在当前 API identity 能够取回它，且另一个权限更高的 account 会接受恢复出的凭据时，才可用于本地提权。解密本地 blob 还需要文件读取权限、匹配且可用的 KMS key 和算法，以及有效的解密权限。对于 [非对称 KMS key](https://docs.aws.amazon.com/cli/latest/reference/kms/decrypt.html)，decrypt request 必须指定用于加密 blob 的算法。自动化主机盘点应仅收集进程、监听器、配置路径和文件权限方面的证据；常规枚举时不要请求或打印 secret 值或解密后的明文。
{{#include ../../banners/hacktricks-training.md}}
