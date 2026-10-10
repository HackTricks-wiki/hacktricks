# Linux 主机上的数据库和机密材料

{{#include ../../banners/hacktricks-training.md}}

数据库和应用凭据通常与其所支持的服务存放在一起。在测试账户是否能够读取数据或执行特权操作之前，先梳理进程、本地 socket 或端口、配置和凭据文件。

## 查找本地数据服务和凭据

```bash
ss -lntup
ss -lnx
ps -eo user,pid,args | grep -E '[m]ysqld|[m]ariadbd|[p]ostgres|[r]edis-server|[m]ongod'
find /etc /opt /var/www /home -type f \( -name '*.env' -o -name '*config*' -o -name '.my.cnf' -o -name '.pgpass' \) -ls 2>/dev/null | head -100
```

检查可读的应用配置、部署文件、服务环境文件和备份，查找连接字符串或密钥。数据库进程的 Unix socket 与其 TCP 监听器可能有不同的访问规则。数据库权限不同于 OS 权限：恢复出的 DB 密码仅授予分配给该 DB 账户的角色，除非能证明还有其他访问路径。在 PostgreSQL 中，行级安全策略可能会对某个角色隐藏记录，而拥有策略管理权限的角色可以更改其可见范围；应区分数据访问与策略管理。请参阅针对 [MySQL/MariaDB](../../network-services-pentesting/pentesting-mysql.md)、[PostgreSQL](../../network-services-pentesting/pentesting-postgresql.md) 和 [Redis](../../network-services-pentesting/6379-pentesting-redis.md) 的专用指南。

其他账户 home 目录中可读的自动化脚本，可能内嵌凭据，即使文件名中没有提到密码。例如，Python 脚本可以启动 `su`，并通过 [`pexpect.sendline`](https://pexpect.readthedocs.io/en/latest/api/pexpect.html) 将明文传给密码提示；[`su`](https://man7.org/linux/man-pages/man1/su.1.html) 仍会执行其身份验证策略。将其视为账户切换前，请确认当前用户可以遍历该目录并读取确切的脚本、明文确实是目标账户的密码，并且该凭据仍然有效。即使脚本无法成功运行，其文本也可能泄露秘密。被动输出应显示路径和权限，不应打印凭据值或尝试登录。

可读的 SQLite 应用数据库可能包含用户名和密码哈希，即使没有正在监听的数据库服务。将哈希视为离线审计线索前，请检查数据库 schema 和文件权限。只有另有证据确认密码复用时，恢复出的应用密码才可能用于 OS 账户或本地管理面板访问；哈希格式或匹配的用户名都不能证明密码复用。

Apache OFBiz 可以在 `runtime/data/derby/<database>/` 下使用嵌入式 Derby 数据库。Derby 的 `service.properties` 文件标识数据库目录；其同级的 `seg0` 目录存放表文件。查看整个数据库目录的权限后，再检查 `USER_LOGIN` 等应用记录。marker 可读并不能证明表可读、密码可恢复，或应用凭据可用于 Unix 账户。常规枚举输出中不要包含数据库内容和密码哈希。请参阅 [Derby 数据库目录文档](https://db.apache.org/derby/docs/10.4/devguide/cdevdvlp40724.html)和 [OFBiz 登录 API](https://nightlies.apache.org/ofbiz/stable/javadoc/org/apache/ofbiz/common/login/LoginServices.html)。

TeamCity 将其服务器数据保存在可配置的数据目录中（通常为 `.BuildServer`）。检查 `config/projects/<project>/pluginData/ssh_keys`、`config/database.properties`、使用嵌入式 HSQLDB 时的 `system/buildserver.*`，以及 `backup/TeamCity_Backup_*.zip` 的权限。上传的 SSH keys 和其他安全设置可能经过加密，因此仅路径可读并不能证明私钥可用。数据库或备份可能存有应用用户和密码哈希；要将其用于 Unix 账户，需要另有证据确认密码复用。枚举时记录路径和访问权限，不要打印密钥、哈希或数据库行。请参阅 TeamCity 的[数据目录](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)、[SSH key](https://www.jetbrains.com/help/teamcity/ssh-keys-management.html)和[备份](https://www.jetbrains.com/help/teamcity/manual-backup-and-restore.html)文档。

Duplicati backup server 将配置保存在 `Duplicati-server.sqlite` 中。其数据目录可能位于服务账户的 home 目录、`/var/lib/Duplicati` 或容器 volume 中；`--server-datafolder` 或 `DUPLICATI_HOME` 可以更改该目录。可读数据库是高价值线索，因为其中可能存有连接凭据和服务器签名材料；但较新的安装可能会加密敏感字段并限制目录访问。结合实际服务器账户以及任何经过身份验证的 UI 或 ServerUtil 访问，核对其权限。如果该服务器以 root 身份运行，且容器挂载了主机的 `/`，经授权的备份恢复和 job hooks 可能越过主机文件系统边界；仅有 loopback listener 或数据库文件名并不能证明可控制。不要假定旧版本基于 nonce 的登录行为适用于当前版本；当前版本采用不同的[身份验证模型](https://docs.duplicati.com/technical-details/server-authentication-model)。有关特定版本的详情，请参阅 Duplicati 的[服务器数据库](https://docs.duplicati.com/database-and-storage/the-server-database)和 [ServerUtil](https://docs.duplicati.com/duplicati-programs/command-line-interface-cli-1/serverutil)文档。

对于 PostgreSQL，检查 `pg_policies` 和 `pg_class.relrowsecurity`，以区分查询结果被过滤和记录缺失。更改或禁用策略需要相应的表所有权或管理权限。另行 leaked 的维护账户可能拥有这些权限，即使应用账户没有。未经过身份验证的 Redis listener 是另一项独立发现：在将其视为秘密来源前，请确认它是否仅绑定到 loopback，以及 protected mode 或 ACL 是否限制当前连接。

## 检查密钥和 token 存储位置

```bash
find /home /root -maxdepth 4 -type f \( -name 'id_*' -o -name '*.ppk' -o -name '*.p12' -o -name '*.pfx' -o -name '*.kdb' -o -name '*.kdbx' -o -name '*.gpg' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home /root -maxdepth 4 -type d -name '.gnupg' -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

SSH 私钥、agent socket、Kerberos 缓存、GPG keyring 或 PKCS#12 bundle 只有在当前用户能够访问，且所需的口令或策略允许使用时才有用。先检查所有权和权限。[users and sessions](../user-information/user-and-session-triage.md)、[Linux AD](../user-information/linux-active-directory.md) 和 [post-exploitation](../post-exploitation/README.md) 页面说明了相应的访问路径。Git 历史、旧备份和 shell 历史也可能在当前配置清理后继续保留秘密信息。即使工作树为空，只要 `.git` 目录可读，其中仍可能保留已删除的源代码和之前提交的凭据；检查访问权限并手动审查历史记录，不要在自动化枚举时将其全部转储。

`/boot` 下可读的启动镜像也是一个值得检查的归档线索。[Initramfs 启动脚本和复制的辅助程序](https://manpages.debian.org/testing/initramfs-tools-core/initramfs-tools.7.en.html)可能包含自定义逻辑，为 [`cryptsetup --key-file=-`](https://manpages.debian.org/testing/cryptsetup-bin/cryptsetup.8.en.html)提供密钥。检查镜像的访问权限，并仅在获授权的离线副本中审查相关启动脚本和辅助程序。内嵌或派生出的磁盘解锁口令并不自动等同于 Unix 账户密码：在将其视为账户切换途径之前，应确认辅助程序的输入、实际启动路径，以及是否存在单独的凭据复用情况。常规枚举不应解包镜像、执行其中的辅助程序或打印候选密钥。

Vault CLI [通常会将其身份验证 token 缓存在 `~/.vault-token` 中](https://developer.hashicorp.com/vault/docs/commands/token-helper)，但自定义 token helper 可能将其存储在其他位置。某个路径可读只能说明存在凭据线索：在推断能否访问任何 secret engine 之前，应验证 token 的有效性和策略。对于 [Vault SSH 一次性密码](https://developer.hashicorp.com/vault/docs/secrets/ssh/one-time-ssh-passwords)，token 必须获授权为某个 role 签发凭据，且该 role 的用户和 CIDR 必须涵盖目标账户和主机；该主机还必须配置 SSH verification helper 并接受登录。role 名称中出现 `root`，或仅存在 token 文件，都不能证明可获得 root 访问权限。被动枚举应报告文件路径，而不要读取 token 或请求 OTP。

[KeePass 1.x 使用 `.kdb`，而 KeePass 2.x 使用 `.kdbx`](https://keepass.info/help/v2/version.html)。应将匹配的文件名视为可能的加密密码库，因为其他产品也可能使用 `.kdb` 后缀。即使密码库可读，没有所需的主密码或密钥文件，也无法查看其中的条目；作为附件存储的 SSH 密钥则是另一个线索，仍需验证其主机访问权限。[KeePass 接受包括图像在内的任意文件作为密钥文件](https://keepass.info/help/base/keys.html)，但附近的文件只有在其用途、所有必需的主密钥组件，以及任何更高权限账户的登录均得到独立确认后，才能视为有效线索。

支持归档可能同时包含 KeePass 密码库和进程内存转储。对于 [2.54 之前的 KeePass 2.x，CVE-2023-32784](https://nvd.nist.gov/vuln/detail/CVE-2023-32784)可能使主密码可从对应的转储中恢复；仅有加密密码库或无关的转储并不足以恢复密码。在常规枚举时，手动检查归档条目和访问权限，不要批量解压或打印秘密信息。PuTTY 私钥可能以 `.ppk` 文件形式出现，也可能作为密码库条目中的 `PuTTY-User-Key-File` 文本出现；应分别确认密钥的目标账户、加密情况以及目标主机是否接受该密钥。

可读的 `.har` HTTP 归档可能保留浏览器请求和响应，包括身份验证 header、cookie 和表单字段。它可能直接保存，也可能包含在支持附件中。先检查所有权和访问权限，再只检查相关条目；仅凭文件名不能证明其中包含可复用的凭据。自动化枚举应列出归档路径，而不要打印捕获的值。[Microsoft Edge 文档](https://learn.microsoft.com/en-us/microsoft-edge/devtools/network/reference#save-all-network-requests-to-a-har-file)说明了敏感数据导出选项。

对于加密的数据库备份，在得出结论之前，应核对可读的归档、可访问的私钥材料以及任何口令要求。在获得授权的情况下，恢复受保护密钥的口令和检查解密后的备份数据是两个独立的手动步骤。数据库的 `root` 凭据不等同于 Unix 的 `root` 凭据；是否在这两个账户间复用密码，需要另行获得授权并验证。Web 应用中的文件系统信任边界也可能暴露持有这些材料的账户；请参阅 [Django 文件缓存审查](../../network-services-pentesting/pentesting-web/django.md#cache-manipulation-to-rce)。

容器 root 和主机 root 是不同的身份。只有在容器内成为 root 后才能读取的 SSH 私钥，可能用于向主机账户进行身份验证（前提是主机接受该密钥），但密钥文件名或公钥注释不能证明具备此类访问权限。同样，在带时间戳的密码更改记录旁发现自定义密码生成器，只能作为手动分析线索：以时间为种子的非密码学生成器可能对应一个较小的候选种子范围，但时区、时钟精度、库的行为以及后续密码更改都会影响重建结果。仅在获得授权时验证候选凭据；不要将生成的候选值视为已确认密码。

如果目录可遍历且文件权限允许，容器内的服务账户可能能够读取名义上位于特权用户主目录中的旧配置脚本。脚本中嵌入的应用管理员密码只是凭据暴露线索，并不意味着能够取得主机 root 权限：应检查该脚本和凭据是否仍在使用、该值属于哪个账户，以及主机账户是否仍接受同一密码。在被动枚举期间，记录文件路径和访问权限，不要打印秘密信息或尝试向主机进行身份验证。

如果可读的 `.p12` 或 `.pfx` bundle 的密码暴露在应用配置中，可使用 `openssl pkcs12 -info -in bundle.p12 -noout` 检查。如果 bundle 中包含可导出的私钥，`openssl pkcs12 -in bundle.p12 -nocerts -nodes -out extracted.key` 会将该密钥以未加密形式写入文件。保护输出文件，并在分析后将其删除；仅将恢复出的密钥用于与之实际匹配的服务或密文。仅有一个 bundle 并不意味着其中的私钥可用于其他应用。
{{#include ../../banners/hacktricks-training.md}}
