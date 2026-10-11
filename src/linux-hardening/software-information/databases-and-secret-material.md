# Linux 主机上的数据库和机密材料

{{#include ../../banners/hacktricks-training.md}}

数据库和应用程序凭据通常存放在其所支持的服务旁边。测试某个账户是否能够读取数据或执行特权操作之前，先梳理进程、本地 socket 或端口、配置以及凭据文件。

## 定位本地数据服务和凭据

```bash
ss -lntup
ss -lnx
ps -eo user,pid,args | grep -E '[m]ysqld|[m]ariadbd|[p]ostgres|[r]edis-server|[m]ongod'
find /etc /opt /var/www /home -type f \( -name '*.env' -o -name '*config*' -o -name '.my.cnf' -o -name '.pgpass' \) -ls 2>/dev/null | head -100
```

检查可读的应用配置、部署文件、服务环境文件和备份，查找连接字符串或密钥。数据库进程的 Unix socket 可能与其 TCP listener 具有不同的访问规则。数据库权限不同于 OS 权限：恢复出的 DB 密码只会授予分配给该 DB 账户的角色，除非有证据证明存在其他途径。在 PostgreSQL 中，行级安全策略可能会对某个角色隐藏记录，而拥有策略管理权限的角色可以更改该视图；应区分数据访问与策略管理。请参阅针对 [MySQL/MariaDB](../../network-services-pentesting/pentesting-mysql.md)、[PostgreSQL](../../network-services-pentesting/pentesting-postgresql.md) 和 [Redis](../../network-services-pentesting/6379-pentesting-redis.md) 的服务专用指南。

另一个账户 home 目录下可读的自动化脚本，可能嵌入凭据，即使文件名中没有提到密码。例如，Python 脚本可以启动 `su`，并通过 [`pexpect.sendline`](https://pexpect.readthedocs.io/en/latest/api/pexpect.html) 向其密码提示符传入明文；[`su`](https://man7.org/linux/man-pages/man1/su.1.html) 仍会执行其身份验证策略。在将此视为账户切换之前，应确认当前用户可以遍历该目录并读取确切的脚本、明文确实是目标账户的密码，并且该凭据仍然有效。即使脚本无法成功运行，其文本仍可能泄露机密。被动输出应显示路径和权限，但不要打印密码或尝试登录。

可读的 SQLite 应用数据库可能包含用户名和密码哈希，即使没有数据库服务在监听。将哈希视为离线审计线索之前，应先检查数据库 schema 和文件权限。只有单独确认了密码复用，恢复出的应用密码才可用于 OS 账户或本地管理面板访问；哈希格式或用户名匹配都不能证明存在密码复用。

Apache OFBiz 可以在 `runtime/data/derby/<database>/` 下使用嵌入式 Derby 数据库。Derby 的 `service.properties` 文件标示数据库目录；其同级的 `seg0` 目录存放表文件。查看应用记录（例如 `USER_LOGIN`）之前，应检查整个数据库目录的权限。标记文件可读，并不能证明表也可读、可以恢复密码，或应用凭据可用于 Unix 账户。例行枚举输出中不要包含数据库内容和密码哈希。请参阅 [Derby database-directory documentation](https://db.apache.org/derby/docs/10.4/devguide/cdevdvlp40724.html) 和 [OFBiz login API](https://nightlies.apache.org/ofbiz/stable/javadoc/org/apache/ofbiz/common/login/LoginServices.html)。

TeamCity 将服务器数据存放在可配置的数据目录下（通常为 `.BuildServer`）。检查 `config/projects/<project>/pluginData/ssh_keys`、`config/database.properties`、使用嵌入式 HSQLDB 时的 `system/buildserver.*`，以及 `backup/TeamCity_Backup_*.zip` 的权限。上传的 SSH keys 和其他安全设置可能已加密，因此仅路径可读并不能证明私钥可用。数据库或备份可能包含应用用户和密码哈希；要将其用于 Unix 账户，需要单独的密码复用证据。枚举时记录路径和访问权限，不要打印 keys、哈希或数据库行。请参阅 TeamCity 的 [data-directory](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)、[SSH-key](https://www.jetbrains.com/help/teamcity/ssh-keys-management.html) 和 [backup](https://www.jetbrains.com/help/teamcity/manual-backup-and-restore.html) 文档。

Duplicati 备份服务器将配置存放在 `Duplicati-server.sqlite` 中。其数据目录可能位于服务账户的 home 目录、`/var/lib/Duplicati` 或容器卷中，也可能由 `--server-datafolder` 或 `DUPLICATI_HOME` 更改。可读的数据库是高价值线索，因为其中可能包含连接凭据和服务器签名材料，但较新的安装可能会加密敏感字段并限制目录访问。将其权限与实际服务器账户以及任何经过身份验证的 UI 或 ServerUtil 访问情况进行对照。如果该服务器以 root 身份运行，且容器挂载了主机的 `/`，经过授权的备份还原和 job hooks 可能越过主机文件系统边界；仅有 loopback listener 或数据库文件名并不能证明可控。不要假定旧版本基于 nonce 的登录行为适用于当前版本；当前版本使用不同的[身份验证模型](https://docs.duplicati.com/technical-details/server-authentication-model)。有关特定版本的详细信息，请参阅 Duplicati 的[服务器数据库](https://docs.duplicati.com/database-and-storage/the-server-database)和 [ServerUtil](https://docs.duplicati.com/duplicati-programs/command-line-interface-cli-1/serverutil) 文档。

对于 PostgreSQL，检查 `pg_policies` 和 `pg_class.relrowsecurity`，以区分查询结果被过滤和记录缺失。更改或禁用策略需要相应的表所有权或管理权限。单独泄露的维护账户可能拥有这些权限，即使应用账户没有。未经过身份验证的 Redis listener 是另一项独立发现：在将其视为机密来源之前，应确认它是否仅绑定到 loopback，以及 protected mode 或 ACLs 是否限制当前连接。

## 检查 key 和 token 存储####

```bash
find /home /root -maxdepth 4 -type f \( -name 'id_*' -o -name '*.ppk' -o -name '*.p12' -o -name '*.pfx' -o -name '*.kdb' -o -name '*.kdbx' -o -name '*.gpg' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home /root -maxdepth 4 -type d -name '.gnupg' -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

SSH 私钥、agent socket、Kerberos cache、GPG keyring 或 PKCS#12 bundle 只有在当前用户能够访问，且所需的 passphrase 或策略允许使用时才有用。先检查所有权和权限。[users and sessions](../user-information/user-and-session-triage.md)、[Linux AD](../user-information/linux-active-directory.md) 和 [post-exploitation](../post-exploitation/README.md) 页面介绍了相应的访问路径。Git 历史记录、旧备份和 shell history 也可能在实时配置清理后继续保留秘密。即使工作树为空，只要 `.git` 目录可读，也可能留存已删除的源代码和先前提交的凭据；请检查访问权限并手动审查历史记录，而不要在自动化枚举时倾倒其中的内容。

`/boot` 下可读的启动映像也是值得检查的归档线索。[Initramfs 启动脚本和复制的辅助程序](https://manpages.debian.org/testing/initramfs-tools-core/initramfs-tools.7.en.html) 可能包含自定义逻辑，为 [`cryptsetup --key-file=-`](https://manpages.debian.org/testing/cryptsetup-bin/cryptsetup.8.en.html) 提供密钥。检查映像的访问权限，并在经过授权的离线副本中仅审查相关启动脚本和辅助程序。嵌入其中或从中派生的磁盘解锁 passphrase 不会自动成为 Unix 账户密码：在将其视为账户转换前，请确认辅助程序的输入、实际启动路径，以及是否存在单独的凭据复用。常规枚举不应解包映像、执行其中的辅助程序或打印候选密钥。

Vault CLI [通常会将其身份验证 token 缓存到 `~/.vault-token`](https://developer.hashicorp.com/vault/docs/commands/token-helper)，不过自定义 token helper 可能会将其存储在其他位置。某个路径可读仅代表存在凭据线索：在推断能否访问任何 secret engine 前，请先验证 token 是否有效及其策略。对于 [Vault SSH 一次性密码](https://developer.hashicorp.com/vault/docs/secrets/ssh/one-time-ssh-passwords)，该 token 必须获准为某个角色签发凭据，且该角色的用户和 CIDR 范围必须包含目标账户和主机；该主机还必须配置 SSH 验证 helper 并接受登录。角色名称为 `root` 或仅发现 token 文件，都不能证明拥有 root 访问权限。被动枚举应报告文件路径，而不要读取 token 或请求 OTP。

[KeePass 1.x 使用 `.kdb`，而 KeePass 2.x 使用 `.kdbx`](https://keepass.info/help/v2/version.html)。将匹配的文件名视为可能的加密 vault，因为其他产品也可能使用 `.kdb` 后缀。没有所需的 master password 或 key file 时，即使 vault 可读也无法查看其中的条目；作为附件存储的 SSH key 是另一条线索，其主机访问权限仍需单独验证。[KeePass 接受任意文件（包括图像）作为 key file](https://keepass.info/help/base/keys.html)，但附近的文件只能视为候选项，除非已分别确认其用途、所有必需的 master-key 组件，以及更高权限账户的登录能力。

支持归档中可能同时包含 KeePass vault 和进程内存转储。对于 [2.54 之前的 KeePass 2.x，CVE-2023-32784](https://nvd.nist.gov/vuln/detail/CVE-2023-32784) 可能使 master password 能够从相应的转储中恢复；仅有加密 vault 或无关的转储并不足够。在常规枚举期间，请手动检查归档条目和访问权限，不要批量解压或打印秘密。PuTTY 私钥可能以 `.ppk` 文件的形式出现，也可能作为 vault 条目中的 `PuTTY-User-Key-File` 文本出现；请分别确认该密钥预期使用的账户、加密状态及其可接受的主机。

可读的 `.har` HTTP 归档可能保留浏览器请求和响应，包括身份验证标头、cookies 和表单字段。它可能被直接保存，也可能位于支持附件中。先检查所有权和访问权限，然后只检查相关条目；仅凭文件名无法证明其中包含可复用的凭据。自动化枚举应列出归档路径，而不要打印捕获的值。[Microsoft Edge 文档](https://learn.microsoft.com/en-us/microsoft-edge/devtools/network/reference#save-all-network-requests-to-a-har-file) 介绍了敏感数据导出选项。

对于加密数据库备份，在得出结论前，请结合可读的归档、可访问的私钥材料以及任何 passphrase 要求进行判断。在获得授权的情况下，恢复受保护密钥的 passphrase 与检查解密后的备份数据是两个独立的手动步骤。数据库的 `root` 凭据不等于 Unix 的 `root` 凭据；是否在这两个账户间复用密码，需要另行授权验证。Web 应用中的文件系统信任边界也可能暴露拥有这些材料的账户；请参阅 [Django file-cache review](../../network-services-pentesting/pentesting-web/django.md#cache-manipulation-to-rce)。

容器 root 和主机 root 是不同的身份。只有在成为容器内的 root 后才能读取的 SSH 私钥，或许能用于验证主机上的某个账户（前提是主机接受该密钥），但密钥文件名或公钥注释并不能证明可以访问该主机。同样，在带时间戳的密码更改记录旁发现自定义密码生成器，只能作为手动分析线索：以时间为种子的非加密生成器可能只有较小的候选种子范围，但时区、时钟精度、库的行为以及后续密码更改都会影响重建结果。仅在获得授权时验证候选凭据；不要将生成的候选项视为已确认的密码。

如果目录可遍历且文件权限允许，容器内的服务账户可能能够读取名义上属于特权账户主目录中的旧配置脚本。嵌入其中的应用管理员密码是凭据暴露线索，而非主机 root 访问权限：请检查该脚本和凭据是否仍在使用、该值属于哪个账户，以及主机上的独立账户是否仍接受相同密码。被动枚举时，请记录文件路径和访问权限，不要打印秘密或尝试通过主机身份验证。

如果可读的 `.p12` 或 `.pfx` bundle 的密码暴露在应用配置中，可使用 `openssl pkcs12 -info -in bundle.p12 -noout` 检查。如果 bundle 中包含可导出的私钥，`openssl pkcs12 -in bundle.p12 -nocerts -nodes -out extracted.key` 会将该密钥以未加密形式写入文件。请妥善保护输出文件，并在分析后将其删除；恢复出的密钥只能用于与之实际匹配的服务或密文。仅有一个 bundle 并不意味着其中的私钥对其他应用也有用。
{{#include ../../banners/hacktricks-training.md}}
