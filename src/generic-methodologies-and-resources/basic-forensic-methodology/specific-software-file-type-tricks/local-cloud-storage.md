# 本地云存储

{{#include ../../../banners/hacktricks-training.md}}

## 本地存储模拟器和账户密钥

在容器中运行的 Azure 兼容 Blob 模拟器，即使存储服务未对外暴露，也可能通过主机或桥接网络访问。检查可读取的本地配置和备份文件元数据，查找账户名和密钥；常规枚举时不要打印密钥。[Azurite 支持自定义本地账户密钥](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite)；[Shared Key 授权](https://learn.microsoft.com/en-us/azure/storage/common/authorize-data-access)可能授予对相应账户数据的广泛访问权限。仅有密钥文件并不能证明存在权限提升：请确认端点可访问、账户和密钥有效，并且特定 Blob 实际包含可用于更高权限身份的凭据。如果其中包含 SSH 私钥，还必须将相应公钥授权给该身份，并允许 SSH 访问。确认密钥暴露后，应妥善保护并轮换密钥。

## OneDrive

在 Windows 中，可以在 `\Users\<username>\AppData\Local\Microsoft\OneDrive` 找到 OneDrive 文件夹。在 `logs\Personal` 中，可以找到文件 `SyncDiagnostics.log`，其中包含有关同步文件的一些有趣数据：<sup>[[3]](#references)</sup>

- 大小（字节）
- 创建日期
- 修改日期
- 云端文件数量
- 文件夹中的文件数量
- **CID**：OneDrive 用户的唯一 ID
- 报告生成时间
- 操作系统硬盘的大小

找到 CID 后，建议**搜索包含此 ID 的文件**。你可能会找到名为 _**\<CID>.ini**_ 和 _**\<CID>.dat**_ 的文件，其中可能包含一些有用信息，例如与 OneDrive 同步的文件名。<sup>[[3]](#references)</sup>

## Google Drive

在 Windows 中，可以在 `\Users\<username>\AppData\Local\Google\Drive\user_default` 找到 Google Drive 主文件夹\
该文件夹包含一个名为 Sync_log.log 的文件，记录 Google Drive 客户端的同步会话，以及文件创建、修改和删除事件。<sup>[[4]](#references)[[6]](#references)</sup>

文件 **`Cloud_graph\Cloud_graph.db`** 是一个 sqlite 数据库。<sup>[[6]](#references)</sup> 它包含 **`cloud_graph_entry`** 表。在此表中，可以找到**已同步** **文件**的**名称**、修改时间、大小和 MD5 校验和。

相关的 **`snapshot.db`** 数据库中的 **`cloud_entry`** 表可能保留已删除记录，包括文件名、时间戳、大小和校验和。<sup>[[4]](#references)</sup>

数据库 **`Sync_config.db`** 的表数据包含账户的电子邮件地址、共享文件夹的路径以及 Google Drive 版本。<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox 使用 **SQLite 数据库**来管理文件。<sup>[[2]](#references)</sup> 在这里\
可以在以下文件夹中找到数据库：

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

主要数据库包括：

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

".dbx" 扩展名表示这些**数据库**经过了**加密**。Dropbox 使用 **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

若要更好地了解 Dropbox 使用的加密方式，可以阅读 [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)。<sup>[[1]](#references)[[2]](#references)</sup>

不过，主要信息如下：<sup>[[1]](#references)</sup>

- **熵**：d114a55212655f74bd772e37e64aee9b
- **Salt**：0D638C092E8B82FC452883F95F355B8E
- **算法**：PBKDF2
- **迭代次数**：1066

除了这些信息，要解密数据库，你还需要：<sup>[[2]](#references)</sup>

- **加密的 DPAPI 密钥**：可在注册表 `NTUSER.DAT\Software\Dropbox\ks\client` 中找到（将此数据导出为二进制）
- **`SYSTEM`** 和 **`SECURITY`** hive
- **DPAPI 主密钥**：可在 `\Users\<username>\AppData\Roaming\Microsoft\Protect` 中找到
- Windows 用户的**用户名**和**密码**

然后可以使用工具 [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**：**

![Google Drive - Dropbox：然后可以使用 DataProtectionDecryptor 工具](<../../../images/image (443).png>)

如果一切顺利，该工具会显示你需要**用来恢复原始密钥的主密钥**。要恢复原始密钥，只需使用此 [CyberChef 配方](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>)，将主密钥填入配方中的 "passphrase"。

最终得到的十六进制值就是用于加密数据库的密钥，可以使用以下方法解密：<sup>[[2]](#references)</sup>

```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```

**`config.dbx`** 数据库包含：

- **Email**：用户的电子邮件地址
- **usernamedisplayname**：用户的名称
- **dropbox_path**：Dropbox 文件夹所在的路径
- **Host_id: Hash**：用于向云端进行身份验证的哈希值。只能通过网页端撤销。
- **Root_ns**：用户标识符

**`filecache.db`** 数据库包含与 Dropbox 同步的所有文件和文件夹的信息。`File_journal` 表包含最有用的信息：<sup>[[5]](#references)</sup>

- **Server_path**：文件在服务器中的路径（此路径前面带有客户端的 `host_id`）。
- **local_sjid**：文件版本
- **local_mtime**：修改日期
- **local_ctime**：创建日期

此数据库中的其他表还包含更多有用的信息：

- **block_cache**：Dropbox 中所有文件和文件夹的哈希值
- **block_ref**：将 `block_cache` 表中的哈希 ID 与 `file_journal` 表中的文件 ID 关联起来
- **mount_table**：Dropbox 的共享文件夹
- **deleted_fields**：Dropbox 已删除的文件
- **date_added**

## References

- [1] [Dropbox 软件安全性的批判性分析（hack.lu 2012）](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [深入了解 Dropbox DBX 解密](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [云存储取证分析（Darren Quick，2012）](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [NIST CFReDS 数据泄露案例：Leakage 答案](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Dropbox 取证](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Windows 中 Google Drive 使用情况的痕迹](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
