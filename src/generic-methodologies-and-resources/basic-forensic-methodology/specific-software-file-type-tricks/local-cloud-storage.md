# 本地云存储

{{#include ../../../banners/hacktricks-training.md}}

## OneDrive

在Windows中，您可以在 `\Users\<username>\AppData\Local\Microsoft\OneDrive` 找到OneDrive文件夹。在 `logs\Personal` 中，可以找到文件 `SyncDiagnostics.log`，其中包含有关同步文件的一些有趣数据：

- 字节大小
- 创建日期
- 修改日期
- 云中的文件数量
- 文件夹中的文件数量
- **CID**: OneDrive用户的唯一ID
- 报告生成时间
- 操作系统的硬盘大小

一旦找到CID，建议**搜索包含此ID的文件**。您可能会找到名为：_**\<CID>.ini**_ 和 _**\<CID>.dat**_ 的文件，这些文件可能包含与OneDrive同步的文件名称等有趣信息。

## Google Drive

在Windows中，您可以在 `\Users\<username>\AppData\Local\Google\Drive\user_default` 找到主要的Google Drive文件夹\
此文件夹包含一个名为Sync_log.log的文件，其中包含帐户的电子邮件地址、文件名、时间戳、文件的MD5哈希等信息。即使是已删除的文件也会在该日志文件中显示其对应的MD5。

文件 **`Cloud_graph\Cloud_graph.db`** 是一个sqlite数据库，包含表 **`cloud_graph_entry`**。在此表中，您可以找到**同步** **文件**的**名称**、修改时间、大小和文件的MD5校验和。

数据库 **`Sync_config.db`** 的表数据包含帐户的电子邮件地址、共享文件夹的路径和Google Drive版本。

## Dropbox

Dropbox使用**SQLite数据库**来管理文件。在此\
您可以在以下文件夹中找到数据库：

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

主要数据库包括：

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

“.dbx”扩展名表示**数据库**是**加密的**。Dropbox使用**DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

要更好地理解Dropbox使用的加密，您可以阅读 [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)。

然而，主要信息是：

- **熵**: d114a55212655f74bd772e37e64aee9b
- **盐**: 0D638C092E8B82FC452883F95F355B8E
- **算法**: PBKDF2
- **迭代次数**: 1066

除此之外，要解密数据库，您还需要：

- **加密的DPAPI密钥**: 您可以在注册表中找到它，路径为 `NTUSER.DAT\Software\Dropbox\ks\client`（将此数据导出为二进制）
- **`SYSTEM`** 和 **`SECURITY`** 注册表项
- **DPAPI主密钥**: 可以在 `\Users\<username>\AppData\Roaming\Microsoft\Protect` 找到
- Windows用户的**用户名**和**密码**

然后您可以使用工具 [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![](<../../../images/image (443).png>)

如果一切顺利，该工具将指示您需要**使用以恢复原始密钥**。要恢复原始密钥，只需使用此 [cyber_chef配方](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>)，将主密钥作为配方中的“密码短语”。

结果十六进制是用于加密数据库的最终密钥，可以用来解密：
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** 数据库包含：

- **Email**: 用户的电子邮件
- **usernamedisplayname**: 用户的名称
- **dropbox_path**: Dropbox 文件夹所在的路径
- **Host_id: Hash** 用于认证到云端。此项只能从网页上撤销。
- **Root_ns**: 用户标识符

**`filecache.db`** 数据库包含与 Dropbox 同步的所有文件和文件夹的信息。表 `File_journal` 是包含更多有用信息的表：

- **Server_path**: 文件在服务器内部的路径（此路径前面有客户端的 `host_id`）。
- **local_sjid**: 文件的版本
- **local_mtime**: 修改日期
- **local_ctime**: 创建日期

此数据库中的其他表包含更多有趣的信息：

- **block_cache**: Dropbox 所有文件和文件夹的哈希
- **block_ref**: 将表 `block_cache` 的哈希 ID 与表 `file_journal` 中的文件 ID 关联
- **mount_table**: Dropbox 的共享文件夹
- **deleted_fields**: Dropbox 删除的文件
- **date_added**

{{#include ../../../banners/hacktricks-training.md}}
