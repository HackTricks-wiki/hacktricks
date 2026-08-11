# 本地 Cloud Storage

{{#include ../../../banners/hacktricks-training.md}}

## OneDrive

在 Windows 中，可以在 `\Users\<username>\AppData\Local\Microsoft\OneDrive` 找到 OneDrive 文件夹。在 `logs\Personal` 中，可以找到文件 `SyncDiagnostics.log`，其中包含有关已同步文件的一些有趣数据：<sup>[[3]](#references)</sup>

- 字节数
- 创建日期
- 修改日期
- cloud 中的文件数量
- 文件夹中的文件数量
- **CID**：OneDrive 用户的唯一 ID
- 报告生成时间
- OS 硬盘大小

找到 CID 后，建议**搜索包含此 ID 的文件**。你可能会找到名为 _**\<CID>.ini**_ 和 _**\<CID>.dat**_ 的文件，其中可能包含已与 OneDrive 同步的文件名等有用信息。<sup>[[3]](#references)</sup>

## Google Drive

在 Windows 中，可以在 `\Users\<username>\AppData\Local\Google\Drive\user_default` 找到 Google Drive 主文件夹\
此文件夹包含一个名为 Sync_log.log 的文件，用于记录 Google Drive 客户端的同步会话，以及文件的创建、修改和删除事件。<sup>[[4]](#references)[[6]](#references)</sup>

文件 **`Cloud_graph\Cloud_graph.db`** 是一个 sqlite 数据库。<sup>[[6]](#references)</sup>其中包含表 **`cloud_graph_entry`**。在此表中，可以找到**同步** **文件**的**名称**、修改时间、大小以及文件的 MD5 checksum。

相关的 **`snapshot.db`** 数据库中的 **`cloud_entry`** 表可以保留包含文件名、时间戳、大小和 checksum 的已删除记录。<sup>[[4]](#references)</sup>

数据库 **`Sync_config.db`** 的表数据包含账户的电子邮件地址、共享文件夹的路径以及 Google Drive 版本。<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox 使用 **SQLite databases** 管理文件。<sup>[[2]](#references)</sup>在此\
你可以在以下文件夹中找到这些数据库：

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

主要数据库包括：

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

“.dbx”扩展名表示这些**databases**已被**encrypted**。Dropbox 使用 **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))。<sup>[[1]](#references)</sup>

要更好地了解 Dropbox 使用的加密方式，可以阅读 [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)。<sup>[[1]](#references)[[2]](#references)</sup>

不过，主要信息如下：<sup>[[1]](#references)</sup>

- **Entropy**：d114a55212655f74bd772e37e64aee9b
- **Salt**：0D638C092E8B82FC452883F95F355B8E
- **Algorithm**：PBKDF2
- **Iterations**：1066

除此之外，要解密这些数据库，你还需要：<sup>[[2]](#references)</sup>

- **encrypted DPAPI key**：可以在注册表 `NTUSER.DAT\Software\Dropbox\ks\client` 中找到（将此数据导出为 binary）
- **`SYSTEM`** 和 **`SECURITY`** hives
- **DPAPI master keys**：可以在 `\Users\<username>\AppData\Roaming\Microsoft\Protect` 中找到
- Windows 用户的**用户名**和**密码**

然后，可以使用工具 [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**：**

![Google Drive - Dropbox：然后，可以使用工具 DataProtectionDecryptor](<../../../images/image (443).png>)

如果一切按预期进行，该工具会显示你需要的**primary key**，你需要**使用它来恢复原始 key**。要恢复原始 key，只需使用此 [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>)，将 primary key 作为 receipt 中的“passphrase”。

生成的 hex 是用于加密这些数据库的最终 key，可以使用以下方式解密：<sup>[[2]](#references)</sup>
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** 数据库包含：

- **Email**：用户的电子邮件
- **usernamedisplayname**：用户的名称
- **dropbox_path**：Dropbox 文件夹所在的路径
- **Host_id: Hash**：用于向 cloud 进行身份验证。只能从 Web 撤销。
- **Root_ns**：用户标识符

**`filecache.db`** 数据库包含与 Dropbox 同步的所有文件和文件夹的信息。`File_journal` 表包含更多有用的信息：<sup>[[5]](#references)</sup>

- **Server_path**：文件在 server 内部所在的路径（此路径前面带有客户端的 `host_id`）。
- **local_sjid**：文件版本
- **local_mtime**：修改日期
- **local_ctime**：创建日期

此数据库中的其他表包含更多有价值的信息：

- **block_cache**：Dropbox 中所有文件和文件夹的 hash
- **block_ref**：将 `block_cache` 表的 hash ID 与 `file_journal` 表中的文件 ID 关联起来
- **mount_table**：Dropbox 的共享文件夹
- **deleted_fields**：Dropbox 中已删除的文件
- **date_added**

## References

- [1] [Dropbox 软件安全性的批判性分析 (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [深入了解 Dropbox DBX 解密](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Cloud Storage Forensic Analysis (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [NIST CFReDS Data Leakage Case: 泄露答案](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Dropbox 取证](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Windows 上 Google Drive 使用情况的痕迹](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
