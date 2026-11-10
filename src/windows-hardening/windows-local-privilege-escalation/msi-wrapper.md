# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapperでは、実行ファイルやスクリプトをWindows Installer（`.msi`）ファイルとしてパッケージ化できます。無料版をダウンロードして起動し、パッケージ化する実行ファイルを選択します。<sup>[[3]](#references)</sup> 一連のコマンドを実行するには、`cmd.exe`をパッケージ化するのではなく、入力として`.bat`ファイルを選択します。<sup>[[1]](#references)</sup>

![MSI Wrapperでソースとなる実行ファイルまたはバッチスクリプトを選択](<../../images/image (417).png>)

実行コンテキストやその他のインストーラーのプロパティを慎重に設定します。

![MSI WrapperでアプリケーションIDとセキュリティコンテキストを設定](<../../images/image (312).png>)

![MSI Wrapperでインストーラーのプロパティを設定](<../../images/image (346).png>)

![MSI Wrapperのビルド設定を確認](<../../images/image (1072).png>)

カスタムバイナリをパッケージ化する際に、これらの値を変更できます。

ウィザードの残りのページを進み、**Build**を選択してインストーラーを生成します。<sup>[[1]](#references)</sup>

## ラップされたコマンドの実行コンテキストを確認する

テスト用パッケージでは、MSIの昇格設定が子プロセスにも適用されると決めつけず、トークンを記録する`.bat`ファイルをラップします。<sup>[[4]](#references)</sup> ウィザードでは、セキュリティコンテキストとして**User**ではなく**System**を選び、意図した実行方法がマシン単位の昇格インストールである場合は、それを選択します。<sup>[[5]](#references)</sup> **System**を選択しても認可を回避できるわけではありません。非管理者ユーザーが実行するには、[2つのポリシーによる`AlwaysInstallElevated`の設定ミス](index.html#alwaysinstallelevated)や、特権を持つインストーラーワークフローなど、昇格インストールの手段が必要です。<sup>[[2]](#references)</sup> **User**を選択すると、ラップされたコマンドはインストールを実行したユーザーのコンテキストで実行されます。ユーザー固有のリソースやネットワークリソースを使う場合は、この設定が必要になることがあります。<sup>[[5]](#references)</sup>

```bat
@echo off
whoami /all > "C:\Users\Public\msi-wrapper-context.txt"
exit /b 0
```

この batch file を入力として MSI をビルドし、テストホストで実行して、記録された ID と権限を確認します。<sup>[[4]](#references)</sup> MSI Wrapper はゼロ以外の batch exit code をインストールエラー 1603 に変換するため、テスト成功後に誤って失敗と判定されないよう、明示的にゼロを返します。<sup>[[4]](#references)</sup> 出力ファイルはテスト成果物です。`msiexec` の終了コードが成功だったことや、サイレントインストールだったことだけを根拠に、SYSTEM として実行されたと判断しないでください。<sup>[[5]](#references)[[6]](#references)</sup>

```cmd
msiexec.exe /i "C:\Users\Public\context-test.msi" /qn /norestart /L*V "C:\Users\Public\context-test.log"
type "C:\Users\Public\msi-wrapper-context.txt"
```

`/qn` は MSI UI を非表示にしますが、ラップされた実行ファイル自体の UI まで非表示にするとは限りません。<sup>[[6]](#references)[[7]](#references)</sup> ラップされたインストーラーの場合は、ウィザードでサポートされているサイレント引数を設定してください。MSI Wrapper の動的な `WRAPPED_ARGUMENTS` プロパティは PRO 機能です。<sup>[[1]](#references)[[7]](#references)</sup> カスタムアクションの順序と偽装を直接制御する必要がある場合は、[WiX のカスタムアクションを使用する方法](create-msi-with-wix.md)を参照してください。

> [!WARNING]
> MSI を作成しただけでは、昇格された権限が付与されるわけではありません。インストールが昇格されるかどうかは、Windows Installer のポリシー、パッケージのコンテキスト、ユーザーの認証によって異なります。Microsoft は、ユーザーとコンピューターの両方で `AlwaysInstallElevated` を有効にすると、非管理者がシステム権限でパッケージをインストールできるようになると警告しています。<sup>[[2]](#references)</sup>



## References

- [1] [MSI Wrapper ドキュメント - はじめに](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - 非管理者向けに昇格された権限でパッケージをインストールする](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - ダウンロード](https://www.exemsi.com/download/)
- [4] [MSI Wrapper - バッチファイルから MSI を作成する](https://www.exemsi.com/documentation/create-msi-from-batch-file/)
- [5] [MSI Wrapper - ウィザードのページ](https://www.exemsi.com/documentation/wizard-pages/)
- [6] [Microsoft Learn - コマンドライン オプション](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)
- [7] [MSI Wrapper - コマンドライン引数](https://www.exemsi.com/documentation/command-line-arguments/)
{{#include ../../banners/hacktricks-training.md}}
