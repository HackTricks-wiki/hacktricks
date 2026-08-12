# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper は、実行ファイルまたはスクリプトを Windows Installer (`.msi`) ファイルとしてパッケージ化できます。free edition をダウンロードして起動し、パッケージ化する実行ファイルを選択します。<sup>[[3]](#references)</sup> 一連のコマンドを実行するには、`cmd.exe` をパッケージ化するのではなく、入力として `.bat` ファイルを選択します。<sup>[[1]](#references)</sup>

![MSI Wrapper でソース実行ファイルまたはバッチスクリプトを選択](<../../images/image (417).png>)

実行コンテキストやその他の installer プロパティは慎重に設定してください。

![MSI Wrapper でアプリケーション ID と security context を設定](<../../images/image (312).png>)

![MSI Wrapper で installer プロパティを設定](<../../images/image (346).png>)

![MSI Wrapper の MSI Wrapper build settings を確認](<../../images/image (1072).png>)

これらの値は、カスタムバイナリをパッケージ化するときに変更できます。

残りの wizard ページを進み、**Build** を選択して installer を生成します。<sup>[[1]](#references)</sup>

> [!WARNING]
> MSI を作成するだけでは、elevated privileges は付与されません。installation が elevated になるかどうかは、Windows Installer policy、package context、および user authorization に依存します。Microsoft は、ユーザーとコンピューターの両方で `AlwaysInstallElevated` を有効にすると、non-administrator が system privileges で packages をインストールできるようになると警告しています。<sup>[[2]](#references)</sup>

## References

- [1] [MSI Wrapper documentation - Getting started](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Installing a package with elevated privileges for a non-admin](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Download](https://www.exemsi.com/download/)
{{#include ../../banners/hacktricks-training.md}}
