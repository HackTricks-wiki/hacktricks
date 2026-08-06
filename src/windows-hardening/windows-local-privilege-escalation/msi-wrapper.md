# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

[https://www.exemsi.com/documentation/getting-started/](https://www.exemsi.com/download/) から無料版の app を Download し、実行して、その中に「malicious」binary を wrap します。\
「**.bat**」を wrap すれば、**command lines を実行する**ことだけが目的の場合にも使用できます（cmd.exe の代わりに .bat file を選択してください）。

![MSI Wrapper: command lines を実行するだけの場合は「.bat」を wrap できることに注意（cmd.exe の代わりに .bat file を選択）](<../../images/image (417).png>)

そして、設定で最も重要な部分は次のとおりです。

![MSI Wrapper: 設定で最も重要な部分](<../../images/image (312).png>)

![MSI Wrapper: 設定で最も重要な部分](<../../images/image (346).png>)

![MSI Wrapper: 設定で最も重要な部分](<../../images/image (1072).png>)

（独自の binary を pack する場合は、これらの値を変更できることに注意してください）

ここからは **next buttons** をクリックし、最後に **build button** をクリックすると、installer/wrapper が生成されます。

{{#include ../../banners/hacktricks-training.md}}
