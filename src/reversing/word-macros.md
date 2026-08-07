# Word Macros

{{#include ../banners/hacktricks-training.md}}

### Junk Code

マクロのreversingをより困難にするため、**決して使用されないjunk code**が見つかることは非常に一般的です。\
例えば、以下の画像では、決してtrueにならないIfが、junkで役に立たないコードを実行するために使われていることがわかります。

![Word Macros - Junk Code: 例えば、以下の画像では、決してtrueにならないIfが、junkで役に立たないコードを実行するために使われていることがわかります](<../images/image (369).png>)

### Macro Forms

**GetObject**関数を使用すると、マクロのフォームからデータを取得できます。これは分析を困難にするために使用できます。以下は、**テキストボックス内にデータを隠す**ために使用されたマクロフォームの画像です（1つのテキストボックスに他のテキストボックスを隠すこともできます）。

![Junk Code - Macro Forms: GetObject関数を使用すると、マクロのフォームからデータを取得できます。これは分析を困難にするために使用できます。以下は、...](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
