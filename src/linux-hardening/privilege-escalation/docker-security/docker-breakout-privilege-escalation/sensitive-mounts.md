# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

`/proc` と `/sys` の適切な名前空間の分離なしでの露出は、攻撃面の拡大や情報漏洩を含む重大なセキュリティリスクを引き起こします。これらのディレクトリには、誤って設定されたり、無許可のユーザーによってアクセスされたりすると、コンテナの脱出、ホストの変更、またはさらなる攻撃を助ける情報を提供する可能性のある機密ファイルが含まれています。たとえば、`-v /proc:/host/proc` を誤ってマウントすると、そのパスベースの性質により AppArmor の保護を回避し、`/host/proc` が保護されない状態になります。

**各潜在的脆弱性の詳細は** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**で確認できます。**

## procfs Vulnerabilities

### `/proc/sys`

このディレクトリは、通常 `sysctl(2)` を介してカーネル変数を変更するためのアクセスを許可し、いくつかの懸念されるサブディレクトリを含んでいます。

#### **`/proc/sys/kernel/core_pattern`**

- [core(5)](https://man7.org/linux/man-pages/man5/core.5.html) に記載されています。
- コアファイル生成時に実行するプログラムを定義でき、最初の128バイトが引数として渡されます。ファイルがパイプ `|` で始まる場合、コード実行につながる可能性があります。
- **テストと悪用の例**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # 書き込みアクセスのテスト
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # カスタムハンドラを設定
sleep 5 && ./crash & # ハンドラをトリガー
```

#### **`/proc/sys/kernel/modprobe`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) に詳述されています。
- カーネルモジュールローダーへのパスを含み、カーネルモジュールをロードするために呼び出されます。
- **アクセス確認の例**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # modprobe へのアクセスを確認
```

#### **`/proc/sys/vm/panic_on_oom`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) に参照されています。
- OOM 条件が発生したときにカーネルがパニックを起こすか、OOM キラーを呼び出すかを制御するグローバルフラグです。

#### **`/proc/sys/fs`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) に従い、ファイルシステムに関するオプションと情報を含みます。
- 書き込みアクセスにより、ホストに対するさまざまなサービス拒否攻撃を可能にします。

#### **`/proc/sys/fs/binfmt_misc`**

- マジックナンバーに基づいて非ネイティブバイナリ形式のインタープリタを登録できます。
- `/proc/sys/fs/binfmt_misc/register` が書き込み可能な場合、特権昇格やルートシェルアクセスにつながる可能性があります。
- 関連するエクスプロイトと説明:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- 詳細なチュートリアル: [Video link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Others in `/proc`

#### **`/proc/config.gz`**

- `CONFIG_IKCONFIG_PROC` が有効な場合、カーネル設定を明らかにする可能性があります。
- 実行中のカーネルの脆弱性を特定するために攻撃者にとって有用です。

#### **`/proc/sysrq-trigger`**

- Sysrq コマンドを呼び出すことができ、即座にシステムを再起動したり、他の重要なアクションを引き起こしたりする可能性があります。
- **ホストを再起動する例**:

```bash
echo b > /proc/sysrq-trigger # ホストを再起動
```

#### **`/proc/kmsg`**

- カーネルリングバッファメッセージを公開します。
- カーネルエクスプロイト、アドレスリーク、機密システム情報の提供に役立ちます。

#### **`/proc/kallsyms`**

- カーネルがエクスポートしたシンボルとそのアドレスをリストします。
- KASLR を克服するためのカーネルエクスプロイト開発に不可欠です。
- アドレス情報は `kptr_restrict` が `1` または `2` に設定されている場合、制限されます。
- 詳細は [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) にあります。

#### **`/proc/[pid]/mem`**

- カーネルメモリデバイス `/dev/mem` とインターフェースします。
- 歴史的に特権昇格攻撃に対して脆弱です。
- 詳細は [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) にあります。

#### **`/proc/kcore`**

- システムの物理メモリを ELF コア形式で表します。
- 読み取りはホストシステムや他のコンテナのメモリ内容を漏洩させる可能性があります。
- 大きなファイルサイズは読み取りの問題やソフトウェアのクラッシュを引き起こす可能性があります。
- 詳細な使用法は [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/) にあります。

#### **`/proc/kmem`**

- カーネル仮想メモリを表す `/dev/kmem` の代替インターフェースです。
- 読み取りと書き込みが可能で、カーネルメモリの直接変更を許可します。

#### **`/proc/mem`**

- 物理メモリを表す `/dev/mem` の代替インターフェースです。
- 読み取りと書き込みが可能で、すべてのメモリの変更には仮想アドレスを物理アドレスに解決する必要があります。

#### **`/proc/sched_debug`**

- プロセススケジューリング情報を返し、PID 名前空間の保護を回避します。
- プロセス名、ID、および cgroup 識別子を公開します。

#### **`/proc/[pid]/mountinfo`**

- プロセスのマウント名前空間内のマウントポイントに関する情報を提供します。
- コンテナの `rootfs` またはイメージの場所を公開します。

### `/sys` Vulnerabilities

#### **`/sys/kernel/uevent_helper`**

- カーネルデバイス `uevents` を処理するために使用されます。
- `/sys/kernel/uevent_helper` への書き込みは、`uevent` トリガー時に任意のスクリプトを実行する可能性があります。
- **悪用の例**: %%%bash

#### ペイロードを作成

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### コンテナの OverlayFS マウントからホストパスを見つける

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### 悪意のあるヘルパーに uevent_helper を設定

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### uevent をトリガー

echo change > /sys/class/mem/null/uevent

#### 出力を読み取る

cat /output %%%

#### **`/sys/class/thermal`**

- 温度設定を制御し、DoS 攻撃や物理的損傷を引き起こす可能性があります。

#### **`/sys/kernel/vmcoreinfo`**

- カーネルアドレスを漏洩させ、KASLR を危険にさらす可能性があります。

#### **`/sys/kernel/security`**

- `securityfs` インターフェースを保持し、AppArmor のような Linux セキュリティモジュールの設定を許可します。
- アクセスにより、コンテナがその MAC システムを無効にする可能性があります。

#### **`/sys/firmware/efi/vars` と `/sys/firmware/efi/efivars`**

- NVRAM 内の EFI 変数と対話するためのインターフェースを公開します。
- 誤設定や悪用により、ラップトップがブリックされたり、ホストマシンが起動不能になったりする可能性があります。

#### **`/sys/kernel/debug`**

- `debugfs` はカーネルへの「ルールなし」のデバッグインターフェースを提供します。
- 制限のない性質のため、セキュリティ問題の歴史があります。

### References

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
