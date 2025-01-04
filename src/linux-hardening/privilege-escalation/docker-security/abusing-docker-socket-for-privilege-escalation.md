# Dockerソケットを悪用して特権昇格を行う

{{#include ../../../banners/hacktricks-training.md}}

**Dockerソケット**に**アクセス**できる場合があり、それを使用して**特権を昇格**させたいことがあります。一部のアクションは非常に疑わしい場合があり、避けたいかもしれません。ここでは、特権を昇格させるのに役立つさまざまなフラグを見つけることができます。

### マウントを介して

**ルート**として実行されているコンテナ内で**ファイルシステム**の異なる部分を**マウント**し、それに**アクセス**できます。\
コンテナ内で特権を昇格させるために**マウントを悪用**することもできます。

- **`-v /:/host`** -> ホストのファイルシステムをコンテナにマウントし、**ホストのファイルシステムを読み取る**ことができます。
- **ホストにいるように感じたい**がコンテナにいる場合、次のフラグを使用して他の防御メカニズムを無効にすることができます：
- `--privileged`
- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `-security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> これは前の方法に似ていますが、ここでは**デバイスディスクをマウント**しています。その後、コンテナ内で `mount /dev/sda1 /mnt` を実行すると、**/mnt**で**ホストのファイルシステムにアクセス**できます。
- ホストで `fdisk -l` を実行して、マウントする `</dev/sda1>` デバイスを見つけます。
- **`-v /tmp:/host`** -> 何らかの理由で**ホストから特定のディレクトリのみをマウント**でき、ホスト内にアクセスできる場合、それをマウントし、マウントされたディレクトリに**suid**を持つ**`/bin/bash`**を作成して、**ホストから実行してルートに昇格**します。

> [!NOTE]
> `/tmp`フォルダをマウントできない場合がありますが、**異なる書き込み可能なフォルダ**をマウントできるかもしれません。書き込み可能なディレクトリを見つけるには、`find / -writable -type d 2>/dev/null`を使用します。
>
> **Linuxマシンのすべてのディレクトリがsuidビットをサポートするわけではありません！** どのディレクトリがsuidビットをサポートしているかを確認するには、`mount | grep -v "nosuid"`を実行します。たとえば、通常、`/dev/shm`、`/run`、`/proc`、`/sys/fs/cgroup`、および`/var/lib/lxcfs`はsuidビットをサポートしていません。
>
> また、**`/etc`**や**設定ファイルを含む他のフォルダ**を**マウント**できる場合、コンテナ内からルートとしてそれらを変更し、**ホストで悪用して特権を昇格**させることができます（たとえば、`/etc/shadow`を変更する）。

### コンテナからの脱出

- **`--privileged`** -> このフラグを使用すると、[コンテナからのすべての隔離を削除します](docker-privileged.md#what-affects)。 [特権コンテナからルートとして脱出する技術](docker-breakout-privilege-escalation/index.html#automatic-enumeration-and-escape)を確認してください。
- **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> [特権を昇格させるために能力を悪用する](../linux-capabilities.md)には、**その能力をコンテナに付与し**、エクスプロイトが機能するのを妨げる可能性のある他の保護方法を無効にします。

### Curl

このページでは、Dockerフラグを使用して特権を昇格させる方法について説明しました。**curl**コマンドを使用してこれらの方法を悪用する方法を見つけることができます。

{{#include ../../../banners/hacktricks-training.md}}
