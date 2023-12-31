# Docker セキュリティ

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有**してください。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で**最も先進的な**コミュニティツールを搭載した**ワークフローを簡単に構築し自動化**する。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **基本的なDockerエンジンのセキュリティ**

Dockerエンジンは、コンテナの実行と管理を行う重要な役割を果たします。Dockerエンジンは、**Namespaces**や**Cgroups**などのLinuxカーネルの機能を使用して、コンテナ間で基本的な**隔離**を提供します。また、**Capabilities dropping**、**Seccomp**、**SELinux/AppArmor**などの機能を使用して、より良い隔離を実現します。

最後に、**認証プラグイン**を使用して、ユーザーが実行できるアクションを**制限**することができます。

![](<../../../.gitbook/assets/image (625) (1) (1).png>)

### **Dockerエンジンの安全なアクセス**

Dockerクライアントは、Unixソケットを使用してローカルに、またはhttpメカニズムを使用してリモートにDockerエンジンにアクセスできます。リモートで使用するには、機密性、完全性、認証を確保するためにhttpsと**TLS**を使用する必要があります。

デフォルトではUnixソケット`unix:///var/`\
`run/docker.sock`にリッスンし、Ubuntuディストリビューションでは、Dockerの起動オプションは`/etc/default/docker`に指定されています。Docker APIとクライアントがリモートからDockerエンジンにアクセスできるようにするには、**httpソケットを使用してDockerデーモンを公開**する必要があります。これは次のように行います：
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H
tcp://192.168.56.101:2376" -> add this to /etc/default/docker
Sudo service docker restart -> Restart Docker daemon
```
Dockerデーモンをhttpを使用して公開することは良い習慣ではありません。接続をhttpsを使用してセキュリティを確保する必要があります。2つのオプションがあります：最初のオプションは**クライアントがサーバーの身元を確認する**ことで、2番目のオプションは**クライアントとサーバーがお互いの身元を確認する**ことです。証明書はサーバーの身元を確立します。両方のオプションの例については[**このページを確認してください**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)。

### **コンテナイメージのセキュリティ**

コンテナイメージは、プライベートリポジトリまたはパブリックリポジトリに保存されます。Dockerがコンテナイメージの保存に提供するオプションは以下の通りです：

* [Docker hub](https://hub.docker.com) – これはDockerが提供するパブリックレジストリサービスです。
* [Docker registry](https://github.com/%20docker/distribution) – これはユーザーが自分のレジストリをホストするために使用できるオープンソースプロジェクトです。
* [Docker trusted registry](https://www.docker.com/docker-trusted-registry) – これはDockerの商用実装であり、ロールベースのユーザー認証とLDAPディレクトリサービスの統合を提供します。

### イメージスキャン

コンテナには、ベースイメージのため、またはベースイメージの上にインストールされたソフトウェアのために、**セキュリティの脆弱性**が存在する可能性があります。Dockerは、コンテナのセキュリティスキャンを行い、脆弱性をリストアップする**Nautilus**というプロジェクトに取り組んでいます。Nautilusは、各コンテナイメージレイヤーを脆弱性リポジトリと比較してセキュリティホールを特定することによって機能します。

詳細については[**こちらをお読みください**](https://docs.docker.com/engine/scan/)。

* **`docker scan`**

**`docker scan`** コマンドを使用すると、イメージ名またはIDを使用して既存のDockerイメージをスキャンできます。例えば、以下のコマンドを実行してhello-worldイメージをスキャンします：
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
* [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <ontainer_name>:<tag>
```
* [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
* [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Docker イメージ署名

Docker コンテナイメージは、パブリックまたはプライベートレジストリに保存できます。イメージが改ざんされていないことを確認するために、コンテナイメージに**署名**する必要があります。コンテンツ**発行者**は、コンテナイメージに署名してレジストリにプッシュする責任があります。\
以下は Docker コンテンツ信頼に関するいくつかの詳細です：

* Docker コンテンツ信頼は、[Notary オープンソースプロジェクト](https://github.com/docker/notary)の実装です。Notary オープンソースプロジェクトは、[The Update Framework (TUF) プロジェクト](https://theupdateframework.github.io)に基づいています。
* Docker コンテンツ**信頼は** `export DOCKER_CONTENT_TRUST=1` で**有効になります**。Docker バージョン 1.10 以降、コンテンツ信頼は**デフォルトでは有効になっていません**。
* コンテンツ信頼が**有効な場合**、**署名されたイメージのみをプルできます**。イメージをプッシュするときは、タグ付けキーを入力する必要があります。
* 発行者が docker push を使用して**初めて**イメージを**プッシュ**するとき、**ルートキーとタグ付けキー**の**パスフレーズ**を入力する必要があります。他のキーは自動的に生成されます。
* Docker は Yubikey を使用したハードウェアキーのサポートも追加し、詳細は[こちら](https://blog.docker.com/2015/11/docker-content-trust-yubikey/)で利用可能です。

以下は、コンテンツ信頼が有効でイメージが署名されていない場合に得られる**エラー**です。
```shell-session
$ docker pull smakam/mybusybox
Using default tag: latest
No trust data for latest
```
以下の出力は、**署名が有効になっているDocker hubへのContainerイメージのプッシュ**を示しています。これが初めてではないため、ユーザーはリポジトリキーのパスフレーズのみを入力するよう求められます。
```shell-session
$ docker push smakam/mybusybox:v2
The push refers to a repository [docker.io/smakam/mybusybox]
a7022f99b0cc: Layer already exists
5f70bf18a086: Layer already exists
9508eff2c687: Layer already exists
v2: digest: sha256:8509fa814029e1c1baf7696b36f0b273492b87f59554a33589e1bd6283557fc9 size: 2205
Signing and pushing trust metadata
Enter passphrase for repository key with ID 001986b (docker.io/smakam/mybusybox):
```
```markdown
ルートキー、リポジトリキー、およびパスフレーズを安全な場所に保管する必要があります。以下のコマンドを使用してプライベートキーのバックアップを取ることができます：
```
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Dockerホストを変更した際、新しいホストから操作を行うために、ルートキーとリポジトリキーを移動する必要がありました。

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で**最も進んだ**コミュニティツールによって動力を得た**ワークフローの自動化**を簡単に構築しましょう。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## コンテナのセキュリティ機能

<details>

<summary>コンテナのセキュリティ機能の概要</summary>

**ネームスペース**

ネームスペースは、プロジェクトを他のプロジェクトから隔離するのに役立ち、プロセス通信、ネットワーク、マウントなどを隔離します。これは、Dockerプロセスを他のプロセスから隔離するのに役立ち（/procフォルダも含む）、他のプロセスを悪用して脱出することができないようにします。

バイナリ**`unshare`**（**`unshare`**システムコールを使用）を使用して「脱出」、正確には**新しいネームスペースを作成する**ことが可能です。Dockerはデフォルトでこれを防ぎますが、Kubernetesは（この文章の執筆時点では）防ぎません。\
とはいえ、これは新しいネームスペースを作成するのに役立ちますが、ホストのデフォルトネームスペースに**戻ることはできません**（ホストネームスペース内の何らかの`/proc`にアクセスできる場合を除き、その場合は**`nsenter`**を使用してホストネームスペースに入ることができます）。

**CGroups**

これによりリソースを制限できますが、プロセスの隔離のセキュリティには影響しません（`release_agent`を使用して脱出することは可能ですが）。

**Capabilities Drop**

プロセス隔離のセキュリティに関しては、これが**最も重要な**機能の一つだと考えています。これは、機能がなければ、プロセスがrootとして実行されていても、必要な機能を持っていないために呼び出された**`syscall`**が権限エラーを返すため、**特権アクションを実行できない**からです。

これらは、プロセスが他の機能をドロップした後に**残る機能**です：

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Dockerではデフォルトで有効になっています。これにより、プロセスが呼び出すことができる**システムコールをさらに制限**するのに役立ちます。
**デフォルトのDocker Seccompプロファイル**はこちらで確認できます：[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Dockerには、以下のリンクからアクティブにできるテンプレートがあります：[https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

これにより、機能、システムコール、ファイルやフォルダへのアクセスを制限できます...

</details>

### Namespaces

**Namespaces**はLinuxカーネルの機能で、**カーネルリソースを分割**し、あるセットの**プロセス**があるセットの**リソース**を見る一方で、**別の**セットの**プロセス**が**異なる**セットのリソースを見ることができます。この機能は、リソースとプロセスの同じ名前空間を持つことにより動作しますが、それらの名前空間は異なるリソースを指します。リソースは複数の空間に存在することができます。

Dockerは、コンテナの隔離を実現するために以下のLinuxカーネルNamespacesを利用しています：

* pid namespace
* mount namespace
* network namespace
* ipc namespace
* UTS namespace

**名前空間に関する詳細情報**については、以下のページを確認してください：

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

Linuxカーネルの機能**cgroups**は、プロセスのセットに対してcpu、メモリ、io、ネットワーク帯域幅などのリソースを**制限する能力**を提供します。Dockerはcgroup機能を使用してコンテナを作成し、特定のコンテナのリソース制御を可能にします。
以下は、ユーザースペースメモリを500mに、カーネルメモリを50mに、cpuシェアを512に、blkioweightを400に制限したコンテナです。CPUシェアはコンテナのCPU使用量を制御する比率です。デフォルト値は1024で、範囲は0から1024です。CPUリソースの競合がある場合、3つのコンテナが同じCPUシェア1024を持っていると、各コンテナは最大で33%のCPUを使用できます。blkio-weightはコンテナのIOを制御する比率です。デフォルト値は500で、範囲は10から1000です。
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
コンテナのcgroupを取得するには、以下の操作を行います:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
詳細については、以下を確認してください：

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Capabilities（機能）

Capabilitiesは、rootユーザーに許可される機能を**より細かく制御する**ために使用されます。DockerはLinuxカーネルのcapability機能を使用して、ユーザーの種類に関係なく**コンテナ内で実行できる操作を制限します**。

dockerコンテナを実行すると、**プロセスは隔離から脱出するために使用できる機密性の高い機能を削除します**。これにより、プロセスが機密性の高い操作を実行して脱出することがないようにしようとします：

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### DockerのSeccomp

これは、Dockerが**コンテナ内で使用できるシステムコールを制限する**ためのセキュリティ機能です：

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### DockerのAppArmor

**AppArmor**は、**プログラムごとのプロファイル**を使用して**コンテナ**を**限定された**リソースに制限するカーネルの強化機能です。:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### DockerのSELinux

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux)は、**ラベリング** **システム**です。すべての**プロセス**とファイルシステムオブジェクトには**ラベル**があります。SELinuxポリシーは、**プロセスラベルがシステム上の他のすべてのラベルで何を行うことが許可されているか**についてのルールを定義します。

コンテナエンジンは、通常`container_t`として**コンテナプロセスを単一の制限されたSELinuxラベルで起動し**、その後コンテナ内のコンテナを`container_file_t`としてラベル付けします。SELinuxポリシールールは基本的に、**`container_t`プロセスは`container_file_t`とラベル付けされたファイルのみを読み書き/実行できる**と言っています。

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

認証プラグインは、現在の**認証**コンテキストと**コマンド**コンテキストの両方に基づいて、Docker**デーモン**への**リクエスト**を**承認**または**拒否**します。**認証**コンテキストには、すべての**ユーザー詳細**と**認証**方法が含まれます。**コマンドコンテキスト**には、すべての**関連する**リクエストデータが含まれます。

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## コンテナからのDoS

コンテナが使用できるリソースを適切に制限していない場合、侵害されたコンテナは実行しているホストをDoS攻撃する可能性があります。

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* バンド幅DoS
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## 興味深いDockerフラグ

### --privilegedフラグ

以下のページでは、**`--privileged`フラグが何を意味するのか**について学ぶことができます：

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

低権限ユーザーとしてアクセスを得た攻撃者がコンテナ内で実行されている場合、**誤設定されたsuidバイナリ**があれば、攻撃者はそれを悪用して**コンテナ内で権限を昇格**させる可能性があります。これにより、コンテナからの脱出が可能になるかもしれません。

**`no-new-privileges`** オプションを有効にしてコンテナを実行すると、この種の権限昇格を**防ぐことができます**。
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### その他
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
以下のオプションについては、こちらをご覧ください: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## その他のセキュリティに関する考慮事項

### シークレットの管理

まず第一に、**イメージの中に入れないでください！**

また、**環境変数を使用して機密情報を管理しないでください**。**`docker inspect`や`exec`コマンドを実行できる人は誰でもあなたのシークレットを見つけることができます**。

Dockerボリュームの使用がより良いです。これはDockerのドキュメントで推奨されている機密情報へのアクセス方法です。**メモリ内に一時的なファイルシステムとしてボリュームを使用することができます**。ボリュームは`docker inspect`とログ記録のリスクを排除します。しかし、**rootユーザーはまだシークレットを見ることができ、`exec`コマンドを実行できる人も同様です**。

ボリュームよりも**さらに良い方法は、Dockerシークレットを使用することです**。

もしイメージ内で**シークレットが必要な場合**、**BuildKit**を使用することができます。BuildKitはビルド時間を大幅に短縮し、**ビルド時のシークレットサポート**を含む他の便利な機能を持っています。

BuildKitバックエンドを指定してその機能を今すぐ使用するには3つの方法があります。:

1. 環境変数として設定するには`export DOCKER_BUILDKIT=1`とします。
2. `build`または`run`コマンドを`DOCKER_BUILDKIT=1`で始めます。
3. BuildKitをデフォルトで有効にする。_/etc/docker/daemon.json_の設定を`{ "features": { "buildkit": true } }`として_true_に設定し、Dockerを再起動します。
4. そして、ビルド時に`--secret`フラグを使用してシークレットを使用することができます。以下のようにします：
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
ファイルでシークレットをキーと値のペアとして指定します。

これらのシークレットはイメージビルドキャッシュから、そして最終イメージから除外されます。

イメージをビルドする際だけでなく、**実行中のコンテナ内でシークレットが必要な場合**は、**Docker ComposeまたはKubernetes**を使用します。

Docker Composeを使用する場合、サービスにシークレットのキーと値のペアを追加し、シークレットファイルを指定します。以下の例は、[Stack Exchangeの回答](https://serverfault.com/a/936262/535325)のDocker Composeのシークレットのヒントに基づいて適応されています。

シークレットを含む`docker-compose.yml`の例：
```yaml
version: "3.7"

services:

my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret

secrets:
my_secret:
file: ./my_secret_file.txt
```
以下は、通常どおり `docker-compose up --build my_service` でComposeを開始します。

[Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/) を使用している場合、シークレットに対応しています。 [Helm-Secrets](https://github.com/futuresimple/helm-secrets) は、K8sでのシークレット管理を容易にするのに役立ちます。さらに、K8sにはロールベースのアクセス制御（RBAC）があります。Docker Enterpriseも同様です。RBACは、チームにとってシークレット管理をより管理しやすく、より安全にします。

### gVisor

**gVisor** は、Goで書かれたアプリケーションカーネルで、Linuxシステムの大部分を実装しています。これには `runsc` という [Open Container Initiative (OCI)](https://www.opencontainers.org) ランタイムが含まれており、**アプリケーションとホストカーネルの間に隔離境界を提供します**。`runsc` ランタイムはDockerとKubernetesに統合されており、サンドボックス化されたコンテナを簡単に実行できます。

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** は、コンテナのように感じられ、コンテナのように動作するが、ハードウェア仮想化技術を使用して **より強力なワークロードの隔離を提供する** 軽量な仮想マシンを構築するために取り組むオープンソースコミュニティです。

{% embed url="https://katacontainers.io/" %}

### 要約のヒント

* **`--privileged` フラグを使用しないでください。また、**[**Dockerソケットをコンテナ内にマウントしないでください**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**。** Dockerソケットを使用すると、コンテナを生成できるため、例えば `--privileged` フラグを使用して別のコンテナを実行することで、ホストを完全に制御する簡単な方法です。
* **コンテナ内でrootとして実行しないでください。**[**異なるユーザー**](https://docs.docker.com/develop/develop-images/dockerfile\_best-practices/#user) **と** [**ユーザーネームスペース**](https://docs.docker.com/engine/security/userns-remap/) **を使用してください。** コンテナのrootは、ユーザーネームスペースでリマップされていない限り、ホスト上のrootと同じです。主にLinuxのネームスペース、機能、およびcgroupsによって軽く制限されているだけです。
* [**すべての機能をドロップ**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`)し、必要なもののみを有効にします** (`--cap-add=...`)。多くのワークロードはいかなる機能も必要とせず、それらを追加すると潜在的な攻撃の範囲が広がります。
* [**“no-new-privileges” セキュリティオプションを使用して**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/)、例えばsuidバイナリを通じて、プロセスがより多くの権限を得るのを防ぎます。
* [**コンテナに利用可能なリソースを制限します**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**。** リソース制限は、サービス拒否攻撃からマシンを保護することができます。
* **[**seccomp**](https://docs.docker.com/engine/security/seccomp/)**、**[**AppArmor**](https://docs.docker.com/engine/security/apparmor/)**（またはSELinux）** プロファイルを調整して、コンテナで利用可能なアクションとシステムコールを最小限に制限します。
* **[**公式のdockerイメージ**](https://docs.docker.com/docker-hub/official\_images/) を使用し、署名を要求するか、それらに基づいて自分のイメージを構築してください。** バックドアが仕掛けられたイメージを継承したり使用したりしないでください。また、rootキー、パスフレーズを安全な場所に保管してください。DockerはUCPでキーを管理する計画を持っています。
* **定期的に** イメージを **再構築して、ホストとイメージにセキュリティパッチを適用します。**
* **シークレットを賢く管理し**、攻撃者がアクセスするのが難しくします。
* **dockerデーモンを公開する場合はHTTPSを使用し**、クライアントとサーバーの認証を行います。
* Dockerfileでは、**ADDの代わりにCOPYを優先します**。ADDは自動的に圧縮ファイルを展開し、URLからファイルをコピーすることができます。COPYにはこれらの機能がありません。可能な限りADDの使用を避け、リモートURLやZipファイルを介した攻撃に対して脆弱にならないようにしてください。
* **各マイクロサービスごとに別々のコンテナを持ちます**
* **コンテナ内にsshを置かないでください**、「docker exec」はコンテナにsshするために使用できます。
* **より小さい** コンテナ **イメージを持ちます**

## Docker Breakout / Privilege Escalation

**dockerコンテナ内にいる場合**、または **dockerグループのユーザーにアクセスできる場合**、**脱出して権限を昇格する** ことを試みることができます：

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Docker Authentication Plugin Bypass

dockerソケットにアクセスできる場合、または **dockerグループのユーザーにアクセスできるが、docker認証プラグインによって行動が制限されている場合**、それを **バイパスできるかどうかを確認してください**：

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Dockerの強化

* ツール [**docker-bench-security**](https://github.com/docker/docker-bench-security) は、本番環境でDockerコンテナをデプロイする際の一般的なベストプラクティスを数十項目チェックするスクリプトです。テストはすべて自動化されており、[CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/) に基づいています。\
ツールを実行するには、dockerを実行しているホストから、または十分な権限を持つコンテナから実行する必要があります。**READMEでの実行方法を確認してください：** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security)。

## 参考文献

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
* [https://en.wikipedia.org/wiki/Linux\_namespaces](https://en.wikipedia.org/wiki/Linux\_namespaces)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) を使用して、世界で **最も先進的な** コミュニティツールによって動力を供給される **ワークフローを簡単に構築および自動化します**。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学びましょう</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksに広告を掲載したい場合**、または **HackTricksをPDFでダウンロードしたい場合**、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com) を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見してください。私たちの独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) コレクションです。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) または [**telegramグループ**](https://t.me/peass) に **参加するか**、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を **フォローしてください**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) および [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) githubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>
