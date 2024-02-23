# Dockerセキュリティ

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)で**フォロー**する
- **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も先進的なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **基本的なDocker Engineセキュリティ**

**Docker Engine**は、Linuxカーネルの**Namespaces**と**Cgroups**を使用してコンテナを分離し、基本的なセキュリティレイヤーを提供します。**Capabilities dropping**、**Seccomp**、**SELinux/AppArmor**を介して追加の保護が提供され、コンテナの分離が強化されます。**認証プラグイン**を使用すると、ユーザーのアクションをさらに制限できます。

![Dockerセキュリティ](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Docker Engineへの安全なアクセス

Docker Engineは、Unixソケットを介してローカルでアクセスするか、HTTPを使用してリモートでアクセスできます。リモートアクセスの場合、機密性、整合性、および認証を確保するためにHTTPSと**TLS**を使用することが重要です。

デフォルトでは、Docker EngineはUnixソケットで`unix:///var/run/docker.sock`でリッスンします。Ubuntuシステムでは、Dockerの起動オプションは`/etc/default/docker`に定義されています。Docker APIとクライアントへのリモートアクセスを有効にするには、次の設定を追加してDockerデーモンをHTTPソケットで公開してください：
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
しかし、DockerデーモンをHTTP経由で公開することはセキュリティ上の懸念から推奨されていません。接続を安全にするためには、HTTPSを使用することが望ましいです。接続を保護するための主なアプローチは2つあります：

1. クライアントがサーバーの正体を確認します。
2. クライアントとサーバーの両方がお互いの正体を相互認証します。

証明書はサーバーの正体を確認するために使用されます。両方の方法の詳細な例については、[**このガイド**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)を参照してください。

### コンテナイメージのセキュリティ

コンテナイメージは、プライベートリポジトリまたはパブリックリポジトリに保存できます。Dockerには、コンテナイメージのためのいくつかのストレージオプションがあります：

* [**Docker Hub**](https://hub.docker.com): Dockerのパブリックレジストリサービス。
* [**Docker Registry**](https://github.com/docker/distribution): ユーザーが独自のレジストリをホストできるオープンソースプロジェクト。
* [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): ロールベースのユーザー認証とLDAPディレクトリサービスとの統合を備えたDockerの商用レジストリオファリング。

### イメージスキャン

コンテナには、ベースイメージまたはベースイメージの上にインストールされたソフトウェアのせいで**セキュリティの脆弱性**がある場合があります。Dockerは、コンテナのセキュリティスキャンを行い脆弱性をリストアップするプロジェクト**Nautilus**に取り組んでいます。Nautilusは、各コンテナイメージレイヤーを脆弱性リポジトリと比較してセキュリティホールを特定することで機能します。

詳細については、[**こちらを読んでください**](https://docs.docker.com/engine/scan/)。

* **`docker scan`**

**`docker scan`**コマンドを使用すると、イメージ名またはIDを使用して既存のDockerイメージをスキャンできます。たとえば、次のコマンドを実行してhello-worldイメージをスキャンできます：
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
### Dockerイメージの署名

Dockerイメージの署名は、コンテナで使用されるイメージのセキュリティと整合性を確保します。以下は要約した説明です：

- **Docker Content Trust** は、Notaryプロジェクトを利用し、The Update Framework (TUF) に基づいてイメージの署名を管理します。詳細については、[Notary](https://github.com/docker/notary) と [TUF](https://theupdateframework.github.io) を参照してください。
- Dockerコンテンツ信頼を有効にするには、`export DOCKER_CONTENT_TRUST=1` を設定します。この機能は、Dockerバージョン1.10以降ではデフォルトでオフになっています。
- この機能を有効にすると、署名されたイメージのみをダウンロードできます。最初のイメージプッシュでは、ルートとタグ付けキーのパスフレーズを設定する必要があり、Dockerはセキュリティを強化するためにYubikeyもサポートしています。詳細は[こちら](https://blog.docker.com/2015/11/docker-content-trust-yubikey/)にあります。
- コンテンツ信頼が有効な状態で署名されていないイメージを取得しようとすると、「最新の信頼データがありません」というエラーが発生します。
- 最初以降のイメージプッシュでは、Dockerはイメージに署名するためにリポジトリキーのパスフレーズを要求します。

プライベートキーをバックアップするには、次のコマンドを使用します：
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Dockerホストを切り替える際には、操作を維持するためにルートとリポジトリキーを移動する必要があります。

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も先進的なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## コンテナセキュリティ機能

<details>

<summary>コンテナセキュリティ機能の概要</summary>

#### メインプロセスの分離機能

コンテナ化された環境では、プロジェクトとそのプロセスを分離することがセキュリティとリソース管理にとって重要です。以下は、主要な概念の簡略化された説明です：

**ネームスペース**

* **目的**: プロセス、ネットワーク、およびファイルシステムなどのリソースの分離を確保します。特にDockerでは、ネームスペースがコンテナのプロセスをホストや他のコンテナから分離します。
* **`unshare`の使用**: `unshare`コマンド（またはその基礎となるシスコール）は、新しいネームスペースを作成するために使用され、追加の分離レイヤーを提供します。ただし、Kubernetesはこれを元々ブロックしませんが、Dockerはします。
* **制限**: 新しいネームスペースを作成することで、プロセスがホストのデフォルトのネームスペースに戻ることはできません。ホストのネームスペースに侵入するには、通常、ホストの`/proc`ディレクトリにアクセスし、`nsenter`を使用します。

**コントロールグループ（CGroups）**

* **機能**: プロセス間でリソースを割り当てるために主に使用されます。
* **セキュリティの側面**: CGroups自体は分離セキュリティを提供しませんが、`release_agent`機能は、誤って構成されている場合、権限のないアクセスに悪用される可能性があります。

**機能の削除**

* **重要性**: プロセスの分離のための重要なセキュリティ機能です。
* **機能**: 特定の機能をドロップすることで、ルートプロセスが実行できるアクションを制限します。プロセスがルート権限で実行されていても、必要な機能がないと特権アクションを実行できません。シスコールは権限が不足しているため失敗します。
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

デフォルトでDockerに有効になっています。これにより、プロセスが呼び出すことができる**syscallsをさらに制限**するのに役立ちます。\
**デフォルトのDocker Seccompプロファイル**は[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)で見つけることができます。

**AppArmor**

Dockerにはアクティベートできるテンプレートがあります: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

これにより、機能の制限、syscalls、ファイルやフォルダへのアクセスが可能になります...

</details>

### Namespaces

**Namespaces**はLinuxカーネルの機能で、1つの**プロセス**セットが1つの**リソース**セットを**見る**一方、別の**プロセス**セットが**異なる**リソースセットを見るようにカーネルリソースを**分割**する機能です。この機能は、一連のリソースとプロセスに同じ名前空間があるが、それらの名前空間が異なるリソースを参照するように機能します。リソースは複数のスペースに存在する可能性があります。

Dockerは、コンテナの分離を実現するために以下のLinuxカーネルNamespacesを利用しています:

* pid namespace
* mount namespace
* network namespace
* ipc namespace
* UTS namespace

**名前空間に関する詳細情報**については、以下のページを参照してください:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

Linuxカーネル機能**cgroups**は、一連のプロセス間でcpu、memory、io、ネットワーク帯域幅などのリソースを**制限**する機能を提供します。 Dockerは、cgroup機能を使用してリソース制御を可能にするコンテナを作成できます。\
以下は、ユーザースペースメモリが500mに制限され、カーネルメモリが50mに制限され、CPUシェアが512に、blkioweightが400に制限されたコンテナの例です。 CPUシェアは、コンテナのCPU使用率を制御する比率です。デフォルト値は1024で、0から1024までの範囲があります。 CPUリソースの競合が発生した場合、CPUシェアが1024の3つのコンテナが同じ場合、各コンテナはCPUの最大33%を取ることができます。 blkio-weightは、コンテナのIOを制御する比率です。デフォルト値は500で、10から1000までの範囲があります。
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
コンテナのcgroupを取得するには、次のようにします:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
以下の情報をご確認ください：

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Capabilities

Capabilitiesはrootユーザーに許可される機能をより細かく制御することができます。DockerはLinuxカーネルの機能を使用して、ユーザーの種類に関係なく、コンテナ内で行われる操作を制限します。

Dockerコンテナが実行されると、プロセスは隔離から脱出するために使用できる機密な機能を削除します。これにより、プロセスが機密なアクションを実行して脱出することができないようにします：

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Docker内のSeccomp

これはDockerがコンテナ内で使用できるシステムコールを制限するセキュリティ機能です：

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### Docker内のAppArmor

AppArmorは、コンテナを限られたリソースセットに制限するためのカーネルの拡張機能であり、プログラムごとのプロファイルを使用します。

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### Docker内のSELinux

* **ラベリングシステム**: SELinuxは、すべてのプロセスとファイルシステムオブジェクトに一意のラベルを割り当てます。
* **ポリシーの強制**: プロセスラベルがシステム内の他のラベルに対して実行できるアクションを定義するセキュリティポリシーを強制します。
* **コンテナプロセスラベル**: コンテナエンジンがコンテナプロセスを開始すると、通常は`container_t`という制限されたSELinuxラベルが割り当てられます。
* **コンテナ内のファイルラベリング**: コンテナ内のファイルは通常、`container_file_t`としてラベル付けされます。
* **ポリシールール**: SELinuxポリシーは、主に`container_t`ラベルを持つプロセスが`container_file_t`としてラベル付けされたファイルとのみやり取り（読み取り、書き込み、実行）できることを保証します。

このメカニズムにより、コンテナ内のプロセスが侵害された場合でも、対応するラベルを持つオブジェクトとのやり取りに制限され、そのような侵害からの潜在的な被害が大幅に制限されます。

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ＆AuthN

Dockerでは、認可プラグインが重要な役割を果たし、Dockerデーモンへのリクエストを許可するかブロックするかを決定します。この決定は、次の2つのキーとなるコンテキストを調査することで行われます：

* **認証コンテキスト**: ユーザーに関する包括的な情報が含まれます。誰であり、どのように認証されたかなど。
* **コマンドコンテキスト**: リクエストに関連するすべての関連データが含まれます。

これらのコンテキストにより、認証されたユーザーからの正当なリクエストのみが処理され、Docker操作のセキュリティが向上します。

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## コンテナからのDoS

コンテナが使用できるリソースを適切に制限していない場合、侵害されたコンテナが実行されているホストをDoS攻撃する可能性があります。

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* バンド幅 DoS
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## インタレスティングなDockerフラグ

### --privileged フラグ

次のページで、**`--privileged` フラグが意味するもの**を学ぶことができます:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

低権限ユーザーとしてアクセスを取得した攻撃者がコンテナを実行している場合、**誤構成されたsuidバイナリ**があると、攻撃者はそれを悪用してコンテナ内で**特権を昇格**させる可能性があります。これにより、脱出することができるかもしれません。

**`no-new-privileges`** オプションを有効にしてコンテナを実行すると、**この種の特権昇格を防ぐ**ことができます。
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
さらなる**`--security-opt`**オプションについては、[https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration) を参照してください。

## その他のセキュリティ考慮事項

### シークレットの管理：ベストプラクティス

Dockerイメージにシークレットを直接埋め込んだり、環境変数を使用したりすることは避けることが重要です。これらの方法は、`docker inspect`や`exec`などのコマンドを使用してコンテナにアクセスできる人に機密情報を公開してしまいます。

**Dockerボリューム**は、機密情報にアクセスするために推奨されるより安全な代替手段です。これらは一時的なメモリ内のファイルシステムとして利用でき、`docker inspect`やログ記録に関連するリスクを軽減します。ただし、ルートユーザーやコンテナへの`exec`アクセス権を持つユーザーは依然としてシークレットにアクセスできる可能性があります。

**Dockerシークレット**は、機密情報を取り扱うためのさらに安全な方法を提供します。イメージのビルドフェーズ中にシークレットが必要な場合、**BuildKit**はビルド時間のシークレットをサポートする効率的なソリューションを提供し、ビルド速度を向上させ、追加の機能を提供します。

BuildKitを活用するためには、次の3つの方法でアクティブ化できます：

1. 環境変数を介して：`export DOCKER_BUILDKIT=1`
2. コマンドにプレフィックスを付けて：`DOCKER_BUILDKIT=1 docker build .`
3. Docker構成でデフォルトで有効にする：`{ "features": { "buildkit": true } }`を設定し、その後Dockerを再起動します。

BuildKitを使用すると、`--secret`オプションを使用してビルド時間のシークレットを利用でき、これらのシークレットがイメージビルドキャッシュや最終イメージに含まれないようにします。
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
実行中のコンテナで必要なシークレットについては、**Docker ComposeとKubernetes**が堅牢なソリューションを提供しています。Docker Composeは、`docker-compose.yml`の例に示すように、サービス定義でシークレットファイルを指定するための`secrets`キーを利用します。
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
この設定では、Docker Composeを使用してサービスを起動する際にシークレットを使用できます。

Kubernetes環境では、シークレットはネイティブでサポートされ、[Helm-Secrets](https://github.com/futuresimple/helm-secrets)などのツールでさらに管理できます。KubernetesのRole Based Access Controls（RBAC）は、Docker Enterpriseと同様にシークレット管理のセキュリティを向上させます。

### gVisor

**gVisor**は、Goで書かれたアプリケーションカーネルで、Linuxシステムサーフェスの大部分を実装しています。[Open Container Initiative（OCI）](https://www.opencontainers.org)ランタイムである`runsc`を含み、**アプリケーションとホストカーネルの間の隔離境界**を提供します。`runsc`ランタイムはDockerとKubernetesと統合されており、サンドボックス化されたコンテナを簡単に実行できます。

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers**は、軽量な仮想マシンを使用してコンテナのように感じ、パフォーマンスを発揮するセキュアなコンテナランタイムを構築するために取り組むオープンソースコミュニティですが、第2の防御層としてハードウェア仮想化技術を使用して**強力なワークロード分離**を提供します。

{% embed url="https://katacontainers.io/" %}

### 要約のヒント

* **`--privileged`フラグを使用しない**か、[**コンテナ内にDockerソケットをマウントしないでください**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)。 Dockerソケットを使用すると、コンテナの生成が可能になり、たとえば`--privileged`フラグを使用して別のコンテナを実行することでホストを完全に制御できるようになります。
* **コンテナ内でrootとして実行しないでください。** [**異なるユーザー**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) **と** [**ユーザーネームスペース**](https://docs.docker.com/engine/security/userns-remap/) **を使用してください。** コンテナ内のrootは、ユーザーネームスペースでリマップされない限り、ホストと同じです。主にLinuxのネームスペース、機能、およびcgroupsによってわずかに制限されています。
* [**すべての機能を削除**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`)し、必要な機能のみを有効にしてください** (`--cap-add=...`)。多くのワークロードには機能が必要ない場合があり、それらを追加すると攻撃の範囲が広がります。
* [**“no-new-privileges”セキュリティオプションを使用**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/)して、例えばsuidバイナリを介してプロセスが特権を取得するのを防止してください。
* **コンテナに利用可能なリソースを制限してください**。リソース制限は、マシンをサービス拒否攻撃から保護できます。
* **[seccomp](https://docs.docker.com/engine/security/seccomp/)**、**[AppArmor](https://docs.docker.com/engine/security/apparmor/)** **（またはSELinux）**プロファイルを調整して、コンテナで利用可能なアクションとシスコールを最小限に制限してください。
* **[公式のDockerイメージ](https://docs.docker.com/docker-hub/official_images/)を使用**し、署名を要求するか、それらを基に独自のイメージを構築してください。[バックドアが仕込まれた](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/)イメージを継承したり使用しないでください。また、ルートキー、パスフレーズは安全な場所に保存してください。DockerはUCPでキーを管理する計画を立てています。
* **定期的に** **イメージを再構築**して、ホストとイメージにセキュリティパッチを適用してください。
* **シークレットを賢く管理**して、攻撃者がアクセスしにくくしてください。
* Dockerデーモンを公開する場合は、HTTPSを使用してクライアントとサーバーの認証を行ってください。
* Dockerfileでは、**ADDの代わりにCOPYを使用**してください。ADDは自動的にzipファイルを解凍し、URLからファイルをコピーできます。COPYにはこれらの機能がありません。可能な限り、ADDを使用しないようにして、リモートURLやZipファイルを介した攻撃に対して脆弱にならないようにしてください。
* **各マイクロサービスには別々のコンテナを使用してください。**
* **コンテナイメージを小さくしてください。**
他のHackTricksのサポート方法:

- [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックして、**HackTricksをPDFでダウンロード**したい場合や、**HackTricksで企業を宣伝**したい場合
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)で**フォロー**する
- [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する
