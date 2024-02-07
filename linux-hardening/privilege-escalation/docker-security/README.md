# Dockerセキュリティ

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**する
- **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **基本的なDocker Engineセキュリティ**

**Docker Engine**は、Linuxカーネルの**Namespaces**と**Cgroups**を使用してコンテナを分離し、基本的なセキュリティレイヤーを提供します。**Capabilities dropping**、**Seccomp**、**SELinux/AppArmor**によって追加の保護が提供され、コンテナの分離が強化されます。**認証プラグイン**を使用すると、ユーザーのアクションをさらに制限できます。

![Dockerセキュリティ](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Docker Engineへの安全なアクセス

Docker Engineは、ローカルでUnixソケットを介してまたはHTTPを使用してリモートでアクセスできます。リモートアクセスの場合、機密性、整合性、および認証を確保するためにHTTPSと**TLS**を使用することが重要です。

デフォルトでは、Docker Engineは`unix:///var/run/docker.sock`でUnixソケットをリッスンします。Ubuntuシステムでは、Dockerの起動オプションは`/etc/default/docker`に定義されています。Docker APIとクライアントへのリモートアクセスを有効にするには、次の設定を追加してDockerデーモンをHTTPソケット経由で公開します：
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
DockerデーモンをHTTP経由で公開することはセキュリティ上の懸念から推奨されていません。接続を安全にするためにはHTTPSを使用することが望ましいです。接続を保護するための主なアプローチは2つあります：
1. クライアントがサーバーの正体を確認します。
2. クライアントとサーバーがお互いの正体を相互認証します。

証明書はサーバーの正体を確認するために使用されます。両方の方法の詳細な例については、[**このガイド**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)を参照してください。

### コンテナイメージのセキュリティ

コンテナイメージは、プライベートまたはパブリックのリポジトリに保存することができます。Dockerには、コンテナイメージのためのいくつかのストレージオプションがあります：

* **[Docker Hub](https://hub.docker.com)**: Dockerのパブリックレジストリサービス。
* **[Docker Registry](https://github.com/docker/distribution)**: ユーザーが独自のレジストリをホストできるオープンソースプロジェクト。
* **[Docker Trusted Registry](https://www.docker.com/docker-trusted-registry)**: Dockerの商用レジストリオファリングで、ロールベースのユーザー認証とLDAPディレクトリサービスとの統合を提供しています。

### イメージスキャン

コンテナには、ベースイメージまたはベースイメージの上にインストールされたソフトウェアのせいで**セキュリティの脆弱性**がある場合があります。Dockerは、コンテナのセキュリティスキャンを行い脆弱性をリストアップするプロジェクト**Nautilus**に取り組んでいます。Nautilusは、各コンテナイメージレイヤーを脆弱性リポジトリと比較してセキュリティホールを特定します。

詳細は[**こちらを参照してください**](https://docs.docker.com/engine/scan/)。

* **`docker scan`**

**`docker scan`**コマンドを使用すると、イメージ名またはIDを使用して既存のDockerイメージをスキャンできます。たとえば、次のコマンドを実行してhello-worldイメージをスキャンします：
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

Dockerイメージの署名は、コンテナで使用されるイメージのセキュリティと整合性を確保します。以下は簡潔な説明です：

- **Docker Content Trust** は、Notaryプロジェクトを利用し、The Update Framework (TUF) に基づいてイメージの署名を管理します。詳細については、[Notary](https://github.com/docker/notary) と [TUF](https://theupdateframework.github.io) を参照してください。
- Docker content trust を有効にするには、`export DOCKER_CONTENT_TRUST=1` を設定します。この機能は、Docker バージョン1.10以降ではデフォルトでオフになっています。
- この機能を有効にすると、署名されたイメージのみがダウンロードできます。初回のイメージプッシュでは、ルートとタグ付けキーのパスフレーズを設定する必要があり、Dockerはセキュリティを強化するためにYubikeyもサポートしています。詳細は[こちら](https://blog.docker.com/2015/11/docker-content-trust-yubikey/)にあります。
- content trust を有効にした状態で署名されていないイメージを取得しようとすると、「No trust data for latest」というエラーが発生します。
- 初回以降のイメージプッシュでは、Dockerはイメージに署名するためにリポジトリキーのパスフレーズを要求します。

プライベートキーをバックアップするには、次のコマンドを使用します：
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Dockerホストを切り替える際には、操作を維持するためにルートとリポジトリキーを移動する必要があります。

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も先進的なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## コンテナセキュリティ機能

<details>

<summary>コンテナセキュリティ機能の概要</summary>

### メインプロセスの分離機能

コンテナ化された環境では、プロジェクトとそのプロセスを分離することがセキュリティとリソース管理にとって重要です。以下は主要な概念の簡略化された説明です:

#### **ネームスペース**
- **目的**: プロセス、ネットワーク、およびファイルシステムなどのリソースの分離を確保します。特にDockerでは、ネームスペースはコンテナのプロセスをホストや他のコンテナから分離します。
- **`unshare`の使用**: `unshare`コマンド（またはその基礎となるシスコール）を使用して新しいネームスペースを作成し、追加の分離レイヤーを提供します。ただし、Kubernetesはこれを元々ブロックしませんが、Dockerはします。
- **制限**: 新しいネームスペースを作成することで、プロセスがホストのデフォルトのネームスペースに戻ることはできません。ホストのネームスペースに侵入するには、通常、ホストの`/proc`ディレクトリへのアクセスが必要で、`nsenter`を使用して入力します。

#### **コントロールグループ（CGroups）**
- **機能**: プロセス間でリソースを割り当てるために主に使用されます。
- **セキュリティの側面**: CGroups自体は、`release_agent`機能を除いて、分離セキュリティを提供しません。この機能が誤構成されている場合、不正アクセスに悪用される可能性があります。

#### **機能の削除**
- **重要性**: プロセスの分離のための重要なセキュリティ機能です。
- **機能**: 特定の機能をドロップすることにより、ルートプロセスが実行できるアクションを制限します。プロセスがルート権限で実行されていても、必要な機能がないと特権アクションを実行できなくなり、シスコールは不十分な権限のために失敗します。

これは、プロセスが他の機能をドロップした後の**残りの機能**です:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Dockerではデフォルトで有効になっています。これにより、プロセスが呼び出すことができる**システムコールをさらに制限**するのに役立ちます。\
**デフォルトのDocker Seccompプロファイル**は[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)で見つけることができます。

**AppArmor**

Dockerには、アクティブ化できるテンプレートがあります: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

これにより、機能の制限、システムコール、ファイルやフォルダへのアクセスが可能になります...

</details>

### 名前空間

**名前空間**はLinuxカーネルの機能で、1つの**プロセス**セットが1つの**リソース**セットを**見る**一方、別の**プロセス**セットが**異なる**リソースセットを**見る**ようにカーネルリソースを**分割**する機能です。この機能は、一連のリソースとプロセスに同じ名前空間を持たせることで機能し、ただし、それらの名前空間は異なるリソースを参照します。リソースは複数のスペースに存在する可能性があります。

Dockerは、コンテナの分離を実現するために以下のLinuxカーネル名前空間を利用しています:

* pid名前空間
* マウント名前空間
* ネットワーク名前空間
* ipc名前空間
* UTS名前空間

**名前空間に関する詳細情報**については、以下のページを参照してください:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

Linuxカーネル機能である**cgroups**は、プロセスのセット間で**cpu、メモリ、io、ネットワーク帯域幅などのリソースを制限**する機能を提供します。 Dockerは、cgroup機能を使用してリソース制御を可能にするコンテナを作成することができます。\
以下は、ユーザースペースメモリが500mに制限され、カーネルメモリが50mに制限され、CPU共有が512に、blkioweightが400に設定されたコンテナの例です。 CPU共有は、コンテナのCPU使用率を制御する比率です。デフォルト値は1024で、0から1024までの範囲があります。 CPUリソースの競合が発生した場合、CPU共有が1024の3つのコンテナがある場合、各コンテナはCPUの33%まで取得できます。 blkio-weightは、コンテナのIOを制御する比率です。デフォルト値は500で、10から1000までの範囲があります。
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
コンテナのcgroupを取得するには、次のようにします:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
以下の情報を確認してください：

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Capabilities

Capabilitiesはrootユーザーに許可される機能をより細かく制御することができます。DockerはLinuxカーネルの機能を使用して、ユーザーの種類に関係なく、コンテナ内で行われる操作を制限します。

Dockerコンテナが実行されると、プロセスは隔離から脱出するために使用できる機密情報を削除します。これにより、プロセスが機密なアクションを実行して脱出することができないようにします：

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Docker内のSeccomp

これはDockerがコンテナ内で使用できるシステムコールを制限するセキュリティ機能です：

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### Docker内のAppArmor

AppArmorは、コンテナを限られたリソースセットに制限するためのカーネルの拡張機能です。プログラムごとのプロファイルを使用してコンテナを制限します：

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### Docker内のSELinux

- **ラベリングシステム**：SELinuxは、すべてのプロセスとファイルシステムオブジェクトに一意のラベルを割り当てます。
- **ポリシーの強制**：プロセスラベルがシステム内の他のラベルに対して実行できるアクションを定義するセキュリティポリシーを強制します。
- **コンテナプロセスラベル**：コンテナエンジンがコンテナプロセスを開始すると、通常は`container_t`という制限されたSELinuxラベルが割り当てられます。
- **コンテナ内のファイルラベリング**：コンテナ内のファイルは通常、`container_file_t`としてラベル付けされます。
- **ポリシールール**：SELinuxポリシーは、主に`container_t`ラベルを持つプロセスが`container_file_t`とラベル付けされたファイルとのみ相互作用（読み取り、書き込み、実行）できることを確認します。

このメカニズムにより、コンテナ内のプロセスが侵害された場合でも、対応するラベルを持つオブジェクトとのみ相互作用するように制限され、そのような侵害からの潜在的な被害が大幅に制限されます。

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ＆AuthN

Dockerでは、認可プラグインが重要な役割を果たし、Dockerデーモンへのリクエストを許可するかブロックするかを決定します。この決定は、次の2つのキーとなるコンテキストを調査することで行われます：

- **認証コンテキスト**：これには、ユーザーに関する包括的な情報が含まれます。誰であるか、どのように認証されたかなど。
- **コマンドコンテキスト**：これには、行われているリクエストに関連するすべての関連データが含まれます。

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

低権限ユーザーとしてアクセスを取得した攻撃者がコンテナを実行している場合、**誤って構成されたsuidバイナリ**があると、攻撃者はそれを悪用してコンテナ内で**特権を昇格**させる可能性があります。これにより、脱出することができるかもしれません。

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
さらなる**`--security-opt`**オプションについては、[https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)を参照してください。

## その他のセキュリティ考慮事項

### シークレットの管理：ベストプラクティス

Dockerイメージにシークレットを直接埋め込んだり、環境変数を使用したりすることは避けることが重要です。これらの方法は、`docker inspect`や`exec`などのコマンドを介してコンテナにアクセス権を持つ人に機密情報を公開してしまいます。

**Dockerボリューム**は、機密情報にアクセスするために推奨されるより安全な代替手段です。これらは一時的なメモリ内のファイルシステムとして利用でき、`docker inspect`やログ記録に関連するリスクを軽減します。ただし、ルートユーザーやコンテナへの`exec`アクセス権を持つユーザーは依然としてシークレットにアクセスできる可能性があります。

**Dockerシークレット**は、機密情報を取り扱うためのさらに安全な方法を提供します。イメージのビルドフェーズ中にシークレットが必要な場合、**BuildKit**はビルド時間シークレットをサポートする効率的なソリューションを提供し、ビルド速度を向上させ、追加の機能を提供します。

BuildKitを活用するためには、次の3つの方法でアクティブ化できます：

1. 環境変数を介して：`export DOCKER_BUILDKIT=1`
2. コマンドにプレフィックスを付けて：`DOCKER_BUILDKIT=1 docker build .`
3. Docker構成でデフォルトで有効にする：`{ "features": { "buildkit": true } }`と記述し、その後にDockerを再起動します。

BuildKitを使用すると、`--secret`オプションを使用してビルド時間シークレットを利用でき、これらのシークレットがイメージビルドキャッシュや最終イメージに含まれないようにします。
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
この設定では、Docker Composeを使用してサービスを起動する際にシークレットを使用できるようになります。

Kubernetes環境では、シークレットはネイティブでサポートされており、[Helm-Secrets](https://github.com/futuresimple/helm-secrets)などのツールでさらに管理できます。KubernetesのRole Based Access Controls（RBAC）は、Docker Enterpriseと同様にシークレット管理のセキュリティを向上させます。

### gVisor

**gVisor**は、Goで書かれたアプリケーションカーネルであり、Linuxシステムサーフェスの大部分を実装しています。これには、アプリケーションとホストカーネルの間の**隔離境界**を提供する[Open Container Initiative（OCI）](https://www.opencontainers.org)ランタイムである`runsc`が含まれています。`runsc`ランタイムはDockerとKubernetesと統合されており、サンドボックス化されたコンテナを簡単に実行できます。

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers**は、コンテナと同様に感じ、パフォーマンスが高い軽量な仮想マシンを使用して、**ハードウェア仮想化技術を使用してより強力なワークロード分離**を提供するセキュアなコンテナランタイムを構築するために取り組むオープンソースコミュニティです。

{% embed url="https://katacontainers.io/" %}

### 要約のヒント

* **`--privileged`フラグを使用しない**か、[**コンテナ内にDockerソケットをマウントしないでください**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)。 Dockerソケットを使用すると、コンテナを生成できるため、たとえば`--privileged`フラグを使用して別のコンテナを実行することでホストを完全に制御できます。
* コンテナ内で**rootとして実行しないでください。**[**異なるユーザー**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) **と**[**ユーザーネームスペース**](https://docs.docker.com/engine/security/userns-remap/) **を使用してください。** コンテナ内のrootは、ユーザーネームスペースでリマップされていない限り、ホストと同じです。主にLinuxのネームスペース、機能、およびcgroupsによってわずかに制限されています。
* [**すべての機能を削除**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`)し、必要な機能のみを有効にしてください**（`--cap-add=...`）。多くのワークロードには機能が必要ない場合があり、それらを追加すると攻撃の範囲が広がります。
* プロセスがsuidバイナリを介して特権を取得するのを防ぐために、**“no-new-privileges”セキュリティオプションを使用してください**。
* コンテナに利用可能なリソースを**制限してください**。リソース制限は、マシンをサービス拒否攻撃から保護できます。
* **[seccomp](https://docs.docker.com/engine/security/seccomp/)**、**[AppArmor](https://docs.docker.com/engine/security/apparmor/)** **（またはSELinux）**プロファイルを調整して、コンテナで利用可能なアクションとシスコールを最小限に制限してください。
* **[公式のDockerイメージ](https://docs.docker.com/docker-hub/official_images/)**を使用し、署名を要求するか、それらを基に独自のイメージを構築してください。[バックドアが仕込まれた](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/)イメージを継承したり使用しないでください。また、ルートキー、パスフレーズは安全な場所に保存してください。DockerはUCPでキーを管理する計画を立てています。
* **定期的に**イメージを**再構築**して、ホストとイメージにセキュリティパッチを適用してください。
* **シークレットを賢く管理**して、攻撃者がアクセスしにくくしてください。
* Dockerデーモンを公開する場合は、HTTPSを使用してクライアントとサーバーの認証を行ってください。
* Dockerfileでは、**ADDの代わりにCOPYを使用**してください。ADDは自動的にzipファイルを解凍し、URLからファイルをコピーできます。COPYにはこれらの機能がありません。可能な限りADDを使用せず、リモートURLやZipファイルを介した攻撃に対して脆弱にならないようにしてください。
* 各マイクロサービスに**別々のコンテナを使用**してください。
* コンテナ**イメージを小さくしてください**

## Docker Breakout / 特権昇格

もし**Dockerコンテナ内にいる**か、**dockerグループのユーザーにアクセス権がある**場合、**脱出して特権を昇格**することができます：

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Docker認証プラグインのバイパス

Dockerソケットにアクセス権があるか、**dockerグループのユーザーにアクセス権があるが、Docker認証プラグインによって制限されている**場合、**バイパスできるかどうかを確認してください**：

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Dockerのハードニング

* ツール[**docker-bench-security**](https://github.com/docker/docker-bench-security)は、本番環境でDockerコンテナを展開する際の数十の一般的なベストプラクティスをチェックするスクリプトです。これらのテストはすべて自動化されており、[CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/)に基づいています。\
このツールを実行するには、Dockerを実行しているホストからまたは十分な権限を持つコンテナから実行する必要があります。READMEでの実行方法については、[**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security)を参照してください。

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
* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
* [https://docs.docker.com/engine/extend/plugins_authorization](https://docs.docker.com/engine/extend/plugins_authorization)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
* [https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/](https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/)

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**してください。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで会社を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのスウォッグ**](https://peass.creator-spring.com)を手に入れましょう
* 独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションである[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks)のGitHubリポジトリにPRを提出して、自分のハッキングトリックを共有してください。

</details>
