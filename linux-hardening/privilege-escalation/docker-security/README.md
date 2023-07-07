# Dockerセキュリティ

![](<../../../.gitbook/assets/image (9) (1) (2).png>)

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も先進的なコミュニティツールによって強化された**ワークフローを簡単に構築**し、自動化します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、HackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**する[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## **基本的なDockerエンジンのセキュリティ**

Dockerエンジンは、コンテナの実行と管理を担当しています。Dockerエンジンは、**Namespaces**と**Cgroups**などのLinuxカーネルの機能を使用して、コンテナ間の基本的な**分離**を提供します。さらに、**Capabilities dropping**、**Seccomp**、**SELinux/AppArmor**などの機能を使用して、より良い分離を実現しています。

最後に、**認証プラグイン**を使用して、ユーザーが実行できるアクションを**制限**することができます。

![](<../../../.gitbook/assets/image (625) (1) (1).png>)

### **Dockerエンジンの安全なアクセス**

Dockerクライアントは、Unixソケットを使用してDockerエンジンに**ローカルでアクセス**するか、httpメカニズムを使用して**リモートでアクセス**することができます。リモートで使用する場合は、httpsと**TLS**を使用して機密性、整合性、認証を確保する必要があります。

デフォルトでは、Unixソケット`unix:///var/`\
`run/docker.sock`でリッスンし、Ubuntuディストリビューションでは、Dockerの起動オプションは`/etc/default/docker`に指定されています。Docker APIとクライアントがリモートでDockerエンジンにアクセスできるようにするには、Dockerデーモンをhttpソケットで**公開する必要があります**。これは次のように行うことができます：
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H
tcp://192.168.56.101:2376" -> add this to /etc/default/docker
Sudo service docker restart -> Restart Docker daemon
```
Dockerデーモンをhttpで公開することは良い慣行ではなく、httpsを使用して接続を保護する必要があります。2つのオプションがあります：最初のオプションは**クライアントがサーバーの正体を確認する**ことであり、2番目のオプションは**クライアントとサーバーがお互いの正体を確認する**ことです。証明書はサーバーの正体を確立します。両方のオプションの例については、[**このページを参照してください**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)。

### **コンテナイメージのセキュリティ**

コンテナイメージは、プライベートリポジトリまたはパブリックリポジトリに保存されます。Dockerがコンテナイメージの保存に提供するオプションは次のとおりです：

* [Docker Hub](https://hub.docker.com) - Dockerが提供するパブリックレジストリサービスです。
* [Docker Registry](https://github.com/%20docker/distribution) - ユーザーが独自のレジストリをホストするために使用できるオープンソースプロジェクトです。
* [Docker Trusted Registry](https://www.docker.com/docker-trusted-registry) - Dockerの商用実装であり、ロールベースのユーザー認証とLDAPディレクトリサービスの統合を提供します。

### イメージスキャン

コンテナには、ベースイメージまたはベースイメージの上にインストールされたソフトウェアのいずれかの理由で**セキュリティの脆弱性**が存在する場合があります。Dockerは、コンテナのセキュリティスキャンと脆弱性の一覧を行うプロジェクトである**Nautilus**に取り組んでいます。Nautilusは、各コンテナイメージレイヤーを脆弱性リポジトリと比較してセキュリティホールを特定することで機能します。

詳細については、[**こちらを読んでください**](https://docs.docker.com/engine/scan/)。

#### イメージのスキャン方法 <a href="#how-to-scan-images" id="how-to-scan-images"></a>

`docker scan`コマンドを使用して、イメージ名またはIDを指定して既存のDockerイメージをスキャンすることができます。たとえば、次のコマンドを実行してhello-worldイメージをスキャンします：
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
### Dockerイメージの署名

Dockerコンテナイメージは、公開またはプライベートレジストリに保存することができます。イメージが改ざんされていないことを確認するために、コンテナイメージには署名が必要です。コンテンツの発行者は、コンテナイメージの署名とレジストリへのプッシュを管理します。

以下は、Dockerコンテンツトラストに関する詳細です：

- Dockerコンテンツトラストは、[Notaryオープンソースプロジェクト](https://github.com/docker/notary)の実装です。Notaryオープンソースプロジェクトは、[The Update Framework (TUF)プロジェクト](https://theupdateframework.github.io)に基づいています。
- Dockerコンテンツトラストは、`export DOCKER_CONTENT_TRUST=1`で有効になります。Dockerバージョン1.10以降、コンテンツトラストはデフォルトで有効になっていません。
- コンテンツトラストが有効になっている場合、署名されたイメージのみをプルすることができます。イメージをプッシュする際には、タグキーを入力する必要があります。
- 発行者が初めてdocker pushを使用してイメージをプッシュする場合、ルートキーとタグキーのパスフレーズを入力する必要があります。他のキーは自動的に生成されます。
- Dockerは、Yubikeyを使用したハードウェアキーのサポートも追加しており、詳細は[こちら](https://blog.docker.com/2015/11/docker-content-trust-yubikey/)で確認できます。

以下は、コンテンツトラストが有効になっており、イメージが署名されていない場合に表示されるエラーメッセージです。
```shell-session
$ docker pull smakam/mybusybox
Using default tag: latest
No trust data for latest
```
以下の出力は、署名が有効な状態でDocker Hubにコンテナのイメージがプッシュされていることを示しています。これが初めてではないため、ユーザーはリポジトリキーのパスフレーズのみを入力するように求められます。
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
rootキー、リポジトリキー、およびパスフレーズを安全な場所に保存する必要があります。次のコマンドを使用して、秘密鍵のバックアップを取ることができます：

```bash
cp /root/.ssh/id_rsa /path/to/backup/folder/root_key
cp /root/.ssh/id_rsa.pub /path/to/backup/folder/repository_key
echo "passphrase" > /path/to/backup/folder/passphrase
```
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Dockerホストを変更した際、新しいホストから操作するためにルートキーとリポジトリキーを移動する必要がありました。

![](<../../../.gitbook/assets/image (9) (1) (2).png>)

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**し、自動化することができます。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## コンテナのセキュリティ機能

<details>

<summary>コンテナのセキュリティ機能の概要</summary>

#### ネームスペース

ネームスペースは、プロセス間の通信、ネットワーク、マウントなどを分離するために役立ちます。Dockerプロセスを他のプロセス（さらには/procフォルダ）から分離するために使用され、他のプロセスを悪用して脱出することを防ぎます。

バイナリの**`unshare`**（**`unshare`**シスコールを使用）を使用して、新しいネームスペースを作成することが可能です。Dockerはデフォルトでこれを防止しますが、kubernetesは（この記述時点では）防止しません。\
とはいえ、これは新しいネームスペースを作成するのに役立ちますが、ホストのデフォルトのネームスペースに戻ることはできません（ホストのネームスペース内のいくつかの`/proc`にアクセスできる場合は、**`nsenter`**を使用してホストのネームスペースに入ることができます）。

#### CGroups

これにより、リソースを制限することができ、プロセスの分離のセキュリティには影響しません（ただし、脱出に使用できる`release_agent`には影響を与える可能性があります）。

#### Capabilitiesの削除

プロセスの分離セキュリティに関して、これは**最も重要な**機能の1つだと考えています。これは、プロセスがrootとして実行されていても、必要な権限を持っていないため、特権のあるアクションを実行できないことがあります（呼び出された**`syscall`**が権限エラーを返すため）。

これは、プロセスが他の権限を削除した後の**残りのcapabilities**です：

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

#### Seccomp

デフォルトでDockerには有効になっています。これにより、プロセスが呼び出すことができるシステムコールをさらに制限することができます。\
デフォルトのDocker Seccompプロファイルは、[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)で見つけることができます。

#### AppArmor

Dockerには、アクティベートできるテンプレートがあります：[https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

これにより、機能の制限、システムコール、ファイルやフォルダへのアクセスが制限されます...

</details>

### Namespaces

**Namespaces（名前空間）**は、Linuxカーネルの機能であり、**カーネルリソースを分割**し、一連の**プロセス**が一連の**リソース**を見る一方、別の一連の**プロセス**が異なる一連のリソースを見るようにします。この機能は、一連のリソースとプロセスに同じ名前空間を持たせることで機能し、ただし、これらの名前空間は異なるリソースを参照します。リソースは複数のスペースに存在する場合があります。

Dockerは、コンテナの分離を実現するために、次のLinuxカーネルの名前空間を利用しています：

* pid名前空間
* mount名前空間
* network名前空間
* ipc名前空間
* UTS名前空間

**名前空間に関する詳細情報**については、次のページを参照してください：

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

Linuxカーネルの機能である**cgroups（コントロールグループ）**は、一連のプロセスに対してCPU、メモリ、IO、ネットワーク帯域幅などのリソースを制限する機能を提供します。 Dockerでは、cgroup機能を使用してリソース制御が可能なコンテナを作成することができます。\
以下は、ユーザースペースのメモリを500mに制限し、カーネルメモリを50mに制限し、CPUシェアを512に設定し、blkioweightを400に設定したコンテナの例です。 CPUシェアは、コンテナのCPU使用率を制御する比率です。デフォルト値は1024で、0から1024の範囲です。 CPUリソースの競合が発生した場合、3つのコンテナが同じCPUシェア1024を持っている場合、各コンテナは最大33%のCPUを使用できます。 blkio-weightは、コンテナのIOを制御する比率です。デフォルト値は500で、10から1000の範囲です。
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
コンテナのcgroupを取得するには、次のようにします：
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
詳細については、次を参照してください：

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Capabilities

Capabilitiesは、rootユーザーに許可される機能をより細かく制御することができます。DockerはLinuxカーネルの機能を使用して、ユーザーの種類に関係なく、コンテナ内で実行できる操作を制限します。

Dockerコンテナが実行されると、プロセスは分離から脱出するために使用できる機密の機能を削除します。これにより、プロセスが機密のアクションを実行して脱出することができないようになります。

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### DockerのSeccomp

これは、Dockerがコンテナ内で使用できるシスコールを制限するセキュリティ機能です。

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### DockerのAppArmor

AppArmorは、カーネルの拡張機能であり、コンテナを制限されたリソースのセットに制約するためのプログラムごとのプロファイルを提供します。

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### DockerのSELinux

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux)は、ラベリングシステムです。すべてのプロセスとすべてのファイルシステムオブジェクトにはラベルがあります。SELinuxポリシーは、システム上の他のすべてのラベルとプロセスラベルが許可される操作についてのルールを定義します。

コンテナエンジンは、通常`container_t`という単一の制約されたSELinuxラベルでコンテナプロセスを起動し、コンテナ内のコンテナを`container_file_t`というラベルで設定します。SELinuxポリシールールは基本的に、`container_t`プロセスが`container_file_t`とラベル付けされたファイルの読み取り/書き込み/実行のみを行えるということを意味します。

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ＆AuthN

認証プラグインは、現在の認証コンテキストとコマンドコンテキストの両方に基づいて、Dockerデーモンへのリクエストを承認または拒否します。認証コンテキストには、すべてのユーザーの詳細と認証方法が含まれます。コマンドコンテキストには、すべての関連するリクエストデータが含まれます。

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## おもしろいDockerフラグ

### --privilegedフラグ

次のページでは、`--privileged`フラグが何を意味するかを学ぶことができます。

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

低特権ユーザーとしてアクセスを取得した攻撃者が実行されているコンテナがある場合、ミス構成されたsuidバイナリを持っている場合、攻撃者はそれを悪用してコンテナ内で特権をエスカレートさせる可能性があります。これにより、攻撃者はコンテナから脱出することができるかもしれません。

`no-new-privileges`オプションを有効にしてコンテナを実行すると、この種の特権エスカレーションを防ぐことができます。
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### その他

In addition to the security measures mentioned above, there are a few other considerations to keep in mind when it comes to Docker security.

##### 1. Limit Container Capabilities

By default, Docker containers have the same capabilities as the host system. This means that if a container is compromised, an attacker could potentially gain full control over the host. To mitigate this risk, it is recommended to limit the capabilities of containers by using the `--cap-drop` and `--cap-add` flags when running containers. This allows you to selectively drop or add specific capabilities to containers based on their requirements.

##### 2. Use AppArmor or SELinux Profiles

AppArmor and SELinux are security frameworks that can be used to enforce mandatory access control policies on Docker containers. By creating and applying AppArmor or SELinux profiles to containers, you can restrict their access to system resources and prevent them from performing unauthorized actions.

##### 3. Monitor Container Activity

Monitoring the activity of Docker containers can help you detect any suspicious or malicious behavior. Tools like Docker logs, Docker events, and container runtime security solutions can provide valuable insights into container activity and help you identify any potential security issues.

##### 4. Regularly Update Docker Images and Containers

Keeping your Docker images and containers up to date is crucial for maintaining their security. Regularly check for updates and security patches for the base images and software packages used in your containers, and ensure that you promptly apply them to minimize the risk of known vulnerabilities being exploited.

##### 5. Implement Network Segmentation

To further enhance Docker security, consider implementing network segmentation. By isolating containers into separate network segments, you can limit the potential impact of a compromised container and prevent lateral movement within your Docker environment.

##### 6. Harden the Host System

In addition to securing Docker containers, it is important to also harden the host system. Apply security best practices such as regularly updating the host operating system, using strong authentication mechanisms, and implementing firewall rules to restrict access to Docker-related ports.

By following these additional security measures, you can further strengthen the security of your Docker environment and reduce the risk of unauthorized access or malicious activities.
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
詳細な**`--security-opt`**オプションについては、[https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)を参照してください。

![](<../../../.gitbook/assets/image (9) (1) (2).png>)

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## その他のセキュリティに関する考慮事項

### シークレットの管理

まず第一に、**イメージ内にそれらを配置しないでください！**

また、**環境変数を使用しないでください**。`docker inspect`または`exec`を実行できる人は、秘密情報を見つけることができます。

Dockerボリュームの方が良いです。Dockerドキュメントでは、Dockerボリュームを使用して秘密情報にアクセスすることが推奨されています。**メモリ内に保持される一時ファイルシステムとしてボリュームを使用**できます。ボリュームは`docker inspect`とログのリスクを除去します。ただし、**rootユーザーとコンテナに`exec`できる人は、秘密情報を見ることができます**。

ボリュームよりも優れた方法として、Dockerシークレットを使用してください。

**イメージ内でシークレットが必要な場合**は、**BuildKit**を使用できます。BuildKitはビルド時間を大幅に短縮し、ビルド時のシークレットサポートを含む他の便利な機能も備えています。

BuildKitのバックエンドを指定する方法は3つあります。:

1. 環境変数として`export DOCKER_BUILDKIT=1`を設定します。
2. `build`または`run`コマンドを`DOCKER_BUILDKIT=1`で開始します。
3. ビルドキットをデフォルトで有効にします。`/_etc/docker/daemon.json_`の設定を`true`に設定します：`{ "features": { "buildkit": true } }`。その後、Dockerを再起動します。
4. その後、次のように`--secret`フラグを使用してビルド時にシークレットを使用できます：
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
あなたのファイルでは、秘密情報をキーと値のペアとして指定します。

これらの秘密情報は、イメージのビルドキャッシュと最終イメージから除外されます。

**実行中のコンテナで秘密情報を使用する**必要がある場合は、**Docker ComposeまたはKubernetes**を使用してください。

Docker Composeを使用する場合は、サービスに秘密情報のキーと値のペアを追加し、秘密ファイルを指定します。以下の例は、[Stack Exchangeの回答](https://serverfault.com/a/936262/535325)からのDocker Composeの秘密情報のヒントを元にしています。

秘密情報を含む例のdocker-compose.ymlファイル:
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
次に、通常通り`docker-compose up --build my_service`でComposeを起動します。

[Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/)を使用している場合、シークレットのサポートがあります。[Helm-Secrets](https://github.com/futuresimple/helm-secrets)は、Kubernetesでのシークレット管理を容易にするのに役立ちます。さらに、KubernetesとDocker Enterpriseの両方には、ロールベースのアクセス制御（RBAC）があります。RBACにより、チームにとってシークレット管理がより管理しやすく、より安全になります。

### gVisor

**gVisor**は、Goで書かれたアプリケーションカーネルで、Linuxシステムの大部分を実装しています。これには、アプリケーションとホストカーネルの間の**隔離境界**を提供する[Open Container Initiative（OCI）](https://www.opencontainers.org)ランタイムである`runsc`が含まれています。`runsc`ランタイムはDockerとKubernetesと統合されており、サンドボックス化されたコンテナを簡単に実行できます。

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers**は、軽量な仮想マシンを使用してコンテナのように感じ、パフォーマンスを提供しながら、**ハードウェア仮想化技術を使用してより強力なワークロードの分離**を提供するために取り組んでいるオープンソースのコミュニティです。

{% embed url="https://katacontainers.io/" %}

### 要約とヒント

* **`--privileged`フラグを使用せず、コンテナ内にDockerソケットをマウントしないでください**。Dockerソケットはコンテナの生成を可能にするため、`--privileged`フラグを使用して別のコンテナを実行するなど、ホストの完全な制御を簡単に取得する方法です。
* コンテナ内で**rootとして実行しないでください。異なるユーザー**[**とユーザーネームスペース**](https://docs.docker.com/engine/security/userns-remap/)を使用してください**。**コンテナ内のrootは、ホストと同じです（ユーザーネームスペースでリマップされていない限り）。主にLinuxのネームスペース、機能、およびcgroupsによって軽く制限されています。
* [**すべての機能をドロップ**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities)**（`--cap-drop=all`）し、必要な機能のみを有効にしてください**（`--cap-add=...`）。多くのワークロードでは、機能は必要ありません。それらを追加すると、潜在的な攻撃の範囲が広がります。
* [**「no-new-privileges」セキュリティオプションを使用**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/)して、プロセスが特権を取得するのを防止してください。たとえば、suidバイナリを介して特権を取得することがあります。
* [**コンテナに利用可能なリソースを制限**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**してください**。リソース制限は、サービス拒否攻撃からマシンを保護することができます。
* **[seccomp](https://docs.docker.com/engine/security/seccomp/)**、**[AppArmor](https://docs.docker.com/engine/security/apparmor/)**（またはSELinux）プロファイルを調整して、コンテナで使用可能なアクションとシスコールを最小限に制限してください。
* [**公式のDockerイメージ**](https://docs.docker.com/docker-hub/official\_images/)を使用し、署名を要求するか、それらを基に独自のイメージをビルドしてください。バックドアが仕込まれたイメージを継承または使用しないでください。また、ルートキーとパスフレーズを安全な場所に保存してください。DockerはUCPでキーを管理する予定です。
* 定期的にイメージを再ビルドして、ホストとイメージにセキュリティパッチを適用してください。
* シークレットを適切に管理し、攻撃者がアクセスしにくいようにしてください。
* Dockerデーモンを公開する場合は、クライアントとサーバーの認証にHTTPSを使用してください。
* Dockerfileでは、ADDの代わりにCOPYを使用してください。ADDは自動的にzipファイルを展開し、URLからファイルをコピーすることができます。COPYにはこれらの機能がありません。可能な限り、リモートURLやZipファイルを介した攻撃に対して脆弱にならないように、ADDの使用を避けてください。
* 各マイクロサービスには**個別のコンテナ**を使用してください。
* コンテナ内にsshを配置しないでください。コンテナへのsshは「docker exec」を使用して行うことができます。
* **より小さな**コンテナ**イメージ**を使用してください。

## Dockerの脱獄/特権エスカレーション

もし**Dockerコンテナ内にいる**か、**dockerグループのユーザーにアクセス権がある**場合、**脱獄して特権をエスカレーション**することができます。

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Docker認証プラグインのバイパス

もしdockerソケットにアクセス権限があるか、**dockerグループのユーザーにアクセス権限があるが、docker認証プラグインによって制限されている場合**、それを**バイパス**できるかどうかを確認してください。

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Dockerのハードニング

* ツール[**docker-bench-security**](https://github.com/docker/docker-bench-security)は、Dockerコンテナを本番環境で展開する際の数十の一般的なベストプラクティスをチェックするスクリプトです。テストはすべて自動化されており、[CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/)に基づいています。\
ツールを実行するには、Dockerを実行しているホストからまたは十分な権限を持つコンテナから実行する必要があります。実行方法については、READMEを参照してください：[**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security)。

## 参考文献

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman
<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

![](<../../../.gitbook/assets/image (9) (1) (2).png>)

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
