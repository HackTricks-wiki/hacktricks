# macOS ユーザー

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい場合は** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、当社の独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) コレクションを発見する
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegramグループ](https://t.me/peass) に参加するか、**Twitter** 🐦 で **@carlospolopm** をフォローする

* **HackTricks** と **HackTricks Cloud** のGitHubリポジトリに **PRを提出** して、あなたのハッキングテクニックを共有してください。

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) は、**ダークウェブ** を活用した検索エンジンで、企業やその顧客が **盗聴マルウェア** によって **侵害** されていないかをチェックする **無料** 機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃に対抗することです。

彼らのウェブサイトをチェックして、**無料** でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

***

### 一般ユーザー

*   **Daemon**: システムデーモン用に予約されたユーザー。デフォルトのデーモンアカウント名は通常 "\_" で始まります:

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```
* **Guest**: 非常に厳しい権限を持つゲスト用アカウント

{% code overflow="wrap" %}
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
{% endcode %}

* **Nobody**: 最小限の権限が必要なプロセスは、このユーザーで実行されます
* **Root**

### ユーザー権限

* **Standard User:** 最も基本的なユーザーです。このユーザーは、ソフトウェアのインストールやその他の高度なタスクを実行しようとする際には、管理者ユーザーから権限を付与される必要があります。自分自身ではそれを行うことはできません。
* **Admin User**: ほとんどの時間を標準ユーザーとして運用するユーザーですが、ソフトウェアのインストールやその他の管理タスクなど、rootアクションを実行することが許可されています。管理者グループに属するすべてのユーザーは、**sudoersファイルを介してrootへのアクセスが与えられます**。
* **Root**: Rootはほとんどのアクションを実行できるユーザーです（システムインテグリティ保護などによる制限があります）。
* たとえば、rootは`/System`内にファイルを配置することはできません。
