# Weaponizing Distroless

{{#include ../../../banners/hacktricks-training.md}}

## What is Distroless

Distrolessコンテナは、**特定のアプリケーションを実行するために必要な依存関係のみを含む**コンテナの一種であり、必要のない追加のソフトウェアやツールは含まれていません。これらのコンテナは、**軽量**かつ**安全**であることを目的としており、不要なコンポーネントを削除することで**攻撃面を最小限に抑える**ことを目指しています。

Distrolessコンテナは、**セキュリティと信頼性が最も重要な**プロダクション環境でよく使用されます。

**Distrolessコンテナのいくつかの例**は次のとおりです：

- **Google**が提供： [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
- **Chainguard**が提供： [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

Distrolessコンテナを武器化する目的は、**distrolessによって示される制限**（システム内の一般的なバイナリの欠如）や、**読み取り専用**や**実行禁止**などのコンテナに一般的に見られる保護にもかかわらず、**任意のバイナリやペイロードを実行できる**ようにすることです。

### Through memory

Coming at some point of 2023...

### Via Existing binaries

#### openssl

\***\*[**In this post,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) これらのコンテナには、**`openssl`**バイナリが頻繁に見られることが説明されています。これは、コンテナ内で実行されるソフトウェアによって**必要とされる**可能性があるためです。

{{#include ../../../banners/hacktricks-training.md}}
