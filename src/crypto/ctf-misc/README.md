# Crypto CTF その他

{{#include ../../banners/hacktricks-training.md}}

このセクションでは、暗号 challenge に登場するものの、ほかのカテゴリにはうまく当てはまらない手法を紹介します。

## 難解プログラミング言語

### 手法

challenge で難解プログラミング言語のプログラムを実行し、その出力をデコードする必要がある場合は、次の手順を使います。

challenge で、標準的な言語には見えないコードが与えられた場合：

- 特徴的な token や命令の並びを検索して、言語を特定します。
- オンライン interpreter または Docker image を使います。
- 出力が奇妙な場合は、実行後にさらに encoding や compression が施されていないか確認します。

言語を調べるには、Esolang wiki が役立ちます。<sup>[[1]](#references)</sup> 一般的な encoding や compression の層には、[Crypto CTF workflow](../ctf-workflow/) を使ってください。手がかりが実行可能な構文ではなく、見えないテキストの場合は、[text steganography](../../stego/text/) を確認してください。

### 事前ロードされた interpreter state の exfiltration

challenge が難解プログラミング言語のソースを受け取り、**custom interpreter** で実行する場合、ソースをデコードパズルとして扱う前に、初期 memory、stack、出力命令を調べてください。interpreter が秘密情報を Befunge stack に事前ロードしている場合、短いプログラムで既存の byte を pop して出力できます。これは、実行されるソースと出力 opcode を制御できる場合に限られ、通常の空の interpreter では機能しません。ある Befunge challenge では、以下の入力によって stack に逆順で事前ロードされた flag の文字が繰り返し出力されました。<sup>[[2]](#references)[[3]](#references)</sup>

```befunge
>,<
```

`>` は右方向への実行を開始し、`,` はスタックから値を取り出して文字を出力し、`<` は命令ポインターを `,` に戻します。カスタムインタープリターのアンダーフローと命令数制限の挙動を確認してください。引用された実装は、スタックが空になるか、1,024 命令が実行されると停止します。秘密情報がスタックに直接ない場合は、標準的な Befunge の動作を前提とせず、ほかに初期化された状態や利用可能な出力／読み込み命令を調べてください。<sup>[[3]](#references)[[4]](#references)</sup>



## References

- [1] [Esolang、難解プログラミング言語のWiki](https://esolangs.org/wiki/Main_Page)
- [2] [WolvCTF 2024 Befuddled1 のオリジナル writeup](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/README.md)
- [3] [WolvCTF 2024 Befuddled1 のインタープリターソース](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/files/befunge.py)
- [4] [Befunge 言語リファレンス](https://esolangs.org/wiki/Befunge)
{{#include ../../banners/hacktricks-training.md}}
