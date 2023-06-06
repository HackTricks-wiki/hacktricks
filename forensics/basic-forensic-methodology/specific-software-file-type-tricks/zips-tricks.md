# Truques com arquivos ZIP

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Existem algumas ferramentas de linha de comando para arquivos zip que serão úteis de conhecer.

* `unzip` frequentemente fornece informações úteis sobre por que um arquivo zip não pode ser descompactado.
* `zipdetails -v` fornecerá informações detalhadas sobre os valores presentes nos vários campos do formato.
* `zipinfo` lista informações sobre o conteúdo do arquivo zip, sem extraí-lo.
* `zip -F input.zip --out output.zip` e `zip -FF input.zip --out output.zip` tentam reparar um arquivo zip corrompido.
* [fcrackzip](https://github.com/hyc/fcrackzip) faz uma tentativa de força bruta para adivinhar a senha de um arquivo zip (para senhas com menos de 7 caracteres, mais ou menos).

[Especificação do formato de arquivo zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

Uma nota importante relacionada à segurança sobre arquivos zip protegidos por senha é que eles não criptografam os nomes de arquivo e os tamanhos de arquivo originais dos arquivos compactados que contêm, ao contrário de arquivos RAR ou 7z protegidos por senha.

Outra nota sobre a quebra de senhas de arquivos zip é que, se você tiver uma cópia não criptografada/não compactada de qualquer um dos arquivos que estão compactados no zip criptografado, você pode realizar um "ataque de texto simples" e quebrar o zip, como [detalhado aqui](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files), e explicado neste [artigo](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). O novo esquema para proteger arquivos zip com senha (com AES-256, em vez de "ZipCrypto") não tem essa fraqueza.
