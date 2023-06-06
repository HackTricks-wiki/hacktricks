# DDexec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Contexto

No Linux, para executar um programa, ele deve existir como um arquivo e deve ser acessível de alguma forma através da hierarquia do sistema de arquivos (é assim que `execve()` funciona). Este arquivo pode residir no disco ou na memória (tmpfs, memfd), mas você precisa de um caminho de arquivo. Isso tornou muito fácil controlar o que é executado em um sistema Linux, torna fácil detectar ameaças e ferramentas de atacantes ou impedi-los de tentar executar qualquer coisa deles (_por exemplo_, não permitindo que usuários não privilegiados coloquem arquivos executáveis em qualquer lugar).

Mas esta técnica está aqui para mudar tudo isso. Se você não pode iniciar o processo que deseja... **então você sequestra um que já existe**.

Esta técnica permite que você **bypass técnicas de proteção comuns, como somente leitura, noexec, lista branca de nomes de arquivos, lista branca de hash...**

## Dependências

O script final depende das seguintes ferramentas para funcionar, elas precisam estar acessíveis no sistema que você está atacando (por padrão, você encontrará todas elas em todos os lugares):
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## A técnica

Se você é capaz de modificar arbitrariamente a memória de um processo, então você pode assumi-lo. Isso pode ser usado para sequestrar um processo já existente e substituí-lo por outro programa. Podemos alcançar isso usando a chamada do sistema `ptrace()` (que requer que você tenha a capacidade de executar chamadas do sistema ou ter o gdb disponível no sistema) ou, mais interessantemente, escrevendo em `/proc/$pid/mem`.

O arquivo `/proc/$pid/mem` é um mapeamento um-para-um de todo o espaço de endereço de um processo (por exemplo, de `0x0000000000000000` a `0x7ffffffffffff000` em x86-64). Isso significa que ler ou escrever neste arquivo em um deslocamento `x` é o mesmo que ler ou modificar o conteúdo no endereço virtual `x`.

Agora, temos quatro problemas básicos a enfrentar:

* Em geral, apenas o root e o proprietário do arquivo do programa podem modificá-lo.
* ASLR.
* Se tentarmos ler ou escrever em um endereço não mapeado no espaço de endereço do programa, receberemos um erro de E/S.

Esses problemas têm soluções que, embora não sejam perfeitas, são boas:

* A maioria dos interpretadores de shell permite a criação de descritores de arquivo que serão herdados pelos processos filhos. Podemos criar um fd apontando para o arquivo `mem` do shell com permissões de gravação... então os processos filhos que usam esse fd poderão modificar a memória do shell.
* O ASLR nem é um problema, podemos verificar o arquivo `maps` do shell ou qualquer outro do procfs para obter informações sobre o espaço de endereço do processo.
* Então precisamos usar `lseek()` no arquivo. A partir do shell, isso não pode ser feito a menos que usemos o infame `dd`.

### Em mais detalhes

Os passos são relativamente fáceis e não exigem nenhum tipo de especialização para entendê-los:

* Analise o binário que queremos executar e o carregador para descobrir quais mapeamentos eles precisam. Em seguida, crie um "shell"code que executará, em termos gerais, as mesmas etapas que o kernel faz em cada chamada para `execve()`:
  * Crie os mapeamentos mencionados.
  * Leia os binários neles.
  * Configure as permissões.
  * Finalmente, inicialize a pilha com os argumentos para o programa e coloque o vetor auxiliar (necessário pelo carregador).
  * Pule para o carregador e deixe-o fazer o resto (carregar bibliotecas necessárias para o programa).
* Obtenha do arquivo `syscall` o endereço para o qual o processo retornará após a chamada do sistema que está executando.
* Sobrescreva aquele lugar, que será executável, com nosso shellcode (através de `mem` podemos modificar páginas não graváveis).
* Passe o programa que queremos executar para o stdin do processo (será `lido()` pelo referido "shell"code).
* Neste ponto, cabe ao carregador carregar as bibliotecas necessárias para nosso programa e pular para ele.

**Confira a ferramenta em** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
