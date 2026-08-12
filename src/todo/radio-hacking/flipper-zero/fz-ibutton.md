# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Introdução

Para obter informações básicas sobre a tecnologia iButton, consulte:

{{#ref}}
../ibutton.md
{{#endref}}

## Design

Na imagem a seguir, a área **azul** mostra como posicionar um iButton físico contra os contatos do Flipper Zero para leitura. A área **verde** mostra quais contatos devem tocar um leitor durante a emulação.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Ações

### Ler

No modo de leitura, o Flipper Zero aguarda uma chave tocar seus contatos, detecta o protocolo e exibe o protocolo acima do ID da chave. O aplicativo integrado oferece suporte às chaves de controle de acesso Dallas, Cyfral e Metakom.<sup>[[2]](#references)</sup>

### Adicionar manualmente

Você pode inserir manualmente os dados da chave para os protocolos Dallas, Cyfral e Metakom.<sup>[[2]](#references)</sup>

### Emular

Você pode emular uma chave salva, independentemente de ela ter sido lida de uma chave física ou inserida manualmente.<sup>[[2]](#references)</sup>

> [!TIP]
> Se os contatos integrados não alcançarem o leitor, conecte os contatos de dados e de aterramento por meio dos pinos GPIO.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Controlando chaves iButton com o Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Documentação do Flipper Zero - Leitura de chaves iButton](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}
