# Clonando um Website

Para uma avaliação de phishing, às vezes pode ser útil **clonar/baixar completamente um website**.

Observe que você também pode adicionar alguns payloads ao website clonado, como um BeEF hook para "controlar" a aba do usuário.

Existem diferentes ferramentas que você pode usar para esse propósito:

## wget

O comando a seguir usa os modos de espelhamento, requisitos da página, conversão de links e ajuste de extensões do Wget e, em seguida, disponibiliza os arquivos baixados a partir do diretório atual com o módulo `http.server` do Python na porta 8000.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

O repositório goclone descreve o utilitário como uma ferramenta que baixa um site para um diretório local, preservando sua estrutura de links relativos, e documenta a execução de `goclone <url>`.<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Kit de Engenharia Social

O repositório do Social-Engineer Toolkit (SET) identifica o SET como um framework open-source de penetration testing para avaliações autorizadas de engenharia social.<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [Manual do GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Documentação do Python `http.server`](https://docs.python.org/3/library/http.server.html)
- [3] [Repositório do goclone](https://github.com/imthaghost/goclone)
- [4] [Repositório do Social-Engineer Toolkit](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
