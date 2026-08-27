# Injeção de Aplicações R no macOS

{{#include ../../../banners/hacktricks-training.md}}

## `R_PROFILE_USER` / `R_PROFILE`

Na inicialização, o R carrega arquivos de perfil do site e do usuário que contêm código R. `R_PROFILE` seleciona o perfil do site, e `R_PROFILE_USER` seleciona o perfil do usuário, permitindo que um ambiente herdado redirecione qualquer uma dessas buscas para um arquivo legível pelo atacante.<sup>[[1]](#references)</sup>
```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```
`--no-init-file` ignora o perfil do usuário, `--no-site-file` ignora o perfil do site, e `--vanilla` inclui ambas as proteções. O R primeiro processa os arquivos de ambiente selecionados por `R_ENVIRON` e `R_ENVIRON_USER`, mas esses arquivos apenas definem variáveis; as variáveis de perfil são a primitiva direta de execução arbitrária de código.

## `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` e caminhos de bibliotecas

O R anexa os pacotes separados por vírgulas em `R_DEFAULT_PACKAGES` durante a inicialização. O `Rscript` dá precedência a `R_SCRIPT_DEFAULT_PACKAGES`. Combinar qualquer uma dessas variáveis com `R_LIBS`, `R_LIBS_USER` ou `R_LIBS_SITE` pode fazer o R encontrar e carregar um pacote instalado controlado pelo atacante; o hook `.onLoad` ou `.onAttach` é executado automaticamente.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```
Isso requer um pacote R instalado e estruturalmente válido, não apenas um arquivo `.R` avulso. `--vanilla` não limpa variáveis herdadas diretamente, portanto um wrapper confiável também deve remover ou substituir as variáveis de pacote padrão e de caminho de bibliotecas, além de desabilitar os arquivos de perfil.

## References

- [1] [Inicialização no início de uma sessão R](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [2] [Instalação e administração do R: pacotes adicionais](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
{{#include ../../../banners/hacktricks-training.md}}
