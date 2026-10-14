# Automação do WinDbg para instrumentação direcionada

{{#include ../../banners/hacktricks-training.md}}

WinDbg e WinDbgX podem executar comandos do depurador na inicialização, em exceções e quando os breakpoints são acionados. Isso permite que uma sessão de fuzzing ou reversing colete o estado apenas em torno de um caminho acionado pela entrada, em vez de parar manualmente em cada evento.<sup>[[1]](#references)</sup>

## Começar por uma exceção útil

`-c` executa comandos na pausa inicial do depurador. Acrescente `;g` para continuar após a configuração. Para uma execução autônoma do WinDbg Classic, `-logo` grava a janela de comandos em um log, `-Q` desativa o salvamento automático do workspace e `-G` ignora o breakpoint final para que a sessão termine quando o alvo sair. O WinDbgX também aceita `-c`; os comandos de inicialização configurados são executados em seguida.<sup>[[1]](#references)[[7]](#references)</sup>

```text
windbg.exe -c "sxd av;g" -logo C:\logs\triage.txt C:\path\target.exe
```

Para violações de acesso, **`sxe av` interrompe na primeira chance**, **`sxd av` ignora a primeira chance, mas interrompe na segunda chance se a exceção não for tratada**, e **`sxi av` ignora ambas as chances**. As descrições de `sxi`/`sxd` no artigo estão invertidas: a Microsoft documenta `sxd` como o filtro de segunda chance e `sxi` como ignorar. Use `-c` para um comando na primeira chance e `-c2` para um comando na segunda chance; um manipulador `-c` de primeira chance não se torna um manipulador de segunda chance apenas porque o filtro é `sxd`. Confirme os filtros ativos com `sx`.<sup>[[1]](#references)[[2]](#references)</sup>

```text
sxd -c2 "r;kv;!analyze -v" av
sxe -c "lm" ld
```

O primeiro comando coleta registradores, um stack trace e a análise da exceção apenas para uma violação de acesso não tratada. O segundo executa `lm` quando um módulo é carregado. Os eventos de breakpoint (`bp`), carregamento de módulo (`ld`) e violação de acesso (`av`) têm ciclos de vida diferentes; portanto, não ignore globalmente `bp` se depender de breakpoints do debugger.<sup>[[1]](#references)[[2]](#references)</sup>

## Condicione breakpoints dispendiosos a um acionador controlado

Escolha uma função visível para scripts ou controlada por entrada que possa ser chamada imediatamente antes do caminho de interesse. Instale **breakpoints de ação** nas chamadas do alocador, do parser ou da API que deseja inspecionar. Desative-os por ID com `bd`. Instale um **breakpoint de acionamento** com um comando associado que habilite esses IDs com `be` e, em seguida, retome a execução com `g`; um segundo acionador controlado pode desativá-los novamente. Verifique os IDs com `bl` antes de configurar o acionador, pois eles dependem da ordem de criação dos breakpoints. Isso separa pontos de controle baratos do rastreamento dispendioso e limita as alterações no timing e no layout do heap do alvo.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Depois de resolver os dois símbolos, use o padrão de comando abaixo. Substitua os símbolos entre colchetes e o ID do breakpoint de ação retornado por `bl`; não presuma que seja zero.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```text
bp <action-symbol> "r;g"
bl
bd <action-id>
bp <trigger-symbol> "be <action-id>;g"
```

Os comandos de breakpoint de ação podem imprimir `@$ip` e `%y` (endereço simbolizado), fazer dump dos argumentos selecionados ou da memória e, em seguida, continuar. Se um breakpoint condicional registra apenas pointers em um intervalo selecionado, verifique primeiro se o intervalo realmente abrange a entrada de teste; uma condição incorreta descarta evidências silenciosamente.<sup>[[1]](#references)</sup>

### Encontrar um gatilho com símbolos

Pesquise em todos os módulos carregados se o módulo que contém a implementação for desconhecido. `bm` define breakpoints em todos os símbolos correspondentes; invoque a função visível pelo script e verifique qual breakpoint é acionado. Por exemplo, o código-fonte executa `Math.cos(0)` no renderer que está sendo depurado, não em qualquer processo do navegador.<sup>[[1]](#references)[[5]](#references)</sup>

```text
x *!*math*cos*
bm *edge*!*math*cos* ".printf \"%y called\n\", @$ip;g"
g
```

Quando um hit identificar a função exata, use `lm a <symbol>` para localizar a imagem que a contém e `? <symbol> - <module>` para calcular um offset relativo ao módulo. O WinDbg pode exibir o mesmo nome curto de módulo para um executável e uma DLL; portanto, verifique o caminho da imagem antes de usar o offset em outro processo. Restrinja os breakpoints com curingas ao símbolo verificado para evitar sobrecarga.<sup>[[1]](#references)</sup>

### Encontrar um candidato sem símbolos

O `corelan_trigscan.py`, baseado em Frida e desenvolvido pela Corelan, verifica um módulo de processo selecionado em busca de padrões de instruções de ponto flutuante, SSE, AVX e trigonométricas. Ele gera comandos de breakpoint do WinDbg em `corelan_trigscan.bps` e arquivos `.bps` numerados menores. Execute-o com Python e `frida-tools` no processo de destino **sem outro depurador conectado**; depois, conecte o WinDbg ao mesmo processo/módulo e carregue um lote gerenciável de breakpoints.<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.5 --min-relevant 50 --min-total 20 --min-trig 1
$$><C:\logs\msedge.dll\corelan_trigscan_0001.bps
```

Para um deslocamento relativo ao módulo conhecido, valide se ele supera os limiares antes de importar todos os breakpoints emitidos:<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.15 --min-relevant 8 --min-total 45 --check-offset 00e13dc0 --min-icall 1
```

`--min-density` é a densidade de instruções relevantes, `--min-relevant` e `--min-total` definem limites mínimos de contagem de instruções, e `--min-trig` exige sinais fortes semelhantes a trig. Se uma função conhecida não for encontrada, passe seu offset **relativo ao módulo** para `--check-offset` para inspecionar seu prólogo, densidade, contagens e chamadas indiretas. Um wrapper fino pode ter baixa densidade e nenhuma instrução trig. Reduza os limites e, se estiver procurando wrappers, use a opção real `--min-icall 1` do script (não `--min-ical`); os callees diretos são analisados, mas não é possível acompanhar os destinos indiretos com confiabilidade. Lotes menores de `--splitsize` ajudam quando muitos breakpoints gerados deixam o WinDbg lento. Um candidato não é validado até que a entrada pretendida faça seu breakpoint disparar.<sup>[[1]](#references)[[6]](#references)</sup>

## Pequenos programas de debugger e PyKD

Use `.if` quando uma condição for confiável, `.foreach` para iterar sobre saídas delimitadas por espaços em branco e `.for` com pseudo-registradores para percorrer memória ou estruturas. `.foreach` **não** preserva colunas: por exemplo, a saída de largura variável de `lm` é uma entrada inadequada, enquanto `lm 1m` produz um nome de módulo por token. Primeiro registre os dados sem filtragem se uma condição presumida puder ocultar o caminho que falha.<sup>[[1]](#references)</sup>

```text
.foreach (mod { lm 1m }) { .echo ${mod} }
r $t0 = 0
.for ( ; @$t0 < 5 ; r $t0 = @$t0 + 1 ) { .printf "i = %d\n", @$t0 }
```

Aliases criados com `as name value` são substituições textuais, não variáveis tipadas. `al` lista os aliases, `ad name` exclui um, e `${name}` força uma expansão inequívoca. Evite nomes como `bp`, `x` ou `r`, pois um alias pode ocultar um comando integrado. As expressões MASM são adequadas para aritmética de ponteiros, como `poi(@$t0)`; `@@c++(...)` pode acessar campos tipados quando há símbolos, evitando offsets de estrutura codificados diretamente.<sup>[[1]](#references)</sup>

Coloque sequências de comandos mais longas em um arquivo de comandos. `$$><filename` combina linhas em um único bloco de comandos e permite um comando do depurador separado por ponto e vírgula em seguida. Estruturas de controle com várias linhas ainda podem ser frágeis; mantenha cada instrução `.if` ou `.for` em uma única linha. O mesmo arquivo pode ser chamado por `-c` na inicialização.<sup>[[1]](#references)[[8]](#references)</sup>

Para lógicas difíceis de expressar na linguagem de comandos, o PyKD expõe estruturas tipadas, registradores, memória e saída do depurador ao Python. Por exemplo, `pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())` acessa campos da PEB, `pykd.loadBytes(address, size)` lê a memória, e `pykd.dbgCommand("lm")` retorna a saída do depurador para análise. Prefira `loadChars`/`loadWChars` com limites a leituras de strings sem limite, quando os dados possivelmente não tiverem terminação. `disasm(address).asm(instruction)` do PyKD **grava bytes montados nesse endereço**, portanto preserve e restaure a memória original se usar esse método para obter opcodes em um processo em execução.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Corelan: Depuração - Automação e scripting do WinDBG(X) - Parte 1](https://corelan.be/index.php/2026/04/17/debugging-windbgx-automation-scripting-part-1)
- [2] [Microsoft: sx, sxd, sxe, sxi, sxn, sxr, sx- (Definir exceções)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [3] [Microsoft: be (Habilitar ponto de interrupção)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/be--breakpoint-enable-)
- [4] [Microsoft: bd (Desabilitar ponto de interrupção)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bd--breakpoint-disable-)
- [5] [Microsoft: bp, bu, bm (Definir ponto de interrupção)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-)
- [6] [Código-fonte do trigscan do Corelan](https://github.com/corelan/blogposts/blob/main/debugging/scripts/frida/corelan_trigscan.py)
- [7] [Microsoft: Opções de linha de comando do WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options)
- [8] [Microsoft: Executar arquivo de script](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-----------------------a---run-script-file-)
