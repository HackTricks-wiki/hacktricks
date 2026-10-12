# Execução de Payload Virtualizado e Evasão por VM Personalizada

{{#include ../banners/hacktricks-training.md}}

A virtualização de payload compila a lógica ofensiva para um conjunto de instruções convidado e a executa com um interpretador nativo. Diferentemente de um packer, que precisa eventualmente expor as instruções nativas originais na memória, um payload virtualizado pode manter a lógica protegida como bytecode durante toda a sua execução. Isso elimina essa janela específica de descompactação, mas **não** oculta comportamentos visíveis ao host, como syscalls, atividade de rede ou o limite entre VM e chamadas nativas.<sup>[[2]](#references)[[3]](#references)</sup>

## Modelo de execução

Um loader virtualizado compacto pode dividir a execução nas seguintes camadas.<sup>[[3]](#references)</sup>

1. Compilar C freestanding, código-fonte BOF ou bibliotecas de runtime por meio do LLVM para uma ISA de bytecode personalizada.
2. Iniciar um pequeno interpretador nativo e inicializar um mapeamento de opcode específico da build.
3. Executar o próprio PE linker-loader como bytecode: analisar cabeçalhos, mapear seções, aplicar relocations, resolver imports e preencher a IAT.
4. Manter as chamadas entre código convidado dentro do interpretador. Encaminhar destinos fora da região de bytecode, como funções de DLL importadas, por meio de um host-call thunk nativo.
5. Colocar recursos auxiliares, como enquadramento HTTP, TLS e partes do runtime C, sob o mesmo limite de interpretação.

Esse modelo evita alocar uma região de código nativo separada para cada plugin e impede que o payload original apareça como um fluxo reconhecível de instruções x86-64. Ainda assim, é um limite de evasão/ofuscação, não um limite de segurança: o interpretador nativo e todo efeito externo continuam observáveis.<sup>[[2]](#references)[[3]](#references)</sup>

## Ponte de memória compartilhada com o host

Uma VM isolada representa ponteiros como deslocamentos em um buffer convidado, então cada chamada à API do host exige tradução de ponteiros e tratamento especial para parâmetros de saída. Já uma VM de memória compartilhada torna os endereços convidados válidos no processo do host. Assim, leituras e gravações podem usar operações no estilo `memcpy`, e um ponteiro retornado por um ECALL de alocação nativo pode ser desreferenciado diretamente pelo bytecode. A RISC-Y Business demonstrou que esse design pode reduzir a ponte à obtenção do PEB e à emissão de chamadas arbitrárias ao host.<sup>[[1]](#references)</sup>

No Windows x64, o arquivo de registradores virtuais pode espelhar a ABI: colocar os quatro primeiros argumentos inteiros ou ponteiros em `RCX`, `RDX`, `R8` e `R9`, com os argumentos subsequentes e o shadow space na pilha. Quando uma `CALL` virtual resolve para um endereço fora do intervalo de bytecode, um thunk universal organiza esse estado para uma chamada nativa e copia o valor de retorno de volta para a VM. Isso permite chamadas à IAT, alocação de heap e operações de socket sem ajustes de ponteiros.<sup>[[2]](#references)[[3]](#references)</sup>

A contrapartida é a perda total de isolamento. A corrupção da memória convidada pode afetar diretamente o host, funções nativas chamadas podem reter ou modificar ponteiros convidados, e o interpretador precisa tratar o bytecode como totalmente confiável. Callbacks de nativo para VM também exigem uma ponte reversa; uma VM que só oferece suporte a chamadas de saída não pode atender diretamente a APIs baseadas em callbacks, como `EnumWindows`.<sup>[[1]](#references)[[3]](#references)</sup>

## Polimorfismo de ISA por build

Uma ISA personalizada de largura fixa simplifica a decodificação, o despacho, as relocations e o mapeamento de registradores virtuais. O Centurion usa um formato de instrução de 18 bytes inspirado em x86-64, que troca densidade de código por análise previsível e também possibilita traduzir artefatos x86-64 existentes para bytecode.<sup>[[3]](#references)</sup>

Randomizar o mapeamento de opcode para handler em cada build faz com que a mesma lógica convidada produza sequências de bytes diferentes. Criptografar a tabela de mapeamento e recuperá-la somente em runtime elimina ainda mais um dicionário de opcode estável em disco. Isso dificulta assinaturas fixas e regras de desmontagem reutilizáveis, mas não torna automaticamente polimórficos o dispatcher nativo, a rotina de descriptografia da tabela ou o limite de chamadas ao host.<sup>[[3]](#references)</sup>

## Trazer o ambiente de execução para dentro da VM

O processo host pode ser reduzido a primitivas de memória, syscall e socket, enquanto bibliotecas freestanding fornecem serviços de nível mais alto dentro da VM. Por exemplo, o FreeRTOS coreHTTP pode implementar o enquadramento HTTP e o mbedTLS pode implementar TLS sem chamar WinHTTP ou uma API TLS do sistema operacional. Sockets raw por meio de `afd.sys` ou de uma interface semelhante tornam-se, então, o limite nativo estreito de rede.<sup>[[3]](#references)</sup>

Esse design **Bring Your Own Execution Environment (BYOEE)** também pode colocar o carregamento de PE, o suporte de runtime e um sistema de arquivos em memória sob o interpretador. Ele reduz implementações nativas reconhecíveis em vez de eliminar a telemetria: operações de socket raw continuam visíveis, e ambientes que exigem proxies explícitos ou interceptação TLS podem impedir que o design de rede funcione.<sup>[[3]](#references)</sup>

## Aceleração nativa seletiva

Interpretar cada instrução é especialmente caro em criptografia de chave pública. Uma divisão prática usa os hooks `MBEDTLS_ALT` do mbedTLS como interface de coprocessador de software: mantém o estado TLS, a análise de certificados, a negociação, a alocação e o código bignum de alto nível em bytecode, mas despacha os kernels aritméticos mais intensivos de `bignum_core.c` por meio de ECALLs nativos. No protótipo Centurion, `bignum.c`, `bignum_mod.c` e `bignum_mod_raw.c` permaneceram virtualizados enquanto os loops internos eram executados nativamente, reduzindo um handshake ECDHE de minutos para segundos.<sup>[[3]](#references)</sup>

Torne os aceleradores opcionais para que payloads que não precisam de TLS omitam os pontos de entrada nativos adicionais. Esse padrão se aplica a qualquer carga de trabalho de interpretador: primeiro faça o profiling, depois exponha a menor primitiva nativa possível, em vez de mover um subsistema inteiro para fora da VM.<sup>[[3]](#references)</sup>

O Centurion validou a cadeia completa com um bind shell TLS 1.2: o loader de bytecode mapeou o PE, as chamadas de socket passaram pelo thunk universal, o mbedTLS tratou o protocolo dentro da VM e ECALLs nativos aceleraram a aritmética ECDHE. Assim, o interpretador nativo, com aproximadamente 18 KB, ofereceu suporte a um canal de comando criptografado sem materializar o payload como código nativo x86-64.<sup>[[3]](#references)</sup>

## Pontos de análise para reversing e detecção

Os pontos a seguir são referências práticas de análise inferidas da arquitetura; a virtualização muda onde os analistas observam o comportamento, mas não o elimina.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Identifique o loop de fetch/decode/dispatch, o contador de programa virtual, o arquivo de registradores e o avanço repetido por instruções de largura fixa.
- Despeje a tabela de opcode após a descriptografia em runtime e associe os endereços dos handlers às operações semânticas, em vez de tentar corresponder o bytecode criptografado em disco.
- Coloque um breakpoint no thunk universal ou no dispatcher ECALL para registrar o destino nativo, os registradores de argumentos virtuais, os argumentos na pilha e o valor de retorno.
- Rastreie o acesso ao PEB, a resolução de exports, a análise de cabeçalhos PE, as gravações de relocations e o preenchimento da IAT, mesmo quando a implementação do loader for bytecode.
- Correlacione a criação de sockets e o tráfego `afd.sys` com a ausência das chamadas esperadas a WinHTTP ou a TLS nativo; a falta de imports de alto nível é uma pista, não uma prova de comportamento benigno.
- Trate os aceleradores aritméticos nativos como pontos críticos semânticos: seus chamadores podem revelar a troca de chaves e a validação de certificados enquanto a máquina de estados TLS ao redor permanece virtualizada.

Para fluxos de análise que começam pelo dispatcher, em vez de pelo grafo de fluxo de controle original, consulte a [orientação sobre malware analysis para virtualizing packers](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Restrições operacionais

A virtualização impõe sobrecarga de interpretação, aumenta a complexidade do toolchain e da ABI e não resolve a detecção comportamental. A memória compartilhada é insegura por definição, a rede por sockets raw pode falhar atrás de proxies obrigatórios e APIs Win32 com muitos callbacks exigem trampolines de nativo para VM. O interpretador, a ponte de syscall e quaisquer aceleradores nativos também continuam sendo uma presença nativa convencional que os defensores podem identificar por assinatura ou instrumentar.<sup>[[2]](#references)[[3]](#references)</sup>

## Páginas relacionadas

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Construindo uma máquina virtual RISC-V para ofuscação de payload](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red Teaming na era do EDR — evasão por meio da virtualização de malware](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — Traga seu próprio ambiente de execução](https://praetorian.com/blog/virtualized-loader-centurion/)
{{#include ../banners/hacktricks-training.md}}
