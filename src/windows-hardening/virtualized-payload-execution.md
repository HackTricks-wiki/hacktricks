# Execução de Payload Virtualizado e Evasão com VM Personalizada

{{#include ../banners/hacktricks-training.md}}

A virtualização de payload compila a lógica ofensiva para um conjunto de instruções guest e a executa com um interpretador nativo. Diferentemente de um packer, que eventualmente precisa expor as instruções nativas originais na memória, um payload virtualizado pode manter a lógica protegida como bytecode durante todo o seu ciclo de vida. Isso elimina essa janela específica de unpacking, mas **não** oculta comportamentos visíveis no host, como syscalls, atividade de rede ou a fronteira entre VM e chamadas nativas.<sup>[[2]](#references)[[3]](#references)</sup>

## Re-hospedagem em WebAssembly para evasão de análise estática

Em vez de editar uma ferramenta Go com muitas assinaturas, ela pode ser compilada como um guest `wasip1` e incorporada em um loader nativo separado. O guest é compilado com base em um GOROOT corrigido, no qual operações sem suporte, como `net.Dial`, `net.Listen`, `os/exec` e `os.Pipe`, são delegadas por meio de `//go:wasmimport`; um módulo host Wazero implementa sockets, operações de processos, chamadas Win32 e chamadas a frameworks do macOS. Isso preserva o uso da API Go do projeto original enquanto transfere a maior parte da lógica para um módulo WASM criptografado que ferramentas estáticas para PE talvez não compreendam.<sup>[[4]](#references)</sup>

### Conectando a memória linear às APIs nativas

Um ponteiro guest é um offset de 32 bits na memória linear WASM, não um endereço virtual do host. Antes de uma chamada nativa, a bridge pode traduzir um argumento somente quando ele está marcado como ponteiro local e está no intervalo `0x10000 <= value < wasmMemorySize`, produzindo `wasmMemoryBase + value`. O limite inferior evita reescrever handles pequenos, flags e `nil`; máscaras por API geradas a partir de `win32metadata` distinguem ponteiros reais de handles, tamanhos e endereços de processos remotos, com substituições para metadados imprecisos ou ambíguos.<sup>[[4]](#references)</sup>

As APIs nativas também podem retornar ponteiros do host por meio de buffers de saída do guest. Uma tabela espelho pode atribuir representações na memória do guest a esses objetos e manter um mapeamento reverso para o endereço original do host. COM exige espelhar tanto a interface quanto sua vtable: ponteiros de dados podem ser seguidos e espelhados, enquanto ponteiros executáveis em regiões `MEM_IMAGE` precisam permanecer como tokens opacos, pois WASM não pode executar instruções nativas. Esse modelo não oferece suporte direto a APIs de callback do host para o guest, como `EnumWindows` ou `SetWindowsHookEx`.<sup>[[4]](#references)</sup>

### Polimorfismo da VM WASM por build

O runtime e o payload podem ser transformados juntos em cada build: embaralhar a tabela de opcode para handler, reescrever cada opcode guest de acordo com o novo mapeamento, randomizar identificadores de seção, substituir o magic padrão `\0asm` por um marcador específico do build e alterar o magic do cache do runtime. O mesmo código-fonte produz, assim, módulos diferentes byte a byte, e ferramentas WASM comuns não conseguem analisar o payload até que o analista recupere o mapeamento personalizado e o framing a partir do loader host.<sup>[[4]](#references)</sup>

Para engenharia reversa, comece pelo host nativo em vez de procurar apenas por `\0asm`: identifique o marcador compilado, o caminho de descriptografia do módulo, a tabela de despacho de opcode e os registros de funções host `env`; em seguida, reconstrua um módulo padrão ou instrumente a fronteira de importação. A bridge continua sendo um ponto de controle comportamental útil, pois chamadas de rede, criação de processos, acesso ao registry, carregamento dinâmico e despacho Win32 genérico passam por ela, mesmo quando o bytecode incorporado muda entre builds.<sup>[[4]](#references)</sup>

### Camuflagem do executável Go externo

Alterar apenas o guest ainda deixa um loader reconhecível. As transformações demonstradas inserem perfis densos de símbolos, coletados de projetos Go legítimos, em `gopclntab`, alternam um pequeno conjunto plausível de imports de DLL e variam `VERSIONINFO` do PE e as strings de identidade do Authenticode. Essas transformações visam recursos estáticos e de machine learning do contêiner; elas não removem o comportamento do runtime exposto pelos shims do host.<sup>[[4]](#references)</sup>

## Modelo de execução

Um loader virtualizado compacto pode dividir a execução nas seguintes camadas.<sup>[[3]](#references)</sup>

1. Compilar C freestanding, código BOF ou bibliotecas de runtime por meio do LLVM para uma ISA de bytecode personalizada.
2. Iniciar um pequeno interpretador nativo e inicializar um mapeamento de opcode específico do build.
3. Executar o próprio PE linker-loader como bytecode: analisar cabeçalhos, mapear seções, aplicar relocations, resolver imports e preencher a IAT.
4. Manter chamadas guest-to-guest dentro do interpretador. Encaminhar alvos fora da região de bytecode, como funções de DLL importadas, por meio de um thunk nativo de host-call.
5. Colocar recursos de suporte, como framing HTTP, TLS e partes do runtime C, atrás da mesma fronteira de interpretação.

Esse modelo evita alocar uma região de código nativo separada para cada plugin e impede que o payload original apareça como um fluxo reconhecível de instruções x86-64. Ainda é uma fronteira de evasão/ofuscação, não uma fronteira de segurança: o interpretador nativo e todo efeito externo continuam observáveis.<sup>[[2]](#references)[[3]](#references)</sup>

## Bridge de memória compartilhada do host

Uma VM isolada representa ponteiros como offsets em um buffer guest, portanto cada chamada a uma API host exige tradução de ponteiros e tratamento especial para parâmetros de saída. Uma VM de memória compartilhada, por outro lado, torna os endereços guest válidos como endereços do processo host. Assim, leituras e gravações podem usar operações no estilo `memcpy`, e um ponteiro retornado por uma ECALL de alocação nativa pode ser dereferenciado diretamente pelo bytecode. A RISC-Y Business demonstrou que esse design pode reduzir a bridge à obtenção do PEB e à emissão de chamadas host arbitrárias.<sup>[[1]](#references)</sup>

No Windows x64, o arquivo de registradores virtuais pode espelhar a ABI: colocar os quatro primeiros argumentos inteiros ou ponteiros em `RCX`, `RDX`, `R8` e `R9`, com os argumentos seguintes e o shadow space na stack. Quando uma `CALL` virtual resolve para fora do intervalo de bytecode, um thunk universal organiza esse estado em uma chamada nativa e copia o valor de retorno de volta para a VM. Isso permite chamadas à IAT, alocação de heap e operações de socket sem ajustes de ponteiros.<sup>[[2]](#references)[[3]](#references)</sup>

A contrapartida é a perda completa de isolamento. A corrupção da memória guest pode afetar diretamente o host, funções nativas podem reter ou modificar ponteiros guest, e o interpretador precisa tratar o bytecode como totalmente confiável. Callbacks de nativo para VM também precisam de uma bridge reversa; uma VM que só oferece suporte a chamadas de saída não pode atender diretamente APIs baseadas em callbacks, como `EnumWindows`.<sup>[[1]](#references)[[3]](#references)</sup>

## Polimorfismo da ISA por build

Uma ISA personalizada de largura fixa simplifica a decodificação, o despacho, a relocação e o mapeamento de registradores virtuais. O Centurion usa um formato de instrução de 18 bytes, inspirado em x86-64, que troca densidade de código por análise previsível e também oferece um possível caminho para traduzir artefatos x86-64 existentes para bytecode.<sup>[[3]](#references)</sup>

Randomizar o mapeamento de opcode para handler em cada build faz com que uma lógica guest idêntica produza sequências de bytes diferentes. Criptografar a tabela de mapeamento e recuperá-la somente em runtime remove ainda mais um dicionário de opcode estável em disco. Isso dificulta assinaturas fixas e regras de disassembly reutilizáveis, mas não torna automaticamente polimórficos o dispatcher nativo, a rotina de descriptografia da tabela ou a fronteira de host-call.<sup>[[3]](#references)</sup>

## Trazendo o ambiente de execução para dentro da VM

O processo host pode ser reduzido a primitivas de memória, syscall e socket, enquanto bibliotecas freestanding fornecem serviços de nível mais alto dentro da VM. Por exemplo, o FreeRTOS coreHTTP pode implementar framing HTTP e o mbedTLS pode implementar TLS sem chamar o WinHTTP ou uma API TLS do sistema operacional. Sockets raw por meio de `afd.sys` ou de uma interface semelhante tornam-se, então, a estreita fronteira nativa de rede.<sup>[[3]](#references)</sup>

Esse design **Bring Your Own Execution Environment (BYOEE)** também pode colocar o carregamento de PE, o suporte de runtime e um sistema de arquivos em memória atrás do interpretador. Ele reduz implementações nativas reconhecíveis em vez de eliminar a telemetria: operações de socket raw continuam visíveis, e ambientes que exigem proxies explícitos ou interceptação TLS podem impedir que o design de rede funcione.<sup>[[3]](#references)</sup>

## Aceleração nativa seletiva

Interpretar cada instrução é especialmente caro em criptografia de chave pública. Uma divisão prática usa os hooks `MBEDTLS_ALT` do mbedTLS como interface para um coprocessador de software: mantém o estado TLS, a análise de certificados, a negociação, a alocação e o código bignum de alto nível em bytecode, mas despacha os kernels aritméticos mais intensivos de `bignum_core.c` por ECALLs nativas. No protótipo Centurion, `bignum.c`, `bignum_mod.c` e `bignum_mod_raw.c` permaneceram virtualizados enquanto os loops internos eram executados nativamente, reduzindo um handshake ECDHE de minutos para segundos.<sup>[[3]](#references)</sup>

Torne os aceleradores opcionais para que payloads que não precisam de TLS omitam os pontos de entrada nativos adicionais. Esse padrão se aplica a qualquer carga de trabalho de interpretador: primeiro faça profiling, depois exponha a menor primitiva nativa possível em vez de mover um subsistema inteiro para fora da VM.<sup>[[3]](#references)</sup>

O Centurion validou a cadeia completa com um bind shell TLS 1.2: o loader de bytecode mapeou o PE, as chamadas de socket passaram pelo thunk universal, o mbedTLS tratou o protocolo dentro da VM e ECALLs nativas aceleraram a aritmética ECDHE. Assim, o interpretador nativo de aproximadamente 18 KB ofereceu suporte a um canal de comando criptografado sem materializar o payload como código nativo x86-64.<sup>[[3]](#references)</sup>

## Pontos de referência para engenharia reversa e detecção

Os seguintes pontos são referências práticas de análise inferidas da arquitetura; a virtualização altera onde os analistas observam o comportamento, mas não elimina o comportamento em si.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Identifique o loop de fetch/decode/dispatch, o program counter virtual, o arquivo de registradores e os passos repetidos de instruções de largura fixa.
- Despeje a tabela de opcode após a descriptografia em runtime e mapeie os endereços dos handlers para operações semânticas, em vez de tentar corresponder o bytecode criptografado em disco.
- Interrompa a execução no thunk universal ou no dispatcher ECALL para registrar o alvo nativo, os registradores de argumentos virtuais, os argumentos na stack e o valor de retorno.
- Rastreie o acesso ao PEB, a resolução de exports, a análise de cabeçalhos PE, as gravações de relocations e o preenchimento da IAT, mesmo quando a implementação do loader for bytecode.
- Correlacione a criação de sockets e o tráfego `afd.sys` com a ausência das chamadas esperadas a WinHTTP ou a TLS nativo; a falta de imports de alto nível é uma pista, não uma prova de comportamento benigno.
- Trate aceleradores aritméticos nativos como pontos de controle semânticos: seus chamadores podem revelar atividade de troca de chaves e validação de certificados enquanto a máquina de estados TLS ao redor permanece virtualizada.

Para fluxos de análise que começam pelo dispatcher, em vez do grafo de fluxo de controle original, consulte a [orientação sobre análise de malware para virtualizar packers](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Restrições operacionais

A virtualização impõe overhead de interpretação, aumenta a complexidade da toolchain e da ABI e não resolve a detecção comportamental. A memória compartilhada é insegura por definição, a rede por socket raw pode falhar atrás de proxies obrigatórios e APIs Win32 com muitos callbacks exigem trampolines de nativo para VM. O interpretador, a bridge de syscall e quaisquer aceleradores nativos também continuam sendo uma footprint nativa convencional que os defensores podem assinar ou instrumentar.<sup>[[2]](#references)[[3]](#references)</sup>

## Páginas relacionadas

Para analisar o packing do VMProtect 3.x, consulte [unpacking emulado e reparo de imports](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#vmprotect-3x-emulated-unpacking-and-import-repair).

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
- [4] [Praetorian - Entre no WasmForge: compilando Sliver para WebAssembly](https://praetorian.com/blog/wasmforge-sliver-webassembly)
{{#include ../banners/hacktricks-training.md}}
