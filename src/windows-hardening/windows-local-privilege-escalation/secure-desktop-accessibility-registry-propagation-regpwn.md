# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Os recursos de Acessibilidade do Windows persistem a configuração do usuário em HKCU e a propagam para locais HKLM por sessão. Durante uma transição de **Secure Desktop** (tela de bloqueio ou prompt do UAC), componentes **SYSTEM** copiam novamente esses valores. Se a **chave HKLM por sessão** puder ser gravada pelo usuário, ela se torna um ponto privilegiado de escrita que pode ser redirecionado com **registry symbolic links**, resultando em uma **arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

A técnica RegPwn explora essa cadeia de propagação com uma pequena janela de race estabilizada por um **opportunistic lock (oplock)** em um arquivo usado pelo `osk.exe`.<sup>[[1]](#references)</sup>

## Cadeia de propagação do Registry (Accessibility -> Secure Desktop)

Exemplo de recurso: **On-Screen Keyboard** (`osk`). Os locais relevantes são:

- **Lista de recursos em todo o sistema**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Configuração por usuário (gravável pelo usuário)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Configuração HKLM por sessão (criada pelo `winlogon.exe`, gravável pelo usuário)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (contexto SYSTEM)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagação durante uma transição para Secure Desktop (simplificada):

1. O `atbroker.exe` do **usuário** copia `HKCU\...\ATConfig\osk` para `HKLM\...\Session<session id>\ATConfig\osk`.
2. O `atbroker.exe` do **SYSTEM** copia `HKLM\...\Session<session id>\ATConfig\osk` para `HKU\.DEFAULT\...\ATConfig\osk`.
3. O `osk.exe` do **SYSTEM** copia `HKU\.DEFAULT\...\ATConfig\osk` de volta para `HKLM\...\Session<session id>\ATConfig\osk`.

Se a subárvore HKLM da sessão puder ser gravada pelo usuário, as etapas 2/3 fornecem uma escrita do SYSTEM por meio de um local que o usuário pode substituir.<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

Substitua a chave por sessão gravável pelo usuário por um **registry symbolic link** que aponte para um destino escolhido pelo atacante. Quando a cópia do SYSTEM ocorrer, ela seguirá o link e gravará valores controlados pelo atacante na chave de destino arbitrária.

Ideia principal:

- Destino da escrita da vítima (gravável pelo usuário):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- O atacante substitui essa chave por um **registry link** para qualquer outra chave.
- O SYSTEM executa a cópia e grava na chave escolhida pelo atacante com permissões do SYSTEM.

Isso fornece uma primitive de **arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

## Vencendo a Race Window com Oplocks

Há uma pequena janela de timing entre o início do **SYSTEM `osk.exe`** e a escrita na chave por sessão. Para torná-la confiável, o exploit coloca um **oplock** em:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Quando o oplock é acionado, o atacante troca a chave HKLM por sessão por um registry link, permite que a gravação do SYSTEM ocorra e, em seguida, remove o link.<sup>[[1]](#references)</sup>

## Fluxo de Exploitation de Exemplo (Alto Nível)

1. Obter o **session ID** atual a partir do access token.
2. Iniciar uma instância oculta de `osk.exe` e aguardar brevemente (para garantir que o oplock seja acionado).
3. Gravar valores controlados pelo atacante em:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Definir um **oplock** em `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Acionar o **Secure Desktop** (`LockWorkstation()`), fazendo com que o SYSTEM inicie `atbroker.exe` / `osk.exe`.
6. Quando o oplock for acionado, substituir `HKLM\...\Session<session id>\ATConfig\osk` por um **registry link** para um target arbitrário.
7. Aguardar brevemente a conclusão da cópia pelo SYSTEM e, em seguida, remover o link.<sup>[[1]](#references)</sup>

## Convertendo o Primitive em Execução como SYSTEM

Uma chain direta consiste em sobrescrever um valor de **service configuration** (por exemplo, `ImagePath`) e, em seguida, iniciar o serviço. O RegPwn PoC sobrescreve o `ImagePath` de **`msiserver`** e o aciona instanciando o **MSI COM object**, resultando em execução de código como **SYSTEM**.<sup>[[1]](#references)[[2]](#references)</sup>

## Relacionado

Para outros comportamentos de Secure Desktop / UIAccess, consulte:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Referências

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
