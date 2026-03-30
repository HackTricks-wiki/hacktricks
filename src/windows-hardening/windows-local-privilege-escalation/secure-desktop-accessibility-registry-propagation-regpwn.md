# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Visão Geral

Os recursos de Acessibilidade do Windows persistem a configuração do usuário sob HKCU e a propagam para locais HKLM por sessão. Durante uma transição de **Secure Desktop** (tela de bloqueio ou prompt do UAC), componentes do **SYSTEM** recopi­am esses valores. Se a **chave HKLM por sessão for gravável pelo usuário**, ela se torna um ponto de estrangulamento de escrita privilegiada que pode ser redirecionado com **links simbólicos do registro**, resultando em uma **escrita arbitrária no registro com privilégios SYSTEM**.

A técnica RegPwn abusa dessa cadeia de propagação com uma pequena janela de corrida estabilizada via um **bloqueio oportunista (oplock)** em um arquivo usado por `osk.exe`.

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Exemplo de recurso: **On-Screen Keyboard** (`osk`). As localizações relevantes são:

- **System-wide feature list**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-user configuration (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (created by `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagação durante uma transição de Secure Desktop (simplificado):

1. **Usuário `atbroker.exe`** copia `HKCU\...\ATConfig\osk` para `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** copia `HKLM\...\Session<session id>\ATConfig\osk` para `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** copia `HKU\.DEFAULT\...\ATConfig\osk` de volta para `HKLM\...\Session<session id>\ATConfig\osk`.

Se a subárvore HKLM da sessão for gravável pelo usuário, os passos 2/3 fornecem uma escrita como SYSTEM através de um local que o usuário pode substituir.

## Primitiva: Escrita Arbitrária no Registro como SYSTEM via Links de Registro

Substitua a chave por sessão gravável pelo usuário por um **link simbólico do registro** que aponte para um destino escolhido pelo atacante. Quando a cópia feita por SYSTEM ocorrer, ela seguirá o link e gravará valores controlados pelo atacante na chave de destino arbitrária.

Ideia-chave:

- Alvo de escrita da vítima (gravável pelo usuário):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- O atacante substitui essa chave por um **link de registro** para qualquer outra chave.
- O SYSTEM realiza a cópia e grava na chave escolhida pelo atacante com permissões SYSTEM.

Isso gera uma primitiva de **escrita arbitrária no registro como SYSTEM**.

## Vencendo a Janela de Corrida com Oplocks

Há uma pequena janela de tempo entre o início do **SYSTEM `osk.exe`** e a gravação da chave por sessão. Para tornar confiável, o exploit coloca um **bloqueio oportunista (oplock)** em:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Quando o oplock é acionado, o atacante troca a chave HKLM por sessão por um registry link, permite que o SYSTEM escreva, e então remove o link.

## Example Exploitation Flow (High Level)

1. Obter o **session ID** atual do access token.
2. Iniciar uma instância oculta de `osk.exe` e pausar brevemente (garantir que o oplock será acionado).
3. Escrever valores controlados pelo atacante em:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Definir um **oplock** em `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Disparar o **Secure Desktop** (`LockWorkstation()`), fazendo com que o SYSTEM `atbroker.exe` / `osk.exe` seja iniciado.
6. Ao acionar o oplock, substituir `HKLM\...\Session<session id>\ATConfig\osk` por um **registry link** para um alvo arbitrário.
7. Aguardar brevemente até a cópia pelo SYSTEM ser concluída, então remover o link.

## Converting the Primitive to SYSTEM Execution

Uma cadeia direta é sobrescrever um valor de **service configuration** (por exemplo, `ImagePath`) e então iniciar o serviço. O RegPwn PoC sobrescreve o `ImagePath` do **`msiserver`** e o aciona instanciando o **MSI COM object**, resultando em execução de código como **SYSTEM**.

## Related

Para outros comportamentos do Secure Desktop / UIAccess, veja:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
