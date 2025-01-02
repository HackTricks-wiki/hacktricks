# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Apple Proprietary File System (APFS)

**Apple File System (APFS)** é um sistema de arquivos moderno projetado para substituir o Hierarchical File System Plus (HFS+). Seu desenvolvimento foi impulsionado pela necessidade de **melhor desempenho, segurança e eficiência**.

Alguns recursos notáveis do APFS incluem:

1. **Compartilhamento de Espaço**: O APFS permite que vários volumes **compartilhem o mesmo armazenamento livre subjacente** em um único dispositivo físico. Isso possibilita uma utilização de espaço mais eficiente, pois os volumes podem crescer e encolher dinamicamente sem a necessidade de redimensionamento manual ou reparticionamento.
1. Isso significa, em comparação com partições tradicionais em discos de arquivos, **que no APFS diferentes partições (volumes) compartilham todo o espaço do disco**, enquanto uma partição regular geralmente tinha um tamanho fixo.
2. **Snapshots**: O APFS suporta **a criação de snapshots**, que são instâncias do sistema de arquivos **somente leitura** e em um determinado momento. Snapshots permitem backups eficientes e reverter facilmente o sistema, pois consomem armazenamento adicional mínimo e podem ser criados ou revertidos rapidamente.
3. **Clones**: O APFS pode **criar clones de arquivos ou diretórios que compartilham o mesmo armazenamento** que o original até que o clone ou o arquivo original seja modificado. Esse recurso fornece uma maneira eficiente de criar cópias de arquivos ou diretórios sem duplicar o espaço de armazenamento.
4. **Criptografia**: O APFS **suporta nativamente a criptografia de disco completo**, bem como criptografia por arquivo e por diretório, melhorando a segurança dos dados em diferentes casos de uso.
5. **Proteção contra Falhas**: O APFS utiliza um **esquema de metadados de cópia ao escrever que garante a consistência do sistema de arquivos** mesmo em casos de perda repentina de energia ou falhas do sistema, reduzindo o risco de corrupção de dados.

No geral, o APFS oferece um sistema de arquivos mais moderno, flexível e eficiente para dispositivos Apple, com foco em melhor desempenho, confiabilidade e segurança.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

O volume `Data` está montado em **`/System/Volumes/Data`** (você pode verificar isso com `diskutil apfs list`).

A lista de firmlinks pode ser encontrada no arquivo **`/usr/share/firmlinks`**.
```bash

```
{{#include ../../banners/hacktricks-training.md}}
