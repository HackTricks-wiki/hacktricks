# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Sistema de arquivos proprietário da Apple (APFS)

O **Apple File System (APFS)** é um sistema de arquivos moderno desenvolvido para substituir o Hierarchical File System Plus (HFS+). Seu desenvolvimento foi impulsionado pela necessidade de **melhor desempenho, segurança e eficiência**.

Alguns recursos importantes do APFS incluem:<sup>[[1]](#references)</sup>

1. **Compartilhamento de espaço**: o APFS permite que vários volumes **compartilhem o mesmo armazenamento livre subjacente** em um único dispositivo físico. Isso possibilita uma utilização mais eficiente do espaço, pois os volumes podem aumentar e diminuir dinamicamente sem a necessidade de redimensionamento ou reparticionamento manual.
1. Isso significa que, em comparação com partições tradicionais em discos, **no APFS partições diferentes (volumes) compartilham todo o espaço do disco**, enquanto uma partição comum geralmente tinha um tamanho fixo.
2. **Snapshots**: o APFS permite **criar snapshots**, que são instâncias do sistema de arquivos **somente leitura** em um determinado momento. Os snapshots permitem backups eficientes e reversões fáceis do sistema, pois consomem pouco armazenamento adicional e podem ser criados ou revertidos rapidamente.
3. **Clones**: o APFS pode **criar clones de arquivos ou diretórios que compartilham o mesmo armazenamento** que o original até que o clone ou o arquivo original seja modificado. Esse recurso oferece uma maneira eficiente de criar cópias de arquivos ou diretórios sem duplicar o espaço de armazenamento.
4. **Criptografia**: o APFS **oferece suporte nativo à criptografia de disco inteiro**, bem como à criptografia por arquivo e por diretório, aumentando a segurança dos dados em diferentes casos de uso.
5. **Proteção contra falhas**: o APFS usa um **esquema de metadados copy-on-write que garante a consistência do sistema de arquivos** mesmo em casos de perda repentina de energia ou falhas do sistema, reduzindo o risco de corrupção de dados.

De modo geral, o APFS oferece um sistema de arquivos mais moderno, flexível e eficiente para dispositivos Apple, com foco em melhor desempenho, confiabilidade e segurança.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

O volume `Data` é montado em **`/System/Volumes/Data`** (você pode verificar isso com `diskutil apfs list`).

A lista de firmlinks pode ser encontrada no arquivo **`/usr/share/firmlinks`**.
```bash

```
## Referências

- [1] [APFS Guide - Features - Apple Developer Documentation](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/Features/Features.html)

{{#include ../../banners/hacktricks-training.md}}
