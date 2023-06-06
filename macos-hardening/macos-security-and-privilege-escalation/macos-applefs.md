## Sistema de Arquivos Proprietário da Apple (APFS)

O APFS, ou Apple File System, é um sistema de arquivos moderno desenvolvido pela Apple Inc. que foi projetado para substituir o antigo Hierarchical File System Plus (HFS+) com ênfase em **melhorar o desempenho, segurança e eficiência**.

Algumas características notáveis do APFS incluem:

1. **Compartilhamento de Espaço**: O APFS permite que vários volumes **compartilhem o mesmo espaço livre subjacente** em um único dispositivo físico. Isso permite uma utilização de espaço mais eficiente, já que os volumes podem crescer e encolher dinamicamente sem a necessidade de redimensionamento ou reparticionamento manual.
   1. Isso significa que, em comparação com partições tradicionais em discos de arquivos, **no APFS diferentes partições (volumes) compartilham todo o espaço em disco**, enquanto uma partição regular geralmente tinha um tamanho fixo.
2. **Snapshots**: O APFS suporta **criação de snapshots**, que são instâncias **somente leitura** do sistema de arquivos em um determinado momento. Os snapshots permitem backups eficientes e fácil reversão do sistema, pois consomem armazenamento mínimo adicional e podem ser criados ou revertidos rapidamente.
3. **Clones**: O APFS pode **criar clones de arquivos ou diretórios que compartilham o mesmo armazenamento** que o original até que o clone ou o arquivo original seja modificado. Essa funcionalidade fornece uma maneira eficiente de criar cópias de arquivos ou diretórios sem duplicar o espaço de armazenamento.
4. **Criptografia**: O APFS **suporta nativamente criptografia de disco completo**, bem como criptografia de arquivo e diretório, aumentando a segurança dos dados em diferentes casos de uso.
5. **Proteção contra falhas**: O APFS usa um **esquema de metadados de cópia-em-gravação que garante a consistência do sistema de arquivos** mesmo em casos de perda de energia repentina ou falhas do sistema, reduzindo o risco de corrupção de dados.

Em geral, o APFS oferece um sistema de arquivos mais moderno, flexível e eficiente para dispositivos Apple, com foco em melhorar o desempenho, confiabilidade e segurança.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

O volume `Data` é montado em **`/System/Volumes/Data`** (você pode verificar isso com o comando `diskutil apfs list`).

A lista de firmlinks pode ser encontrada no arquivo **`/usr/share/firmlinks`**.
```bash
cat /usr/share/firmlinks
/AppleInternal	AppleInternal
/Applications	Applications
/Library	Library
[...]
```
À **esquerda**, está o caminho do diretório no **volume do sistema**, e à **direita**, o caminho do diretório onde ele é mapeado no **volume de dados**. Então, `/library` --> `/system/Volumes/data/library`.
