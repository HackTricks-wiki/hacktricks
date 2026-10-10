# Arquivos Interessantes e Permissões

{{#include ../../banners/hacktricks-training.md}}

A propriedade dos arquivos, o acesso de gravação, as opções de montagem e os privilégios de execução podem alterar o alcance efetivo de um usuário local. Comece identificando o arquivo ou caminho de execução visado e, em seguida, consulte a página relevante:

- [SUID, SGID, ACLs e arquivos sensíveis](suid-sgid-and-acl-triage.md) apresenta um fluxo de trabalho inicial para privilégios de execução e permissões de acesso ocultas.
- [Gravação arbitrária em arquivos como root](write-to-root.md) descreve como gravações em caminhos privilegiados podem ser usadas para obter escalonamento.
- [Linux capabilities](linux-capabilities.md) explica capabilities por processo e por arquivo.
- [Abuso de bibliotecas compartilhadas e do linker com SUID](suid-shared-library-and-linker-abuse.md) aborda o carregamento dinâmico em binários privilegiados.
- [Exemplo de escalonamento de privilégios com `ld.so`](ld.so.conf-example.md) acompanha um caso envolvendo configuração do linker.
- [Configuração incorreta de NFS com `no_root_squash` e `no_all_squash`](nfs-no_root_squash-misconfiguration-pe.md) aborda o mapeamento de identidades em sistemas de arquivos remotos.
- [Wildcard spare tricks](wildcards-spare-tricks.md) aborda a expansão de argumentos em comandos privilegiados.
- [SELinux](selinux.md) explica a aplicação de políticas e as etapas relevantes de investigação.
{{#include ../../banners/hacktricks-training.md}}
