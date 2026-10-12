# Remoção do marcador de skb encaminhado pelo Open vSwitch para gravações na page cache do ESP

{{#include ../../../banners/hacktricks-training.md}}

Um padrão útil de exploração do kernel Linux consiste em **remover os metadados de propriedade de um skb sem remover seus fragmentos de terceiros** e, em seguida, encaminhar esse skb a um consumidor que grava in-place. No caso do Open vSwitch (OVS), uma falha no upcall para userspace limpa `SKBFL_SHARED_FRAG` de um skb `MSG_ZEROCOPY` ainda ativo; em seguida, o ESP descriptografa diretamente sobre o folio da page cache de um arquivo somente leitura. Isso permite uma gravação determinística na page cache local e foi rastreado como CVE-2026-90049, CVE-2026-89487 e CVE-2026-80977.<sup>[[1]](#references)[[2]](#references)</sup>

Este é um problema da classe Copy Fail/Dirty Frag, e não uma corrupção clássica de memória: não é necessária nenhuma race ou divulgação de endereço, basta que o arquivo possa ser lido, e os bytes alterados ficam na page cache, não no disco.<sup>[[2]](#references)[[3]](#references)</sup>

## Invariante de segurança: fragmentos de terceiros devem permanecer marcados

`SKBFL_SHARED_FRAG` informa aos consumidores que gravam in-place que um fragmento de skb pode apontar para um armazenamento que eles não possuem exclusivamente. O fast path do ESP em `esp_input()` só pode descriptografar in-place um skb não linear e não clonado quando `skb_has_shared_frag()` é falso; caso contrário, `skb_cow_data()` primeiro cria armazenamento privado. Essa verificação no consumidor foi adicionada após o Dirty Frag.<sup>[[5]](#references)</sup>

Portanto, o invariante tem duas partes independentes:<sup>[[2]](#references)[[4]](#references)[[5]](#references)</sup>

1. Os escritores in-place devem verificar `SKBFL_SHARED_FRAG` e copiar os dados compartilhados antes de modificá-los.
2. Todo caminho de clonagem, coalescência, transferência ou encaminhamento deve preservar o marcador enquanto a página de terceiros permanecer anexada.

O Fragnesia violou a segunda regra ao mover descritores de fragmentos em `skb_try_coalesce()`. O caminho do OVS é sutilmente diferente: ele não transfere o fragmento; em vez disso, limpa o marcador **in-place no skb original e continua encaminhando-o**.<sup>[[2]](#references)[[4]](#references)</sup>

## Alcance do OVS sem privilégios

O datapath do kernel do OVS é controlado por famílias generic-netlink, como `ovs_datapath`, `ovs_vport`, `ovs_flow` e `ovs_packet`. Suas operações de alteração usam `GENL_UNS_ADMIN_PERM`, que considera namespaces; assim, um processo executado sob `unshare -Urn` obtém o `CAP_NET_ADMIN` necessário para criar um datapath, conectar um veth e instalar ações de fluxo dentro do próprio namespace de rede. Resolver a família OVS também pode carregar automaticamente `openvswitch.ko`; `CAP_SYS_MODULE` no host, `ovs-vsctl` e `ovs-vswitchd` não são necessários para essa superfície de ataque.<sup>[[2]](#references)[[7]](#references)</sup>

A distinção importante é entre dois tipos de upcall:<sup>[[2]](#references)[[7]](#references)</sup>

- Um **flow miss** envia o pacote para `ovs-vswitchd`; se o upcall falhar, normalmente o pacote é descartado.
- Uma ação explícita `OVS_ACTION_ATTR_USERSPACE` envia uma cópia emprestada para um port ID selecionado e, em seguida, executa as ações posteriores no skb original.

Assim, um atacante pode instalar um fluxo com a seguinte estrutura:<sup>[[1]](#references)[[2]](#references)</sup>

```text
in_port(1),ipv4 -> USERSPACE(pid=<unbound-portid>), OUTPUT(0)
```

Nenhum listener possui o ID de porta selecionado, fazendo a ação userspace falhar de forma previsível, enquanto a ação `OUTPUT` seguinte mantém o pacote original ativo.<sup>[[1]](#references)[[2]](#references)</sup>

## Causa raiz: `skb_tx_error()` em um pacote que sobrevive

O caminho vulnerável de erro do upcall do OVS chama `skb_tx_error(skb)`. Esse helper foi projetado para uma transmissão com falha, na qual o skb é liberado depois; ele conclui o bookkeeping de zerocopy por meio de `skb_zcopy_clear()`, cuja máscara de flags historicamente também removia `SKBFL_SHARED_FRAG`. O OVS ignorava o erro da ação userspace e continuava a lista de ações, violando o contrato de duração do helper.<sup>[[1]](#references)[[2]](#references)</sup>

A transição de estado explorável é:<sup>[[2]](#references)</sup>

```text
before failed upcall: flags=0xb, nr_frags=1, page-cache folio attached
skb_tx_error():       zerocopy flags, including SHARED_FRAG, are cleared
after failed upcall:  flags=0x0, nr_frags=1, same folio still attached
OUTPUT:               unmarked skb continues to local ESP input
```

Isso só funciona quando `skb_zcopy()` encontra o estado zerocopy. Um fragmento que carrega apenas `SKBFL_SHARED_FRAG` não é suficiente; `MSG_ZEROCOPY` é útil porque cria `SKBFL_ZEROCOPY_ENABLE | SKBFL_SHARED_FRAG` e também define `SKBFL_DONT_ORPHAN`. Isso faz com que `skb_orphan_frags()` ignore a substituição das páginas externas durante a cópia do OVS para o userspace.<sup>[[2]](#references)[[3]](#references)</sup>

## Construindo a primitiva de escrita

O gatilho de ponta a ponta tem os seguintes componentes.<sup>[[2]](#references)[[3]](#references)</sup>

1. Entre em namespaces privados de usuário e rede com `unshare -Urn`.
2. Mapeie um arquivo-alvo legível com `PROT_READ | MAP_SHARED`.
3. Use um netns de envio separado e um par veth; o loopback local copiaria as páginas emprestadas e destruiria a primitiva.
4. Crie um datapath OVS e o fluxo `USERSPACE`-seguido-de-`OUTPUT` que falha.
5. Instale um estado XFRM ESP-in-UDP em modo de transporte usando `rfc4106(gcm(aes))` e a porta UDP 4500.
6. Envie um datagrama `MSG_ZEROCOPY` com um iovec estruturado como `[cabeçalho ESP | bytes do arquivo mapeado | ICV inválido]`.

O estado XFRM usa 20 bytes de material de chave AES-128-GCM: 16 bytes de chave AES seguidos pelo salt RFC 4106 de quatro bytes. Para um IV explícito de oito bytes escolhido, a confidencialidade do payload começa com o bloco contador `salt || IV || be32(2)`; o valor de contador 1 mascara o resultado da autenticação.<sup>[[2]](#references)[[6]](#references)</sup>

```bash
ip xfrm state add src 10.99.99.1 dst 10.99.99.2 proto esp \
  spi 0x42434445 mode transport \
  aead 'rfc4106(gcm(aes))' \
  0x000102030405060708090a0b0c0d0e0f11223344 128 \
  encap espinudp 4500 4500 0.0.0.0
```

Depois que o OVS remove o marker, o ESP segue o caminho no-copy e executa `plaintext = ciphertext XOR keystream` sobre o fragmento respaldado por arquivo. A autenticação é verificada **após** essa transformação, então um ICV inválido composto apenas por zeros faz o pacote falhar com `-EBADMSG` somente depois que os bytes do page cache já foram alterados.<sup>[[2]](#references)</sup>

### Convertendo GCM em bytes escolhidos

Para o byte atual `C` e o byte desejado `P`, o primeiro byte do keystream do payload deve ser `C XOR P`. Com a chave AES e o salt fixos, percorra um sufixo de 16 bits do IV explícito e pré-calcule um sufixo para cada possível primeiro byte do keystream:<sup>[[2]](#references)[[3]](#references)[[6]](#references)</sup>

```text
for n in 0..0xffff:
    iv = 0xcccccccc || 0x0000 || be16(n)
    k0 = AES_K(salt || iv || be32(2))[0]
    first_suffix_for[k0] ??= n
```

A implementação pública limita o ciphertext a 32 bytes e avança o fragmento do arquivo em um byte para cada pacote. O primeiro byte escolhido sobrescreve o primeiro byte colateral do pacote anterior; `pread()` atualiza `C` antes de cada pacote, bytes iguais são ignorados e o pacote final é encurtado para que as gravações não ultrapassem o intervalo solicitado. Assim, uma tabela de consulta com 256 entradas transforma a primitiva em uma gravação no page-cache de conteúdo escolhido, granularidade de byte, a aproximadamente um pacote por byte diferente.<sup>[[2]](#references)[[3]](#references)</sup>

## Gravação no page-cache para obter root

Um alvo prático é um executável setuid-root existente. O PoC substitui os primeiros 160 bytes por um ELF estático completo, contendo um `PT_LOAD` de leitura/execução em endereço fixo, sem `PT_INTERP` e com código que chama `setuid(0)` antes de `execve("/bin/sh", ...)`. Isso evita suposições sobre o ponto de entrada do binário original, o layout de PIE, o carregador dinâmico ou as relocações.<sup>[[2]](#references)[[3]](#references)</sup>

A modificação é visível em todos os user namespaces porque o page-cache não é isolado por namespace. O folio alterado não é marcado como dirty, portanto não é gravado de volta; execute o alvo enquanto ele estiver residente e, em seguida, descarte a corrupção temporária com `posix_fadvise(..., POSIX_FADV_DONTNEED)` para que leituras posteriores carreguem novamente o conteúdo original do disco.<sup>[[2]](#references)[[3]](#references)</sup>

## Verificações de exposição e mitigação

Verifique primeiro o kernel do fornecedor em uso. Os fatores relevantes para a exposição são user namespaces sem privilégios, disponibilidade ou presença do OVS e uma implementação ESP disponível.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
unshare -Urn true 2>/dev/null && echo 'user+net namespaces available'
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone \
  kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
lsmod | grep openvswitch
modprobe -n -v openvswitch esp4 esp6 2>/dev/null
modinfo esp4 esp6 2>/dev/null | grep -E '^(name|alias):'
```

Atualize para um kernel que inclua a série completa de correções; o reparo final cobre o caminho de recirculação e evita modificar o estado compartilhado de `skb_shinfo()`, além de corrigir um problema relacionado de remoção em `skb_zerocopy()`.<sup>[[1]](#references)[[2]](#references)</sup>

Se o OVS não for usado, impeça o carregamento tanto por alias quanto por nome usando uma regra `install` do modprobe, em vez de depender apenas de `blacklist`. Se o host não terminar conexões IPsec e o ESP for modular, o mesmo controle pode remover o sink de descriptografia.<sup>[[2]](#references)</sup>

```conf
# /etc/modprobe.d/disable-unused-network-surfaces.conf
install openvswitch /bin/false
install esp4 /bin/false
install esp6 /bin/false
```

Estas regras não ajudam quando um módulo já está carregado ou o recurso está integrado ao kernel. Desabilitar user namespaces sem privilégios também remove a fonte de capacidade de namespace, mas pode impedir o funcionamento de navegadores, Flatpak, Podman e outras cargas de trabalho de sandboxing/contêineres.<sup>[[2]](#references)</sup>

## Lições da revisão

Ao auditar redes zero-copy, não limite a busca a helpers que copiam ou movem fragmentos. Identifique também os helpers de erro/conclusão que limpam flags agrupadas e, em seguida, verifique se todos os chamadores respeitam o contrato documentado de ciclo de vida do skb. Um bit de propriedade de página agrupado com bits do ciclo de vida zerocopy é sensível à segurança, mesmo quando o código que o limpa nunca acessa diretamente um fragmento.<sup>[[1]](#references)[[2]](#references)</sup>

Uma correção robusta precisa cobrir todas as rotas pelas quais o skb pode persistir — incluindo a continuação de ações e a recirculação — e levar em conta clones que compartilham `skb_shinfo()`. No lado do consumidor, uma falha de autenticação não desfaz as gravações em texto simples já realizadas por uma transformação AEAD in-place; portanto, as verificações de armazenamento externo precisam ocorrer antes do início da descriptografia.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Série de correções da Doyensec para netdev: net: não remova marcadores de fragmentos zerocopy de um skb encaminhado](https://lore.kernel.org/netdev/4B5CCA6E-2C49-4F86-8C4E-E1BE15C16C0A@doyensec.com/T/#t)
- [2] [Doyensec: a remoção de marcadores de skb encaminhado no Open vSwitch permite LPE determinístico no page cache do ESP](https://blog.doyensec.com/2026/09/17/ovs.html)
- [3] [Prova de conceito `ovs-pagecache-write` da Doyensec](https://github.com/doyensec/ovs-pagecache-write)
- [4] [Correção do Linux para o caminho original de coalescência Fragnesia (`f84eca581739`)](https://github.com/torvalds/linux/commit/f84eca5817390257cef78013d0112481c503b4a3)
- [5] [Verificação de fragmentos compartilhados no lado do consumidor ESP do Linux (`f4c50a4034e6`)](https://github.com/torvalds/linux/commit/f4c50a4034e6)
- [6] [RFC 4106: o uso do modo Galois/Counter (GCM) no IPsec ESP](https://datatracker.ietf.org/doc/html/rfc4106)
- [7] [Documentação do datapath do kernel do Open vSwitch](https://docs.openvswitch.org/en/latest/topics/datapath/)
{{#include ../../../banners/hacktricks-training.md}}
