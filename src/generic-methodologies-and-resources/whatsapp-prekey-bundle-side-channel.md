# Esgotamento e reabastecimento do pacote de Prekeys do WhatsApp por canal lateral

{{#include ../banners/hacktricks-training.md}}

O WhatsApp armazena uma chave de identidade, uma prekey assinada e uma reserva de prekeys de uso único para cada dispositivo. Buscar o pacote de um dispositivo consome uma prekey de uso único armazenada no servidor, mesmo que o solicitante não envie nenhuma mensagem. Isso oferece a um atacante com uma conta do WhatsApp e o número de telefone do alvo uma sondagem **do lado do servidor**, distinta da [temporização dos recibos de entrega do cliente](side-channel-attacks-on-messaging-protocols.md). A ausência de uma prekey de uso único também enfraquece o sigilo futuro das *mensagens iniciais* de uma sessão recém-estabelecida; por si só, não expõe o texto simples.<sup>[[1]](#references)[[2]](#references)</sup>

## Inspecionar os pacotes de dispositivos de um alvo

O artefato [Prekey Pogo](https://github.com/sbaresearch/prekey-pogo) é pareado como uma sessão complementar do WhatsApp e oferece suporte a consultas **manuais** de dispositivos e prekeys. Faça o pareamento com uma conta de teste e use os comandos interativos `target`, `devices`, `prekey` (dispositivo principal) e `combine` (todos os dispositivos). O artefato publicado omite deliberadamente as funções automatizadas de esgotamento e congestionamento do servidor.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
git clone https://github.com/sbaresearch/prekey-pogo
cd prekey-pogo
./setup.sh
go run .
```

Para cada resposta, registre o JID do dispositivo, o timestamp do bundle `t`, o ID da signed-prekey `skey.id` e se o `key.id` de uso único está presente. O ID de dispositivo `0` é o telefone; IDs diferentes de zero são dispositivos complementares. Nas implementações testadas no artigo, o ID inicial da signed-prekey também distingue alguns clientes: Android começa em `0`, iOS e macOS usam um valor aleatório, e WhatsApp Web e Windows Desktop começam em `1`. Trate isso como uma impressão digital da implementação, não como uma regra imutável do protocolo.<sup>[[1]](#references)</sup>

## Transforme recargas em um oráculo de status online

Primeiro, calibre em um dispositivo que você controla: solicite repetidamente o bundle até o servidor parar de retornar uma `key` de uso único, anotando o último timestamp e os IDs das keys. Para um dispositivo-alvo, repita o esgotamento e consulte novamente após um intervalo controlado: uma nova key de uso único e um timestamp de bundle avançado indicam que o dispositivo enviou um novo lote. Nos testes de WhatsApp relatados, o servidor solicitava uma recarga quando restavam menos de 11 keys, e os clientes enviavam 812 novas keys. Aplique o procedimento por JID de dispositivo para distinguir um telefone de dispositivos complementares. Uma recarga atrasada apenas **sugere** que um dispositivo está offline: o agendamento em segundo plano, a perda de rede e a latência de recarga específica do cliente podem produzir a mesma observação. Diferentemente de um RTT de recibo, essa sondagem não exige uma mensagem cifrada entregue nem uma confirmação do lado da vítima.<sup>[[1]](#references)[[2]](#references)</sup>

Cada consulta consome uma key de uso único; portanto, um oráculo contínuo exige um cliente personalizado capaz de recuperar prekeys repetidamente. O artefato público demonstra apenas consultas manuais. Manter a reserva vazia pode fazer com que outros usuários estabeleçam novas sessões sem uma prekey de uso único. Isso reduz o forward secrecy das mensagens iniciais até uma nova etapa do ratchet, mas explorar ciphertexts registrados também exige acesso ao ciphertext E2EE e o comprometimento posterior das chaves privadas de longo e médio prazo relevantes. Sessões já estabelecidas não sofrem downgrade automaticamente.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Prekey Pogo: Investigando problemas de segurança e privacidade no mecanismo de handshake do WhatsApp](https://www.usenix.org/system/files/woot25-gegenhuber.pdf)
- [2] [O protocolo de acordo de chaves X3DH](https://signal.org/docs/specifications/x3dh/)
- [3] [Artefatos do Prekey Pogo](https://github.com/sbaresearch/prekey-pogo)
{{#include ../banners/hacktricks-training.md}}
