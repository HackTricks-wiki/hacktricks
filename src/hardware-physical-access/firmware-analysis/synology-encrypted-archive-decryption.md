# Synology PAT/SPK Encrypted Archive Decryption

{{#include ../../banners/hacktricks-training.md}}

## Overview

Vários dispositivos Synology (DSM/BSM NAS, BeeStation, …) distribuem seu firmware e pacotes de aplicativos em **arquivos PAT / SPK criptografados**. Esses arquivos podem ser descriptografados *offline* com nada além dos arquivos de download públicos, graças a chaves codificadas embutidas dentro das bibliotecas de extração oficiais.

Esta página documenta, passo a passo, como o formato criptografado funciona e como recuperar completamente o **TAR** em texto claro que está dentro de cada pacote. O procedimento é baseado na pesquisa da Synacktiv realizada durante o Pwn2Own Irlanda 2024 e implementado na ferramenta de código aberto [`synodecrypt`](https://github.com/synacktiv/synodecrypt).

> ⚠️  O formato é exatamente o mesmo para os arquivos `*.pat` (atualização do sistema) e `*.spk` (aplicativo) – eles diferem apenas no par de chaves codificadas que são selecionadas.

---

## 1. Grab the archive

A atualização do firmware/aplicativo pode normalmente ser baixada do portal público da Synology:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Despeje a estrutura PAT (opcional)

`*.pat` imagens são, elas mesmas, um **pacote cpio** que incorpora vários arquivos (carregador de inicialização, kernel, rootfs, pacotes…). A ferramenta gratuita [`patology`](https://github.com/sud0woodo/patology) é conveniente para inspecionar esse wrapper:
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Para `*.spk` você pode pular diretamente para o passo 3.

## 3. Extraia as bibliotecas de extração da Synology

A verdadeira lógica de descriptografia está em:

* `/usr/syno/sbin/synoarchive`               → wrapper CLI principal
* `/usr/lib/libsynopkg.so.1`                 → chama o wrapper da interface do DSM
* `libsynocodesign.so`                       → **contém a implementação criptográfica**

Ambos os binários estão presentes no rootfs do sistema (`hda1.tgz`) **e** no init-rd comprimido (`rd.bin`). Se você tiver apenas o PAT, pode obtê-los desta forma:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Recuperar as chaves codificadas (`get_keys`)

Dentro de `libsynocodesign.so`, a função `get_keys(int keytype)` simplesmente retorna duas variáveis globais de 128 bits para a família de arquivos solicitada:
```c
case 0:            // PAT (system)
case 10:
case 11:
signature_key = qword_23A40;
master_key    = qword_23A68;
break;

case 3:            // SPK (applications)
signature_key = qword_23AE0;
master_key    = qword_23B08;
break;
```
* **signature_key** → Chave pública Ed25519 usada para verificar o cabeçalho do arquivo.
* **master_key**    → Chave raiz usada para derivar a chave de criptografia por arquivo.

Você só precisa despejar essas duas constantes uma vez para cada versão principal do DSM.

## 5. Estrutura do cabeçalho e verificação de assinatura

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` realiza o seguinte:

1. Ler mágica (3 bytes) `0xBFBAAD` **ou** `0xADBEEF`.
2. Ler little-endian 32-bit `header_len`.
3. Ler `header_len` bytes + a próxima **assinatura Ed25519 de 0x40 bytes**.
4. Iterar sobre todas as chaves públicas incorporadas até que `crypto_sign_verify_detached()` tenha sucesso.
5. Decodificar o cabeçalho com **MessagePack**, resultando em:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` permite que o libarchive verifique a integridade de cada arquivo à medida que é descriptografado.

## 6. Derivar a sub-chave por arquivo

A partir do blob `data` contido no cabeçalho MessagePack:

* `subkey_id`  = little-endian `uint64` no deslocamento 0x10
* `ctx`        = 7 bytes no deslocamento 0x18

A chave de **stream** de 32 bytes é obtida com libsodium:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Backend **libarchive** personalizado da Synology

A Synology agrupa uma libarchive corrigida que registra um formato "tar" falso sempre que o magic é `0xADBEEF`:
```c
register_format(
"tar", spk_bid, spk_options,
spk_read_header, spk_read_data, spk_read_data_skip,
NULL, spk_cleanup, NULL, NULL);
```
### spk_read_header()
```
- Read 0x200 bytes
- nonce  = buf[0:0x18]
- cipher = buf[0x18:0x18+0x193]
- crypto_secretstream_xchacha20poly1305_init_pull(state, nonce, kdf_subkey)
- crypto_secretstream_xchacha20poly1305_pull(state, tar_hdr, …, cipher, 0x193)
```
O `tar_hdr` descriptografado é um **cabeçalho TAR POSIX clássico**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Cada **nonce de 0x18 bytes** é precedido ao bloco criptografado.

Uma vez que todas as entradas são processadas, libarchive produz um **`.tar`** perfeitamente válido que pode ser descompactado com qualquer ferramenta padrão.

## 8. Decrypt everything with synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` detecta automaticamente PAT/SPK, carrega as chaves corretas e aplica toda a cadeia descrita acima.

## 9. Armadilhas comuns

* Não troque `signature_key` e `master_key` – eles servem a propósitos diferentes.
* O **nonce** vem *antes* do texto cifrado para cada bloco (cabeçalho e dados).
* O tamanho máximo do bloco criptografado é **0x400000 + 0x11** (tag libsodium).
* Arquivos criados para uma geração do DSM podem mudar para chaves codificadas diferentes na próxima versão.

## 10. Ferramentas adicionais

* [`patology`](https://github.com/sud0woodo/patology) – analisar/dump arquivos PAT.
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – descriptografar PAT/SPK/outros.
* [`libsodium`](https://github.com/jedisct1/libsodium) – implementação de referência de XChaCha20-Poly1305 secretstream.
* [`msgpack`](https://msgpack.org/) – serialização de cabeçalho.

## Referências

- [Extração de arquivos criptografados da Synology – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [synodecrypt no GitHub](https://github.com/synacktiv/synodecrypt)
- [patology no GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
