# Descriptografia de Arquivos PAT/SPK Criptografados da Synology

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Vários dispositivos Synology (NAS DSM/BSM, BeeStation, …) distribuem seus firmwares e pacotes de aplicativos em **arquivos PAT / SPK criptografados**. Esses arquivos podem ser descriptografados *offline* usando apenas os arquivos públicos para download, graças às chaves codificadas diretamente nas bibliotecas oficiais de extração.

Esta página documenta, passo a passo, como o formato criptografado funciona e como recuperar completamente o **TAR** em texto claro contido em cada pacote. O procedimento baseia-se na pesquisa da Synacktiv realizada durante o Pwn2Own Ireland 2024 e implementada na ferramenta open source [`synodecrypt`](https://github.com/synacktiv/synodecrypt).<sup>[[1]](#references)[[2]](#references)</sup>

> ⚠️  O formato é exatamente o mesmo para arquivos `*.pat` (atualização do sistema) e `*.spk` (aplicativo) – eles diferem apenas no par de chaves codificadas selecionadas.

---

## 1. Baixe o arquivo

A atualização do firmware/aplicativo normalmente pode ser baixada no portal público da Synology:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Extraia a estrutura PAT (opcional)

As imagens `*.pat` são um **pacote cpio** que incorpora vários arquivos (carregador de boot, kernel, rootfs, pacotes…). O utilitário gratuito [`patology`](https://github.com/sud0woodo/patology) é conveniente para inspecionar esse wrapper:<sup>[[3]](#references)</sup>
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Para arquivos `*.spk`, você pode ir diretamente para a etapa 3.

## 3. Extraia as bibliotecas de extração do Synology

A lógica real de descriptografia está em:

* `/usr/syno/sbin/synoarchive`               → wrapper principal da CLI
* `/usr/lib/libsynopkg.so.1`                 → chama o wrapper pela interface do DSM
* `libsynocodesign.so`                       → **contém a implementação criptográfica**

Ambos os binários estão presentes no rootfs do sistema (`hda1.tgz`) **e** no init-rd compactado (`rd.bin`). Se você tiver apenas o PAT, poderá obtê-los desta forma:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Recuperar as chaves hard-coded (`get_keys`)

Dentro de `libsynocodesign.so`, a função `get_keys(int keytype)` simplesmente retorna duas variáveis globais de 128 bits para a família de archive solicitada:<sup>[[1]](#references)</sup>
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
* **signature_key** → chave pública Ed25519 usada para verificar o header do archive.
* **master_key**    → chave raiz usada para derivar a chave de encryption por archive.

Você só precisa fazer dump dessas duas constantes uma vez para cada versão principal do DSM.

## 5. Estrutura do header e verificação da assinatura

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` executa o seguinte:<sup>[[1]](#references)</sup>

1. Lê o magic (3 bytes) `0xBFBAAD` **ou** `0xADBEEF`.
2. Lê `header_len` de 32 bits em little-endian.
3. Lê `header_len` bytes + a próxima **assinatura Ed25519 de 0x40 bytes**.
4. Itera por todas as chaves públicas incorporadas até `crypto_sign_verify_detached()` ser bem-sucedido.
5. Decodifica o header com **MessagePack**, resultando em:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` posteriormente permite que o libarchive verifique a integridade de cada arquivo à medida que ele é descriptografado.

## 6. Derive a sub-key específica do archive

A partir do blob `data` contido no cabeçalho MessagePack:

* `subkey_id`  = `uint64` little-endian no offset 0x10
* `ctx`        = 7 bytes no offset 0x18

A **stream key** de 32 bytes é obtida com o libsodium:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Backend **libarchive** personalizado da Synology

A Synology inclui uma versão modificada do libarchive que registra um formato "tar" falso sempre que o magic é `0xADBEEF`:<sup>[[1]](#references)</sup>
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
Cada **nonce de 0x18 bytes** é prefixado ao chunk criptografado.

Depois que todas as entradas são processadas, o libarchive produz um **`.tar`** perfeitamente válido que pode ser descompactado com qualquer ferramenta padrão.

## 8. Descriptografar tudo com synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` detecta automaticamente PAT/SPK, carrega as chaves corretas e aplica a cadeia completa descrita acima.<sup>[[2]](#references)</sup>

## 9. Armadilhas comuns

* **Não** troque `signature_key` e `master_key` – elas têm finalidades diferentes.
* O **nonce** vem *antes* do ciphertext em cada bloco (header e dados).
* O tamanho máximo do chunk encrypted é **0x400000 + 0x11** (tag do libsodium).
* Archives criados para uma geração do DSM podem mudar para chaves hard-coded diferentes na próxima release.

## 10. Ferramentas adicionais

* [`patology`](https://github.com/sud0woodo/patology) – parse/dump de archives PAT.<sup>[[3]](#references)</sup>
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – decrypt de PAT/SPK/outros.<sup>[[2]](#references)</sup>
* [`libsodium`](https://github.com/jedisct1/libsodium) – implementação de referência do secretstream XChaCha20-Poly1305.
* [`msgpack`](https://msgpack.org/) – serialização do header.

## Referências

- [1] [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [2] [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [3] [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
