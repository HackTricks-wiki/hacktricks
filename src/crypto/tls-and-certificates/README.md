# TLS e Certificados

{{#include ../../banners/hacktricks-training.md}}

Esta seção aborda a inspeção de X.509, codificações, conversões e erros de validação relevantes para a segurança.

## Análise de X.509

O OpenSSL pode exibir os campos decodificados de um certificado, enquanto `asn1parse` mostra a estrutura ASN.1 subjacente.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Revise pelo menos:

- o subject, issuer e Subject Alternative Name (SAN);
- key usage e extended key usage;
- basic constraints e path-length constraints;
- os tempos de validade `notBefore` e `notAfter`;
- os parâmetros da chave pública e o algoritmo de assinatura.

Assinaturas legadas, como assinaturas de certificados baseadas em MD5 ou SHA-1, são descobertas particularmente importantes, embora a aceitação exata e o impacto dependam do validador e do contexto de confiança.<sup>[[3]](#references)</sup>

A RFC 5280 define o perfil X.509 da Internet e as regras de processamento para extensões como SAN, key usage, name constraints e basic constraints.<sup>[[3]](#references)</sup>

## Codificações e Contêineres

- **Codificação textual no estilo PEM:** dados em Base64 entre delimitadores `BEGIN` e `END`.
- **DER:** a representação binária Distinguished Encoding Rules.
- **PKCS#7/CMS (`.p7b`):** normalmente contém certificados e uma cadeia de certificados, mas não chaves privadas.
- **PKCS#12 (`.p12` ou `.pfx`):** pode conter chaves privadas, certificados e certificados de suporte.

A RFC 7468 especifica as codificações textuais usadas para estruturas PKIX, PKCS e CMS; o comando `pkcs12` do OpenSSL cria e analisa arquivos PKCS#12.<sup>[[4]](#references)[[5]](#references)</sup>
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
Trate `out.pem` como sensível: a menos que opções como `-nokeys` sejam usadas, a saída pode conter material de chave privada.<sup>[[5]](#references)</sup>

## Security Review Checklist

Aplique os requisitos de processamento de certificados da RFC 5280 ao revisar um validador ou uma decisão de confiança.<sup>[[3]](#references)</sup>

- Verifique a cadeia completa até uma âncora explicitamente confiável; não confie implicitamente em raízes fornecidas pelo usuário.
- Confirme o hostname ou a identidade do serviço em relação aos valores SAN.<sup>[[8]](#references)</sup>
- Aplique as restrições básicas, as restrições de nome, o uso da chave e o uso estendido da chave.
- Rejeite certificados expirados ou ainda não válidos e algoritmos de chave ou assinatura não permitidos.
- Associe as identidades dos certificados de cliente à conta correta da aplicação e ao contexto de autorização.

## Certificate Transparency Logs

Certificate Transparency fornece logs publicamente auditáveis de certificados emitidos.<sup>[[6]](#references)</sup> Pesquise um domínio com crt.sh durante a descoberta autorizada de ativos.<sup>[[7]](#references)</sup>

## References

- [1] [Documentação do OpenSSL - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [Documentação do OpenSSL - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Perfil de Certificado e CRL da Infraestrutura de Chave Pública X.509 da Internet](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - Codificações Textuais de Estruturas PKIX, PKCS e CMS](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [Documentação do OpenSSL - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency Versão 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Pesquisa de Certificados](https://crt.sh/)
- [8] [RFC 9525 - Identidade de Serviço em TLS](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
