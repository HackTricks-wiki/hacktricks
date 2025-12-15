# TLS & Certificates

{{#include ../../banners/hacktricks-training.md}}

Esta área trata de **X.509 análise, formatos, conversões e erros comuns**.

## X.509: análise, formatos & erros comuns

### Análise rápida
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Campos úteis para inspecionar:

- Assunto / Emissor / SAN
- Uso da chave / EKU
- Restrições básicas (é uma CA?)
- Janela de validade (NotBefore/NotAfter)
- Algoritmo de assinatura (MD5? SHA1?)

### Formatos e conversão

- PEM (Base64 com cabeçalhos BEGIN/END)
- DER (binário)
- PKCS#7 (`.p7b`) (cadeia de certificados, sem chave privada)
- PKCS#12 (`.pfx/.p12`) (certificado + chave privada + cadeia)

Conversões:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Vetores ofensivos comuns

- CAs raiz fornecidas pelo usuário / validação da cadeia ausente
- Algoritmos de assinatura fracos (legado)
- Restrições de nome / bugs de parsing de SAN (específicos da implementação)
- Problemas de confused deputy com misbinding na autenticação client-certificate

### CT logs

- https://crt.sh/

{{#include ../../banners/hacktricks-training.md}}
