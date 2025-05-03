---
title: API Keys
---

As API Keys permitem que seus serviços backend interajam de forma segura com a API de Serviço do Draft Auth para gerenciar acesso e cargos de usuários programaticamente.

## Geração

- API Keys são geradas através da **Management API** (`/api/manage/:appId/api-keys`) ou pela interface web de administração.
- Cada chave consiste em um **Key ID** (público, prefixado com `sk_<appId>_`) e um **Secret Key** (privado).
- **Importante:** O Secret Key só é exibido **uma única vez** durante a criação. Armazene-o de forma segura.

## Armazenamento Seguro

- O Secret Key **nunca** deve ser exposto no frontend ou versionado em código.
- Utilize variáveis de ambiente ou um gerenciador de segredos no seu backend para armazenar o Secret Key.
- O Draft Auth armazena uma versão **criptografada** do Secret Key, utilizando a `API_SECRET_ENCRYPTION_KEY` configurada no ambiente da API.

## Uso

- API Keys são usadas em conjunto com a **Autenticação HMAC** para assinar requests.
- O `Key ID` é enviado no header `X-Api-Key-Id`.
- O `Secret Key` é usado para gerar a assinatura HMAC enviada no header `X-Signature`.

## Revogação

- API Keys podem ser revogadas a qualquer momento através da Management API (`/api/manage/api-keys/:keyId`) ou da interface web.
- Uma vez revogada, a chave não poderá mais ser usada para autenticar requests.

_Veja também:_

- [Autenticação HMAC](/concepts/hmac)
- [API Reference: Service API](/api/service)
