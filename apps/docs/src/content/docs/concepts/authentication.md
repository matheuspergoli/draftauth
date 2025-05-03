---
title: Autenticação no Draft Auth
---

Entenda como o Draft Auth lida com o processo de login e verificação de identidade dos usuários.

## Fluxo de Autenticação

O Draft Auth utiliza o padrão OAuth 2.0 e OpenID Connect (OIDC) para a maioria dos fluxos.

1.  **Início:** O usuário clica no botão de login na aplicação cliente (frontend).
2.  **Redirecionamento:** A aplicação cliente redireciona o usuário para a página de login centralizada do Draft Auth (hospedada pelo pacote `@draftauth/core`).
3.  **Seleção do Provedor:** O usuário escolhe como se autenticar (Google, GitHub, Senha).
4.  **Autenticação Externa:** O usuário se autentica com o provedor escolhido (ex: faz login no Google).
5.  **Retorno ao Draft Auth:** O provedor redireciona o usuário de volta ao Draft Auth com um código de autorização ou token.
6.  **Verificação e Criação/Link de Usuário:**
    - O Draft Auth verifica a identidade do usuário com o provedor.
    - Busca um usuário existente pelo email verificado ou ID do provedor.
    - Se não existir, cria um novo usuário centralizado.
    - Vincula a identidade externa (ex: ID do Google) ao usuário central.
7.  **Emissão de Tokens:** O Draft Auth emite tokens (Access Token, Refresh Token) para a aplicação cliente original.
8.  **Redirecionamento Final:** O usuário é redirecionado de volta para a aplicação cliente com os tokens.

## Provedores Suportados

- **Google:** Utiliza OAuth 2.0[cite: 527, 532]. Requer configuração de Client ID e Client Secret do Google Cloud Console.
- **GitHub:** Utiliza OAuth 2.0[cite: 527, 531]. Requer configuração de Client ID e Client Secret do GitHub Developer Settings[cite: 526].
- **Senha (Email/Código):** Fluxo customizado com envio de código de verificação para o email (implementação de envio de email necessária) e validação de força/vazamento de senha[cite: 527, 528, 534, 535].

## Verificação de Email

A verificação do email é crucial e geralmente garantida pelos provedores OAuth (Google, GitHub). Para o provedor de Senha, a verificação ocorre através do código enviado.

## Gerenciamento de Sessão

O Draft Auth gerencia a sessão centralizada e a emissão/renovação de tokens para as aplicações cliente.

_Veja também:_

- [Guia: Configurando Provedores OAuth](/guides/oauth-providers)
- [API Reference: Endpoints de Autenticação](/api/...) (Adicionar link correto quando criado)
