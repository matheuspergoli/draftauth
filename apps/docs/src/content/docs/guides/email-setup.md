---
title: Configuração de Envio de Email
description: Como configurar o envio de emails transacionais usando Resend no Draft Auth.
---

O Draft Auth utiliza envio de emails para funcionalidades essenciais de autenticação, especificamente para enviar códigos de verificação no fluxo de login por senha (passwordless).

## Provedor Utilizado: Resend

A integração é feita com o [Resend](https://resend.com). O cliente Resend é inicializado e exportado diretamente pelo módulo `apps/api/src/libs/resend.ts`.

## Configuração

Para habilitar o envio de emails:

1.  **Conta e API Key:** Crie uma conta no [Resend](https://resend.com) e gere uma API Key.
2.  **Domínio (Recomendado):** Configure e verifique seu domínio de envio no Resend.
3.  **Variável de Ambiente:** Defina a variável `RESEND_API_KEY` no ambiente da sua API (`apps/api/.env`). O módulo `libs/resend.ts` usa esta chave para inicializar o cliente.

## Uso no Código

A instância do cliente `resend` exportada por `libs/resend.ts` é importada e utilizada diretamente na função `sendCode` dentro da configuração do `PasswordProvider` em `apps/api/src/libs/auth.ts`.

- **Login por Senha (Passwordless):** Após passar pelas verificações de rate limit (por IP e por email), a função `sendCode` chama `resend.emails.send(...)` para enviar o código de verificação. O conteúdo do email é renderizado usando o componente React `VerificationCodeEmail` (`@draftauth/emails/verification-code-email`).

_Veja também:_

- [Variáveis de Ambiente](/guides/environment-variables#api-appsapi) (Seção Resend)
- [Rate Limiting](/concepts/rate-limiting) (Verificado antes do envio)
- [Autenticação](/concepts/authentication)
