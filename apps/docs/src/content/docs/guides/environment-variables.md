---
title: Variáveis de Ambiente
description: Guia completo sobre as variáveis de ambiente necessárias para configurar o Draft Auth.
---

O Draft Auth utiliza variáveis de ambiente para configurar conexões, provedores de autenticação, chaves de segurança e URLs. É essencial configurar essas variáveis corretamente. Crie arquivos `.env` separados para a API (`apps/api/.env`) e para a Web (`apps/web/.env`).

## API (`apps/api`)

Configuradas em `apps/api/.env`.

| Variável                            | Obrigatória | Descrição                                                                                              | Links Relevantes                                         |
| :---------------------------------- | :---------- | :----------------------------------------------------------------------------------------------------- | :------------------------------------------------------- |
| `FRONTEND_URL`                      | Sim         | A URL completa da sua aplicação frontend (Admin UI, `apps/web`). Ex: `http://localhost:5173`           | -                                                        |
| `OWNER_APPLICATION_ID`              | Sim         | O ID fixo e único para a aplicação de gerenciamento principal. Ex: `draftauth-admin-app`               | [Aplicações](/concepts/applications)                     |
| `API_SECRET_ENCRYPTION_KEY`         | Sim         | Chave secreta forte (gere com `openssl rand -base64 32`) usada para criptografar segredos de API Keys. | [API Keys](/concepts/api-keys)                           |
| `GITHUB_CLIENT_ID`                  | Sim         | Client ID do app OAuth no GitHub.                                                                      | [Configurando Provedores OAuth](/guides/oauth-providers) |
| `GITHUB_CLIENT_SECRET`              | Sim         | Client Secret do app OAuth no GitHub.                                                                  | [Configurando Provedores OAuth](/guides/oauth-providers) |
| `GOOGLE_CLIENT_ID`                  | Sim         | Client ID do app OAuth no Google Cloud Console.                                                        | [Configurando Provedores OAuth](/guides/oauth-providers) |
| `GOOGLE_CLIENT_SECRET`              | Sim         | Client Secret do app OAuth no Google Cloud Console.                                                    | [Configurando Provedores OAuth](/guides/oauth-providers) |
| `REDIS_URL`                         | Sim         | A URL de conexão do seu servidor Redis (usado para Rate Limiting). Ex: `redis://...`                   | [Rate Limiting](/concepts/rate-limiting)                 |
| `REDIS_TOKEN`                       | Sim         | O token/senha de autenticação para o servidor Redis (usado para Rate Limiting).                        | [Rate Limiting](/concepts/rate-limiting)                 |
| `RESEND_API_KEY`                    | Sim         | A API Key obtida no Resend para envio de emails transacionais (ex: códigos de login).                  | [Configuração de Email](/guides/email-setup)             |
| `DATABASE_URL`                      | Sim         | A URL de conexão do seu banco de dados Turso para produção.                                            | [Instalação](/guides/installation)                       |
| `DATABASE_AUTH_TOKEN`               | Sim         | O token de autenticação para o banco de dados Turso em produção.                                       | [Instalação](/guides/installation)                       |
| `DATABASE_URL_DEV`                  | Não         | O caminho para o arquivo SQLite local em desenvolvimento. Padrão: `file:./db.sqlite`                   | [Instalação](/guides/installation)                       |
| `NODE_ENV`                          | Não         | Define o ambiente (`development`, `production`, `test`). Padrão: `development`                         | -                                                        |
| `PORT` (Opcional via `process.env`) | Não         | Porta onde a API Hono irá rodar. Padrão: `3000`.                                                       | -                                                        |

**Notas:**

- Mantenha chaves secretas (`API_SECRET_ENCRYPTION_KEY`, `*_CLIENT_SECRET`, `REDIS_TOKEN`, `RESEND_API_KEY`, `DATABASE_AUTH_TOKEN`) seguras.

## Web (`apps/web`)

Configuradas em `apps/web/.env`.

| Variável              | Obrigatória | Descrição                                                                                         | Links Relevantes                     |
| :-------------------- | :---------- | :------------------------------------------------------------------------------------------------ | :----------------------------------- |
| `VITE_BACKEND_URL`    | Sim         | A URL completa onde a API do Draft Auth (`apps/api`) está rodando. Ex: `http://localhost:3000`    | -                                    |
| `VITE_APPLICATION_ID` | Sim         | O ID da aplicação de gerenciamento. **Deve ser o mesmo valor** que `OWNER_APPLICATION_ID` na API. | [Aplicações](/concepts/applications) |
