---
title: Variáveis de Ambiente
description: Guia completo sobre as variáveis de ambiente necessárias para configurar o Draft Auth.
---

O Draft Auth utiliza variáveis de ambiente para configurar conexões com bancos de dados, provedores de autenticação, chaves de segurança e URLs da aplicação. É essencial configurar essas variáveis corretamente para que o sistema funcione.

Normalmente, você criará arquivos `.env` separados para a API (`apps/api/.env`) e para a aplicação Web (`apps/web/.env`) com base nos arquivos `.env.example` fornecidos em cada diretório.

## API (`apps/api`)

Estas variáveis são configuradas no arquivo `.env` dentro do diretório `apps/api`.

| Variável                            | Obrigatória | Descrição                                                                                                      | Links Relevantes                                         |
| :---------------------------------- | :---------- | :------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------- |
| `FRONTEND_URL`                      | Sim         | A URL completa da sua aplicação frontend (Admin UI, `apps/web`). Ex: `http://localhost:5173`                   | -                                                        |
| `OWNER_APPLICATION_ID`              | Sim         | O ID fixo e único para a aplicação de gerenciamento principal do Draft Auth. Ex: `draftauth-admin-app`         | [Aplicações](/concepts/applications)                     |
| `API_SECRET_ENCRYPTION_KEY`         | Sim         | Uma chave secreta forte (gere com `openssl rand -base64 32`) usada para criptografar os segredos das API Keys. | [API Keys](/concepts/api-keys)                           |
| `GITHUB_CLIENT_ID`                  | Sim         | O Client ID obtido ao registrar seu app OAuth no GitHub.                                                       | [Configurando Provedores OAuth](/guides/oauth-providers) |
| `GITHUB_CLIENT_SECRET`              | Sim         | O Client Secret obtido ao registrar seu app OAuth no GitHub.                                                   | [Configurando Provedores OAuth](/guides/oauth-providers) |
| `GOOGLE_CLIENT_ID`                  | Sim         | O Client ID obtido ao registrar seu app OAuth no Google Cloud Console.                                         | [Configurando Provedores OAuth](/guides/oauth-providers) |
| `GOOGLE_CLIENT_SECRET`              | Sim         | O Client Secret obtido ao registrar seu app OAuth no Google Cloud Console.                                     | [Configurando Provedores OAuth](/guides/oauth-providers) |
| `DATABASE_URL`                      | Sim (Prod)  | A URL de conexão do seu banco de dados Turso para produção.                                                    | [Instalação](/guides/installation)                       |
| `DATABASE_AUTH_TOKEN`               | Sim (Prod)  | O token de autenticação para o banco de dados Turso em produção.                                               | [Instalação](/guides/installation)                       |
| `DATABASE_URL_DEV`                  | Não         | O caminho para o arquivo SQLite local em desenvolvimento. Padrão: `file:./db.sqlite`                           | [Instalação](/guides/installation)                       |
| `NODE_ENV`                          | Não         | Define o ambiente de execução (`development`, `production`, `test`). Padrão: `development`                     | -                                                        |
| `PORT` (Opcional via `process.env`) | Não         | Porta onde a API Hono irá rodar. Padrão: `3000`.                                                               | -                                                        |

**Notas:**

- As variáveis `DATABASE_URL` e `DATABASE_AUTH_TOKEN` são obrigatórias apenas se `NODE_ENV` for `"production"`.
- `DATABASE_URL_DEV` é usada se `NODE_ENV` não for `"production"`.
- Mantenha `API_SECRET_ENCRYPTION_KEY`, `GITHUB_CLIENT_SECRET`, `GOOGLE_CLIENT_SECRET` e `DATABASE_AUTH_TOKEN` seguras e nunca as versione no seu código.

## Web (`apps/web`)

Estas variáveis são configuradas no arquivo `.env` dentro do diretório `apps/web` e são prefixadas com `VITE_` para serem expostas ao frontend durante o build com Vite.

| Variável              | Obrigatória | Descrição                                                                                                      | Links Relevantes                     |
| :-------------------- | :---------- | :------------------------------------------------------------------------------------------------------------- | :----------------------------------- |
| `VITE_BACKEND_URL`    | Sim         | A URL completa onde a API do Draft Auth (`apps/api`) está rodando. Ex: `http://localhost:3000`                 | -                                    |
| `VITE_APPLICATION_ID` | Sim         | O ID da aplicação de gerenciamento. **Deve ser o mesmo valor** que `OWNER_APPLICATION_ID` na API (`apps/api`). | [Aplicações](/concepts/applications) |

Certifique-se de que `VITE_BACKEND_URL` esteja acessível a partir do navegador onde a aplicação web será executada.
