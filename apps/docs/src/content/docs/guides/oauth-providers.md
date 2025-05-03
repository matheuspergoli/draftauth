---
title: Configurando Provedores OAuth
---

Passos para configurar Google e GitHub como provedores de autenticação.

**1. Google:**

- Acesse o [Google Cloud Console](https://console.cloud.google.com/).
- Crie um novo projeto ou selecione um existente.
- Vá para "APIs & Services" > "Credentials".
- Crie "OAuth client ID":
  - Tipo de Aplicação: "Web application".
  - Adicione a URI de redirecionamento do Draft Auth: `{VITE_BACKEND_URL}/google/callback` (ex: `http://localhost:3000/google/callback`).
- Copie o `Client ID` e `Client Secret`.
- Configure as variáveis `GOOGLE_CLIENT_ID` e `GOOGLE_CLIENT_SECRET` no `.env` da API.

**2. GitHub:**

- Acesse [GitHub Developer Settings](https://github.com/settings/developers).
- Vá para "OAuth Apps" > "New OAuth App".
- Preencha o nome da aplicação.
- Homepage URL: URL do seu frontend (ex: `http://localhost:5173`).
- Authorization callback URL: `{VITE_BACKEND_URL}/github/callback` (ex: `http://localhost:3000/github/callback`).
- Registre a aplicação.
- Gere um novo `Client Secret`.
- Copie o `Client ID` e o `Client Secret` gerado.
- Configure as variáveis `GITHUB_CLIENT_ID` e `GITHUB_CLIENT_SECRET` no `.env` da API.

**Importante:** Certifique-se de que as URIs de callback configuradas nos provedores correspondem exatamente às que o Draft Auth espera.
