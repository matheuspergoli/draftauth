---
title: Guia Rápido
---

Este guia mostra como configurar rapidamente o Draft Auth e realizar um fluxo de autenticação básico.

**Pré-requisitos:**

- Node.js e pnpm instalados.
- Acesso a um terminal.

**Passos:**

1.  **Clonar o Repositório:**
    ```bash
    git clone https://github.com/matheuspergoli/draftauth.git
    cd draftauth
    ```
2.  **Instalar Dependências:**
    ```bash
    pnpm install
    ```
3.  **Configurar Variáveis de Ambiente:**
    - Crie um arquivo `.env` na raiz e em `apps/api` e `apps/web`.
    - Preencha as variáveis necessárias (veja `env.ts` em cada app, especialmente `DATABASE_URL`, `CLIENT_ID`s, `CLIENT_SECRET`s, `FRONTEND_URL`, `VITE_BACKEND_URL`).
4.  **Rodar Migrations (Desenvolvimento):**
    ```bash
    pnpm --filter ./apps/api db:push
    ```
5.  **Iniciar Aplicações:**
    ```bash
    pnpm dev
    ```
6.  **Acessar o Frontend:** Abra o `FRONTEND_URL` (geralmente `http://localhost:5173`) no navegador.
7.  **Setup Inicial:** Você será redirecionado para a autenticação e depois para a tela de setup para criar a aplicação principal.
8.  **Acessar Dashboard:** Após o setup, você poderá acessar o dashboard de administração.
