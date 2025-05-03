---
title: Management API Reference
---

A Management API (`/api/manage`) fornece endpoints para administrar todos os aspectos do Draft Auth. Ela é acessada principalmente pela interface web de administração (`apps/web`).

**Autenticação:**

- Requer um **Bearer Token** no header `Authorization`.
- Este token é o **Access Token** obtido pelo usuário administrador (proprietário do sistema) após se autenticar via fluxo OAuth/OIDC gerenciado pelo `@draftauth/core`.
- O middleware `adminMiddleware` valida o token e garante que o usuário é o proprietário configurado.

**Principais Grupos de Endpoints:**

- **Aplicações (`/applications`, `/applications/:appId`, `/:appId`)**
  - Listar, criar, obter detalhes e deletar aplicações.
- **URIs de Redirecionamento (`/applications/:appId/redirect-uris`)**
  - Listar, adicionar e remover URIs de redirecionamento OAuth para uma aplicação.
- **Cargos / Roles (`/applications/:appId/roles`, `/applications/:appId/roles/:roleId`, `/roles/:roleId`)**
  - Listar, criar, atualizar e deletar cargos dentro de uma aplicação específica.
- **Usuários (`/users`, `/users/:id`, `/users/:id/*`)**
  - Listar todos os usuários.
  - Obter detalhes de um usuário específico (`userId`, `email`, `status`, `createdAt`).
  - Obter/Definir o status global (`active`/`inactive`) de um usuário.
  - Listar todos os cargos de um usuário agregados por aplicação.
  - Listar todos os status de acesso (`enabled`/`disabled`) de um usuário por aplicação.
- **Atribuição de Cargos (`/users/:userId/roles`, `/users/:userId/roles/:roleId`)**
  - Atribuir um cargo existente a um usuário para a aplicação correspondente ao cargo.
  - Revogar um cargo de um usuário.
- **Acesso por Aplicação (`/users/:userId/access/:appId`)**
  - Definir explicitamente o status de acesso (`enabled` ou `disabled`) de um usuário para uma aplicação específica.
- **API Keys (`/:appId/api-keys`, `/api-keys/:keyId`)**
  - Listar as API Keys de uma aplicação (apenas metadados, sem o segredo).
  - Gerar uma nova API Key para uma aplicação (retorna o segredo apenas nesta chamada).
  - Revogar (deletar) uma API Key existente.
- **Usuário Atual (`/user`)**
  - Obter os detalhes do usuário administrador atualmente autenticado.

**Observação:** Para detalhes específicos sobre parâmetros, corpo de requisição/resposta e códigos de status de cada endpoint, consulte o código-fonte em `apps/api/src/routes/management.ts` ou utilize ferramentas de exploração de API se disponíveis.
