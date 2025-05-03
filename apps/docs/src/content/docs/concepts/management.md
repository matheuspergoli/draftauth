---
title: Management API Reference
---

Endpoints para administração do Draft Auth. Requer autenticação do usuário administrador (proprietário).

**Base Path:** `/api/manage`

**Autenticação:** Bearer Token (Access Token do usuário administrador)

Endpoints principais:

- **Aplicações:**
  - `GET /applications`: Lista todas as aplicações e contagens.
  - `POST /applications`: Cria uma nova aplicação.
  - `GET /applications/:appId`: Obtém detalhes de uma aplicação.
  - `DELETE /:appId`: Deleta uma aplicação.
- **URIs de Redirecionamento:**
  - `GET /applications/:appId/redirect-uris`: Lista URIs. 546]
  - `POST /applications/:appId/redirect-uris`: Adiciona URI. 546]
  - `DELETE /applications/:appId/redirect-uris`: Remove URI. 546]
- **Cargos (Roles):**
  - `GET /applications/:appId/roles`: Lista cargos da aplicação.
  - `POST /applications/:appId/roles`: Cria um cargo.
  - `PUT /applications/:appId/roles/:roleId`: Atualiza um cargo.
  - `DELETE /roles/:roleId`: Deleta um cargo.
- **Usuários:**
  - `GET /users`: Lista todos os usuários.
  - `GET /users/:id`: Obtém detalhes de um usuário.
  - `GET /users/:id/status`: Obtém status global.
  - `PUT /users/:id/status`: Define status global.
  - `GET /users/:id/applications-roles`: Lista todos os cargos do usuário em todas as apps.
  - `GET /users/:id/applications-access`: Lista status de acesso do usuário em todas as apps.
- **Atribuição de Cargos:**
  - `POST /users/:userId/roles`: Atribui cargo a usuário.
  - `DELETE /users/:userId/roles/:roleId`: Revoga cargo de usuário.
- **Acesso por Aplicação:**
  - `PUT /users/:userId/access/:appId`: Define status de acesso do usuário na aplicação.
- **API Keys:**
  - `GET /:appId/api-keys`: Lista API Keys da aplicação.
  - `POST /:appId/api-keys`: Gera nova API Key.
  - `DELETE /api-keys/:keyId`: Revoga uma API Key.
- **Usuário Atual:**
  - `GET /user`: Retorna detalhes do usuário administrador logado.

_(Detalhar parâmetros, corpos de requisição/resposta e códigos de status para cada endpoint)_
