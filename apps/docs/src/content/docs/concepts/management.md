---
title: Management API Reference
---

Endpoints para administração do Draft Auth. Requer autenticação do usuário administrador (proprietário).

**Base Path:** `/api/manage`

**Autenticação:** Bearer Token (Access Token do usuário administrador)

Endpoints principais:

- **Aplicações:**
  - `GET /applications`: Lista todas as aplicações e contagens.[cite: 547]
  - `POST /applications`: Cria uma nova aplicação.[cite: 547]
  - `GET /applications/:appId`: Obtém detalhes de uma aplicação.[cite: 547]
  - `DELETE /:appId`: Deleta uma aplicação.[cite: 547]
- **URIs de Redirecionamento:**
  - `GET /applications/:appId/redirect-uris`: Lista URIs.[cite: 546]
  - `POST /applications/:appId/redirect-uris`: Adiciona URI.[cite: 546]
  - `DELETE /applications/:appId/redirect-uris`: Remove URI.[cite: 546]
- **Cargos (Roles):**
  - `GET /applications/:appId/roles`: Lista cargos da aplicação.[cite: 548]
  - `POST /applications/:appId/roles`: Cria um cargo.[cite: 548]
  - `PUT /applications/:appId/roles/:roleId`: Atualiza um cargo.[cite: 548]
  - `DELETE /roles/:roleId`: Deleta um cargo.[cite: 548]
- **Usuários:**
  - `GET /users`: Lista todos os usuários.[cite: 547]
  - `GET /users/:id`: Obtém detalhes de um usuário.[cite: 545]
  - `GET /users/:id/status`: Obtém status global.[cite: 545]
  - `PUT /users/:id/status`: Define status global.[cite: 547]
  - `GET /users/:id/applications-roles`: Lista todos os cargos do usuário em todas as apps.[cite: 545]
  - `GET /users/:id/applications-access`: Lista status de acesso do usuário em todas as apps.[cite: 545]
- **Atribuição de Cargos:**
  - `POST /users/:userId/roles`: Atribui cargo a usuário.[cite: 548]
  - `DELETE /users/:userId/roles/:roleId`: Revoga cargo de usuário.[cite: 548]
- **Acesso por Aplicação:**
  - `PUT /users/:userId/access/:appId`: Define status de acesso do usuário na aplicação.[cite: 549]
- **API Keys:**
  - `GET /:appId/api-keys`: Lista API Keys da aplicação.[cite: 549]
  - `POST /:appId/api-keys`: Gera nova API Key.[cite: 549]
  - `DELETE /api-keys/:keyId`: Revoga uma API Key.[cite: 549]
- **Usuário Atual:**
  - `GET /user`: Retorna detalhes do usuário administrador logado.[cite: 545]

_(Detalhar parâmetros, corpos de requisição/resposta e códigos de status para cada endpoint)_
