---
title: Service API Reference
---

Endpoints para serviços backend interagirem com o Draft Auth.

**Base Path:** `/api/service`

**Autenticação:** HMAC (veja [Autenticação HMAC](/concepts/hmac))

Endpoints:

- **Acesso do Usuário:**
  - `GET /users/:userId/access`: Verifica o status de acesso de um usuário na aplicação (determinada pela API Key usada).
  - `PUT /users/:userId/access`: Define o status de acesso (`enabled`/`disabled`) de um usuário na aplicação.
- **Gerenciamento de Cargos:**
  - `POST /roles/:userId/assign`: Atribui um cargo (pelo nome) a um usuário na aplicação.
  - `DELETE /users/:userId/revoke`: Revoga um cargo (pelo nome) de um usuário na aplicação.

_(Detalhar parâmetros, corpos de requisição/resposta e códigos de status para cada endpoint)_
