---
title: Setup API Reference
---

Endpoints usados exclusivamente para a configuração inicial do Draft Auth.

**Base Path:** `/api/setup`

**Autenticação:** Baseada em `state` temporário gerado no fluxo inicial.

Endpoints:

- **Verificar Status:**
  - `GET /status`: Verifica se a configuração inicial já foi completada.
- **Inicializar:**
  - `POST /initialize`: Completa a configuração inicial, criando a aplicação principal, definindo o usuário proprietário e configurando a primeira URI de redirecionamento. Requer o `state` válido da autenticação inicial.
