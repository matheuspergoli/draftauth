---
title: Gerenciando Acesso por Aplicação
---

Controle fino sobre quais usuários podem acessar quais aplicações integradas ao Draft Auth.

**Conceitos:**

- **Status Global:** Um usuário pode estar `active` ou `inactive` globalmente no Draft Auth. Um usuário `inactive` não pode logar em _nenhuma_ aplicação.
- **Status de Acesso por Aplicação:** Independentemente do status global, o acesso de um usuário a uma _aplicação específica_ pode ser `enabled` (padrão) ou `disabled`.

**Casos de Uso:**

- **Bloquear Acesso Temporário:** Desabilitar (`disabled`) o acesso de um usuário a uma aplicação específica sem desativar sua conta inteira.
- **Acesso Gradual:** Habilitar (`enabled`) o acesso a novas aplicações para usuários existentes conforme necessário.
- **Revogação Simples:** Desabilitar o acesso a uma aplicação legada para um usuário.

**Como Gerenciar:**

1.  **Dashboard de Administração (UI):**
    - Navegue até a página de detalhes do usuário.
    - Na seção "Acesso em Aplicações", você verá uma lista de todas as aplicações.
    - Use o controle (Switch) ao lado de cada aplicação para habilitar ou desabilitar o acesso.
2.  **Management API:**
    - Use o endpoint `PUT /api/manage/users/:userId/access/:appId`.
    - Envie no corpo `{ "status": "enabled" }` ou `{ "status": "disabled" }`.
3.  **Service API:**
    - Seus serviços backend podem usar `PUT /api/service/users/:userId/access` (autenticado via HMAC) para alterar o status de acesso do usuário _na aplicação correspondente à API Key utilizada_.
    - Use `GET /api/service/users/:userId/access` para verificar o status atual.

**Importante:** Se o status de acesso de um usuário para uma aplicação não estiver explicitamente definido (`enabled` ou `disabled`), o padrão é `enabled` (permitido), desde que o status global do usuário seja `active`.
