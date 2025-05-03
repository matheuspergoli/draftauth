---
title: Usuários
---

O Draft Auth gerencia usuários de forma centralizada.

- **Identidade Central:** Cada usuário possui um `userId` único no Draft Auth.
- **Email:** O email é o principal identificador único visível para o usuário.
- **Status Global:** Usuários podem ter um status `active` ou `inactive`. Um usuário inativo não pode se autenticar.
- **Identidades Externas:** Uma conta de usuário pode ter múltiplas identidades vinculadas (ex: Google, GitHub, Senha). O login por qualquer uma delas resulta no mesmo usuário central.
- **Acesso por Aplicação:** O acesso de um usuário a uma aplicação específica pode ser `enabled` ou `disabled`, independentemente do seu status global.
- **Cargos (Roles):** Cargos são atribuídos a usuários _dentro do contexto de uma aplicação específica_.
