---
title: Usuários
---

O Draft Auth gerencia usuários de forma centralizada.

- **Identidade Central:** Cada usuário possui um `userId` único no Draft Auth.[cite: 523]
- **Email:** O email é o principal identificador único visível para o usuário.[cite: 523]
- **Status Global:** Usuários podem ter um status `active` ou `inactive`. Um usuário inativo não pode se autenticar.[cite: 523, 573]
- **Identidades Externas:** Uma conta de usuário pode ter múltiplas identidades vinculadas (ex: Google, GitHub, Senha). O login por qualquer uma delas resulta no mesmo usuário central.[cite: 525]
- **Acesso por Aplicação:** O acesso de um usuário a uma aplicação específica pode ser `enabled` ou `disabled`, independentemente do seu status global.[cite: 554, 555]
- **Cargos (Roles):** Cargos são atribuídos a usuários _dentro do contexto de uma aplicação específica_.
