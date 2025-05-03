---
title: Gerenciamento de Estado (Frontend)
---

O estado da aplicação frontend é gerenciado principalmente pelo **TanStack Query**.

- **Busca de Dados:** As queries (`@/shared/queries`) definem como buscar dados da API de Gerenciamento.[cite: 635]
- **Cache:** TanStack Query gerencia o cache de dados, revalidação e otimizações.
- **Mutações:** Ações que modificam dados (criar, atualizar, deletar) são feitas usando `useMutation` (`@/features/.../hooks`).[cite: 605, 606, 607, 608]
- **Invalidação:** Mutações bem-sucedidas geralmente invalidam queries relacionadas para buscar dados atualizados (configurado no `queryClient`).[cite: 619, 620]
- **Estado Local:** Estado simples de componentes é gerenciado com `React.useState` ou `React.useReducer` quando apropriado.
- **Estado de Autenticação:** Gerenciado pelo módulo `@/libs/auth`.
