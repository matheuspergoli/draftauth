---
title: Visão Geral - Frontend
---

A aplicação web (`apps/web`) serve como interface administrativa para o Draft Auth.

- **Tecnologias:** React, TanStack Router, TanStack Query, Zustand (implícito via TanStack), shadcn/ui, Tailwind CSS.
- **Interação com API:** Utiliza `hono/client` (`@/libs/api`) para fazer chamadas tipadas para a API de Gerenciamento.
- **Autenticação:** Implementa o fluxo OAuth com o backend usando `@draftauth/core/client` e armazena tokens (`@/libs/auth`).
- **Funcionalidades:** Permite visualizar e gerenciar usuários, aplicações, cargos, API keys e configurações.
