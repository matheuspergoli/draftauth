---
title: Roteamento (Frontend)
---

O roteamento da aplicação frontend é gerenciado pelo **TanStack Router**.

- **Configuração:** `apps/web/src/router.tsx` e `apps/web/vite.config.ts` (plugin).
- **Estrutura Baseada em Arquivos:** As rotas são definidas pela estrutura de diretórios em `apps/web/src/routes/`.
- **Rotas Protegidas:** O layout do dashboard (`/dashboard/_layout.tsx`) possui um hook `beforeLoad` que verifica a autenticação antes de permitir o acesso.
- **Tipagem:** TanStack Router oferece forte tipagem para parâmetros de rota, busca (search params) e contexto.
- **Contexto:** O contexto do roteador injeta instâncias do `queryClient` e do módulo `auth` nas rotas.
