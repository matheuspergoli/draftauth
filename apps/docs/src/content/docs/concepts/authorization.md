---
title: Autorização (RBAC)
---

O Draft Auth utiliza um modelo de **Controle de Acesso Baseado em Função (RBAC)** que opera no nível de cada **Aplicação** registrada.

## Componentes Principais

- **Aplicações:** Representam seus sistemas distintos (ex: "Meu E-commerce", "Painel Interno"). Cada aplicação tem seu próprio conjunto isolado de cargos.
- **Cargos (Roles):** São definidos _dentro_ de cada aplicação. Um cargo como `admin` na aplicação "E-commerce" é diferente do cargo `admin` na aplicação "Painel Interno". Eles concedem permissões específicas _dentro daquela aplicação_.
- **Usuários:** Usuários são centralizados. Um mesmo usuário pode ter cargos diferentes (ou nenhum cargo) em aplicações diferentes.
- **Atribuição:** A interface de administração ou a Management API são usadas para atribuir cargos de uma aplicação específica a um usuário.
- **Verificação:** Suas aplicações backend (usando a Service API com autenticação HMAC) podem verificar se um usuário autenticado possui um determinado cargo _para aquela aplicação específica_, permitindo ou negando ações com base nisso.

## Vantagens

- **Granularidade:** Controle fino sobre as permissões em cada sistema.
- **Centralização:** Gerenciamento de permissões simplificado em um único local.
- **Flexibilidade:** Usuários podem ter níveis de acesso diferentes em sistemas diferentes.

_Veja também:_

- [Aplicações](/concepts/applications)
- [Usuários](/concepts/users)
- [API Reference: Service API (Roles)](/api/service#gerenciamento-de-cargos)
- [API Reference: Management API (Roles)](/api/management#cargos-roles)
