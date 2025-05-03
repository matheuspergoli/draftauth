---
title: Aplicações
---

No Draft Auth, uma "Aplicação" representa um sistema ou serviço que utiliza o Draft Auth para autenticação e/ou autorização.

- **Identificação:** Cada aplicação possui um `appId` (único, usado como Client ID no OAuth) e um `appName` (nome amigável).
- **Gerenciamento:** Aplicações são criadas e gerenciadas através da API de Gerenciamento ou da interface web.
- **Isolamento:** Cargos (Roles) são específicos de cada aplicação. Um cargo "admin" na Aplicação A é diferente de um cargo "admin" na Aplicação B.
- **URIs de Redirecionamento:** Cada aplicação deve ter suas URIs de redirecionamento OAuth válidas configuradas.
- **API Keys:** API Keys são geradas _para_ uma aplicação específica, permitindo que o backend dessa aplicação interaja com a API de Serviço do Draft Auth.
