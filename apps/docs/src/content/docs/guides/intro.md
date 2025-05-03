---
title: O que é Draft Auth?
---

DraftAuth é uma plataforma **centralizada** de identidade e acesso de **código aberto**, projetada para simplificar e unificar a autenticação e autorização em múltiplas aplicações[cite: 581].

## O Problema

Gerenciar usuários, logins e permissões separadamente para cada aplicação pode se tornar complexo e propenso a erros rapidamente. Manter a consistência e a segurança entre diferentes sistemas é um desafio constante.

## A Solução Draft Auth

DraftAuth aborda esses desafios oferecendo[cite: 576]:

- **Ponto Único de Gerenciamento:** Administre todos os usuários, suas credenciais e permissões em um só lugar[cite: 579].
- **Autenticação Flexível:** Suporta múltiplos métodos de login, como **Google**, **GitHub** e **Email/Senha**, com verificação de email[cite: 577].
- **Controle de Acesso Granular (RBAC):** Defina **Aplicações**, crie **Cargos (Roles)** específicos para cada uma e atribua permissões detalhadas aos usuários, controlando o que eles podem fazer em cada sistema[cite: 578].
- **Gerenciamento de Identidades:** Vincule várias identidades externas (Google, GitHub) a uma única conta de usuário central[cite: 579].
- **API Segura para Serviços:** Permite que seus backends interajam com o sistema de forma segura para gerenciar acesso e cargos programaticamente, usando **API Keys** e autenticação **HMAC**[cite: 580, 541].

## Para Quem é?

- Desenvolvedores construindo múltiplas aplicações que precisam compartilhar usuários.
- Equipes que buscam padronizar e centralizar a gestão de identidade e acesso.
- Projetos que necessitam de um controle de permissões granular por aplicação.

## Próximos Passos

- Siga o **[Guia Rápido](/guides/quickstart)** para colocar o Draft Auth para rodar.
- Explore os **[Conceitos Fundamentais](/concepts/authentication)** para entender a arquitetura.
- Consulte a **[Referência da API](/api/management)** para detalhes sobre os endpoints.
