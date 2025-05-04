---
title: Rate Limiting
description: Como o Draft Auth protege a API contra abuso usando Rate Limiting com Upstash Redis.
---

Para garantir a estabilidade e proteger funcionalidades sensíveis contra abuso, o Draft Auth implementa Rate Limiting utilizando o [Upstash Redis](https://upstash.com/redis) (ou outro Redis compatível) e a biblioteca [`@upstash/ratelimit`](https://github.com/upstash/ratelimit).

## Implementação

A lógica de configuração do Rate Limiter está no módulo `apps/api/src/libs/rate-limit.ts`. Este módulo:

1.  Inicializa um cliente Redis usando as variáveis `env.REDIS_URL` e `env.REDIS_TOKEN`.
2.  Define duas instâncias de `Ratelimit` com cache efêmero em memória e algoritmo **Sliding Window**:
    - **IP Limiter (`ipRateLimiterInstance`):** Limita por endereço IP, permitindo **3 requisições por janela de 60 segundos**. Usa o prefixo `ratelimit_ip` no Redis.
    - **Email Limiter (`emailRateLimiterInstance`):** Limita por endereço de email, permitindo **3 requisições por janela de 10 minutos**. Usa o prefixo `ratelimit_email` no Redis.
3.  Exporta duas funções auxiliares:
    - `limitIpRate(identifier: string)`: Verifica o limite para um IP.
    - `limitEmailRate(identifier: string)`: Verifica o limite para um email.
    - **Importante:** Estas funções retornam apenas `{ success: boolean, remaining: number }`. Em caso de erro na comunicação com o Redis, elas retornam `{ success: true, remaining: 0 }` por padrão (devido ao `try/catch`), o que significa que o rate limit pode ser bypassado se o Redis estiver indisponível.

## Uso Atual

- O Rate Limiting **é aplicado exclusivamente dentro da função `sendCode` do `PasswordProvider`** (no arquivo `libs/auth.ts`). Ele **não** é aplicado automaticamente a outras rotas da API como `/api/manage`, `/api/service` ou `/api/setup`.
- As funções `limitIpRate` e `limitEmailRate` são injetadas no contexto Hono para cada requisição.
- A função `sendCode`:
  1.  Obtém as funções `limitIpRate` e `limitEmailRate` do contexto.
  2.  Chama `limitIpRate` com o IP do requisitante.
  3.  Chama `limitEmailRate` com o email fornecido.
  4.  Verifica o resultado `success` de ambas as chamadas.
  5.  Se qualquer uma falhar (`!success`), **lança uma `HTTPException` com status 429 (Too Many Requests)**, impedindo o envio do email.

## Configuração

Requer a configuração das variáveis de ambiente do Redis:

- `REDIS_URL`
- `REDIS_TOKEN`

_Veja também:_

- [Variáveis de Ambiente](/guides/environment-variables#api-appsapi) (Seção Redis)
- [Configuração de Email](/guides/email-setup) (Onde o rate limit é aplicado)
