---
title: Autenticação HMAC
---

A API de Serviço (`/api/service`) utiliza autenticação HMAC (Hash-based Message Authentication Code) para garantir a segurança e integridade das requisições feitas pelos backends das suas aplicações.

**Como Funciona:**

1.  **API Key:** Sua aplicação backend precisa de um `apiKeyId` e um `apiSecretKey` gerados pelo Draft Auth.
2.  **Timestamp:** Cada requisição deve incluir um header `X-Request-Timestamp` com o timestamp Unix (em milissegundos) atual. O Draft Auth rejeita requisições com timestamps muito antigos para prevenir ataques de replay.
3.  **Digest (para POST/PUT/PATCH):** Para requisições com corpo (body), um header `Digest` contendo o hash SHA-256 do corpo (em base64) deve ser incluído (`SHA-256=<hash>`). Isso garante a integridade do corpo da requisição.
4.  **String para Assinar:** Uma string específica é construída combinando:
    - Método HTTP (ex: `POST`)
    - Caminho e Query String (ex: `/api/service/users/123/access?param=1`)
    - Valor do header `X-Request-Timestamp`
    - Valor do header `Digest` (mesmo que vazio para GET/DELETE)
5.  **Assinatura HMAC:** A "String para Assinar" é assinada usando HMAC-SHA256 com o `apiSecretKey` da sua aplicação. O resultado (em base64) é enviado no header `X-Signature`.
6.  **Validação no Servidor:** O Draft Auth:
    - Busca o `apiSecretKey` correspondente ao `apiKeyId` recebido.
    - Reconstrói a "String para Assinar" usando os headers recebidos.
    - Recalcula a assinatura HMAC usando o `apiSecretKey` armazenado.
    - Compara (de forma segura contra timing attacks) a assinatura calculada com a assinatura recebida (`X-Signature`).
    - Verifica o `Digest` se aplicável.
    - Verifica o `Timestamp` para evitar replay attacks.

**Biblioteca Cliente:**

O pacote `@draftauth/client` simplifica esse processo, cuidando da geração dos headers e da assinatura HMAC automaticamente.
