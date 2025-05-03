---
title: Protegendo sua API com HMAC
---

Como seu serviço backend pode fazer chamadas seguras para a API de Serviço do Draft Auth.

**Opção 1: Usar `@draftauth/client` (Recomendado)**

Esta biblioteca Node.js simplifica o processo.

1.  **Instalação:**
    ```bash
    pnpm add @draftauth/client # Ou npm/yarn
    ```
2.  **Uso:**

    ```typescript
    import { createDraftauthServiceClient } from "@draftauth/client";

    const client = createDraftauthServiceClient({
      apiUrl: "YOUR_DRAFTAUTH_API_URL", // Ex: http://localhost:3000
      apiKeyId: "YOUR_API_KEY_ID", // Ex: sk_myapp_...
      apiSecretKey: "YOUR_SECRET_KEY", // O segredo obtido na criação da key
    });

    async function checkUserAccess(userId: string) {
      try {
        const status = await client.getUserAccess({ userId });
        console.log(`User ${userId} access status: ${status}`);
        return status;
      } catch (error) {
        console.error("Error checking user access:", error);
        // Lidar com o erro (ex: usuário não encontrado, chave inválida)
      }
    }

    // Chamar outras funções: client.setUserAccess, client.assignRoleToUser, etc.
    ```

**Opção 2: Implementação Manual (Exemplo Conceitual)**

Se não estiver usando Node.js ou o client, você precisará implementar a lógica HMAC manualmente:

1.  **Obtenha** `apiKeyId` e `apiSecretKey`.
2.  **Prepare a Requisição:**
    - Defina o Método (GET, POST, etc.).
    - Construa a URL completa (com query params).
    - Obtenha o Timestamp atual (ms).
    - **Se POST/PUT/PATCH:** Calcule o hash SHA-256 do corpo (body), converta para base64 e crie o header `Digest: SHA-256=<hash-base64>`.
    - **Se GET/DELETE:** O `Digest` pode ser omitido ou vazio.
3.  **Construa a String para Assinar:**
    ```
    METHOD\n
    /path?query\n
    TIMESTAMP\n
    DIGEST_HEADER_VALUE
    ```
    _Use `\n` como separador. Use o valor completo do header `Digest` (incluindo `SHA-256=`)._
4.  **Calcule a Assinatura HMAC:**
    - Use HMAC-SHA256 com o `apiSecretKey` sobre a "String para Assinar".
    - Converta o resultado para base64.
5.  **Monte os Headers:**
    - `X-Api-Key-Id`: Seu `apiKeyId`.
    - `X-Request-Timestamp`: O timestamp usado.
    - `X-Signature`: A assinatura HMAC calculada em base64.
    - `Digest`: O header `Digest` (se aplicável).
    - `Content-Type: application/json` (se houver corpo).
    - `Accept: application/json`.
6.  **Envie a Requisição:** Faça a chamada HTTP com os headers e corpo montados.
