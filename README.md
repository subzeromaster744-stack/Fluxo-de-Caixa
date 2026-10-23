# Fluxo de Caixa

Finanças pessoais e da casa (instalável como app no celular e no computador): ganhos e despesas com gráfico mês a mês, contas marcadas como pagas, investimentos com projeção de quantos anos quiser e objetivos com prazo estimado e botão de concluído.

Cada pessoa tem usuário e senha. Os dados ficam em **salas**: o dono gera um código de convite, a outra pessoa digita o código na conta dela e aceita — a partir daí os dois veem e editam a mesma sala.

## Como funciona

- **Cloudflare Worker** (`src/index.js`) — API em `/api/*`: cadastro, login, salas, convites e dados.
- **Cloudflare D1** (`fluxo-de-caixa`) — banco com usuários, sessões, salas, membros e convites (`schema.sql`).
- **Front-end** (`public/index.html`) — uma página só, servida pelos assets do Worker.

Senhas são guardadas com PBKDF2-SHA256 (100 mil iterações, salt por usuário). A sessão fica num cookie `HttpOnly`/`Secure` por 30 dias. Códigos de convite têm 8 caracteres, valem 7 dias e só podem ser usados uma vez.

## Publicar no Cloudflare

O banco D1 já foi criado e as tabelas já existem. Para colocar no ar:

1. No painel do Cloudflare, vá em **Workers & Pages → Create → Import a repository**.
2. Escolha o repositório `fluxo-de-caixa`.
3. Deixe o comando de deploy como `npx wrangler deploy` e confirme.

Depois disso, cada `git push` na `main` publica uma versão nova automaticamente.

## Rodar no computador

```bash
npm install
npm run db:schema:local
npm run dev
```

Abra http://localhost:8787.
