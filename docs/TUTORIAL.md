# xahau-mcp — A Plain-English Guide

**What this is:** xahau-mcp connects an AI assistant (like Claude) to the **Xahau** network.
Once it's set up, you stop clicking around explorers and copying cryptic hex codes — you just
**ask, in plain English**, and your assistant does the on-chain work for you.

It's **read-only and holds no keys** — it can look things up, explain them, and *prepare*
transactions, but it can never move your money or sign anything. Safe to point at any account.

> New to the words? A **Hook** is a small program that lives on a Xahau account and runs on its
> transactions (think: an automatic rule, like "reject any payment over 100 XAH"). A **URIToken**
> is Xahau's NFT. **Burn2Mint** is how value bridges in from the XRP Ledger. You don't need to
> know any of this — just ask.

---

## Setting it up (one time)

You need **Node.js 20+** (one-time: [nodejs.org](https://nodejs.org)). Then install xahau-mcp:

```bash
npm install -g github:Hugegreencandle/xahau-mcp
```

That gives you a command called `xahau-mcp`. Test it works:

```bash
xahau-mcp --smoke
```

You should see a health line ending in `live mainnet read: … OK`. Now connect it to whatever you use:

### Claude Desktop

1. Open **Settings → Developer → Edit Config** (or edit the file directly):
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
2. Add xahau-mcp under `mcpServers`:
   ```json
   {
     "mcpServers": {
       "xahau": { "command": "xahau-mcp" }
     }
   }
   ```
   (If `xahau-mcp` isn't found, use the npx form instead: `"command": "npx", "args": ["-y", "github:Hugegreencandle/xahau-mcp"]`.)
3. **Fully quit and reopen Claude Desktop.** You'll see a 🔌/tools icon — "xahau" should be listed.

### Claude Code (CLI)

One command:

```bash
claude mcp add xahau -- xahau-mcp
```

(or `claude mcp add xahau -- npx -y github:Hugegreencandle/xahau-mcp`). Check it with `claude mcp list`. That's it — start a session and ask away.

### Codex CLI

Add it to `~/.codex/config.toml`:

```toml
[mcp_servers.xahau]
command = "xahau-mcp"
# or:  command = "npx"
#      args = ["-y", "github:Hugegreencandle/xahau-mcp"]
```

Restart Codex. (MCP config formats move fast — if this differs, check your Codex version's MCP docs; the command to run is always just `xahau-mcp`.)

### Any other MCP client / local testing

xahau-mcp is a standard **stdio MCP server** — any MCP-compatible client connects by running the
command `xahau-mcp` (or `node /path/to/xahau-mcp/dist/index.js`). To explore the tools yourself with
no chat client, use the official MCP Inspector:

```bash
npx @modelcontextprotocol/inspector xahau-mcp
```

It opens a local UI where you can click through and run every tool by hand.

### Confirm it's connected

Ask your assistant: **"What's the current Xahau transaction fee?"** If it answers with a real number,
you're live. From here, everything below is just *typing a question.*

---

## What you can do (in everyday terms)

- **Understand any Hook** — paste a Hook (or just give an account) and ask "what does this do?
  is it safe?" It explains it in English and flags anything dangerous.
- **Check before you sign** — about to approve something in Xaman? Paste it and ask "what am I
  agreeing to?" It warns you about the scary stuff *before* you tap confirm.
- **Look up anything on-chain** — balances, what's installed on an account, NFTs owned, trustlines,
  recent transactions, current fees — all in plain language.
- **Decode the cryptic bits** — those long hex strings (HookOn bitmaps, amounts, Burn2Mint proofs,
  addresses) become readable.
- **Build a starter Hook** — describe what you want ("block payments over 100 XAH") and get
  working starter code.
- **Prepare a transaction safely** — it fills in the technical fields and hands you an *unsigned*
  transaction to sign yourself, offline. It never signs for you.

---

## Cool things to try (just type these)

**1. "Is this Hook safe to install?"**
> *Paste a Hook's code.* → Your assistant runs a full security check (missing safety exits,
> infinite loops, dangerous permissions, over-broad triggers), *simulates the actual code*, and
> tells you whether it's safe — before it ever touches your account.

**2. "What does the Hook on account r… actually do?"**
> → It pulls the Hook off that account and explains it: *"This is a payment firewall — it rejects
> incoming payments unless they include a destination tag."* No code-reading required.

**3. "I'm about to sign this in my wallet — what am I really agreeing to?"**
> *Paste the transaction.* → *"You'd be authorizing account r… to install a Hook that runs code
> on every transaction. ⚠ Review it first. ⚠ It has no expiry, so the signed version never goes
> stale."* A plain-English safety brief before you commit.

**4. "Write me a Hook that blocks any payment over 100 XAH."**
> → You get ready-to-compile starter code, plus the steps to build and (importantly) *test* it
> before going live.

**5. "Did this Hook upgrade add anything risky compared to the old version?"**
> *Give it both versions.* → *"The new version gained the ability to send its own transactions and
> write to another account's data — review before upgrading."*

**6. "Show me everything about account r…"**
> → Balance, what Hooks are installed and what they react to, NFTs owned, trustlines, open trades —
> a full readable snapshot.

**7. "What transaction types does this HookOn code react to?"**
> *Paste the cryptic `FFFFFF…` string.* → *"It fires on Payments and Invokes only."* (This one is
> notoriously easy to get wrong by hand — it's inverted. Let the tool do it.)

**8. "Decode this Burn2Mint proof for me."**
> *Paste the blob from an Import transaction.* → *"This burns 1,000 XAH on the source chain to mint
> it on Xahau, validated by N validators, from source ledger #…"*

**9. "Run this Hook against a test payment of 50 XAH and tell me if it would accept or reject."**
> → It runs the *real* Hook code locally against your made-up transaction and reports the actual
> decision, plus a step-by-step trace — no test network or node needed.

**10. "Is my account safe against future quantum computers?"**
> → It grades your account's key setup and gives you a readiness score with recommendations.

**11. "What's the current Xahau transaction fee?"** / **"What NFTs does this account own?"**
> → Quick, plain-language lookups whenever you need them.

---

## The golden rule

xahau-mcp is **read-only**. It will happily *prepare* a transaction for you, but the last step —
**signing** — always happens in your own wallet, with your own keys, that the tool never sees. When
in doubt, ask it: *"does this move any of my money?"* (The answer is always no — it can't.)

And before you ever install a Hook or sign anything important: **ask it to check first.** That's
the whole point.

---

*xahau-mcp is open source (MIT). Found a bug or want a feature? → the
[GitHub repo](https://github.com/Hugegreencandle/xahau-mcp).*
