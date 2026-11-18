# Circuit artifacts — vfy-policy (official)

Downloaded from `https://agentgames.zkverify.io/circuits/`:

- `vfy-policy.wasm` (2,991,212 bytes)
  sha256 `bc0998250d2baf75b89deef5306867ffa7085a08d4f7d2caf0dd63a060b134d2`
- `vfy-policy_final.zkey` (810,586 bytes)
  sha256 `f9666a1655279ef27f7fee6d535ac8aa9e39286ac40ff6279fea87c21ab6ce41`

Verify with `sha256sum -c SHA256SUMS`.

- `verification_key.json` — exported from the `.zkey`
  (`npm run export:vk`).
- `circuit-info.json` — copy of `https://agentgames.zkverify.io/api/circuit-info`
  (`vfyPolicy.vkHash = 0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`).

The server verifies both hashes at startup and refuses to serve on a
mismatch (see `src/circuitArtifacts.js`).
