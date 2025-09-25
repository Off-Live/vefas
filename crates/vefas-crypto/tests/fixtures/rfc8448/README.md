# RFC 8448 Vector Files (Optional)

This directory can contain JSON files with TLS 1.3 key schedule vectors used by the test harness in `key_schedule_vectors.rs`.

Tests are opt-in via environment variables:

- `RFC8448_VECTOR_FILE=/absolute/path/to/vector.json` — validate a single vector
- `RFC8448_VECTORS_DIR=/absolute/path/to/dir` — validate all `*.json` vectors in a directory

## JSON Schema (informal)

```
{
  "shared_secret": "<hex>",
  "transcript_hash": "<hex>",
  "client_application_secret": "<hex>",
  "server_application_secret": "<hex>",
  "client_application_key": "<hex>",
  "server_application_key": "<hex>",
  "client_application_iv": "<hex>",
  "server_application_iv": "<hex>",
  "master_secret": "<hex>",
  "resumption_master_secret": "<hex>"
}
```

Notes:
- Current implementation targets `TLS_AES_128_GCM_SHA256` (SHA-256; key=16 bytes; IV=12 bytes)
- Hex strings are lowercase or uppercase (case-insensitive)
- `transcript_hash` should be the relevant hash per RFC 8446 for the stage being validated (32 bytes for SHA-256)

## Example (template)

```
{
  "shared_secret": "1f2e3d4c....",
  "transcript_hash": "9a8b7c6d....",
  "client_application_secret": "...",
  "server_application_secret": "...",
  "client_application_key": "...16 bytes...",
  "server_application_key": "...16 bytes...",
  "client_application_iv": "...12 bytes...",
  "server_application_iv": "...12 bytes...",
  "master_secret": "...32 bytes...",
  "resumption_master_secret": "...32 bytes..."
}
```

Place official values from RFC 8448 or generated vectors from a trusted reference.
