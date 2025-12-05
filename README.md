# Simplified ChaCha Stream Cipher – Hand-in Packet

This packet documents the educational ChaCha stream cipher implementation and the accompanying Flask UI so it can be graded easily. Everything runs locally with Python; no external services are required.

## Project contents
- `chacha.py` – core simplified ChaCha20 implementation plus a demonstration `main()` that prints test vectors and verification runs.
- `app.py` – Flask wrapper that captures the `chacha.py` demo output and serves it as HTML.
- `templates/index.html` – simple page showing the captured output with styling and a refresh button.
- `requirements.txt` – Python dependency list (Flask only).

## Quickstart (Windows-friendly)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py        # serve on http://localhost:8000
```
Use `set PORT=8080` (PowerShell: `$env:PORT='8080'`) before running `python app.py` to change the port.

## What the demo shows
The bundled `main()` in `chacha.py` prints:
- Key/nonce generation with correct sizes (32-byte key, 12-byte nonce).
- Quarter-round example with known input and output words.
- Initial 4x4 state matrix derived from the constants, key, nonce, and counter.
- Encryption/decryption of two messages (long and short) with success checks.
- Keystream consistency check (same key+nonce+counter gives identical ciphertext for the same plaintext).

## How the cipher works (summary)
ChaCha uses a 4x4 matrix of 32-bit words. Each 64-byte block is produced by applying 20 rounds (10 double rounds) of mixing, then adding the original state and outputting little-endian words.

Quarter round (operates on words a, b, c, d):
$$
\begin{aligned}
a &= (a + b) \bmod 2^{32};\\
d &= (d \oplus a) \lll 16;\\
c &= (c + d) \bmod 2^{32};\\
b &= (b \oplus c) \lll 12;\\
a &= (a + b) \bmod 2^{32};\\
d &= (d \oplus a) \lll 8;\\
c &= (c + d) \bmod 2^{32};\\
b &= (b \oplus c) \lll 7.
\end{aligned}
$$

Double round structure:
- Column rounds on words (0,4,8,12), (1,5,9,13), (2,6,10,14), (3,7,11,15).
- Diagonal rounds on words (0,5,10,15), (1,6,11,12), (2,7,8,13), (3,4,9,14).

Pseudocode for one block:
```
state = constants || key[0..7] || counter || nonce[0..2]
working = copy(state)
for 10 double rounds:
    apply column quarter rounds
    apply diagonal quarter rounds
for i in 0..15: working[i] = (working[i] + state[i]) mod 2^32
return little_endian_bytes(working)
```

Stream cipher usage:
- Key stream blocks are XORed with plaintext to produce ciphertext: `cipher = plaintext xor keystream`.
- Decryption is identical: `plaintext = cipher xor keystream`.
- Never reuse the same (key, nonce, counter) for different messages.

## Web UI notes
- `app.py` calls `get_demo_output()`, which runs `chacha.main()` and captures stdout.
- On each page load (`/`), the latest demo output is rendered into `templates/index.html`.
- Default host/port: `0.0.0.0:8000`; override with `PORT` env var.

## How to run just the console demo
```powershell
python chacha.py
```
You should see section headers, test vectors, ciphertext hex strings, and success checks marked as `True`.

## Expected key points for grading
- Correct sizes: 32-byte key, 12-byte nonce, 32-bit counter, 64-byte block output.
- Quarter-round matches the reference transformation and shows the expected example output.
- Double-round ordering: columns first, then diagonals, repeated 10 times (20 rounds total).
- Keystream added back to the original state before serialization.
- Encryption and decryption symmetry demonstrated with two messages and a consistency test.
- Web UI cleanly displays the captured output and refreshes on demand.

## Security and scope (educational)
- This is an educational simplification; it does not aim for constant-time guarantees.
- Do not reuse (key, nonce) pairs; counters must be unique per block under a given pair.
- For real security, use a vetted library (e.g., `cryptography`'s ChaCha20-Poly1305) and add authentication.

## Troubleshooting
- If Flask is missing, run `pip install -r requirements.txt` inside the virtualenv.
- If the port is busy, set `PORT` to an unused number (e.g., 8080) before running `python app.py`.
- If output is empty in the browser, check the server log for Python exceptions.

## Suggested talking points (for oral defense)
- Explain how the quarter round mixes diffusion and confusion across 32-bit words.
- Describe why nonces are 96 bits and why counters must not wrap for the same key/nonce.
- Point out the keystream consistency test and how it validates determinism.
- Clarify that the web layer simply surfaces the console demo; cryptography stays in `chacha.py`.
