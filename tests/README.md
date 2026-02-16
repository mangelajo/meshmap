# MeshMap Tests

This directory contains tests for the meshmap packet decryption functionality.

## Test Coverage

### ✅ What's Tested

#### Channel Secret Derivation (`TestChannelSecretDerivation`)
- ✓ Deriving AES-128 keys for public channels (#general, #public)
- ✓ Deterministic key generation (same channel = same key)
- ✓ Different channels produce different keys

#### ECDH Shared Secret Computation (`TestSharedSecretComputation`)
- ✓ Computing X25519 shared secrets with orlp/ed25519 private key format
- ✓ Using only first 32 bytes (scalar), not nonce seed
- ✓ Verified against real device keys

#### Group Message Decryption (`TestGroupMessageDecryption`)
- ✓ Decryption structure for #general, #public channels
- ✓ Failure on unknown/wrong channel names

#### Private Message Decryption (`TestPrivateMessageDecryption`)
- ✓ TXT_MSG packet decryption
- ✓ Metadata parsing (timestamp, message type)
- ✓ Rejection of messages to wrong recipients

#### End-to-End Tests (`TestEndToEndDecryption`)
- ✓ Real private key derivation to device public key
- ⚠️  Real packet decryption (skipped - needs test keys)

#### Edge Cases (`TestEdgeCases`)
- ✓ Empty payloads
- ✓ Invalid key lengths
- ✓ Malformed packets
- ✓ Unsupported packet types

#### Message Format Parsing (`TestMessageFormatParsing`)
- ✓ Timestamp parsing (uint32 little-endian)
- ✓ Message type byte
- ✓ Handling messages without metadata

## Running Tests

### All tests
```bash
uv run pytest tests/
```

### Specific test file
```bash
uv run pytest tests/test_crypto.py -v
```

### With coverage report
```bash
uv run pytest tests/ --cov=meshmap --cov-report=html
```

### Watch mode (requires pytest-watch)
```bash
uv run ptw tests/
```

## Test Data

### Real Keys Used in Tests
- **Device 0x33 (EA4IPW)**: Private key from serial export
  - Public key: `33cd80e38931d731...719f4c09`
  - Used to verify key derivation works correctly

### Adding New Test Cases

To add tests with real captured packets:

1. **Capture a packet** with known plaintext:
   ```bash
   uv run meshmap /dev/ttyUSB0 --sniff 60 --debug
   ```

2. **Extract the data**:
   - Packet type (e.g., TXT_MSG, GRP_TXT)
   - Payload hex
   - Expected plaintext
   - Timestamp

3. **Add test case**:
   ```python
   def test_decrypt_specific_message(self):
       """Test decrypting a specific captured message."""
       result = decrypt_packet_payload(
           packet_type="TXT_MSG",
           payload_hex="50ad6f7a...",  # From capture
           private_key_hex="...",       # Test key (not real!)
           contacts=test_contacts,
           debug=False
       )

       assert result['success'] is True
       assert result['plaintext'] == "Expected message"
   ```

### Security Note

**Do NOT commit real private keys to the repository!**

For CI/CD tests, generate test keypairs specifically for testing:

```python
import nacl.signing

# Generate test keypair
signing_key = nacl.signing.SigningKey.generate()
private_key = signing_key.encode() + signing_key.verify_key.encode()
public_key = signing_key.verify_key.encode()

print(f"Test private key: {private_key.hex()}")
print(f"Test public key: {public_key.hex()}")
```

## What's Protected

These tests ensure that future changes don't break:

1. ✅ **orlp/ed25519 key format handling**
   - First 32 bytes = scalar (used in ECDH)
   - Last 32 bytes = nonce seed (not used in ECDH)

2. ✅ **Ed25519 → X25519 conversion**
   - Correct public key derivation
   - Correct ECDH shared secret computation

3. ✅ **Message format parsing**
   - [Timestamp: 4 bytes][Type: 1 byte][Message text]
   - Little-endian timestamp decoding
   - UTF-8 message decoding

4. ✅ **Channel encryption**
   - SHA-256(channel_name)[:16] = AES-128 key
   - Channel-based group message decryption

5. ✅ **MAC verification**
   - HMAC-SHA256 truncated to 2 bytes
   - Rejection of tampered/wrong messages

## Coverage

Current test coverage: ~49% of crypto.py

Areas not yet covered:
- ANON_REQ decryption (requires test data)
- Full GRP_TXT/GRP_DATA with real packets
- All error paths in MAC verification

## CI/CD

To run tests in CI:

```yaml
- name: Run tests
  run: |
    uv pip install pytest pytest-cov
    uv run pytest tests/ --cov=meshmap
```

## Contributing

When adding new crypto features:
1. Add tests FIRST (TDD)
2. Ensure tests use test keys (not real ones)
3. Document the packet format being tested
4. Run full test suite before committing
