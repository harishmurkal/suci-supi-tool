# Profile-F Reference (Group-C: Wrapper Hybrid)
Based on 3GPP TR 33.704 Solution #23

## Core Idea

This is a **compatibility wrapper hybrid**.

- Keeps ECIES unchanged
- Adds PQC protection ONLY to ECC ephemeral key

## UE Flow

1. Generate ECC ephemeral keypair:
   (eph_pub, eph_priv)

2. Compute shared secret:
   ss = ECDH(eph_priv, HN_pub)

3. Derive keys:
   encKey, macKey

4. Encrypt SUPI:
   ciphertext = AES(encKey, SUPI)

5. Compute MAC:
   mac = MAC(macKey, ciphertext)

6. PQC encapsulation:
   encrypted_eph_key = ML-KEM_Encrypt(eph_pub)

7. Output:
   SUCI = encrypted_eph_key || ciphertext || mac

## HN Flow

1. PQC decapsulation:
   eph_pub = ML-KEM_Decrypt(encrypted_eph_key)

2. Compute shared secret:
   ss = ECDH(HN_priv, eph_pub)

3. Derive keys:
   encKey, macKey

4. Verify MAC

5. Decrypt SUPI

## Key Properties

- ECIES remains unchanged
- PQC only protects ECC ephemeral key

## Pros to preserve

- Minimal change to existing ECIES
- Easy migration path
- Low implementation complexity
- Backward compatibility friendly

## Cons to be aware

- Not true hybrid security
- Depends heavily on ECC correctness
- PQC only protects ephemeral key, not full data