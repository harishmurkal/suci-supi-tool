# Profile-E Reference (Group-B2: Nested Hybrid)
Based on 3GPP TR 33.704 Solution #20

## Core Idea

This is a **nested hybrid encryption scheme**, NOT a parallel hybrid.

- ECC and PQC do NOT combine secrets
- Instead:
  - ECC protects PQ ciphertext
  - PQC protects SUPI

## UE Flow

Input:
- SUPI (m)
- HN public key:
  - ECC public key (ekE)
  - ML-KEM public key (ekM)

Steps:

1. Generate ECC ephemeral keypair:
   (ek_ep, dk_ep)

2. Compute ECC shared key:
   k1 = ECDH(dk_ep, ekE)

3. ML-KEM encapsulation:
   (k0, c0) = ML-KEM(ekM)

4. Encrypt PQ ciphertext using ECC key:
   c2 = AE_Encrypt(k1, c0)

5. Encrypt SUPI using PQ key:
   c3 = AE_Encrypt(k0, SUPI)

6. Output:
   SUCI = c1 || c2 || c3

Where:
- c1 = ECC ephemeral public key
- c2 = encrypted PQ ciphertext
- c3 = encrypted SUPI

## HN Flow

Input:
- SUCI = (c1, c2, c3)
- HN private keys:
  - ECC private key (dkE)
  - ML-KEM private key (dkM)

Steps:

1. Recover ECC shared key:
   k1 = ECDH(c1, dkE)

2. Decrypt PQ ciphertext:
   c0 = AE_Decrypt(k1, c2)

3. ML-KEM decapsulation:
   k0 = ML-KEM_Decap(dkM, c0)

4. Decrypt SUPI:
   SUPI = AE_Decrypt(k0, c3)

## Key Properties

- No combiner
- No shared KDF across PQC + ECC
- Two independent encryption layers

## Pros to preserve

- Strong separation of trust domains
- Survives PQC break (ECC still protects c0)
- Survives ECC break (PQC still protects SUPI)
- No complex combiner design

## Cons to be aware

- More complex processing chain
- Two encryption layers
- Larger payload
- Not standard hybrid KEM model