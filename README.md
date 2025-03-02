## Python implementation of Groth 21 NiDKG

This road map layers all the features from simplest to most advanced, mirroring roughly how Groth 21 NiDKG evolves from basic ElGamal encryption to a full forward‐secure, verifiable distributed key generation protocol:

1. Shamir Secret Sharing/Reconstruction

2. Shamir Secret Resharing

3. Single‐receiver chunked ElGamal

    What you’ve learned:
        Plain ElGamal in the source group G1G1​.
        How to split a large secret (like a share ss) into multiple small “chunks” so each chunk can be discrete‐logged (baby‐step–giant‐step).

    This establishes the fundamental encryption/decryption mechanism.

4. Multi‐receiver encryption

    What you’ve learned:
        Re‐use the same ephemeral randomness rr (and ephemeral exponents) to encrypt shares to multiple users in the same ciphertext.
        Groth 21 NiDKG must distribute Shamir shares to many parties simultaneously; multi‐receiver encryption is key to efficiency.

    What to learn/implement:
        How to build a ciphertext ({Ci},…)({Ci​},…) that includes an ElGamal component for each recipient ii.
        The same chunking approach is applied for each user’s share chunk.

5. Forward‐securing the encryption

    Why next?
        In NiDKG, each node’s private key evolves in time (epochs).
        If a node is compromised after some epoch, the attacker shouldn’t learn old shares from prior epochs.

    Key steps:
        Turn your single/multi‐receiver encryption into a tree‐based or hierarchical approach, where an epoch ττ corresponds to a leaf.
        Integrate the ephemeral “leaf key” logic so that the user updates dkτ→dkτ+1dkτ​→dkτ+1​ and discards old keys.

    This is the step that really uses pairings in a deeper sense (to do hierarchical identity or binary‐tree–based derivation).

6. Proof of chunking (“proof of smallness”)

    Why next?
        Once you have multi‐user (or single‐user) chunked encryption, you want to publicly prove that each chunk is small enough to be found by baby‐step–giant‐step.
        Otherwise, a dishonest dealer could embed something huge that no one can decrypt.

    Key steps:
        Construct a zero‐knowledge range‐type proof (or “approximate range proof”) showing Δ⋅mj∈Δ⋅mj​∈ “small range,” or that each chunk is ≤B−1≤B−1.
        This ensures that the ciphertext is “decryptable in feasible time.”

7. Proof of polynomial validity (“t‐polynomial” check)

    Why next?
        In NiDKG, the shares each user receives come from a polynomial a(x)a(x).
        You want a publicly verifiable guarantee that each share is consistent with the same polynomial.

    Key steps:
        Construct a zero‐knowledge proof that each share is a valid evaluation of a polynomial of degree t-1.
        This ensures that the shares are consistent and can be used to reconstruct the secret.

8. Distributed key generation (DKG)

    Why next?
        To eliminate the need for a trusted dealer, you want to generate the secret and shares in a distributed manner.

    Key steps:
        Implement a protocol where each participant contributes to the generation of the secret and shares.
        Ensure that the protocol is secure against malicious participants and that the generated shares are verifiable.

9. Forward-secure DKG

    Why next?
        Combine forward security with distributed key generation to ensure that the system remains secure even if participants are compromised over time.

    Key steps:
        Integrate the forward-secure encryption scheme with the DKG protocol.
        Ensure that the keys evolve securely and that old shares cannot be compromised.

10. Verifiable secret sharing (VSS)

    Why next?
        To ensure that the shares distributed in the DKG protocol are correct and consistent.

    Key steps:
        Implement a verifiable secret sharing scheme where each participant can verify the correctness of their share.
        Ensure that the scheme is secure against malicious participants and that the shares can be used to reconstruct the secret.

11. Full NiDKG protocol

    Why next?
        Combine all the previous steps to implement the full NiDKG protocol, which provides forward-secure, verifiable distributed key generation.

    Key steps:
        Integrate all the components (forward-secure encryption, DKG, VSS) into a single protocol.
        Ensure that the protocol is secure, efficient, and scalable.




## TL;DR: Recommended Sequence

- Shamir Secret Sharing/Reconstruction (done).
- Shamir Secret Resharing.
- Single‐receiver chunked encryption (done).
- Multi‐receiver encryption logic.
- Forward secrecy / “tree‐based” key updates.
- Proof of chunking (NIZK that each chunk is small).
- Proof of polynomial membership in Shamir shares.
- Proof of possession of secret exponents.
- Assemble everything into the final NiDKG with non‐interactive distribution and verifiability.

That path most closely mirrors how Groth 21 NiDKG layering evolves.

## Running the tests
### run all tests
```
python -m pytest
```


### Or if you want to run the tests individually:
```
python -m encryption.keygen_test
python -m encryption.enc_secret_shares_test
python -m encryption.chunking_test
python -m encryption.bsgs_test
python -m shamir_test
```