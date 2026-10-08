# AI Conversation Log
CSCE 465/765 - Homework 2
AI Tool: ChatGPT (OpenAI)
Date: October 7, 2026

This file contains the relevant AI interactions used while completing
Homework 2. Unrelated conversation and private information have been omitted.

---

## Interaction 1 - Understanding the Assignment

Prompt:
Help me understand the requirements for Homework 2 and what files I need
to create for each task.

AI Response:
Explained that the assignment is divided into four main tasks:

- Task 1 demonstrates weaknesses of AES-CTR when encryption is used
  without integrity protection.
- Task 2 implements an authenticated finite-field Diffie-Hellman
  handshake using RSA-PSS signatures, nonces, and the ffdhe3072 group.
- Task 3 implements an encrypt-then-MAC record layer using AES-256-CTR
  and HMAC-SHA-256.
- Task 4 tests attacks including ciphertext modification, header
  modification, replay, reflection, and authentication failures.

Also identified the required supporting files such as baseline_ctr.py,
handshake.py, secure_record.py, ffdhe3072.pem, tests/, README.md,
AI_USAGE.md, and the report.

---

## Interaction 2 - Lab Preparation and ffdhe3072

Prompt:
Do I have ffdhe3072.pem, the group file generated in Lab Preparation?

AI Response:
Explained how to check the hw2 directory for ffdhe3072.pem and verify
that the generated Diffie-Hellman parameters correspond to the
ffdhe3072 group using OpenSSL.

---

## Interaction 3 - AES-CTR Baseline

Prompt:
Help me implement and understand the AES-CTR baseline for Task 1,
including the bit-flipping and replay demonstrations.

AI Response:
Explained how AES-CTR encrypts plaintext using a keystream and why
changing ciphertext bytes can predictably modify the corresponding
plaintext bytes when there is no MAC.

Explained the XOR relationship:

    C = P XOR K
    C' = C XOR P XOR P'

where P is the original plaintext and P' is the desired modified
plaintext.

Also explained that encryption alone does not provide replay
protection, so replaying the same ciphertext can cause the receiver to
process the same command again.

---

## Interaction 4 - Authenticated Diffie-Hellman Handshake

Prompt:
Help me implement and debug the authenticated Diffie-Hellman handshake
for Task 2.

AI Response:
Helped structure the handshake around the assignment requirements,
including:

- Loading the ffdhe3072 group parameters
- Generating fresh ephemeral DH private/public values
- Generating 16-byte nonces
- Building a canonical length-prefixed transcript
- Including identities, roles, nonces, and DH public values
- Hashing the transcript with SHA-256
- Signing the transcript hash using RSA-PSS
- Verifying the peer signature and expected identity
- Computing the shared Diffie-Hellman secret
- Deriving separate directional encryption and MAC keys
- Deriving the session identifier

The response also explained why signing the transcript protects against
basic man-in-the-middle and reflection attacks.

---

## Interaction 5 - Secure Record Layer

Prompt:
Help me implement and debug secure_record.py for Task 3.

AI Response:
Explained how to construct the required record format using a header,
IV, ciphertext, and HMAC tag.

The response explained the encrypt-then-MAC order:

1. Construct the authenticated header.
2. Construct the IV from session_id and sequence number.
3. Encrypt the plaintext with AES-256-CTR.
4. Compute HMAC-SHA-256 over header || IV || ciphertext.
5. Verify the MAC before decrypting on the receiving side.

It also explained why encryption and MAC keys should be separate and
why sequence numbers and directional keys prevent replay and reflection
of records.

---

## Interaction 6 - Adversarial Testing

Prompt:
Help me create and debug the adversarial tests required for Task 4.

AI Response:
Helped identify tests for:

- A valid handshake and bidirectional communication
- Modified ciphertext
- Modified authenticated headers
- Replayed records
- Records reflected into the opposite direction
- Invalid RSA authentication or reflected handshake messages

The response emphasized that each invalid case should result in a
specific safe failure and should not release unauthenticated plaintext.

---

## Interaction 7 - Debugging and Verification

Prompt:
Help me debug my implementation and tests and make sure they satisfy
the assignment requirements.

AI Response:
Reviewed errors and test behavior, suggested corrections, and explained
why the corrections were needed. The implementation was then tested
inside the course VM using pytest and the assignment's required
cryptographic libraries.

I reviewed the suggested changes and verified the resulting behavior
before including them in my submission.

---

## Interaction 8 - README and AI Documentation

Prompt:
What should I name the README and AI usage files, and what should I put
inside them?

AI Response:
Recommended README.md for setup/testing instructions and AI_USAGE.md
for documenting how ChatGPT was used. Helped organize the required
information into the assignment's requested AI-use format.

---

## Interaction 9 - GitHub Repository Setup

Prompt:
Help me create the GitHub repository and upload my HW2 files.

AI Response:
Provided instructions for initializing the local Git repository,
configuring the remote repository, creating an SSH key for GitHub,
testing SSH authentication, pushing the repository, and checking that
the local main branch was synchronized with origin/main.

---

## Verification

All AI-assisted material was reviewed before submission. I ran the
implementation and tests inside the course VM and used the resulting
outputs to verify the behavior described in my report.

ChatGPT was used as a learning, debugging, and development assistant.
I remained responsible for reviewing the implementation, testing the
results, and understanding the submitted work.
