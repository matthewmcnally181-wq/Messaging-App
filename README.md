# Messaging-App
End-to-End Encrypted Messaging
A Telegram-like messaging application with full end-to-end encryption using NaCl/TweetNaCl cryptography. All messages are encrypted on the client and can only be decrypted by the intended recipient.

Features
End-to-End Encryption - Every message is encrypted using NaCl (Networking and Cryptography library)✅ Real-time Messaging - WebSocket-based instant message delivery✅ User Authentication - Secure registration and login with bcrypt password hashing✅ Multi-user Support - Multiple simultaneous conversations✅ Message History - Encrypted messages stored in database✅ Online Status - Real-time online/offline indicator✅ Mobile Responsive - Works on desktop and mobile devices
How the Encryption Works
Encryption Algorithm: Box (Authenticated Encryption)
	•	Algorithm: XSalsa20-Poly1305
	•	Key Exchange: Curve25519
	•	Library: TweetNaCl.js (JavaScript port of NaCl)
Key Generation
Each user generates a keypair:
	•	Public Key (shared with server, stored for other users)
	•	Secret Key (kept only on client, never sent to server)
Message Encryption
	1.	Message is encrypted with:
	•	Recipient’s public key
	•	Sender’s secret key
	•	Random nonce (number used once)
	2.	Encrypted message + nonce sent to server
	3.	Server stores encrypted data (cannot read it)
	4.	Recipient decrypts using:
	•	Sender’s public key
	•	Their secret key
	•	Nonce from message

Even if server is compromised, messages cannot be read