<div align="center">

<img src="https://github.com/JaiServanaBhava/SamparkKranti/blob/7862140db1b5c3a837cecf56b27499764ec5f9ed/logo.png" width="180">

# Sampark Kranti Messager

### Communication Without Middlemen

*A Fully Decentralized, Serverless & End-to-End Encrypted Messenger*

<br>

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![DHT](https://img.shields.io/badge/DHT-Kademlia-success)
![Encryption](https://img.shields.io/badge/AES--256--GCM-orange)
![P2P](https://img.shields.io/badge/Architecture-Peer--to--Peer-red)

</div>
<br>
<div align="center">

### ⚡ Ready to Start Secure Messaging?

<a href="../../releases/latest">
  <img src="https://img.shields.io/badge/⬇%20Download-SamparkKranti%20for%20Windows-2ea44f?style=for-the-badge" alt="Download SamparkKranti">
</a>

<br>

🚀 **Portable Single EXE** • 🔒 **End-to-End Encrypted** • 🌐 **No Servers Required**

</div>

## 📖 Overview

**SamparkKranti P2P** is a privacy-focused desktop messenger that enables users to communicate directly without relying on centralized servers.

Unlike traditional messaging platforms that route messages through company-controlled infrastructure, SamparkKranti establishes secure peer-to-peer connections between users while utilizing a decentralized Kademlia Distributed Hash Table (DHT) for peer discovery.

This architecture ensures:

* 🔒 End-to-end encrypted communication
* 🌐 No central server dependency
* 👤 No phone numbers or email registration
* 🚫 No user tracking or data collection
* ⚡ Fast direct communication between peers

---

## ✨ Key Features

### 🌐 Decentralized Peer Discovery

Uses a Kademlia-based DHT network to locate peers without requiring a central directory service.

### 🔒 End-to-End Encryption

All communications are protected using:

* AES-256-GCM for message encryption
* X25519 key exchange
* Cryptographically secure session keys

### 👤 Identity-Based Communication

Each user owns a cryptographic identity instead of relying on:

* Phone numbers
* Email addresses
* Third-party accounts

### 💬 Real-Time Messaging

Provides instant communication through asynchronous socket networking.

### 🎨 Modern Desktop Experience

Features:

* Multiple premium themes
* Conversation timeline grouping
* Responsive chat interface
* Local-first design

### 💾 Local Data Ownership

All chat history and configuration data remain on the user's device using SQLite storage.

### 📦 Portable Deployment

Can be packaged as a standalone executable for easy distribution.

---

## 🏗 Architecture

```text
┌─────────────────────────┐
│      User Client        │
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  Kademlia DHT Network   │
│   Peer Discovery Layer  │
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│ Direct P2P Connection   │
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│ AES-256-GCM Encryption  │
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│ Encrypted Message Flow  │
└─────────────────────────┘
```

---

## 🛠 Technology Stack

| Component      | Technology   |
| -------------- | ------------ |
| Language       | Python 3.10+ |
| Networking     | TCP Sockets  |
| Peer Discovery | Kademlia DHT |
| Encryption     | AES-256-GCM  |
| Key Exchange   | X25519       |
| Database       | SQLite       |
| Packaging      | PyInstaller  |
| UI             | HTML         |

---

## 🚀 Installation

### Clone Repository

```bash
git clone https://github.com/JaiServanaBhava/SamparkKranti.git
cd SamparkKranti
```

### Run Application

```bash
python main.py
```

---

## 📂 Project Structure

```text
SamparkKranti/
├── main.py
├── bridge.py
├── database.py
├── storage.py
├── manager.py
├── network.py
├── index.html
│
├── crypto/
│   ├── __init__.py
│   ├── keys.py
│   └── encryption.py
│
├── dht/
│   ├── __init__.py
│   ├── node.py
│   ├── routing_table.py
│   └── bootstrap.py
│
├── messaging/
│   ├── __init__.py
│   └── handler.py
│
└── networking/
│   ├── __init__.py
    └── transport.py
```

---

## 🗺 Roadmap

### Phase 1

* [x] Local messaging
* [x] SQLite storage
* [x] Theme system
* [x] Contact management

### Phase 2

* [x] Kademlia DHT integration
* [x] Identity-based discovery
* [x] AES-256-GCM encryption
* [x] X25519 key exchange

### Phase 3

* [ ] File sharing
* [ ] Group messaging
* [ ] Voice calls
* [ ] NAT traversal
* [ ] Mobile companion app

### Phase 4

* [ ] Distributed offline messaging
* [ ] Multi-device synchronization
* [ ] Decentralized profile system

---

## 🔐 Security Model

SamparkKranti follows a zero-trust architecture:

1. Peers discover each other via DHT.
2. X25519 establishes a shared secret.
3. AES-256-GCM encrypts all payloads.
4. No central entity can read message contents.
5. Users retain complete ownership of their data.

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome.

1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Open a Pull Request

---

## 📜 License

Released under the MIT License.

---

<div align="center">

### Built for Privacy. Built for Freedom.

**SamparkKranti P2P — Communication Without Middlemen.**

</div>
