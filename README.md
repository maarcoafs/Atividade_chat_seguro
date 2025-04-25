# 🔐 Chat Seguro - Projeto de Criptografia e Segurança

Este projeto foi desenvolvido como parte do Trabalho Prático da disciplina **Criptografia e Segurança**. O objetivo é implementar um sistema de chat simples com foco na **confidencialidade**, **integridade** e **autenticação** das mensagens trocadas entre os usuários.

## 📌 Objetivos

- Garantir **confidencialidade** das mensagens com criptografia simétrica (AES).
- Garantir **integridade** utilizando HMAC com SHA-256.
- Implementar **autenticação entre usuários** com assinaturas digitais RSA.
- Utilizar sockets para comunicação em rede (cliente-servidor).

---

## ⚙️ Tecnologias Utilizadas

- **Python 3**
- Bibliotecas:
  - `pycryptodome`
  - `socket`
  - `threading`

---

## 🔐 Algoritmos de Segurança

- **Criptografia Simétrica**: AES (modo EAX)
- **Criptografia Assimétrica**: RSA (2048 bits)
- **Integridade**: HMAC com SHA-256
- **Assinatura Digital**: RSA + SHA-256

---

