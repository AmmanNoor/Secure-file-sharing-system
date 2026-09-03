# 🔐 Secure File Sharing System

A secure cloud-based file sharing system developed as part of a **Cybersecurity Internship**.

The system allows users to upload files, encrypt them using **AES-256-GCM**, securely store them in **AWS S3**, download them through a protected endpoint, and generate temporary share links.

---

## 📌 Project Overview

The main goal of this project is to provide a secure way to upload, store, download, and share files.

Instead of storing the original file directly in cloud storage, the application encrypts the file before uploading it to AWS S3.

### 🔒 Main Security Flow

```text
User
  │
  ▼
Upload File
  │
  ▼
AES-256-GCM Encryption
  │
  ▼
AWS S3 Storage
  │
  ▼
Encrypted .enc File
