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
for downloading:
AWS S3
  │
  ▼
Encrypted File
  │
  ▼
AES-256-GCM Decryption
  │
  ▼
Original File
  │
  ▼
User Download
✨ Features
🔐 AES-256-GCM file encryption
☁️ AWS S3 cloud storage
🔒 AWS S3 Server-Side Encryption (SSE-S3)
📤 Secure file upload
📥 Secure file download
🔗 Temporary secure share links
⏱️ Share links expire automatically after 10 minutes
🛡️ File extension/type validation
📦 Maximum file size limit
🛡️ HTTP security headers using Helmet
🚦 Rate limiting
🌐 CORS protection
🔑 Safe file/key handling
📁 Encrypted .enc objects stored in S3
💻 Simple web-based interface
🛠️ Technologies Used
Frontend
HTML
CSS
JavaScript
Backend
Node.js
Express.js
Multer
Cloud
Amazon Web Services (AWS)
Amazon S3
Security
AES-256-GCM
S3 Server-Side Encryption
Helmet
Express Rate Limit
CORS
📂 Project Structure
secure-file-sharing/
│
├── backend/
│   ├── public/
│   │   └── upload.html
│   │
│   ├── .env
│   ├── .gitignore
│   ├── aws.js
│   ├── package.json
│   ├── package-lock.json
│   └── server.js
│
├── frontend/
│
├── package.json
└── package-lock.json
⚙️ Requirements

Before running the project, make sure you have:

Node.js installed
An AWS account
An AWS S3 bucket
AWS IAM credentials with appropriate S3 permissions
🚀 Installation
1. Clone the Repository
git clone https://github.com/YOUR-USERNAME/secure-file-sharing.git

Go into the project folder:

cd secure-file-sharing
2. Install Dependencies

Go to the backend folder:

cd backend

Install the required packages:

npm install
🔑 Environment Variables

Create a .env file inside the backend folder.

Example:

AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=ap-south-1
AWS_BUCKET_NAME=your_bucket_name
ENCRYPTION_KEY=your_32_byte_encryption_key
PORT=5000
⚠️ Important

Never upload your .env file to GitHub.

Make sure .gitignore contains:

.env
node_modules/

Never expose:

AWS Access Key
AWS Secret Key
Encryption Key
AWS Session Token
▶️ Running the Project

Inside the backend folder, run:

node server.js

The server will start on:

http://localhost:5000

Open the application in your browser:

http://localhost:5000
🔐 How the System Works
1. File Upload

The user selects a file from the web interface and clicks:

Upload & Encrypt

The backend receives the file and encrypts it using:

AES-256-GCM
2. Encrypted Storage

After encryption, the encrypted file is uploaded to AWS S3.

The stored object uses an .enc extension.

Example:

uploads/report.pdf.enc

The original file is therefore not directly stored in the S3 bucket.

3. Secure Download

When the user requests a download:

GET /api/secure-download

The server:

Retrieves the encrypted object from S3.
Decrypts the file.
Returns the original file to the user.
4. Secure Share Link

The application can generate a temporary share link.

The share link contains a temporary token and automatically expires after:

10 minutes

This provides controlled and time-limited file sharing.

🛡️ Security Measures
AES-256-GCM Encryption

Files are encrypted before being stored in AWS S3 using authenticated encryption.

AWS S3 Server-Side Encryption

S3 objects also use:

SSE-S3 / AES256

for an additional layer of protection.

File Validation

The application only allows supported file extensions such as:

.pdf
.doc
.docx
.txt
.jpg
.jpeg
.png
.gif
.zip
.csv
.xlsx
.ppt
.pptx
File Size Limit

The application limits uploaded files to prevent unnecessarily large uploads.

Rate Limiting

Rate limiting helps reduce abuse and excessive API requests.

Helmet

Helmet adds security-related HTTP headers to help protect the application.

CORS

CORS is configured to control cross-origin requests.

Temporary Share Links

Share links automatically expire after 10 minutes.

🔄 API Endpoints
Method	Endpoint	Purpose
GET	/	Open file-sharing portal
POST	/api/upload	Upload and encrypt file
GET	/api/secure-download	Securely download and decrypt file
POST	/api/create-share-link	Generate temporary share link
GET	/api/share/:token	Access shared file
☁️ AWS S3

The project uses Amazon S3 as the cloud storage service.

Encrypted objects are stored in the S3 bucket rather than exposing the original uploaded files.

For better security, the S3 bucket should remain private and public access should be blocked.

🧪 Testing

A sample file can be used to test the complete workflow.

Example:

test-report.pdf
Test Workflow
Select File
     ↓
Upload & Encrypt
     ↓
AES-256-GCM Encryption
     ↓
Upload to AWS S3
     ↓
Verify .enc Object
     ↓
Secure Download
     ↓
Decrypt
     ↓
Original File Downloaded
     ↓
Generate Share Link
     ↓
Open Temporary Link
🎯 Project Objectives

The project was developed to demonstrate practical knowledge of:

Cybersecurity
Data encryption
Secure file handling
Cloud storage security
AWS S3
Node.js backend development
API security
Temporary file sharing
Secure data transmission
📸 Demonstration

The project demonstration includes:

Starting the Node.js server
Opening the secure file-sharing portal
Uploading a sample file
Encrypting the file
Verifying the encrypted object in AWS S3
Securely downloading the original file
Generating a temporary share link
Testing the temporary share link
👨‍💻 Internship Project

This project was developed as part of a Cybersecurity Internship to gain practical experience in secure file sharing, encryption, cloud storage, and application security.

⚠️ Security Notice

This project is intended for educational and internship demonstration purposes.

For production deployment, additional security controls such as authentication, authorization, key management systems, audit logging, HTTPS, malware scanning, and stronger access controls should be considered.
