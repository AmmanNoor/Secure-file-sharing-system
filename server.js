const crypto = require("crypto");
const path = require("path");
const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const multer = require("multer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const {
    ListBucketsCommand,
    PutObjectCommand,
    GetObjectCommand,
    HeadObjectCommand
} = require("@aws-sdk/client-s3");

const s3Client = require("./aws");
dotenv.config({
    path: path.join(__dirname, ".env")
});

const app = express();

const PORT = Number(process.env.PORT) || 5000;

const MAX_FILE_SIZE = 10 * 1024 * 1024;

const SHARE_LINK_EXPIRY = 10 * 60 * 1000;

const IS_PRODUCTION =
    process.env.NODE_ENV === "production";
app.disable("x-powered-by");

app.set("trust proxy", false);
const ALLOWED_EXTENSIONS = [
    ".pdf",
    ".doc",
    ".docx",
    ".txt",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".zip",
    ".csv",
    ".xlsx",
    ".ppt",
    ".pptx"
];
const ALLOWED_MIME_TYPES = {

    ".pdf": [
        "application/pdf"
    ],

    ".doc": [
        "application/msword"
    ],

    ".docx": [
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    ],

    ".txt": [
        "text/plain"
    ],

    ".jpg": [
        "image/jpeg"
    ],

    ".jpeg": [
        "image/jpeg"
    ],

    ".png": [
        "image/png"
    ],

    ".gif": [
        "image/gif"
    ],

    ".zip": [
        "application/zip",
        "application/x-zip-compressed"
    ],

    ".csv": [
        "text/csv",
        "application/csv",
        "application/vnd.ms-excel"
    ],

    ".xlsx": [
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    ],

    ".ppt": [
        "application/vnd.ms-powerpoint"
    ],

    ".pptx": [
        "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    ]
};
const publicDir = path.join(
    __dirname,
    "public"
);
app.use(
    helmet({
        contentSecurityPolicy: false,

        crossOriginResourcePolicy: {
            policy: "cross-origin"
        },

        referrerPolicy: {
            policy: "no-referrer"
        },

        frameguard: {
            action: "deny"
        },

        hidePoweredBy: true,

        noSniff: true,

        xssFilter: false
    })
);
app.use(
    cors({
        origin: true,

        methods: [
            "GET",
            "POST",
            "OPTIONS"
        ],

        allowedHeaders: [
            "Content-Type"
        ],

        credentials: false
    })
);
app.use(
    express.json({
        limit: "100kb"
    })
);

app.use(
    express.urlencoded({
        extended: false,
        limit: "100kb"
    })
);
const apiLimiter = rateLimit({

    windowMs: 15 * 60 * 1000,

    max: 100,

    standardHeaders: true,

    legacyHeaders: false,

    message: {
        success: false,
        message:
            "Too many requests. Please try again later."
    }
});

const uploadLimiter = rateLimit({

    windowMs: 15 * 60 * 1000,

    max: 20,

    standardHeaders: true,

    legacyHeaders: false,

    message: {
        success: false,
        message:
            "Too many upload attempts. Please try again later."
    }
});

const shareLinkLimiter = rateLimit({

    windowMs: 15 * 60 * 1000,

    max: 30,

    standardHeaders: true,

    legacyHeaders: false,

    message: {
        success: false,
        message:
            "Too many share-link requests. Please try again later."
    }
});

app.use(
    "/api/",
    apiLimiter
);

app.use(
    express.static(
        publicDir,
        {
            index: false
        }
    )
);
function getExtension(filename) {

    if (!filename) {
        return "";
    }

    const dot =
        filename.lastIndexOf(".");

    if (dot === -1) {
        return "";
    }

    return filename
        .substring(dot)
        .toLowerCase();
}
function sanitizeFilename(filename) {

    return String(
        filename || "downloaded-file"
    )
        .replace(/[\/\\:*?"<>|]/g, "_")
        .replace(/\.\./g, "_")
        .replace(/[\r\n]/g, "_")
        .trim()
        .substring(0, 200)
        || "downloaded-file";
}
const upload = multer({

    storage:
        multer.memoryStorage(),

    limits: {

        fileSize:
            MAX_FILE_SIZE,

        files: 1,

        fields: 10,

        parts: 12
    },

    fileFilter:
        (req, file, cb) => {

            const extension =
                getExtension(
                    file.originalname
                );

            // Check extension
            if (
                !ALLOWED_EXTENSIONS.includes(
                    extension
                )
            ) {

                return cb(
                    new Error(
                        `File extension ${
                            extension || "unknown"
                        } is not allowed.`
                    )
                );
            }

            // Check MIME type
            const allowedMimeTypes =
                ALLOWED_MIME_TYPES[
                    extension
                ] || [];

            if (
                !allowedMimeTypes.includes(
                    file.mimetype
                )
            ) {

                return cb(
                    new Error(
                        `Invalid MIME type for ${extension} file. Received: ${file.mimetype}`
                    )
                );
            }

            cb(null, true);
        }
});

function getEncryptionKey() {

    const key =
        Buffer.from(
            process.env.ENCRYPTION_KEY || "",
            "hex"
        );

    if (key.length !== 32) {

        throw new Error(
            "ENCRYPTION_KEY must be exactly 32 bytes (64 hexadecimal characters)."
        );
    }

    return key;
}
function encryptFile(buffer) {

    const key =
        getEncryptionKey();

    const iv =
        crypto.randomBytes(12);

    const cipher =
        crypto.createCipheriv(
            "aes-256-gcm",
            key,
            iv
        );

    const encrypted =
        Buffer.concat([
            cipher.update(buffer),
            cipher.final()
        ]);

    const authTag =
        cipher.getAuthTag();

    return Buffer.concat([
        iv,
        authTag,
        encrypted
    ]);
}
function decryptFile(buffer) {

    const key =
        getEncryptionKey();

    if (
        !Buffer.isBuffer(buffer) ||
        buffer.length < 28
    ) {

        throw new Error(
            "Invalid encrypted file."
        );
    }

    const iv =
        buffer.subarray(0, 12);

    const authTag =
        buffer.subarray(12, 28);

    const encrypted =
        buffer.subarray(28);

    const decipher =
        crypto.createDecipheriv(
            "aes-256-gcm",
            key,
            iv
        );

    decipher.setAuthTag(
        authTag
    );

    return Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
    ]);
}
function createS3Key(filename) {

    const safeFilename =
        sanitizeFilename(filename);

    return (
        `uploads/${Date.now()}-` +
        `${crypto.randomUUID()}-` +
        `${safeFilename}.enc`
    );
}
function isValidS3Key(key) {

    if (
        typeof key !== "string"
    ) {
        return false;
    }

    if (
        key.length === 0 ||
        key.length > 1024
    ) {
        return false;
    }

    if (
        !key.startsWith("uploads/")
    ) {
        return false;
    }

    if (
        !key.endsWith(".enc")
    ) {
        return false;
    }

    if (
        key.includes("..") ||
        key.includes("\\") ||
        key.includes("\0")
    ) {
        return false;
    }

    return true;
}
async function streamToBuffer(body) {

    if (!body) {

        throw new Error(
            "Empty S3 response."
        );
    }

    const chunks = [];

    for await (
        const chunk of body
    ) {

        chunks.push(
            Buffer.isBuffer(chunk)
                ? chunk
                : Buffer.from(chunk)
        );
    }

    return Buffer.concat(
        chunks
    );
}
function sendDownload(
    res,
    buffer,
    filename,
    contentType
) {

    const safeName =
        sanitizeFilename(
            filename
        );

    res.setHeader(
        "Content-Type",
        contentType ||
        "application/octet-stream"
    );

    res.setHeader(
        "Content-Disposition",
        `attachment; filename="${safeName}"`
    );

    res.setHeader(
        "Content-Length",
        buffer.length
    );

    res.setHeader(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, private"
    );

    res.setHeader(
        "Pragma",
        "no-cache"
    );

    res.setHeader(
        "X-Content-Type-Options",
        "nosniff"
    );

    res.send(buffer);
}
function getClientIp(req) {

    return (
        req.ip ||
        req.socket?.remoteAddress ||
        "unknown"
    );
}
function securityLog(
    event,
    req,
    details = {}
) {

    console.log(
        JSON.stringify({

            timestamp:
                new Date().toISOString(),

            event,

            ip:
                getClientIp(req),

            ...details
        })
    );
}
function safeErrorMessage(error) {

    if (IS_PRODUCTION) {

        return (
            "An internal server error occurred."
        );
    }

    return (
        error?.message ||
        "Unknown error."
    );
}
app.get(
    "/",
    (req, res) => {

        res.sendFile(
            path.join(
                publicDir,
                "upload.html"
            )
        );
    }
);

app.get(
    "/upload.html",
    (req, res) => {

        res.sendFile(
            path.join(
                publicDir,
                "upload.html"
            )
        );
    }
);
app.get(
    "/api/test-aws",
    async (req, res) => {

        try {

            await s3Client.send(
                new ListBucketsCommand({})
            );

            securityLog(
                "AWS_CONNECTION_TEST_SUCCESS",
                req
            );

            return res.json({

                success: true,

                message:
                    "AWS S3 connection successful!"
            });

        } catch (error) {

            console.error(
                "AWS ERROR:",
                error
            );

            securityLog(
                "AWS_CONNECTION_TEST_FAILED",
                req
            );

            return res
                .status(500)
                .json({

                    success: false,

                    message:
                        "AWS S3 connection failed.",

                    ...(
                        IS_PRODUCTION
                            ? {}
                            : {
                                error:
                                    error.message
                            }
                    )
                });
        }
    }
);
app.post(
    "/api/upload",

    uploadLimiter,

    (req, res, next) => {

        upload.single("file")(
            req,
            res,
            (error) => {

                if (error) {

                    console.error(
                        "MULTER ERROR:",
                        error
                    );

                    if (
                        error instanceof
                        multer.MulterError
                    ) {

                        if (
                            error.code ===
                            "LIMIT_FILE_SIZE"
                        ) {

                            return res
                                .status(413)
                                .json({

                                    success: false,

                                    message:
                                        "File is too large. Maximum allowed size is 10 MB."
                                });
                        }

                        if (
                            error.code ===
                            "LIMIT_FILE_COUNT"
                        ) {

                            return res
                                .status(400)
                                .json({

                                    success: false,

                                    message:
                                        "Only one file can be uploaded."
                                });
                        }

                        return res
                            .status(400)
                            .json({

                                success: false,

                                message:
                                    `Upload error: ${error.message}`
                            });
                    }

                    return res
                        .status(400)
                        .json({

                            success: false,

                            message:
                                error.message ||
                                "Invalid file."
                        });
                }

                next();
            }
        );
    },

    async (req, res) => {

        try {
            if (!req.file) {

                securityLog(
                    "UPLOAD_REJECTED_NO_FILE",
                    req
                );

                return res
                    .status(400)
                    .json({

                        success: false,

                        message:
                            "No file uploaded. Please select a file."
                    });
            }
            if (
                req.file.size >
                MAX_FILE_SIZE
            ) {

                return res
                    .status(413)
                    .json({

                        success: false,

                        message:
                            "File is too large. Maximum allowed size is 10 MB."
                    });
            }

            const extension =
                getExtension(
                    req.file.originalname
                );
            const allowedMimeTypes =
                ALLOWED_MIME_TYPES[
                    extension
                ] || [];

            if (
                !allowedMimeTypes.includes(
                    req.file.mimetype
                )
            ) {

                return res
                    .status(400)
                    .json({

                        success: false,

                        message:
                            `Invalid MIME type: ${req.file.mimetype}`
                    });
            }
            const safeOriginalName =
                sanitizeFilename(
                    req.file.originalname
                );
            const encryptedBuffer =
                encryptFile(
                    req.file.buffer
                );
            const fileKey =
                createS3Key(
                    safeOriginalName
                );
            await s3Client.send(
                new PutObjectCommand({

                    Bucket:
                        process.env.S3_BUCKET_NAME,

                    Key:
                        fileKey,

                    Body:
                        encryptedBuffer,

                    ContentType:
                        "application/octet-stream",

                    ServerSideEncryption:
                        "AES256",

                    Metadata: {

                        originalname:
                            safeOriginalName,

                        originaltype:
                            req.file.mimetype,

                        originalextension:
                            extension,

                        encrypted:
                            "true",

                        encryption:
                            "AES-256-GCM"
                    }
                })
            );
            securityLog(
                "FILE_UPLOADED",
                req,
                {

                    filename:
                        safeOriginalName,

                    s3Key:
                        fileKey,

                    mimeType:
                        req.file.mimetype,

                    size:
                        req.file.size,

                    encryptedSize:
                        encryptedBuffer.length
                }
            );
            return res.json({

                success: true,

                message:
                    "File encrypted and uploaded successfully!",

                filename:
                    safeOriginalName,

                key:
                    fileKey,

                mimeType:
                    req.file.mimetype,

                encryption:
                    "AES-256-GCM"
            });

        } catch (error) {

            console.error(
                "UPLOAD ERROR:",
                error
            );

            securityLog(
                "UPLOAD_FAILED",
                req,
                {
                    error:
                        error.message
                }
            );

            return res
                .status(500)
                .json({

                    success: false,

                    message:
                        "Encrypted file upload failed.",

                    error:
                        safeErrorMessage(error)
                });
        }
    }
);
app.get(
    "/api/secure-download",
    async (req, res) => {

        try {

            const key =
                req.query.key;

            if (
                !isValidS3Key(key)
            ) {

                return res
                    .status(400)
                    .json({

                        success: false,

                        message:
                            "Invalid file key."
                    });
            }
            const s3Response =
                await s3Client.send(
                    new GetObjectCommand({

                        Bucket:
                            process.env.S3_BUCKET_NAME,

                        Key:
                            key
                    })
                );
            const encryptedBuffer =
                await streamToBuffer(
                    s3Response.Body
                );
            const decryptedBuffer =
                decryptFile(
                    encryptedBuffer
                );
            const originalName =
                s3Response.Metadata
                    ?.originalname ||
                "downloaded-file";

            const originalType =
                s3Response.Metadata
                    ?.originaltype ||
                "application/octet-stream";
            securityLog(
                "FILE_DOWNLOADED",
                req,
                {
                    s3Key:
                        key
                }
            );
            return sendDownload(
                res,
                decryptedBuffer,
                originalName,
                originalType
            );

        } catch (error) {

            console.error(
                "DOWNLOAD ERROR:",
                error
            );

            securityLog(
                "DOWNLOAD_FAILED",
                req
            );

            return res
                .status(500)
                .json({

                    success: false,

                    message:
                        "Secure file download failed.",

                    error:
                        safeErrorMessage(error)
                });
        }
    }
);
const shareLinks =
    new Map();
app.post(
    "/api/create-share-link",

    shareLinkLimiter,

    async (req, res) => {

        try {

            const key =
                req.body?.key;

            if (
                !isValidS3Key(key)
            ) {

                return res
                    .status(400)
                    .json({

                        success: false,

                        message:
                            "Invalid file key."
                    });
            }
            const s3Response =
                await s3Client.send(
                    new HeadObjectCommand({

                        Bucket:
                            process.env.S3_BUCKET_NAME,

                        Key:
                            key
                    })
                );
            if (
                s3Response.Metadata?.encrypted !==
                "true"
            ) {

                return res
                    .status(400)
                    .json({

                        success: false,

                        message:
                            "This file is not marked as encrypted."
                    });
            }
            const originalName =
                s3Response.Metadata
                    ?.originalname ||
                "downloaded-file";
            const token =
                crypto
                    .randomBytes(32)
                    .toString("hex");

            const now =
                Date.now();

            const expiresAt =
                now +
                SHARE_LINK_EXPIRY;
            shareLinks.set(
                token,
                {

                    key,

                    originalName,

                    expiresAt,

                    createdAt:
                        now
                }
            );
            const shareUrl =
                `${req.protocol}://${req.get(
                    "host"
                )}/api/share/${token}`;
            securityLog(
                "SHARE_LINK_CREATED",
                req,
                {

                    s3Key:
                        key,

                    expiresAt
                }
            );

            return res.json({

                success: true,

                message:
                    "Secure share link created.",

                shareUrl,

                expiresIn:
                    "10 minutes"
            });

        } catch (error) {

            console.error(
                "SHARE LINK ERROR:",
                error
            );

            return res
                .status(500)
                .json({

                    success: false,

                    message:
                        "Could not create secure share link.",

                    error:
                        safeErrorMessage(error)
                });
        }
    }
);
app.get(
    "/api/share/:token",
    async (req, res) => {

        try {

            const token =
                req.params.token;
            if (
                !/^[a-f0-9]{64}$/i.test(
                    token
                )
            ) {

                return res
                    .status(400)
                    .send(
                        "Invalid share token."
                    );
            }
            const share =
                shareLinks.get(
                    token
                );

            if (!share) {

                return res
                    .status(404)
                    .send(
                        "Secure link not found or expired."
                    );
            }
            if (
                Date.now() >
                share.expiresAt
            ) {

                shareLinks.delete(
                    token
                );

                return res
                    .status(410)
                    .send(
                        "This secure share link has expired."
                    );
            }
            const s3Response =
                await s3Client.send(
                    new GetObjectCommand({

                        Bucket:
                            process.env.S3_BUCKET_NAME,

                        Key:
                            share.key
                    })
                );
            const encryptedBuffer =
                await streamToBuffer(
                    s3Response.Body
                );
            const decryptedBuffer =
                decryptFile(
                    encryptedBuffer
                );

            const originalName =
                s3Response.Metadata
                    ?.originalname ||
                share.originalName ||
                "downloaded-file";

            const originalType =
                s3Response.Metadata
                    ?.originaltype ||
                "application/octet-stream";
            securityLog(
                "SHARE_FILE_DOWNLOADED",
                req,
                {

                    token:
                        token.substring(0, 8) +
                        "...",

                    s3Key:
                        share.key
                }
            );
            return sendDownload(
                res,
                decryptedBuffer,
                originalName,
                originalType
            );

        } catch (error) {

            console.error(
                "SHARE DOWNLOAD ERROR:",
                error
            );

            return res
                .status(500)
                .send(
                    "Secure file download failed."
                );
        }
    }
);
setInterval(
    () => {

        const now =
            Date.now();

        for (
            const [
                token,
                share
            ]
            of shareLinks.entries()
        ) {

            if (
                now >
                share.expiresAt
            ) {

                shareLinks.delete(
                    token
                );
            }
        }

    },
    60 * 1000
);
app.use(
    (req, res) => {

        if (
            req.path.startsWith(
                "/api/"
            )
        ) {

            return res
                .status(404)
                .json({

                    success: false,

                    message:
                        `API endpoint not found: ${req.method} ${req.path}`
                });
        }

        return res
            .status(404)
            .send(
                "Page not found."
            );
    }
);
app.use(
    (error, req, res, next) => {

        console.error(
            "SERVER ERROR:",
            error
        );

        securityLog(
            "SERVER_ERROR",
            req
        );

        if (
            res.headersSent
        ) {

            return next(error);
        }

        return res
            .status(500)
            .json({

                success: false,

                message:
                    "Internal server error.",

                error:
                    safeErrorMessage(
                        error
                    )
            });
    }
);
function validateEnvironment() {

    const requiredVariables = [
        "S3_BUCKET_NAME",
        "ENCRYPTION_KEY"
    ];

    const missing =
        requiredVariables.filter(
            variable =>
                !process.env[
                    variable
                ]
        );

    if (
        missing.length > 0
    ) {

        console.error("");

        console.error(
            "❌ Missing required environment variables:"
        );

        missing.forEach(
            variable => {

                console.error(
                    `   - ${variable}`
                );
            }
        );

        console.error("");

        process.exit(1);
    }

    try {

        getEncryptionKey();

    } catch (error) {

        console.error("");

        console.error(
            "❌ Encryption configuration error:"
        );

        console.error(
            error.message
        );

        console.error("");

        process.exit(1);
    }
}
function shutdown(signal) {

    console.log(
        `\n${signal} received. Shutting down server...`
    );

    process.exit(0);
}

process.on(
    "SIGINT",
    () => shutdown("SIGINT")
);

process.on(
    "SIGTERM",
    () => shutdown("SIGTERM")
);
validateEnvironment();

app.listen(
    PORT,
    () => {

        console.log("");

        console.log(
            "=========================================="
        );

        console.log(
            "🔐 SECURE FILE SHARING SERVER"
        );

        console.log(
            "=========================================="
        );

        console.log(
            `Server: http://localhost:${PORT}`
        );

        console.log(
            `Frontend: http://localhost:${PORT}/upload.html`
        );

        console.log(
            `Maximum upload size: ${
                MAX_FILE_SIZE /
                (1024 * 1024)
            } MB`
        );

        console.log(
            "Encryption: AES-256-GCM"
        );

        console.log(
            "S3 Server-Side Encryption: AES256"
        );

        console.log(
            "MIME validation: ENABLED"
        );

        console.log(
            "File extension validation: ENABLED"
        );

        console.log(
            "Share links expire after 10 minutes"
        );

        console.log(
            "Security headers: ENABLED"
        );

        console.log(
            "Rate limiting: ENABLED"
        );

        console.log(
            "CORS protection: ENABLED"
        );

        console.log(
            "=========================================="
        );

        console.log("");
    }
);