Often, RSA is used to securely exchange an AES key (a process called hybrid encryption), which is then used for encrypting the actual data using AES-256-GCM. This combines the strengths of both systems.
for _, c in ipairs(require("resty.openssl.cipher").list()) do print(c) end
