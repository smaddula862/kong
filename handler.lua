-- Import required modules
local openssl = require("resty.openssl")
local cjson = require("cjson")

-- Helper function to Base64 URL encode
local function base64url_encode(data)
    return (openssl.util.base64(data):gsub('+', '-'):gsub('/', '_'):gsub('=', ''))
end

-- Helper function to generate a random CEK (Content Encryption Key)
local function generate_cek()
    return openssl.rand(32)  -- 32 bytes for AES-256
end

-- Helper function to encrypt CEK using RSA-OAEP-256
local function encrypt_cek_with_rsa(public_key, cek)
    return public_key:encrypt(cek, {oaep = true, hash = "sha256"})
end

-- Helper function to encrypt plaintext using AES-GCM
local function encrypt_with_aes(cek, plaintext)
    local iv = openssl.rand(12)  -- 12 bytes IV for AES-GCM (common size for AES-GCM)
    local cipher = openssl.cipher.new("aes-256-gcm", cek)
    cipher:set_iv(iv)  -- Set the IV for AES-GCM
    local ciphertext, tag = cipher:encrypt(plaintext)
    return iv, ciphertext, tag
end

-- Main function to perform RSA-OAEP-256 JWE encryption
local function encrypt_jwe(plaintext, rsa_public_key)
    -- 1. Generate a random CEK (32 bytes for AES-256)
    local cek = generate_cek()

    -- 2. Encrypt the CEK using RSA-OAEP-256 with the public RSA key
    local encrypted_cek = encrypt_cek_with_rsa(rsa_public_key, cek)

    -- 3. Encrypt the plaintext with AES-256-GCM using the CEK
    local iv, ciphertext, tag = encrypt_with_aes(cek, plaintext)

    -- 4. Create the JWE Protected Header
    local jwe_header = {
        alg = "RSA-OAEP-256",  -- RSA encryption algorithm
        enc = "A256GCM"        -- AES GCM encryption algorithm
    }
    local protected_header_json = cjson.encode(jwe_header)
    local protected_header = base64url_encode(protected_header_json)

    -- 5. Construct the final JWE compact serialization
    local jwe = table.concat({
        protected_header,
        ".",
        base64url_encode(encrypted_cek),
        ".",
        base64url_encode(iv),
        ".",
        base64url_encode(ciphertext),
        ".",
        base64url_encode(tag)
    })

    return jwe
end

-- Example usage
local rsa_key = openssl.pkey.new({bits = 2048})  -- Generate RSA key pair with 2048 bits
local rsa_public_key = rsa_key:pubkey()  -- Get the public key

local plaintext = "This is a secret message."

-- Encrypt the message to create the JWE token
local jwe_token = encrypt_jwe(plaintext, rsa_public_key)

-- Output the JWE token
ngx.say("Encrypted JWE Token: ", jwe_token)







-- Helper function to Base64 URL decode
local function base64url_decode(data)
    return openssl.util.base64(data:gsub('-', '+'):gsub('_', '/'):gsub('^([A-Za-z0-9+/=]*)$', '%1='))
end

-- Helper function to decrypt CEK using RSA-OAEP-256
local function decrypt_cek_with_rsa(private_key, encrypted_cek)
    return private_key:decrypt(encrypted_cek, {oaep = true, hash = "sha256"})
end

-- Helper function to decrypt plaintext using AES-GCM
local function decrypt_with_aes(cek, iv, ciphertext, tag)
    local cipher = openssl.cipher.new("aes-256-gcm", cek)
    cipher:set_iv(iv)
    return cipher:decrypt(ciphertext, tag)
end

-- Main function to perform RSA-OAEP-256 JWE decryption
local function decrypt_jwe(jwe_token, rsa_private_key)
    -- 1. Split the JWE token into its parts
    local parts = {}
    for part in jwe_token:gmatch("([^%.]+)") do
        table.insert(parts, base64url_decode(part))
    end

    -- 2. Extract the components from the JWE
    local protected_header = cjson.decode(parts[1])
    local encrypted_cek = parts[2]
    local iv = parts[3]
    local ciphertext = parts[4]
    local tag = parts[5]

    -- 3. Decrypt the CEK using the RSA private key (RSA-OAEP-256)
    local cek = decrypt_cek_with_rsa(rsa_private_key, encrypted_cek)

    -- 4. Decrypt the ciphertext using AES-256-GCM
    local plaintext = decrypt_with_aes(cek, iv, ciphertext, tag)

    return plaintext
end

-- Example usage
local rsa_private_key = rsa_key  -- Use the private key generated earlier

-- Example JWE Token (replace with an actual token from encryption step)
local jwe_token = "eyJhbGciOiAiUlNBLU9BRFAyNTYiLCAiZW5jIjogIkEyNTZHQ00ifQ..."

-- Decrypt the JWE token
local decrypted_plaintext = decrypt_jwe(jwe_token, rsa_private_key)

-- Output the decrypted plaintext
ngx.say("Decrypted Plaintext: ", decrypted_plaintext)
