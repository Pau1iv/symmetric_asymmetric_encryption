from fastapi import FastAPI, HTTPException
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64

app = FastAPI()

symmetric_key = None
asymmetric_private_key = None
asymmetric_public_key = None


def generate_symmetric_key():
    """Generate a symmetric key."""
    return Fernet.generate_key()

def encrypt_message_with_symmetric_key(message: str, key: bytes):
    """Encrypt a message using a symmetric key."""
    cipher = Fernet(key)
    return cipher.encrypt(message.encode()).hex()

def decrypt_message_with_symmetric_key(encrypted_message: str, key: bytes):
    """Decrypt a message using a symmetric key."""
    cipher = Fernet(key)
    return cipher.decrypt(bytes.fromhex(encrypted_message)).decode()

@app.get("/symmetric/key",tags=["symmetric_key"])
def get_symmetric_key():
    """Get a new symmetric key."""
    global symmetric_key
    symmetric_key = generate_symmetric_key()
    return {"key": symmetric_key.hex()}

@app.post("/symmetric/key",tags=["symmetric_key"])
def set_symmetric_key(key: str):
    """Set a symmetric key."""
    global symmetric_key
    try:
        symmetric_key = bytes.fromhex(key)
        return {"message": "Symmetric key set successfully."}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid symmetric key format. Please provide a valid hexadecimal key.")

@app.post("/symmetric/encode",tags=["symmetric_key"])
def symmetric_encode(message: str):
    """Encode a message using the symmetric key."""
    global symmetric_key
    if symmetric_key is None:
        raise HTTPException(status_code=400, detail="Symmetric key is not set")
    return {"encrypted_message": encrypt_message_with_symmetric_key(message, symmetric_key)}

@app.post("/symmetric/decode",tags=["symmetric_key"])
def symmetric_decode(encrypted_message: str):
    """Decode an encrypted message using the symmetric key."""
    global symmetric_key
    if symmetric_key is None:
        raise HTTPException(status_code=400, detail="Symmetric key is not set")
    try:
        return {"decrypted_message": decrypt_message_with_symmetric_key(encrypted_message, symmetric_key)}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Failed to decrypt message. Please provide a valid encrypted message.")


def generate_asymmetric_key():
    """Generate an asymmetric key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_private_key(private_key):
    """Serialize a private key to PEM format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

def serialize_public_key(public_key):
    """Serialize a public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

@app.get("/asymmetric/key",tags=["asymmetric_key"])
def get_asymmetric_key():
    """Get a new asymmetric key pair."""
    global asymmetric_private_key, asymmetric_public_key
    asymmetric_private_key, asymmetric_public_key = generate_asymmetric_key()
    private_key_pem = serialize_private_key(asymmetric_private_key)
    public_key_pem = serialize_public_key(asymmetric_public_key)
    return {"private_key": private_key_pem, "public_key": public_key_pem}

@app.get("/asymmetric/key/ssh",tags=["asymmetric_key"])
def get_ssh_asymmetric_key():
    """Get the SSH-compatible public key."""
    global asymmetric_private_key, asymmetric_public_key
    if asymmetric_private_key is None:
        raise HTTPException(status_code=400, detail="Asymmetric key pair is not generated")
    private_key_pem = serialize_private_key(asymmetric_private_key)
    public_key_ssh = asymmetric_public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode()
    return {"private_key": private_key_pem, "public_key": public_key_ssh}

@app.post("/asymmetric/key",tags=["asymmetric_key"])
def set_asymmetric_key(keys: dict):
    """Set the asymmetric key pair."""
    global asymmetric_private_key, asymmetric_public_key
    private_key = keys.get("private_key")
    public_key = keys.get("public_key")
    try:
        if private_key and public_key:
            asymmetric_private_key = serialization.load_pem_private_key(
                private_key.encode(),
                password=None,
                backend=default_backend()
            )
            asymmetric_public_key = serialization.load_pem_public_key(
                public_key.encode(),
                backend=default_backend()
            )
            return {"message": "Asymmetric key pair set successfully."}
        else:
            raise HTTPException(status_code=400, detail="Invalid key data. Please provide both private and public keys.")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid key format. Please provide keys in PEM format.")

@app.post("/asymmetric/verify",tags=["asymmetric_key"])
def asymmetric_verify(message: str):
    """Sign a message using the private key."""
    global asymmetric_private_key
    if asymmetric_private_key is None:
        raise HTTPException(status_code=400, detail="Asymmetric private key is not set")
    try:
        signature = asymmetric_private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {"signature": base64.b64encode(signature).decode()}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Failed to sign message. Please provide a valid message.")

@app.post("/asymmetric/sign",tags=["asymmetric_key"])
def asymmetric_sign(message: str, signature: str):
    """Verify the signature of a message using the public key."""
    global asymmetric_public_key
    if asymmetric_public_key is None:
        raise HTTPException(status_code=400, detail="Asymmetric public key is not set")
    try:
        signature_bytes = base64.b64decode(signature)
        asymmetric_public_key.verify(
            signature_bytes,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {"verified": True}
    except Exception as e:
        return {"verified": False}

@app.post("/asymmetric/encode",tags=["asymmetric_key"])
def asymmetric_encode(message: str):
    """Encrypt a message using the public key."""
    global asymmetric_public_key
    if asymmetric_public_key is None:
        raise HTTPException(status_code=400, detail="Asymmetric public key is not set")
    try:
        encrypted_message = asymmetric_public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"encrypted_message": base64.b64encode(encrypted_message).decode()}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Failed to encrypt message. Please provide a valid message.")

@app.post("/asymmetric/decode",tags=["asymmetric_key"])
def asymmetric_decode(encrypted_message: str):
    """Decrypt an encrypted message using the private key."""
    global asymmetric_private_key
    if asymmetric_private_key is None:
        raise HTTPException(status_code=400, detail="Asymmetric private key is not set")
    try:
        decrypted_message = asymmetric_private_key.decrypt(
            base64.b64decode(encrypted_message),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"decrypted_message": decrypted_message.decode()}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Failed to decrypt message. Please provide a valid encrypted message.")

if __name__ == "__main__":
    import uvicorn
    import signal
    from functools import partial

    server = uvicorn.run(app, host="0.0.0.0", port=8000)

    def handle_shutdown(server, signal, frame):
        server.should_exit = True

    signal.signal(signal.SIGINT, partial(handle_shutdown, server))
