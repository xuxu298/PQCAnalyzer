# Sample Python file with crypto usage
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from Crypto.PublicKey import RSA

def generate_rsa_key():
    private_key = rsa.generate_private_key(65537, 2048)
    return private_key

def compute_hash(data):
    return hashlib.md5(data)

def create_ec_key():
    key = ec.generate_private_key(ec.SECP256R1())
    return key
