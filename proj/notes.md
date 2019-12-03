# Confidentiality
Diffie-Hellman generates symmetric key
# Integrity 
HMAC
# Non Repudiation 
Asymmetric key pair for both server and client (sign function)
# Freshness
C_id with Timestamp
# Authenticity
Username and Password

# Decisions:
1-Use standard (g,p) pair from NIST due to these having to follow several properties to garantee y,g:a (no one can discover a and b, secret values)

2-Assure Perfect Foward Secrecy by always generating new a and b random values is important to the scope of the project because it is important to protect the confidentiality of all previous submissions from an user.
