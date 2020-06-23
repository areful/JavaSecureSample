# generate .pem of private key
openssl genrsa -out private_key.pem 1024

# generate .der of private key
openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.der -nocrypt

# generate .pem of public key
openssl rsa -in private_key.pem -pubout -out public_key.pem
# generate .der of public key
openssl rsa -in private_key.pem -pubout -out public_key.der -outform DER
