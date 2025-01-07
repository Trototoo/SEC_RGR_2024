import socket
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

CA_HOST = '127.0.0.1'
CA_PORT = 1223

class CertificateAuthority:
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        
        self.certificate = self._create_ca_certificate()

    def _create_ca_certificate(self):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"Mega Cool CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Mega Cool CA Organization")
        ])

        return x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
        ).sign(self.private_key, hashes.SHA256())

    def issue_certificate(self, public_key_pem):
        server_public_key = serialization.load_pem_public_key(public_key_pem)
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"Mega Cool Server"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.certificate.subject
        ).public_key(
            server_public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30)
        ).sign(self.private_key, hashes.SHA256())
        
        return cert.public_bytes(serialization.Encoding.PEM)

def main():
    ca = CertificateAuthority()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((CA_HOST, CA_PORT))
    server_socket.listen(1)
    print("CA Server is listening...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connection from {addr}")
        
        request = conn.recv(4096)
        
        if request == b"GET_CA_CERT":
            ca_cert_pem = ca.certificate.public_bytes(serialization.Encoding.PEM)
            conn.sendall(ca_cert_pem)
        else:
            certificate = ca.issue_certificate(request)
            conn.sendall(certificate)
            
        conn.close()

if __name__ == "__main__":
    main()