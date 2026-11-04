#!/usr/bin/env bash
# Genera el sistema de demostración que usan las pruebas de Suaya.
# TODAS las llaves son de PRUEBA, generadas al momento; nunca las use en producción.
set -euo pipefail
cd "$(dirname "$0")"
D=fixtures/sistema-demo
S_TMP=$(mktemp -d)
trap 'rm -rf "$S_TMP"' EXIT
rm -rf "$D" && mkdir -p "$D"/{etc/ssh,etc/nginx,etc/apache2,etc/pki,home/ana/.ssh,legado,srv}

# 1. Certificado roto: RSA-1024 firmado con SHA-1.
openssl req -x509 -newkey rsa:1024 -sha1 -nodes -days 365 -subj "/CN=legado.ejemplo.mx" \
  -keyout "$D/legado/legado.key" -out "$D/legado/legado.crt" 2>/dev/null

# 2. Certificado de servidor ECDSA P-256, vigente hasta después de 2030.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes -days 5000 \
  -subj "/CN=www.ejemplo.mx" -addext "extendedKeyUsage=serverAuth" -addext "basicConstraints=critical,CA:FALSE" \
  -keyout "$D/etc/nginx/www.key" -out "$D/etc/nginx/www.crt" 2>/dev/null
chmod 600 "$D/etc/nginx/www.key"

# 3. Autoridad certificadora Ed25519 (en DER).
openssl req -x509 -newkey ed25519 -nodes -days 3650 -subj "/CN=CA Demo Suaya" \
  -addext "basicConstraints=critical,CA:TRUE" -keyout "$D/etc/pki/ca.key" -outform DER -out "$D/etc/pki/ca.der" 2>/dev/null
chmod 600 "$D/etc/pki/ca.key"

# 4. Llaves RSA en varios formatos.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$D/srv/app.key" 2>/dev/null
chmod 644 "$D/srv/app.key"   # permisos laxos a propósito
openssl pkcs8 -topk8 -v2 aes-256-cbc -passout pass:prueba -in "$D/srv/app.key" -out "$D/srv/app-cifrada.key"
openssl pkey -in "$D/srv/app.key" -traditional -out "$D/legado/app-pkcs1.key"
openssl pkey -in "$D/srv/app.key" -traditional -aes128 -passout pass:prueba -out "$D/legado/app-pkcs1-cifrada.key"
openssl pkey -in "$D/srv/app.key" -pubout -out "$D/srv/app.pub.pem"
openssl ecparam -name secp384r1 -genkey -noout -out "$D/legado/ec384-sec1.key"

# 5. Llave pública ML-DSA-65 sintética (estructura válida, contenido aleatorio).
python3 - "$D/srv/firma-mldsa65.pub.pem" <<'PY'
import base64, os, sys
def tlv(t, b):
    n = len(b)
    if n < 128: l = bytes([n])
    else:
        s = n.to_bytes((n.bit_length() + 7) // 8, "big"); l = bytes([0x80 | len(s)]) + s
    return bytes([t]) + l + b
oid = bytes.fromhex("0609608648016503040312")  # 2.16.840.1.101.3.4.3.18
spki = tlv(0x30, tlv(0x30, oid) + tlv(0x03, b"\x00" + os.urandom(1952)))
b64 = base64.b64encode(spki).decode()
with open(sys.argv[1], "w") as f:
    f.write("-----BEGIN PUBLIC KEY-----\n")
    f.write("\n".join(b64[i:i+64] for i in range(0, len(b64), 64)))
    f.write("\n-----END PUBLIC KEY-----\n")
PY

# 6. SSH.
# Se usa Python (cryptography) para no depender de ssh-keygen.
python3 - "$D/home/ana/.ssh" <<'PY'
import os, sys
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
d = sys.argv[1]
def guardar(nombre, llave, comentario, contrasena=None):
    cifrado = s.BestAvailableEncryption(contrasena) if contrasena else s.NoEncryption()
    with open(os.path.join(d, nombre), "wb") as f:
        f.write(llave.private_bytes(s.Encoding.PEM, s.PrivateFormat.OpenSSH, cifrado))
    os.chmod(os.path.join(d, nombre), 0o600)
    pub = llave.public_key().public_bytes(s.Encoding.OpenSSH, s.PublicFormat.OpenSSH)
    with open(os.path.join(d, nombre + ".pub"), "w") as f:
        f.write(pub.decode() + " " + comentario + "\n")
guardar("id_ed25519", ed25519.Ed25519PrivateKey.generate(), "ana@demo")
guardar("id_rsa", rsa.generate_private_key(public_exponent=65537, key_size=3072), "ana-rsa@demo", b"prueba")
PY
{ echo "# llaves autorizadas"; echo "from=\"10.0.0.0/8\",no-pty $(cat "$D/home/ana/.ssh/id_rsa.pub")"; cat "$D/home/ana/.ssh/id_ed25519.pub"; } > "$D/home/ana/.ssh/authorized_keys"
echo "servidor.ejemplo.mx $(cut -d' ' -f1-2 "$D/home/ana/.ssh/id_ed25519.pub")" > "$D/home/ana/.ssh/known_hosts"

cat > "$D/etc/ssh/sshd_config" <<'CFG'
# Servidor moderno con intercambio híbrido
Port 22
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
CFG

mkdir -p "$D/legado/ssh"
cat > "$D/legado/ssh/sshd_config" <<'CFG'
KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha1
Ciphers aes128-ctr,3des-cbc
MACs hmac-sha1
HostKeyAlgorithms ssh-rsa,ssh-dss
CFG

# 7. Servidores web.
cat > "$D/etc/nginx/nginx.conf" <<'CFG'
server {
    listen 443 ssl;
    server_name www.ejemplo.mx;
    ssl_certificate     /etc/nginx/www.crt;
    ssl_certificate_key /etc/nginx/www.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;
}
CFG
cat > "$D/etc/apache2/ssl.conf" <<'CFG'
<VirtualHost *:443>
    SSLEngine on
    SSLProtocol all -SSLv3
    SSLCertificateFile /etc/ssl/certs/intranet.crt
</VirtualHost>
CFG

# 8. Cifrado de volumen.
cat > "$D/etc/crypttab" <<'CFG'
# nombre  dispositivo  llave  opciones
raiz  UUID=0b1c2d3e-0000-4000-8000-000000000001  none  luks,discard,tpm2-device=auto
datos UUID=0b1c2d3e-0000-4000-8000-000000000002  /root/datos.key  cipher=aes-xts-plain64,size=256
CFG

# 9. Contenedor PKCS#12.
openssl pkcs12 -export -passout pass:prueba -inkey "$D/etc/nginx/www.key" -in "$D/etc/nginx/www.crt" -out "$D/srv/almacen.p12"
# 10. HAProxy: certificado y llave combinados en un directorio.
mkdir -p "$D/etc/haproxy/certs"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 400 -subj "/CN=api.ejemplo.mx" \
  -addext "extendedKeyUsage=serverAuth" -addext "basicConstraints=critical,CA:FALSE" \
  -keyout "$D/etc/haproxy/certs/api.key" -out "$D/etc/haproxy/certs/api.crt" 2>/dev/null
cat "$D/etc/haproxy/certs/api.crt" "$D/etc/haproxy/certs/api.key" > "$D/etc/haproxy/certs/api.pem"
rm "$D/etc/haproxy/certs/api.crt" "$D/etc/haproxy/certs/api.key"
chmod 600 "$D/etc/haproxy/certs/api.pem"
cat > "$D/etc/haproxy/haproxy.cfg" <<'CFG'
global
    ssl-default-bind-curves X25519MLKEM768:X25519:P-256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

frontend publico
    bind :443 ssl crt /etc/haproxy/certs/ alpn h2,http/1.1

frontend heredado
    # Socio que aún no actualiza sus clientes
    bind :8443 ssl crt /etc/haproxy/certs/api.pem curves P-256 ssl-min-ver TLSv1.0
CFG

# 11. PostgreSQL: un servidor con TLS híbrido y otro sin TLS expuesto a la red.
mkdir -p "$D/var/lib/pgsql/data" "$D/legado/pgsql"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -sha384 -nodes -days 400 -subj "/CN=db.ejemplo.mx" \
  -addext "extendedKeyUsage=serverAuth" -addext "basicConstraints=critical,CA:FALSE" \
  -keyout "$D/var/lib/pgsql/data/server.key" -out "$D/var/lib/pgsql/data/server.crt" 2>/dev/null
chmod 600 "$D/var/lib/pgsql/data/server.key"
cat > "$D/var/lib/pgsql/data/postgresql.conf" <<'CFG'
listen_addresses = '*'
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
ssl_min_protocol_version = 'TLSv1.3'
ssl_groups = 'X25519MLKEM768:X25519'   # PostgreSQL 18
CFG
cat > "$D/legado/pgsql/postgresql.conf" <<'CFG'
listen_addresses = '0.0.0.0'
ssl = off
CFG

# 12. Kubernetes: Secret TLS, kubeconfig y cert-manager.
mkdir -p "$D/k8s" "$D/home/ana/.kube"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes -days 90 -subj "/CN=tienda.ejemplo.mx" \
  -addext "extendedKeyUsage=serverAuth" -addext "basicConstraints=critical,CA:FALSE" \
  -keyout "$S_TMP/tienda.key" -out "$S_TMP/tienda.crt" 2>/dev/null
cat > "$D/k8s/secret-tienda.yaml" <<CFG
apiVersion: v1
kind: Secret
metadata:
  name: tienda-tls
  namespace: tienda
type: kubernetes.io/tls
data:
  tls.crt: $(base64 -w0 "$S_TMP/tienda.crt")
  tls.key: $(base64 -w0 "$S_TMP/tienda.key")
CFG
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 -subj "/CN=ana" -addext "extendedKeyUsage=clientAuth" \
  -keyout "$S_TMP/ana.key" -out "$S_TMP/ana.crt" 2>/dev/null
cat > "$D/home/ana/.kube/config" <<CFG
apiVersion: v1
kind: Config
clusters:
- name: produccion
  cluster:
    server: https://k8s.ejemplo.mx:6443
users:
- name: ana
  user:
    client-certificate-data: $(base64 -w0 "$S_TMP/ana.crt")
    client-key-data: $(base64 -w0 "$S_TMP/ana.key")
CFG
cat > "$D/k8s/certificados.yaml" <<'CFG'
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: tienda
  namespace: tienda
spec:
  secretName: tienda-tls
  dnsNames: [tienda.ejemplo.mx]
  privateKey:
    algorithm: ECDSA
    size: 256
    rotationPolicy: Always
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: intranet
  namespace: interno
spec:
  secretName: intranet-tls
  dnsNames: [intranet.ejemplo.mx]
CFG

# 13. Imagen de contenedor (fuera del sistema de demostración): la llave
# se agrega en la capa 1 y se borra en la capa 2, pero sigue en la imagen.
mkdir -p fixtures/imagenes
python3 - fixtures/imagenes "$S_TMP" <<'PY'
import gzip, io, json, os, sys, tarfile
destino, tmp = sys.argv[1], sys.argv[2]
def capa(archivos, comprimir):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as t:
        for nombre, datos, modo in archivos:
            i = tarfile.TarInfo(nombre); i.size = len(datos); i.mode = modo
            t.addfile(i, io.BytesIO(datos))
    crudo = b.getvalue()
    return gzip.compress(crudo, mtime=0) if comprimir else crudo
llave = open(os.path.join(tmp, "tienda.key"), "rb").read()
cert = open(os.path.join(tmp, "tienda.crt"), "rb").read()
nginx = b"server {\n  listen 443 ssl;\n  ssl_certificate /etc/ssl/tienda.crt;\n  ssl_protocols TLSv1.3;\n  ssl_ecdh_curve X25519MLKEM768:X25519;\n}\n"
capas = [
    ("capa1.tar.gz", capa([("etc/ssl/private/tienda.key", llave, 0o600), ("etc/ssl/tienda.crt", cert, 0o644)], True)),
    ("capa2.tar", capa([("etc/nginx/conf.d/tienda.conf", nginx, 0o644), ("etc/ssl/private/.wh.tienda.key", b"", 0o600)], False)),
]
salida = io.BytesIO()
with tarfile.open(fileobj=salida, mode="w") as t:
    def agregar(n, d):
        i = tarfile.TarInfo(n); i.size = len(d); t.addfile(i, io.BytesIO(d))
    for n, d in capas:
        agregar(n, d)
    agregar("manifest.json", json.dumps([{"Config": "config.json", "RepoTags": ["demo/tienda:1.0"], "Layers": [n for n, _ in capas]}]).encode())
    agregar("config.json", b"{}")
open(os.path.join(destino, "tienda-docker.tar"), "wb").write(salida.getvalue())
PY

# 14. VPN: WireGuard, OpenVPN y strongSwan.
mkdir -p "$D/etc/wireguard" "$D/etc/openvpn" "$D/etc/swanctl" "$D/legado/vpn"
cat > "$D/etc/wireguard/wg0.conf" <<'CFG'
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = gI6EdUSYvn8ugXOt8QQD6Yc+JyiZxIhp3GInSWRfWGE=

[Peer]
# Sucursal Culiacán
PublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=
PresharedKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=
AllowedIPs = 10.8.0.2/32

[Peer]
# Teletrabajo
PublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=
AllowedIPs = 10.8.0.3/32
CFG
chmod 600 "$D/etc/wireguard/wg0.conf"
cat > "$D/etc/openvpn/server.conf" <<'CFG'
port 1194
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
dh none
tls-version-min 1.2
tls-groups X25519MLKEM768:X25519
data-ciphers AES-256-GCM:CHACHA20-POLY1305
tls-crypt /etc/openvpn/tc.key
CFG
cat > "$D/legado/vpn/cliente.ovpn" <<'CFG'
client
dev tun
remote vpn.ejemplo.mx 1194
cipher BF-CBC
auth SHA1
tls-version-min 1.0
CFG
cat > "$D/etc/swanctl/swanctl.conf" <<'CFG'
connections {
    sucursales {
        version = 2
        proposals = aes256gcm16-sha384-x25519-ke1_mlkem768, aes256-sha256-modp2048
        children {
            red {
                esp_proposals = aes256gcm16-ecp384
            }
        }
    }
}
CFG
cat > "$D/legado/vpn/ipsec.conf" <<'CFG'
conn proveedor
    keyexchange=ikev1
    ike=3des-md5-modp1024!
    esp=3des-md5!
CFG

# 15. Bases de datos MySQL/MariaDB y correo Postfix.
mkdir -p "$D/etc/mysql/mysql.conf.d" "$D/etc/postfix" "$D/legado/mysql" "$D/legado/postfix"
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 400 -subj "/CN=mysql.ejemplo.mx" \
  -addext "extendedKeyUsage=serverAuth" -addext "basicConstraints=critical,CA:FALSE" \
  -keyout "$D/etc/mysql/server-key.pem" -out "$D/etc/mysql/server-cert.pem" 2>/dev/null
chmod 600 "$D/etc/mysql/server-key.pem"
cat > "$D/etc/mysql/mysql.conf.d/mysqld.cnf" <<'CFG'
[mysqld]
bind-address = 0.0.0.0
ssl-cert = /etc/mysql/server-cert.pem
ssl-key = /etc/mysql/server-key.pem
tls_version = TLSv1.3
require_secure_transport = ON
CFG
cat > "$D/legado/mysql/my.cnf" <<'CFG'
[client]
port = 3306

[mysqld]
bind-address = 0.0.0.0
tls_version = TLSv1,TLSv1.1,TLSv1.2
CFG
# Postfix admite llave y cadena en un solo archivo (smtpd_tls_chain_files).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes -days 400 -subj "/CN=correo.ejemplo.mx" \
  -addext "extendedKeyUsage=serverAuth" -addext "basicConstraints=critical,CA:FALSE" \
  -keyout "$S_TMP/correo.key" -out "$S_TMP/correo.crt" 2>/dev/null
cat "$S_TMP/correo.key" "$S_TMP/correo.crt" > "$D/etc/postfix/correo.pem"
chmod 600 "$D/etc/postfix/correo.pem"
cat > "$D/etc/postfix/main.cf" <<'CFG'
myhostname = correo.ejemplo.mx
inet_interfaces = all
smtpd_tls_chain_files = $config_directory/correo.pem
smtpd_tls_security_level = may
smtpd_tls_protocols = >=TLSv1.2
smtpd_tls_mandatory_protocols = >=TLSv1.2
tls_eecdh_auto_curves = X25519MLKEM768 X25519
    prime256v1
smtp_tls_security_level = dane
CFG
cat > "$D/legado/postfix/main.cf" <<'CFG'
myhostname = viejo.ejemplo.mx
inet_interfaces = all
smtpd_tls_security_level = none
CFG

# 16. Política criptográfica de Java: la predeterminada y una recortada.
mkdir -p "$D/etc/java-21-openjdk/security" "$D/legado/java"
cat > "$D/etc/java-21-openjdk/security/java.security" <<'CFG'
keystore.type=pkcs12
jdk.certpath.disabledAlgorithms=MD2, MD5, SHA1 jdkCA & usage TLSServer, \
    RSA keySize < 1024, DSA keySize < 1024, EC keySize < 224, \
    SHA1 usage SignedJAR & denyAfter 2019-01-01
jdk.jar.disabledAlgorithms=MD2, MD5, RSA keySize < 1024, \
      DSA keySize < 1024, SHA1 denyAfter 2019-01-01
jdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, DTLSv1.0, RC4, DES, \
    MD5withRSA, DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, \
    NULL, ECDH
CFG
cat > "$D/legado/java/java.security" <<'CFG'
# Recortada «por compatibilidad» con un proveedor antiguo.
keystore.type=jks
jdk.certpath.disabledAlgorithms=MD2, RSA keySize < 1024
jdk.tls.disabledAlgorithms=SSLv3, RC4, DES, MD5withRSA, anon, NULL
CFG

# 17. Código fuente con usos buenos y malos (los comentarios no deben contar).
mkdir -p "$D/srv/app"
cat > "$D/srv/app/pagos.py" <<'SRC'
import hashlib
import requests
from cryptography.hazmat.primitives.asymmetric import rsa

# Antes usábamos hashlib.sha1(); ya no.
def huella(datos):
    return hashlib.md5(datos).hexdigest()

def llave():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)

def consultar(url):
    return requests.get(url, verify=False)
SRC
cat > "$D/srv/app/Firma.java" <<'SRC'
import java.security.*;
import javax.crypto.*;

public class Firma {
    // MessageDigest.getInstance("MD5") quedó fuera.
    byte[] resumen(byte[] d) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(d);
    }
    Cipher cifrador() throws Exception {
        return Cipher.getInstance("AES");
    }
    KeyPair par() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }
    KeyPair kem() throws Exception {
        return KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair();
    }
    Signature firma() throws Exception {
        return Signature.getInstance("SHA256withRSA");
    }
}
SRC
cat > "$D/srv/app/main.go" <<'SRC'
package main

import (
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/tls"
)

// md5.Sum ya no se usa.
func config() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	}
}

func llave() (*mlkem.DecapsulationKey768, [32]byte) {
	k, _ := mlkem.GenerateKey768()
	return k, sha256.Sum256([]byte("x"))
}
SRC
cat > "$D/srv/app/cliente.ts" <<'SRC'
import { createHash, createCipheriv, generateKeyPairSync } from "node:crypto";
import https from "node:https";

export const huella = (d: Buffer) => createHash("sha1").update(d).digest("hex");
export const cifrador = (k: Buffer, iv: Buffer) => createCipheriv("aes-256-gcm", k, iv);
export const par = () => generateKeyPairSync("rsa", { modulusLength: 3072 });
export const agente = new https.Agent({ rejectUnauthorized: false });
SRC
cat > "$D/srv/app/Cifrado.cs" <<'SRC'
using System.Security.Cryptography;
using System.Security.Authentication;

class Cifrado {
    byte[] Huella(byte[] d) => SHA1.Create().ComputeHash(d);
    SymmetricAlgorithm Viejo() => TripleDES.Create();
    MLKem Nuevo() => MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
    SslProtocols Protocolos() => SslProtocols.Tls12 | SslProtocols.Tls13;
}
SRC
cat > "$D/srv/app/firma.rs" <<'SRC'
use ml_kem::{KemCore, MlKem768};
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};

/// Ejemplo: Sha1::new() en un comentario no cuenta.
pub fn llaves(rng: &mut impl rand_core::CryptoRngCore) {
    let _ = MlKem768::generate(rng);
    let _ = RsaPrivateKey::new(&mut rng, 2048);
    let _ = Sha256::new();
}
SRC
cat > "$D/srv/app/legado.c" <<'SRC'
#include <openssl/ssl.h>
#include <openssl/evp.h>

/* EVP_md5() se retiró. */
SSL_CTX *contexto(void) {
    SSL_CTX *ctx = SSL_CTX_new(SSLv3_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    return ctx;
}

const EVP_CIPHER *cifrador(void) { return EVP_des_ede3_cbc(); }
SRC

# 18. Bibliotecas criptográficas: manifiestos, un JAR y un binario sintético.
mkdir -p "$D/srv/app/lib" "$D/srv/bin"
cat > "$D/srv/app/requirements.txt" <<'CFG'
cryptography==41.0.7
pycrypto==2.6.1
requests>=2.31
CFG
cat > "$D/srv/app/go.mod" <<'CFG'
module ejemplo.mx/pagos

go 1.22

require (
	golang.org/x/crypto v0.21.0
	github.com/cloudflare/circl v1.3.7
)
CFG
cat > "$D/srv/app/package-lock.json" <<'CFG'
{
  "name": "cliente",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "cliente" },
    "node_modules/crypto-js": { "version": "4.2.0" },
    "node_modules/@noble/post-quantum": { "version": "0.4.1" }
  }
}
CFG
cat > "$D/srv/app/pom.xml" <<'CFG'
<project>
  <properties>
    <bc.version>1.80</bc.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>${bc.version}</version>
    </dependency>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk15on</artifactId>
      <version>1.70</version>
    </dependency>
  </dependencies>
</project>
CFG
cat > "$D/srv/app/Cargo.lock" <<'CFG'
version = 3

[[package]]
name = "openssl-src"
version = "300.3.1+3.3.1"

[[package]]
name = "ml-kem"
version = "0.2.1"
CFG
: > "$D/srv/app/lib/bcprov-jdk18on-1.78.1.jar"
printf '\177ELF\002\001\001\000junk\000OpenSSL 1.1.1w  11 Sep 2023\000fin\000' > "$D/srv/bin/herramienta"
chmod 755 "$D/srv/bin/herramienta"

echo "Sistema de demostración generado en $D"
