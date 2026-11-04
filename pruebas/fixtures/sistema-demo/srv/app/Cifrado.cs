using System.Security.Cryptography;
using System.Security.Authentication;

class Cifrado {
    byte[] Huella(byte[] d) => SHA1.Create().ComputeHash(d);
    SymmetricAlgorithm Viejo() => TripleDES.Create();
    MLKem Nuevo() => MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
    SslProtocols Protocolos() => SslProtocols.Tls12 | SslProtocols.Tls13;
}
