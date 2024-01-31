##### Pergunta P.VII.1.2

1. Desenvolva em java uma aplicação linha de comando que permita assinar e verificar a assinatura de um ficheiro. Para a cifra assimétrica e hash, utilize os seguintes algoritmos, consoante o número do seu grupo:

- Grupo 11: ECC com curva brainpoolP384r1 e SHA384, utilizando os providers do BouncyCastle;

  ```java
  import java.io.UnsupportedEncodingException;
  import java.security.InvalidAlgorithmParameterException;
  import java.security.InvalidKeyException;
  import java.security.KeyPair;
  import java.security.KeyPairGenerator;
  import java.security.NoSuchAlgorithmException;
  import java.security.NoSuchProviderException;
  import java.security.SecureRandom;
  import java.security.Security;
  import java.security.Signature;
  import java.security.SignatureException;
  import org.bouncycastle.jce.ECNamedCurveTable;
  import org.bouncycastle.jce.provider.BouncyCastleProvider;
  import org.bouncycastle.jce.spec.ECParameterSpec;

  public class ecdsa {



      public static byte[] GenerateSignature(String plaintext, KeyPair keys)
              throws SignatureException, UnsupportedEncodingException,
              InvalidKeyException, NoSuchAlgorithmException,
              NoSuchProviderException {
          Signature sign = Signature
                  .getInstance("SHA384withECDSA", "BC");
          sign.initSign(keys.getPrivate());
          sign.update(plaintext.getBytes("UTF-8"));
          byte[] signature = sign.sign();
          System.out.println(signature.toString());
          return signature;
      }

      public static boolean ValidateSignature(String plaintext, KeyPair pair,
              byte[] signature) throws SignatureException,
              InvalidKeyException, UnsupportedEncodingException,
              NoSuchAlgorithmException, NoSuchProviderException {
          Signature verify = Signature.getInstance("SHA384withECDSA",
                  "BC");
          verify.initVerify(pair.getPublic());
          verify.update(plaintext.getBytes("UTF-8"));
          return verify.verify(signature);
      }

      public static KeyPair GenerateKeys() throws NoSuchAlgorithmException,
              NoSuchProviderException, InvalidAlgorithmParameterException {
        ECParameterSpec ecSpec = ECNamedCurveTable
                  .getParameterSpec("brainpoolP384r1");

          KeyPairGenerator keygen = KeyPairGenerator.getInstance("ECDSA", "BC");

          keygen.initialize(ecSpec, new SecureRandom());

          return keygen.generateKeyPair();
      }

      public static void main(String[] args) throws Exception {

          Security.addProvider(new BouncyCastleProvider());

          String plaintext = "Plain text";
          KeyPair keys = GenerateKeys();

          byte[] signature = GenerateSignature(plaintext, keys);

          boolean isValidated = ValidateSignature(plaintext, keys, signature);
          System.out.println("Resultado: " + isValidated);
      }

  }
  ```
