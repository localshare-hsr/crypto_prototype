package ch.hsr.epj.cryptoprototype;

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

public class Main {

  private static final String PATH = "keys/";
  private static final String FRIENDLY_NAME = "Max";

  public static void main(String[] args) {
    File filePath = new File(PATH);
    if (!filePath.exists()) {
      filePath.mkdir();
    }
    filePath = filePath.getAbsoluteFile();
    char[] password = "foobar".toCharArray();

    KeyStore ks = null;
    try {
      ks = loadKeyStore(filePath, password);
    } catch (FileNotFoundException e) {
      try {
        ks = createNewKeyStore(password);
        generateNewCertificate(ks, password);
        saveNewKeyStore(ks, filePath, password);
      } catch (KeyStoreException
          | IOException
          | CertificateException
          | NoSuchAlgorithmException
          | SignatureException
          | NoSuchProviderException
          | InvalidKeyException e1) {
        e1.printStackTrace();
      }
    } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
      e.printStackTrace();
    }

    startWebserver(ks, password);
  }

  private static KeyStore loadKeyStore(File path, char[] password)
      throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
    System.out.println("Load KeyStore" + path + "/keystore.p12");
    KeyStore ks = KeyStore.getInstance("pkcs12");
    ks.load(new FileInputStream(path + "/keystore.p12"), password);
    return ks;
  }

  private static KeyStore createNewKeyStore(char[] password)
      throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
    System.out.println("Create new KeyStore");
    KeyStore ks = KeyStore.getInstance("pkcs12");
    ks.load(null, password);
    return ks;
  }

  private static void saveNewKeyStore(KeyStore ks, File path, char[] password)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    System.out.println("Save new KeyStore" + path + "/keystore.p12");
    FileOutputStream fos = new FileOutputStream(path + "/keystore.p12");
    ks.store(fos, password);
  }

  private static void generateNewCertificate(KeyStore ks, char[] password)
      throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, IOException,
      CertificateException, SignatureException, KeyStoreException {
    System.out.println("Generate new certificate");

    CertAndKeyGen certGen = new CertAndKeyGen("EC", "SHA256withECDSA", null);
    certGen.generate(256);

    long validSecs = (long) 356 * 24 * 3600;
    X509Certificate cert =
        certGen.getSelfCertificate(new X500Name("CN=" + FRIENDLY_NAME), validSecs);

    X509Certificate[] chain = new X509Certificate[1];
    chain[0] = cert;
    ks.setKeyEntry("me", certGen.getPrivateKey(), password, chain);
  }

  private static String readCertificateData(KeyStore ks) {
    String cert = "";
    try {
      Certificate me = ks.getCertificate("me");
      cert = me.toString();
    } catch (KeyStoreException e) {
      e.printStackTrace();
    }

    return cert;
  }

  private static void startWebserver(KeyStore ks, char[] password) {
    try {
      SSLContext context = SSLContext.getInstance("TLS");
      KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
      kmf.init(ks, password);
      context.init(kmf.getKeyManagers(), null, null);

      SSLServerSocketFactory factory = context.getServerSocketFactory();
      SSLServerSocket server = (SSLServerSocket) factory.createServerSocket(8640);

      System.out.println("Start TLS Server on https://localhost:8640");

      while (true) {
        try (Socket connection = server.accept()) {
          InputStream in = new BufferedInputStream(connection.getInputStream());
          Writer out =
              new BufferedWriter(
                  new OutputStreamWriter(connection.getOutputStream(), StandardCharsets.US_ASCII));

          StringBuilder sb = new StringBuilder(80);
          while (true) {
            int c = in.read();
            if (c == '\r' || c == '\n' || c == -1) {
              break;
            }
            sb.append((char) c);
          }
          System.out.println(sb.toString());

          out.write("HTTP/1.1 200 OK\r\n");
          out.write("Content-type: text/html\r\n\r\n");
          out.write("<html><head></head><body><p>Hello pascal</p><p>");
          out.write(readCertificateData(ks));
          out.write("</p></body></html>\r\n\r\n");
          out.flush();

        } catch (IOException ex) {
          ex.printStackTrace();
        }
      }

    } catch (NoSuchAlgorithmException
        | KeyStoreException
        | UnrecoverableKeyException
        | KeyManagementException
        | IOException e) {
      e.printStackTrace();
    }
  }
}
