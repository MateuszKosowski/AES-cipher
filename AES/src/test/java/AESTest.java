import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zespol6.aes.AES;

public class AESTest {
    AES aes;

    @BeforeEach
    public void setUp() {
        aes = new AES();
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }

    @Test
    public void testEncrypt() {
        aes.generateMainKey(256);
        aes.readFile("src/main/resources/testFile.txt");
        aes.getData();
        System.out.println("-----------------------------------");
        System.out.println("Generated key (hex): " + aes.getMainKey().toString(16).toUpperCase());
        aes.keyExpansion(aes.getMainKey());
        byte[] bigKlucz = aes.getExpandedKey();
        System.out.println("Key expansion:" + bytesToHex(bigKlucz));
        System.out.println("Read data from file (hex): " + bytesToHex(aes.getData()));
        byte[] expectedData= aes.encrypt(aes.getData(), aes.getMainKey());
        System.out.println("Encrypted data: " + bytesToHex(expectedData));
        byte[] decryptedData = aes.decrypt(expectedData, aes.getMainKey());
        System.out.println("Decrypted data: " + aes.bytesToString(decryptedData));
    }

}
