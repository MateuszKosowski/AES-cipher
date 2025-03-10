import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zespol6.*;
import java.math.BigInteger;

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
    public void testGenerateKey() {
        aes.generateMainKey();
        BigInteger key = aes.getMainKey();
        System.out.println("-----------------------------------");
        System.out.println("Generated key (hex): " + key.toString(16).toUpperCase());
    }

    @Test
    public void testReadFile() {
        aes.readFile("src/main/resources/testFile.txt");
        byte[] data = aes.getData();
        System.out.println("-----------------------------------");
        System.out.println("Read data from file (bytes): " + new String(data));
        System.out.println("Read data from file (hex): " + bytesToHex(data));
    }

    @Test
    public void testSplitIntoBlocks() {
        aes.readFile("src/main/resources/testFile.txt");
        byte[] data = aes.getData();
        byte[][] blocks = aes.splitIntoBlocks(data);
        System.out.println("-----------------------------------");
        System.out.println("Split data into blocks:");
        for (int i = 0; i < blocks.length; i++) {
            System.out.println("Block " + i + " (hex): " + bytesToHex(blocks[i]));
        }
    }

    @Test
    public void testAddRoundKey() {
        aes.readFile("src/main/resources/testFile.txt");
        byte[] data = aes.getData();
        byte[][] blocks = aes.splitIntoBlocks(data);
        aes.generateMainKey();
        BigInteger key = aes.getMainKey();
        byte[] keyBytes = key.toByteArray();

        System.out.println("-----------------------------------");
        System.out.println("Round key (hex): " + key.toString(16).toUpperCase());
        System.out.println("Round key in bytes (hex): " + bytesToHex(keyBytes));
        System.out.println("XOR result:");

        for (int i = 0; i < blocks.length; i++) {
            System.out.println("Before XOR - Block " + i + " (hex): " + bytesToHex(blocks[i]));
            aes.addRoundKey(blocks[i], key);
            System.out.println("After XOR  - Block " + i + " (hex): " + bytesToHex(blocks[i]));
        }
    }
}
