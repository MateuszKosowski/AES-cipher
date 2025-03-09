import org.junit.jupiter.api.BeforeEach;
import org.zespol6.*;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;


public class aesTest {

    AES aes;

    @BeforeEach
    public void setUp() {
        aes = new AES();
    }

    @Test
    public void testGenerateKey() {
        BigInteger key = aes.generateKey();
        System.out.println("\n Generated first key: " + key.toString(16));
    }

    @Test
    public void testReadFile() {
        byte[] data = aes.readFile("src/main/resources/testFile.txt");
        System.out.println("\n Read data from file:");
        for (byte b : data) {
            System.out.print(b + " ");
        }
    }

}
