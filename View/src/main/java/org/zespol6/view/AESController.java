package org.zespol6.view;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.control.TextArea;
import org.zespol6.aes.AES;

import java.math.BigInteger;

public class AESController {

    @FXML
    Button keyGenButton;

    @FXML
    Button encryptButton;

    @FXML
    Button decryptButton;

    @FXML
    Button copyEncryptedDataButton;

    @FXML
    Button copyDecryptedDataButton;

    @FXML
    TextArea dataField;

    @FXML
    TextArea encryptedDataField;

    @FXML
    TextField keyField;

    @FXML
    public void initialize() {

        AES aes = new AES();
        final javafx.scene.input.Clipboard clipboard = javafx.scene.input.Clipboard.getSystemClipboard();
        final javafx.scene.input.ClipboardContent content = new javafx.scene.input.ClipboardContent();

        keyGenButton.setOnAction(e -> {
            aes.generateMainKey();
            keyField.setText(aes.getMainKey().toString(16).toUpperCase());
        });

        encryptButton.setOnAction(e -> {
            try {
                String keyHex = keyField.getText().toLowerCase();
                BigInteger keyBigInt = new BigInteger(keyHex, 16);
                aes.setMainKey(keyBigInt);
                aes.readStringToBytes(dataField.getText());
                byte[] expectedData= aes.encrypt(aes.getData(), aes.getMainKey());
                encryptedDataField.setText(aes.bytesToHex(expectedData));
            } catch (NumberFormatException ex) {
                encryptedDataField.setText("Error: Invalid key format");
            } catch (Exception ex) {
                encryptedDataField.setText("Error: " + ex.getMessage());
            }
        });

        decryptButton.setOnAction(e -> {
            try {
                String keyHex = keyField.getText().toLowerCase();
                BigInteger keyBigInt = new BigInteger(keyHex, 16);
                aes.setMainKey(keyBigInt);

                // Hex string konwertujemy na tablicę bajtów
                byte[] encryptedBytes = aes.hexToBytes(encryptedDataField.getText());

                byte[] expectedData = aes.decrypt(encryptedBytes, aes.getMainKey());
                dataField.setText(aes.bytesToString(expectedData));
            } catch (NumberFormatException ex) {
                dataField.setText("Error: Invalid key format");
            } catch (Exception ex) {
                dataField.setText("Error: " + ex.getMessage());
            }
        });

        copyEncryptedDataButton.setOnAction(e -> {
            content.putString(encryptedDataField.getText());
            clipboard.setContent(content);
        });

        copyDecryptedDataButton.setOnAction(e -> {
            content.putString(dataField.getText());
            clipboard.setContent(content);
        });


    }

}