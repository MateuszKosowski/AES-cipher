package org.zespol6.view;

import javafx.fxml.FXML;
import javafx.scene.control.*;

import java.io.*;
import org.zespol6.aes.AES;

import java.math.BigInteger;
import java.util.Objects;

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
    Button loadEncryptedButton;

    @FXML
    Button loadDecryptedButton;

    @FXML
    Button saveEncryptedButton;

    @FXML
    Button keySaveButton;

    @FXML
    Button keyLoadButton;

    @FXML
    TextArea dataField;

    @FXML
    TextArea encryptedDataField;

    @FXML
    TextField keyField;

    @FXML
    RadioButton key128;

    @FXML
    RadioButton key192;

    @FXML
    RadioButton key256;

    @FXML
    ToggleGroup key;

    @FXML
    public void initialize() {

        key.selectedToggleProperty().addListener((observable, oldValue, newValue) -> {
            keyField.clear();
        });

        AES aes = new AES();
        final javafx.scene.input.Clipboard clipboard = javafx.scene.input.Clipboard.getSystemClipboard();
        final javafx.scene.input.ClipboardContent content = new javafx.scene.input.ClipboardContent();

        keyGenButton.setOnAction(e -> {
            int keyLength = getKeySize();
            // TODO: Implementacja generowania klucza AES o określonej długości
            aes.generateMainKey();
            keyField.setText(aes.getMainKey().toString(16).toUpperCase());
        });

        keySaveButton.setOnAction(e -> {
            saveButtonAction(keyField, null, 2);
        });

        keyLoadButton.setOnAction(e -> {
            loadButtonAction(null, keyField, 2);
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

        loadEncryptedButton.setOnAction(e -> {
            loadButtonAction(encryptedDataField, null, 0);
        });

        loadDecryptedButton.setOnAction(e -> {
            loadButtonAction(dataField, null, 1);
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

        saveEncryptedButton.setOnAction(e -> {
            saveButtonAction(null, encryptedDataField, 0);
        });
    }

    private void loadButtonAction(TextArea textArea, TextField textField, int option) {
        // Otworzenie okienka dialogowego do wyboru pliku
        javafx.stage.FileChooser fileChooser = new javafx.stage.FileChooser();
        switch (option) {
            case 0:
                fileChooser.setTitle("Wybierz plik z zaszyfrowanymi danymi");
                break;
            case 1:
                fileChooser.setTitle("Wybierz plik z odszyfrowanymi danymi");
                break;
            case 2:
                fileChooser.setTitle("Wybierz plik z kluczem");
                break;
            default:
                fileChooser.setTitle("Wybierz plik");
                break;
        }
        fileChooser.getExtensionFilters().addAll(
                new javafx.stage.FileChooser.ExtensionFilter("Wszystkie pliki", "*.*"),
                new javafx.stage.FileChooser.ExtensionFilter("Pliki tekstowe", "*.txt")
        );
        File selectedFile = fileChooser.showOpenDialog(null);

        if (selectedFile != null) {
            try {
                String contentLoad = new String(java.nio.file.Files.readAllBytes(selectedFile.toPath()));
                if (textArea != null) {
                    textArea.setText(contentLoad);
                } else {
                    textField.setText(contentLoad);
                }
            } catch (IOException ex) {
                if (textArea != null) {
                    textArea.setText("Error: " + ex.getMessage());
                } else {
                    textField.setText("Error: " + ex.getMessage());
                }
            }
        }
    }

    private void saveButtonAction(TextField textField, TextArea textArea, int option) {
        // Otworzenie okienka dialogowego do wyboru pliku
        javafx.stage.FileChooser fileChooser = new javafx.stage.FileChooser();
        switch (option) {
            case 0:
                fileChooser.setTitle("Zapisz zaszyfrowane dane");
                break;
            case 2:
                fileChooser.setTitle("Zapisz klucz");
                break;
            default:
                fileChooser.setTitle("Zapisz plik");
                break;
        }
        fileChooser.getExtensionFilters().addAll(
                new javafx.stage.FileChooser.ExtensionFilter("Pliki tekstowe", "*.txt")
        );
        File selectedFile = fileChooser.showSaveDialog(null);

        if (selectedFile != null) {
            try {
                if (textArea != null) {
                    java.nio.file.Files.write(selectedFile.toPath(), textArea.getText().getBytes());
                } else {
                    java.nio.file.Files.write(selectedFile.toPath(), textField.getText().getBytes());
                }
            } catch (IOException ex) {
                Objects.requireNonNullElse(textArea, textField).setText("Error: " + ex.getMessage());
            }
        }
    }

    private int getKeySize() {
        if (key128.isSelected()) {
            return 128;
        } else if (key192.isSelected()) {
            return 192;
        } else if (key256.isSelected()) {
            return 256;
        }
        return 128; // Domyślny rozmiar klucza
    }
}