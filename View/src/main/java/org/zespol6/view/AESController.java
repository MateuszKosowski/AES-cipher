/*
 * Nazwa programu: AES-cipher
 * Copyright (C) 2025  Mateusz Kosowski Nikodem Nowak
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package org.zespol6.view;

import javafx.fxml.FXML;
import javafx.scene.control.*;

import java.io.*;

import org.zespol6.aes.AES;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Objects;

public class AESController {

    @FXML
    public Label keyLabel;

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
    Button saveDecryptedButton;

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
    RadioButton field;

    @FXML
    RadioButton file;

    @FXML
    ToggleGroup fieldOrFile;

    byte[] originalDataFile;
    byte[] encryptedDataFile;
    byte[] originalDataTextField;
    byte[] encryptedDataTextField;
    byte[] keyData;

    @FXML
    public void initialize() {
        key.selectedToggleProperty().addListener((observable, oldValue, newValue) -> keyField.clear());

        AES aes = new AES();
        final javafx.scene.input.Clipboard clipboard = javafx.scene.input.Clipboard.getSystemClipboard();
        final javafx.scene.input.ClipboardContent content = new javafx.scene.input.ClipboardContent();

        keyGenButton.setOnAction(e -> {
            int keyLength = getKeySize();
            aes.generateMainKey(keyLength);
            keyData = aes.getMainKey().toByteArray();
            keyField.setText(aes.bytesToHex(keyData));
        });

        keySaveButton.setOnAction(e -> saveButtonAction(keyField, null, 2));

        keyLoadButton.setOnAction(e -> {
            loadButtonAction(null, keyField, 2);
            String keyHex = keyField.getText();
            switch (keyField.getLength() * 4) {
                case 128:
                    key128.setSelected(true);
                    break;
                case 192:
                    key192.setSelected(true);
                    break;
                case 256:
                    key256.setSelected(true);
                    break;
            }
            keyField.setText(keyHex);
        });

        encryptButton.setOnAction(e -> {
            try {
                String keyHex = aes.bytesToHex(keyData);
                BigInteger keyBigInt = new BigInteger(keyHex, 16);
                aes.setMainKey(keyBigInt);
                byte[] expectedData;
                if (field.isSelected()) {
                    originalDataTextField = dataField.getText().getBytes(StandardCharsets.UTF_8);
                    expectedData = aes.encrypt(originalDataTextField, aes.getMainKey());
                    encryptedDataTextField = Arrays.copyOf(expectedData, expectedData.length);
                } else {
                    expectedData = aes.encrypt(originalDataFile, aes.getMainKey());
                    encryptedDataFile = Arrays.copyOf(expectedData, expectedData.length);
                }
                encryptedDataField.setText(aes.bytesToHex(expectedData));
            } catch (NumberFormatException ex) {
                encryptedDataField.setText("Error: Invalid key format");
            } catch (Exception ex) {
                encryptedDataField.setText("Error: " + ex.getMessage());
            }
        });

        loadEncryptedButton.setOnAction(e -> loadButtonAction(encryptedDataField, null, 0));

        loadDecryptedButton.setOnAction(e -> loadButtonAction(dataField, null, 1));

        decryptButton.setOnAction(e -> {
            try {
                String keyHex = aes.bytesToHex(keyData);
                BigInteger keyBigInt = new BigInteger(keyHex, 16);
                aes.setMainKey(keyBigInt);

                // Hex string konwertujemy na tablicę bajtów
                byte[] expectedData;
                if (field.isSelected()) {
                    byte[] encryptedBytes = aes.hexToBytes(encryptedDataField.getText());
                    expectedData = aes.decrypt(encryptedBytes, aes.getMainKey());
                    originalDataTextField = Arrays.copyOf(expectedData, expectedData.length);
                    dataField.setText(new String(expectedData, StandardCharsets.UTF_8));
                } else {
                    expectedData = aes.decrypt(encryptedDataFile, aes.getMainKey());
                    originalDataFile = Arrays.copyOf(expectedData, expectedData.length);
                    dataField.setText(aes.bytesToHex(expectedData));
                }

            } catch (NumberFormatException ex) {
                dataField.setText("Error: Invalid key format, key: " + new String(keyData).toLowerCase());
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

        saveEncryptedButton.setOnAction(e -> saveButtonAction(null, encryptedDataField, 0));

        saveDecryptedButton.setOnAction(e -> saveButtonAction(null, dataField, 3));
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
                new javafx.stage.FileChooser.ExtensionFilter("Wszystkie pliki", "*.*")
        );
        File selectedFile = fileChooser.showOpenDialog(null);

        if (selectedFile != null) {
            try {
                byte[] data = Files.readAllBytes(selectedFile.toPath());
                switch (option) {
                    case 0:
                        encryptedDataFile = Arrays.copyOf(data, data.length);
                        file.setSelected(true);
                        break;
                    case 1:
                        originalDataFile = Arrays.copyOf(data, data.length);
                        file.setSelected(true);
                        break;
                    case 3:
                        keyData = Arrays.copyOf(data, data.length);
                        break;
                    default:
                        break;
                }
                AES aes = new AES();
                if (textArea != null) {
                    textArea.setText(aes.bytesToHex(data));
                } else {
                    textField.setText(aes.bytesToHex(data));
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
            case 3:
                fileChooser.setTitle("Zapisz odszyfrowane dane");
                break; // Dodany break
            default:
                fileChooser.setTitle("Zapisz plik");
                break;
        }
        fileChooser.getExtensionFilters().addAll(
                new javafx.stage.FileChooser.ExtensionFilter("Wszystkie pliki", "*.*")
        );
        File selectedFile = fileChooser.showSaveDialog(null);

        if (selectedFile != null) {
            try {
                byte[] dataToSave = null;

                switch (option) {
                    case 0: // Zaszyfrowane dane
                        if (field.isSelected() && encryptedDataTextField != null) {
                            dataToSave = encryptedDataTextField;
                        } else if (encryptedDataFile != null) {
                            dataToSave = encryptedDataFile;
                        }
                        break;
                    case 2: // Klucz
                        if (keyData != null) {
                            dataToSave = keyData;
                        }
                        break;
                    case 3: // Odszyfrowane dane
                        if (field.isSelected() && originalDataTextField != null) {
                            dataToSave = originalDataTextField;
                        } else if (originalDataFile != null) {
                            dataToSave = originalDataFile;
                        }
                        break;
                }

                if (dataToSave != null) {
                    java.nio.file.Files.write(selectedFile.toPath(), dataToSave);
                } else {
                    throw new IOException("Brak danych do zapisania");
                }

            } catch (IOException ex) {
                if (textArea != null) {
                    textArea.setText("Error: " + ex.getMessage());
                } else if (textField != null) {
                    textField.setText("Error: " + ex.getMessage());
                }
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