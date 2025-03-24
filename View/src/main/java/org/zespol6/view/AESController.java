package org.zespol6.view;

import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import org.zespol6.*;

public class AESController {

    @FXML
    Button keyGenButton;

    @FXML
    TextField keyField;

    @FXML
    public void initialize() {

        AES aes = new AES();


        keyGenButton.setOnAction(e -> {
            aes.generateMainKey();
            keyField.setText(aes.getMainKey().toString(16).toUpperCase());
        });
    }

}