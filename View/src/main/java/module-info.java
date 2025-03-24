module org.zespol6.view {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.controlsfx.controls;
    requires AES;

    opens org.zespol6.view to javafx.fxml;
    exports org.zespol6.view;

}