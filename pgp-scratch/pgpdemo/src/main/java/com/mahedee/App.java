package com.mahedee;

import java.time.LocalDateTime;
import java.util.logging.Level;
import java.util.logging.Logger;

public class App {

    private static Logger logger = Logger.getLogger(App.class.getName());

    public static void main(String[] args) {

        try {

            // print current date time
            logger.log(Level.INFO, "Current Date and Time " + LocalDateTime.now());

            PGPKeyGenerator.generateKeyPair("test@example.com", "strong-passphrase");
            logger.log(Level.INFO, "Public Key and Private Key written to public_key.pgp and private_key.pgp.");
        }
        catch (Exception e) {
            logger.log(Level.SEVERE, e.getMessage());
        }
    }
}