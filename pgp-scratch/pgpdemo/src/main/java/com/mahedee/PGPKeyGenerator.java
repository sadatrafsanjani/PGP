package com.mahedee;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PGPKeyGenerator {

    private static Logger logger = Logger.getLogger(PGPKeyGenerator.class.getName());

    public static void generateKeyPair(String identity, String passphrase) {

        try {

            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);

            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
            PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPair, new Date());

            PGPSecretKey secretKey = new PGPSecretKey(
                    PGPSignature.DEFAULT_CERTIFICATION,
                    pgpKeyPair,
                    identity,
                    sha1Calc,
                    null,
                    null,
                    new JcaPGPContentSignerBuilder(pgpKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                    new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc)
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(passphrase.toCharArray())
            );

            ArmoredOutputStream publicKey = new ArmoredOutputStream(Files.newOutputStream(Paths.get("public_key.pgp")));
            secretKey.getPublicKey().encode(publicKey);

            ArmoredOutputStream privateKey = new ArmoredOutputStream(Files.newOutputStream(Paths.get("private_key.pgp")));
            secretKey.encode(privateKey);

            logger.log(Level.INFO,"Keys generated and saved to files.");
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException | PGPException | IOException e) {

            throw new RuntimeException(e.getCause());
        }
    }
}