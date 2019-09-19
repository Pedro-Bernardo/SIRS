package pt.ulisboa.tecnico.meic.sirs;

import javax.crypto.Cipher;
import java.io.IOException;

/**
 * Encrypts an image with the AES algorithm in multiple modes, with a given, appropriate AES key
 */
public class ImageRSACipher {

    public static void main(String[] args) throws IOException {

        if(args.length != 4) {
            System.err.println("This program encrypts an image file with RSA.");
            System.err.println("Usage: ImageRSACipher [inputFile.png] [publicKey] [ECB|CBC|OFB] [outputFile.png]");
            return;
        }

        final String inputFile = args[0];
        final String keyFile = args[1];
        final String mode = args[2].toUpperCase();
        final String outputFile = args[3];

        if( !(mode.equals("ECB") || mode.equals("CBC") || mode.equals("OFB")) ) {
            System.err.println("The modes of operation must be ECB, CBC or OFB.");
            return;
        }

        RSACipherByteArrayMixer cipher = new RSACipherByteArrayMixer(Cipher.ENCRYPT_MODE);
        cipher.setParameters(keyFile, mode);
        ImageMixer.mix(inputFile, outputFile, cipher);

    }

}
