package utils;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by Norbert Burza on 13.07.2017.
 */
public class Handler {

    // Used to build 'client nonce' distributed across multiple SystemOut.log lines
    private StringBuilder clientNonce;

    // Used to build 'master secret' distributed across multiple SystemOut.log lines
    private StringBuilder masterSecret;

    // A helper value stating which line of client nonce was lastly read
    private int clientNonceState = -1;

    // A helper value stating which line of master secret was lastly read
    private int masterSecretState = -1;

    // Used to store extracted client nonces and corresponding master secrets
    private PrintWriter writer;

    /**
     * Creates an instance of Handler for analyzing Websphere SystemOut.log.
     *
     * @param outputFilePath file path where extracted client nonces and keys should be saved
     */
    public Handler(String outputFilePath) {
        openFile(outputFilePath);
    }

    /**
     * Processes a single line of SystemOut.log.
     * @param line
     */
    public void handle(String line) {
        if (line.indexOf(" Client Nonce:") != -1) {
            clientNonceState = 0;
            clientNonce = new StringBuilder();
        } else if (clientNonceState == 0) {
            addToClientNonce(line);
            clientNonceState++;
        } else if (clientNonceState == 1) {
            addToClientNonce(line);
            clientNonceState = -1;
        } else if (line.indexOf(" Master Secret:") != -1) {
            masterSecretState = 0;
            masterSecret = new StringBuilder();
        } else if (masterSecretState >= 0 && masterSecretState <= 1) {
            addToMasterSecret(line);
            masterSecretState++;
        } else if (masterSecretState == 2) {
            addToMasterSecret(line);
            masterSecretState = -1;
            String complete = "CLIENT_RANDOM " + clientNonce.toString() + " " + masterSecret.toString();
            writeToFile(complete);
            System.out.println(complete);
        }
    }

    private void addToClientNonce(String line) {
        String hex = getHexFromLine(line);
        clientNonce.append(hex);
    }

    private void addToMasterSecret(String line) {
        String hex = getHexFromLine(line);
        masterSecret.append(hex);
    }


    private String getHexFromLine(String line) {
        StringBuilder hexBuilder = new StringBuilder();

        final String regex = "([0-9a-f]{2} ){8} ";
        final Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(line);
        while (matcher.find()) {
            for (int i = 1; i <= matcher.groupCount(); i++) {
                String match = matcher.group(0);
                String replaced = match.replaceAll("\\s","");
                hexBuilder.append(replaced);
            }
        }
        return hexBuilder.toString();
    }

    private void openFile(String outputFilePath) {
        if (writer == null) {
            try {
                writer = new PrintWriter("C:\\tmp\\websphereSSLKeys.log", "UTF-8");
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }
    }

    private void writeToFile(String line) {
            writer.println(line);
            writer.flush();
    }
}
