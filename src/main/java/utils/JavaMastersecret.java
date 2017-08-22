package utils;

import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

/**
 * Keys Reader from the java ssl debug logs.
 */
public class JavaMastersecret {

    @Option(name = "-input", required = true, usage = "std output log file (e.g. SystemOut.log in Websphere)")
    private String inputFile;

    @Option(name = "-output", required = true, usage = "file to store keys (for Wireshark)")
    private String outputFile;

    @Option(name = "-f", usage = "follow input")
    private Boolean follow = Boolean.TRUE;

    public static void main(String[] args) {
        new JavaMastersecret().doMain(args);
    }

    public void doMain(String[] args) {

        // Command line arguments parser
        CmdLineParser parser = new CmdLineParser(this);

        try {
            parser.parseArgument(args);
        } catch (CmdLineException e) {
            // Print error message
            System.err.println(e.getMessage());

            // If required parameters were not found, print usage note and exit.
            parser.printUsage(System.err);
            System.exit(-1);
        }

        // Create handler for processing std output log file
        Handler h = new Handler(outputFile);

        try {
            BufferedReader bufferedReader = new BufferedReader(new FileReader(inputFile));
            String line = null; // A variable with holding the current line of the log file
            while (true) {
                line = bufferedReader.readLine();
                if (line == null) {
                    // Wait for new handshakes
                    Thread.sleep(500);
                } else {
                    h.handle(line);
                }
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
