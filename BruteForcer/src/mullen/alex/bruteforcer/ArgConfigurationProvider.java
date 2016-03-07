package mullen.alex.bruteforcer;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

/**
 * A configuration provider that builds a configuration based on supplied
 * program arguments.
 *
 * @author  Alex Mullen
 *
 */
public class ArgConfigurationProvider implements ConfigurationProvider {
    /** Represents the option for specifying the type. */
    public static final String CMD_OPTION_TYPE = "type";
    /** Represents the option for specifying the hash. */
    public static final String CMD_OPTION_HASH = "hash";
    /** Represents the option for specifying the method. */
    public static final String CMD_OPTION_METHOD = "method";
    /** Represents the option for specifying the maximum length. */
    public static final String CMD_OPTION_MAXLENGTH = "maxlength";
    /** Represents the option for specifying the set of chars. */
    public static final String CMD_OPTION_CHARS = "chars";
    /** Represents the option for specifying the thread count. */
    public static final String CMD_OPTION_THREADS = "threads";
    ////////////////////////////////////////////////////////////////////////////
    /** The passed arguments. */
    private final CommandLine arguments;
    /**
     * Creates a new instance that builds configurations based on the specified
     * arguments.
     *
     * @param args  the arguments
     * @throws ParseException  if there are any problems encountered while
     *                         parsing the command line tokens
     */
    public ArgConfigurationProvider(final String... args)
            throws ParseException {
        final Options options = initCmdOptions();
        // Parse the command line arguments using the options we built.
        final CommandLineParser parser = new DefaultParser();
        arguments = parser.parse(options, args, false);
    }
    @Override
    public final Configuration retrieveConfiguration() {
        final Configuration config = new Configuration();
        config.setMethodName(arguments.getOptionValue(CMD_OPTION_METHOD));
        config.setDigest(parseHash(arguments));
        config.setDigestType(arguments.getOptionValue(CMD_OPTION_TYPE));
        config.setMaxLength(parseMaxLength(arguments));
        config.setMaxThreads(parseThreads(arguments));
        config.setCharacters(parseChars(arguments));
        return config;
    }
    /**
     * Initialises and returns the command line options.
     *
     * @return  the options
     */
    private static Options initCmdOptions() {
        final Options options = new Options();
        options.addOption(CMD_OPTION_TYPE, true, "the type of hash");
        options.addOption(CMD_OPTION_HASH, true,
                "the hash in hexadecimal format");
        options.addOption(CMD_OPTION_METHOD, true,
                "[raw|chars] the method for brute forcing");
        options.addOption(CMD_OPTION_CHARS, true,
                "the set of characters to use when method=chars");
        options.addOption(CMD_OPTION_MAXLENGTH, true,
                "the maximum message length in either chars or bytes to try");
        options.addOption(CMD_OPTION_THREADS, true,
                "the number of threads to use");
        return options;
    }
    /**
     * Parses the hash from the command line arguments.
     *
     * @param args  the command line arguments
     * @return      the digest in byte format otherwise <code>null</code>
     */
    private static byte[] parseHash(final CommandLine args) {
        byte[] hash = null;
        if (args.hasOption(CMD_OPTION_HASH)) {
            final String hashString = args.getOptionValue(CMD_OPTION_HASH);
            hash = DatatypeConverter.parseHexBinary(hashString);
        }
        return hash;
    }
    /**
     * Parses the maximum length command line option from the command line
     * arguments.
     *
     * @param args  the command line arguments
     * @return      the length
     */
    private static int parseMaxLength(final CommandLine args) {
        int maxLength = 0;
        if (args.hasOption(CMD_OPTION_MAXLENGTH)) {
            final String maxLengthStr =
                    args.getOptionValue(CMD_OPTION_MAXLENGTH);
            maxLength = Integer.parseInt(maxLengthStr);
        }
        return maxLength;
    }
    /**
     * Parses the number of threads to use from the command line arguments.
     *
     * @param args        the command line arguments
     * @return            the number of threads to use
     */
    private static int parseThreads(final CommandLine args) {
        int threadCount = 0;
        if (args.hasOption(CMD_OPTION_THREADS)) {
            final String threadsStr =
                    args.getOptionValue(CMD_OPTION_THREADS);
            threadCount = Integer.parseInt(threadsStr);
        }
        return threadCount;
    }
    /**
     * Parses the set of characters to use from the command line arguments.
     *
     * @param args  the command line arguments
     * @return      an array of the specified characters
     */
    private static char[] parseChars(final CommandLine args) {
        char[] chars = null;
        if (args.hasOption(CMD_OPTION_CHARS)) {
            final String charsStr = args.getOptionValue(CMD_OPTION_CHARS);
            chars = charsStr.toCharArray();
        }
        return chars;
    }
}
