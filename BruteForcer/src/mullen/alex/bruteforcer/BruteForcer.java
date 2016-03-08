package mullen.alex.bruteforcer;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import mullen.alex.bruteforcer.characters.CharacterMethod;
import mullen.alex.bruteforcer.dictionary.DictionaryMethod;
import mullen.alex.bruteforcer.raw.RawMethod;

import org.apache.commons.cli.ParseException;

/**
 * The main application entry class for a basic unsalted hash brute-forcer.
 *
 * @author  Alex Mullen
 *
 */
public final class BruteForcer {
    /** The logger instance for this class. */
    private static final Logger LOG =
            Logger.getLogger(BruteForcer.class.getName());
    ////////////////////////////////////////////////////////////////////////////
    /**
     * Private constructor to disallow instantiation.
     */
    private BruteForcer() {
        // Intentionally empty.
    }
    /**
     * The main application entry point.
     *
     * @param args  the supplied program arguments
     *
     * @throws NoSuchAlgorithmException  if the system does not provide a
     *                                   an implementation of the requested
     *                                   digest algorithm
     * @throws ParseException            if an exception occurs whilst parsing
     *                                   command line arguments
     * @throws InterruptedException      if the process is interrupted
     */
    public static void main(final String... args)
            throws NoSuchAlgorithmException, ParseException,
            InterruptedException {
        final ConfigurationProvider configProvider =
                new ArgConfigurationProvider(args);
        // Retrieve a configuration.
        final Configuration config = configProvider.retrieveConfiguration();
        if (config == null) {
            LOG.log(Level.SEVERE, "Failed to retrieve configuration.");
            return;
        }
        final String methodName = config.getMethodName();
        if (methodName == null) {
            LOG.log(Level.SEVERE, "No brute force method specified.");
            return;
        }
        preprocessConfiguration(config, new DefaultDigestDeterminer());
        final Map<String, BruteForceMethod> methods = new HashMap<>(3);
        methods.put("raw", new RawMethod());
        methods.put("chars", new CharacterMethod());
        methods.put("dictionary", new DictionaryMethod());
        final BruteForceMethod methodImp = methods.get(methodName);
        if (methodImp == null) {
            LOG.log(Level.SEVERE, "Unknown method: " + methodName);
        } else {
            methodImp.run(config, BruteForcer::printFoundMessage);
        }
    }
    /**
     * Preprocesses a configuration.
     *
     * @param config            the configuration to preprocess
     * @param digestDeterminer  the digest determiner to possibly use for
     *                          guessing an unspecified digest type
     */
    private static void preprocessConfiguration(final Configuration config,
            final DigestDeterminer digestDeterminer) {
        possiblyGuessDigest(config, digestDeterminer);
        warnIfDigestTypeCouldBeWrongType(config, digestDeterminer);
        possiblyLimitThreadCount(config);
    }
    /**
     * Possibly guess the digest type if its type is not specified.
     *
     * @param config            the configuration
     * @param digestDeterminer  the digest determiner to use for guessing what
     *                          type of digest we think it is
     */
    private static void possiblyGuessDigest(final Configuration config,
            final DigestDeterminer digestDeterminer) {
        final byte[] digest = config.getDigest();
        if (config.getDigestType() == null && digest != null) {
            System.out.println(
                    "Digest type not specified, will attempt to determine...");
            config.setDigestType(digestDeterminer.determine(digest));
            if (config.getDigestType() == null) {
                LOG.log(Level.SEVERE, "Unable to determine the digest type!");
            } else {
                System.out.println(
                        "Determined that the digest might be of type: "
                                + config.getDigestType());
            }
        }
    }
    /**
     * Prints a warning if the specified hash type differs with what we guess
     * it to be.
     *
     * @param config            the configuration
     * @param digestDeterminer  the digest determiner to use for guessing what
     *                          type of digest we think it is
     */
    private static void warnIfDigestTypeCouldBeWrongType(
            final Configuration config,
            final DigestDeterminer digestDeterminer) {
        final byte[] digest = config.getDigest();
        final String digestType = config.getDigestType();
        if (digestType != null) {
            final String digestTypeGuess = digestDeterminer.determine(digest);
            if (!digestType.equalsIgnoreCase(digestTypeGuess)) {
                LOG.log(Level.WARNING, "Digest type looks to be "
                        + digestTypeGuess + " but '" + digestType
                        + "' was specified!");
            }
        }
    }
    /**
     * Limits the thread count to the number of available processors if the
     * specified thread count exceeds the processor count on the current system.
     *
     * @param config  the configuration
     */
    private static void possiblyLimitThreadCount(final Configuration config) {
        final int processorCount = Runtime.getRuntime().availableProcessors();
        if (config.getMaxThreads() > processorCount) {
            config.setMaxThreads(processorCount);
            System.out.println("Limiting thread count to core count of "
                    + processorCount);
        }
    }
    /**
     * Prints out a message that is an input to the digest.
     *
     * @param msg  the raw message bytes
     */
    private static void printFoundMessage(final byte[] msg) {
        try {
            System.out.println("Message found: " + Arrays.toString(msg)
                    + " = \"" + new String(msg, "UTF-8") + "\"");
        } catch (final UnsupportedEncodingException e) {
            LOG.log(Level.SEVERE, e.toString(), e);
        }
    }
}
