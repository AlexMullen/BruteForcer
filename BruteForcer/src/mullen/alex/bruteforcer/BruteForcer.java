package mullen.alex.bruteforcer;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.NumberFormat;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
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
    /** Represents the number of milliseconds in one second. */
    private static final int MS_IN_SECOND = 1000;
    /** Represents the number of nanoseconds in one second. */
    private static final int NS_IN_SECOND = 1000000000;
    /** Holds the message length for the raw method benchmark. */
    private static final int RAWMETHOD_BENCHMARK_MSGLENGTH = 3;
    ////////////////////////////////////////////////////////////////////////////
    /** Holds the byte length of a MD5 digest. */
    private static final int MD5_DIGEST_BYTELENGTH = 16;
    /** Holds the byte length of a SHA-1 digest. */
    private static final int SHA1_DIGEST_BYTELENGTH = 20;
    /** Holds the byte length of a SHA-224 digest. */
    private static final int SHA224_DIGEST_BYTELENGTH = 28;
    /** Holds the byte length of a SHA-256 digest. */
    private static final int SHA256_DIGEST_BYTELENGTH = 32;
    /** Holds the byte length of a SHA-384 digest. */
    private static final int SHA384_DIGEST_BYTELENGTH = 48;
    /** Holds the byte length of a SHA-512 digest. */
    private static final int SHA512_DIGEST_BYTELENGTH = 64;
    ////////////////////////////////////////////////////////////////////////////
    /** Represents the command line option for specifying the type. */
    private static final String CMD_OPTION_TYPE = "type";
    /** Represents the command line option for specifying the hash. */
    private static final String CMD_OPTION_HASH = "hash";
    /** Represents the command line option for specifying the method. */
    private static final String CMD_OPTION_METHOD = "method";
    /** Represents the command line option for specifying the maximum length. */
    private static final String CMD_OPTION_MAXLENGTH = "maxlength";
    /** Represents the command line option for specifying the set of chars. */
    private static final String CMD_OPTION_CHARS = "chars";
    /** Represents the command line option for specifying the thread count. */
    private static final String CMD_OPTION_THREADS = "threads";
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
        // Create the command line options.
        final Options options = new Options();
        options.addOption(CMD_OPTION_TYPE, true, "the type of hash");
        options.addOption(
                CMD_OPTION_HASH, true, "the hash in hexadecimal format");
        options.addOption(CMD_OPTION_METHOD, true,
                "[raw|chars] the method for brute forcing");
        options.addOption(CMD_OPTION_CHARS, true,
                "the set of characters to use when method=chars");
        options.addOption(CMD_OPTION_MAXLENGTH, true,
                "the maximum message length in either chars or bytes to try");
        options.addOption(
                CMD_OPTION_THREADS, true, "the number of threads to use");
        // Parse the command line arguments using the options we built.
        final CommandLineParser parser = new DefaultParser();
        final CommandLine cmd = parser.parse(options, args, false);
        if (cmd.hasOption(CMD_OPTION_METHOD)) {
            final String method = cmd.getOptionValue(CMD_OPTION_METHOD);
            if ("raw".equals(method)) {
                rawMethod(parseRawConfiguration(cmd));
            } else if ("chars".equals(method)) {
                charMethod(parseCharConfiguration(cmd));
            } else if ("dictionary".equals(method)) {
                LOG.log(Level.SEVERE,
                        "Dictionary method chosen but not implemented yet!");
            } else {
                LOG.log(Level.SEVERE, "Unknown method: " + method);
            }
        } else {
            final HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("bforce", options);
        }
    }
    /**
     * Parses a the command line arguments and creates a new
     * {@link RawMethodConfiguration} that represents the job configuration.
     *
     * @param args  the command line arguments
     * @return      the configuration
     *
     * @throws ParseException  if there was something wrong with the
     *                         passed parameters or some were missing
     */
    private static RawMethodConfiguration parseRawConfiguration(
            final CommandLine args) throws ParseException {
        final byte[] hash = parseHash(args);
        String hashType = parseHashType(args);
        if (hashType == null) {
            // Type not specified so try work out the type of hash.
            System.out.println(
                    "No hash type specified, will attempt to guess...");
            hashType = guessHashType(hash);
            if (hashType == null) {
                throw new ParseException(
                        "No hash type was specified and was unable to guess the"
                        + " hash type!");
            } else {
                System.out.println("Guess result: " + hashType);
            }
        }
        final int maxLength = parseMaxLength(args);
        final int maxThreads = parseThreads(args, 1);
        return new RawMethodConfiguration(hash, hashType, maxLength,
                maxThreads);
    }
    /**
     * Parses a the command line arguments and creates a new
     * {@link CharMethodConfiguration} that represents the job configuration.
     *
     * @param args  the command line arguments
     * @return      the configuration
     *
     * @throws ParseException  if there was something wrong with the
     *                         passed parameters or some were missing
     */
    private static CharMethodConfiguration parseCharConfiguration(
            final CommandLine args) throws ParseException {
        final byte[] hash = parseHash(args);
        String hashType = parseHashType(args);
        if (hashType == null) {
            // Type not specified so try work out the type of hash.
            System.out.println(
                    "No hash type specified, will attempt to guess...");
            hashType = guessHashType(hash);
            if (hashType == null) {
                throw new ParseException(
                        "No hash type was specified and was unable to guess the"
                        + " hash type!");
            } else {
                System.out.println("Guess result: " + hashType);
            }
        }
        final int maxLength = parseMaxLength(args);
        final int maxThreads = parseThreads(args, 1);
        final char[] chars = parseChars(args);
        return new CharMethodConfiguration(
                hash, hashType, maxLength, maxThreads, chars);
    }
    /**
     * Given a digest, will attempt to guess what algorithm generated the digest
     * based on the length of it.
     *
     * @param hash  the raw digest
     * @return      a string representing the guessed algorithm otherwise
     *              <code>null</code> is returned if no reasonable guess could
     *              be done
     */
    private static String guessHashType(final byte[] hash) {
        String guess = null;
        switch (hash.length) {
            case MD5_DIGEST_BYTELENGTH:
                guess = "MD5";
                break;
            case SHA1_DIGEST_BYTELENGTH:
                guess = "SHA-1";
                break;
            case SHA224_DIGEST_BYTELENGTH:
                guess = "SHA-224";
                break;
            case SHA256_DIGEST_BYTELENGTH:
                guess = "SHA-256";
                break;
            case SHA384_DIGEST_BYTELENGTH:
                guess = "SHA-384";
                break;
            case SHA512_DIGEST_BYTELENGTH:
                guess = "SHA-512";
                break;
            default:
                break;
        }
        return guess;
    }
    /**
     * Performs the raw method of brute forcing.
     *
     * @param config  the configuration
     *
     * @throws NoSuchAlgorithmException  if the system does not provide a
     *                                   an implementation of the requested
     *                                   digest algorithm
     * @throws InterruptedException      if the process is interrupted whilst
     *                                   waiting for tasks to finish
     */
    private static void rawMethod(final RawMethodConfiguration config)
            throws NoSuchAlgorithmException, InterruptedException {
        printRawMethodJobDetails(config);

        System.out.println("Benchmarking...");
        final BigDecimal avgPermPerSec = rawMethodBenchmark(config);
        final BigDecimal estTimeSecs =
                new BigDecimal(
                        calculateRawMethodPermutationCount(config.maxLength)).
                        divide(avgPermPerSec, 2, RoundingMode.DOWN);
        System.out.println("Benchmarking completed!");
        System.out.println("Estimated time to take: " + estTimeSecs + " secs");

        final long timeStartedAt = System.currentTimeMillis();
        final ExecutorService executor =
                Executors.newFixedThreadPool(config.getMaxThreads());
        for (int i = 0; i < RawBruteForcerTask.UNIQUE_BYTE_VALUES; i++) {
            executor.execute(new RawBruteForcerTask(
                    MessageDigest.getInstance(config.getDigestType()),
                    config.getDigest(), config.getMaxLength(), i));
        }
        // Shutdown and wait for the tasks to finish.
        executor.shutdown();
//        Thread.currentThread().interrupt(); // For testing.
        executor.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);
        ////////////////////////////////////////////////////////////////////////
        final double timeElapsedSecs = (double)
                (System.currentTimeMillis() - timeStartedAt) / MS_IN_SECOND;
        System.out.println("\nFinished in " + timeElapsedSecs + " seconds!");
        final BigDecimal totalPermsDec = new BigDecimal(
                calculateRawMethodPermutationCount(config.maxLength));
        System.out.println("Average speed: "
                + NumberFormat.getInstance().format(totalPermsDec.divide(// TODO: Possible to divide by zero!
                        BigDecimal.valueOf(timeElapsedSecs), 2,
                        RoundingMode.HALF_DOWN)) + " perms/sec");
    }
    /**
     * Prints out information about the raw job that was specified.
     *
     * @param config  the job configuration
     */
    private static void printRawMethodJobDetails(
            final RawMethodConfiguration config) {
        System.out.println("Hash (" + config.hashType + "): "
                + DatatypeConverter.printHexBinary(config.hash));

        System.out.print("Using method raw up to " + config.maxLength);
        if (config.maxLength > 1) {
            System.out.print(" bytes ");
        } else {
            System.out.print(" byte ");
        }
        System.out.println("in length");

        System.out.println("Thread count: " + config.maxThreads);
        final BigInteger totalPermutations =
                calculateRawMethodPermutationCount(config.maxLength);
        System.out.println("Total permuations possible: "
                + NumberFormat.getInstance().format(totalPermutations));
        System.out.println();
    }
    /**
     * Prints out information about the char job that was specified.
     *
     * @param config  the job configuration
     */
    private static void printCharMethodJobDetails(
            final CharMethodConfiguration config) {
        System.out.println("Hash (" + config.getDigestType() + "): "
                + DatatypeConverter.printHexBinary(config.getDigest()));

        System.out.print("Using method 'chars' up to " + config.getMaxLength());
        if (config.getMaxLength() > 1) {
            System.out.print(" characters ");
        } else {
            System.out.print(" character ");
        }
        System.out.println("in length");

        System.out.println("Thread count: " + config.getMaxThreads());
//        final BigInteger totalPermutations =
//                calculateRawMethodPermutationCount(config.getMaxLength());
//        System.out.println("Total permuations possible: "
//                + NumberFormat.getInstance().format(totalPermutations));
        System.out.println();
    }
    /**
     * Performs a dry run of the raw method so that an estimate can be retrieved
     * as to how fast the current system is.
     * <p>
     * The estimate returned by this tends to be a lower than what is actually
     * achieved, most likely due to JIT optimisations that occur when the task
     * is ran for longer than the benchmark.
     *
     * @param config  the configuration for the job
     * @return        a <code>BigDecimal</code> that holds the approximate
     *                number of permutations per second that can be generated
     *                and tested on the system using the number of execution
     *                threads specified in <code>config</code>
     *
     * @throws NoSuchAlgorithmException  if the system does not provide a
     *                                   an implementation of the requested
     *                                   digest algorithm
     * @throws InterruptedException      if the process is interrupted whilst
     *                                   waiting for tasks to finish
     */
    private static BigDecimal rawMethodBenchmark(
            final RawMethodConfiguration config)
            throws NoSuchAlgorithmException, InterruptedException {
        // Get the time at the start in nanoseconds.
        final long timeStartedAt = System.nanoTime();
        final ExecutorService executor =
                Executors.newFixedThreadPool(config.getMaxThreads());
        for (int i = 0; i < RawBruteForcerTask.UNIQUE_BYTE_VALUES; i++) {
            executor.execute(new RawBruteForcerTask(
                    MessageDigest.getInstance(config.getDigestType()),
                    config.getDigest(), RAWMETHOD_BENCHMARK_MSGLENGTH, i));
        }
        // Shutdown and wait for the tasks to finish.
        executor.shutdown();
        executor.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);
        // Elapsed time taken in nanoseconds.
        final long timeElapsedNs = System.nanoTime() - timeStartedAt;
        // Elapsed time taken in seconds.
        final BigDecimal timeElapsedSecs =
                BigDecimal.valueOf(timeElapsedNs).divide(
                        new BigDecimal(NS_IN_SECOND), 2, RoundingMode.HALF_UP);
        // Total number of permutations possible.
        final BigDecimal totalPermsDec = new BigDecimal(
                calculateRawMethodPermutationCount(3));
        return totalPermsDec.divide(timeElapsedSecs, 2, RoundingMode.FLOOR);
    }
    /**
     * Calculates the maximum number of permutations possible for the 'raw'
     * method at a specific maximum length.
     *
     * @param lengthUpto  the maximum length of the generated message
     * @return            a <code>BigInteger</code> instance that holds
     *                    and represents the maximum number of permutations
     */
    private static BigInteger calculateRawMethodPermutationCount(
            final int lengthUpto) {
        BigInteger total = new BigInteger("0");
        for (int i = 1; i <= lengthUpto; i++) {
            final BigInteger base =
                    BigInteger.valueOf(RawBruteForcerTask.UNIQUE_BYTE_VALUES);
            total = total.add(base.pow(i));
        }
        return total;
    }
    /**
     * Performs the character method of brute forcing.
     *
     * @param config  the configuration
     *
     * @throws NoSuchAlgorithmException  if the system does not provide a
     *                                   an implementation of the requested
     *                                   digest algorithm
     * @throws InterruptedException      if the process is interrupted whilst
     *                                   waiting for tasks to finish
     */
    private static void charMethod(final CharMethodConfiguration config)
            throws NoSuchAlgorithmException, InterruptedException {
        printCharMethodJobDetails(config);
        final ExecutorService executor =
                Executors.newFixedThreadPool(config.getMaxThreads());
        // Split the work up by each character in the key set.
        for (final char c : config.getCharacters()) {
            final StrippedStringBuilder sb =
                    new StrippedStringBuilder(config.getMaxLength());
            sb.append(c);
            executor.execute(new CharacterBruteForcerTask(
                    MessageDigest.getInstance(config.getDigestType()),
                    config.getDigest(),
                    config.getCharacters(), config.getMaxLength(), sb));
        }
        // Shutdown and wait for the tasks to finish.
        executor.shutdown();
        executor.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);
    }
    /**
     * Parses the hash from the command line arguments. (-hash)
     *
     * @param args  the command line arguments
     * @return      the byte representation of hash
     *
     * @throws ParseException  if no hash was specified
     */
    private static byte[] parseHash(final CommandLine args)
            throws ParseException {
        if (args.hasOption(CMD_OPTION_HASH)) {
            final String hashString = args.getOptionValue(CMD_OPTION_HASH);
            return DatatypeConverter.parseHexBinary(hashString);
        } else {
            throw new ParseException("No hash was specified. (-hash)");
        }
    }
    /**
     * Parses the hash type from the command line arguments. (-type)
     *
     * @param args  the command line arguments
     * @return      the type of hash as specified (possible erroneous) or
     *              <code>null</code> if the type was not specified
     */
    private static String parseHashType(final CommandLine args) {
        return args.getOptionValue(CMD_OPTION_TYPE);
    }
    /**
     * Parses the maximum length command line option from the command line
     * arguments. (-maxlength)
     *
     * @param args  the command line arguments
     * @return      the length
     *
     * @throws ParseException  if the maximum length was <code>< 1</code> or
     *                         was not specified
     */
    private static int parseMaxLength(final CommandLine args)
            throws ParseException {
        if (args.hasOption(CMD_OPTION_MAXLENGTH)) {
            final String maxLengthStr =
                    args.getOptionValue(CMD_OPTION_MAXLENGTH);
            final int maxLength = Integer.parseInt(maxLengthStr);
            if (maxLength < 1) {
                throw new ParseException(
                        "Maximum length has to be at least 1. (-maxlength)");
            } else {
                return maxLength;
            }
        } else {
            throw new ParseException(
                    "The maximum length was not specified (-maxlength)");
        }
    }
    /**
     * Parses the number of threads to use from the command line arguments.
     * (-threads)
     *
     * @param args        the command line arguments
     * @param defaultVal  the default value to return if the option is not
     *                    specified
     * @return            the number of threads to use
     *
     * @throws ParseException  if the number of threads is <code>< 1</code>
     */
    private static int parseThreads(final CommandLine args,
            final int defaultVal) throws ParseException {
        if (args.hasOption(CMD_OPTION_THREADS)) {
            final String threadsStr = args.getOptionValue(CMD_OPTION_THREADS);
            final int threads = Integer.parseInt(threadsStr);
            if (threads < 1) {
                throw new ParseException(
                        "The number of threads has to be at least 1. "
                        + "(-threads)");
            } else {
                return threads;
            }
        } else {
            return defaultVal;
        }
    }
    /**
     * Parses the set of characters to use from the command line arguments.
     * (-chars)
     *
     * @param args  the command line arguments
     * @return      an array of the specified characters
     *
     * @throws ParseException  if the parameter was missing
     */
    private static char[] parseChars(final CommandLine args)
            throws ParseException {
        if (args.hasOption(CMD_OPTION_CHARS)) {
            final String charsStr = args.getOptionValue(CMD_OPTION_CHARS);
            return charsStr.toCharArray();
        } else {
            throw new ParseException("No characters were specified. (-chars)");
        }
    }
    /**
     * Holds and represents the configuration for a raw bruteforce.
     * <p>
     * <b>
     * Please note that this class is designed to be immutable so any
     * modifications should respect this.
     * </b>
     *
     * @author  Alex Mullen
     *
     */
    private static class RawMethodConfiguration {
        /** Holds the digest. */
        private final byte[] hash;
        /** Holds the type of digest. */
        private final String hashType;
        /** Holds the maximum length of message to generate. */
        private final int maxLength;
        /** Holds the maximum number of threads to use. */
        private final int maxThreads;
        /**
         * Creates a new instance with the specified parameters.
         *
         * @param digest       the digest
         * @param type         a string representing the type of digest
         * @param lengthUpTo   the maximum length of message to generate up to
         * @param threadCount  the maximum number of threads to use
         *
         * @throws  NullPointerException  if <code>digest</code> or
         *                                <code>type</code> is <code>null</code>
         * @throws  IllegalArgumentException  if <code>lengthUpTo</code> or
         *                                    <code>threadCount</code> is
         *                                    <code>< 1</code>
         */
        RawMethodConfiguration(final byte[] digest, final String type,
                final int lengthUpTo, final int threadCount) {
            // Copy the array so nothing outside can modify ours.
            hash = Arrays.copyOf(digest, digest.length);
            hashType = Objects.requireNonNull(type);
            if (lengthUpTo < 1 || threadCount < 1) {
                throw new IllegalArgumentException(
                        "lengthUpTo or threadCount cannot be less than one");
            } else {
                maxLength = lengthUpTo;
                maxThreads = threadCount;
            }
        }
        /**
         * Gets the digest.
         *
         * @return  a copy of the digest held within
         */
        public byte[] getDigest() {
            return Arrays.copyOf(hash, hash.length);
        }
        /**
         * Gets a string that represents the type of digest.
         *
         * @return  the type
         */
        public String getDigestType() {
            return hashType;
        }
        /**
         * Gets the maximum length of messages to generate up to.
         *
         * @return  the maximum length in bytes
         */
        public int getMaxLength() {
            return maxLength;
        }
        /**
         * Gets the maximum number of threads to use.
         *
         * @return  the maximum number to use
         */
        public int getMaxThreads() {
            return maxThreads;
        }
    }
    /**
     * Holds and represents the configuration for a character bruteforce.
     * <p>
     * <b>
     * Please note that this class is designed to be immutable so any
     * modifications should respect this.
     * </b>
     *
     * @author  Alex Mullen
     *
     */
    private static class CharMethodConfiguration
        extends RawMethodConfiguration {
        /** Holds the characters to use when generating messages. */
        private final char[] characters;
        /**
         * Creates a new instance with the specified parameters.
         *
         * @param digest       the digest
         * @param type         a string representing the type of digest
         * @param lengthUpTo   the maximum length of message to generate up to
         * @param threadCount  the maximum number of threads to use
         * @param chars        the set of characters to use
         *
         * @throws  NullPointerException  if <code>digest</code>,
         *                                <code>type</code> or
         *                                <code>chars</code> is
         *                                <code>null</code>
         * @throws  IllegalArgumentException  if <code>lengthUpTo</code> or
         *                                    <code>threadCount</code> is
         *                                    <code>< 1</code>
         */
        CharMethodConfiguration(final byte[] digest, final String type,
                final int lengthUpTo, final int threadCount,
                final char[] chars) {
            super(digest, type, lengthUpTo, threadCount);
            characters = Arrays.copyOf(chars, chars.length);
        }
        /**
         * Gets the set of characters.
         *
         * @return  a copy of the characters held within
         */
        public char[] getCharacters() {
            return Arrays.copyOf(characters, characters.length);
        }
    }
}
