package mullen.alex.bruteforcer.characters;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.NumberFormat;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.bind.DatatypeConverter;

import mullen.alex.bruteforcer.BruteForceMethod;
import mullen.alex.bruteforcer.Configuration;

/**
 * Represents a character set brute forcer method that generates and tries every
 * possible arrangement for a given set of specified characters.
 *
 * @author  Alex Mullen
 *
 */
public class CharacterMethod implements BruteForceMethod {
    /** The logger instance for this class. */
    private static final Logger LOG =
            Logger.getLogger(CharacterMethod.class.getName());
    ////////////////////////////////////////////////////////////////////////////
    /** Represents the number of nanoseconds in one second. */
    private static final int NS_IN_SECOND = 1000000000;
    /** Holds the message length for the raw method benchmark. */
    private static final int CHARMETHOD_BENCHMARK_MSGLENGTH = 5;
    ////////////////////////////////////////////////////////////////////////////
    /**
     * Creates a new instance.
     */
    public CharacterMethod() {
        // Intentionally empty.
    }
    @Override
    public final void run(final Configuration config,
            final Consumer<byte[]> messageAction) {
        if (!validateConfig(config)) {
            return;
        }
        printJobDetails(config);
        try {
            System.out.println("Estimating time required...");
            System.out.println("Estimated time required: "
                    + estimateTimeRequired(config) + " second(s)");
            System.out.println("Brute force started...");
            final long timeStartedAt = System.nanoTime();
            ////////////////////////////////////////////////////////////////////
            performCharMethod(config, messageAction);
            ////////////////////////////////////////////////////////////////////
            final double timeElapsedSecs = (double)
                    (System.nanoTime() - timeStartedAt) / NS_IN_SECOND;
            System.out.println("Finished in "
                    + String.format("%.2f", Double.valueOf(timeElapsedSecs))
                    + " seconds!");
            final BigDecimal totalPermsDec = new BigDecimal(
                    calculatePermutationCount(config.getCharacters().length,
                            config.getMaxLength()));
            System.out.println("Average speed: "
                    + NumberFormat.getInstance().format(totalPermsDec.divide(
                            BigDecimal.valueOf(timeElapsedSecs), 2,
                            RoundingMode.HALF_DOWN)) + " perms/sec");
        } catch (final NoSuchAlgorithmException | InterruptedException e) {
            LOG.log(Level.SEVERE, e.toString(), e);
        }
    }
    /**
     * Calculates an estimate for how long the specified job configuration will
     * take in seconds.
     *
     * @param config  the configuration
     * @return        the estimate in seconds
     *
     * @throws NoSuchAlgorithmException  if the system does not provide a
     *                                   an implementation of the requested
     *                                   digest algorithm
     * @throws InterruptedException      if the process is interrupted whilst
     *                                   waiting for tasks to finish
     */
    private static BigInteger estimateTimeRequired(final Configuration config)
            throws NoSuchAlgorithmException, InterruptedException {
        final BigDecimal avgPermPerSec = performBenchmark(config);
        final BigInteger totalPermCount =
                calculatePermutationCount(config.getCharacters().length,
                        config.getMaxLength());
        final BigDecimal estTimeSecs =
                new BigDecimal(totalPermCount).divide(
                        avgPermPerSec, 2, RoundingMode.DOWN);
        return estTimeSecs.toBigInteger();
    }
    /**
     * Prints out information about the job from the configuration.
     *
     * @param config  the job configuration
     */
    private static void printJobDetails(final Configuration config) {
        System.out.println("Hash (" + config.getDigestType() + "): "
                + DatatypeConverter.printHexBinary(config.getDigest()));
        System.out.print("Using character method up to "
                + config.getMaxLength());
        if (config.getMaxLength() > 1) {
            System.out.print(" characters ");
        } else {
            System.out.print(" character ");
        }
        System.out.println("in length");
        System.out.println("Thread count: " + config.getMaxThreads());
        final BigInteger totalPermutations =
                calculatePermutationCount(config.getCharacters().length,
                        config.getMaxLength());
        System.out.println("Total permuations possible: "
                + NumberFormat.getInstance().format(totalPermutations));
    }
    /**
     * Validates the specified configuration so that the data required in it
     * exists and fits with the brute force method constraints.
     *
     * @param config  the configuration
     * @return        <code>true</code> if the configuration is valid; otherwise
     *                <code>false</code>
     */
    private static boolean validateConfig(final Configuration config) {
        boolean isValid = true;
        if (config.getDigest() == null) {
            LOG.log(Level.SEVERE, "No hash provided.");
            isValid = false;
        }
        if (config.getDigestType() == null) {
            LOG.log(Level.SEVERE, "Hash type is not specified.");
            isValid = false;
        }
        if (config.getCharacters() == null) {
            LOG.log(Level.SEVERE, "No set of characters specified.");
            isValid = false;
        }
        if (config.getMaxLength() < 1) {
            LOG.log(Level.SEVERE, "Maximum length is less than one.");
            isValid = false;
        }
        if (config.getMaxThreads() < 1) {
            LOG.log(Level.SEVERE, "Maximum threads is less than one.");
            isValid = false;
        }
        return isValid;
    }
    /**
     * Performs a dry run of the method so that an estimate can be retrieved
     * as to how fast the current system is.
     * <p>
     * The estimate returned by this tends to be a higher than what is actually
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
    private static BigDecimal performBenchmark(final Configuration config)
            throws NoSuchAlgorithmException, InterruptedException {
        // Get the time at the start in nanoseconds.
        final long timeStartedAt = System.nanoTime();
        ////////////////////////////////////////////////////////////////////////
        performCharMethod(createBenchmarkConfig(config),
                msg -> { /* Do nothing. */ });
        ////////////////////////////////////////////////////////////////////////
        // Elapsed time taken in nanoseconds.
        final long timeElapsedNs = System.nanoTime() - timeStartedAt;
        // Elapsed time taken in seconds.
        final BigDecimal timeElapsedSecs =
                BigDecimal.valueOf(timeElapsedNs).divide(
                        new BigDecimal(NS_IN_SECOND), 2, RoundingMode.HALF_UP);
        // Total number of permutations possible.
        final BigDecimal totalPermsDec = new BigDecimal(
                calculatePermutationCount(config.getCharacters().length,
                        CHARMETHOD_BENCHMARK_MSGLENGTH));
        return totalPermsDec.divide(timeElapsedSecs, 2, RoundingMode.FLOOR);
    }
    /**
     * Performs the character method of brute forcing.
     *
     * @param config         the configuration
     * @param messageAction  the action to perform when a message is found
     *
     * @throws NoSuchAlgorithmException  if the system does not provide a
     *                                   an implementation of the requested
     *                                   digest algorithm
     * @throws InterruptedException      if the process is interrupted whilst
     *                                   waiting for tasks to finish
     */
    private static void performCharMethod(final Configuration config,
            final Consumer<byte[]> messageAction)
            throws NoSuchAlgorithmException, InterruptedException {
        final ExecutorService executor =
                Executors.newFixedThreadPool(config.getMaxThreads());
        // Split the work up by each character in the key set.
        for (final char c : config.getCharacters()) {
            final StrippedStringBuilder sb =
                    new StrippedStringBuilder(config.getMaxLength());
            sb.append(c);
            executor.execute(new CharacterBruteForcerTask(
                    MessageDigest.getInstance(config.getDigestType()),
                    config, sb, messageAction));
        }
        // Shutdown and wait for the tasks to finish.
        executor.shutdown();
        executor.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);
    }
    /**
     * Calculates the maximum number of permutations possible at a specific
     * maximum length.
     *
     * @param charCount   the number of characters
     * @param lengthUpto  the maximum length of the generated message
     * @return            a <code>BigInteger</code> instance that holds
     *                    and represents the maximum number of permutations
     */
    private static BigInteger calculatePermutationCount(final int charCount,
            final int lengthUpto) {
        BigInteger total = BigInteger.ZERO;
        for (int i = 1; i <= lengthUpto; i++) {
            final BigInteger base = BigInteger.valueOf(charCount);
            total = total.add(base.pow(i));
        }
        return total;
    }
    /**
     * Creates a configuration copy of the specified configuration but reduces
     * the maximum message length option to an amount that is long enough to
     * get a good speed estimate but does not take too long.
     *
     * @param config  the configuration to base it on
     * @return        the configuration to use for the benchmark
     */
    private static Configuration createBenchmarkConfig(
            final Configuration config) {
        return new Configuration(config).
                setMaxLength(CHARMETHOD_BENCHMARK_MSGLENGTH);
    }
}
