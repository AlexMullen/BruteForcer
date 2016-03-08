package mullen.alex.bruteforcer.raw;

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
 * Represents a brute forcer method that generates every possible arrangement of
 * bytes for a specified length.
 *
 * @author  Alex Mullen
 *
 */
public class RawMethod implements BruteForceMethod {
    /** The logger instance for this class. */
    private static final Logger LOG =
            Logger.getLogger(RawMethod.class.getName());
    ////////////////////////////////////////////////////////////////////////////
    /** Represents the number of nanoseconds in one second. */
    private static final int NS_IN_SECOND = 1000000000;
    /** Holds the message length for the raw method benchmark. */
    private static final int RAWMETHOD_BENCHMARK_MSGLENGTH = 3;
    ////////////////////////////////////////////////////////////////////////////
    /**
     * Creates a new instance.
     */
    public RawMethod() {
        // Intentionally empty.
    }
    @Override
    public final void run(final Configuration config,
            final Consumer<byte[]> messageAction) {
        try {
            System.out.println("Brute force started...");
            final long timeStartedAt = System.nanoTime();
            ////////////////////////////////////////////////////////////////////
            performRawMethod(config, messageAction);
            ////////////////////////////////////////////////////////////////////
            final double timeElapsedSecs = (double)
                    (System.nanoTime() - timeStartedAt) / NS_IN_SECOND;
            System.out.println("Finished in "
                    + String.format("%.2f", Double.valueOf(timeElapsedSecs))
                    + " seconds!");
            final BigDecimal totalPermsDec = new BigDecimal(
                    calculatePermutationCount(config.getMaxLength()));
            System.out.println("Average speed: "
                    + NumberFormat.getInstance().format(totalPermsDec.divide(
                            BigDecimal.valueOf(timeElapsedSecs), 2,
                            RoundingMode.HALF_DOWN)) + " perms/sec");
        } catch (final NoSuchAlgorithmException | InterruptedException e) {
            LOG.log(Level.SEVERE, e.toString(), e);
        }
    }
    @Override
    public final BigInteger estimateTimeRequired(final Configuration config) {
        BigInteger timeEstimateSecs = BigInteger.ZERO;
        try {
            final BigDecimal avgPermPerSec = performBenchmark(config);
            final BigInteger totalPermCount =
                    calculatePermutationCount(config.getMaxLength());
            final BigDecimal estTimeSecs =
                    new BigDecimal(totalPermCount).divide(
                            avgPermPerSec, 2, RoundingMode.DOWN);
            timeEstimateSecs = estTimeSecs.toBigInteger();
        } catch (final NoSuchAlgorithmException | InterruptedException e) {
            LOG.log(Level.SEVERE, e.toString(), e);
        }
        return timeEstimateSecs;
    }
    @Override
    public final void printJobDetails(final Configuration config) {
        System.out.println("Hash (" + config.getDigestType() + "): "
                + DatatypeConverter.printHexBinary(config.getDigest()));
        System.out.print("Using raw method up to " + config.getMaxLength());
        if (config.getMaxLength() > 1) {
            System.out.print(" bytes ");
        } else {
            System.out.print(" byte ");
        }
        System.out.println("in length");
        System.out.println("Thread count: " + config.getMaxThreads());
        final BigInteger totalPermutations =
                calculatePermutationCount(config.getMaxLength());
        System.out.println("Total permuations possible: "
                + NumberFormat.getInstance().format(totalPermutations));
    }
    @Override
    public final  boolean validateConfig(final Configuration config) {
        boolean isValid = true;
        if (config.getDigest() == null) {
            LOG.log(Level.SEVERE, "No hash provided.");
            isValid = false;
        }
        if (config.getDigestType() == null) {
            LOG.log(Level.SEVERE, "Hash type is not specified.");
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
     * Performs the raw method of brute forcing.
     *
     * @param config       the configuration
     * @param foundAction  the action to perform when a message is found
     *
     * @throws NoSuchAlgorithmException  if the system does not provide a
     *                                   an implementation of the requested
     *                                   digest algorithm
     * @throws InterruptedException      if the process is interrupted whilst
     *                                   waiting for tasks to finish
     */
    private static void performRawMethod(final Configuration config,
            final Consumer<byte[]> foundAction)
            throws NoSuchAlgorithmException, InterruptedException {
        final ExecutorService executor =
                Executors.newFixedThreadPool(config.getMaxThreads());
        for (int i = 0; i < RawBruteForcerTask.UNIQUE_BYTE_VALUES; i++) {
            executor.execute(new RawBruteForcerTask(
                    MessageDigest.getInstance(config.getDigestType()), config,
                    i, foundAction));
        }
        // Shutdown and wait for the tasks to finish.
        executor.shutdown();
//        Thread.currentThread().interrupt(); // For testing.
        executor.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);
    }
    /**
     * Performs a dry run of the raw method so that an estimate can be retrieved
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
        performRawMethod(createBenchmarkConfig(config),
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
                calculatePermutationCount(3));
        return totalPermsDec.divide(timeElapsedSecs, 2, RoundingMode.FLOOR);
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
                setMaxLength(RAWMETHOD_BENCHMARK_MSGLENGTH);
    }
    /**
     * Calculates the maximum number of permutations possible for the 'raw'
     * method at a specific maximum length.
     *
     * @param lengthUpto  the maximum length of the generated message
     * @return            a <code>BigInteger</code> instance that holds
     *                    and represents the maximum number of permutations
     */
    private static BigInteger calculatePermutationCount(
            final int lengthUpto) {
        BigInteger total = BigInteger.ZERO;
        for (int i = 1; i <= lengthUpto; i++) {
            final BigInteger base =
                    BigInteger.valueOf(RawBruteForcerTask.UNIQUE_BYTE_VALUES);
            total = total.add(base.pow(i));
        }
        return total;
    }
}
