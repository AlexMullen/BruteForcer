package mullen.alex.bruteforcer;

import java.math.BigInteger;
import java.util.function.Consumer;

/**
 * Represents a method of brute force.
 *
 * @author  Alex Mullen
 *
 */
public interface BruteForceMethod {
    /**
     * Perform the method using the specified configuration.
     *
     * @param config         the configuration
     * @param messageAction  the action to perform whenever a message is found
     */
    void run(Configuration config, Consumer<byte[]> messageAction);
    /**
     * Calculates an estimate for how long the specified job configuration will
     * take in seconds.
     *
     * @param config  the configuration
     * @return        the estimate in seconds
     */
    BigInteger estimateTimeRequired(Configuration config);
    /**
     * Prints out information about the job from the configuration.
     *
     * @param config  the job configuration
     */
    void printJobDetails(Configuration config);
}
