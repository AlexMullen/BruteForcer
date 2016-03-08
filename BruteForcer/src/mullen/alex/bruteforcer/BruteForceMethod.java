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
     * Validates the specified configuration so that the data required in it
     * exists and fits with the brute force method constraints.
     * <p>
     * <b>
     * This method should be used on the configuration before any other method
     * is used on it.
     * </b>
     *
     * @param config  the configuration
     * @return        <code>true</code> if the configuration is valid; otherwise
     *                <code>false</code>
     */
    boolean validateConfig(Configuration config);
    /**
     * Perform the method using the specified configuration.
     *
     * @param config         the configuration
     * @param messageAction  the action to perform whenever a message is found
     */
    void run(Configuration config, Consumer<byte[]> messageAction);
    /**
     * Calculates an estimate for how long the specified job configuration will
     * take in seconds. If an estimate cannot be calculated then
     * {@link BigInteger#ZERO} is returned.
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
