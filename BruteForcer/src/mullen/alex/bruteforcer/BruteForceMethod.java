package mullen.alex.bruteforcer;

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
}
