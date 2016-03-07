package mullen.alex.bruteforcer;

/**
 * An interface that defines a specific implementation for providing a
 * configuration.
 *
 * @author  Alex Mullen
 *
 */
@FunctionalInterface
public interface ConfigurationProvider {
    /**
     * Retrieves a configuration.
     *
     * @return  a {@link Configuration} object or <code>null</code> if something
     *          went wrong or there was no configuration
     */
    Configuration retrieveConfiguration();
}
