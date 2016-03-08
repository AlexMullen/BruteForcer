package mullen.alex.bruteforcer;

import java.util.Arrays;

/**
 * Represents a configuration for a brute force.
 *
 * @author  Alex Mullen
 *
 */
public class Configuration {
    /** Holds the method name. */
    private String methodName;
    /** Holds the digest. */
    private byte[] digest;
    /** Holds the type of digest. */
    private String digestType;
    /** Holds the maximum length of message to generate. */
    private int maxLength;
    /** Holds the maximum number of threads to use. */
    private int maxThreads;
    /** Holds the set of characters to use. */
    private char[] characters;
    /** Holds the path to the file to use. */
    private String filePath;
    /**
     * Creates a new instance.
     */
    public Configuration() {
        // Intentionally empty.
    }
    /**
     * Creates a new instance that is a deep-copy of the specified
     * configuration.
     *
     * @param config  the configuration to copy
     *
     * @throws NullPointerException  if <code>config</code> is <code>null</code>
     */
    public Configuration(final Configuration config) {
        methodName = config.methodName;
        digestType = config.digestType;
        maxLength = config.maxLength;
        maxThreads = config.maxThreads;
        filePath = config.filePath;
        if (config.digest != null) {
            digest = Arrays.copyOf(config.digest, config.digest.length);
        }
        if (config.characters != null) {
            characters =
                    Arrays.copyOf(config.characters, config.characters.length);
        }
    }
    /**
     * Gets the method name.
     *
     * @return  the method name
     */
    public final String getMethodName() {
        return methodName;
    }
    /**
     * Sets the method name.
     *
     * @param newMethod  the new method name
     * @return           a reference to this configuration for method chaining
     */
    public final Configuration setMethodName(final String newMethod) {
        methodName = newMethod;
        return this;
    }
    /**
     * Gets the digest.
     *
     * @return  a copy of the digest held within
     */
    public final byte[] getDigest() {
        byte[] digestToReturn = null;
        if (digest != null) {
            digestToReturn = Arrays.copyOf(digest, digest.length);
        }
        return digestToReturn;
    }
    /**
     * Sets the digest.
     *
     * @param newDigest  the new digest value
     * @return           a reference to this configuration for method chaining
     */
    public final Configuration setDigest(final byte[] newDigest) {
        if (newDigest == null) {
            digest = null;
        } else {
            digest = Arrays.copyOf(newDigest, newDigest.length);
        }
        return this;
    }
    /**
     * Gets a string that represents the type of digest.
     *
     * @return  the type
     */
    public final String getDigestType() {
        return digestType;
    }
    /**
     * Sets the digest type.
     *
     * @param newType  the new digest type
     * @return         a reference to this configuration for method chaining
     */
    public final Configuration setDigestType(final String newType) {
        digestType = newType;
        return this;
    }
    /**
     * Gets the maximum length of messages to generate up to.
     *
     * @return  the maximum length in bytes
     */
    public final int getMaxLength() {
        return maxLength;
    }
    /**
     * Sets the maximum message length.
     *
     * @param newLength  the new maximum length
     * @return           a reference to this configuration for method chaining
     */
    public final Configuration setMaxLength(final int newLength) {
        maxLength = newLength;
        return this;
    }
    /**
     * Gets the maximum number of threads to use.
     *
     * @return  the maximum number to use
     */
    public final int getMaxThreads() {
        return maxThreads;
    }
    /**
     * Sets the maximum number of threads to use.
     *
     * @param newMaxThreads  the new maximum thread count value
     * @return               a reference to this configuration for method
     *                       chaining
     */
    public final Configuration setMaxThreads(final int newMaxThreads) {
        maxThreads = newMaxThreads;
        return this;
    }
    /**
     * Gets the set of characters to use.
     *
     * @return  the characters
     */
    public final char[] getCharacters() {
        char[] charsToReturn = null;
        if (characters != null) {
            charsToReturn = Arrays.copyOf(characters, characters.length);
        }
        return charsToReturn;
    }
    /**
     * Sets the characters to use.
     *
     * @param newCharacters  the new set of characters to assign
     * @return               a reference to this configuration for method
     *                       chaining
     */
    public final Configuration setCharacters(final char[] newCharacters) {
        if (newCharacters == null) {
            characters = null;
        } else {
            characters = Arrays.copyOf(newCharacters, newCharacters.length);
        }
        return this;
    }
    /**
     * Gets the file path.
     *
     * @return  the file path
     */
    public final String getFilePath() {
        return filePath;
    }
    /**
     * Sets the file path.
     *
     * @param newPath  the new file path
     * @return         a reference to this configuration for method chaining
     */
    public final Configuration setFilePath(final String newPath) {
        filePath = newPath;
        return this;
    }
}
