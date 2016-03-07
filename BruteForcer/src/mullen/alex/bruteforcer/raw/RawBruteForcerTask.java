package mullen.alex.bruteforcer.raw;

import java.io.UnsupportedEncodingException;
import java.security.DigestException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

import mullen.alex.bruteforcer.Configuration;

/**
 * Represents a brute forcer task that generates every possible arrangement of
 * bytes for a specified length.
 *
 * @author  Alex Mullen
 *
 */
public class RawBruteForcerTask implements Runnable {
    /** The logger instance for this class. */
    private static final Logger LOG =
            Logger.getLogger(RawBruteForcerTask.class.getName());
    /** Holds/represents the number of unique values one byte can hold. */
    public static final int UNIQUE_BYTE_VALUES = 256;
    ////////////////////////////////////////////////////////////////////////////
    /** The hash algorithm. */
    private final MessageDigest algorithm;
    /** The hash to crack. */
    private final byte[] hash;
    /** The maximum length of message to generate and try. */
    private final int maxMessageLength;
    /** The action to take when a successful message is found. */
    private final Consumer<byte[]> foundAction;
    ////////////////////////////////////////////////////////////////////////////
    /** A reusable buffer for storing a generated digest. */
    private final byte[] hashBuffer;
    /** Holds the current generated input permutation. */
    private final byte[] generatedBuffer;
    /**
     * Creates a new instance.
     *
     * @param algo            the algorithm to use
     * @param config          job information
     * @param initialMessage  the initial prefix message to start with
     * @param action          the action to take when a message is found
     */
    public RawBruteForcerTask(final MessageDigest algo,
            final Configuration config, final int initialMessage,
            final Consumer<byte[]> action) {
        // Passed parameters.
        algorithm = Objects.requireNonNull(algo);
        foundAction = Objects.requireNonNull(action);
        hash = Arrays.copyOf(config.getDigest(), config.getDigest().length);
        maxMessageLength = config.getMaxLength();
        // Initialise objects we require.
        generatedBuffer = new byte[maxMessageLength];
        generatedBuffer[0] = (byte) initialMessage;
        hashBuffer = new byte[algorithm.getDigestLength()];
    }
    @Override
    public final void run() {
        try {
            dive(1);
        } catch (final DigestException | UnsupportedEncodingException e) {
            LOG.log(Level.SEVERE, e.toString(), e);
        }
    }
    /**
     * Performs the recursive search of all permutations.
     *
     * @param count  the current length of the message
     *
     * @throws DigestException               if an error occurs performing the
     *                                       digest
     * @throws UnsupportedEncodingException  if the specified character set is
     *                                       not supported
     */
    private void dive(final int count) throws DigestException,
        UnsupportedEncodingException {
        algorithm.update(generatedBuffer, 0, count);
        algorithm.digest(hashBuffer, 0, hashBuffer.length);
        /*
         * Check if it generated the same hash as the one we are looking
         * for.
         */
        if (Arrays.equals(hashBuffer, hash)) {
            // Found an input message!
            foundAction.accept(Arrays.copyOf(generatedBuffer, count));
        }
        if (count < maxMessageLength) {
            final int nextCount = count + 1;
            for (int i = 0; i < UNIQUE_BYTE_VALUES; i++) {
                generatedBuffer[count] = (byte) i;
                dive(nextCount);
            }
        }
    }
}
