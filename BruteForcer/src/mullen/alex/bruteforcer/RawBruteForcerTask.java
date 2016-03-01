package mullen.alex.bruteforcer;

import java.io.UnsupportedEncodingException;
import java.security.DigestException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.bind.DatatypeConverter;

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
    ////////////////////////////////////////////////////////////////////////////
    /** A reusable buffer for storing a generated digest. */
    private final byte[] hashBuffer;
    /** Holds the current generated input permutation. */
    private final byte[] generatedBuffer;
    /**
     * Creates a new instance.
     *
     * @param algo            the algorithm to use
     * @param h               the hash to brute force
     * @param maxMsgLength    the maximum length of message to generate
     * @param initialMessage  the initial prefix message to start with
     */
    public RawBruteForcerTask(final MessageDigest algo, final byte[] h,
            final int maxMsgLength, final int initialMessage) {
        // Passed parameters.
        algorithm = Objects.requireNonNull(algo);
        hash = Arrays.copyOf(h, h.length);
        maxMessageLength = maxMsgLength;
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
//        System.out.println(Arrays.toString(
//                Arrays.copyOf(generatedBuffer, count)));
        algorithm.update(generatedBuffer, 0, count);
        algorithm.digest(hashBuffer, 0, hashBuffer.length);
        /*
         * Check if it generated the same hash as the one we are looking
         * for.
         */
        if (Arrays.equals(hashBuffer, hash)) {
            final byte[] messageBytes =
                    Arrays.copyOf(generatedBuffer, count);
            System.out.println("Key candidate found: "
                    + Arrays.toString(messageBytes)
                    + " = " + DatatypeConverter.printHexBinary(messageBytes)
                    + " = " + new String(messageBytes, "UTF-8"));
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
