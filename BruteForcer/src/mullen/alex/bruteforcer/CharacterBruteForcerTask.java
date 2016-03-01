package mullen.alex.bruteforcer;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Represents a character set brute forcer task that generates every possible
 * arrangement for a set of specified characters.
 *
 * @author  Alex Mullen
 *
 */
public class CharacterBruteForcerTask implements Runnable {
    /** The logger instance for this class. */
    private static final Logger LOG =
            Logger.getLogger(CharacterBruteForcerTask.class.getName());
    /** The character encoding to use for representing strings. */
    private static final Charset CHARSET = StandardCharsets.UTF_8;
    ////////////////////////////////////////////////////////////////////////////
    /** The hash algorithm. */
    private final MessageDigest algorithm;
    /** The hash to crack. */
    private final byte[] hash;
    /** The character space of characters to try. */
    private final char[] characterSpace;
    /** The maximum length of message to generate and try. */
    private final int maxMessageLength;
    /** The current generated message. */
    private final StrippedStringBuilder messageBuilder;
    ////////////////////////////////////////////////////////////////////////////
    /** A reusable buffer for storing a generated digest. */
    private final byte[] digestBuffer;
    /** The character set encoder to use for converting characters to bytes. */
    private final CharsetEncoder stringEncoder;
    /** The character buffer to use for storing the generated characters. */
    private final CharBuffer charBuffer;
    /** The byte buffer to use for storing the bytes for a string. */
    private final ByteBuffer stringByteBuffer;
    /**
     * Creates a new instance.
     *
     * @param algo            the algorithm to use
     * @param h               the hash to brute force
     * @param charSpace       the character space to use
     * @param maxLength       the maximum length of message to generate
     * @param initalMessage   the initial prefix message to start with
     */
    public CharacterBruteForcerTask(final MessageDigest algo,
            final byte[] h, final char[] charSpace,
            final int maxLength, final StrippedStringBuilder initalMessage) {
        // Passed parameters.
        algorithm = Objects.requireNonNull(algo);
        hash = Arrays.copyOf(h, h.length);
        characterSpace = Arrays.copyOf(charSpace, charSpace.length);
        messageBuilder = Objects.requireNonNull(initalMessage);
        maxMessageLength = maxLength;
        // Initialise objects we require.
        digestBuffer = new byte[algorithm.getDigestLength()];
        stringEncoder = CHARSET.newEncoder(); //!!!
        stringByteBuffer = ByteBuffer.allocate(maxMessageLength);
        charBuffer = CharBuffer.allocate(maxMessageLength);
    }
    @Override
    public final void run() {
        try {
            dive();
        } catch (final DigestException e) {
            LOG.log(Level.SEVERE, e.toString(), e);
        }
    }
    /**
     * Performs the recursive search of all permutations.
     *
     * @throws DigestException  if an error occurs performing the digest
     */
    private void dive() throws DigestException {
        final String generatedKey = messageBuilder.toString();
        ////////////////////////////////////////////////////////////////
        /*
         * Leave this line commented out unless you want to see every
         * key being generated which significantly slows down the
         * process.
         */
//        System.out.println("[" + generatedKey + "]");
        ////////////////////////////////////////////////////////////////
        // Append the generated key string into the character buffer.
        charBuffer.append(generatedKey, 0, generatedKey.length());
        charBuffer.flip();
        // Encode the string into bytes.
        stringEncoder.encode(charBuffer, stringByteBuffer, true);
        stringByteBuffer.flip();
        // Digest the bytes.
        algorithm.update(stringByteBuffer.array(), 0,
                stringByteBuffer.remaining());
        algorithm.digest(digestBuffer, 0, digestBuffer.length);
        // Clear buffers ready for next time.
        charBuffer.clear();
        stringByteBuffer.clear();
        /*
         * Check if it generated the same hash as the one we are looking
         * for.
         */
        if (Arrays.equals(digestBuffer, hash)) {
            System.out.println("Key candidate found: " + generatedKey);
        }
        /*
         * Check if we do not need to dive any deeper. Failing to check for
         * this will result in a stack overflow.
         */
        if (messageBuilder.length() < maxMessageLength) {
            /*
             * Go through each character in the key space and append it to the
             * current path so as to generate a new key to try.
             */
            for (int i = 0; i < characterSpace.length; i++) {
                messageBuilder.append(characterSpace[i]);
                /*
                 * This is the recursive part where this procedure calls itself
                 * so that this process can happen again on the next key.
                 */
                dive();
                // Undo the added character.
                messageBuilder.clipLastCharacter();
            }
        }
    }
}
