package mullen.alex.bruteforcer.characters;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

import mullen.alex.bruteforcer.Configuration;

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
    /** The action to take when a successful message is found. */
    private final Consumer<byte[]> foundAction;
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
     * @param config          the configuration details
     * @param initalMessage   the initial prefix message to start with
     * @param action          the action to take when a message is found
     */
    public CharacterBruteForcerTask(final MessageDigest algo,
            final Configuration config,
            final StrippedStringBuilder initalMessage,
            final Consumer<byte[]> action) {
        // Passed parameters.
        algorithm = Objects.requireNonNull(algo);
        hash = Arrays.copyOf(config.getDigest(), config.getDigest().length);
        final char[] characters = config.getCharacters();
        characterSpace = Arrays.copyOf(characters, characters.length);
        messageBuilder = Objects.requireNonNull(initalMessage);
        foundAction = Objects.requireNonNull(action);
        maxMessageLength = config.getMaxLength();
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
        /*
         * Check if it generated the same hash as the one we are looking
         * for.
         */
        if (Arrays.equals(digestBuffer, hash)) {
            foundAction.accept(Arrays.copyOf(stringByteBuffer.array(),
                    stringByteBuffer.remaining()));
        }
        stringByteBuffer.clear();
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
