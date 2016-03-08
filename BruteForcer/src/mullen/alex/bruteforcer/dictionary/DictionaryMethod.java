package mullen.alex.bruteforcer.dictionary;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.bind.DatatypeConverter;

import mullen.alex.bruteforcer.BruteForceMethod;
import mullen.alex.bruteforcer.Configuration;

/**
 * Represents a brute forcer that uses a dictionary of words against a digest.
 *
 * @author  Alex Mullen
 *
 */
public class DictionaryMethod implements BruteForceMethod {
    /** The logger instance for this class. */
    private static final Logger LOG =
            Logger.getLogger(DictionaryMethod.class.getName());
    /** The character encoding to use for representing strings. */
    private static final Charset CHARSET = StandardCharsets.UTF_8;
    ////////////////////////////////////////////////////////////////////////////
    /**
     * Creates a new instance.
     */
    public DictionaryMethod() {
        // Intentionally empty.
    }
    @Override
    public final void run(final Configuration config,
            final Consumer<byte[]> messageAction) {
        // Open dictionary.
        final File dictionaryFile = new File(config.getFilePath());
        try (final BufferedReader reader =
                    new BufferedReader(new InputStreamReader(
                            new FileInputStream(dictionaryFile), CHARSET))) {
            // Go through each word.
            final MessageDigest digestAlgorithm =
                    MessageDigest.getInstance(config.getDigestType());
            final byte[] digestBuffer =
                    new byte[digestAlgorithm.getDigestLength()];
            final byte[] hash = config.getDigest();
            final CharsetEncoder stringEncoder = CHARSET.newEncoder();
            final CharBuffer charBuffer = CharBuffer.allocate(512); // !!!
            final ByteBuffer stringByteBuffer = ByteBuffer.allocate(512); // !!!
            String nextWord = reader.readLine();
            while (nextWord != null) {
                charBuffer.append(nextWord, 0, nextWord.length());
                charBuffer.flip();
                // Encode the string into bytes.
                stringEncoder.encode(charBuffer, stringByteBuffer, true);
                stringByteBuffer.flip();
                // Digest the bytes.
                digestAlgorithm.update(stringByteBuffer.array(), 0,
                        stringByteBuffer.remaining());
                digestAlgorithm.digest(digestBuffer, 0, digestBuffer.length);
                // Clear buffers ready for next time.
                charBuffer.clear();
                /*
                 * Check if it generated the same hash as the one we are looking
                 * for.
                 */
                if (Arrays.equals(digestBuffer, hash)) {
                    messageAction.accept(Arrays.copyOf(stringByteBuffer.array(),
                            stringByteBuffer.remaining()));
                }
                stringByteBuffer.clear();
                nextWord = reader.readLine();
            }
        } catch (final IOException | NoSuchAlgorithmException
                | DigestException e) {
            LOG.log(Level.SEVERE, e.toString(), e);
        }
    }
    @Override
    public final BigInteger estimateTimeRequired(final Configuration config) {
        return BigInteger.ZERO;
    }
    @Override
    public final void printJobDetails(final Configuration config) {
        System.out.println("Hash (" + config.getDigestType() + "): "
                + DatatypeConverter.printHexBinary(config.getDigest()));
        System.out.println("Using dictionary: " + config.getFilePath());
    }
    @Override
    public final boolean validateConfig(final Configuration config) {
        boolean isValid = true;
        if (config.getDigest() == null) {
            LOG.log(Level.SEVERE, "No hash provided.");
            isValid = false;
        }
        if (config.getDigestType() == null) {
            LOG.log(Level.SEVERE, "Hash type is not specified.");
            isValid = false;
        }
        if (config.getFilePath() == null) {
            LOG.log(Level.SEVERE, "No dictionary file specified.");
            isValid = false;
        }
        return isValid;
    }
}
