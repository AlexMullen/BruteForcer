package mullen.alex.bruteforcer;

/**
 * A basic digest determiner that uses the length of the digest to deduce the
 * message digest algorithm that produced it.
 *
 * @author  Alex Mullen
 *
 */
public class DefaultDigestDeterminer implements DigestDeterminer {
    /** Holds the byte length of a MD5 digest. */
    private static final int MD5_DIGEST_BYTELENGTH = 16;
    /** Holds the byte length of a SHA-1 digest. */
    private static final int SHA1_DIGEST_BYTELENGTH = 20;
    /** Holds the byte length of a SHA-224 digest. */
    private static final int SHA224_DIGEST_BYTELENGTH = 28;
    /** Holds the byte length of a SHA-256 digest. */
    private static final int SHA256_DIGEST_BYTELENGTH = 32;
    /** Holds the byte length of a SHA-384 digest. */
    private static final int SHA384_DIGEST_BYTELENGTH = 48;
    /** Holds the byte length of a SHA-512 digest. */
    private static final int SHA512_DIGEST_BYTELENGTH = 64;
    /**
     * Creates a new instance.
     */
    public DefaultDigestDeterminer() {
        // Intentionally empty.
    }
    @Override
    public final String determine(final byte[] digest) {
        String guess = null;
        switch (digest.length) {
            case MD5_DIGEST_BYTELENGTH:
                guess = "MD5";
                break;
            case SHA1_DIGEST_BYTELENGTH:
                guess = "SHA-1";
                break;
            case SHA224_DIGEST_BYTELENGTH:
                guess = "SHA-224";
                break;
            case SHA256_DIGEST_BYTELENGTH:
                guess = "SHA-256";
                break;
            case SHA384_DIGEST_BYTELENGTH:
                guess = "SHA-384";
                break;
            case SHA512_DIGEST_BYTELENGTH:
                guess = "SHA-512";
                break;
            default:
                break;
        }
        return guess;
    }
}
