package mullen.alex.bruteforcer;

/**
 * An interface for determine a class that determines what algorithm produced
 * a given digest.
 *
 * @author  Alex Mullen
 *
 */
public interface DigestDeterminer {
    /**
     * Determines what message digest algorithm produced the specified digest.
     *
     * @param digest  the raw digest
     * @return        a string representing the name of the message digest
     *                algorithm or <code>null</code> if it could not be
     *                determined
     */
    String determine(final byte[] digest);
}
