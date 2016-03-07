package mullen.alex.bruteforcer.characters;

/**
 * A very minimal and bespoke string builder implementation that cuts out
 * all validation for critical performance reasons.
 *
 * @author  Alex Mullen
 *
 */
public class StrippedStringBuilder {
    /** The number of characters currently held. */
    private int count;
    /** The backing character array. */
    private final char[] value;
    /**
     * Creates a new instance of that has the specified capacity.
     *
     * @param capacity  the capacity in characters
     */
    StrippedStringBuilder(final int capacity) {
        value = new char[capacity];
    }
    /**
     * Appends the specified character.
     *
     * @param c  the character
     */
    public final void append(final char c) {
        value[count++] = c;
    }
    /**
     * Gets the number of characters held.
     *
     * @return  the number of characters
     */
    public final int length() {
        return count;
    }
    /**
     * Removes the last character.
     */
    public final void clipLastCharacter() {
        count--;
    }
    @Override
    public final String toString() {
        return new String(value, 0, count);
    }
}
