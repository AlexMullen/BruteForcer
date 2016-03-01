# BruteForcer
A hash brute forcer written in Java that was written to further my understanding of how they work so as to demonstrate how fast a computer can crack weak passwords.

To use it you need to pass in the required command-line arguments.

<b>-type</b> [the digest algorithm]<br>
<b>-hash</b> [the hexadecimal hash string]<br>
<b>-method</b> [<i>raw|chars|dictionary</i>]<br>
<b>-maxlength</b> [maximum length of messages to generate]<br>
<b>-threads</b> [number of CPU threads to use]<br>

if "chars" is chosen for -method then you need to provide a set of characters using<br>
<b>-chars</b> 0123456789abcdef....

The <i>raw</i> method choice attempts to find a raw byte message upto <b>-maxlength</b> in length that has a hash equal to <b>-hash</b>. The "char" method goes through every permutation of characters specified in <b>-chars</b> upto <b>-maxlength</b> so that the set of characters "ab" up to a <b>-maxlength</b> of <b>2</b> would check.

a<br>
aa<br>
ab<br>
b<br>
ba<br>
bb<br>


Currently the "dictionary" method is not implemented yet.
