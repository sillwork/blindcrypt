package io.github.sillwork.blindcrypt.core;

import java.util.concurrent.ConcurrentLinkedQueue;
import javax.crypto.Cipher;

/**
 * Striped pool of reusable {@link Cipher} instances that does not use {@code ThreadLocal}.
 * <p>
 * The pool holds 16 {@link ConcurrentLinkedQueue} stripes, selected by the calling thread's id.
 * Each stripe keeps at most 64 idle ciphers. When the selected stripe is empty, a new cipher is created.
 * Ciphers returned to a full stripe are discarded.
 */
public final class StripedCipherPool {

    private static final int STRIPE_COUNT = 16;
    private static final int MASK = STRIPE_COUNT - 1;

    @SuppressWarnings("unchecked")
    private final ConcurrentLinkedQueue<Cipher>[] stripes = new ConcurrentLinkedQueue[STRIPE_COUNT];
    private final String transformation;

    /**
     * Constructs a striped Cipher pool for the specified cryptographic transformation.
     *
     * @param transformation the JCA transformation string (e.g. {@code "AES/GCM/NoPadding"})
     */
    public StripedCipherPool(String transformation) {
        this.transformation = transformation;
        for (int i = 0; i < STRIPE_COUNT; i++) {
            this.stripes[i] = new ConcurrentLinkedQueue<>();
        }
    }

    /**
     * Borrows an initialized Cipher from the thread's designated stripe,
     * or instantiates a fresh Cipher if the stripe is currently empty.
     *
     * @return a usable {@link Cipher} instance for the pool's transformation
     * @throws CryptoException if a new Cipher instance cannot be instantiated
     */
    public Cipher borrowCipher() {
        int stripeIndex = (int) (Thread.currentThread().threadId() & MASK);
        Cipher cipher = stripes[stripeIndex].poll();
        if (cipher != null) {
            return cipher;
        }
        return createCipher();
    }

    private static final int MAX_CIPHERS_PER_STRIPE = 64;

    /**
     * Returns a borrowed Cipher back to the calling thread's stripe for subsequent reuse.
     *
     * @param cipher the {@link Cipher} instance to return, or {@code null}
     */
    public void returnCipher(Cipher cipher) {
        if (cipher != null) {
            int stripeIndex = (int) (Thread.currentThread().threadId() & MASK);
            if (stripes[stripeIndex].size() < MAX_CIPHERS_PER_STRIPE) {
                stripes[stripeIndex].offer(cipher);
            }
        }
    }

    private Cipher createCipher() {
        try {
            return Cipher.getInstance(transformation);
        } catch (Exception e) {
            throw new CryptoException("Failed to initialize Cipher for transformation: " + transformation, e);
        }
    }
}
