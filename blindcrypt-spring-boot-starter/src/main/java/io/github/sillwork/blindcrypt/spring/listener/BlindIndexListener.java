package io.github.sillwork.blindcrypt.spring.listener;

import java.util.concurrent.atomic.AtomicReference;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;

/**
 * Standard JPA Entity Lifecycle Listener for automatic flush-time blind index calculation.
 * <p>
 * Must be declared on any JPA entity containing {@link io.github.sillwork.blindcrypt.spring.annotation.BlindIndex} fields:
 * <pre>{@code
 * @Entity
 * @EntityListeners(BlindIndexListener.class)
 * public class User { ... }
 * }</pre>
 * Automatically intercepted by JPA during {@code @PrePersist} and {@code @PreUpdate} lifecycle phases
 * to ensure blind indexes are mathematically synchronized before SQL flush.
 */
public class BlindIndexListener {

    private static final AtomicReference<BlindIndexRegistry> REGISTRY_REF = new AtomicReference<>();

    /** Creates the instance; the JPA provider instantiates the listener from {@code @EntityListeners}, not application code. */
    public BlindIndexListener() {
        // Instantiated by the JPA provider (Hibernate) from @EntityListeners; the registry is shared statically.
    }

    /**
     * Injects the global application {@link BlindIndexRegistry}.
     *
     * @param registry the active BlindIndexRegistry bean
     */
    public static void setRegistry(BlindIndexRegistry registry) {
        REGISTRY_REF.set(registry);
    }

    /**
     * Intercepts JPA {@code @PrePersist} and {@code @PreUpdate} events to compute and assign
     * companion blind indexes for all annotated fields.
     *
     * @param entity the managed JPA entity being persisted or updated
     */
    @PrePersist
    @PreUpdate
    public void onPersistOrUpdate(Object entity) {
        BlindIndexRegistry registry = REGISTRY_REF.get();
        if (registry != null) {
            registry.computeAndAssignIndexes(entity);
        }
    }
}
