package io.github.sillwork.blindcrypt.spring.repository;

import jakarta.persistence.EntityManagerFactory;
import java.util.Map;
import java.util.Objects;
import org.springframework.beans.factory.ListableBeanFactory;

/**
 * Dynamically resolves the specific {@link EntityManagerFactory} managing a given domain entity type.
 * <p>
 * In multi-datasource or multi-persistence-unit configurations, standard Spring Data
 * lookups can fail or route to the wrong database context. This resolver inspects all registered
 * {@link EntityManagerFactory} beans in the Spring application context, checks their JPA metamodels,
 * and routes blind index queries to the exact matching persistence unit.
 */
public final class DynamicEntityManagerFactoryResolver {

    private DynamicEntityManagerFactoryResolver() { }

    /**
     * Resolves the primary {@link EntityManagerFactory} that manages the specified entity domain class.
     *
     * @param domainClass the entity class type to resolve (e.g. {@code User.class})
     * @param beanFactory the Spring {@link ListableBeanFactory} to query for available EntityManagerFactory beans
     * @return the matching {@link EntityManagerFactory}
     * @throws IllegalStateException if no registered EntityManagerFactory manages the specified entity class
     */
    public static EntityManagerFactory resolveForEntity(Class<?> domainClass, ListableBeanFactory beanFactory) {
        Objects.requireNonNull(domainClass, "domainClass cannot be null");
        Objects.requireNonNull(beanFactory, "beanFactory cannot be null");

        Map<String, EntityManagerFactory> entityManagerFactories = beanFactory.getBeansOfType(EntityManagerFactory.class);
        for (EntityManagerFactory entityManagerFactory : entityManagerFactories.values()) {
            try {
                if (entityManagerFactory.getMetamodel().entity(domainClass) != null) {
                    return entityManagerFactory;
                }
            } catch (IllegalArgumentException ignored) {
                // The entity is not managed by this specific EntityManagerFactory; continue scanning
            }
        }
        throw new IllegalStateException("Could not resolve an EntityManagerFactory managing domain entity: " + domainClass.getName());
    }
}
