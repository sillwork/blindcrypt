package io.github.sillwork.blindcrypt.spring.listener;

import io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException;
import io.github.sillwork.blindcrypt.spring.annotation.BlindIndex;
import io.github.sillwork.blindcrypt.spring.annotation.Encrypted;
import io.github.sillwork.blindcrypt.spring.model.EncryptedBytes;
import io.github.sillwork.blindcrypt.spring.model.EncryptedText;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Embeddable;
import jakarta.persistence.Embedded;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.metamodel.EntityType;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.hibernate.annotations.DynamicUpdate;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.metamodel.MappingMetamodel;
import org.hibernate.persister.entity.EntityPersister;
import org.springframework.beans.factory.SmartInitializingSingleton;

/**
 * Fail-fast startup validation engine.
 * <p>
 * Runs after all singletons are created and before the embedded web server starts.
 * <p>
 * Scans the JPA metamodel on application boot to detect and abort on silent misconfigurations:
 * <ul>
 *   <li>Missing {@code @EntityListeners(BlindIndexListener.class)} on entities with {@code @BlindIndex}.</li>
 *   <li>Usage of {@code @DynamicUpdate} on encrypted entities, which breaks blind index updates inside {@code @PreUpdate}.</li>
 *   <li>Usage of searchable encrypted embeddables inside unsupported {@code @ElementCollection} associations.</li>
 *   <li>Any persistent {@code @Encrypted} attribute, including the ciphertext inside {@code EncryptedText} and
 *       {@code EncryptedBytes}, that Hibernate's runtime mapping does not convert through the BlindCrypt
 *       converter. Such an attribute would be stored in plaintext.</li>
 * </ul>
 */
public class BlindIndexStartupValidator implements SmartInitializingSingleton {

    private final EntityManager entityManager;

    /**
     * Constructs a BlindIndexStartupValidator for the active EntityManager.
     *
     * @param entityManager the JPA EntityManager to inspect metamodels from
     */
    public BlindIndexStartupValidator(EntityManager entityManager) {
        this.entityManager = Objects.requireNonNull(entityManager, "entityManager cannot be null");
    }

    /**
     * Validates all registered entity types once every singleton has been created.
     *
     * @throws BlindCryptConfigurationException if an entity is mapped in an unsupported way, or an {@code @Encrypted}
     *                                          attribute is not mapped through the BlindCrypt converter
     */
    @Override
    public void afterSingletonsInstantiated() {
        Set<EntityType<?>> entities = entityManager.getMetamodel().getEntities();
        for (EntityType<?> entityType : entities) {
            Class<?> javaType = entityType.getJavaType();
            if (javaType != null) {
                validateEntity(javaType);
            }
        }
        MappingMetamodel mappingMetamodel = null;
        for (EntityType<?> entityType : entities) {
            Class<?> javaType = entityType.getJavaType();
            if (javaType == null || !declaresEncryptedMembers(javaType)) {
                continue;
            }
            if (mappingMetamodel == null) {
                mappingMetamodel = resolveMappingMetamodel();
            }
            verifyEncryptedAttributes(javaType, mappingMetamodel);
        }
    }

    private MappingMetamodel resolveMappingMetamodel() {
        try {
            return entityManager.getEntityManagerFactory().unwrap(SessionFactoryImplementor.class).getMappingMetamodel();
        } catch (RuntimeException | LinkageError e) {
            throw new BlindCryptConfigurationException(
                    "BlindCrypt cannot read the Hibernate mapping model to verify that @Encrypted attributes are converted.",
                    "Use Hibernate ORM as the JPA provider. BlindCrypt is tested with Hibernate 6.5.x; report other versions at "
                            + "https://github.com/sillwork/blindcrypt/issues.", e);
        }
    }

    private void verifyEncryptedAttributes(Class<?> entityClass, MappingMetamodel mappingMetamodel) {
        try {
            EntityPersister persister = mappingMetamodel.findEntityDescriptor(entityClass);
            if (persister == null) {
                throw new BlindCryptConfigurationException(
                        "Hibernate has no entity mapping for " + entityClass.getName()
                                + ", so BlindCrypt cannot verify that its encrypted attributes are converted.",
                        "Report this setup at https://github.com/sillwork/blindcrypt/issues.");
            }
            EncryptedConverterVerifier.verify(entityClass, persister);
        } catch (LinkageError e) {
            throw new BlindCryptConfigurationException(
                    "BlindCrypt cannot verify @Encrypted attributes of " + entityClass.getName() + " on Hibernate "
                            + EncryptedConverterVerifier.hibernateVersion() + ".",
                    "Use a Hibernate version supported by this BlindCrypt release (tested with 6.5.x), or report the version at "
                            + "https://github.com/sillwork/blindcrypt/issues.", e);
        }
    }

    /**
     * Returns whether the class hierarchy declares an {@code @Encrypted} member or an {@code EncryptedText} /
     * {@code EncryptedBytes} field. Other embeddables are checked when the class has such a member itself.
     */
    private static boolean declaresEncryptedMembers(Class<?> entityClass) {
        for (Class<?> current = entityClass; current != null && current != Object.class; current = current.getSuperclass()) {
            for (Field field : current.getDeclaredFields()) {
                if (field.isAnnotationPresent(Encrypted.class) || field.getType() == EncryptedText.class
                        || field.getType() == EncryptedBytes.class || isEmbedded(field)) {
                    return true;
                }
            }
            for (java.lang.reflect.Method method : current.getDeclaredMethods()) {
                if (method.isAnnotationPresent(Encrypted.class)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isEmbedded(Field field) {
        return field.isAnnotationPresent(Embedded.class) || field.getType().isAnnotationPresent(Embeddable.class);
    }

    private void validateEntity(Class<?> entityClass) {
        if (entityClass == null) {
            return;
        }
        List<Field> indexedFields = findIndexedFields(entityClass);
        if (indexedFields.isEmpty()) return;

        // Ensure Entity declares @EntityListeners(BlindIndexListener.class) in hierarchy
        if (!hasEntityListener(entityClass, BlindIndexListener.class)) {
            throw new BlindCryptConfigurationException(
                    "Entity " + entityClass.getName() + " has @BlindIndex fields but does not register BlindIndexListener.",
                    "Add @EntityListeners(BlindIndexListener.class) to " + entityClass.getSimpleName()
                            + " or a superclass. Without it, blind index columns stay null and lookups return nothing.");
        }

        // Reject @DynamicUpdate in hierarchy
        if (hasAnnotationInHierarchy(entityClass, DynamicUpdate.class)) {
            throw new BlindCryptConfigurationException(
                    "Entity " + entityClass.getName() + " is annotated with @DynamicUpdate, which BlindCrypt does not support.",
                    "Remove @DynamicUpdate. Hibernate may omit blind index columns that BlindIndexListener changes in @PreUpdate.");
        }

        // Validate that no searchable embeddable is declared in an ElementCollection
        for (Field field : entityClass.getDeclaredFields()) {
            if (field.isAnnotationPresent(ElementCollection.class)) {
                Class<?> fieldType = field.getType();
                if (fieldType.equals(EncryptedText.class) || fieldType.equals(EncryptedBytes.class)) {
                    throw new BlindCryptConfigurationException(
                            "Field " + entityClass.getName() + "." + field.getName()
                                    + " places an encrypted embeddable inside @ElementCollection, which is not supported.",
                            "Model the collection as a @OneToMany entity with its own @BlindIndex field.");
                }
            }
        }
    }

    private List<Field> findIndexedFields(Class<?> targetClass) {
        List<Field> fields = new ArrayList<>();
        Class<?> currentClass = targetClass;
        while (currentClass != null && currentClass != Object.class) {
            for (Field field : currentClass.getDeclaredFields()) {
                if (field.isAnnotationPresent(BlindIndex.class)) {
                    fields.add(field);
                }
            }
            currentClass = currentClass.getSuperclass();
        }
        return fields;
    }

    private boolean hasEntityListener(Class<?> targetClass, Class<?> listenerClass) {
        Class<?> current = targetClass;
        while (current != null && current != Object.class) {
            EntityListeners listeners = current.getAnnotation(EntityListeners.class);
            if (listeners != null && Arrays.asList(listeners.value()).contains(listenerClass)) {
                return true;
            }
            current = current.getSuperclass();
        }
        return false;
    }

    private boolean hasAnnotationInHierarchy(Class<?> targetClass, Class<? extends Annotation> annotationClass) {
        Class<?> current = targetClass;
        while (current != null && current != Object.class) {
            if (current.isAnnotationPresent(annotationClass)) {
                return true;
            }
            current = current.getSuperclass();
        }
        return false;
    }
}
