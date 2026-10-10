package io.github.sillwork.blindcrypt.spring.listener;

import io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException;
import io.github.sillwork.blindcrypt.core.Normalization;
import io.github.sillwork.blindcrypt.core.UltraBlindIndexer;
import io.github.sillwork.blindcrypt.spring.annotation.BlindIndex;
import io.github.sillwork.blindcrypt.spring.model.EncryptedBytes;
import io.github.sillwork.blindcrypt.spring.model.EncryptedText;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Metadata cache and evaluator for entity blind indexes.
 * <p>
 * Inspects entity classes for {@link BlindIndex} annotations and computes/assigns HMAC blind index
 * hashes at runtime during entity persistence or update cycles. Reflective inspection results are
 * cached per entity class in a {@link ConcurrentHashMap} so each class is scanned once.
 */
public class BlindIndexRegistry {

    private final UltraBlindIndexer blindIndexer;
    private final Map<Class<?>, List<FieldMetadata>> metadataCache = new ConcurrentHashMap<>();

    /**
     * Constructs a BlindIndexRegistry backed by the specified cryptographic indexer.
     *
     * @param blindIndexer the active cryptographic blind indexer
     */
    public BlindIndexRegistry(UltraBlindIndexer blindIndexer) {
        this.blindIndexer = Objects.requireNonNull(blindIndexer, "blindIndexer cannot be null");
    }

    /**
     * Inspects entity fields and synchronously computes/assigns companion blind indexes.
     *
     * @param entity the entity instance being evaluated
     */
    public void computeAndAssignIndexes(Object entity) {
        if (entity == null) {
            return;
        }

        Class<?> entityClass = entity.getClass();
        List<FieldMetadata> fields = metadataCache.computeIfAbsent(entityClass, this::scanClass);

        for (FieldMetadata fieldMetadata : fields) {
            assignIndexForField(entity, fieldMetadata, entityClass);
        }
    }

    private void assignIndexForField(Object entity, FieldMetadata fieldMetadata, Class<?> entityClass) {
        try {
            Object fieldValue = fieldMetadata.field.get(entity);
            if (fieldValue instanceof EncryptedText encryptedText) {
                processEncryptedText(encryptedText, fieldMetadata);
            } else if (fieldValue instanceof EncryptedBytes encryptedBytes) {
                processEncryptedBytes(encryptedBytes, fieldMetadata);
            }
        } catch (IllegalAccessException exception) {
            throw new BlindCryptConfigurationException(
                    "Cannot read field " + entityClass.getName() + "." + fieldMetadata.field.getName() + ".",
                    "Make sure the field is not final and the entity module is open to BlindCrypt reflection.", exception);
        }
    }

    private void processEncryptedText(EncryptedText encryptedText, FieldMetadata fieldMetadata) {
        String plainText = encryptedText.value();
        if (plainText != null) {
            String hexHash = blindIndexer.computeHex(
                    fieldMetadata.annotation.name(), 
                    plainText, 
                    fieldMetadata.annotation.normalization(), 
                    null);
            encryptedText.assignBlindIndex(hexHash);
        } else {
            encryptedText.assignBlindIndex(null);
        }
    }

    private void processEncryptedBytes(EncryptedBytes encryptedBytes, FieldMetadata fieldMetadata) {
        byte[] plainBytes = encryptedBytes.value();
        if (plainBytes != null) {
            byte[] binaryHash;
            if (fieldMetadata.annotation.normalization() == Normalization.NONE) {
                binaryHash = blindIndexer.computeBinary(
                        fieldMetadata.annotation.name(),
                        plainBytes,
                        null);
            } else {
                String plainTextString = new String(plainBytes, StandardCharsets.UTF_8);
                binaryHash = blindIndexer.computeBinary(
                        fieldMetadata.annotation.name(), 
                        plainTextString, 
                        fieldMetadata.annotation.normalization(), 
                        null);
            }
            encryptedBytes.assignBlindIndex(binaryHash);
        } else {
            encryptedBytes.assignBlindIndex(null);
        }
    }

    /**
     * Finds the {@link BlindIndex} annotation configuration for a specific entity property name.
     *
     * @param entityClass  the entity class type to check
     * @param propertyName the Java property name (e.g. "email")
     * @return an {@link Optional} containing the annotation if present, or empty
     */
    public Optional<BlindIndex> findBlindIndexAnnotation(Class<?> entityClass, String propertyName) {
        List<FieldMetadata> fields = metadataCache.computeIfAbsent(entityClass, this::scanClass);
        for (FieldMetadata fieldMetadata : fields) {
            if (fieldMetadata.field.getName().equals(propertyName)) {
                return Optional.of(fieldMetadata.annotation);
            }
        }
        return Optional.empty();
    }

    @SuppressWarnings("java:S3011") // Reflection accessibility required to inspect and read private @BlindIndex entity fields
    private List<FieldMetadata> scanClass(Class<?> targetClass) {
        List<FieldMetadata> fieldList = new ArrayList<>();
        Class<?> currentClass = targetClass;
        while (currentClass != null && currentClass != Object.class) {
            for (Field field : currentClass.getDeclaredFields()) {
                BlindIndex annotation = field.getAnnotation(BlindIndex.class);
                if (annotation != null) {
                    field.setAccessible(true);
                    fieldList.add(new FieldMetadata(field, annotation));
                }
            }
            currentClass = currentClass.getSuperclass();
        }
        return List.copyOf(fieldList);
    }

    private record FieldMetadata(Field field, BlindIndex annotation) { }
}
