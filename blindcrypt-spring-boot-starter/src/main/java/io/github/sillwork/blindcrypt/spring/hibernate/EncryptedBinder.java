package io.github.sillwork.blindcrypt.spring.hibernate;

import io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException;
import io.github.sillwork.blindcrypt.spring.annotation.Encrypted;
import io.github.sillwork.blindcrypt.spring.converter.EncryptedBytesConverter;
import io.github.sillwork.blindcrypt.spring.converter.EncryptedStringConverter;
import jakarta.persistence.AttributeConverter;
import java.lang.reflect.Field;
import org.hibernate.binder.AttributeBinder;
import org.hibernate.boot.model.convert.internal.ClassBasedConverterDescriptor;
import org.hibernate.boot.model.convert.spi.ConverterDescriptor;
import org.hibernate.boot.spi.MetadataBuildingContext;
import org.hibernate.mapping.BasicValue;
import org.hibernate.mapping.PersistentClass;
import org.hibernate.mapping.Property;

/**
 * Idempotent Hibernate attribute binder for {@link Encrypted}, tested with Hibernate 6.5.x.
 * <p>
 * Attaches the appropriate {@link ConverterDescriptor} directly to the Hibernate metamodel
 * {@link BasicValue} at bootstrap time. Automatically selects between {@link EncryptedStringConverter}
 * and {@link EncryptedBytesConverter} depending on the property's returned Java type.
 * <p>
 * The binder relies on Hibernate internals (it clears the cached {@code BasicValue} resolution). It does not
 * check the Hibernate version itself. Instead, {@link io.github.sillwork.blindcrypt.spring.listener.BlindIndexStartupValidator}
 * verifies at startup, against Hibernate's runtime mapping model, that every persistent {@code @Encrypted}
 * attribute is converted by BlindCrypt, and stops the application otherwise.
 */
public class EncryptedBinder implements AttributeBinder<Encrypted> {

    /** Creates the instance; Hibernate instantiates the binder from {@link Encrypted @Encrypted}, not application code. */
    public EncryptedBinder() {
        // Instantiated by Hibernate through the attribute binder type declared on @Encrypted; the binder is stateless.
    }

    /**
     * Binds the appropriate JPA AttributeConverter to the entity attribute within the Hibernate metamodel.
     *
     * @param annotation      the {@link Encrypted} annotation present on the property
     * @param buildingContext the Hibernate metadata building context
     * @param persistentClass the declaring persistent entity class
     * @param property        the property being bound
     * @throws BlindCryptConfigurationException if applied to non-basic values or if conflicting converters exist
     */
    @Override
    @SuppressWarnings("java:S3011") // Required to clear Hibernate 6 BasicValue resolution cache during dynamic annotation binding
    public void bind(Encrypted annotation, MetadataBuildingContext buildingContext,
                     PersistentClass persistentClass, Property property) {
        String owner = persistentClass != null ? persistentClass.getClassName() : "embeddable";
        if (!(property.getValue() instanceof BasicValue basicValue)) {
            throw new BlindCryptConfigurationException(
                    "@Encrypted on " + owner + "." + property.getName() + " is not a basic attribute.",
                    "Use @Encrypted on String or byte[] fields only. For searchable values use EncryptedText or EncryptedBytes with @BlindIndex.");
        }

        // Hibernate 6.5 invokes attribute binders multiple times during bootstrap.
        // Guard against duplicate registrations to keep the binder strictly idempotent.
        ConverterDescriptor existingDescriptor = basicValue.getJpaAttributeConverterDescriptor();
        if (existingDescriptor != null) {
            Class<?> existingConverterClass = existingDescriptor.getAttributeConverterClass();
            if (existingConverterClass == EncryptedStringConverter.class ||
                existingConverterClass == EncryptedBytesConverter.class) {
                return;
            }
            throw new BlindCryptConfigurationException(
                    owner + "." + property.getName() + " has both @Encrypted and converter "
                            + existingConverterClass.getName() + ".",
                    "Remove the other @Convert. @Encrypted applies the BlindCrypt converter itself.");
        }

        // Select converter based on returned Java type (byte[] vs String)
        Class<?> returnedClass = property.getType().getReturnedClass();
        Class<? extends AttributeConverter<?, ?>> converterClass =
                (returnedClass != null && byte[].class.isAssignableFrom(returnedClass))
                        ? EncryptedBytesConverter.class
                        : EncryptedStringConverter.class;

        basicValue.setJpaAttributeConverterDescriptor(new ClassBasedConverterDescriptor(
                converterClass, false, buildingContext.getBootstrapContext().getClassmateContext()));

        // Hibernate 6.5 caches BasicValue's resolution during annotation scanning; clear it so the converter applies.
        // If this fails, the converter may not be applied and the column would be written in plaintext, so stop startup.
        try {
            Field resolutionField = BasicValue.class.getDeclaredField("resolution");
            resolutionField.setAccessible(true);
            resolutionField.set(basicValue, null);
        } catch (ReflectiveOperationException | RuntimeException e) {
            throw new BlindCryptConfigurationException(
                    "Cannot apply @Encrypted to " + owner + "." + property.getName()
                            + " on Hibernate " + org.hibernate.Version.getVersionString() + ".",
                    "BlindCrypt is tested with Hibernate 6.5.x. Use that version, or report this one at "
                            + "https://github.com/sillwork/blindcrypt/issues.", e);
        }
    }
}
