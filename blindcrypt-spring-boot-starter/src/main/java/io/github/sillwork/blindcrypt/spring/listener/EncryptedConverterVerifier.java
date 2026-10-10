package io.github.sillwork.blindcrypt.spring.listener;

import io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException;
import io.github.sillwork.blindcrypt.spring.annotation.Encrypted;
import io.github.sillwork.blindcrypt.spring.converter.EncryptedBytesConverter;
import io.github.sillwork.blindcrypt.spring.converter.EncryptedStringConverter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import org.hibernate.metamodel.mapping.AttributeMapping;
import org.hibernate.metamodel.mapping.BasicValuedModelPart;
import org.hibernate.metamodel.mapping.EmbeddableValuedModelPart;
import org.hibernate.metamodel.mapping.ManagedMappingType;
import org.hibernate.type.descriptor.converter.spi.BasicValueConverter;
import org.hibernate.type.descriptor.converter.spi.JpaAttributeConverter;

/**
 * Verifies against Hibernate's runtime mapping model that every persistent {@link Encrypted @Encrypted} attribute
 * is converted by {@link EncryptedStringConverter} or {@link EncryptedBytesConverter}.
 * <p>
 * {@link io.github.sillwork.blindcrypt.spring.hibernate.EncryptedBinder} attaches the converter while Hibernate builds its
 * boot model. If a Hibernate version, another converter or a custom type prevents that, the column would be
 * written in plaintext without any error. This check reads the mapping Hibernate actually uses at runtime and
 * stops startup instead.
 * <p>
 * Embedded attributes ({@code EncryptedText}, {@code EncryptedBytes} and application embeddables) are checked
 * recursively. Members that Hibernate does not map (static, {@code transient}, {@code @Transient}) are skipped
 * because nothing is stored for them.
 */
final class EncryptedConverterVerifier {

    private static final int MAX_EMBEDDING_DEPTH = 8;
    private static final String ISSUES_URL = "https://github.com/sillwork/blindcrypt/issues";

    private EncryptedConverterVerifier() { }

    /**
     * Verifies all {@code @Encrypted} members of a managed class and of its embedded attributes.
     *
     * @param javaClass   the entity or embeddable class
     * @param mappingType Hibernate's runtime mapping of that class
     * @throws BlindCryptConfigurationException if a persistent {@code @Encrypted} attribute is not converted by BlindCrypt
     */
    static void verify(Class<?> javaClass, ManagedMappingType mappingType) {
        verifyManagedType(javaClass, mappingType, javaClass.getSimpleName(), 0);
    }

    private static void verifyManagedType(Class<?> javaClass, ManagedMappingType mappingType, String path, int depth) {
        if (depth > MAX_EMBEDDING_DEPTH) {
            throw new BlindCryptConfigurationException(
                    "Embedded attribute " + path + " is nested deeper than " + MAX_EMBEDDING_DEPTH
                            + " levels, so BlindCrypt cannot verify that its @Encrypted attributes are converted; "
                            + "they could be stored in plaintext.",
                    "Flatten the embeddable structure to at most " + MAX_EMBEDDING_DEPTH + " levels, or report it at "
                            + ISSUES_URL + " if the nesting is intended.");
        }
        for (Class<?> current = javaClass; isMappedHierarchyClass(current); current = current.getSuperclass()) {
            verifyFields(current, mappingType, path, depth);
            verifyAccessors(current, mappingType, path);
        }
    }

    private static boolean isMappedHierarchyClass(Class<?> candidate) {
        return candidate != null && candidate != Object.class;
    }

    private static void verifyFields(Class<?> declaringClass, ManagedMappingType mappingType, String path, int depth) {
        for (Field field : declaringClass.getDeclaredFields()) {
            verifyField(field, mappingType, path, depth);
        }
    }

    private static void verifyField(Field field, ManagedMappingType mappingType, String path, int depth) {
        if (Modifier.isStatic(field.getModifiers())) {
            return;
        }
        AttributeMapping attribute = mappingType.findAttributeMapping(field.getName());
        if (attribute == null) {
            return;
        }
        String attributePath = path + "." + field.getName();
        if (field.isAnnotationPresent(Encrypted.class)) {
            requireBlindCryptConverter(attributePath, attribute);
        } else if (attribute instanceof EmbeddableValuedModelPart embedded) {
            verifyManagedType(field.getType(), embedded.getEmbeddableTypeDescriptor(), attributePath, depth + 1);
        }
    }

    private static void verifyAccessors(Class<?> declaringClass, ManagedMappingType mappingType, String path) {
        for (Method method : declaringClass.getDeclaredMethods()) {
            verifyAccessor(method, mappingType, path);
        }
    }

    private static void verifyAccessor(Method method, ManagedMappingType mappingType, String path) {
        String propertyName = propertyNameOfAccessor(method);
        if (propertyName == null || !method.isAnnotationPresent(Encrypted.class)) {
            return;
        }
        AttributeMapping attribute = mappingType.findAttributeMapping(propertyName);
        if (attribute != null) {
            requireBlindCryptConverter(path + "." + propertyName, attribute);
        }
    }

    private static String propertyNameOfAccessor(Method method) {
        String name = method.getName();
        int prefixLength = accessorPrefixLength(name);
        if (prefixLength == 0 || name.length() == prefixLength || method.getParameterCount() != 0) {
            return null;
        }
        return Character.toLowerCase(name.charAt(prefixLength)) + name.substring(prefixLength + 1);
    }

    private static int accessorPrefixLength(String methodName) {
        if (methodName.startsWith("get")) {
            return 3;
        }
        if (methodName.startsWith("is")) {
            return 2;
        }
        return 0;
    }

    private static void requireBlindCryptConverter(String attributePath, AttributeMapping attribute) {
        if (attribute instanceof BasicValuedModelPart basic) {
            BasicValueConverter<?, ?> converter = basic.getJdbcMapping().getValueConverter();
            if (converter instanceof JpaAttributeConverter<?, ?> jpaConverter) {
                Class<?> converterClass = jpaConverter.getConverterJavaType().getJavaTypeClass();
                if (converterClass == EncryptedStringConverter.class || converterClass == EncryptedBytesConverter.class) {
                    return;
                }
            }
        }
        throw new BlindCryptConfigurationException(
                "@Encrypted attribute " + attributePath + " is not mapped through the BlindCrypt converter; "
                        + "it would be stored in plaintext.",
                "Remove any other @Convert, @Type or @JdbcTypeCode on the attribute. If there is none, this Hibernate "
                        + "version (" + hibernateVersion() + ") is not supported by this BlindCrypt release, which is tested "
                        + "with Hibernate 6.5.x; report it at " + ISSUES_URL + ".");
    }

    /**
     * Returns the running Hibernate version for error messages.
     *
     * @return the version string, or {@code unknown} if Hibernate does not report one
     */
    static String hibernateVersion() {
        String version = org.hibernate.Version.getVersionString();
        return version == null ? "unknown" : version;
    }
}
