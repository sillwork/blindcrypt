package io.github.sillwork.blindcrypt.spring.listener;

import io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException;
import io.github.sillwork.blindcrypt.spring.annotation.Encrypted;
import io.github.sillwork.blindcrypt.spring.converter.EncryptedBytesConverter;
import io.github.sillwork.blindcrypt.spring.converter.EncryptedStringConverter;
import jakarta.persistence.AttributeConverter;
import org.hibernate.metamodel.mapping.AttributeMapping;
import org.hibernate.metamodel.mapping.BasicValuedModelPart;
import org.hibernate.metamodel.mapping.EmbeddableMappingType;
import org.hibernate.metamodel.mapping.EmbeddableValuedModelPart;
import org.hibernate.metamodel.mapping.JdbcMapping;
import org.hibernate.metamodel.mapping.ManagedMappingType;
import org.hibernate.type.descriptor.converter.spi.JpaAttributeConverter;
import org.hibernate.type.descriptor.java.JavaType;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

class EncryptedConverterVerifierTest {

    static class SecretHolder {
        @Encrypted
        private String secret;

        // Package-private fixture field: Hibernate maps it, but it is not @Encrypted and so must not be checked.
        String plain;

        @Encrypted
        private transient String notPersisted;
    }

    static class OtherConverter implements AttributeConverter<String, String> {
        @Override
        public String convertToDatabaseColumn(String attribute) { return attribute; }

        @Override
        public String convertToEntityAttribute(String dbData) { return dbData; }
    }

    private static AttributeMapping basicMapping(Class<?> converterClass) {
        AttributeMapping attribute = mock(AttributeMapping.class, withSettings().extraInterfaces(BasicValuedModelPart.class));
        JdbcMapping jdbcMapping = mock(JdbcMapping.class);
        when(((BasicValuedModelPart) attribute).getJdbcMapping()).thenReturn(jdbcMapping);
        if (converterClass != null) {
            JpaAttributeConverter<?, ?> converter = mock(JpaAttributeConverter.class);
            JavaType<?> converterType = mock(JavaType.class);
            doReturn(converterClass).when(converterType).getJavaTypeClass();
            doReturn(converterType).when(converter).getConverterJavaType();
            doReturn(converter).when(jdbcMapping).getValueConverter();
        }
        return attribute;
    }

    private static ManagedMappingType mappingWithSecret(AttributeMapping secretMapping) {
        ManagedMappingType mappingType = mock(ManagedMappingType.class);
        when(mappingType.findAttributeMapping("secret")).thenReturn(secretMapping);
        AttributeMapping plainMapping = basicMapping(null);
        when(mappingType.findAttributeMapping("plain")).thenReturn(plainMapping);
        // notPersisted is transient: Hibernate has no attribute mapping for it
        return mappingType;
    }

    @Test
    void attributeWithoutAnyConverterIsRejected() {
        ManagedMappingType mappingType = mappingWithSecret(basicMapping(null));
        assertThatThrownBy(() -> EncryptedConverterVerifier.verify(SecretHolder.class, mappingType))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("SecretHolder.secret")
                .hasMessageContaining("stored in plaintext")
                .satisfies(e -> org.assertj.core.api.Assertions.assertThat(
                        ((BlindCryptConfigurationException) e).getAction()).contains("Hibernate"));
    }

    @Test
    void attributeWithAnotherConverterIsRejected() {
        ManagedMappingType mappingType = mappingWithSecret(basicMapping(OtherConverter.class));
        assertThatThrownBy(() -> EncryptedConverterVerifier.verify(SecretHolder.class, mappingType))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("SecretHolder.secret");
    }

    @Test
    void nonBasicMappingIsRejected() {
        ManagedMappingType mappingType = mappingWithSecret(mock(AttributeMapping.class));
        assertThatThrownBy(() -> EncryptedConverterVerifier.verify(SecretHolder.class, mappingType))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("SecretHolder.secret");
    }

    @Test
    void attributeMappedThroughBlindCryptConverterIsAccepted() {
        assertThatCode(() -> EncryptedConverterVerifier.verify(SecretHolder.class,
                mappingWithSecret(basicMapping(EncryptedStringConverter.class)))).doesNotThrowAnyException();
        assertThatCode(() -> EncryptedConverterVerifier.verify(SecretHolder.class,
                mappingWithSecret(basicMapping(EncryptedBytesConverter.class)))).doesNotThrowAnyException();
    }

    static class Node {
        // Package-private fixture field: the verifier walks it by reflection to follow the embedding.
        Node next;
    }

    @Test
    void embeddingNestedBeyondTheVerificationDepthIsRejected() {
        ManagedMappingType root = mock(ManagedMappingType.class);
        EmbeddableMappingType nested = mock(EmbeddableMappingType.class);
        AttributeMapping nextMapping = mock(AttributeMapping.class, withSettings().extraInterfaces(EmbeddableValuedModelPart.class));
        when(((EmbeddableValuedModelPart) nextMapping).getEmbeddableTypeDescriptor()).thenReturn(nested);
        when(root.findAttributeMapping("next")).thenReturn(nextMapping);
        when(nested.findAttributeMapping("next")).thenReturn(nextMapping);

        assertThatThrownBy(() -> EncryptedConverterVerifier.verify(Node.class, root))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("Node.next")
                .hasMessageContaining("nested deeper than");
    }

    @Test
    void unannotatedMappedAttributeWithoutConverterIsNotRejected() {
        // "plain" has a basic mapping with no converter at all; only @Encrypted attributes are verified.
        ManagedMappingType mappingType = mappingWithSecret(basicMapping(EncryptedStringConverter.class));
        assertThatCode(() -> EncryptedConverterVerifier.verify(SecretHolder.class, mappingType)).doesNotThrowAnyException();
        verify(mappingType).findAttributeMapping("plain");
    }

    @Test
    void encryptedAttributeIsRejectedEvenWhenUnannotatedSiblingIsConverted() {
        ManagedMappingType mappingType = mappingWithSecret(basicMapping(null));
        AttributeMapping convertedSibling = basicMapping(EncryptedStringConverter.class);
        when(mappingType.findAttributeMapping("plain")).thenReturn(convertedSibling);
        assertThatThrownBy(() -> EncryptedConverterVerifier.verify(SecretHolder.class, mappingType))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("SecretHolder.secret");
    }
}
