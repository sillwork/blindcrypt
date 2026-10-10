package io.github.sillwork.blindcrypt.spring.hibernate;

import io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException;
import io.github.sillwork.blindcrypt.spring.annotation.Encrypted;
import io.github.sillwork.blindcrypt.spring.converter.EncryptedBytesConverter;
import io.github.sillwork.blindcrypt.spring.converter.EncryptedStringConverter;
import jakarta.persistence.AttributeConverter;
import org.hibernate.boot.internal.ClassmateContext;
import org.hibernate.boot.model.convert.spi.ConverterDescriptor;
import org.hibernate.boot.spi.BootstrapContext;
import org.hibernate.boot.spi.MetadataBuildingContext;
import org.hibernate.mapping.BasicValue;
import org.hibernate.mapping.PersistentClass;
import org.hibernate.mapping.Property;
import org.hibernate.mapping.SimpleValue;
import org.hibernate.type.Type;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The binder is the only thing that attaches the BlindCrypt converter to an {@code @Encrypted} attribute, so every
 * way it can refuse or mis-bind must be explicit.
 */
class EncryptedBinderTest {

    static class OtherConverter implements AttributeConverter<String, String> {
        @Override
        public String convertToDatabaseColumn(String attribute) {
            return attribute;
        }

        @Override
        public String convertToEntityAttribute(String dbData) {
            return dbData;
        }
    }

    static class Holder {
        @Encrypted
        String secret;
    }

    private final EncryptedBinder binder = new EncryptedBinder();
    private Encrypted annotation;
    private MetadataBuildingContext buildingContext;
    private PersistentClass persistentClass;
    private Property property;
    private BasicValue basicValue;
    private Type type;

    @BeforeEach
    void setUp() throws NoSuchFieldException {
        annotation = Holder.class.getDeclaredField("secret").getAnnotation(Encrypted.class);
        buildingContext = mock(MetadataBuildingContext.class);
        BootstrapContext bootstrapContext = mock(BootstrapContext.class);
        when(buildingContext.getBootstrapContext()).thenReturn(bootstrapContext);
        when(bootstrapContext.getClassmateContext()).thenReturn(new ClassmateContext());
        persistentClass = mock(PersistentClass.class);
        when(persistentClass.getClassName()).thenReturn("com.acme.Customer");
        property = mock(Property.class);
        when(property.getName()).thenReturn("secret");
        basicValue = mock(BasicValue.class);
        when(property.getValue()).thenReturn(basicValue);
        type = mock(Type.class);
        when(property.getType()).thenReturn(type);
    }

    private ConverterDescriptor boundDescriptor() {
        ArgumentCaptor<ConverterDescriptor> captor = ArgumentCaptor.forClass(ConverterDescriptor.class);
        verify(basicValue).setJpaAttributeConverterDescriptor(captor.capture());
        return captor.getValue();
    }

    private void returnedClassIs(Class<?> returnedClass) {
        doReturn(returnedClass).when(type).getReturnedClass();
    }

    private void existingConverterIs(Class<?> converterClass) {
        ConverterDescriptor existing = mock(ConverterDescriptor.class);
        doReturn(converterClass).when(existing).getAttributeConverterClass();
        when(basicValue.getJpaAttributeConverterDescriptor()).thenReturn(existing);
    }

    @Test
    void stringAttributeGetsTheStringConverter() {
        returnedClassIs(String.class);

        binder.bind(annotation, buildingContext, persistentClass, property);

        assertThat(boundDescriptor().getAttributeConverterClass()).isEqualTo(EncryptedStringConverter.class);
    }

    @Test
    void byteArrayAttributeGetsTheBytesConverter() {
        returnedClassIs(byte[].class);

        binder.bind(annotation, buildingContext, persistentClass, property);

        assertThat(boundDescriptor().getAttributeConverterClass()).isEqualTo(EncryptedBytesConverter.class);
    }

    @Test
    void attributeWithUnknownReturnedClassFallsBackToTheStringConverter() {
        returnedClassIs(null);

        binder.bind(annotation, buildingContext, persistentClass, property);

        assertThat(boundDescriptor().getAttributeConverterClass()).isEqualTo(EncryptedStringConverter.class);
    }

    @Test
    void bindingAgainWithTheStringConverterAlreadyPresentChangesNothing() {
        existingConverterIs(EncryptedStringConverter.class);

        binder.bind(annotation, buildingContext, persistentClass, property);

        verify(basicValue, never()).setJpaAttributeConverterDescriptor(any());
    }

    @Test
    void bindingAgainWithTheBytesConverterAlreadyPresentChangesNothing() {
        existingConverterIs(EncryptedBytesConverter.class);

        binder.bind(annotation, buildingContext, persistentClass, property);

        verify(basicValue, never()).setJpaAttributeConverterDescriptor(any());
    }

    @Test
    void anotherConverterOnTheSameAttributeStopsStartupNamingBothSides() {
        existingConverterIs(OtherConverter.class);

        assertThatThrownBy(() -> binder.bind(annotation, buildingContext, persistentClass, property))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("com.acme.Customer.secret")
                .hasMessageContaining("@Encrypted")
                .hasMessageContaining(OtherConverter.class.getName());
        verify(basicValue, never()).setJpaAttributeConverterDescriptor(any());
    }

    @Test
    void nonBasicAttributeStopsStartup() {
        SimpleValue nonBasicValue = mock(SimpleValue.class);
        when(property.getValue()).thenReturn(nonBasicValue);

        assertThatThrownBy(() -> binder.bind(annotation, buildingContext, persistentClass, property))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("com.acme.Customer.secret is not a basic attribute");
    }

    @Test
    void attributeOfAnEmbeddableIsReportedWithoutAPersistentClass() {
        SimpleValue nonBasicValue = mock(SimpleValue.class);
        when(property.getValue()).thenReturn(nonBasicValue);

        assertThatThrownBy(() -> binder.bind(annotation, buildingContext, null, property))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("embeddable.secret is not a basic attribute");
    }
}
