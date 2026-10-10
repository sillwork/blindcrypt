package io.github.sillwork.blindcrypt.spring.listener;

import io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException;
import io.github.sillwork.blindcrypt.spring.annotation.BlindIndex;
import io.github.sillwork.blindcrypt.spring.annotation.Encrypted;
import io.github.sillwork.blindcrypt.spring.converter.EncryptedStringConverter;
import io.github.sillwork.blindcrypt.spring.model.EncryptedText;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.metamodel.EntityType;
import jakarta.persistence.metamodel.Metamodel;
import java.util.Set;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.metamodel.mapping.AttributeMapping;
import org.hibernate.metamodel.mapping.BasicValuedModelPart;
import org.hibernate.metamodel.mapping.JdbcMapping;
import org.hibernate.metamodel.spi.MappingMetamodelImplementor;
import org.hibernate.persister.entity.EntityPersister;
import org.hibernate.type.descriptor.converter.spi.JpaAttributeConverter;
import org.hibernate.type.descriptor.java.JavaType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

/**
 * Unit tests for the startup guard's handling of Hibernate runtime problems. Each of them must stop startup rather
 * than let an {@code @Encrypted} attribute through unverified.
 */
class BlindIndexStartupValidatorTest {

    static class PlainEntity {
        String name;
    }

    static class FieldEncryptedEntity {
        @Encrypted
        private String secret;
    }

    static class AccessorEncryptedEntity {
        private String secret;

        @Encrypted
        public String getSecret() {
            return secret;
        }
    }

    static class EmbeddableTypedEntity {
        private EncryptedText note;

        EncryptedText getNote() {
            return note;
        }
    }

    @EntityListeners(BlindIndexListener.class)
    static class ElementCollectionEntity {
        @BlindIndex(name = "tags")
        private EncryptedText indexed;

        @ElementCollection
        private EncryptedText tags;
    }

    private EntityManager entityManager;
    private EntityManagerFactory entityManagerFactory;
    private SessionFactoryImplementor sessionFactory;
    private MappingMetamodelImplementor mappingMetamodel;
    private Metamodel metamodel;

    @BeforeEach
    void setUp() {
        entityManager = mock(EntityManager.class);
        entityManagerFactory = mock(EntityManagerFactory.class);
        mappingMetamodel = mock(MappingMetamodelImplementor.class);
        // Mockito cannot generate a mock of this very large Hibernate interface, so a proxy answers the one call used.
        sessionFactory = (SessionFactoryImplementor) java.lang.reflect.Proxy.newProxyInstance(
                SessionFactoryImplementor.class.getClassLoader(), new Class<?>[] {SessionFactoryImplementor.class},
                (proxy, method, args) -> "getMappingMetamodel".equals(method.getName()) ? mappingMetamodel : null);
        metamodel = mock(Metamodel.class);
        when(entityManager.getMetamodel()).thenReturn(metamodel);
        when(entityManager.getEntityManagerFactory()).thenReturn(entityManagerFactory);
        when(entityManagerFactory.unwrap(SessionFactoryImplementor.class)).thenReturn(sessionFactory);
    }

    private void managing(Class<?>... javaTypes) {
        Set<EntityType<?>> entities = new java.util.LinkedHashSet<>();
        for (Class<?> javaType : javaTypes) {
            EntityType<?> entityType = mock(EntityType.class);
            doReturn(javaType).when(entityType).getJavaType();
            entities.add(entityType);
        }
        when(metamodel.getEntities()).thenReturn(entities);
    }

    private BlindIndexStartupValidator validator() {
        return new BlindIndexStartupValidator(entityManager);
    }

    private static EntityPersister persisterWithSecretConverter(Class<?> converterClass) {
        EntityPersister persister = mock(EntityPersister.class);
        AttributeMapping secret = mock(AttributeMapping.class, withSettings().extraInterfaces(BasicValuedModelPart.class));
        JdbcMapping jdbcMapping = mock(JdbcMapping.class);
        when(((BasicValuedModelPart) secret).getJdbcMapping()).thenReturn(jdbcMapping);
        if (converterClass != null) {
            JpaAttributeConverter<?, ?> converter = mock(JpaAttributeConverter.class);
            JavaType<?> converterType = mock(JavaType.class);
            doReturn(converterClass).when(converterType).getJavaTypeClass();
            doReturn(converterType).when(converter).getConverterJavaType();
            doReturn(converter).when(jdbcMapping).getValueConverter();
        }
        when(persister.findAttributeMapping("secret")).thenReturn(secret);
        return persister;
    }

    @Test
    void entityWithoutEncryptedMembersNeverTouchesTheHibernateMappingModel() {
        managing(PlainEntity.class);

        assertThatCode(validator()::afterSingletonsInstantiated).doesNotThrowAnyException();
        verify(entityManagerFactory, never()).unwrap(any());
    }

    @Test
    void entityWithNoJavaTypeIsSkipped() {
        EntityType<?> typeless = mock(EntityType.class);
        when(metamodel.getEntities()).thenReturn(Set.<EntityType<?>>of(typeless));

        assertThatCode(validator()::afterSingletonsInstantiated).doesNotThrowAnyException();
    }

    @Test
    void encryptedFieldMappedThroughBlindCryptConverterPasses() {
        managing(FieldEncryptedEntity.class);
        EntityPersister persister = persisterWithSecretConverter(EncryptedStringConverter.class);
        when(mappingMetamodel.findEntityDescriptor(FieldEncryptedEntity.class)).thenReturn(persister);

        assertThatCode(validator()::afterSingletonsInstantiated).doesNotThrowAnyException();
    }

    @Test
    void encryptedFieldWithoutBlindCryptConverterStopsStartup() {
        managing(FieldEncryptedEntity.class);
        EntityPersister persister = persisterWithSecretConverter(null);
        when(mappingMetamodel.findEntityDescriptor(FieldEncryptedEntity.class)).thenReturn(persister);

        assertThatThrownBy(validator()::afterSingletonsInstantiated)
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("FieldEncryptedEntity.secret")
                .hasMessageContaining("stored in plaintext");
    }

    @Test
    void encryptedAccessorIsVerifiedToo() {
        managing(AccessorEncryptedEntity.class);
        EntityPersister persister = persisterWithSecretConverter(null);
        when(mappingMetamodel.findEntityDescriptor(AccessorEncryptedEntity.class)).thenReturn(persister);

        assertThatThrownBy(validator()::afterSingletonsInstantiated)
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("AccessorEncryptedEntity.secret");
    }

    @Test
    void encryptedEmbeddableTypedFieldTriggersVerification() {
        managing(EmbeddableTypedEntity.class);
        when(mappingMetamodel.findEntityDescriptor(EmbeddableTypedEntity.class)).thenReturn(null);

        assertThatThrownBy(validator()::afterSingletonsInstantiated)
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("Hibernate has no entity mapping for " + EmbeddableTypedEntity.class.getName());
    }

    @Test
    void missingEntityDescriptorStopsStartup() {
        managing(FieldEncryptedEntity.class);
        when(mappingMetamodel.findEntityDescriptor(FieldEncryptedEntity.class)).thenReturn(null);

        assertThatThrownBy(validator()::afterSingletonsInstantiated)
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("Hibernate has no entity mapping for " + FieldEncryptedEntity.class.getName())
                .hasMessageContaining("cannot verify");
    }

    @Test
    void unavailableMappingModelStopsStartupWithTheCauseAttached() {
        managing(FieldEncryptedEntity.class);
        IllegalStateException cause = new IllegalStateException("not hibernate");
        when(entityManagerFactory.unwrap(SessionFactoryImplementor.class)).thenThrow(cause);

        assertThatThrownBy(validator()::afterSingletonsInstantiated)
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("cannot read the Hibernate mapping model")
                .hasCause(cause)
                .satisfies(e -> assertThat(((BlindCryptConfigurationException) e).getAction()).contains("Hibernate ORM"));
    }

    @Test
    void incompatibleHibernateClassesAtMappingModelLookupStopStartup() {
        managing(FieldEncryptedEntity.class);
        NoClassDefFoundError linkage = new NoClassDefFoundError("org/hibernate/Missing");
        when(entityManagerFactory.unwrap(SessionFactoryImplementor.class)).thenThrow(linkage);

        assertThatThrownBy(validator()::afterSingletonsInstantiated)
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("cannot read the Hibernate mapping model")
                .hasCause(linkage);
    }

    @Test
    void incompatibleHibernateClassesDuringVerificationStopStartupAndNameTheEntity() {
        managing(FieldEncryptedEntity.class);
        NoSuchMethodError linkage = new NoSuchMethodError("findAttributeMapping");
        when(mappingMetamodel.findEntityDescriptor(FieldEncryptedEntity.class)).thenThrow(linkage);

        assertThatThrownBy(validator()::afterSingletonsInstantiated)
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining(FieldEncryptedEntity.class.getName())
                .hasMessageContaining("on Hibernate")
                .hasCause(linkage);
    }

    @Test
    void mappingModelIsResolvedOnceForSeveralEntities() {
        managing(FieldEncryptedEntity.class, AccessorEncryptedEntity.class);
        EntityPersister first = persisterWithSecretConverter(EncryptedStringConverter.class);
        EntityPersister second = persisterWithSecretConverter(EncryptedStringConverter.class);
        when(mappingMetamodel.findEntityDescriptor(FieldEncryptedEntity.class)).thenReturn(first);
        when(mappingMetamodel.findEntityDescriptor(AccessorEncryptedEntity.class)).thenReturn(second);

        assertThatCode(validator()::afterSingletonsInstantiated).doesNotThrowAnyException();
        verify(entityManagerFactory).unwrap(SessionFactoryImplementor.class);
    }

    @Test
    void encryptedEmbeddableInsideElementCollectionIsRejected() {
        managing(ElementCollectionEntity.class);

        assertThatThrownBy(validator()::afterSingletonsInstantiated)
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("ElementCollectionEntity.tags")
                .hasMessageContaining("@ElementCollection");
    }

    @Test
    void constructorRejectsNullEntityManager() {
        assertThatThrownBy(() -> new BlindIndexStartupValidator(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("entityManager");
    }
}
