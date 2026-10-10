package io.github.sillwork.blindcrypt.spring.config;

import io.github.sillwork.blindcrypt.core.FieldEncryptor;
import io.github.sillwork.blindcrypt.core.KeyRing;
import io.github.sillwork.blindcrypt.core.StripedCipherPool;
import io.github.sillwork.blindcrypt.core.UltraBlindIndexer;
import io.github.sillwork.blindcrypt.spring.converter.EncryptedBytesConverter;
import io.github.sillwork.blindcrypt.spring.converter.EncryptedStringConverter;
import io.github.sillwork.blindcrypt.spring.listener.BlindIndexListener;
import io.github.sillwork.blindcrypt.spring.listener.BlindIndexRegistry;
import io.github.sillwork.blindcrypt.spring.listener.BlindIndexStartupValidator;
import io.github.sillwork.blindcrypt.spring.migration.VectorizedReEncryptionService;
import io.github.sillwork.blindcrypt.spring.repository.BlindIndexRepositoryConfigurer;
import io.github.sillwork.blindcrypt.spring.repository.BlindIndexRepositoryFactoryBeanPostProcessor;
import io.github.sillwork.blindcrypt.spring.hibernate.EncryptedNamingStrategy;
import org.hibernate.boot.model.naming.ImplicitNamingStrategy;
import jakarta.persistence.EntityManager;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.data.jpa.JpaRepositoriesAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.JdbcTemplateAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Spring Boot auto-configuration orchestrator for BlindCrypt.
 * <p>
 * Active when JPA is on the classpath and {@code blindcrypt.enabled} is not {@code false}. Fails startup with a
 * {@link io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException} when keys are missing or invalid.
 * Initializes cryptographic infrastructure prior to Spring Data JPA repository bootstrapping:
 * <ol>
 *   <li>{@link #encryptedNamingStrategy()}: Maps embeddable column names (e.g. {@code email} and {@code email_bidx}).</li>
 *   <li>{@link #cipherPool()}: Allocates the striped AES-GCM cipher pool.</li>
 *   <li>{@link #keyRing(CryptoProperties)}: Constructs the multi-version cryptographic key repository.</li>
 *   <li>{@link #fieldEncryptor(KeyRing, StripedCipherPool, CryptoProperties)}: Configures transparent column encryption.</li>
 *   <li>{@link #ultraBlindIndexer(KeyRing)}: Initializes HMAC blind indexing.</li>
 *   <li>{@link #blindIndexRegistry(UltraBlindIndexer)}: Caches entity metadata and calculates indexes at flush time.</li>
 *   <li>{@link #blindIndexStartupValidator(EntityManager)}: Fail-fast metamodel bootstrap validator.</li>
 *   <li>{@link #blindIndexRepositoryConfigurer(BlindIndexRegistry, UltraBlindIndexer, ListableBeanFactory)}: Rewrites repository derived queries.</li>
 *   <li>{@link #vectorizedReEncryptionService(JdbcTemplate)}: batch re-encryption service.</li>
 * </ol>
 *
 * @see CryptoProperties
 * @see io.github.sillwork.blindcrypt.core.KeyRing
 * @see io.github.sillwork.blindcrypt.core.FieldEncryptor
 * @see io.github.sillwork.blindcrypt.core.UltraBlindIndexer
 */
@AutoConfiguration(
        before = JpaRepositoriesAutoConfiguration.class,
        after = {DataSourceAutoConfiguration.class, JdbcTemplateAutoConfiguration.class}
)
@ConditionalOnClass({EntityManager.class})
@ConditionalOnProperty(prefix = "blindcrypt", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(CryptoProperties.class)
public class BlindCryptAutoConfiguration {

    /** Creates the instance; Spring Boot instantiates it from the auto-configuration imports, not application code. */
    public BlindCryptAutoConfiguration() {
        // Instantiated by Spring Boot's auto-configuration mechanism; nothing to initialise.
    }

    /**
     * Registers the Hibernate {@link ImplicitNamingStrategy} that translates embeddable property paths
     * into standard database column names without requiring manual {@code @AttributeOverride} annotations.
     *
     * @return the configured {@link EncryptedNamingStrategy}
     */
    @Bean
    @ConditionalOnMissingBean
    public ImplicitNamingStrategy encryptedNamingStrategy() {
        return new EncryptedNamingStrategy();
    }

    /**
     * Registers the striped {@link StripedCipherPool} used for AES/GCM ciphers.
     *
     * @return the configured {@link StripedCipherPool} for {@code "AES/GCM/NoPadding"}
     */
    @Bean
    @ConditionalOnMissingBean
    public StripedCipherPool cipherPool() {
        return new StripedCipherPool("AES/GCM/NoPadding");
    }

    /**
     * Constructs and validates the multi-version {@link KeyRing} from application properties.
     *
     * @param props the loaded {@link CryptoProperties}
     * @return the initialized {@link KeyRing}
     */
    @Bean
    @ConditionalOnMissingBean
    public KeyRing keyRing(CryptoProperties props) {
        return KeyRing.fromBase64(props.getKeys(), props.getActiveKeyVersion(), props.getBlindIndexKey());
    }

    /**
     * Registers the primary {@link FieldEncryptor} bean for AES-256-GCM authenticated encryption
     * and initializes static converter references.
     *
     * @param keyRing the active {@link KeyRing}
     * @param pool    the cipher pool
     * @param props   the crypto configuration properties
     * @return the configured {@link FieldEncryptor}
     */
    @Bean
    @ConditionalOnMissingBean
    public FieldEncryptor fieldEncryptor(KeyRing keyRing, StripedCipherPool pool, CryptoProperties props) {
        FieldEncryptor encryptor = new FieldEncryptor(keyRing, pool);
        EncryptedStringConverter.setEncryptor(encryptor);
        EncryptedStringConverter.setAllowPlaintextRead(props.isAllowPlaintextRead());
        EncryptedBytesConverter.setEncryptor(encryptor);
        EncryptedBytesConverter.setAllowPlaintextRead(props.isAllowPlaintextRead());
        return encryptor;
    }

    /**
     * Registers the {@link UltraBlindIndexer} engine.
     *
     * @param keyRing the active {@link KeyRing}
     * @return the initialized {@link UltraBlindIndexer}
     */
    @Bean
    @ConditionalOnMissingBean
    public UltraBlindIndexer ultraBlindIndexer(KeyRing keyRing) {
        return new UltraBlindIndexer(keyRing);
    }

    /**
     * Registers the entity metadata registry and connects it to {@link BlindIndexListener}.
     *
     * @param indexer the cryptographic blind indexer
     * @return the initialized {@link BlindIndexRegistry}
     */
    @Bean
    @ConditionalOnMissingBean
    public BlindIndexRegistry blindIndexRegistry(UltraBlindIndexer indexer) {
        BlindIndexRegistry registry = new BlindIndexRegistry(indexer);
        BlindIndexListener.setRegistry(registry);
        return registry;
    }

    /**
     * Registers the fail-fast startup validator that inspects entity metamodels after all singletons are created and before the embedded web server starts.
     *
     * @param entityManager the JPA entity manager
     * @return the {@link BlindIndexStartupValidator}
     */
    @Bean
    @ConditionalOnMissingBean
    public BlindIndexStartupValidator blindIndexStartupValidator(EntityManager entityManager) {
        return new BlindIndexStartupValidator(entityManager);
    }

    /**
     * Registers the repository proxy post-processor installing query rewriting interceptors
     * on interfaces marked with {@link io.github.sillwork.blindcrypt.spring.annotation.BlindIndexQueries}.
     *
     * @param registry    the entity blind index registry
     * @param indexer     the cryptographic indexer
     * @param beanFactory the Spring bean factory
     * @return the {@link BlindIndexRepositoryConfigurer}
     */
    @Bean
    @ConditionalOnMissingBean
    public BlindIndexRepositoryConfigurer blindIndexRepositoryConfigurer(
            BlindIndexRegistry registry, UltraBlindIndexer indexer, ListableBeanFactory beanFactory) {
        return new BlindIndexRepositoryConfigurer(registry, indexer, beanFactory);
    }

    /**
     * Registers the {@link BlindIndexRepositoryFactoryBeanPostProcessor} attaching repository customizers.
     *
     * @param configurerProvider lazy provider for the configurer
     * @return the bean post-processor
     */
    @Bean
    @ConditionalOnMissingBean
    public static BlindIndexRepositoryFactoryBeanPostProcessor blindIndexRepositoryFactoryBeanPostProcessor(
            ObjectProvider<BlindIndexRepositoryConfigurer> configurerProvider) {
        return new BlindIndexRepositoryFactoryBeanPostProcessor(configurerProvider);
    }

    /**
     * Registers the vectorized re-encryption service when {@link JdbcTemplate} is present.
     *
     * @param jdbcTemplate the Spring JDBC template
     * @return the {@link VectorizedReEncryptionService}
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(JdbcTemplate.class)
    public VectorizedReEncryptionService vectorizedReEncryptionService(JdbcTemplate jdbcTemplate) {
        return new VectorizedReEncryptionService(jdbcTemplate);
    }
}
