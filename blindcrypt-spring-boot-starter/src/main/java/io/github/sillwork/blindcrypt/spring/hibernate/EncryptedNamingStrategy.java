package io.github.sillwork.blindcrypt.spring.hibernate;

import io.github.sillwork.blindcrypt.spring.model.EncryptedBytes;
import io.github.sillwork.blindcrypt.spring.model.EncryptedText;
import org.hibernate.boot.model.naming.Identifier;
import org.hibernate.boot.model.naming.ImplicitBasicColumnNameSource;
import org.hibernate.boot.model.source.spi.AttributePath;
import org.springframework.boot.orm.jpa.hibernate.SpringImplicitNamingStrategy;

/**
 * Spring ImplicitNamingStrategy automatically naming embeddable value columns.
 * <p>
 * Eliminates repetitive {@code @AttributeOverride} declarations by dynamically translating:
 * <ul>
 *   <li>{@code user.email.encryptedValue} -> column {@code email}</li>
 *   <li>{@code user.email.blindIndex} -> column {@code email_bidx}</li>
 * </ul>
 */
public class EncryptedNamingStrategy extends SpringImplicitNamingStrategy {

    /** Creates the instance; the auto-configuration registers it as the Hibernate implicit naming strategy. */
    public EncryptedNamingStrategy() {
        // Instantiated by BlindCryptAutoConfiguration, which exposes it as the implicit naming strategy; it holds no state.
    }

    /**
     * Determines the physical column name for an entity attribute, translating embeddable property paths
     * into clean column names without requiring manual {@code @AttributeOverride} declarations.
     *
     * @param source the column name source metadata provided by Hibernate
     * @return the calculated column {@link Identifier}
     */
    @Override
    public Identifier determineBasicColumnName(ImplicitBasicColumnNameSource source) {
        AttributePath path = source.getAttributePath();
        AttributePath owner = path.getParent();

        if (owner != null && !source.isCollectionElement()) {
            String property = path.getProperty();
            String baseName = owner.getFullPath().replace('.', '_');

            if (EncryptedText.VALUE_ATTRIBUTE.equals(property) ||
                EncryptedBytes.VALUE_ATTRIBUTE.equals(property)) {
                return toIdentifier(baseName, source.getBuildingContext());
            }
            if (EncryptedText.INDEX_ATTRIBUTE.equals(property) ||
                EncryptedBytes.INDEX_ATTRIBUTE.equals(property)) {
                return toIdentifier(baseName + "_bidx", source.getBuildingContext());
            }
        }
        return super.determineBasicColumnName(source);
    }
}
