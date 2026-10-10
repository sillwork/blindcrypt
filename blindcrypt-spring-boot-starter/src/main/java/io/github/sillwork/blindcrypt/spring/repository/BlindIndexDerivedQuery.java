package io.github.sillwork.blindcrypt.spring.repository;

import io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException;
import io.github.sillwork.blindcrypt.core.Normalization;
import io.github.sillwork.blindcrypt.core.UltraBlindIndexer;
import io.github.sillwork.blindcrypt.spring.annotation.BlindIndex;
import io.github.sillwork.blindcrypt.spring.listener.BlindIndexRegistry;
import io.github.sillwork.blindcrypt.spring.model.EncryptedBytes;
import io.github.sillwork.blindcrypt.spring.model.EncryptedText;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.Query;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.springframework.data.repository.query.parser.Part;
import org.springframework.data.repository.query.parser.PartTree;

/**
 * Dynamic query rewriting engine for Spring Data JPA repository derived methods.
 * <p>
 * Transparently intercepts repository query methods (e.g., {@code findByEmail(String plaintext)})
 * targeting columns annotated with {@link BlindIndex}. Instead of performing impossible searches
 * against randomized AES-256-GCM ciphertexts, this class:
 * <ul>
 *   <li>Parses method criteria into an AST using Spring Data's {@link PartTree}.</li>
 *   <li>Rewrites JPQL property paths from domain properties to blind index fields
 *       (e.g., {@code e.email} &rarr; {@code e.email.blindIndex}).</li>
 *   <li>Applies designated canonicalization and computes cryptographic HMAC blind index hashes
 *       for all search parameters prior to binding them to the query.</li>
 * </ul>
 */
public class BlindIndexDerivedQuery {

    private static final Set<Part.Type> SUPPORTED_BLIND_INDEX_TYPES =
            EnumSet.of(Part.Type.SIMPLE_PROPERTY, Part.Type.IN, Part.Type.IS_NULL, Part.Type.IS_NOT_NULL);

    /**
     * Predicates on non-blind-indexed properties that the rewriter translates faithfully when they appear in the
     * same method as a blind-index predicate. Must match the cases in {@link #processStandardPart}.
     */
    private static final Set<Part.Type> SUPPORTED_STANDARD_TYPES = EnumSet.of(Part.Type.SIMPLE_PROPERTY,
            Part.Type.NEGATING_SIMPLE_PROPERTY, Part.Type.IN, Part.Type.IS_NULL, Part.Type.IS_NOT_NULL);

    private final Method method;
    private final Class<?> domainClass;
    private final PartTree partTree;
    private final BlindIndexRegistry registry;
    private final UltraBlindIndexer indexer;
    private final boolean hasBlindIndexPredicate;

    /**
     * Constructs a BlindIndexDerivedQuery parser and rewriter for a specific repository method.
     *
     * @param method      the reflected repository query method
     * @param domainClass the managed entity class (e.g. {@code User.class})
     * @param registry    the entity metadata registry containing index configurations
     * @param indexer     the cryptographic blind indexing engine
     * @throws BlindCryptConfigurationException if a blind-indexed property is used with a predicate other than
     *                                          exact match, In, IsNull or IsNotNull; if a method with a blind-index
     *                                          predicate uses IgnoreCase, or a predicate other than exact match, Not,
     *                                          In, IsNull or IsNotNull, on another property; or if the method shape
     *                                          cannot be rewritten (see
     *                                          {@link QueryMethodValidator#validateBlindIndexQuery})
     */
    public BlindIndexDerivedQuery(Method method, Class<?> domainClass, BlindIndexRegistry registry, UltraBlindIndexer indexer) {
        this.method = Objects.requireNonNull(method, "method cannot be null");
        this.domainClass = Objects.requireNonNull(domainClass, "domainClass cannot be null");
        this.registry = Objects.requireNonNull(registry, "registry cannot be null");
        this.indexer = Objects.requireNonNull(indexer, "indexer cannot be null");
        this.partTree = new PartTree(method.getName(), domainClass);
        this.hasBlindIndexPredicate = inspectHasBlindIndex();
        validateSupportedPredicates();
        if (hasBlindIndexPredicate) {
            QueryMethodValidator.validateBlindIndexQuery(method, partTree, domainClass);
        }
    }

    private void validateSupportedPredicates() {
        for (PartTree.OrPart orPart : partTree) {
            for (Part part : orPart) {
                String propertyPath = part.getProperty().toDotPath();
                if (registry.findBlindIndexAnnotation(domainClass, propertyPath).isPresent()) {
                    validateBlindIndexedPredicate(part, propertyPath);
                } else if (hasBlindIndexPredicate) {
                    validateStandardPredicate(part, propertyPath);
                }
            }
        }
    }

    private void validateBlindIndexedPredicate(Part part, String propertyPath) {
        if (!SUPPORTED_BLIND_INDEX_TYPES.contains(part.getType())) {
            throw new BlindCryptConfigurationException(
                    "Repository method " + qualifiedMethodName() + " uses " + part.getType().name()
                            + " on blind-indexed property '" + propertyPath + "'.",
                    "Blind indexes support only exact match, In, IsNull and IsNotNull. "
                            + "Rename the method to findBy" + toMethodNameSegment(propertyPath) + " or remove @BlindIndex from the property.");
        }
    }

    /**
     * A method with a blind-index predicate is executed entirely by this rewriter, so every other predicate in it
     * must be one the rewriter translates. Anything else would silently run as a different query.
     */
    private void validateStandardPredicate(Part part, String propertyPath) {
        if (!SUPPORTED_STANDARD_TYPES.contains(part.getType())) {
            throw new BlindCryptConfigurationException(
                    "Repository method " + qualifiedMethodName() + " combines a blind-index predicate with "
                            + part.getType().name() + " on property '" + propertyPath + "', which @BlindIndexQueries cannot rewrite.",
                    "In a method with a blind-index predicate, other properties support only exact match, Not, In, IsNull "
                            + "and IsNotNull. Split the query, or use an explicit @Query on the blindIndex column.");
        }
        if (part.shouldIgnoreCase() != Part.IgnoreCaseType.NEVER) {
            throw new BlindCryptConfigurationException(
                    "Repository method " + qualifiedMethodName() + " combines a blind-index predicate with IgnoreCase"
                            + " on property '" + propertyPath + "', which @BlindIndexQueries cannot rewrite.",
                    "Remove IgnoreCase or AllIgnoreCase from the method name, or use an explicit @Query with LOWER() on that property.");
        }
    }

    private String qualifiedMethodName() {
        return method.getDeclaringClass().getSimpleName() + "." + method.getName();
    }

    /**
     * Turns a property path such as {@code address.city} into the method-name form {@code AddressCity}.
     */
    private static String toMethodNameSegment(String propertyPath) {
        StringBuilder segment = new StringBuilder();
        for (String name : propertyPath.split("\\.")) {
            segment.append(Character.toUpperCase(name.charAt(0))).append(name.substring(1));
        }
        return segment.toString();
    }

    /**
     * Indicates whether any predicate in the query targets a blind-indexed property.
     *
     * @return {@code true} if query contains blind-indexed predicates, {@code false} otherwise
     */
    public boolean hasBlindIndexPredicate() {
        return hasBlindIndexPredicate;
    }

    private boolean inspectHasBlindIndex() {
        for (PartTree.OrPart orPart : partTree) {
            for (Part part : orPart) {
                String propertyPath = part.getProperty().toDotPath();
                if (registry.findBlindIndexAnnotation(domainClass, propertyPath).isPresent()) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Executes the rewritten JPQL query against the provided JPA {@link EntityManager}.
     *
     * @param entityManager   the active JPA EntityManager
     * @param methodArguments the runtime parameters passed to the repository method
     * @return the query result (e.g. entity, list, optional, count, or boolean)
     */
    public Object execute(EntityManager entityManager, Object[] methodArguments) {
        String alias = "e";
        StringBuilder jpqlQuery = new StringBuilder(buildSelectClause(alias));

        QueryBuildingContext ctx = new QueryBuildingContext(methodArguments);
        buildWhereClause(alias, ctx);

        if (!ctx.whereClause.isEmpty()) {
            jpqlQuery.append(" WHERE ").append(ctx.whereClause);
        }

        appendOrderByClause(jpqlQuery, alias);

        Query query = entityManager.createQuery(jpqlQuery.toString());
        ctx.queryParams.forEach(query::setParameter);

        return executeQueryResult(query);
    }

    private String buildSelectClause(String alias) {
        String entityName = resolveEntityName(domainClass);
        if (partTree.isCountProjection() || partTree.isExistsProjection()) {
            return "SELECT COUNT(" + alias + ") FROM " + entityName + " " + alias;
        }
        return "SELECT " + alias + " FROM " + entityName + " " + alias;
    }

    private static String resolveEntityName(Class<?> entityClass) {
        Entity entityAnnotation = entityClass.getAnnotation(Entity.class);
        if (entityAnnotation != null && !entityAnnotation.name().isBlank()) {
            return entityAnnotation.name();
        }
        return entityClass.getSimpleName();
    }

    private void buildWhereClause(String alias, QueryBuildingContext ctx) {
        boolean firstOr = true;
        for (PartTree.OrPart orPart : partTree) {
            if (!firstOr) {
                ctx.whereClause.append(" OR ");
            } else {
                firstOr = false;
            }
            ctx.whereClause.append("(");
            buildAndClause(alias, orPart, ctx);
            ctx.whereClause.append(")");
        }
    }

    private void buildAndClause(String alias, PartTree.OrPart orPart, QueryBuildingContext ctx) {
        boolean firstAnd = true;
        for (Part part : orPart) {
            if (!firstAnd) {
                ctx.whereClause.append(" AND ");
            } else {
                firstAnd = false;
            }
            processPart(alias, part, ctx);
        }
    }

    private void processPart(String alias, Part part, QueryBuildingContext ctx) {
        String propertyName = part.getProperty().toDotPath();
        Optional<BlindIndex> optionalBlindIndex = registry.findBlindIndexAnnotation(domainClass, propertyName);

        if (optionalBlindIndex.isPresent()) {
            processBlindIndexedPart(alias, part, propertyName, optionalBlindIndex.get(), ctx);
        } else {
            processStandardPart(alias, part, propertyName, ctx);
        }
    }

    private void processBlindIndexedPart(String alias, Part part, String propertyName, BlindIndex blindIndex, QueryBuildingContext ctx) {
        String paramName = "param_" + ctx.paramIndex;
        Object rawArg = ctx.nextArgument();
        boolean isBinary = isBinaryField(propertyName);

        switch (part.getType()) {
            case SIMPLE_PROPERTY -> {
                ctx.whereClause.append(alias).append(".").append(propertyName).append(".blindIndex = :").append(paramName);
                ctx.queryParams.put(paramName, computeHash(blindIndex, rawArg, isBinary));
                ctx.paramIndex++;
            }
            case IN -> {
                ctx.whereClause.append(alias).append(".").append(propertyName).append(".blindIndex IN :").append(paramName);
                ctx.queryParams.put(paramName, computeHashedCollection(blindIndex, rawArg, isBinary));
                ctx.paramIndex++;
            }
            case IS_NULL -> ctx.whereClause.append(alias).append(".").append(propertyName).append(".blindIndex IS NULL");
            case IS_NOT_NULL -> ctx.whereClause.append(alias).append(".").append(propertyName).append(".blindIndex IS NOT NULL");
            default -> throw new IllegalStateException("Unreachable: predicate validated at startup");
        }
    }

    private List<Object> computeHashedCollection(BlindIndex blindIndex, Object rawArg, boolean isBinary) {
        List<Object> hashedList = new ArrayList<>();
        if (rawArg instanceof Collection<?> inCollection) {
            for (Object item : inCollection) {
                hashedList.add(computeHash(blindIndex, item, isBinary));
            }
        }
        return hashedList;
    }

    private void processStandardPart(String alias, Part part, String propertyName, QueryBuildingContext ctx) {
        String paramName = "param_" + ctx.paramIndex;
        Object rawArg = ctx.nextArgument();

        switch (part.getType()) {
            case SIMPLE_PROPERTY -> {
                ctx.whereClause.append(alias).append(".").append(propertyName).append(" = :").append(paramName);
                ctx.queryParams.put(paramName, rawArg);
                ctx.paramIndex++;
            }
            case NEGATING_SIMPLE_PROPERTY -> {
                ctx.whereClause.append(alias).append(".").append(propertyName).append(" != :").append(paramName);
                ctx.queryParams.put(paramName, rawArg);
                ctx.paramIndex++;
            }
            case IN -> {
                ctx.whereClause.append(alias).append(".").append(propertyName).append(" IN :").append(paramName);
                ctx.queryParams.put(paramName, rawArg);
                ctx.paramIndex++;
            }
            case IS_NULL -> ctx.whereClause.append(alias).append(".").append(propertyName).append(" IS NULL");
            case IS_NOT_NULL -> ctx.whereClause.append(alias).append(".").append(propertyName).append(" IS NOT NULL");
            default -> throw new IllegalStateException("Unreachable: predicate validated at startup");
        }
    }

    private void appendOrderByClause(StringBuilder jpqlQuery, String alias) {
        if (partTree.getSort().isSorted()) {
            StringBuilder orderClause = new StringBuilder(" ORDER BY ");
            partTree.getSort().forEach(order ->
                orderClause.append(alias).append(".").append(order.getProperty())
                        .append(" ").append(order.getDirection()).append(", ")
            );
            orderClause.setLength(orderClause.length() - 2);
            jpqlQuery.append(orderClause);
        }
    }

    private Object executeQueryResult(Query query) {
        if (partTree.isCountProjection()) {
            return query.getSingleResult();
        }
        if (partTree.isExistsProjection()) {
            Number count = (Number) query.getSingleResult();
            return count != null && count.longValue() > 0;
        }

        Class<?> returnType = method.getReturnType();
        if (Optional.class.isAssignableFrom(returnType)) {
            try {
                return Optional.ofNullable(query.getSingleResult());
            } catch (NoResultException e) {
                return Optional.empty();
            }
        }
        if (List.class.isAssignableFrom(returnType) || Collection.class.isAssignableFrom(returnType)) {
            return query.getResultList();
        }
        try {
            return query.getSingleResult();
        } catch (NoResultException e) {
            return null;
        }
    }

    private static final class QueryBuildingContext {
        final StringBuilder whereClause = new StringBuilder();
        final Map<String, Object> queryParams = new LinkedHashMap<>();
        final Object[] methodArguments;
        int paramIndex = 0;

        QueryBuildingContext(Object[] methodArguments) {
            this.methodArguments = methodArguments;
        }

        Object nextArgument() {
            return (methodArguments != null && paramIndex < methodArguments.length) ? methodArguments[paramIndex] : null;
        }
    }

    private Object computeHash(BlindIndex blindIndex, Object rawValue, boolean isBinary) {
        if (rawValue == null) {
            return null;
        }
        if (rawValue instanceof EncryptedText encText) {
            String text = encText.value();
            return text == null ? null : indexer.computeHex(blindIndex.name(), text, blindIndex.normalization(), null);
        }
        if (rawValue instanceof EncryptedBytes encBytes) {
            byte[] bytes = encBytes.value();
            return bytes == null ? null : computeHashFromBytes(blindIndex, bytes, isBinary);
        }
        if (rawValue instanceof byte[] rawBytes) {
            return computeHashFromBytes(blindIndex, rawBytes, isBinary);
        }
        return computeHashFromString(blindIndex, rawValue.toString(), isBinary);
    }

    private Object computeHashFromBytes(BlindIndex blindIndex, byte[] bytes, boolean isBinary) {
        if (isBinary && blindIndex.normalization() == Normalization.NONE) {
            return indexer.computeBinary(blindIndex.name(), bytes, null);
        }
        String rawString = new String(bytes, StandardCharsets.UTF_8);
        return computeHashFromString(blindIndex, rawString, isBinary);
    }

    private Object computeHashFromString(BlindIndex blindIndex, String rawString, boolean isBinary) {
        if (isBinary) {
            return indexer.computeBinary(blindIndex.name(), rawString, blindIndex.normalization(), null);
        }
        return indexer.computeHex(blindIndex.name(), rawString, blindIndex.normalization(), null);
    }

    private boolean isBinaryField(String propertyName) {
        Class<?> current = domainClass;
        while (current != null && current != Object.class) {
            try {
                Field field = current.getDeclaredField(propertyName);
                return EncryptedBytes.class.isAssignableFrom(field.getType());
            } catch (NoSuchFieldException ignored) {
                current = current.getSuperclass();
            }
        }
        return false;
    }
}
