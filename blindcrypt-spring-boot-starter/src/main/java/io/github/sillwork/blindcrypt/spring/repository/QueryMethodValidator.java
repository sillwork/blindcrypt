package io.github.sillwork.blindcrypt.spring.repository;

import io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException;
import io.github.sillwork.blindcrypt.spring.annotation.BlindIndex;
import io.github.sillwork.blindcrypt.spring.annotation.Encrypted;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.springframework.data.domain.Limit;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.data.repository.query.parser.Part;
import org.springframework.data.repository.query.parser.PartTree;

/**
 * Gatekeeper validating repository method definitions against unsupported configurations.
 * <p>
 * Runs during repository creation at application startup, so an unsupported method fails the application
 * before it serves traffic.
 * <p>
 * For every derived method on a {@code @BlindIndexQueries} repository, {@link #validateRepositoryMethod(Method, Class)}
 * rejects:
 * <ul>
 *   <li><b>Gap #13</b>: direct navigation to internal embeddable attributes (e.g. {@code findByEmailBlindIndex}).</li>
 *   <li>predicates on {@code @Encrypted} properties that have no {@code @BlindIndex}.</li>
 * </ul>
 * Only for methods that the rewriter will execute (those with a blind-index predicate),
 * {@link #validateBlindIndexQuery(Method, PartTree, Class)} additionally rejects:
 * <ul>
 *   <li>derived deletes, First/Top limits, paging, sorting and streaming
 *       (see {@link #validateRewritableShape(Method, PartTree)}).</li>
 *   <li><b>Gap #6</b>: {@link Lock @Lock}, {@link EntityGraph @EntityGraph} and {@link QueryHints @QueryHints}.</li>
 *   <li>return types other than the domain entity, {@code Optional}, {@code List} or {@code Collection} of it,
 *       {@code long}/{@code Long} for {@code countBy} and {@code boolean}/{@code Boolean} for {@code existsBy}
 *       (this rejects projections, {@code Set}, {@code Iterable} and {@code int} counts).</li>
 * </ul>
 * Unsupported predicates in such methods are rejected by {@link BlindIndexDerivedQuery}.
 * Methods without a blind-index predicate are executed by Spring Data unchanged, so those annotations and
 * return types remain available to them.
 */
public final class QueryMethodValidator {

    private QueryMethodValidator() { }

    /**
     * Validates any derived method on a {@code @BlindIndexQueries} repository, whether or not it has a
     * blind-index predicate.
     *
     * @param method      the reflected repository query method
     * @param domainClass the managed entity class
     * @throws BlindCryptConfigurationException if the method targets internal embeddable properties, or queries an
     *                                          {@code @Encrypted} property that has no {@code @BlindIndex}
     */
    public static void validateRepositoryMethod(Method method, Class<?> domainClass) {
        validatePropertyNameTargeting(method.getName(), method.getDeclaringClass());
        validateSearchableEncryptedFields(method, domainClass);
    }

    /**
     * Validates a derived method that has a blind-index predicate and will therefore be executed by the
     * blind index rewriter instead of Spring Data.
     *
     * @param method      the reflected repository query method
     * @param partTree    the parsed method name
     * @param domainClass the managed entity class
     * @throws BlindCryptConfigurationException if the method has a shape the rewriter does not implement, declares
     *                                          {@code @Lock}, {@code @EntityGraph} or {@code @QueryHints}, or has a
     *                                          return type the rewriter cannot produce
     */
    public static void validateBlindIndexQuery(Method method, PartTree partTree, Class<?> domainClass) {
        validateRewritableShape(method, partTree);
        validateQueryAnnotations(method);
        validateReturnType(method, partTree, domainClass);
    }

    /**
     * Rejects derived-query shapes that the blind index rewriter does not implement.
     *
     * @param method   the repository method
     * @param partTree the parsed method name
     * @throws BlindCryptConfigurationException if the method deletes, limits, pages, sorts by parameter or streams
     */
    public static void validateRewritableShape(Method method, PartTree partTree) {
        String name = method.getDeclaringClass().getSimpleName() + "." + method.getName();
        if (partTree.isDelete()) {
            throw new BlindCryptConfigurationException(
                    "Repository method " + name + " is a derived delete on a blind-indexed property, which @BlindIndexQueries cannot rewrite.",
                    "Load the entities with findBy... and delete them with deleteAll(entities), or use @Modifying @Query on the blindIndex column.");
        }
        if (partTree.isLimiting()) {
            throw new BlindCryptConfigurationException(
                    "Repository method " + name + " uses First/Top, which @BlindIndexQueries does not support.",
                    "Return a List and take the first element, or use an explicit @Query with a LIMIT.");
        }
        for (Class<?> parameterType : method.getParameterTypes()) {
            if (Pageable.class.isAssignableFrom(parameterType) || Sort.class.isAssignableFrom(parameterType)
                    || Limit.class.isAssignableFrom(parameterType)) {
                throw new BlindCryptConfigurationException(
                        "Repository method " + name + " takes a " + parameterType.getSimpleName() + " parameter, which @BlindIndexQueries does not support.",
                        "Use an OrderBy clause in the method name, or an explicit @Query.");
            }
        }
        Class<?> returnType = method.getReturnType();
        if (Slice.class.isAssignableFrom(returnType) || Stream.class.isAssignableFrom(returnType)) {
            throw new BlindCryptConfigurationException(
                    "Repository method " + name + " returns " + returnType.getSimpleName() + ", which @BlindIndexQueries does not support.",
                    "Return the entity, Optional, List, long (countBy) or boolean (existsBy).");
        }
    }

    private static void validatePropertyNameTargeting(String methodName, Class<?> declaringClass) {
        if (methodName.contains("BlindIndex") || methodName.contains("EncryptedValue")) {
            throw new BlindCryptConfigurationException(
                    "Repository method '" + methodName + "' on " + declaringClass.getSimpleName()
                            + " targets internal embeddable properties (blindIndex or encryptedValue).",
                    "Query the domain property with the plaintext value instead, for example findByEmail(plaintext).");
        }
    }

    private static void validateQueryAnnotations(Method method) {
        String methodName = method.getName();
        if (method.isAnnotationPresent(Lock.class)) {
            throw new BlindCryptConfigurationException(
                    "Repository method '" + methodName + "' declares @Lock, which @BlindIndexQueries cannot apply.",
                    "Use an explicit @Query, for example: SELECT u FROM User u WHERE u.email.blindIndex = :bidx.");
        }
        if (method.isAnnotationPresent(EntityGraph.class)) {
            throw new BlindCryptConfigurationException(
                    "Repository method '" + methodName + "' declares @EntityGraph, which @BlindIndexQueries cannot apply.",
                    "Use an explicit @Query with JOIN FETCH when a custom entity graph is required.");
        }
        if (method.isAnnotationPresent(QueryHints.class)) {
            throw new BlindCryptConfigurationException(
                    "Repository method '" + methodName + "' declares @QueryHints, which @BlindIndexQueries does not pass to the rewritten query.",
                    "Remove @QueryHints, or use an explicit @Query on the blindIndex column.");
        }
    }

    /**
     * Allow-list of the return types the rewriter produces: {@code getSingleResult()} for the entity and
     * {@code Optional}, {@code getResultList()} (a {@code List}) for collections, a {@code Long} count and a
     * {@code boolean} for exists. Anything else would fail with a {@code ClassCastException} on first call.
     */
    private static void validateReturnType(Method method, PartTree partTree, Class<?> domainClass) {
        Class<?> returnType = method.getReturnType();
        String name = method.getDeclaringClass().getSimpleName() + "." + method.getName();
        if (partTree.isCountProjection()) {
            requireCountReturnType(name, returnType);
        } else if (partTree.isExistsProjection()) {
            requireExistsReturnType(name, returnType);
        } else if (isCollectionReturnType(returnType)) {
            requireCollectionOfDomainEntity(name, method, domainClass);
        } else if (!isDomainEntityReturnType(method, domainClass)) {
            throw unsupportedReturnType(name, returnType.getSimpleName(),
                    "Return " + domainClass.getSimpleName() + ", or an Optional, List or Collection of it, and map projections in code.");
        }
    }

    private static void requireCountReturnType(String name, Class<?> returnType) {
        if (returnType != long.class && returnType != Long.class) {
            throw unsupportedReturnType(name, returnType.getSimpleName(), "Declare countBy methods to return long or Long.");
        }
    }

    private static void requireExistsReturnType(String name, Class<?> returnType) {
        if (returnType != boolean.class && returnType != Boolean.class) {
            throw unsupportedReturnType(name, returnType.getSimpleName(), "Declare existsBy methods to return boolean or Boolean.");
        }
    }

    private static boolean isCollectionReturnType(Class<?> returnType) {
        return returnType == Optional.class || returnType == List.class || returnType == Collection.class;
    }

    private static void requireCollectionOfDomainEntity(String name, Method method, Class<?> domainClass) {
        Type elementType = method.getGenericReturnType() instanceof ParameterizedType parameterized
                ? parameterized.getActualTypeArguments()[0] : null;
        if (elementType instanceof Class<?> elementClass && !elementClass.isAssignableFrom(domainClass)) {
            throw unsupportedReturnType(name, method.getReturnType().getSimpleName() + "<" + elementClass.getSimpleName() + ">",
                    "Return the managed domain entity " + domainClass.getSimpleName() + " and map it to the projection in code.");
        }
    }

    /**
     * Whether the method returns the entity itself. A return type that is a type variable of the declaring
     * interface, such as {@code T findByEmail(String)} on a generic base repository, erases to its bound; it is
     * accepted when every bound is a supertype of the entity. A type variable declared on the method itself is
     * rejected, because the caller chooses it and the rewriter cannot honour an arbitrary type.
     */
    private static boolean isDomainEntityReturnType(Method method, Class<?> domainClass) {
        if (method.getGenericReturnType() instanceof TypeVariable<?> typeVariable) {
            return typeVariable.getGenericDeclaration() instanceof Class<?> && boundsAcceptDomainClass(typeVariable, domainClass);
        }
        Class<?> returnType = method.getReturnType();
        return returnType != Object.class && returnType.isAssignableFrom(domainClass);
    }

    private static boolean boundsAcceptDomainClass(TypeVariable<?> typeVariable, Class<?> domainClass) {
        for (Type bound : typeVariable.getBounds()) {
            if (!boundAcceptsDomainClass(bound, domainClass)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Checks one bound against the entity, the way the erased return type was checked before. A parameterized bound
     * such as {@code BaseEntity<ID>} is reduced to its raw class and a bound that is itself a type variable is
     * checked through its own bounds. Any other kind of bound (wildcard, array) cannot be resolved here, so it is
     * rejected and the method fails startup rather than risking a {@code ClassCastException} on first call.
     */
    private static boolean boundAcceptsDomainClass(Type bound, Class<?> domainClass) {
        if (bound instanceof Class<?> boundClass) {
            return boundClass.isAssignableFrom(domainClass);
        }
        if (bound instanceof ParameterizedType parameterized && parameterized.getRawType() instanceof Class<?> rawClass) {
            return rawClass.isAssignableFrom(domainClass);
        }
        if (bound instanceof TypeVariable<?> nested) {
            return boundsAcceptDomainClass(nested, domainClass);
        }
        return false;
    }

    private static BlindCryptConfigurationException unsupportedReturnType(String name, String returnType, String action) {
        return new BlindCryptConfigurationException(
                "Repository method " + name + " returns " + returnType + ", which @BlindIndexQueries does not support.",
                action);
    }

    private static void validateSearchableEncryptedFields(Method method, Class<?> domainClass) {
        try {
            PartTree partTree = new PartTree(method.getName(), domainClass);
            for (PartTree.OrPart orPart : partTree) {
                for (Part part : orPart) {
                    validatePartField(part, domainClass, method);
                }
            }
        } catch (BlindCryptConfigurationException configurationException) {
            throw configurationException;
        } catch (Exception ignored) {
            // Let Spring Data handle standard PartTree parsing errors
        }
    }

    private static void validatePartField(Part part, Class<?> domainClass, Method method) {
        String propertyName = part.getProperty().getSegment();
        Field field = findField(domainClass, propertyName);
        if (field != null && field.isAnnotationPresent(Encrypted.class) 
                && !field.isAnnotationPresent(BlindIndex.class)) {
            throw new BlindCryptConfigurationException(
                    "Repository method '" + method.getName() + "' on " + method.getDeclaringClass().getSimpleName()
                            + " queries property '" + propertyName + "' which is annotated with @Encrypted but lacks a @BlindIndex."
                            + " Unindexed encrypted columns cannot be searched because AES-256-GCM uses random IVs.",
                    "To make this property searchable, declare it as '@BlindIndex private EncryptedText " + propertyName + ";'.");
        }
    }

    /**
     * Recursively traverses class inheritance hierarchy to find a declared field by name.
     *
     * @param targetClass the entity class to inspect
     * @param fieldName   the name of the declared field
     * @return the resolved {@link Field}, or {@code null} if not found in hierarchy
     */
    private static Field findField(Class<?> targetClass, String fieldName) {
        Class<?> currentClass = targetClass;
        while (currentClass != null && currentClass != Object.class) {
            try {
                return currentClass.getDeclaredField(fieldName);
            } catch (NoSuchFieldException ignored) {
                currentClass = currentClass.getSuperclass();
            }
        }
        return null;
    }
}
