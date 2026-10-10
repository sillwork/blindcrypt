package io.github.sillwork.blindcrypt.spring.badrepo;

import io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException;
import io.github.sillwork.blindcrypt.core.KeyRing;
import io.github.sillwork.blindcrypt.core.UltraBlindIndexer;
import io.github.sillwork.blindcrypt.spring.listener.BlindIndexRegistry;
import io.github.sillwork.blindcrypt.spring.repository.BlindIndexDerivedQuery;
import io.github.sillwork.blindcrypt.spring.test.TestUser;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.data.repository.Repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Startup validation of blind-index derived queries: mixed predicates and return types.
 */
class BlindIndexQueryValidationTest {

    interface MixedRepo extends Repository<TestUser, Long> {
        // Mixed predicates the rewriter implements
        List<TestUser> findByEmailAndFullName(String email, String fullName);
        List<TestUser> findByEmailAndFullNameNot(String email, String fullName);
        List<TestUser> findByEmailAndFullNameIn(String email, Collection<String> names);
        List<TestUser> findByEmailAndFullNameIsNull(String email);
        List<TestUser> findByEmailAndFullNameIsNotNull(String email);

        // Mixed predicates the rewriter would silently turn into equality
        List<TestUser> findByEmailAndFullNameContaining(String email, String fragment);
        List<TestUser> findByEmailAndFullNameIgnoreCase(String email, String fullName);
        List<TestUser> findByEmailAndFullNameStartingWith(String email, String prefix);
        List<TestUser> findByEmailAndIdBetween(String email, Long from, Long to);
        List<TestUser> findByEmailAndIdGreaterThan(String email, Long id);
    }

    interface ReturnTypeRepo extends Repository<TestUser, Long> {
        // Supported
        TestUser findByEmail(String email);
        Optional<TestUser> findByPhone(String phone);
        List<TestUser> findByRegistrationNo(String registrationNo);
        Collection<TestUser> findByEmailAndFullName(String email, String fullName);
        long countByEmail(String email);
        Long countByPhone(String phone);
        boolean existsByEmail(String email);
        Boolean existsByPhone(String phone);

        // Unsupported: the rewriter returns a List or a Long, so these fail with ClassCastException at runtime
        int countByRegistrationNo(String registrationNo);
        Integer countByEmailAndFullName(String email, String fullName);
        Set<TestUser> findByPhoneAndFullName(String phone, String fullName);
        Iterable<TestUser> findByRegistrationNoAndFullName(String registrationNo, String fullName);
        String findByEmailAndId(String email, Long id);
        List<String> findByPhoneAndId(String phone, Long id);
    }

    /** Generic base declaring the entity as a type variable, as shared base repositories do. */
    interface GenericBase<T, I> extends Repository<T, I> {
        T findByEmail(String email);

        <P> P findByPhone(String phone);
    }

    interface GenericUserRepo extends GenericBase<TestUser, Long> { }

    interface NumberBase<T extends Number> extends Repository<TestUser, Long> {
        T findByRegistrationNo(String registrationNo);
    }

    interface NumberRepo extends NumberBase<Integer> { }

    /** A parameterized supertype the entity implements, used as a bound by generic base repositories. */
    interface Tagged<K> { }

    static class TaggedUser extends TestUser implements Tagged<Long> {
        TaggedUser() { }
    }

    interface ParameterizedBoundBase<T extends Tagged<K>, K> extends Repository<T, K> {
        T findByEmail(String email);
    }

    interface ParameterizedBoundRepo extends ParameterizedBoundBase<TaggedUser, Long> { }

    interface NestedBoundBase<T extends U, U extends Tagged<Long>> extends Repository<T, Long> {
        T findByEmail(String email);
    }

    interface NestedBoundRepo extends NestedBoundBase<TaggedUser, TaggedUser> { }

    interface UnrelatedParameterizedBoundBase<T extends Comparable<T>> extends Repository<TestUser, Long> {
        T findByEmail(String email);
    }

    interface UnrelatedParameterizedBoundRepo extends UnrelatedParameterizedBoundBase<String> { }

    private final BlindIndexRegistry registry;
    private final UltraBlindIndexer indexer;

    BlindIndexQueryValidationTest() {
        byte[] encKey = new byte[32];
        byte[] blindKey = new byte[32];
        blindKey[0] = 1;
        indexer = new UltraBlindIndexer(new KeyRing(Map.of("v1", encKey), "v1", blindKey));
        registry = new BlindIndexRegistry(indexer);
    }

    private static Method method(Class<?> repo, String name) {
        return Arrays.stream(repo.getMethods()).filter(m -> m.getName().equals(name)).findFirst().orElseThrow();
    }

    private BlindIndexDerivedQuery build(Class<?> repo, String name) {
        return new BlindIndexDerivedQuery(method(repo, name), TestUser.class, registry, indexer);
    }

    private BlindIndexDerivedQuery buildFor(Class<?> repo, Class<?> domainClass, String name) {
        return new BlindIndexDerivedQuery(method(repo, name), domainClass, registry, indexer);
    }

    @ParameterizedTest
    @ValueSource(strings = {"findByEmailAndFullName", "findByEmailAndFullNameNot", "findByEmailAndFullNameIn",
            "findByEmailAndFullNameIsNull", "findByEmailAndFullNameIsNotNull"})
    void mixedQueriesWithImplementedStandardPredicatesAreAccepted(String name) {
        assertThat(build(MixedRepo.class, name).hasBlindIndexPredicate()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"findByEmailAndFullNameContaining", "findByEmailAndFullNameStartingWith",
            "findByEmailAndIdBetween", "findByEmailAndIdGreaterThan"})
    void mixedQueriesWithUnimplementedStandardPredicatesAreRejected(String name) {
        assertThatThrownBy(() -> build(MixedRepo.class, name))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining(name)
                .hasMessageContaining("on property");
    }

    @Test
    void mixedQueryWithIgnoreCaseOnStandardPropertyIsRejected() {
        assertThatThrownBy(() -> build(MixedRepo.class, "findByEmailAndFullNameIgnoreCase"))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("findByEmailAndFullNameIgnoreCase")
                .hasMessageContaining("fullName")
                .hasMessageContaining("IgnoreCase");
    }

    @ParameterizedTest
    @ValueSource(strings = {"findByEmail", "findByPhone", "findByRegistrationNo", "findByEmailAndFullName",
            "countByEmail", "countByPhone", "existsByEmail", "existsByPhone"})
    void supportedReturnTypesAreAccepted(String name) {
        assertThat(build(ReturnTypeRepo.class, name).hasBlindIndexPredicate()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"countByRegistrationNo", "countByEmailAndFullName", "findByPhoneAndFullName",
            "findByRegistrationNoAndFullName", "findByEmailAndId", "findByPhoneAndId"})
    void unsupportedReturnTypesAreRejected(String name) {
        assertThatThrownBy(() -> build(ReturnTypeRepo.class, name))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining(name);
    }

    @Test
    void entityReturnedAsClassTypeVariableOfGenericBaseRepositoryIsAccepted() {
        assertThat(build(GenericUserRepo.class, "findByEmail").hasBlindIndexPredicate()).isTrue();
    }

    @Test
    void methodLevelTypeVariableReturnTypeIsRejected() {
        assertThatThrownBy(() -> build(GenericUserRepo.class, "findByPhone"))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("GenericBase.findByPhone")
                .hasMessageContaining("does not support");
    }

    @Test
    void typeVariableBoundedAwayFromTheEntityIsRejected() {
        assertThatThrownBy(() -> build(NumberRepo.class, "findByRegistrationNo"))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("NumberBase.findByRegistrationNo");
    }

    @Test
    void entityReturnedAsTypeVariableWithParameterizedBoundIsAccepted() {
        assertThat(buildFor(ParameterizedBoundRepo.class, TaggedUser.class, "findByEmail").hasBlindIndexPredicate()).isTrue();
    }

    @Test
    void entityReturnedAsTypeVariableBoundedByAnotherTypeVariableIsAccepted() {
        assertThat(buildFor(NestedBoundRepo.class, TaggedUser.class, "findByEmail").hasBlindIndexPredicate()).isTrue();
    }

    @Test
    void parameterizedBoundTheEntityDoesNotImplementIsRejected() {
        assertThatThrownBy(() -> build(UnrelatedParameterizedBoundRepo.class, "findByEmail"))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("UnrelatedParameterizedBoundBase.findByEmail");
    }
}
