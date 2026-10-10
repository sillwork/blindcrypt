package io.github.sillwork.blindcrypt.spring.badrepo;

import io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException;
import io.github.sillwork.blindcrypt.spring.repository.QueryMethodValidator;
import io.github.sillwork.blindcrypt.spring.test.TestDocument;
import io.github.sillwork.blindcrypt.spring.test.TestUser;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.data.domain.Limit;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.Sort;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.parser.PartTree;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class QueryMethodValidatorTest {

    interface UserRepo extends Repository<TestUser, Long> {
        List<TestUser> findByEmail(String email, Pageable pageable);
        List<TestUser> findByPhone(String phone, Sort sort);
        List<TestUser> findByRegistrationNo(String registrationNo, Limit limit);
        @SuppressWarnings("java:S7186") // fixture intentionally declares an unpaged query method
        Slice<TestUser> findByEmailAndFullName(String email, String fullName);
        List<TestUser> findByEmailAndId(String email, Long id);
        int existsByEmail(String email);
        Optional<String> findByPhoneAndId(String phone, Long id);
        @SuppressWarnings("rawtypes")
        List findByRegistrationNoAndId(String registrationNo, Long id);
        Object findByEmailAndFullNameNot(String email, String fullName);
        List<Object> findByPhoneAndFullName(String phone, String fullName);
        List<TestUser> findBySecretNotes(String notes);
        List<TestUser> findByFullName(String fullName);
        List<TestUser> findByEmailBlindIndex(String hash);
        List<TestUser> findByEncryptedValueIsNull();
    }

    interface DocumentRepo extends Repository<TestDocument, Long> {
        List<TestDocument> findByVersion(Long version);
    }

    private static Method method(Class<?> repo, String name) {
        return Arrays.stream(repo.getMethods()).filter(m -> m.getName().equals(name)).findFirst().orElseThrow();
    }

    private static void validateQuery(String name) {
        Method method = method(UserRepo.class, name);
        PartTree partTree = new PartTree(name, TestUser.class);
        QueryMethodValidator.validateBlindIndexQuery(method, partTree, TestUser.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"findByEmail", "findByPhone", "findByRegistrationNo"})
    void pagingSortingAndLimitParametersAreRejectedWithTheParameterType(String name) {
        Method method = method(UserRepo.class, name);
        PartTree partTree = new PartTree(name, TestUser.class);

        assertThatThrownBy(() -> QueryMethodValidator.validateRewritableShape(method, partTree))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("UserRepo." + name)
                .hasMessageContaining("parameter, which @BlindIndexQueries does not support");
    }

    @Test
    void sliceReturnTypeIsRejectedAsAShape() {
        Method method = method(UserRepo.class, "findByEmailAndFullName");
        PartTree partTree = new PartTree("findByEmailAndFullName", TestUser.class);

        assertThatThrownBy(() -> QueryMethodValidator.validateRewritableShape(method, partTree))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("returns Slice");
    }

    @Test
    void existsMethodMustReturnABoolean() {
        assertThatThrownBy(() -> validateQuery("existsByEmail"))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("returns int")
                .satisfies(e -> org.assertj.core.api.Assertions.assertThat(((BlindCryptConfigurationException) e).getAction())
                        .contains("boolean or Boolean"));
    }

    @Test
    void optionalOfAnUnrelatedTypeIsRejectedAsAProjection() {
        assertThatThrownBy(() -> validateQuery("findByPhoneAndId"))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("Optional<String>")
                .satisfies(e -> org.assertj.core.api.Assertions.assertThat(((BlindCryptConfigurationException) e).getAction())
                        .contains("TestUser"));
    }

    @Test
    void rawListAndListOfASupertypeOfTheEntityAreAccepted() {
        assertThatCode(() -> validateQuery("findByRegistrationNoAndId")).doesNotThrowAnyException();
        assertThatCode(() -> validateQuery("findByPhoneAndFullName")).doesNotThrowAnyException();
    }

    @Test
    void plainObjectReturnTypeIsRejectedBecauseItCannotBeVerified() {
        assertThatThrownBy(() -> validateQuery("findByEmailAndFullNameNot"))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("returns Object");
    }

    @Test
    void queryingAnEncryptedPropertyWithoutBlindIndexIsRejected() {
        Method method = method(UserRepo.class, "findBySecretNotes");

        assertThatThrownBy(() -> QueryMethodValidator.validateRepositoryMethod(method, TestUser.class))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("secretNotes")
                .hasMessageContaining("lacks a @BlindIndex");
    }

    @Test
    void plainAndBlindIndexedPropertiesPassRepositoryMethodValidation() {
        assertThatCode(() -> QueryMethodValidator.validateRepositoryMethod(method(UserRepo.class, "findByFullName"), TestUser.class))
                .doesNotThrowAnyException();
        assertThatCode(() -> QueryMethodValidator.validateRepositoryMethod(method(UserRepo.class, "findByEmailAndId"), TestUser.class))
                .doesNotThrowAnyException();
    }

    @Test
    void propertyDeclaredOnASuperclassIsFoundWhenValidating() {
        assertThatCode(() -> QueryMethodValidator.validateRepositoryMethod(method(DocumentRepo.class, "findByVersion"), TestDocument.class))
                .doesNotThrowAnyException();
    }

    @Test
    void methodNamesTargetingInternalEmbeddablePropertiesAreRejected() {
        Method blindIndexTarget = method(UserRepo.class, "findByEmailBlindIndex");
        Method encryptedValueTarget = method(UserRepo.class, "findByEncryptedValueIsNull");
        assertThatThrownBy(() -> QueryMethodValidator.validateRepositoryMethod(blindIndexTarget, TestUser.class))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("findByEmailBlindIndex")
                .hasMessageContaining("internal embeddable properties");
        assertThatThrownBy(() -> QueryMethodValidator.validateRepositoryMethod(encryptedValueTarget, TestUser.class))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("findByEncryptedValueIsNull");
    }
}
