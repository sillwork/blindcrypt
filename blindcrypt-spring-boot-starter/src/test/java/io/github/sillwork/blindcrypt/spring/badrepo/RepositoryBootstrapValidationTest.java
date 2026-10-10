package io.github.sillwork.blindcrypt.spring.badrepo;

import io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException;
import io.github.sillwork.blindcrypt.spring.repository.QueryMethodValidator;
import io.github.sillwork.blindcrypt.spring.test.TestUser;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.SpringApplication;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.parser.PartTree;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RepositoryBootstrapValidationTest {

    interface ShapeRepo extends Repository<TestUser, Long> {
        void deleteByEmail(String email);
        Optional<TestUser> findFirstByEmail(String email);
        Page<TestUser> findByEmail(String email, Pageable pageable);
        Stream<TestUser> streamByEmail(String email);
    }

    @Test
    void unsupportedPredicateFailsStartupWithoutAnyCall() {
        SpringApplication app = new SpringApplication(BadApp.class);
        assertThatThrownBy(() -> app.run("--spring.datasource.url=jdbc:h2:mem:bootstrap_validation"))
                .rootCause()
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("findByEmailContaining")
                .hasMessageContaining("CONTAINING");
    }

    @Test
    void streamOnBlindIndexedPropertyReportsTheShapeNotAProjection() throws NoSuchMethodException {
        Method method = ShapeRepo.class.getMethod("streamByEmail", String.class);
        PartTree partTree = new PartTree("streamByEmail", TestUser.class);
        assertThatThrownBy(() -> QueryMethodValidator.validateBlindIndexQuery(method, partTree, TestUser.class))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("returns Stream")
                .hasMessageNotContaining("interface projection");
    }

    @ParameterizedTest
    @ValueSource(strings = {"deleteByEmail", "findFirstByEmail", "findByEmail", "streamByEmail"})
    void unsupportedShapesOnBlindIndexedPropertyAreRejected(String methodName) {
        Method method = Arrays.stream(ShapeRepo.class.getMethods())
                .filter(m -> m.getName().equals(methodName)).findFirst().orElseThrow();
        PartTree partTree = new PartTree(methodName, TestUser.class);
        assertThatThrownBy(() -> QueryMethodValidator.validateRewritableShape(method, partTree))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining(methodName);
    }
}
