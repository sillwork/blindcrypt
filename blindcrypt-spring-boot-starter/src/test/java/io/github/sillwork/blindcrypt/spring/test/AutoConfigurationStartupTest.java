package io.github.sillwork.blindcrypt.spring.test;

import io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException;
import io.github.sillwork.blindcrypt.core.FieldEncryptor;
import io.github.sillwork.blindcrypt.spring.config.BlindCryptAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;

class AutoConfigurationStartupTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(BlindCryptAutoConfiguration.class))
            .withBean(jakarta.persistence.EntityManager.class,
                    () -> mock(jakarta.persistence.EntityManager.class, RETURNS_DEEP_STUBS));

    @Test
    void missingKeysFailWithConfigurationExceptionNamingTheProperty() {
        runner.run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .rootCause()
                    .isInstanceOf(BlindCryptConfigurationException.class)
                    .hasMessageContaining("blindcrypt.keys");
        });
    }

    @Test
    void disabledStarterCreatesNoBeans() {
        runner.withPropertyValues("blindcrypt.enabled=false")
              .run(context -> {
                  assertThat(context).hasNotFailed();
                  assertThat(context).doesNotHaveBean(FieldEncryptor.class);
              });
    }

    @Test
    void validConfigurationStarts() {
        runner.withPropertyValues(
                        "blindcrypt.keys.v1=MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
                        "blindcrypt.blind-index-key=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=")
              .run(context -> assertThat(context).hasSingleBean(FieldEncryptor.class));
    }
}
