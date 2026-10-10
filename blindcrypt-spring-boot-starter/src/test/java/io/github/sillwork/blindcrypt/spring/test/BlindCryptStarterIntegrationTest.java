package io.github.sillwork.blindcrypt.spring.test;

import io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException;
import io.github.sillwork.blindcrypt.spring.repository.QueryMethodValidator;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest(classes = TestApplication.class)
class BlindCryptStarterIntegrationTest {

    @Autowired
    private TestUserRepository userRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void cleanUp() {
        userRepository.deleteAll();
    }

    @Test
    void testSaveAndTransparentEncryption() {
        TestUser user = new TestUser("Priya Nair", "priya@company.com", "+91 (98450) 12345", "REG-101");
        user.setSecretNotes("Highly sensitive proprietary secret notes with zero searchability needed");
        TestUser saved = userRepository.saveAndFlush(user);

        // 1. Assert raw database columns contain ONLY ciphertext and blind index hashes
        Map<String, Object> raw = jdbcTemplate.queryForMap(
                "SELECT email, email_bidx, phone, phone_bidx, registration_no, registration_no_bidx, secret_notes FROM test_users WHERE id = ?",
                saved.getId());

        String rawEmail = (String) raw.get("email");
        String rawEmailBidx = (String) raw.get("email_bidx");
        String rawPhone = (String) raw.get("phone");
        String rawPhoneBidx = (String) raw.get("phone_bidx");
        String rawSecretNotes = (String) raw.get("secret_notes");

        assertThat(rawEmail).startsWith("ENC:v1:").doesNotContain("priya");
        assertThat(rawEmailBidx).matches("^[0-9a-f]{64}$");

        assertThat(rawPhone).startsWith("ENC:v1:").doesNotContain("98450");
        assertThat(rawPhoneBidx).matches("^[0-9a-f]{64}$");

        // Verify encryption-only: ciphertext stored, but NO blind index column exists
        assertThat(rawSecretNotes).startsWith("ENC:v1:").doesNotContain("proprietary");

        // 2. Assert transparent decryption when reading entity back
        TestUser fetched = userRepository.findById(saved.getId()).orElseThrow();
        assertThat(fetched.getFullName()).isEqualTo("Priya Nair");
        assertThat(fetched.getEmail()).isEqualTo("priya@company.com");
        assertThat(fetched.getPhone()).isEqualTo("+91 (98450) 12345");
        assertThat(fetched.getRegistrationNo()).isEqualTo("REG-101");
        assertThat(fetched.getSecretNotes()).isEqualTo("Highly sensitive proprietary secret notes with zero searchability needed");
    }

    @Test
    void testDerivedQueryRewritingWithEmailNormalization() {
        TestUser user = new TestUser("Priya Nair", "priya.nair@company.com", "+919845012345", "REG-202");
        userRepository.saveAndFlush(user);

        // Derived search with mixed casing and leading/trailing whitespace
        List<TestUser> results = userRepository.findByEmail("  Priya.Nair@Company.COM  ");
        assertThat(results).hasSize(1);
        assertThat(results.get(0).getFullName()).isEqualTo("Priya Nair");
        assertThat(results.get(0).getEmail()).isEqualTo("priya.nair@company.com");
    }

    @Test
    void testDerivedQueryPhoneIn() {
        TestUser u1 = new TestUser("Alice", "alice@company.com", "+1 (555) 123-4567", "REG-301");
        TestUser u2 = new TestUser("Bob", "bob@company.com", "+1 (555) 987-6543", "REG-302");
        userRepository.saveAllAndFlush(List.of(u1, u2));

        // Search with unformatted digits or alternate formatting
        List<TestUser> found = userRepository.findByPhoneIn(List.of("15551234567", "+1-555-000-0000"));
        assertThat(found).hasSize(1);
        assertThat(found.get(0).getFullName()).isEqualTo("Alice");
    }

    @Test
    void testPlainDerivedQueryWithPageableIsLeftToSpringData() {
        userRepository.saveAndFlush(new TestUser("Dana", "dana@company.com", "9845000123", "REG-401"));

        List<TestUser> found = userRepository.findByFullName("Dana", PageRequest.of(0, 10));
        assertThat(found).extracting(TestUser::getFullName).containsExactly("Dana");
    }

    @Test
    void testDerivedQueryExistsByRegistrationNo() {
        TestUser user = new TestUser("Charlie", "charlie@company.com", "9998887776", "CORP-REG-99");
        userRepository.saveAndFlush(user);

        boolean exists = userRepository.existsByRegistrationNo("  corp-reg-99 ");
        assertThat(exists).isTrue();

        boolean notExists = userRepository.existsByRegistrationNo("NON-EXISTENT");
        assertThat(notExists).isFalse();
    }

    @Test
    void testUniqueConstraintCollisionEnforced() {
        // Resolves Gap #9: Database unique constraint collision on blind index
        TestUser u1 = new TestUser("Admin 1", "admin1@company.com", "9845000001", "UNIQUE-LIC-001");
        userRepository.saveAndFlush(u1);

        TestUser u2 = new TestUser("Admin 2", "admin2@company.com", "9845000002", "  unique-lic-001  ");

        // Attempting to save u2 must trigger physical unique constraint failure on registration_no_bidx
        assertThatThrownBy(() -> userRepository.saveAndFlush(u2))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void testQueryingUnindexedEncryptedFieldThrowsHelpfulException() throws NoSuchMethodException {
        interface DummyRepo {
            List<TestUser> findBySecretNotes(String notes);
        }
        Method method = DummyRepo.class.getMethod("findBySecretNotes", String.class);

        assertThatThrownBy(() -> QueryMethodValidator.validateRepositoryMethod(method, TestUser.class))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("queries property 'secretNotes' which is annotated with @Encrypted but lacks a @BlindIndex");
    }
}
