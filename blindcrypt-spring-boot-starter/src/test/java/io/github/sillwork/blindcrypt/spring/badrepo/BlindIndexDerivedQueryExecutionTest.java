package io.github.sillwork.blindcrypt.spring.badrepo;

import io.github.sillwork.blindcrypt.core.KeyRing;
import io.github.sillwork.blindcrypt.core.Normalization;
import io.github.sillwork.blindcrypt.core.UltraBlindIndexer;
import io.github.sillwork.blindcrypt.spring.listener.BlindIndexRegistry;
import io.github.sillwork.blindcrypt.spring.model.EncryptedBytes;
import io.github.sillwork.blindcrypt.spring.model.EncryptedText;
import io.github.sillwork.blindcrypt.spring.repository.BlindIndexDerivedQuery;
import io.github.sillwork.blindcrypt.spring.test.TestDocument;
import io.github.sillwork.blindcrypt.spring.test.TestUser;
import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.Query;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.repository.Repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Verifies the JPQL and the bound parameters that {@link BlindIndexDerivedQuery} produces, and how it shapes the result,
 * against a mocked {@link EntityManager}. Blind-index parameters must be hashes, never the plaintext argument.
 */
class BlindIndexDerivedQueryExecutionTest {

    interface UserRepo extends Repository<TestUser, Long> {
        TestUser findByEmail(String email);
        Optional<TestUser> findByPhone(String phone);
        List<TestUser> findByEmailIn(Collection<String> emails);
        List<TestUser> findByEmailOrPhone(String email, String phone);
        List<TestUser> findByEmailAndFullNameNotOrderByFullNameDesc(String email, String fullName);
        List<TestUser> findByEmailAndFullNameIn(String email, Collection<String> names);
        List<TestUser> findByEmailIsNull();
        List<TestUser> findByEmailIsNotNullAndFullNameIsNull();
        Collection<TestUser> findByRegistrationNo(String registrationNo);
        long countByEmail(String email);
        boolean existsByEmail(String email);
    }

    interface DocumentRepo extends Repository<TestDocument, Long> {
        Optional<TestDocument> findByFingerprint(byte[] fingerprint);
        List<TestDocument> findBySignature(String signature);
        List<TestDocument> findBySignatureIn(Collection<EncryptedBytes> signatures);
        List<TestDocument> findByDocTitle(EncryptedText title);
    }

    private UltraBlindIndexer indexer;
    private BlindIndexRegistry registry;
    private EntityManager entityManager;
    private Query query;
    private final Map<String, Object> boundParameters = new LinkedHashMap<>();

    @BeforeEach
    void setUp() {
        byte[] encKey = new byte[32];
        byte[] blindKey = new byte[32];
        blindKey[0] = 1;
        indexer = new UltraBlindIndexer(new KeyRing(Map.of("v1", encKey), "v1", blindKey));
        registry = new BlindIndexRegistry(indexer);
        entityManager = mock(EntityManager.class);
        query = mock(Query.class);
        when(entityManager.createQuery(anyString())).thenReturn(query);
        when(query.setParameter(anyString(), any())).thenAnswer(invocation -> {
            boundParameters.put(invocation.getArgument(0), invocation.getArgument(1));
            return query;
        });
    }

    private BlindIndexDerivedQuery derived(Class<?> repo, Class<?> domain, String name) {
        Method method = Arrays.stream(repo.getMethods()).filter(m -> m.getName().equals(name)).findFirst().orElseThrow();
        return new BlindIndexDerivedQuery(method, domain, registry, indexer);
    }

    private String executedJpql(BlindIndexDerivedQuery derivedQuery, Object... arguments) {
        derivedQuery.execute(entityManager, arguments);
        ArgumentCaptor<String> jpql = ArgumentCaptor.forClass(String.class);
        verify(entityManager).createQuery(jpql.capture());
        return jpql.getValue();
    }

    private String emailHash(String value) {
        return indexer.computeHex("user_email", value, Normalization.TRIM_CASE_INSENSITIVE, null);
    }

    private String phoneHash(String value) {
        return indexer.computeHex("user_phone", value, Normalization.DIGITS_ONLY, null);
    }

    @Test
    void equalityOnBlindIndexedPropertyBindsTheHashNotThePlaintext() {
        String jpql = executedJpql(derived(UserRepo.class, TestUser.class, "findByEmail"), "  Alice@Example.com ");

        assertThat(jpql).isEqualTo("SELECT e FROM TestUser e WHERE (e.email.blindIndex = :param_0)");
        assertThat(boundParameters).containsOnlyKeys("param_0");
        assertThat(boundParameters.get("param_0")).isEqualTo(emailHash("alice@example.com")).isNotEqualTo("Alice@Example.com");
    }

    @Test
    void singleEntityResultIsReturnedAndMissingEntityBecomesNull() {
        BlindIndexDerivedQuery derived = derived(UserRepo.class, TestUser.class, "findByEmail");
        TestUser user = mock(TestUser.class);
        when(query.getSingleResult()).thenReturn(user);
        assertThat(derived.execute(entityManager, new Object[] {"a@b.com"})).isSameAs(user);

        when(query.getSingleResult()).thenThrow(new NoResultException());
        assertThat(derived.execute(entityManager, new Object[] {"a@b.com"})).isNull();
    }

    @Test
    void optionalResultIsPresentOrEmpty() {
        BlindIndexDerivedQuery derived = derived(UserRepo.class, TestUser.class, "findByPhone");
        TestUser user = mock(TestUser.class);
        when(query.getSingleResult()).thenReturn(user);
        assertThat(derived.execute(entityManager, new Object[] {"555-0100"})).isEqualTo(Optional.of(user));

        when(query.getSingleResult()).thenThrow(new NoResultException());
        assertThat(derived.execute(entityManager, new Object[] {"555-0100"})).isEqualTo(Optional.empty());
    }

    @Test
    void collectionAndListResultsComeFromGetResultList() {
        List<Object> rows = List.of(mock(TestUser.class));
        when(query.getResultList()).thenReturn(rows);

        assertThat(derived(UserRepo.class, TestUser.class, "findByRegistrationNo").execute(entityManager, new Object[] {"R-1"}))
                .isEqualTo(rows);
        assertThat(derived(UserRepo.class, TestUser.class, "findByEmailIn").execute(entityManager, new Object[] {List.of("a@b.com")}))
                .isEqualTo(rows);
    }

    @Test
    void inPredicateOnBlindIndexedPropertyHashesEveryElementAndKeepsNulls() {
        List<String> emails = Arrays.asList("A@b.com", null, "c@d.com");
        String jpql = executedJpql(derived(UserRepo.class, TestUser.class, "findByEmailIn"), emails);

        assertThat(jpql).isEqualTo("SELECT e FROM TestUser e WHERE (e.email.blindIndex IN :param_0)");
        assertThat(boundParameters)
                .containsEntry("param_0", Arrays.asList(emailHash("a@b.com"), null, emailHash("c@d.com")));
    }

    @Test
    void inPredicateWithoutACollectionArgumentBindsAnEmptyList() {
        executedJpql(derived(UserRepo.class, TestUser.class, "findByEmailIn"), "not-a-collection");
        assertThat(boundParameters).containsEntry("param_0", List.of());
    }

    @Test
    void orPredicatesAreJoinedAndEachBlindIndexedArgumentIsHashedWithItsOwnIndex() {
        String jpql = executedJpql(derived(UserRepo.class, TestUser.class, "findByEmailOrPhone"), "a@b.com", "(555) 010-0");

        assertThat(jpql).isEqualTo("SELECT e FROM TestUser e WHERE (e.email.blindIndex = :param_0) OR (e.phone.blindIndex = :param_1)");
        assertThat(boundParameters).containsEntry("param_0", emailHash("a@b.com")).containsEntry("param_1", phoneHash("5550100"));
    }

    @Test
    void standardPredicatesKeepRawArgumentsAndOrderByIsAppended() {
        String jpql = executedJpql(derived(UserRepo.class, TestUser.class, "findByEmailAndFullNameNotOrderByFullNameDesc"),
                "a@b.com", "Bob");

        assertThat(jpql).isEqualTo("SELECT e FROM TestUser e WHERE (e.email.blindIndex = :param_0 AND e.fullName != :param_1)"
                + " ORDER BY e.fullName DESC");
        assertThat(boundParameters).containsEntry("param_1", "Bob");
    }

    @Test
    void inPredicateOnStandardPropertyPassesTheCollectionThrough() {
        List<String> names = List.of("Bob", "Eve");
        String jpql = executedJpql(derived(UserRepo.class, TestUser.class, "findByEmailAndFullNameIn"), "a@b.com", names);

        assertThat(jpql).isEqualTo("SELECT e FROM TestUser e WHERE (e.email.blindIndex = :param_0 AND e.fullName IN :param_1)");
        assertThat(boundParameters).containsEntry("param_1", names);
    }

    @Test
    void nullPredicatesConsumeNoArgumentAndBindNothing() {
        assertThat(executedJpql(derived(UserRepo.class, TestUser.class, "findByEmailIsNull")))
                .isEqualTo("SELECT e FROM TestUser e WHERE (e.email.blindIndex IS NULL)");
        assertThat(boundParameters).isEmpty();
    }

    @Test
    void notNullPredicateOnBlindIndexAndStandardProperty() {
        assertThat(executedJpql(derived(UserRepo.class, TestUser.class, "findByEmailIsNotNullAndFullNameIsNull")))
                .isEqualTo("SELECT e FROM TestUser e WHERE (e.email.blindIndex IS NOT NULL AND e.fullName IS NULL)");
    }

    @Test
    void countQueryReturnsTheCountAsIs() {
        when(query.getSingleResult()).thenReturn(3L);
        BlindIndexDerivedQuery derived = derived(UserRepo.class, TestUser.class, "countByEmail");

        assertThat(derived.execute(entityManager, new Object[] {"a@b.com"})).isEqualTo(3L);
        verify(entityManager).createQuery("SELECT COUNT(e) FROM TestUser e WHERE (e.email.blindIndex = :param_0)");
    }

    @Test
    void existsQueryIsTrueOnlyForAPositiveCount() {
        BlindIndexDerivedQuery derived = derived(UserRepo.class, TestUser.class, "existsByEmail");
        when(query.getSingleResult()).thenReturn(2L);
        assertThat(derived.execute(entityManager, new Object[] {"a@b.com"})).isEqualTo(true);

        when(query.getSingleResult()).thenReturn(0L);
        assertThat(derived.execute(entityManager, new Object[] {"a@b.com"})).isEqualTo(false);

        when(query.getSingleResult()).thenReturn(null);
        assertThat(derived.execute(entityManager, new Object[] {"a@b.com"})).isEqualTo(false);
    }

    @Test
    void nullArgumentOnBlindIndexedPropertyBindsNullInsteadOfHashing() {
        executedJpql(derived(UserRepo.class, TestUser.class, "findByEmail"), (Object) null);
        assertThat(boundParameters).containsEntry("param_0", null);
    }

    @Test
    void missingArgumentArrayBindsNull() {
        derived(UserRepo.class, TestUser.class, "findByEmail").execute(entityManager, null);
        assertThat(boundParameters).containsEntry("param_0", null);
    }

    @Test
    void encryptedTextArgumentIsHashedByItsPlaintextAndNullValueBindsNull() {
        BlindIndexDerivedQuery byTitle = derived(DocumentRepo.class, TestDocument.class, "findByDocTitle");
        byTitle.execute(entityManager, new Object[] {EncryptedText.of("  Annual Report ")});
        assertThat(boundParameters)
                .containsEntry("param_0", indexer.computeHex("doc_title", "annual report", Normalization.TRIM_CASE_INSENSITIVE, null));

        boundParameters.clear();
        byTitle.execute(entityManager, new Object[] {EncryptedText.update(null, null)});
        assertThat(boundParameters).containsEntry("param_0", null);
    }

    @Test
    void binaryIndexedPropertyHashesBytesAsBinaryAndStringsThroughTheNormalizer() {
        byte[] fingerprint = {1, 2, 3, 4};
        derived(DocumentRepo.class, TestDocument.class, "findByFingerprint")
                .execute(entityManager, new Object[] {fingerprint});
        assertThat(boundParameters).containsEntry("param_0", indexer.computeBinary("doc_fingerprint", fingerprint, null));

        boundParameters.clear();
        derived(DocumentRepo.class, TestDocument.class, "findBySignature")
                .execute(entityManager, new Object[] {"sig-text"});
        assertThat(boundParameters)
                .containsEntry("param_0", indexer.computeBinary("doc_signature", "sig-text", Normalization.NONE, null));
    }

    @Test
    void encryptedBytesArgumentsInAnInPredicateAreHashedAsBinary() {
        byte[] one = {9, 9};
        derived(DocumentRepo.class, TestDocument.class, "findBySignatureIn")
                .execute(entityManager, new Object[] {List.of(EncryptedBytes.of(one))});

        assertThat((List<?>) boundParameters.get("param_0"))
                .singleElement()
                .isEqualTo(indexer.computeBinary("doc_signature", one, null));
    }
}
