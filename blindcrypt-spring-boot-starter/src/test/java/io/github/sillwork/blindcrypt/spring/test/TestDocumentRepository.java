package io.github.sillwork.blindcrypt.spring.test;

import io.github.sillwork.blindcrypt.spring.annotation.BlindIndexQueries;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;

import java.util.List;
import java.util.Optional;

@NoRepositoryBean
interface BaseDocumentRepository<T, I> extends JpaRepository<T, I> {
    // Derived query declared on an inherited interface
    List<T> findByDocTitle(String title);
}

@BlindIndexQueries
public interface TestDocumentRepository extends BaseDocumentRepository<TestDocument, Long> {

    // Derived query searching binary column using byte[] parameter
    Optional<TestDocument> findByFingerprint(byte[] fingerprint);

    // Derived query searching binary column using EncryptedBytes parameter
    Optional<TestDocument> findBySignature(byte[] signature);

    long countByDocTitle(String title);

    boolean existsByDocTitle(String title);

    List<TestDocument> findByDocTitleOrderByDocTitleAsc(String title);
}
