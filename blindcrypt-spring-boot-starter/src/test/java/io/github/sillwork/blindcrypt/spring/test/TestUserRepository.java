package io.github.sillwork.blindcrypt.spring.test;

import io.github.sillwork.blindcrypt.spring.annotation.BlindIndexQueries;
import jakarta.persistence.LockModeType;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;

@BlindIndexQueries
public interface TestUserRepository extends JpaRepository<TestUser, Long> {

    List<TestUser> findByEmail(String email);

    Optional<TestUser> findByRegistrationNo(String registrationNo);

    boolean existsByRegistrationNo(String registrationNo);

    List<TestUser> findByPhoneIn(Collection<String> phones);

    // No blind-index predicate: the Pageable shape check must not reject it at startup
    List<TestUser> findByFullName(String fullName, Pageable pageable);

    // No blind-index predicate: Stream returns and @Lock stay available to plain derived queries
    Stream<TestUser> streamByFullName(String fullName);

    @Lock(LockModeType.PESSIMISTIC_READ)
    List<TestUser> findLockedByFullName(String fullName);
}
