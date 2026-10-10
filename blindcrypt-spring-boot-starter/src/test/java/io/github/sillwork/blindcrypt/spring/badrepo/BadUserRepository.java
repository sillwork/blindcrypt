package io.github.sillwork.blindcrypt.spring.badrepo;

import io.github.sillwork.blindcrypt.spring.annotation.BlindIndexQueries;
import io.github.sillwork.blindcrypt.spring.test.TestUser;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

@BlindIndexQueries
public interface BadUserRepository extends JpaRepository<TestUser, Long> {

    // CONTAINING cannot be answered by an exact-match blind index
    List<TestUser> findByEmailContaining(String fragment);
}
