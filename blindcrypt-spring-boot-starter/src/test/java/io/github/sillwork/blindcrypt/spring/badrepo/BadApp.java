package io.github.sillwork.blindcrypt.spring.badrepo;

import io.github.sillwork.blindcrypt.spring.test.TestUser;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;

/**
 * Isolated application whose only repository is {@link BadUserRepository}.
 * <p>
 * It lives outside the {@code io.github.sillwork.blindcrypt.spring.test} package tree on purpose: {@code TestApplication}'s
 * component and repository scans cover every sub-package of {@code spring.test}, so placing this app or its
 * repository there would break every {@code @SpringBootTest} context. Equally, this app's scans must not reach
 * {@code TestApplication} or the regular test repositories.
 */
@SpringBootApplication
@EntityScan(basePackageClasses = TestUser.class)
public class BadApp {
}
