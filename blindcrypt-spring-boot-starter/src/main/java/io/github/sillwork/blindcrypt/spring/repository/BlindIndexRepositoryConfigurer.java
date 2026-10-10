package io.github.sillwork.blindcrypt.spring.repository;

import io.github.sillwork.blindcrypt.core.UltraBlindIndexer;
import io.github.sillwork.blindcrypt.spring.annotation.BlindIndexQueries;
import io.github.sillwork.blindcrypt.spring.listener.BlindIndexRegistry;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.mapping.PropertyReferenceException;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.ListPagingAndSortingRepository;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.core.RepositoryInformation;
import org.springframework.data.repository.core.support.RepositoryProxyPostProcessor;
import org.springframework.data.repository.query.QueryByExampleExecutor;
import org.springframework.data.repository.query.parser.PartTree;
import org.springframework.orm.jpa.EntityManagerFactoryUtils;

/**
 * Spring Data {@link RepositoryProxyPostProcessor} that instruments repository proxies with blind index rewriting advice.
 * <p>
 * During Spring Data repository proxy creation, this post-processor inspects repository interfaces
 * for {@link BlindIndexQueries @BlindIndexQueries}. If present:
 * <ol>
 *   <li>Dynamically resolves the managing {@link EntityManagerFactory} for the entity type using {@link DynamicEntityManagerFactoryResolver}.</li>
 *   <li>Validates and pre-builds every candidate derived query method, so an unsupported method fails application
 *       startup with a {@link io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException} instead of failing on the first call.</li>
 *   <li>Prepends an AOP {@link MethodInterceptor} at advice position 0 to intercept derived queries before standard Spring Data execution.</li>
 * </ol>
 *
 * @see BlindIndexQueries
 * @see BlindIndexDerivedQuery
 * @see DynamicEntityManagerFactoryResolver
 */
public class BlindIndexRepositoryConfigurer implements RepositoryProxyPostProcessor {

    private final BlindIndexRegistry registry;
    private final UltraBlindIndexer indexer;
    private final ListableBeanFactory beanFactory;

    /**
     * Constructs a BlindIndexRepositoryConfigurer.
     *
     * @param registry    the entity blind index registry
     * @param indexer     the cryptographic blind indexing engine
     * @param beanFactory the Spring ListableBeanFactory to dynamically resolve persistence units
     */
    public BlindIndexRepositoryConfigurer(BlindIndexRegistry registry, UltraBlindIndexer indexer, ListableBeanFactory beanFactory) {
        this.registry = registry;
        this.indexer = indexer;
        this.beanFactory = beanFactory;
    }

    /**
     * Post-processes the Spring Data proxy factory to install the blind index query interceptor.
     *
     * @param factory               the proxy factory creating the repository bean instance
     * @param repositoryInformation metadata describing the repository interface and domain type
     * @throws io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException if a repository method cannot be rewritten
     *                                                                    into a blind index query
     */
    @Override
    public void postProcess(ProxyFactory factory, RepositoryInformation repositoryInformation) {
        Class<?> repoInterface = repositoryInformation.getRepositoryInterface();
        if (!repoInterface.isAnnotationPresent(BlindIndexQueries.class)) {
            return;
        }

        Class<?> domainType = repositoryInformation.getDomainType();
        EntityManagerFactory emf = DynamicEntityManagerFactoryResolver.resolveForEntity(domainType, beanFactory);

        BlindIndexMethodInterceptor interceptor = new BlindIndexMethodInterceptor(domainType, emf, registry, indexer);
        for (Method method : repoInterface.getMethods()) {
            if (interceptor.isCandidate(method)) {
                interceptor.prepareAtStartup(method);
            }
        }
        factory.addAdvice(0, interceptor);
    }

    private static class BlindIndexMethodInterceptor implements MethodInterceptor {

        private final Class<?> domainType;
        private final EntityManagerFactory emf;
        private final BlindIndexRegistry registry;
        private final UltraBlindIndexer indexer;
        private final Map<Method, BlindIndexDerivedQuery> queryCache = new ConcurrentHashMap<>();
        private final Set<Method> nonDerivedMethods = ConcurrentHashMap.newKeySet();

        public BlindIndexMethodInterceptor(Class<?> domainType, EntityManagerFactory emf, 
                                           BlindIndexRegistry registry, UltraBlindIndexer indexer) {
            this.domainType = domainType;
            this.emf = emf;
            this.registry = registry;
            this.indexer = indexer;
        }

        private static final Set<Class<?>> SPRING_DATA_BASE_INTERFACES = Set.of(
                Object.class,
                Repository.class,
                CrudRepository.class,
                ListCrudRepository.class,
                PagingAndSortingRepository.class,
                ListPagingAndSortingRepository.class,
                JpaRepository.class,
                QueryByExampleExecutor.class,
                JpaSpecificationExecutor.class
        );

        @Override
        public Object invoke(MethodInvocation invocation) throws Throwable {
            Method method = invocation.getMethod();

            if (!isCandidate(method)) {
                return invocation.proceed();
            }
            BlindIndexDerivedQuery derivedQuery = prepare(method);

            if (!derivedQuery.hasBlindIndexPredicate()) {
                return invocation.proceed();
            }

            EntityManager em = EntityManagerFactoryUtils.getTransactionalEntityManager(emf);
            boolean closeEm = false;
            if (em == null) {
                em = emf.createEntityManager();
                closeEm = true;
            }

            try {
                return derivedQuery.execute(em, invocation.getArguments());
            } finally {
                if (closeEm) {
                    em.close();
                }
            }
        }

        /**
         * Returns whether the method may be a blind index derived query: not a default method, not an explicit
         * {@code @Query} method, not a built-in Spring Data method and not a method whose name failed to parse
         * as a derived query at startup.
         */
        boolean isCandidate(Method method) {
            return !method.isDefault() && !method.isAnnotationPresent(Query.class) && !isSpringDataBaseMethod(method)
                    && !nonDerivedMethods.contains(method);
        }

        /**
         * Validates and caches the method at startup. A name that is not a derived query (custom fragment,
         * {@code @Procedure}, {@code findAll(Predicate)} and so on) is recorded so later calls go straight to
         * Spring Data, which handles it as before.
         */
        void prepareAtStartup(Method method) {
            try {
                new PartTree(method.getName(), domainType);
            } catch (PropertyReferenceException | IllegalArgumentException notDerivedQuery) {
                nonDerivedMethods.add(method);
                return;
            }
            // Outside the try: a validation failure must abort startup, never mark the method as non-derived.
            prepare(method);
        }

        /**
         * Validates the method (Gap #13, unindexed encrypted properties, and for blind-index queries also
         * unsupported predicates, shapes, annotations and projections) and caches its rewriter.
         */
        BlindIndexDerivedQuery prepare(Method method) {
            return queryCache.computeIfAbsent(method, m -> {
                QueryMethodValidator.validateRepositoryMethod(m, domainType);
                return new BlindIndexDerivedQuery(m, domainType, registry, indexer);
            });
        }

        private boolean isSpringDataBaseMethod(Method method) {
            Class<?> declaring = method.getDeclaringClass();
            return SPRING_DATA_BASE_INTERFACES.contains(declaring);
        }
    }
}
