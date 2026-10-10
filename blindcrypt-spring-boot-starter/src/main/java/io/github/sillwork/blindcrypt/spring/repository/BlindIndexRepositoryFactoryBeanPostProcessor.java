package io.github.sillwork.blindcrypt.spring.repository;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.data.repository.core.support.RepositoryFactoryBeanSupport;

/**
 * Spring {@link BeanPostProcessor} that registers the {@link BlindIndexRepositoryConfigurer}
 * with all Spring Data {@link RepositoryFactoryBeanSupport} instances before repository beans are instantiated.
 * <p>
 * Ensures custom repository proxy post-processors are attached early in the Spring container lifecycle.
 *
 * @see BlindIndexRepositoryConfigurer
 * @see io.github.sillwork.blindcrypt.spring.annotation.BlindIndexQueries
 */
public class BlindIndexRepositoryFactoryBeanPostProcessor implements BeanPostProcessor {

    private final ObjectProvider<BlindIndexRepositoryConfigurer> configurerProvider;

    /**
     * Constructs the post-processor with a lazy provider for the configurer bean.
     *
     * @param configurerProvider lazy object provider for {@link BlindIndexRepositoryConfigurer}
     */
    public BlindIndexRepositoryFactoryBeanPostProcessor(ObjectProvider<BlindIndexRepositoryConfigurer> configurerProvider) {
        this.configurerProvider = configurerProvider;
    }

    /**
     * Inspects candidate repository factory beans and adds the blind index proxy customizer.
     *
     * @param bean     the new bean instance
     * @param beanName the name of the bean
     * @return the bean instance to use
     * @throws BeansException in case of initialization errors
     */
    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        if (bean instanceof RepositoryFactoryBeanSupport<?, ?, ?> factoryBean) {
            factoryBean.addRepositoryFactoryCustomizer(repositoryFactory ->
                repositoryFactory.addRepositoryProxyPostProcessor(configurerProvider.getObject())
            );
        }
        return bean;
    }
}
