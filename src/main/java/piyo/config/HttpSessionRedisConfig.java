package piyo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

@Configuration
@EnableRedisHttpSession
public class HttpSessionRedisConfig {
    @Bean
    public JedisConnectionFactory connectionFactory() {
        //TODO ファクトリはSpring session redisで用意されているものであればどれでもいいです。私はJedisが好き。
        return new JedisConnectionFactory();
    }
}

