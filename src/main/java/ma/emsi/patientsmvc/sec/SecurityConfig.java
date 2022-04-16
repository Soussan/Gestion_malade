package ma.emsi.patientsmvc.sec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;

@Configuration //Les classes Configuration instancié en premier lieu
@EnableWebSecurity //Activer la sécurité web
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired //On injecte le data source de l'application dans properties
    private DataSource dataSource;
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        PasswordEncoder passwordEncoder=passwordEncoder();
        /*String encodedPWD=passwordEncoder.encode("1234");
        System.out.println(encodedPWD);
        auth.inMemoryAuthentication().withUser("user1").password(encodedPWD).roles("USER");

        auth.inMemoryAuthentication().withUser("user2").password(passwordEncoder.encode("1111")).roles("USER");

        auth.inMemoryAuthentication().withUser("admin").password(passwordEncoder.encode("2345")).roles("USER","ADMIN");*/


        //Quand l'utilisateur saisie le login et mdp le prgrm va effectuer cette requette sql
        auth.jdbcAuthentication()
                .dataSource(dataSource)
                .usersByUsernameQuery("select username as principal, password as credentials, active from users where username=?")
                .authoritiesByUsernameQuery("select username as principal, role as role from users_roles where username=?")
                .rolePrefix("ROLE_")
                .passwordEncoder(passwordEncoder);



    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin(); //utiliser un formulaire d'authentication par défaut
        //cad toutes les url entre anMatchers necessite un role admin
        http.authorizeRequests().antMatchers("/").permitAll();
        http.authorizeRequests().antMatchers("/admin/**").hasRole("ADMIN");
        http.authorizeRequests().antMatchers("/user/**").hasRole("USER");
        http.authorizeRequests().anyRequest().authenticated(); //toutes les requestes http necessitent eue auth
        http.exceptionHandling().accessDeniedPage("/403");
    }
    @Bean  //cad au démarrage créer un objet passwordencoder
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
