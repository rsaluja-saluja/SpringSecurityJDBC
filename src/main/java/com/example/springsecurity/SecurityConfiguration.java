package com.example.springsecurity;


import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	//SPring securtit would find H2 database in classpath so create and 
	// inject the datasource object here
	
	@Autowired
	DataSource dataSource;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {

		//With below code SPring would create default schema in empty database
		// and create users with provided roles
		
//		auth.jdbcAuthentication()
//			.dataSource(dataSource)
//			.withDefaultSchema()
//			.withUser(User.withUsername("user")
//					.password("user")
//					.roles("USER"))
//			.withUser(User.withUsername("admin")
//					.password("admin")
//					.roles("ADMIN"));
		
//Below code would create the auth object with already existed schema and user details in database
//		auth.jdbcAuthentication()
//			.dataSource(dataSource);

		//If user and authority table schema is different from the default one 
		// then query that spring securtiy needs to run can be defined in the above call also like below:
		//default queries are as mentioned below, table name/column names etc can be changed 
		auth.jdbcAuthentication()
			.dataSource(dataSource)
			.usersByUsernameQuery("select username, password, enabled "
									+ "from users "
									+ "where username = ?")
			.authoritiesByUsernameQuery("select username, authority "
									+ " from authorities "
									+ "where username = ?");
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			.antMatchers("/admin").hasRole("ADMIN")
			.antMatchers("/user").hasAnyRole("USER","ADMIN")
			.antMatchers("/").permitAll()
			.and().formLogin();
	}
	
	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
}
