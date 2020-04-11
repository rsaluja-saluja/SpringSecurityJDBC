package com.example.springsecurity;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeResource {

	@RequestMapping("/")
	public String home() {
		return "Welcome Home!!!";
	}
	
	@RequestMapping("/user")
	public String user() {
		return "Welcome User!!!";
	}
	
	@RequestMapping("/admin")
	public String admin() {
		return "Welcome Admin!!!";
	}
}
