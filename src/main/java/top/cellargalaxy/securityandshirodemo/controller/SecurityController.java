//package top.cellargalaxy.securityandshirodemo.controller;
//
//import org.springframework.security.access.prepost.PreAuthorize;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RestController;
//
///**
// * Created by cellargalaxy on 18-7-31.
// */
//@RestController
//@RequestMapping("/security")
//public class SecurityController {
//
//	//公开页面，需要在WebSecurityConfig里配置
//	@GetMapping("/")
//	public String p1() {
//		return "公开页面";
//	}
//
//	//需要登录但不用权限的页面
//	@GetMapping("/p2")
//	public String p2() {
//		return "需要登录但不用权限的页面";
//	}
//
//	//对于spring security的hasAuthority的权限，为任意字符串
//
//	//需要登录并且需要user权限的页面
//	@PreAuthorize("hasAuthority('USER')")
//	@GetMapping("/p3")
//	public String p3() {
//		return "需要登录并且需要user权限的页面";
//	}
//
//	//需要登录并且需要admin权限的页面
//	@PreAuthorize("hasAuthority('ADMIN')")
//	@GetMapping("/p4")
//	public String p4() {
//		return "需要登录并且需要admin权限的页面";
//	}
//
//	//对于spring security的hasRole的角色，为任意字符串需要加上ROLE_作为前缀，否则无法识别
//
//	//需要登录并且需要root角色的页面
//	@PreAuthorize("hasRole('ROLE_ADMIN')")
//	@GetMapping("/p5")
//	public String p5() {
//		return "需要登录并且需要admin角色的页面";
//	}
//
//	//需要登录并且需要root角色的页面
//	@PreAuthorize("hasRole('ROLE_ROOT')")
//	@GetMapping("/p6")
//	public String p6() {
//		return "需要登录并且需要root角色的页面";
//	}
//}
