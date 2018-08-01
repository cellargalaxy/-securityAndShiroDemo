package top.cellargalaxy.securityandshirodemo.controller;

import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import top.cellargalaxy.securityandshirodemo.model.SecurityUser;
import top.cellargalaxy.securityandshirodemo.service.SecurityService;

/**
 * @author cellargalaxy
 * @time 2018/8/1
 */
@RestController
@RequestMapping("/shiro")
public class ShiroController {
	@Autowired
	private SecurityService securityService;

	@PostMapping("/login")
	public String login(@RequestParam("username") String username,
	                    @RequestParam("password") String password) {
		SecurityUser securityUser = securityService.checkSecurityUser(username, password);
		if (securityUser != null) {
			return securityService.createToken(securityUser);
		} else {
			return "账号或密码错误";
		}
	}

	//公开页面，需要在WebSecurityConfig里配置
	@GetMapping("/")
	public String p1() {
		return "公开页面";
	}

	//需要登录但不用权限的页面
	@RequiresUser
	@GetMapping("/p2")
	public String p2() {
		return "需要登录但不用权限的页面";
	}

	//对于Shiro的hasAuthority的权限，为任意字符串

	//需要登录并且需要user权限的页面
	@RequiresPermissions("USER")
	@GetMapping("/p3")
	public String p3() {
		return "需要登录并且需要user权限的页面";
	}

	//需要登录并且需要admin权限的页面
	@RequiresPermissions("ADMIN")
	@GetMapping("/p4")
	public String p4() {
		return "需要登录并且需要admin权限的页面";
	}

	//对于Shiro的hasRole的角色，依然为任意字符串

	//需要登录并且需要root角色的页面
	@RequiresRoles("ROLE_ADMIN")
	@GetMapping("/p5")
	public String p5() {
		return "需要登录并且需要admin角色的页面";
	}

	//需要登录并且需要root角色的页面
	@RequiresRoles("ROLE_ROOT")
	@GetMapping("/p6")
	public String p6() {
		return "需要登录并且需要root角色的页面";
	}
}
